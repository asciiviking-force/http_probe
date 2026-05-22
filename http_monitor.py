#!/usr/bin/env python3
"""
HTTP/HTTPS endpoint monitor.

Repeatedly probes one or more URLs, prints the HTTP status code with a
timestamp in real time, writes every probe to log.txt, and writes a
status-change log plus per-URL statistics to summary.txt on exit.

Uses only the Python standard library — no external dependencies.

Examples:
    python3 http_monitor.py -u https://example.com -i 2
    python3 http_monitor.py -f url.txt -i 1 -c 100
    python3 http_monitor.py -u https://a.com -u https://b.com -i 5

Copyright (c) Viking Li <viking.li@walmart.com>. All rights reserved.
"""

__author__ = "Viking Li <viking.li@walmart.com>"
__copyright__ = "Copyright (c) Viking Li <viking.li@walmart.com>"
__version__ = "1.3.0"
__date__ = "2026-05-21"

# Bookkeeping caps for tracert state. See tracert_worker / write_summary.
TRACERT_SNAPSHOT_CAP = 6     # snapshots retained per host (initial + latest always preserved)
TRACERT_CHANGE_CAP = 10      # path-change history entries retained per host
COPYRIGHT_NOTICE = "Copyright (c) Viking Li - viking.li@walmart.com"
VERSION_BANNER = f"HTTP/HTTPS Monitor v{__version__}  (released {__date__})"

import os
import sys

# If a local http.py / http/ sits next to this script (e.g. a scapy sniffer),
# it shadows the stdlib `http` package and breaks urllib. Drop our own dir
# from sys.path before importing anything that pulls in `http`.
_script_dir = os.path.dirname(os.path.abspath(__file__))
sys.path[:] = [p for p in sys.path if os.path.abspath(p or ".") != _script_dir]

import argparse
import ipaddress
import re
import shutil
import signal
import socket
import ssl
import subprocess
import threading
import time
import urllib.error
import urllib.request
from collections import defaultdict, deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse


def load_urls(url_args, file_path):
    urls = list(url_args) if url_args else []
    if file_path:
        p = Path(file_path)
        if not p.is_file():
            sys.exit(f"URL file not found: {file_path}")
        for line in p.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                urls.append(line)
    if not urls:
        default = Path("url.txt")
        if default.is_file():
            for line in default.read_text().splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    urls.append(line)
    if not urls:
        sys.exit("No URLs provided. Use -u/--url, -f/--file, or create url.txt.")
    seen, deduped = set(), []
    for u in urls:
        if u not in seen:
            seen.add(u)
            deduped.append(u)
    return deduped


def classify_error(exc):
    """Map an exception to a short status label and a human-readable detail."""
    # URLError wraps the underlying socket/SSL exception in .reason.
    reason = getattr(exc, "reason", exc)
    if isinstance(reason, socket.timeout) or isinstance(reason, TimeoutError):
        return "TIMEOUT", f"timeout: {reason}"
    if isinstance(reason, ConnectionRefusedError):
        return "DENIED", f"connection refused: {reason}"
    if isinstance(reason, socket.gaierror):
        return "DNS", f"dns failure: {reason}"
    if isinstance(reason, ssl.SSLError):
        return "SSL", f"ssl error: {reason}"
    if isinstance(reason, ConnectionResetError):
        return "RESET", f"connection reset: {reason}"
    if isinstance(reason, ConnectionError):
        return "CONNERR", f"connection error: {reason}"
    # Fall back to the textual reason if it carries a recognisable keyword.
    text = str(reason).lower()
    if "timed out" in text or "timeout" in text:
        return "TIMEOUT", f"timeout: {reason}"
    if "refused" in text:
        return "DENIED", f"connection refused: {reason}"
    if "name or service" in text or "name resolution" in text or "nodename" in text:
        return "DNS", f"dns failure: {reason}"
    if "certificate" in text or "ssl" in text:
        return "SSL", f"ssl error: {reason}"
    if "unreachable" in text:
        return "UNREACH", f"network unreachable: {reason}"
    return "ERR", f"{type(exc).__name__}: {reason}"


def resolve_ip(url):
    """Resolve the host of `url` to an IP. Returns (ip, error_detail)."""
    parsed = urlparse(url)
    host = parsed.hostname
    if not host:
        return None, "no host in URL"
    # IP literal — skip DNS.
    try:
        ipaddress.ip_address(host)
        return host, None
    except ValueError:
        pass
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        if not infos:
            return None, "no DNS records"
        # Prefer IPv4 when present, otherwise take the first result.
        for family, _, _, _, sockaddr in infos:
            if family == socket.AF_INET:
                return sockaddr[0], None
        return infos[0][4][0], None
    except socket.gaierror as exc:
        return None, f"dns failure: {exc}"


def probe(url, timeout, ssl_ctx):
    # Resolve first so we always know which IP the probe targeted; if DNS
    # fails we can short-circuit with a DNS status and skip the HTTP call.
    ip, dns_err = resolve_ip(url)
    if ip is None:
        return "DNS", 0.0, "-", dns_err

    started = time.monotonic()
    req = urllib.request.Request(url, method="GET",
                                 headers={"User-Agent": "http_monitor/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ssl_ctx) as resp:
            code = resp.getcode()
            resp.read(0)  # don't drain body; just confirm headers
        elapsed_ms = (time.monotonic() - started) * 1000
        return str(code), elapsed_ms, ip, None
    except urllib.error.HTTPError as exc:
        # Server responded with a non-2xx status — that's a real status code.
        elapsed_ms = (time.monotonic() - started) * 1000
        # 401/403 are explicit application-level denials; surface that too.
        detail = None
        if exc.code in (401, 403):
            detail = f"denied: {exc.reason}"
        return str(exc.code), elapsed_ms, ip, detail
    except urllib.error.URLError as exc:
        elapsed_ms = (time.monotonic() - started) * 1000
        code, detail = classify_error(exc)
        return code, elapsed_ms, ip, detail
    except (TimeoutError, ConnectionError, socket.timeout, ssl.SSLError) as exc:
        elapsed_ms = (time.monotonic() - started) * 1000
        code, detail = classify_error(exc)
        return code, elapsed_ms, ip, detail
    except Exception as exc:
        elapsed_ms = (time.monotonic() - started) * 1000
        return "ERR", elapsed_ms, ip, f"{type(exc).__name__}: {exc}"


def find_tracert_cmd():
    """Return the traceroute command template for this platform, or None."""
    if sys.platform.startswith("win"):
        if shutil.which("tracert"):
            return ["tracert", "-d"]
        return None
    # macOS / Linux
    if shutil.which("traceroute"):
        # -n: numeric only, -w: per-probe wait, -q: 1 query per hop (faster)
        return ["traceroute", "-n", "-w", "2", "-q", "1"]
    return None


_HOP_LINE_RE = re.compile(r"^\s*(\d+)\s+(.*)")
_IPV4_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")


def run_tracert(host, max_hops, timeout, base_cmd):
    """Run a single traceroute. Returns (hops_list, error_or_None).

    `hops_list` is an ordered list of strings: an IPv4 or "*" per hop.
    """
    if base_cmd is None:
        return None, "traceroute binary not found"
    if base_cmd[0] == "tracert":
        cmd = base_cmd + ["-h", str(max_hops), host]
    else:
        cmd = base_cmd + ["-m", str(max_hops), host]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True,
                                timeout=timeout)
    except subprocess.TimeoutExpired:
        return None, f"traceroute timed out after {timeout}s"
    except FileNotFoundError as exc:
        return None, f"traceroute binary missing: {exc}"
    except Exception as exc:
        return None, f"{type(exc).__name__}: {exc}"

    hops = []
    for line in result.stdout.splitlines():
        m = _HOP_LINE_RE.match(line)
        if not m:
            continue
        rest = m.group(2)
        ip_m = _IPV4_RE.search(rest)
        hops.append(ip_m.group(1) if ip_m else "*")
    if not hops and result.stderr.strip():
        return None, result.stderr.strip().splitlines()[-1]
    return hops, None


def tracert_worker(host, interval, max_hops, timeout, base_cmd,
                   tracert_state, lock, stop_event, log_f, log_lock):
    """Periodically traceroute `host`, recording path changes."""
    last_hops = None
    # First run happens immediately so the user gets a baseline.
    while not stop_event.is_set():
        hops, err = run_tracert(host, max_hops, timeout, base_cmd)
        ts = datetime.now().isoformat(timespec="milliseconds")
        with lock:
            entry = tracert_state[host]
            if err:
                entry["errors"].append((ts, err))
                msg = f"[{ts}] TRACERT {host:<30} ERROR  {err}"
            else:
                entry["latest"] = hops
                entry["runs"] += 1
                if last_hops is None:
                    entry["initial"] = hops
                    entry["snapshots"].append((ts, hops))
                    msg = (f"[{ts}] TRACERT {host:<30} INITIAL "
                           f"{len(hops)} hop(s): {' -> '.join(hops)}")
                elif last_hops != hops:
                    entry["total_changes"] += 1
                    # Append full-path change; cap history.
                    entry["changes"].append((ts, last_hops, hops))
                    if len(entry["changes"]) > TRACERT_CHANGE_CAP:
                        entry["changes"].pop(0)
                    # Append snapshot; cap by dropping the oldest non-initial
                    # entry so snapshots[0] (initial) and snapshots[-1] (latest)
                    # remain preserved.
                    entry["snapshots"].append((ts, hops))
                    if len(entry["snapshots"]) > TRACERT_SNAPSHOT_CAP:
                        entry["snapshots"].pop(1)
                    diff_desc = _hops_diff_brief(last_hops, hops)
                    msg = (f"[{ts}] TRACERT {host:<30} *PATH CHANGE* {diff_desc}")
                else:
                    msg = None  # unchanged, stay quiet on terminal
                last_hops = hops
        if msg:
            print(msg)
            with log_lock:
                log_f.write(
                    f"# tracert\t{ts}\t{host}\t"
                    f"{'ERROR' if err else ('CHANGE' if entry['changes'] and entry['changes'][-1][0] == ts else 'INITIAL')}\t"
                    f"{(err if err else ' -> '.join(hops))}\n")
        # Sleep with responsiveness to stop signal.
        slept = 0.0
        while slept < interval and not stop_event.is_set():
            chunk = min(0.5, interval - slept)
            time.sleep(chunk)
            slept += chunk


def _hops_diff_brief(old, new):
    """Compact human-readable diff of two hop sequences."""
    max_len = max(len(old), len(new))
    diffs = []
    for i in range(max_len):
        o = old[i] if i < len(old) else "-"
        n = new[i] if i < len(new) else "-"
        if o != n:
            diffs.append(f"hop{i + 1}: {o}->{n}")
    if not diffs:
        return "(no diff)"
    if len(diffs) > 3:
        return "; ".join(diffs[:3]) + f"; +{len(diffs) - 3} more"
    return "; ".join(diffs)


def percentile(sorted_values, p):
    if not sorted_values:
        return 0.0
    if len(sorted_values) == 1:
        return sorted_values[0]
    k = (len(sorted_values) - 1) * (p / 100)
    f = int(k)
    c = min(f + 1, len(sorted_values) - 1)
    if f == c:
        return sorted_values[f]
    return sorted_values[f] + (sorted_values[c] - sorted_values[f]) * (k - f)


def _render_change_table(rows):
    """Render change rows for one URL as an aligned ASCII table.

    rows: iterable of (timestamp, (prev_code, prev_ip), (curr_code, curr_ip))
    """
    headers = ["Timestamp", "From", "From IP", "To", "To IP"]
    body = [[ts, prev[0], prev[1], curr[0], curr[1]] for ts, prev, curr in rows]
    widths = [len(h) for h in headers]
    for row in body:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(str(cell)))

    sep = "+" + "+".join("-" * (w + 2) for w in widths) + "+"

    def fmt(row):
        return "| " + " | ".join(
            str(cell).ljust(widths[i]) for i, cell in enumerate(row)) + " |"

    out = [sep, fmt(headers), sep]
    out.extend(fmt(row) for row in body)
    out.append(sep)
    return out


def _render_table(headers, body):
    """Generic aligned ASCII table renderer."""
    widths = [len(h) for h in headers]
    for row in body:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(str(cell)))
    sep = "+" + "+".join("-" * (w + 2) for w in widths) + "+"

    def fmt(row):
        return "| " + " | ".join(
            str(cell).ljust(widths[i]) for i, cell in enumerate(row)) + " |"

    out = [sep, fmt(headers), sep]
    out.extend(fmt(row) for row in body)
    out.append(sep)
    return out


def _render_snapshots_table(snaps):
    """Render up to N path snapshots side-by-side.

    `snaps` is a list of (timestamp, hops) tuples with snaps[0]=initial,
    snaps[-1]=latest. Each snapshot becomes a column; rows are hop indices.
    The header row carries the snapshot label, the second row its short
    timestamp (HH:MM:SS).
    """
    if not snaps:
        return []
    n = len(snaps)
    # Column 0 = Hop number; columns 1..n = snapshots.
    # Build two-line headers.
    labels = []
    times = []
    for idx, (ts, _) in enumerate(snaps, start=1):
        if idx == 1 and n > 1:
            labels.append(f"#{idx} initial")
        elif idx == n and n > 1:
            labels.append(f"#{idx} latest")
        elif n == 1:
            labels.append(f"#{idx} initial=latest")
        else:
            labels.append(f"#{idx}")
        # Keep just the HH:MM:SS portion of the ISO timestamp for narrowness.
        try:
            times.append(ts.split("T", 1)[1].split(".", 1)[0])
        except (IndexError, AttributeError):
            times.append(str(ts))

    max_hops = max(len(h) for _, h in snaps)
    # Build cell grid: each row = hop number then one cell per snapshot.
    body = []
    for i in range(max_hops):
        row = [str(i + 1)]
        for _, hops in snaps:
            row.append(hops[i] if i < len(hops) else "-")
        body.append(row)

    # Compute column widths.
    headers_top = ["Hop"] + labels
    headers_bot = [""] + times
    widths = [len(h) for h in headers_top]
    for i, h in enumerate(headers_bot):
        widths[i] = max(widths[i], len(h))
    for row in body:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(str(cell)))

    sep = "+" + "+".join("-" * (w + 2) for w in widths) + "+"

    def fmt(row):
        return "| " + " | ".join(
            str(cell).ljust(widths[i]) for i, cell in enumerate(row)) + " |"

    out = [sep, fmt(headers_top), fmt(headers_bot), sep]
    out.extend(fmt(row) for row in body)
    out.append(sep)
    return out


def write_summary(path, urls, stats, changes, latency_events, tracert_state,
                  url_hosts, started_at, ended_at, total_requests):
    lines = []
    lines.append("HTTP/HTTPS Monitor Summary")
    lines.append(VERSION_BANNER)
    lines.append(COPYRIGHT_NOTICE)
    lines.append("=" * 60)
    lines.append(f"Started : {started_at.isoformat(timespec='seconds')}")
    lines.append(f"Ended   : {ended_at.isoformat(timespec='seconds')}")
    duration = (ended_at - started_at).total_seconds()
    lines.append(f"Duration: {duration:.2f}s")
    lines.append(f"Total requests: {total_requests}")
    lines.append("")

    lines.append("Per-URL Statistics")
    lines.append("-" * 60)
    for url in urls:
        s = stats[url]
        total = s["total"]
        if total == 0:
            lines.append(f"{url}\n  no requests completed")
            lines.append("")
            continue
        success = sum(c for code, c in s["codes"].items()
                      if code.isdigit() and 200 <= int(code) < 400)
        failure = total - success
        rate = (success / total) * 100
        avg_ms = s["elapsed_total"] / total
        lines.append(f"{url}")
        lines.append(f"  total       : {total}")
        lines.append(f"  success     : {success}  ({rate:.2f}%)")
        lines.append(f"  failure     : {failure}")
        lines.append(f"  latency ms  : avg={avg_ms:.1f}  "
                     f"min={s['elapsed_min']:.1f}  max={s['elapsed_max']:.1f}")
        samples = sorted(s["latency_samples"])
        if samples:
            p50 = percentile(samples, 50)
            p95 = percentile(samples, 95)
            p99 = percentile(samples, 99)
            lines.append(f"  percentiles : p50={p50:.1f}  p95={p95:.1f}  p99={p99:.1f}  "
                         f"(n={len(samples)})")
        lines.append("  status code breakdown:")
        for code in sorted(s["codes"]):
            lines.append(f"    {code:<8} : {s['codes'][code]}")
        lines.append("  resolved IP breakdown:")
        for ip in sorted(s["ips"]):
            lines.append(f"    {ip:<15} : {s['ips'][ip]}")
        lines.append("")

    lines.append("Status Change Log")
    lines.append("-" * 60)
    if not changes:
        lines.append("(no status / IP changes observed)")
    else:
        # Group changes by URL, preserving the order URLs first appear in.
        by_url = {}
        for ts, url, prev, curr in changes:
            by_url.setdefault(url, []).append((ts, prev, curr))

        for url in urls:
            rows = by_url.get(url)
            if not rows:
                continue
            lines.append(f"URL: {url}  ({len(rows)} change(s))")
            lines.extend(_render_change_table(rows))
            lines.append("")
    lines.append("")

    # -- Latency anomaly log -------------------------------------------------
    lines.append("Latency Anomaly Log")
    lines.append("-" * 60)
    if not latency_events:
        lines.append("(no latency anomalies recorded)")
    else:
        by_url = {}
        for ts, url, baseline, observed, ip in latency_events:
            by_url.setdefault(url, []).append((ts, baseline, observed, ip))
        for url in urls:
            rows = by_url.get(url)
            if not rows:
                continue
            lines.append(f"URL: {url}  ({len(rows)} anomaly/anomalies)")
            body = [[ts, f"{baseline:.1f}", f"{observed:.1f}",
                     f"{observed / baseline:.2f}x" if baseline > 0 else "-",
                     ip]
                    for ts, baseline, observed, ip in rows]
            lines.extend(_render_table(
                ["Timestamp", "Baseline ms", "Observed ms", "Factor", "IP"],
                body))
            lines.append("")
    lines.append("")

    # -- Traceroute path change log -----------------------------------------
    lines.append("Traceroute Path Changes")
    lines.append("-" * 60)
    if not tracert_state:
        lines.append("(traceroute disabled)")
    else:
        any_data = False
        # Group by host but report under URL headings (multiple URLs may share host).
        for url in urls:
            host = url_hosts.get(url)
            if not host or host not in tracert_state:
                continue
            entry = tracert_state[host]
            initial = entry.get("initial") or []
            latest = entry.get("latest") or []
            snaps = entry.get("snapshots", [])
            ch = entry.get("changes", [])
            errs = entry.get("errors", [])
            runs = entry.get("runs", 0)
            total_changes = entry.get("total_changes", 0)
            # Total snapshots observed over the run = 1 (initial) + every change.
            total_snaps_taken = (1 if initial else 0) + total_changes
            if not (initial or latest or snaps or ch or errs):
                continue
            any_data = True
            lines.append(
                f"URL: {url}  (host: {host}, runs: {runs}, "
                f"path changes: {total_changes}, errors: {len(errs)})")

            # ---- Path snapshots (up to TRACERT_SNAPSHOT_CAP) -------------
            if snaps:
                kept = len(snaps)
                if total_snaps_taken > kept:
                    lines.append(
                        f"  Path snapshots (keeping {kept} of {total_snaps_taken}; "
                        f"initial + latest always preserved):")
                else:
                    lines.append(f"  Path snapshots ({kept}):")
                lines.extend(_render_snapshots_table(snaps))
            elif initial or latest:
                # Fallback if snapshots somehow empty but initial/latest exist.
                cur_path = latest or initial
                body = [[str(i + 1), hop] for i, hop in enumerate(cur_path)]
                lines.append("  Current path:")
                lines.extend(_render_table(["Hop", "IP"], body))

            # ---- Path change history (full hops, up to TRACERT_CHANGE_CAP)
            if ch:
                kept_ch = len(ch)
                if total_changes > kept_ch:
                    lines.append(
                        f"  Change history (showing {kept_ch} most recent of "
                        f"{total_changes} total):")
                else:
                    lines.append(f"  Change history ({kept_ch}):")
                for idx, (ts, prev_hops, curr_hops) in enumerate(ch, start=1):
                    diff_desc = _hops_diff_brief(prev_hops, curr_hops)
                    lines.append(
                        f"    #{idx}  {ts}  ({len(prev_hops)} -> {len(curr_hops)} hops)  "
                        f"{diff_desc}")
                    max_len = max(len(prev_hops), len(curr_hops))
                    body = []
                    for i in range(max_len):
                        o = prev_hops[i] if i < len(prev_hops) else "-"
                        n = curr_hops[i] if i < len(curr_hops) else "-"
                        marker = "*" if o != n else ""
                        body.append([str(i + 1), o, n, marker])
                    lines.extend(_render_table(
                        ["Hop", "Old", "New", "Δ"], body))

            # Error table (last 5).
            if errs:
                lines.append(f"  Errors (last {min(5, len(errs))} of {len(errs)}):")
                body = [[ts, err] for ts, err in errs[-5:]]
                lines.extend(_render_table(["Timestamp", "Error"], body))

            lines.append("")
        if not any_data:
            lines.append("(no traceroute results yet)")
    lines.append("")

    Path(path).write_text("\n".join(lines))


def main():
    parser = argparse.ArgumentParser(
        description="Repeatedly probe HTTP/HTTPS URLs and log status codes.")
    parser.add_argument("-u", "--url", action="append", default=[],
                        help="URL to probe (repeatable).")
    parser.add_argument("-f", "--file",
                        help="File with one URL per line (default: url.txt if present).")
    parser.add_argument("-i", "--interval", type=float, default=1.0,
                        help="Seconds between probe rounds (default: 1.0).")
    parser.add_argument("-c", "--count", type=int, default=0,
                        help="Total probe rounds per URL (0 = run until Ctrl+C).")
    parser.add_argument("-t", "--timeout", type=float, default=10.0,
                        help="Per-request timeout in seconds (default: 10).")
    parser.add_argument("-k", "--insecure", action="store_true",
                        help="Skip TLS certificate verification.")
    parser.add_argument("--log", default="log.txt",
                        help="Per-request log file (default: log.txt).")
    parser.add_argument("--summary", default="summary.txt",
                        help="Summary file written on exit (default: summary.txt).")
    parser.add_argument("--latency-window", type=int, default=10,
                        help="Rolling window size (samples) for latency baseline "
                             "(default: 10).")
    parser.add_argument("--latency-factor", type=float, default=2.0,
                        help="Anomaly if latency >= factor * rolling avg "
                             "(default: 2.0).")
    parser.add_argument("--latency-min-delta-ms", type=float, default=50.0,
                        help="Anomaly only if observed - baseline >= this ms "
                             "(default: 50).")
    parser.add_argument("--tracert-interval", type=float, default=0.0,
                        help="Run traceroute per host every N seconds "
                             "(default: 0 = disabled; suggested: 60+).")
    parser.add_argument("--tracert-max-hops", type=int, default=20,
                        help="Maximum traceroute hops (default: 20).")
    parser.add_argument("--tracert-timeout", type=float, default=30.0,
                        help="Per-run traceroute timeout in seconds (default: 30).")
    args = parser.parse_args()

    if args.interval < 0:
        sys.exit("Interval must be >= 0.")

    urls = load_urls(args.url, args.file)

    ssl_ctx = None
    if args.insecure:
        ssl_ctx = ssl.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE

    stats = {u: {"total": 0, "codes": defaultdict(int),
                 "ips": defaultdict(int),
                 "elapsed_total": 0.0,
                 "elapsed_min": float("inf"), "elapsed_max": 0.0,
                 "latency_samples": []}
             for u in urls}
    last_state = {u: None for u in urls}  # (code, ip) tuple
    changes = []
    # Rolling window for latency baseline + collected anomaly events.
    latency_window = {u: deque(maxlen=max(2, args.latency_window)) for u in urls}
    latency_events = []  # list of (ts, url, baseline, observed, ip)
    started_at = datetime.now()
    total_requests = 0

    # Map URL -> host for tracert grouping.
    url_hosts = {}
    for u in urls:
        h = urlparse(u).hostname
        if h:
            url_hosts[u] = h

    # Set up tracert workers (one per unique host) if enabled.
    tracert_state = {}
    tracert_threads = []
    tracert_stop = threading.Event()
    log_lock = threading.Lock()
    tracert_lock = threading.Lock()
    if args.tracert_interval > 0:
        base_cmd = find_tracert_cmd()
        if base_cmd is None:
            print("WARNING: traceroute/tracert binary not found — "
                  "path tracking disabled.")
        else:
            unique_hosts = []
            seen_hosts = set()
            for h in url_hosts.values():
                if h not in seen_hosts:
                    seen_hosts.add(h)
                    unique_hosts.append(h)
            for h in unique_hosts:
                tracert_state[h] = {"initial": None, "latest": None,
                                    "snapshots": [],
                                    "changes": [], "errors": [], "runs": 0,
                                    "total_changes": 0}

    print("=" * 60)
    print(VERSION_BANNER)
    print(COPYRIGHT_NOTICE)
    print(f"Run started: {started_at.isoformat(timespec='seconds')}")
    print("=" * 60)
    print(f"Monitoring {len(urls)} URL(s) every {args.interval}s. "
          f"Press Ctrl+C to stop.")
    for u in urls:
        print(f"  - {u}")
    if tracert_state:
        print(f"Tracert: every {args.tracert_interval}s for "
              f"{len(tracert_state)} host(s) (max {args.tracert_max_hops} hops)")

    log_f = open(args.log, "w", buffering=1)
    log_f.write(f"# HTTP monitor log — started {started_at.isoformat(timespec='seconds')}\n")
    log_f.write(f"# {VERSION_BANNER}\n")
    log_f.write(f"# {COPYRIGHT_NOTICE}\n")
    log_f.write("# Per-request rows:  timestamp\\tstatus\\tlatency_ms\\tip\\turl\\tdetail\n")
    log_f.write("# Event lines start with '# latency' or '# tracert'.\n")
    log_f.write("# timestamp\tstatus\tlatency_ms\tip\turl\tdetail\n")

    # Now that log_f exists, start tracert workers.
    if tracert_state:
        base_cmd = find_tracert_cmd()
        for h in tracert_state.keys():
            t = threading.Thread(
                target=tracert_worker,
                args=(h, args.tracert_interval, args.tracert_max_hops,
                      args.tracert_timeout, base_cmd,
                      tracert_state, tracert_lock, tracert_stop,
                      log_f, log_lock),
                name=f"tracert-{h}", daemon=True)
            t.start()
            tracert_threads.append(t)

    stop = {"flag": False}

    def handle_signal(signum, frame):
        stop["flag"] = True
        print("\nStopping (signal received)...")

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    # One worker per URL so a slow/timing-out URL never blocks the others.
    pool = ThreadPoolExecutor(max_workers=max(1, len(urls)),
                              thread_name_prefix="probe")
    try:
        round_index = 0
        while not stop["flag"]:
            if args.count and round_index >= args.count:
                break
            round_index += 1

            # Fire every URL in this round at the same time.
            futures = {pool.submit(probe, url, args.timeout, ssl_ctx): url
                       for url in urls}

            for fut in as_completed(futures):
                url = futures[fut]
                try:
                    code, elapsed_ms, ip, err = fut.result()
                except Exception as exc:  # safety net; probe() catches its own
                    code, elapsed_ms, ip, err = "ERR", 0.0, "-", f"{type(exc).__name__}: {exc}"

                ts = datetime.now().isoformat(timespec="milliseconds")
                total_requests += 1

                s = stats[url]
                s["total"] += 1
                s["codes"][code] += 1
                s["ips"][ip] += 1
                s["elapsed_total"] += elapsed_ms
                s["elapsed_min"] = min(s["elapsed_min"], elapsed_ms)
                s["elapsed_max"] = max(s["elapsed_max"], elapsed_ms)

                # Track latency samples only for runs that actually hit the
                # network (successful HTTP responses, not DNS short-circuits).
                is_http_response = code.isdigit()
                if is_http_response:
                    s["latency_samples"].append(elapsed_ms)

                # Latency anomaly: compare against rolling baseline.
                latency_anomaly = None
                if is_http_response:
                    window = latency_window[url]
                    if len(window) >= 2:
                        baseline = sum(window) / len(window)
                        if (baseline > 0
                                and elapsed_ms >= baseline * args.latency_factor
                                and elapsed_ms - baseline >= args.latency_min_delta_ms):
                            latency_anomaly = baseline
                    window.append(elapsed_ms)

                prev = last_state[url]
                curr = (code, ip)
                changed = prev is not None and prev != curr

                markers = []
                if changed:
                    markers.append("*CHANGE*")
                if latency_anomaly is not None:
                    markers.append(
                        f"*LATENCY {elapsed_ms / latency_anomaly:.2f}x*")
                marker = ("  " + "  ".join(markers)) if markers else ""

                detail = err if err else ""
                line = (f"[{ts}] {code:>7}  {elapsed_ms:7.1f}ms  "
                        f"{ip:<15}  {url}"
                        f"{('  ' + detail) if detail else ''}{marker}")
                print(line)

                with log_lock:
                    log_f.write(
                        f"{ts}\t{code}\t{elapsed_ms:.1f}\t{ip}\t{url}\t{detail}\n")
                    if latency_anomaly is not None:
                        log_f.write(
                            f"# latency\t{ts}\t{url}\t"
                            f"baseline={latency_anomaly:.1f}ms\t"
                            f"observed={elapsed_ms:.1f}ms\t"
                            f"factor={elapsed_ms / latency_anomaly:.2f}\tip={ip}\n")

                if changed:
                    changes.append((ts, url, prev, curr))
                if latency_anomaly is not None:
                    latency_events.append(
                        (ts, url, latency_anomaly, elapsed_ms, ip))
                last_state[url] = curr

            if stop["flag"]:
                break
            if args.interval > 0:
                # Sleep in small slices so Ctrl+C feels responsive.
                remaining = args.interval
                while remaining > 0 and not stop["flag"]:
                    chunk = min(0.2, remaining)
                    time.sleep(chunk)
                    remaining -= chunk
    finally:
        pool.shutdown(wait=False, cancel_futures=True)
        # Signal tracert workers and give them a moment to exit cleanly.
        tracert_stop.set()
        for t in tracert_threads:
            t.join(timeout=2.0)
        with log_lock:
            log_f.close()
        ended_at = datetime.now()
        # Snapshot tracert state under the lock for a consistent summary.
        with tracert_lock:
            tracert_snapshot = {
                h: {"initial": v.get("initial"),
                    "latest": v.get("latest"),
                    "snapshots": list(v.get("snapshots", [])),
                    "changes": list(v.get("changes", [])),
                    "errors": list(v.get("errors", [])),
                    "runs": v.get("runs", 0),
                    "total_changes": v.get("total_changes", 0)}
                for h, v in tracert_state.items()}
        write_summary(args.summary, urls, stats, changes,
                      latency_events, tracert_snapshot, url_hosts,
                      started_at, ended_at, total_requests)
        print(f"\nLog saved to {args.log}")
        print(f"Summary saved to {args.summary}")


if __name__ == "__main__":
    main()
