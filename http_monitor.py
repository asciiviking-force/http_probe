#!/usr/bin/env python3
"""
HTTP/HTTPS endpoint monitor.

Repeatedly probes one or more URLs, prints the HTTP status code with a
timestamp in real time, writes every probe to log.txt, and writes a
status-change log plus per-URL statistics to summary.txt on exit.

Uses only the Python standard library — no external dependencies.

Optionally runs background traceroute, ICMP-ping, TCP-ping (connect probe),
and nslookup probes per host. Command parameters and DNS servers can also be
set in a config.txt file.

Examples:
    python3 http_monitor.py -u https://example.com -i 2
    python3 http_monitor.py -f url.txt -i 1 -c 100
    python3 http_monitor.py -u https://a.com -u https://b.com -i 5
    python3 http_monitor.py -f url.txt --ping-interval 2 --tracert-interval 60
    python3 http_monitor.py -f url.txt --nslookup-interval 10 \
        --dns-server 8.8.8.8 --dns-server 1.1.1.1
    python3 http_monitor.py --config config.txt

Copyright (c) Viking Li <viking.li@walmart.com>. All rights reserved.
"""

__author__ = "Viking Li <viking.li@walmart.com>"
__copyright__ = "Copyright (c) Viking Li <viking.li@walmart.com>"
__version__ = "1.6.0"
__date__ = "2026-05-22"

# Bookkeeping cap for tracert state. See tracert_worker / write_summary.
TRACERT_SNAPSHOT_CAP = 8     # snapshots retained per host (initial + latest always preserved)
# Change-history list is uncapped — every path change is recorded with full
# old/new hop sequences. On very long runs this grows linearly with the
# number of path changes; that's an accepted trade-off for full audit fidelity.
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
import errno
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


def load_config(path, parser):
    """Parse a key=value config file into {argparse_dest: value}.

    - Keys use the long-option spelling with dashes or underscores
      (e.g. `ping-interval` or `ping_interval`).
    - Types are taken from the parser's option definitions.
    - Append options (--url, --dns-server) accept comma-separated values
      and/or repeated keys; they accumulate into a list.
    - Boolean flags (--insecure) accept true/false/yes/no/on/off/1/0.
    - Unknown keys are ignored with a warning.

    Precedence is enforced by the caller via parser.set_defaults(), so an
    explicit command-line value always wins over the config file.
    """
    cfg = {}
    p = Path(path)
    if not p.is_file():
        return cfg
    actions = {a.dest: a for a in parser._actions}
    list_dests = {a.dest for a in parser._actions
                  if isinstance(a, argparse._AppendAction)}
    bool_dests = {a.dest for a in parser._actions
                  if isinstance(a, (argparse._StoreTrueAction,
                                    argparse._StoreFalseAction))}
    raw = {}
    for lineno, line in enumerate(p.read_text().splitlines(), start=1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            sys.stderr.write(f"config {path}:{lineno}: ignoring malformed "
                             f"line (no '='): {line}\n")
            continue
        key, val = line.split("=", 1)
        key = key.strip().replace("-", "_")
        # Strip inline comments (whitespace + '#' to end-of-line). The leading
        # whitespace requirement avoids clobbering '#' inside a value such as
        # a URL fragment.
        val = re.split(r"\s+#", val, 1)[0].strip()
        if key not in actions:
            sys.stderr.write(f"config {path}:{lineno}: unknown key '{key}' "
                             f"(ignored)\n")
            continue
        if key in list_dests:
            items = [x.strip() for x in val.split(",") if x.strip()]
            raw.setdefault(key, []).extend(items)
        else:
            raw[key] = val
    for dest, val in raw.items():
        if dest in list_dests:
            cfg[dest] = val  # list of strings
        elif dest in bool_dests:
            cfg[dest] = str(val).lower() in ("1", "true", "yes", "on")
        else:
            conv = actions[dest].type or str
            try:
                cfg[dest] = conv(val)
            except (ValueError, TypeError):
                sys.stderr.write(f"config {path}: bad value for '{dest}': "
                                 f"{val!r} (ignored)\n")
    return cfg


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
                    # Append full-path change (uncapped — keep entire history).
                    entry["changes"].append((ts, last_hops, hops))
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


# ---------------------------------------------------------------------------
# ICMP ping (via the system `ping` binary — no raw sockets / root needed).
# ---------------------------------------------------------------------------
_PING_RTT_RE = re.compile(r"time[=<]\s*([\d.]+)\s*ms", re.IGNORECASE)
_PING_TTL_RE = re.compile(r"ttl[=]?\s*(\d+)", re.IGNORECASE)


def find_ping_cmd():
    """Return a ping 'mode' string for this platform, or None if no binary.

    Modes: 'win' (Windows), 'darwin' (macOS), 'unix' (Linux/other).
    """
    if not shutil.which("ping"):
        return None
    if sys.platform.startswith("win"):
        return "win"
    if sys.platform == "darwin":
        return "darwin"
    return "unix"


def run_ping(host, timeout, mode):
    """Send a single ICMP echo. Returns (rtt_ms_or_None, ttl_or_None, error).

    - rtt is None on packet loss.
    - error is set only on a command-level failure (binary missing, unknown
      host, subprocess error), NOT on ordinary packet loss.

    Flag semantics differ per platform:
      macOS   ping -c 1 -W <ms>   (-W = per-reply wait in milliseconds)
      Linux   ping -c 1 -W <sec>  (-W = per-reply wait in whole seconds)
      Windows ping -n 1 -w <ms>   (-w = per-reply wait in milliseconds)
    """
    if mode is None:
        return None, None, "ping binary not found"
    if mode == "win":
        cmd = ["ping", "-n", "1", "-w", str(int(max(1, timeout * 1000))), host]
    elif mode == "darwin":
        cmd = ["ping", "-c", "1", "-W", str(int(max(1, timeout * 1000))), host]
    else:  # unix / linux
        cmd = ["ping", "-c", "1", "-W", str(int(max(1, round(timeout)))), host]
    # Hard backstop a little beyond the per-reply wait.
    hard = timeout + 3.0
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=hard)
    except subprocess.TimeoutExpired:
        return None, None, None  # treat as loss (no reply within budget)
    except FileNotFoundError as exc:
        return None, None, f"ping binary missing: {exc}"
    except Exception as exc:
        return None, None, f"{type(exc).__name__}: {exc}"

    text = (result.stdout or "") + "\n" + (result.stderr or "")
    rtt_m = _PING_RTT_RE.search(text)
    if rtt_m:
        rtt = float(rtt_m.group(1))
        ttl_m = _PING_TTL_RE.search(text)
        ttl = int(ttl_m.group(1)) if ttl_m else None
        return rtt, ttl, None
    # No RTT -> loss or hard error. Distinguish resolution failures.
    low = text.lower()
    if ("unknown host" in low or "cannot resolve" in low
            or "name or service not known" in low
            or "could not find host" in low):
        return None, None, "unknown host"
    # Ordinary packet loss (100% loss / timeout). Not an error.
    return None, None, None


def ping_worker(host, interval, timeout, mode,
                ping_state, lock, stop_event, log_f, log_lock):
    """Periodically ICMP-ping `host`, recording RTT / loss / TTL changes.

    Terminal output is intentionally quiet: it only announces the first loss
    of a streak, recovery, TTL changes, and hard errors. Every result is
    written to the log file as a `# ping` event line.
    """
    while not stop_event.is_set():
        rtt, ttl, err = run_ping(host, timeout, mode)
        now_dt = datetime.now()
        ts = now_dt.isoformat(timespec="milliseconds")
        msg = None
        with lock:
            entry = ping_state[host]
            entry["sent"] += 1
            if err:
                entry["errors"].append((ts, err))
                entry["lost"] += 1
                entry["consecutive_losses"] += 1
                entry["max_consecutive_losses"] = max(
                    entry["max_consecutive_losses"], entry["consecutive_losses"])
                msg = f"[{ts}] PING    {host:<30} ERROR  {err}"
                log_kind, log_val = "ERROR", err
                cur_reach, reach_detail = "DOWN", f"error: {err}"
            elif rtt is None:
                entry["lost"] += 1
                entry["consecutive_losses"] += 1
                entry["max_consecutive_losses"] = max(
                    entry["max_consecutive_losses"], entry["consecutive_losses"])
                # Only announce the first loss of a streak on the terminal.
                if entry["consecutive_losses"] == 1:
                    msg = f"[{ts}] PING    {host:<30} *LOSS*  (no reply)"
                log_kind, log_val = "LOSS", ""
                cur_reach, reach_detail = "DOWN", "no reply"
            else:
                prev_streak = entry["consecutive_losses"]
                entry["consecutive_losses"] = 0
                entry["recv"] += 1
                entry["rtt_total"] += rtt
                entry["rtt_min"] = min(entry["rtt_min"], rtt)
                entry["rtt_max"] = max(entry["rtt_max"], rtt)
                entry["rtts"].append(rtt)
                if ttl is not None:
                    entry["ttls"][ttl] += 1
                    if entry["last_ttl"] is not None and entry["last_ttl"] != ttl:
                        entry["ttl_changes"].append((ts, entry["last_ttl"], ttl))
                        msg = (f"[{ts}] PING    {host:<30} *TTL CHANGE* "
                               f"{entry['last_ttl']} -> {ttl}  rtt={rtt:.1f}ms")
                    entry["last_ttl"] = ttl
                # Recovery announcement after a loss streak (unless TTL already spoke).
                if prev_streak > 0 and msg is None:
                    msg = (f"[{ts}] PING    {host:<30} RECOVERED after "
                           f"{prev_streak} lost  rtt={rtt:.1f}ms"
                           + (f" ttl={ttl}" if ttl is not None else ""))
                log_kind = "OK"
                log_val = (f"rtt={rtt:.1f}ms"
                           + (f" ttl={ttl}" if ttl is not None else ""))
                cur_reach = "UP"
                reach_detail = (f"rtt={rtt:.1f}ms"
                                + (f" ttl={ttl}" if ttl is not None else ""))

            # Reachability (UP<->DOWN) transition tracking, mirroring the URL
            # status-change log. The first probe just sets the baseline state.
            prev_reach = entry["reach_state"]
            if prev_reach is None:
                entry["reach_state"] = cur_reach
                entry["reach_since"] = now_dt
            elif prev_reach != cur_reach:
                prev_lasted = (now_dt - entry["reach_since"]).total_seconds()
                entry["reach_changes"].append(
                    (ts, prev_reach, cur_reach, prev_lasted, reach_detail))
                entry["reach_state"] = cur_reach
                entry["reach_since"] = now_dt
        if msg:
            print(msg)
        with log_lock:
            log_f.write(f"# ping\t{ts}\t{host}\t{log_kind}\t{log_val}\n")
        # Sleep with responsiveness to stop signal.
        slept = 0.0
        while slept < interval and not stop_event.is_set():
            chunk = min(0.5, interval - slept)
            time.sleep(chunk)
            slept += chunk


# ---------------------------------------------------------------------------
# DNS resolution tracking via the system `nslookup` binary.
# ---------------------------------------------------------------------------
# An answer line is "Address: <ip>" (no port); the server line is
# "Address:\t<ip>#53" (has '#'), which we skip.
_NS_ADDR_RE = re.compile(r"^Address(?:es)?:\s*(\S+)", re.IGNORECASE)


def find_nslookup_cmd():
    """Return 'nslookup' if available, else None."""
    return "nslookup" if shutil.which("nslookup") else None


def run_nslookup(host, server, timeout):
    """Resolve `host` via `server` using nslookup.

    Returns (sorted_ip_tuple, error_or_None). `server` may be the sentinel
    "system" to use the OS default resolver (no server argument).
    """
    if not shutil.which("nslookup"):
        return None, "nslookup binary not found"
    cmd = ["nslookup", host]
    if server and server != "system":
        cmd.append(server)
    try:
        result = subprocess.run(cmd, capture_output=True, text=True,
                                timeout=timeout)
    except subprocess.TimeoutExpired:
        return None, f"nslookup timed out after {timeout}s"
    except FileNotFoundError as exc:
        return None, f"nslookup binary missing: {exc}"
    except Exception as exc:
        return None, f"{type(exc).__name__}: {exc}"

    text = (result.stdout or "") + "\n" + (result.stderr or "")
    low = text.lower()
    if "nxdomain" in low or "can't find" in low or "no answer" in low:
        return None, "NXDOMAIN / no answer"
    if "no servers could be reached" in low or "connection timed out" in low:
        return None, "server unreachable"
    if "servfail" in low:
        return None, "SERVFAIL"

    ips = []
    # Skip the header block (Server:/Address:#53) — the answer Address lines
    # do not carry a '#port' suffix.
    for line in text.splitlines():
        m = _NS_ADDR_RE.match(line.strip())
        if not m:
            continue
        val = m.group(1)
        if "#" in val:
            continue  # server address line
        ips.append(val)
    if not ips:
        # Non-zero exit or unparseable output → surface last stderr line.
        if result.returncode != 0 and result.stderr.strip():
            return None, result.stderr.strip().splitlines()[-1]
        return None, "no addresses returned"
    return tuple(sorted(set(ips))), None


def nslookup_worker(host, servers, interval, timeout, ns_state,
                    lock, stop_event, log_f, log_lock):
    """Periodically resolve `host` via each DNS server, recording IP-set
    changes. IPs are compared as a sorted set, so DNS round-robin reordering
    is not counted as a change — only genuine membership changes are.
    """
    last = {srv: None for srv in servers}
    while not stop_event.is_set():
        for server in servers:
            if stop_event.is_set():
                break
            ips, err = run_nslookup(host, server, timeout)
            ts = datetime.now().isoformat(timespec="milliseconds")
            msg = None
            with lock:
                entry = ns_state[host][server]
                entry["runs"] += 1
                if err:
                    entry["errors"].append((ts, err))
                    log_kind, log_val = "ERROR", err
                    msg = f"[{ts}] NSLOOKUP {host:<28} @{server:<15} ERROR  {err}"
                else:
                    entry["current"] = ips
                    prev = last[server]
                    if prev is None:
                        entry["initial"] = ips
                        log_kind = "INITIAL"
                        log_val = ",".join(ips)
                        msg = (f"[{ts}] NSLOOKUP {host:<28} @{server:<15} "
                               f"INITIAL {len(ips)} ip(s): {', '.join(ips)}")
                    elif prev != ips:
                        entry["total_changes"] += 1
                        entry["changes"].append((ts, prev, ips))
                        log_kind = "CHANGE"
                        log_val = ",".join(ips)
                        added = [i for i in ips if i not in prev]
                        removed = [i for i in prev if i not in ips]
                        brief = []
                        if added:
                            brief.append("+" + ",".join(added))
                        if removed:
                            brief.append("-" + ",".join(removed))
                        msg = (f"[{ts}] NSLOOKUP {host:<28} @{server:<15} "
                               f"*DNS CHANGE* {' '.join(brief)}")
                    else:
                        log_kind = None  # unchanged, stay quiet
                    last[server] = ips
            if msg:
                print(msg)
            if log_kind:
                with log_lock:
                    log_f.write(
                        f"# nslookup\t{ts}\t{host}\t{server}\t{log_kind}\t{log_val}\n")
        # Sleep with responsiveness to stop signal.
        slept = 0.0
        while slept < interval and not stop_event.is_set():
            chunk = min(0.5, interval - slept)
            time.sleep(chunk)
            slept += chunk


# ---------------------------------------------------------------------------
# TCP ping — measure a TCP connect (handshake) to host:port. Works where
# ICMP is filtered and tests the actual service port. Pure stdlib sockets.
# ---------------------------------------------------------------------------
def _classify_tcp_error(exc):
    """Short label for a TCP connect failure."""
    if isinstance(exc, (socket.timeout, TimeoutError)):
        return "timeout"
    if isinstance(exc, ConnectionRefusedError):
        return "refused"
    if isinstance(exc, socket.gaierror):
        return "dns failure"
    if isinstance(exc, ConnectionResetError):
        return "reset"
    if isinstance(exc, OSError):
        en = getattr(exc, "errno", None)
        if en in (errno.EHOSTUNREACH, errno.ENETUNREACH):
            return "unreachable"
        return exc.strerror or f"errno {en}"
    return type(exc).__name__


def run_tcp_ping(host, port, timeout):
    """Attempt a TCP connect to host:port. Returns (connect_ms_or_None, err).

    connect_ms is None on failure; err is a short label (None on success).
    """
    started = time.monotonic()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            elapsed_ms = (time.monotonic() - started) * 1000
        return elapsed_ms, None
    except Exception as exc:
        return None, _classify_tcp_error(exc)


def tcp_ping_worker(host, port, interval, timeout,
                    tcp_state, lock, stop_event, log_f, log_lock):
    """Periodically TCP-connect to host:port, recording connect time / loss /
    reachability (UP<->DOWN) transitions. Terminal output is quiet: only the
    first failure of a streak, recovery, and errors are announced."""
    while not stop_event.is_set():
        connect_ms, err = run_tcp_ping(host, port, timeout)
        now_dt = datetime.now()
        ts = now_dt.isoformat(timespec="milliseconds")
        msg = None
        with lock:
            entry = tcp_state[host]
            entry["sent"] += 1
            if err is not None:
                entry["lost"] += 1
                entry["consecutive_losses"] += 1
                entry["max_consecutive_losses"] = max(
                    entry["max_consecutive_losses"], entry["consecutive_losses"])
                entry["fail_reasons"][err] += 1
                # Only announce the first failure of a streak.
                if entry["consecutive_losses"] == 1:
                    msg = (f"[{ts}] TCPPING {host + ':' + str(port):<28} "
                           f"*FAIL*  {err}")
                log_kind, log_val = "FAIL", err
                cur_reach, reach_detail = "DOWN", err
            else:
                prev_streak = entry["consecutive_losses"]
                entry["consecutive_losses"] = 0
                entry["recv"] += 1
                entry["ct_total"] += connect_ms
                entry["ct_min"] = min(entry["ct_min"], connect_ms)
                entry["ct_max"] = max(entry["ct_max"], connect_ms)
                entry["cts"].append(connect_ms)
                if prev_streak > 0:
                    msg = (f"[{ts}] TCPPING {host + ':' + str(port):<28} "
                           f"RECOVERED after {prev_streak} fail  "
                           f"{connect_ms:.1f}ms")
                log_kind = "OK"
                log_val = f"connect={connect_ms:.1f}ms"
                cur_reach, reach_detail = "UP", f"{connect_ms:.1f}ms"

            # Reachability transition tracking (mirrors ICMP ping / URL log).
            prev_reach = entry["reach_state"]
            if prev_reach is None:
                entry["reach_state"] = cur_reach
                entry["reach_since"] = now_dt
            elif prev_reach != cur_reach:
                prev_lasted = (now_dt - entry["reach_since"]).total_seconds()
                entry["reach_changes"].append(
                    (ts, prev_reach, cur_reach, prev_lasted, reach_detail))
                entry["reach_state"] = cur_reach
                entry["reach_since"] = now_dt
        if msg:
            print(msg)
        with log_lock:
            log_f.write(f"# tcpping\t{ts}\t{host}:{port}\t{log_kind}\t{log_val}\n")
        # Sleep with responsiveness to stop signal.
        slept = 0.0
        while slept < interval and not stop_event.is_set():
            chunk = min(0.5, interval - slept)
            time.sleep(chunk)
            slept += chunk


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
                  ping_state, tcp_state, ns_state, dns_servers, url_hosts,
                  started_at, ended_at, total_requests):
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

            # ---- Path change history (compact one-line entries) ------
            if ch:
                lines.append(f"  Change history ({len(ch)}):")
                for idx, (ts, prev_hops, curr_hops) in enumerate(ch, start=1):
                    diff_desc = _hops_diff_brief(prev_hops, curr_hops)
                    lines.append(
                        f"    #{idx}  {ts}  "
                        f"({len(prev_hops)} -> {len(curr_hops)} hops)  "
                        f"{diff_desc}")

            # Error table (last 5).
            if errs:
                lines.append(f"  Errors (last {min(5, len(errs))} of {len(errs)}):")
                body = [[ts, err] for ts, err in errs[-5:]]
                lines.extend(_render_table(["Timestamp", "Error"], body))

            lines.append("")
        if not any_data:
            lines.append("(no traceroute results yet)")
    lines.append("")

    # -- ICMP ping statistics -----------------------------------------------
    lines.append("Per-Host ICMP Ping")
    lines.append("-" * 60)
    if not ping_state:
        lines.append("(icmp ping disabled)")
    else:
        any_ping = False
        for url in urls:
            host = url_hosts.get(url)
            if not host or host not in ping_state:
                continue
            p = ping_state[host]
            sent = p.get("sent", 0)
            if sent == 0:
                continue
            any_ping = True
            recv = p.get("recv", 0)
            lost = p.get("lost", 0)
            loss_pct = (lost / sent * 100) if sent else 0.0
            lines.append(
                f"URL: {url}  (host: {host})")
            lines.append(
                f"  sent={sent}  recv={recv}  lost={lost}  "
                f"({loss_pct:.2f}% loss)  "
                f"max consecutive loss={p.get('max_consecutive_losses', 0)}")
            # Reachability (UP<->DOWN) change table, mirroring the URL log.
            reach_changes = p.get("reach_changes", [])
            if reach_changes:
                lines.append(f"  Reachability changes ({len(reach_changes)}):")
                body = [[ts, frm, to, f"{dur:.1f}s", detail]
                        for ts, frm, to, dur, detail in reach_changes]
                lines.extend(_render_table(
                    ["Timestamp", "From", "To", "Prev lasted", "Detail"], body))
            if recv > 0:
                avg = p["rtt_total"] / recv
                lines.append(
                    f"  rtt ms      : min={p['rtt_min']:.1f}  "
                    f"avg={avg:.1f}  max={p['rtt_max']:.1f}")
                samples = sorted(p.get("rtts", []))
                if samples:
                    lines.append(
                        f"  percentiles : p50={percentile(samples, 50):.1f}  "
                        f"p95={percentile(samples, 95):.1f}  "
                        f"p99={percentile(samples, 99):.1f}  (n={len(samples)})")
            else:
                lines.append("  rtt ms      : (no replies)")
            ttls = p.get("ttls", {})
            if ttls:
                lines.append("  TTL breakdown:")
                for ttl in sorted(ttls):
                    lines.append(f"    {ttl:<5} : {ttls[ttl]}")
            ttl_changes = p.get("ttl_changes", [])
            if ttl_changes:
                lines.append(f"  TTL changes ({len(ttl_changes)}):")
                body = [[ts, str(old), str(new)] for ts, old, new in ttl_changes]
                lines.extend(_render_table(
                    ["Timestamp", "Old TTL", "New TTL"], body))
            errs = p.get("errors", [])
            if errs:
                lines.append(f"  Errors (last {min(5, len(errs))} of {len(errs)}):")
                body = [[ts, err] for ts, err in errs[-5:]]
                lines.extend(_render_table(["Timestamp", "Error"], body))
            lines.append("")
        if not any_ping:
            lines.append("(no ping results yet)")
    lines.append("")

    # -- TCP ping (connect probe) -------------------------------------------
    lines.append("Per-Host TCP Ping")
    lines.append("-" * 60)
    if not tcp_state:
        lines.append("(tcp ping disabled)")
    else:
        any_tcp = False
        for url in urls:
            host = url_hosts.get(url)
            if not host or host not in tcp_state:
                continue
            p = tcp_state[host]
            sent = p.get("sent", 0)
            if sent == 0:
                continue
            any_tcp = True
            port = p.get("port")
            recv = p.get("recv", 0)
            lost = p.get("lost", 0)
            loss_pct = (lost / sent * 100) if sent else 0.0
            lines.append(f"URL: {url}  (host: {host}:{port})")
            lines.append(
                f"  sent={sent}  recv={recv}  lost={lost}  "
                f"({loss_pct:.2f}% loss)  "
                f"max consecutive loss={p.get('max_consecutive_losses', 0)}")
            reach_changes = p.get("reach_changes", [])
            if reach_changes:
                lines.append(f"  Reachability changes ({len(reach_changes)}):")
                body = [[ts, frm, to, f"{dur:.1f}s", detail]
                        for ts, frm, to, dur, detail in reach_changes]
                lines.extend(_render_table(
                    ["Timestamp", "From", "To", "Prev lasted", "Detail"], body))
            if recv > 0:
                avg = p["ct_total"] / recv
                lines.append(
                    f"  connect ms  : min={p['ct_min']:.1f}  "
                    f"avg={avg:.1f}  max={p['ct_max']:.1f}")
                samples = sorted(p.get("cts", []))
                if samples:
                    lines.append(
                        f"  percentiles : p50={percentile(samples, 50):.1f}  "
                        f"p95={percentile(samples, 95):.1f}  "
                        f"p99={percentile(samples, 99):.1f}  (n={len(samples)})")
            else:
                lines.append("  connect ms  : (no successful connects)")
            reasons = p.get("fail_reasons", {})
            if reasons:
                lines.append("  failure breakdown:")
                for r in sorted(reasons, key=lambda k: -reasons[k]):
                    lines.append(f"    {r:<12} : {reasons[r]}")
            lines.append("")
        if not any_tcp:
            lines.append("(no tcp ping results yet)")
    lines.append("")

    # -- DNS resolution (nslookup) ------------------------------------------
    lines.append("Per-Host DNS Resolution (nslookup)")
    lines.append("-" * 60)
    if not ns_state:
        lines.append("(nslookup disabled)")
    else:
        any_ns = False
        for url in urls:
            host = url_hosts.get(url)
            if not host or host not in ns_state:
                continue
            servers = ns_state[host]
            # Skip hosts that produced nothing at all.
            if not any(sv.get("runs", 0) for sv in servers.values()):
                continue
            any_ns = True
            lines.append(f"URL: {url}  (host: {host})")
            # Per-server one-line status.
            for srv in dns_servers:
                sv = servers.get(srv)
                if not sv:
                    continue
                cur = sv.get("current")
                cur_str = ", ".join(cur) if cur else "(none)"
                lines.append(
                    f"  via {srv:<15} : runs={sv.get('runs', 0)}  "
                    f"changes={sv.get('total_changes', 0)}  "
                    f"errors={len(sv.get('errors', []))}  "
                    f"current=[{cur_str}]")
            # Combined resolution-change table across all servers for this host.
            rows = []
            for srv in dns_servers:
                sv = servers.get(srv)
                if not sv:
                    continue
                for ts, old, new in sv.get("changes", []):
                    rows.append([ts, srv, ", ".join(old), ", ".join(new)])
            if rows:
                rows.sort(key=lambda r: r[0])
                lines.append(f"  Resolution changes ({len(rows)}):")
                lines.extend(_render_table(
                    ["Timestamp", "DNS Server", "Old IPs", "New IPs"], rows))
            # Combined error table (last 5 across servers).
            err_rows = []
            for srv in dns_servers:
                sv = servers.get(srv)
                if not sv:
                    continue
                for ts, err in sv.get("errors", []):
                    err_rows.append([ts, srv, err])
            if err_rows:
                err_rows.sort(key=lambda r: r[0])
                shown = err_rows[-5:]
                lines.append(f"  Errors (last {len(shown)} of {len(err_rows)}):")
                lines.extend(_render_table(
                    ["Timestamp", "DNS Server", "Error"], shown))
            lines.append("")
        if not any_ns:
            lines.append("(no nslookup results yet)")
    lines.append("")

    Path(path).write_text("\n".join(lines))


def main():
    parser = argparse.ArgumentParser(
        description="Repeatedly probe HTTP/HTTPS URLs and log status codes.")
    parser.add_argument("--config", default="config.txt",
                        help="Config file with command params + dns servers "
                             "(default: config.txt if present).")
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
    parser.add_argument("--ping-interval", type=float, default=0.0,
                        help="ICMP-ping each host every N seconds "
                             "(default: 0 = disabled; suggested: 1-5).")
    parser.add_argument("--ping-timeout", type=float, default=2.0,
                        help="Per-ping reply wait in seconds (default: 2).")
    parser.add_argument("--tcp-interval", type=float, default=0.0,
                        help="TCP-connect probe each host every N seconds "
                             "(default: 0 = disabled; suggested: 1-5).")
    parser.add_argument("--tcp-port", type=int, default=0,
                        help="Port for TCP ping (default: 0 = derive from each "
                             "URL's scheme/port, e.g. https=443, http=80).")
    parser.add_argument("--tcp-timeout", type=float, default=2.0,
                        help="Per TCP-connect timeout in seconds (default: 2).")
    parser.add_argument("--dns-server", action="append", default=[],
                        help="DNS server for nslookup queries (repeatable; "
                             "also settable in config as dns-server).")
    parser.add_argument("--nslookup-interval", type=float, default=0.0,
                        help="nslookup each host every N seconds "
                             "(default: 0 = disabled; suggested: 5-30).")
    parser.add_argument("--nslookup-timeout", type=float, default=5.0,
                        help="Per-nslookup timeout in seconds (default: 5).")

    # Resolve the config path from the command line first, then fold config
    # values in as defaults so explicit CLI args still win.
    pre = argparse.ArgumentParser(add_help=False)
    pre.add_argument("--config", default="config.txt")
    pre_args, _ = pre.parse_known_args()
    cfg = load_config(pre_args.config, parser)
    if cfg:
        parser.set_defaults(**cfg)

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

    # Unique hosts, preserving first-seen order (shared by tracert / ping / tcp).
    unique_hosts = []
    seen_hosts = set()
    for h in url_hosts.values():
        if h not in seen_hosts:
            seen_hosts.add(h)
            unique_hosts.append(h)

    # Derive a TCP port per host: --tcp-port overrides; else the port of the
    # first URL that maps to that host (https=443, http=80, or explicit).
    host_ports = {}
    for u in urls:
        parsed = urlparse(u)
        h = parsed.hostname
        if not h or h in host_ports:
            continue
        if args.tcp_port:
            host_ports[h] = args.tcp_port
        else:
            host_ports[h] = parsed.port or (443 if parsed.scheme == "https"
                                            else 80)

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
            for h in unique_hosts:
                tracert_state[h] = {"initial": None, "latest": None,
                                    "snapshots": [],
                                    "changes": [], "errors": [], "runs": 0,
                                    "total_changes": 0}

    # Set up ping workers (one per unique host) if enabled.
    ping_state = {}
    ping_threads = []
    ping_stop = threading.Event()
    ping_lock = threading.Lock()
    ping_mode = None
    if args.ping_interval > 0:
        ping_mode = find_ping_cmd()
        if ping_mode is None:
            print("WARNING: ping binary not found — ICMP ping disabled.")
        else:
            for h in unique_hosts:
                ping_state[h] = {"sent": 0, "recv": 0, "lost": 0,
                                 "rtts": [], "rtt_total": 0.0,
                                 "rtt_min": float("inf"), "rtt_max": 0.0,
                                 "ttls": defaultdict(int), "last_ttl": None,
                                 "ttl_changes": [],
                                 "consecutive_losses": 0,
                                 "max_consecutive_losses": 0,
                                 "reach_state": None, "reach_since": None,
                                 "reach_changes": [],
                                 "errors": []}

    # Set up TCP-ping workers (one per unique host) if enabled.
    tcp_state = {}
    tcp_threads = []
    tcp_stop = threading.Event()
    tcp_lock = threading.Lock()
    if args.tcp_interval > 0:
        for h in unique_hosts:
            tcp_state[h] = {"port": host_ports.get(h, 80),
                            "sent": 0, "recv": 0, "lost": 0,
                            "cts": [], "ct_total": 0.0,
                            "ct_min": float("inf"), "ct_max": 0.0,
                            "consecutive_losses": 0,
                            "max_consecutive_losses": 0,
                            "reach_state": None, "reach_since": None,
                            "reach_changes": [],
                            "fail_reasons": defaultdict(int)}

    # Set up nslookup workers (one per unique host) if enabled.
    ns_state = {}
    ns_threads = []
    ns_stop = threading.Event()
    ns_lock = threading.Lock()
    # De-dup DNS servers, preserving order; fall back to system resolver.
    dns_servers = []
    for srv in args.dns_server:
        srv = srv.strip()
        if srv and srv not in dns_servers:
            dns_servers.append(srv)
    if not dns_servers:
        dns_servers = ["system"]
    if args.nslookup_interval > 0:
        if find_nslookup_cmd() is None:
            print("WARNING: nslookup binary not found — DNS tracking disabled.")
        else:
            for h in unique_hosts:
                ns_state[h] = {srv: {"runs": 0, "initial": None,
                                     "current": None, "changes": [],
                                     "errors": [], "total_changes": 0}
                               for srv in dns_servers}

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
    if ping_state:
        print(f"ICMP ping: every {args.ping_interval}s for "
              f"{len(ping_state)} host(s) (wait {args.ping_timeout}s)")
    if tcp_state:
        ports = sorted({e["port"] for e in tcp_state.values()})
        print(f"TCP ping: every {args.tcp_interval}s for "
              f"{len(tcp_state)} host(s) on port(s) "
              f"{', '.join(map(str, ports))} (wait {args.tcp_timeout}s)")
    if ns_state:
        print(f"nslookup: every {args.nslookup_interval}s for "
              f"{len(ns_state)} host(s) via {len(dns_servers)} server(s) "
              f"[{', '.join(dns_servers)}]")

    log_f = open(args.log, "w", buffering=1)
    log_f.write(f"# HTTP monitor log — started {started_at.isoformat(timespec='seconds')}\n")
    log_f.write(f"# {VERSION_BANNER}\n")
    log_f.write(f"# {COPYRIGHT_NOTICE}\n")
    log_f.write("# Per-request rows:  timestamp\\tstatus\\tlatency_ms\\tip\\turl\\tdetail\n")
    log_f.write("# Event lines: '# latency', '# tracert', '# ping', '# tcpping', '# nslookup'.\n")
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

    # Start ping workers.
    if ping_state:
        for h in ping_state.keys():
            t = threading.Thread(
                target=ping_worker,
                args=(h, args.ping_interval, args.ping_timeout, ping_mode,
                      ping_state, ping_lock, ping_stop, log_f, log_lock),
                name=f"ping-{h}", daemon=True)
            t.start()
            ping_threads.append(t)

    # Start TCP-ping workers.
    if tcp_state:
        for h in tcp_state.keys():
            t = threading.Thread(
                target=tcp_ping_worker,
                args=(h, tcp_state[h]["port"], args.tcp_interval,
                      args.tcp_timeout, tcp_state, tcp_lock, tcp_stop,
                      log_f, log_lock),
                name=f"tcpping-{h}", daemon=True)
            t.start()
            tcp_threads.append(t)

    # Start nslookup workers.
    if ns_state:
        for h in ns_state.keys():
            t = threading.Thread(
                target=nslookup_worker,
                args=(h, dns_servers, args.nslookup_interval,
                      args.nslookup_timeout, ns_state, ns_lock, ns_stop,
                      log_f, log_lock),
                name=f"nslookup-{h}", daemon=True)
            t.start()
            ns_threads.append(t)

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
        # Signal background workers and give them a moment to exit cleanly.
        tracert_stop.set()
        ping_stop.set()
        tcp_stop.set()
        ns_stop.set()
        for t in tracert_threads:
            t.join(timeout=2.0)
        for t in ping_threads:
            t.join(timeout=2.0)
        for t in tcp_threads:
            t.join(timeout=2.0)
        for t in ns_threads:
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
        # Snapshot ping state under the lock for a consistent summary.
        with ping_lock:
            ping_snapshot = {
                h: {"sent": v.get("sent", 0), "recv": v.get("recv", 0),
                    "lost": v.get("lost", 0),
                    "rtts": list(v.get("rtts", [])),
                    "rtt_total": v.get("rtt_total", 0.0),
                    "rtt_min": v.get("rtt_min", float("inf")),
                    "rtt_max": v.get("rtt_max", 0.0),
                    "ttls": dict(v.get("ttls", {})),
                    "last_ttl": v.get("last_ttl"),
                    "ttl_changes": list(v.get("ttl_changes", [])),
                    "reach_changes": list(v.get("reach_changes", [])),
                    "max_consecutive_losses": v.get("max_consecutive_losses", 0),
                    "errors": list(v.get("errors", []))}
                for h, v in ping_state.items()}
        # Snapshot TCP-ping state under the lock for a consistent summary.
        with tcp_lock:
            tcp_snapshot = {
                h: {"port": v.get("port"),
                    "sent": v.get("sent", 0), "recv": v.get("recv", 0),
                    "lost": v.get("lost", 0),
                    "cts": list(v.get("cts", [])),
                    "ct_total": v.get("ct_total", 0.0),
                    "ct_min": v.get("ct_min", float("inf")),
                    "ct_max": v.get("ct_max", 0.0),
                    "reach_changes": list(v.get("reach_changes", [])),
                    "max_consecutive_losses": v.get("max_consecutive_losses", 0),
                    "fail_reasons": dict(v.get("fail_reasons", {}))}
                for h, v in tcp_state.items()}
        # Snapshot nslookup state under the lock for a consistent summary.
        with ns_lock:
            ns_snapshot = {
                h: {srv: {"runs": sv.get("runs", 0),
                          "initial": sv.get("initial"),
                          "current": sv.get("current"),
                          "changes": list(sv.get("changes", [])),
                          "errors": list(sv.get("errors", [])),
                          "total_changes": sv.get("total_changes", 0)}
                    for srv, sv in servers.items()}
                for h, servers in ns_state.items()}
        write_summary(args.summary, urls, stats, changes,
                      latency_events, tracert_snapshot, ping_snapshot,
                      tcp_snapshot, ns_snapshot, dns_servers, url_hosts,
                      started_at, ended_at, total_requests)
        print(f"\nLog saved to {args.log}")
        print(f"Summary saved to {args.summary}")


if __name__ == "__main__":
    main()
