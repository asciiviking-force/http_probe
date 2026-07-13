# http_monitor

**v1.4.1** — released 2026-05-22
Copyright (c) Viking Li &lt;viking.li@walmart.com&gt;

A stand-alone Python 3 monitoring tool that repeatedly probes HTTP/HTTPS
endpoints, classifies each outcome, detects latency anomalies, tracks
traceroute path changes, and runs optional ICMP-ping probes — all written
to a live terminal stream, a tab-separated per-request log, and a
human-readable summary on exit.

Uses only the Python standard library. No `pip install` required.

---

## Highlights

- **Concurrent probes** — every URL in a round is fired at the same time;
  a slow or timing-out URL never blocks the others.
- **Specific status labels** — beyond the numeric HTTP code, failures are
  classified as `TIMEOUT`, `DENIED`, `DNS`, `SSL`, `RESET`, `UNREACH`,
  `CONNERR`, or `ERR`.
- **Resolved-IP tracking** — every probe records the IP it actually used;
  an IP change (e.g. DNS round-robin) is treated as a status change.
- **Latency anomaly detection** — per-URL rolling baseline; significant
  spikes are flagged inline and tabled in the summary.
- **Traceroute path tracking** — background worker per host runs
  `traceroute` / `tracert` on an interval and records hop-path changes.
  Up to **8 path snapshots** are kept per host (initial + latest always
  preserved); **every** path change is recorded in a compact
  one-line-per-change history with a brief hop-level diff.
- **ICMP ping** — optional background worker per host runs the system
  `ping` binary on an interval (no root/raw sockets needed) and records
  RTT (min/avg/max + p50/p95/p99), packet loss, max consecutive loss,
  TTL breakdown, plus **reachability (UP↔DOWN) and TTL change tables**
  — same style as the URL Status Change Log.
- **Three output streams** — terminal, `log.txt`, and `summary.txt`,
  all carrying the version and copyright headers.

---

## Requirements

- Python 3.8+ (developed on 3.14)
- For optional traceroute tracking: `traceroute` on macOS/Linux or
  `tracert` on Windows must be present on `PATH`. ICMP-based traceroute
  may require elevated privileges on some systems.
- For optional ICMP ping: the system `ping` binary must be on `PATH`
  (present by default on macOS/Linux/Windows). It is normally setuid /
  setcap, so **no root is required**.

---

## Installation

No installation needed — just place `http_monitor.py` somewhere convenient
and run it.

```bash
chmod +x http_monitor.py
./http_monitor.py --help
```

To install the man page system-wide:

```bash
sudo install -m 0644 http_monitor.1 /usr/local/share/man/man1/
man http_monitor
```

---

## Quick start

Probe a single URL once a second until you stop it:

```bash
python3 http_monitor.py -u https://example.com -i 1
```

Probe every URL listed in `url.txt`, 100 rounds, one round per second,
with 60-second traceroutes running in the background:

```bash
python3 http_monitor.py -f url.txt -i 1 -c 100 --tracert-interval 60
```

Sample `url.txt`:

```
# one URL per line, blank/#-comment lines are ignored
https://www.google.com
https://api.example.com/health
https://internal.service.local:8443/status
```

---

## Command-line options

### Targets

| Option | Description |
|---|---|
| `-u, --url URL` | URL to probe (may be repeated). |
| `-f, --file FILE` | Read URLs from `FILE`, one per line. Falls back to `./url.txt` if neither `-u` nor `-f` is given. |

### Scheduling

| Option | Default | Description |
|---|---|---|
| `-i, --interval SECONDS` | `1.0` | Seconds between probe **rounds**. |
| `-c, --count N` | `0` | Stop after `N` rounds. `0` = run forever. |
| `-t, --timeout SECONDS` | `10` | Per-request timeout. |

### Transport

| Option | Description |
|---|---|
| `-k, --insecure` | Skip TLS certificate verification. |

### Output files

| Option | Default | Description |
|---|---|---|
| `--log PATH` | `log.txt` | Per-request tab-separated log + event lines. |
| `--summary PATH` | `summary.txt` | Summary written on exit. |

### Latency anomaly detection

| Option | Default | Description |
|---|---|---|
| `--latency-window N` | `10` | Rolling window (samples) for baseline. |
| `--latency-factor F` | `2.0` | Anomaly when `observed >= F * baseline`. |
| `--latency-min-delta-ms MS` | `50` | Plus `observed - baseline >= MS`. |

### Traceroute path tracking

| Option | Default | Description |
|---|---|---|
| `--tracert-interval SECONDS` | `0` (off) | Run traceroute per host every N seconds. |
| `--tracert-max-hops N` | `20` | Max hops per traceroute run. |
| `--tracert-timeout SECONDS` | `30` | Per-run timeout for the traceroute process. |

### ICMP ping

| Option | Default | Description |
|---|---|---|
| `--ping-interval SECONDS` | `0` (off) | ICMP-ping each host every N seconds. |
| `--ping-timeout SECONDS` | `2` | Per-ping reply wait. |

---

## Outputs

### Terminal stream

```
============================================================
HTTP/HTTPS Monitor v1.4.1  (released 2026-05-22)
Copyright (c) Viking Li - viking.li@walmart.com
Run started: 2026-05-21T15:47:16
============================================================
Monitoring 2 URL(s) every 1.0s. Press Ctrl+C to stop.
  - https://www.google.com
  - https://httpbin.org
Tracert: every 60.0s for 2 host(s) (max 20 hops)
[2026-05-21T15:47:16.789]     200    596.1ms  142.251.154.119  https://www.google.com
[2026-05-21T15:47:17.763]     200   1390.7ms  54.209.210.20    https://httpbin.org
[2026-05-21T15:47:20.012]     200   1218.4ms  54.91.177.181    https://httpbin.org  *CHANGE*
[2026-05-21T15:47:25.112]    DNS      0.0ms  -                https://broken.invalid/  dns failure: ...
[2026-05-21T15:47:30.001]     200   2400.0ms  54.91.177.181    https://httpbin.org  *LATENCY 2.05x*
```

Each line carries:

```
[timestamp] status latency_ms ip url [detail] [*CHANGE*] [*LATENCY F.FFx*]
```

`status` is the numeric HTTP code on a real response, or one of the
classified failure labels:

| Label | Meaning |
|---|---|
| `TIMEOUT` | Socket / read timeout |
| `DENIED` | Connection refused (also tagged in detail for HTTP 401/403) |
| `DNS` | Name resolution failure |
| `SSL` | TLS / certificate error |
| `RESET` | Connection reset by peer |
| `UNREACH` | Network unreachable |
| `CONNERR` | Other `ConnectionError` |
| `ERR` | Anything else (with exception detail) |

### log.txt

Tab-separated, one row per request, plus annotated event lines:

```
# HTTP monitor log — started 2026-05-21T15:47:16
# HTTP/HTTPS Monitor v1.4.1  (released 2026-05-22)
# Copyright (c) Viking Li - viking.li@walmart.com
# timestamp	status	latency_ms	ip	url	detail
2026-05-21T15:47:16.789	200	596.1	142.251.154.119	https://www.google.com	
2026-05-21T15:47:17.763	200	1390.7	54.209.210.20	https://httpbin.org	
# latency	2026-05-21T15:47:30.001	https://httpbin.org	baseline=1170.5ms	observed=2400.0ms	factor=2.05	ip=54.91.177.181
# tracert	2026-05-21T15:48:16.000	httpbin.org	CHANGE	10.x -> 10.y -> 18.z -> ...
# ping	2026-05-21T15:47:17.100	www.google.com	OK	rtt=12.4ms ttl=115
# ping	2026-05-21T15:47:18.100	www.google.com	LOSS	
```

Event line kinds: `# latency`, `# tracert`, and `# ping`. Ping lines are
`# ping <ts> <host> <OK|LOSS|ERROR> <detail>` — one per ping (OK carries
`rtt=..ms ttl=..`).

### summary.txt

Sections, written on exit:

1. **Header** — title, version, copyright, run window, duration, totals.
2. **Per-URL Statistics** — totals, success rate, latency avg/min/max,
   p50/p95/p99, status code breakdown, resolved IP breakdown.
3. **Status Change Log** — one ASCII table per URL listing each
   `(code, ip)` transition with timestamp.
4. **Latency Anomaly Log** — one ASCII table per URL listing baseline,
   observed, factor, and IP for each anomaly.
5. **Traceroute Path Changes** — per URL/host:
   - A **Path snapshots** table (up to 8 columns) showing each retained
     snapshot side-by-side with hop numbers as rows. The first column is
     always the initial path, the last column is always the latest path;
     if more than 8 distinct snapshots are taken, the oldest intermediate
     ones are dropped while initial and latest are preserved.
   - A **Change history** section listing every path change observed as
     one compact line — `#N timestamp (oldhops -> newhops) hopX: a->b; ...`
     — with no per-change tables. Uncapped.
   - An **Errors** table with the last 5 traceroute errors (if any).
6. **Per-Host ICMP Ping** — per URL/host: sent/recv/lost with loss %,
   max consecutive loss, RTT min/avg/max, p50/p95/p99, a TTL breakdown,
   and three ASCII tables — a **Reachability changes** table
   (`Timestamp | From | To | Prev lasted | Detail`, one row per UP↔DOWN
   transition), a **TTL changes** table, and an errors table (last 5).

Truncated example:

```
HTTP/HTTPS Monitor Summary
HTTP/HTTPS Monitor v1.4.1  (released 2026-05-22)
Copyright (c) Viking Li - viking.li@walmart.com
============================================================
Started : 2026-05-21T15:47:16
Ended   : 2026-05-21T15:47:26
Duration: 10.17s
Total requests: 8

Per-URL Statistics
------------------------------------------------------------
https://httpbin.org
  total       : 4
  success     : 4  (100.00%)
  failure     : 0
  latency ms  : avg=1414.5  min=1218.4  max=1680.5
  percentiles : p50=1379.6  p95=1637.0  p99=1671.8  (n=4)
  status code breakdown:
    200      : 4
  resolved IP breakdown:
    18.233.255.213  : 1
    44.216.249.42   : 1
    54.209.210.20   : 1
    54.91.177.181   : 1

Status Change Log
------------------------------------------------------------
URL: https://httpbin.org  (3 change(s))
+-------------------------+------+---------------+-----+----------------+
| Timestamp               | From | From IP       | To  | To IP          |
+-------------------------+------+---------------+-----+----------------+
| 2026-05-21T15:47:20.012 | 200  | 54.209.210.20 | 200 | 54.91.177.181  |
| 2026-05-21T15:47:22.715 | 200  | 54.91.177.181 | 200 | 44.216.249.42  |
| 2026-05-21T15:47:25.112 | 200  | 44.216.249.42 | 200 | 18.233.255.213 |
+-------------------------+------+---------------+-----+----------------+

Traceroute Path Changes
------------------------------------------------------------
URL: https://example.test/  (host: example.test, runs: 13, path changes: 11, errors: 0)
  Path snapshots (keeping 8 of 12; initial + latest always preserved):
+-----+------------+-----------+----------+----------+-----------+-----------+----------+-----------+
| Hop | #1 initial | #2        | #3       | #4       | #5        | #6        | #7       | #8 latest |
|     | 15:00:00   | 15:06:00  | 15:07:00 | 15:08:00 | 15:09:00  | 15:10:00  | 15:11:00 | 15:12:00  |
+-----+------------+-----------+----------+----------+-----------+-----------+----------+-----------+
| 1   | 10.0.0.1   | 10.0.0.1  | 10.0.0.1 | 10.0.0.1 | 10.0.0.1  | 10.0.0.1  | 10.0.0.1 | 10.0.0.1  |
| 2   | 10.0.0.2   | 10.0.0.2  | 10.0.0.2 | 10.0.0.2 | 10.0.0.55 | 10.0.0.42 | 10.0.0.2 | 10.0.0.55 |
| 3   | 10.0.0.3   | 10.0.0.99 | 10.0.0.3 | 10.0.0.3 | 10.0.0.66 | 10.0.0.3  | 10.0.0.3 | 10.0.0.66 |
+-----+------------+-----------+----------+----------+-----------+-----------+----------+-----------+
  Change history (11):
    #1  2026-05-22T15:01:00.000  (5 -> 5 hops)  hop3: 10.0.0.3->10.0.0.99
    #2  2026-05-22T15:02:00.000  (5 -> 5 hops)  hop3: 10.0.0.99->10.0.0.3
    #3  2026-05-22T15:04:00.000  (5 -> 5 hops)  hop2: 10.0.0.2->10.0.0.42
    ... (one compact line per path change, no cap)

Per-Host ICMP Ping
------------------------------------------------------------
URL: https://www.google.com  (host: www.google.com)
  sent=60  recv=57  lost=3  (5.00% loss)  max consecutive loss=3
  Reachability changes (2):
+-------------------------+------+------+-------------+--------------------+
| Timestamp               | From | To   | Prev lasted | Detail             |
+-------------------------+------+------+-------------+--------------------+
| 2026-05-21T15:47:40.001 | UP   | DOWN | 24.0s       | no reply           |
| 2026-05-21T15:47:43.002 | DOWN | UP   | 3.0s        | rtt=13.1ms ttl=115 |
+-------------------------+------+------+-------------+--------------------+
  rtt ms      : min=9.8  avg=12.4  max=41.2
  percentiles : p50=11.9  p95=18.0  p99=33.5  (n=57)
  TTL breakdown:
    115   : 57
  TTL changes (1):
+-------------------------+---------+---------+
| Timestamp               | Old TTL | New TTL |
+-------------------------+---------+---------+
| 2026-05-21T15:47:52.100 | 115     | 116     |
+-------------------------+---------+---------+
```

---

## Examples

```bash
# Probe one URL every 2 seconds, indefinitely.
python3 http_monitor.py -u https://example.com -i 2

# Probe URLs from a file, 100 rounds, 1s apart.
python3 http_monitor.py -f url.txt -i 1 -c 100

# Mix CLI URLs and a file, skip TLS verification.
python3 http_monitor.py -u https://a.example -u https://b.example -k

# Enable traceroute every 60s with a 30s budget per run.
python3 http_monitor.py -f url.txt -i 5 \
    --tracert-interval 60 --tracert-timeout 30 --tracert-max-hops 20

# ICMP-ping every host every 2s alongside HTTP probes.
python3 http_monitor.py -f url.txt -i 5 --ping-interval 2 --ping-timeout 2

# Full picture: HTTP + ping + traceroute together.
python3 http_monitor.py -f url.txt -i 5 \
    --ping-interval 2 --tracert-interval 60

# Tight latency anomaly thresholds for a fast endpoint.
python3 http_monitor.py -u https://api.example/health \
    --latency-window 20 --latency-factor 1.5 --latency-min-delta-ms 20
```

---

## Signal handling

`SIGINT` (Ctrl+C) and `SIGTERM` trigger an orderly shutdown:

1. The current probe round finishes.
2. Traceroute and ping background workers are signalled to stop (2s join
   timeout each).
3. `log.txt` is flushed and closed.
4. `summary.txt` is written.
5. The process exits 0.

---

## Caveats / Notes

- **`http.py` shadow** — a local file named `http.py` in the working
  directory shadows the standard-library `http` package. The script
  detects this at startup and removes its own directory from `sys.path`
  before importing `urllib`.
- **Traceroute privileges** — on some systems the system `traceroute`
  binary uses raw sockets and requires elevated privileges. Errors are
  captured per host in the summary's traceroute error table; the monitor
  itself does not abort.
- **DNS round-robin** — when a host has multiple A records, each probe
  may resolve to a different IP. This is normal behaviour and the
  resulting IP changes will appear in the Status Change Log; suppress
  them by pinning to a single resolver if undesired.
- **Latency baseline ignores failures** — only HTTP responses with a
  numeric status code contribute to the rolling latency window, so DNS
  failures and timeouts do not poison the baseline.

---

## Files in this package

| File | Description |
|---|---|
| `http_monitor.py` | The script. |
| `http_monitor.1` | troff/man page (section 1). |
| `README.md` | This file. |
| `url.txt` | Optional default input file. |
| `log.txt` | Generated per-request log. |
| `summary.txt` | Generated summary. |

---

## Author

Viking Li — &lt;viking.li@walmart.com&gt;

## Copyright

Copyright (c) Viking Li &lt;viking.li@walmart.com&gt;. All rights reserved.
