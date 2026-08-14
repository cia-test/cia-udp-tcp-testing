#!/usr/bin/env python3
"""Summarise the JSON traffic lines the server writes to stdout.

    docker compose logs --no-log-prefix app | python3 test/analyze_traffic.py
    docker compose logs app | python3 test/analyze_traffic.py     # prefixes ok
    python3 test/analyze_traffic.py server.log --ports

Non-JSON lines and any `service-1  | ` log prefix are ignored, so the raw
output of `docker compose logs` can be piped in directly. Use this after an
observation run to decide on ALLOWED_SOURCES and the rate limits.
"""

import argparse
import json
import sys
from collections import defaultdict

EVENT_KEYS = ("n_ok", "n_throttled", "n_blocked", "n_refused_port", "n_no_marker", "n_oversize")


def iter_json_lines(stream):
    """Yield JSON objects, tolerating log prefixes and interleaved output."""
    for line in stream:
        start = line.find("{")
        if start < 0:
            continue
        try:
            yield json.loads(line[start:])
        except ValueError:
            continue


def collect(stream):
    sources = {}
    summary = {"windows": 0, "untracked_sources": 0, "throttled": {}}

    for entry in iter_json_lines(stream):
        kind = entry.get("type")
        if kind == "traffic_summary":
            summary["windows"] += 1
            summary["untracked_sources"] = max(
                summary["untracked_sources"], entry.get("untracked_sources", 0)
            )
            for name, count in (entry.get("throttled") or {}).items():
                summary["throttled"][name] = max(summary["throttled"].get(name, 0), count)
            continue
        if kind != "traffic":
            continue

        key = (entry.get("listener", "?"), entry.get("ip", "?"))
        record = sources.get(key)
        if record is None:
            record = sources[key] = {
                "windows": 0,
                "peak_pps": 0.0,
                "ports": defaultdict(int),
                "first_seen": entry.get("first_seen", ""),
                "last_payload_text": "",
            }
        record["windows"] += 1
        record["peak_pps"] = max(record["peak_pps"], entry.get("pps_window", 0.0))
        # Cumulative fields: the newest line for a source is authoritative.
        for field in ("packets", "bytes", "distinct_source_ports", "last_seen",
                      "last_payload_text", *EVENT_KEYS):
            if field in entry:
                record[field] = entry[field]
        for port, count in (entry.get("source_ports") or {}).items():
            record["ports"][str(port)] = max(record["ports"][str(port)], count)

    return sources, summary


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("logfile", nargs="?", help="log file (default: stdin)")
    parser.add_argument("--ports", action="store_true", help="list source ports per source")
    args = parser.parse_args()

    stream = open(args.logfile) if args.logfile else sys.stdin
    try:
        sources, summary = collect(stream)
    finally:
        if args.logfile:
            stream.close()

    if not sources:
        print("no traffic lines found (is STATS_INTERVAL > 0?)")
        return 1

    rows = sorted(sources.items(), key=lambda kv: -kv[1].get("packets", 0))
    width = max(len(f"{listener} {ip}") for (listener, ip) in sources)

    header = f"{'listener / source':<{width}}  {'packets':>9} {'peak/s':>7} {'ports':>6}  events"
    print(header)
    print("-" * len(header))
    for (listener, ip), record in rows:
        events = " ".join(
            f"{key[2:]}={record[key]}" for key in EVENT_KEYS if record.get(key)
        )
        print(
            f"{listener + ' ' + ip:<{width}}  {record.get('packets', 0):>9}"
            f" {record['peak_pps']:>7.2f} {record.get('distinct_source_ports', 0):>6}  {events}"
        )
        if record.get("last_payload_text"):
            print(f"{'':<{width}}  last payload: {record['last_payload_text']!r}")
        if args.ports:
            listed = sorted(record["ports"].items(), key=lambda kv: -kv[1])[:20]
            print(f"{'':<{width}}  ports: " + ", ".join(f"{p}({c})" for p, c in listed))

    distinct_ips = {ip for _, ip in sources}
    print()
    print(f"{len(distinct_ips)} distinct source IP(s) across {len(sources)} listener/source pairs")
    print(f"{summary['windows']} reporting window(s)")
    if summary["throttled"]:
        print(f"throttled (cumulative): {summary['throttled']}")
    if summary["untracked_sources"]:
        print(f"untracked sources (table full): {summary['untracked_sources']}")

    multi_port = [
        (listener, ip)
        for (listener, ip), rec in sources.items()
        if rec.get("distinct_source_ports", 0) > 4
    ]
    if multi_port:
        print(
            "\nSources using many source ports (consistent with carrier NAT, or "
            "one device per connection):"
        )
        for listener, ip in multi_port:
            print(f"  {listener} {ip}: {sources[(listener, ip)]['distinct_source_ports']} ports")
    print("\nSuggested ALLOWED_SOURCES: " + ",".join(sorted(distinct_ips)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
