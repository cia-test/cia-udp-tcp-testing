"""Traffic accounting: per-source counters, the JSON log lines, /stats."""

import asyncio
import importlib.util
import json
import socket
import sys
import time
from pathlib import Path

import pytest
import requests

SERVER_PY = Path(__file__).resolve().parent.parent / "src" / "server.py"


def _load_server_module():
    spec = importlib.util.spec_from_file_location("cia_server_stats", SERVER_PY)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


server_mod = _load_server_module()


# --------------------------------------------------------------------------
# unit: TrafficStats
# --------------------------------------------------------------------------


def test_records_are_keyed_by_listener_and_ip():
    stats = server_mod.TrafficStats()
    stats.record("udp/3000", "10.0.0.1", 5000, b"ping", "ok")
    stats.record("udp/3000", "10.0.0.1", 5001, b"ping", "ok")
    stats.record("udp/3001", "10.0.0.1", 5000, b"\x00\x00\x00", "ok")
    stats.record("udp/3000", "10.0.0.2", 5000, b"ping", "ok")

    assert len(stats) == 3
    snapshot = {(s["listener"], s["ip"]): s for s in stats.snapshot()}
    assert snapshot[("udp/3000", "10.0.0.1")]["packets"] == 2
    assert snapshot[("udp/3000", "10.0.0.1")]["distinct_source_ports"] == 2
    assert snapshot[("udp/3001", "10.0.0.1")]["packets"] == 1


def test_counts_bytes_and_events():
    stats = server_mod.TrafficStats()
    stats.record("udp/3001", "10.0.0.1", 5000, b"1234", "ok")
    stats.record("udp/3001", "10.0.0.1", 5000, b"12", "no_marker")
    stats.record("udp/3001", "10.0.0.1", 5000, b"1", "throttled")

    record = stats.snapshot()[0]
    assert record["packets"] == 3
    assert record["bytes"] == 7
    assert record["n_ok"] == 1
    assert record["n_no_marker"] == 1
    assert record["n_throttled"] == 1
    assert record["n_blocked"] == 0


def test_payload_preview_only_tracks_accepted_packets():
    stats = server_mod.TrafficStats()
    stats.record("udp/3000", "10.0.0.1", 5000, b"DUT-07 alive", "ok")
    stats.record("udp/3000", "10.0.0.1", 5000, b"dropped junk", "throttled")

    record = stats.snapshot()[0]
    assert record["last_payload_text"] == "DUT-07 alive"[: server_mod.PAYLOAD_PREVIEW_BYTES]
    assert record["last_payload_hex"].startswith(b"DUT-07".hex())


def test_payload_preview_sanitises_binary():
    stats = server_mod.TrafficStats()
    stats.record("udp/3001", "10.0.0.1", 5000, b"\x00\x01ab\xff", "ok")
    record = stats.snapshot()[0]
    assert record["last_payload_text"] == "..ab."
    assert record["last_payload_hex"] == b"\x00\x01ab\xff".hex()


def test_source_port_table_is_bounded_but_count_is_not():
    stats = server_mod.TrafficStats()
    total = server_mod.MAX_SOURCE_PORTS + 25
    for port in range(40000, 40000 + total):
        stats.record("udp/3000", "10.0.0.1", port, b"x", "ok")

    record = stats.snapshot()[0]
    assert len(record["source_ports"]) == server_mod.MAX_SOURCE_PORTS
    assert record["source_ports_untracked"] == 25
    assert record["distinct_source_ports"] == total
    assert record["packets"] == total


def test_established_sources_survive_a_flood_of_new_ones():
    """Unlike the rate-limiter table, stats must not lose days of history."""
    stats = server_mod.TrafficStats(max_sources=3)
    for i in range(3):
        stats.record("udp/3000", f"10.0.0.{i}", 5000, b"x", "ok")
    for i in range(100):
        stats.record("udp/3000", f"192.168.1.{i}", 5000, b"x", "ok")

    assert len(stats) == 3
    assert stats.untracked_sources == 100
    assert {s["ip"] for s in stats.snapshot()} == {"10.0.0.0", "10.0.0.1", "10.0.0.2"}


def test_flush_window_returns_active_sources_then_resets():
    stats = server_mod.TrafficStats()
    stats.record("udp/3000", "10.0.0.1", 5000, b"x" * 10, "ok")
    stats.record("udp/3000", "10.0.0.1", 5000, b"x" * 10, "ok")

    first = stats.flush_window(10.0)
    assert len(first) == 1
    assert first[0]["packets_window"] == 2
    assert first[0]["bytes_window"] == 20
    assert first[0]["pps_window"] == 0.2

    assert stats.flush_window(10.0) == []  # nothing new since the last flush
    assert stats.snapshot()[0]["packets"] == 2  # cumulative counter is kept


# --------------------------------------------------------------------------
# the JSON log lines
# --------------------------------------------------------------------------


def _parse_log_lines(text):
    lines = []
    for line in text.strip().splitlines():
        line = line.strip()
        if line.startswith("{"):
            lines.append(json.loads(line))
    return lines


def test_stats_logger_emits_parseable_json(capsys):
    stats = server_mod.TrafficStats()
    stats.record("udp/3000", "10.0.0.1", 41234, b"ping", "ok")
    stats.record("udp/3000", "10.0.0.1", 41234, b"ping", "ok")
    limiters = {"pong": server_mod.UdpRateLimiter(0, 0, 10)}

    async def run_briefly():
        task = asyncio.create_task(server_mod.stats_logger(stats, limiters, 0.05))
        await asyncio.sleep(0.12)
        task.cancel()

    asyncio.run(run_briefly())
    lines = _parse_log_lines(capsys.readouterr().out)

    traffic = [line for line in lines if line["type"] == "traffic"]
    summaries = [line for line in lines if line["type"] == "traffic_summary"]
    assert len(traffic) == 1, "the second window had no traffic, so no line"
    assert traffic[0]["ip"] == "10.0.0.1"
    assert traffic[0]["listener"] == "udp/3000"
    assert traffic[0]["packets_window"] == 2
    assert traffic[0]["source_ports"] == {"41234": 2}
    assert traffic[0]["ts"]
    assert len(summaries) >= 2
    assert summaries[0]["tracked_sources"] == 1
    assert summaries[0]["throttled"] == {"pong": 0}


# --------------------------------------------------------------------------
# over the wire
# --------------------------------------------------------------------------


def test_stats_endpoint_requires_the_token(server):
    if not server.token:
        pytest.skip("server running without a token")
    assert requests.get(f"{server.api}/stats", timeout=5).status_code == 401


def test_stats_endpoint_reports_real_traffic(server):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(("127.0.0.1", 0))
        source_port = sock.getsockname()[1]
        sock.settimeout(2.0)
        sock.sendto(b"stats-probe", (server.host, server.pong_port))
        sock.recvfrom(2048)

    deadline = time.monotonic() + 5
    listener = f"udp/{server.pong_port}"
    while time.monotonic() < deadline:
        body = server.request("GET", "/stats").json()
        record = next(
            (
                s
                for s in body["sources"]
                if s["listener"] == listener and str(source_port) in s["source_ports"]
            ),
            None,
        )
        if record:
            break
        time.sleep(0.05)

    assert record, f"source port {source_port} never appeared in /stats"
    assert record["ip"] == "127.0.0.1"
    assert record["n_ok"] >= 1
    assert record["last_payload_text"].startswith("stats-probe")
    assert record["first_seen"] and record["last_seen"]
    assert body["limits"]["udp_global_rate"] >= 0


def test_health_reports_per_listener_throttle_counters(server):
    body = server.request("GET", "/health").json()
    assert set(body["udp_throttled"]) == {"pong", "samples"}
    assert body["tracked_sources"] >= 1
