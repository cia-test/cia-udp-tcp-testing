"""Concurrent test runs against one shared server.

The real workload: a DUT boots, sends a zero-payload datagram every second for
15s, and the harness checks that at least 3 arrived. Several such runs overlap,
and every boot brings a fresh source IP and port, so a run cannot recognise its
own device by address.

These tests reproduce the false negative the old erase-run-read cycle produced
and cover the windowed, flow-grouped read that replaces it.
"""

import importlib.util
import socket
import sys
import time
from pathlib import Path

import pytest

SERVER_PY = Path(__file__).resolve().parent.parent / "src" / "server.py"


def _load_server_module():
    spec = importlib.util.spec_from_file_location("cia_server_conc", SERVER_PY)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


server_mod = _load_server_module()

# What the DUT actually sends: a fixed, all-zero payload carrying no identity.
ZERO_PAYLOAD = b"\x00" * 10


class FakeDut:
    """One boot session: a single socket, so a stable source port."""

    def __init__(self, host, port):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.target = (host, port)

    @property
    def source_port(self):
        return self.sock.getsockname()[1]

    def send(self, count=1, payload=ZERO_PAYLOAD):
        for _ in range(count):
            self.sock.sendto(payload, self.target)

    def close(self):
        self.sock.close()


@pytest.fixture
def dut_factory(server):
    duts = []

    def make():
        dut = FakeDut(server.host, server.sample_port)
        duts.append(dut)
        return dut

    yield make
    for dut in duts:
        dut.close()


def wait_until(predicate, timeout=5.0, poll=0.05):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = predicate()
        if result:
            return result
        time.sleep(poll)
    return predicate()


# --------------------------------------------------------------------------
# the failure mode being fixed
# --------------------------------------------------------------------------


def test_draining_steals_samples_from_a_concurrent_run(clean_store, dut_factory):
    """Why erase-run-read produced false negatives: run B's drain consumes the
    packets run A is still waiting for."""
    server = clean_store
    dut_a, dut_b = dut_factory(), dut_factory()

    dut_a.send(3)
    dut_b.send(3)
    wait_until(lambda: server.count() == 6)

    stolen = server.drain()          # run B reads first, consuming everything
    assert len(stolen) == 6
    assert server.count() == 0       # run A now sees nothing: false negative


def test_windowed_reads_let_both_runs_see_their_own_packets(clean_store, dut_factory):
    """The fix: each run reads from its own cursor and consumes nothing."""
    server = clean_store

    cursor_a = server.cursor()
    dut_a = dut_factory()
    dut_a.send(3)
    wait_until(lambda: server.count(since=cursor_a) == 3)

    cursor_b = server.cursor()
    dut_b = dut_factory()
    dut_b.send(3)
    wait_until(lambda: server.count(since=cursor_b) == 3)

    # Run A still sees its own 3 (plus B's, which is what flow grouping fixes).
    flows_a = server.flows_since(cursor_a, min_packets=3)
    flows_b = server.flows_since(cursor_b, min_packets=3)

    assert {f["port"] for f in flows_a} == {dut_a.source_port, dut_b.source_port}
    assert {f["port"] for f in flows_b} == {dut_b.source_port}
    assert all(f["packets"] == 3 for f in flows_a)


def test_flow_grouping_separates_concurrent_devices(clean_store, dut_factory):
    """Three overlapping runs, interleaved packets: one flow each, not one blob."""
    server = clean_store
    cursor = server.cursor()
    duts = [dut_factory() for _ in range(3)]

    for _ in range(4):                      # interleave, like real concurrent runs
        for dut in duts:
            dut.send(1)

    wait_until(lambda: server.count(since=cursor) == 12)
    flows = server.flows_since(cursor)

    assert len(flows) == 3
    assert {f["port"] for f in flows} == {dut.source_port for dut in duts}
    assert all(f["packets"] == 4 for f in flows)


def test_min_packets_filters_out_a_failing_device(clean_store, dut_factory):
    """A device that sent too few packets must not be rescued by the others."""
    server = clean_store
    cursor = server.cursor()
    healthy, broken = dut_factory(), dut_factory()

    healthy.send(5)
    broken.send(1)                          # only one packet before dying
    wait_until(lambda: server.count(since=cursor) == 6)

    qualifying = server.flows_since(cursor, min_packets=3)
    assert len(qualifying) == 1
    assert qualifying[0]["port"] == healthy.source_port

    # The broken device is still visible, which is what makes it diagnosable.
    all_flows = {f["port"]: f["packets"] for f in server.flows_since(cursor)}
    assert all_flows[broken.source_port] == 1


def test_ongoing_flow_is_not_mistaken_for_a_new_one(clean_store, dut_factory):
    """A neighbour that was already streaming when I took my cursor must not
    vouch for my board: only genuinely new boots count."""
    server = clean_store
    neighbour = dut_factory()
    neighbour.send(3)
    wait_until(lambda: server.count() == 3)

    cursor = server.cursor()             # my run starts here
    neighbour.send(4)                    # neighbour keeps streaming
    wait_until(lambda: server.count(since=cursor) == 4)

    # 4 of the neighbour's packets landed in my window, but its flow is old.
    assert server.flows_since(cursor, min_packets=3) == []

    ongoing = server.flows_since(cursor, min_packets=3, include_ongoing=True)
    assert len(ongoing) == 1
    assert ongoing[0]["new"] is False
    assert ongoing[0]["packets_since"] == 4
    assert ongoing[0]["packets"] == 7     # cumulative across the whole flow


def test_new_flow_after_cursor_is_reported_as_new(clean_store, dut_factory):
    server = clean_store
    dut_factory().send(3)                # a neighbour, before my cursor
    wait_until(lambda: server.count() == 3)

    cursor = server.cursor()
    mine = dut_factory()
    mine.send(3)
    wait_until(lambda: server.count(since=cursor) == 3)

    flows = server.flows_since(cursor, min_packets=3)
    assert len(flows) == 1
    assert flows[0]["port"] == mine.source_port
    assert flows[0]["new"] is True


def test_zero_payloads_carry_no_identity(clean_store, dut_factory):
    """All samples are byte-identical, so the flow tuple is the only handle."""
    server = clean_store
    cursor = server.cursor()
    dut_factory().send(3)
    wait_until(lambda: server.count(since=cursor) == 3)

    samples = server.peek(since=cursor)
    assert len({s["data_hex"] for s in samples}) == 1
    assert len({(s["ip"], s["port"]) for s in samples}) == 1


def test_empty_datagrams_are_not_stored(clean_store, dut_factory):
    """A truly zero-length datagram has no marker, so it is dropped. If the DUT
    sends these, no amount of read-side work will help."""
    server = clean_store
    cursor = server.cursor()
    dut = dut_factory()
    dut.send(2, payload=b"")
    dut.send(1)                             # a marked packet proves ordering

    wait_until(lambda: server.count(since=cursor) == 1)
    assert server.count(since=cursor) == 1


# --------------------------------------------------------------------------
# cursor and window semantics
# --------------------------------------------------------------------------


def test_cursor_advances_and_has_no_side_effects(clean_store, dut_factory):
    server = clean_store
    before = server.cursor()
    assert server.cursor() == before        # reading it changes nothing

    dut_factory().send(2)
    wait_until(lambda: server.cursor() == before + 2)
    assert server.cursor() == before + 2
    assert server.count(since=before) == 2


def test_since_excludes_earlier_samples(clean_store, dut_factory):
    server = clean_store
    dut_factory().send(2)
    wait_until(lambda: server.count() == 2)

    cursor = server.cursor()
    dut_factory().send(1)
    wait_until(lambda: server.count(since=cursor) == 1)

    assert server.count() == 3
    assert server.count(since=cursor) == 1


def test_since_with_drain_is_rejected(clean_store):
    """Guard against the destructive pattern creeping back in."""
    response = clean_store.request(
        "GET", "/samples", params={"since": 1, "drain": "true"}
    )
    assert response.status_code == 400
    assert "since" in response.json()["error"]


def test_since_defaults_to_non_destructive(clean_store, dut_factory):
    server = clean_store
    dut_factory().send(2)
    wait_until(lambda: server.count() == 2)

    body = server.request("GET", "/samples", params={"since": 0}).json()
    assert body["drained"] is False
    assert body["count"] == 2
    assert server.count() == 2              # still there


# --------------------------------------------------------------------------
# unit: flow grouping and retention
# --------------------------------------------------------------------------


def test_flows_group_by_ip_and_port():
    store = server_mod.SampleStore(maxlen=100)
    store.add(ZERO_PAYLOAD, "10.0.0.1", 5000)
    store.add(ZERO_PAYLOAD, "10.0.0.1", 5000)
    store.add(ZERO_PAYLOAD, "10.0.0.1", 5001)   # same device, new boot
    store.add(ZERO_PAYLOAD, "10.0.0.2", 5000)   # different device

    flows = store.flows()
    assert len(flows) == 3
    assert [(f["ip"], f["port"], f["packets"]) for f in flows] == [
        ("10.0.0.1", 5000, 2),
        ("10.0.0.1", 5001, 1),
        ("10.0.0.2", 5000, 1),
    ]


def test_flows_report_id_range_and_span():
    store = server_mod.SampleStore(maxlen=100)
    for _ in range(3):
        store.add(ZERO_PAYLOAD, "10.0.0.1", 5000)

    flow = store.flows()[0]
    assert flow["first_id"] == 1
    assert flow["last_id"] == 3
    assert flow["bytes"] == 3 * len(ZERO_PAYLOAD)
    assert flow["duration_s"] >= 0
    assert "_first_monotonic" not in flow      # internal fields stay internal


def test_flows_respect_since_and_min_packets():
    store = server_mod.SampleStore(maxlen=100)
    store.add(ZERO_PAYLOAD, "10.0.0.1", 5000)
    cursor = store.last_id
    store.add(ZERO_PAYLOAD, "10.0.0.2", 6000)
    store.add(ZERO_PAYLOAD, "10.0.0.2", 6000)

    assert len(store.flows()) == 2
    assert [f["port"] for f in store.flows(since=cursor)] == [6000]
    assert store.flows(since=cursor, min_packets=3) == []
    assert len(store.flows(min_packets=2)) == 1


def test_count_limit_evicts_oldest():
    store = server_mod.SampleStore(maxlen=3, retention_s=0)
    for _ in range(5):
        store.add(ZERO_PAYLOAD, "10.0.0.1", 5000)

    assert len(store) == 3
    assert store.dropped == 2
    assert store.evictions["count"] == 2
    assert [s["id"] for s in store.peek()] == [3, 4, 5]


def test_byte_budget_evicts_oldest():
    store = server_mod.SampleStore(maxlen=1000, max_bytes=25, retention_s=0)
    for _ in range(5):
        store.add(ZERO_PAYLOAD, "10.0.0.1", 5000)   # 10 bytes each

    assert len(store) == 2
    assert store.evictions["bytes"] == 3


def test_retention_expires_old_samples(monkeypatch):
    clock = {"now": 1000.0}
    monkeypatch.setattr(server_mod.time, "monotonic", lambda: clock["now"])

    store = server_mod.SampleStore(maxlen=1000, retention_s=60)
    store.add(ZERO_PAYLOAD, "10.0.0.1", 5000)
    clock["now"] += 30
    store.add(ZERO_PAYLOAD, "10.0.0.1", 5000)
    assert len(store) == 2

    clock["now"] += 31                  # first sample is now 61s old
    assert len(store) == 1
    assert store.evictions["expired"] == 1
    assert store.peek()[0]["id"] == 2


def test_ids_keep_increasing_across_eviction():
    """Cursors must stay valid even after the samples they point at are gone."""
    store = server_mod.SampleStore(maxlen=2, retention_s=0)
    for _ in range(5):
        store.add(ZERO_PAYLOAD, "10.0.0.1", 5000)

    assert store.last_id == 5
    cursor = store.last_id
    store.add(ZERO_PAYLOAD, "10.0.0.1", 5000)
    assert [s["id"] for s in store.peek(since=cursor)] == [6]
