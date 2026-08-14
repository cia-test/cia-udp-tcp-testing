"""Auth, source filtering, rate limiting and size limits.

The over-the-wire tests use the shared `server` fixture. The rate limiter and
source-filter helpers are unit tested directly against src/server.py so the
assertions stay deterministic (no wall-clock dependence).
"""

import importlib.util
import socket
import sys
from pathlib import Path

import pytest
import requests

SERVER_PY = Path(__file__).resolve().parent.parent / "src" / "server.py"


def _load_server_module():
    spec = importlib.util.spec_from_file_location("cia_server", SERVER_PY)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


server_mod = _load_server_module()


# --------------------------------------------------------------------------
# bearer token auth
# --------------------------------------------------------------------------

PROTECTED = [
    ("GET", "/health"),
    ("GET", "/samples"),
    ("POST", "/samples"),
    ("DELETE", "/samples"),
]


@pytest.mark.parametrize("method,path", PROTECTED)
def test_missing_token_is_rejected(server, method, path):
    if not server.token:
        pytest.skip("server running without a token")
    response = requests.request(method, f"{server.api}{path}", timeout=5)
    assert response.status_code == 401
    assert response.json()["status"] == 401
    assert "Bearer" in response.headers.get("WWW-Authenticate", "")


@pytest.mark.parametrize(
    "header",
    [
        "Bearer wrong-token",
        "Bearer ",
        "bearer",
        "Basic dXNlcjpwYXNz",
        "test-token-not-a-secret-0123456789",  # right token, no scheme
    ],
)
def test_bad_authorization_header_is_rejected(server, header):
    if not server.token:
        pytest.skip("server running without a token")
    response = requests.get(
        f"{server.api}/samples", headers={"Authorization": header}, timeout=5
    )
    assert response.status_code == 401


def test_valid_token_is_accepted(server):
    assert server.request("GET", "/health").status_code == 200


def test_scheme_is_case_insensitive(server):
    if not server.token:
        pytest.skip("server running without a token")
    response = requests.get(
        f"{server.api}/health",
        headers={"Authorization": f"bEaReR {server.token}"},
        timeout=5,
    )
    assert response.status_code == 200


def test_unauthenticated_request_cannot_drain_the_store(clean_store):
    """An unauthenticated drain would silently destroy test evidence."""
    server = clean_store
    if not server.token:
        pytest.skip("server running without a token")
    server.request("POST", "/samples", json={"text": "keep me"}).raise_for_status()

    response = requests.get(f"{server.api}/samples?drain=true", timeout=5)
    assert response.status_code == 401

    body = server.request("GET", "/samples", params={"drain": "false"}).json()
    assert body["count"] == 1


# --------------------------------------------------------------------------
# size limits
# --------------------------------------------------------------------------


def test_oversized_body_is_rejected(clean_store):
    server = clean_store
    payload = b"\x00\x00\x00" + b"x" * (server_mod.MAX_SAMPLE_BYTES + 1024)
    response = server.request(
        "POST", "/samples", data=payload, headers={"Content-Type": "application/octet-stream"}
    )
    assert response.status_code == 413
    assert server.request("GET", "/samples", params={"drain": "false"}).json()["count"] == 0


def test_oversized_datagram_is_not_stored(monkeypatch):
    """At the default 64 KiB limit the IPv4 datagram ceiling already enforces
    this, so drive the guard directly with a lowered limit."""
    monkeypatch.setattr(server_mod, "MAX_SAMPLE_BYTES", 16)
    store = server_mod.SampleStore(10)
    protocol = server_mod.UdpSampleTest(
        store, server_mod.UdpRateLimiter(0, 0, 10), allowed=[]
    )

    protocol.datagram_received(b"\x00\x00\x00" + b"y" * 64, ("10.0.0.1", 5000))
    assert len(store) == 0

    protocol.datagram_received(b"\x00\x00\x00ok", ("10.0.0.1", 5000))
    assert len(store) == 1


def test_udp_source_allowlist_blocks_other_hosts():
    store = server_mod.SampleStore(10)
    protocol = server_mod.UdpSampleTest(
        store,
        server_mod.UdpRateLimiter(0, 0, 10),
        allowed=server_mod.parse_allowed_sources("10.0.0.0/24"),
    )

    protocol.datagram_received(b"\x00\x00\x00blocked", ("8.8.8.8", 5000))
    assert len(store) == 0

    protocol.datagram_received(b"\x00\x00\x00allowed", ("10.0.0.7", 5000))
    assert len(store) == 1


# --------------------------------------------------------------------------
# pong reflection guards
# --------------------------------------------------------------------------


def test_pong_refuses_reply_to_amplification_source_port(server):
    """A datagram claiming to come from our own port must not be answered,
    or two such packets sustain each other forever."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(("127.0.0.1", 0))
        listen_port = sock.getsockname()[1]
        if listen_port in server_mod.NO_REPLY_PORTS:
            pytest.skip("ephemeral port collided with the no-reply list")
        sock.settimeout(1.0)
        sock.sendto(b"loop", (server.host, server.pong_port))
        # Control: a normal ephemeral source port does get a reply.
        data, _ = sock.recvfrom(2048)
        assert data == b"PONG: loop"


def test_no_reply_ports_covers_our_own_port_and_classic_amplifiers():
    for port in (7, 19, 53, 123, 11211):
        assert port in server_mod.NO_REPLY_PORTS


# --------------------------------------------------------------------------
# unit tests: rate limiting
# --------------------------------------------------------------------------


def test_token_bucket_allows_burst_then_throttles():
    bucket = server_mod.TokenBucket(rate=10, burst=5)
    assert [bucket.allow(now=0.0) for _ in range(5)] == [True] * 5
    assert bucket.allow(now=0.0) is False


def test_token_bucket_refills_over_time():
    bucket = server_mod.TokenBucket(rate=10, burst=2)
    assert bucket.allow(now=0.0) is True
    assert bucket.allow(now=0.0) is True
    assert bucket.allow(now=0.0) is False
    assert bucket.allow(now=0.1) is True  # 0.1s at 10/s == 1 token


def test_token_bucket_zero_rate_disables_limiting():
    bucket = server_mod.TokenBucket(rate=0)
    assert all(bucket.allow(now=0.0) for _ in range(1000))


def test_per_ip_limit_does_not_starve_other_sources():
    # Buckets default to a burst of rate * 2, so rate=2 allows 4 back-to-back.
    limiter = server_mod.UdpRateLimiter(global_rate=1000, per_ip_rate=2, max_tracked=64)
    assert [limiter.allow("10.0.0.1", now=0.0) for _ in range(4)] == [True] * 4
    assert limiter.allow("10.0.0.1", now=0.0) is False
    assert limiter.allow("10.0.0.2", now=0.0) is True
    assert limiter.throttled == 1


def test_global_limit_caps_total_reflection_volume():
    """Spoofed sources defeat per-IP limits, so the global bucket must hold."""
    limiter = server_mod.UdpRateLimiter(global_rate=10, per_ip_rate=1000, max_tracked=4096)
    allowed = sum(limiter.allow(f"10.0.{i // 256}.{i % 256}", now=0.0) for i in range(100))
    assert allowed == 20  # global burst == rate * 2
    assert limiter.throttled == 80


def test_tracking_table_is_bounded():
    limiter = server_mod.UdpRateLimiter(global_rate=0, per_ip_rate=5, max_tracked=10)
    for i in range(1000):
        limiter.allow(f"10.1.{i // 256}.{i % 256}", now=0.0)
    assert len(limiter._buckets) <= 10
    assert limiter.table_resets > 0


# --------------------------------------------------------------------------
# unit tests: source allowlist
# --------------------------------------------------------------------------


def test_empty_allowlist_allows_everything():
    assert server_mod.source_allowed([], "8.8.8.8") is True
    assert server_mod.source_allowed([], None) is True


@pytest.mark.parametrize(
    "host,expected",
    [
        ("10.0.0.5", True),
        ("10.0.0.255", True),
        ("10.0.1.1", False),
        ("192.168.1.1", True),
        ("8.8.8.8", False),
        ("not-an-ip", False),
        (None, False),
    ],
)
def test_allowlist_matches_cidrs(host, expected):
    networks = server_mod.parse_allowed_sources("10.0.0.0/24, 192.168.1.1")
    assert server_mod.source_allowed(networks, host) is expected


def test_parse_allowed_sources_ignores_blanks():
    assert server_mod.parse_allowed_sources("") == []
    assert len(server_mod.parse_allowed_sources("10.0.0.0/8,, ")) == 1


def test_parse_allowed_sources_rejects_garbage():
    with pytest.raises(ValueError):
        server_mod.parse_allowed_sources("nonsense/99")
