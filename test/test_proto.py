"""Exercises the pong protocols and the REST sample API.

Run against a locally spawned server (default):

    pip install -r requirements.txt -r requirements-test.txt
    pytest test/ -v

Run against docker compose:

    docker compose up --build -d
    CIA_SERVER_HOST=localhost CIA_REST_TOKEN=<token> pytest test/ -v
"""

import base64
import socket
import time

import pytest

SAMPLE_MARKER = b"\x00\x00\x00"
TIMEOUT = 5.0


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------


def send_udp(host, port, payload):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.sendto(payload, (host, port))


def send_udp_expect_reply(host, port, payload):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(TIMEOUT)
        sock.sendto(payload, (host, port))
        data, _ = sock.recvfrom(2048)
        return data


def send_tcp(host, port, payload):
    with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
        sock.sendall(payload)
        return sock.recv(2048)


def get_samples(server, drain=False, limit=None):
    params = {"drain": str(drain).lower()}
    if limit is not None:
        params["limit"] = limit
    response = server.request("GET", "/samples", params=params)
    response.raise_for_status()
    return response.json()


def wait_for_samples(server, count, timeout=TIMEOUT):
    """UDP delivery is asynchronous, so poll until the store settles."""
    deadline = time.monotonic() + timeout
    body = get_samples(server, drain=False)
    while body["count"] < count and time.monotonic() < deadline:
        time.sleep(0.05)
        body = get_samples(server, drain=False)
    assert body["count"] == count, f"expected {count} samples, got {body['count']}"
    return body


# --------------------------------------------------------------------------
# pong protocols (unchanged behaviour)
# --------------------------------------------------------------------------


def test_udp_pong(server):
    reply = send_udp_expect_reply(server.host, server.pong_port, b"foobar")
    assert reply == b"PONG: foobar"


def test_tcp_pong(server):
    assert send_tcp(server.host, server.pong_port, b"foobar") == b"PONG: foobar"


# --------------------------------------------------------------------------
# REST API
# --------------------------------------------------------------------------


def test_health(server):
    body = server.request("GET", "/health").json()
    assert body["status"] == "ok"
    assert body["ports"]["udp_samples"] == server.sample_port


def test_samples_empty(clean_store):
    body = get_samples(clean_store, drain=True)
    assert body == {"count": 0, "drained": True, "remaining": 0, "samples": []}


def test_udp_sample_is_stored_and_drained(clean_store):
    server = clean_store
    payload = b"\x01\x02" + SAMPLE_MARKER + b"\xaa"
    send_udp(server.host, server.sample_port, payload)

    body = wait_for_samples(server, 1)
    sample = body["samples"][0]
    assert sample["length"] == len(payload)
    assert sample["data_hex"] == payload.hex()
    assert base64.b64decode(sample["data_b64"]) == payload
    assert sample["received_at"]
    assert sample["source"]

    drained = get_samples(server, drain=True)
    assert drained["count"] == 1
    assert drained["remaining"] == 0
    assert drained["samples"][0]["id"] == sample["id"]

    assert get_samples(server, drain=False)["count"] == 0


def test_datagram_without_marker_is_ignored(clean_store):
    server = clean_store
    send_udp(server.host, server.sample_port, b"asdf")
    send_udp(server.host, server.sample_port, b"\x00\x00")

    # Push a marked datagram after the unmarked ones; once it lands, the
    # unmarked ones have certainly been processed too (same socket, ordered).
    send_udp(server.host, server.sample_port, SAMPLE_MARKER)
    body = wait_for_samples(server, 1)
    assert body["samples"][0]["data_hex"] == SAMPLE_MARKER.hex()


def test_multiple_samples_keep_order_and_ids(clean_store):
    server = clean_store
    payloads = [SAMPLE_MARKER + bytes([i]) for i in range(5)]
    for payload in payloads:
        send_udp(server.host, server.sample_port, payload)

    body = wait_for_samples(server, len(payloads))
    assert [s["data_hex"] for s in body["samples"]] == [p.hex() for p in payloads]
    ids = [s["id"] for s in body["samples"]]
    assert ids == sorted(ids)
    assert len(set(ids)) == len(ids)


def test_peek_does_not_consume(clean_store):
    server = clean_store
    send_udp(server.host, server.sample_port, SAMPLE_MARKER + b"peek")
    wait_for_samples(server, 1)

    for _ in range(3):
        body = get_samples(server, drain=False)
        assert body["count"] == 1
        assert body["remaining"] == 1


def test_limit_drains_oldest_first(clean_store):
    server = clean_store
    for i in range(3):
        send_udp(server.host, server.sample_port, SAMPLE_MARKER + bytes([i]))
    wait_for_samples(server, 3)

    first = get_samples(server, drain=True, limit=2)
    assert first["count"] == 2
    assert first["remaining"] == 1
    assert [s["data_hex"][-2:] for s in first["samples"]] == ["00", "01"]

    rest = get_samples(server, drain=True)
    assert rest["count"] == 1
    assert rest["samples"][0]["data_hex"][-2:] == "02"


def test_delete_clears_store(clean_store):
    server = clean_store
    send_udp(server.host, server.sample_port, SAMPLE_MARKER + b"clearme")
    wait_for_samples(server, 1)

    body = server.request("DELETE", "/samples").json()
    assert body == {"cleared": 1, "remaining": 0}
    assert get_samples(server, drain=False)["count"] == 0


@pytest.mark.parametrize(
    "payload,expected",
    [
        ({"text": "hello"}, b"hello"),
        ({"data_hex": "000000ff"}, b"\x00\x00\x00\xff"),
        ({"data_b64": base64.b64encode(b"\x00\x00\x00abc").decode()}, b"\x00\x00\x00abc"),
    ],
)
def test_post_injects_sample(clean_store, payload, expected):
    """POST is a testing aid: exercise the read path without a DUT."""
    server = clean_store
    response = server.request("POST", "/samples", json=payload)
    assert response.status_code == 201
    assert base64.b64decode(response.json()["data_b64"]) == expected

    body = get_samples(server, drain=True)
    assert body["count"] == 1
    assert base64.b64decode(body["samples"][0]["data_b64"]) == expected


def test_post_raw_body(clean_store):
    server = clean_store
    response = server.request(
        "POST",
        "/samples",
        data=b"\x00\x00\x00raw",
        headers={"Content-Type": "application/octet-stream"},
    )
    assert response.status_code == 201
    assert get_samples(server, drain=True)["samples"][0]["data_hex"] == b"\x00\x00\x00raw".hex()


@pytest.mark.parametrize(
    "kwargs",
    [
        {"json": {}},
        {"json": {"text": "a", "data_hex": "00"}},
        {"json": {"data_hex": "not-hex"}},
        {"json": {"text": 42}},
        {"data": b"", "headers": {"Content-Type": "application/octet-stream"}},
    ],
)
def test_post_rejects_bad_payloads(clean_store, kwargs):
    response = clean_store.request("POST", "/samples", **kwargs)
    assert response.status_code == 400
    assert response.json()["error"]


@pytest.mark.parametrize("params", [{"drain": "maybe"}, {"limit": "abc"}, {"limit": "-1"}])
def test_get_rejects_bad_params(clean_store, params):
    response = clean_store.request("GET", "/samples", params=params)
    assert response.status_code == 400
    assert response.json()["error"]


def test_unknown_route_is_json_404(server):
    response = server.request("GET", "/nope")
    assert response.status_code == 404
    assert response.json()["status"] == 404


def test_full_dut_flow(clean_store):
    """End-to-end equivalent of the old TCP 'foobar' flow."""
    server = clean_store

    assert get_samples(server, drain=True)["count"] == 0

    send_udp(server.host, server.sample_port, b"noise-no-marker")
    send_udp(server.host, server.sample_port, SAMPLE_MARKER + b"sample-1")
    send_udp(server.host, server.sample_port, b"lead" + SAMPLE_MARKER + b"sample-2")
    wait_for_samples(server, 2)

    body = get_samples(server, drain=True)
    assert body["count"] == 2
    payloads = [base64.b64decode(s["data_b64"]) for s in body["samples"]]
    assert all(SAMPLE_MARKER in p for p in payloads)
    assert b"sample-1" in payloads[0] and b"sample-2" in payloads[1]

    assert get_samples(server, drain=True)["count"] == 0
