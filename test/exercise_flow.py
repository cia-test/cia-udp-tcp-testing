#!/usr/bin/env python3
"""Manual driver for the UDP -> REST flow. Uses stdlib only.

    python3 test/exercise_flow.py --token "$REST_API_TOKEN"
    python3 test/exercise_flow.py --host node-test-07 --https --insecure
    python3 test/exercise_flow.py --count 5 --keep       # don't drain at the end

The token defaults to $CIA_REST_TOKEN. Exits non-zero if any step fails.
"""

import argparse
import base64
import json
import os
import socket
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

SAMPLE_MARKER = b"\x00\x00\x00"

TOKEN = ""
SSL_CONTEXT = None


def api_call(base, path, method="GET", params=None, body=None, content_type=None,
             token=None):
    url = f"{base}{path}"
    if params:
        url = f"{url}?{urllib.parse.urlencode(params)}"
    request = urllib.request.Request(url, method=method, data=body)
    if content_type:
        request.add_header("Content-Type", content_type)
    bearer = TOKEN if token is None else token
    if bearer:
        request.add_header("Authorization", f"Bearer {bearer}")
    try:
        with urllib.request.urlopen(request, timeout=5, context=SSL_CONTEXT) as response:
            return response.status, json.loads(response.read() or b"null")
    except urllib.error.HTTPError as exc:
        try:
            return exc.code, json.loads(exc.read() or b"null")
        except ValueError:
            return exc.code, None


def step(label):
    print(f"\n--- {label}")


def check(condition, message):
    print(f"    {'ok  ' if condition else 'FAIL'} {message}")
    return bool(condition)


def udp_send(host, port, payload):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.sendto(payload, (host, port))


def udp_pong(host, port, payload):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(5)
        sock.sendto(payload, (host, port))
        return sock.recvfrom(2048)[0]


def tcp_pong(host, port, payload):
    with socket.create_connection((host, port), timeout=5) as sock:
        sock.sendall(payload)
        return sock.recv(2048)


def wait_for(base, count, timeout=5.0):
    deadline = time.monotonic() + timeout
    while True:
        _, body = api_call(base, "/samples", params={"drain": "false"})
        if body["count"] >= count or time.monotonic() > deadline:
            return body
        time.sleep(0.05)


def main():
    global TOKEN, SSL_CONTEXT

    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="localhost")
    parser.add_argument("--pong-port", type=int, default=3000)
    parser.add_argument("--sample-port", type=int, default=3001)
    parser.add_argument("--rest-port", type=int, default=8080)
    parser.add_argument("--count", type=int, default=3, help="samples to send over UDP")
    parser.add_argument("--keep", action="store_true", help="skip the final drain")
    parser.add_argument(
        "--token",
        default=os.environ.get("CIA_REST_TOKEN", ""),
        help="bearer token (default: $CIA_REST_TOKEN)",
    )
    parser.add_argument("--https", action="store_true", help="use TLS")
    parser.add_argument(
        "--insecure", action="store_true", help="with --https, skip certificate checks"
    )
    args = parser.parse_args()

    TOKEN = args.token
    scheme = "https" if args.https else "http"
    if args.https and args.insecure:
        SSL_CONTEXT = ssl._create_unverified_context()

    base = f"{scheme}://{args.host}:{args.rest_port}/api/v1"
    ok = True

    step(f"health ({base}/health)")
    status, body = api_call(base, "/health")
    ok &= check(status == 200 and body.get("status") == "ok", f"HTTP {status} {body}")
    if not ok:
        print("\nserver unreachable, aborting")
        return 1

    step("pong protocols")
    ok &= check(
        udp_pong(args.host, args.pong_port, b"foobar") == b"PONG: foobar",
        f"udp/{args.pong_port} pong",
    )
    ok &= check(
        tcp_pong(args.host, args.pong_port, b"foobar") == b"PONG: foobar",
        f"tcp/{args.pong_port} pong",
    )

    step("clear store")
    status, body = api_call(base, "/samples", method="DELETE")
    ok &= check(status == 200, f"DELETE /samples -> {body}")

    step(f"send {args.count} marked + 1 unmarked datagram to udp/{args.sample_port}")
    udp_send(args.host, args.sample_port, b"unmarked-should-be-dropped")
    sent = []
    for i in range(args.count):
        payload = SAMPLE_MARKER + f"sample-{i}".encode()
        sent.append(payload)
        udp_send(args.host, args.sample_port, payload)
        print(f"    tx {payload!r}")

    step("peek (drain=false)")
    body = wait_for(base, len(sent))
    ok &= check(body["count"] == len(sent), f"stored {body['count']}/{len(sent)}")
    for sample in body["samples"]:
        print(f"    id={sample['id']} len={sample['length']} hex={sample['data_hex']}")
    ok &= check(body["remaining"] == len(sent), "peek did not consume")

    step("inject one sample over REST")
    status, sample = api_call(
        base,
        "/samples",
        method="POST",
        body=json.dumps({"text": "injected-over-rest"}).encode(),
        content_type="application/json",
    )
    ok &= check(status == 201, f"POST /samples -> HTTP {status} id={sample.get('id')}")

    step("error handling")
    status, body = api_call(base, "/samples", params={"limit": "abc"})
    ok &= check(status == 400 and "error" in body, f"bad limit -> HTTP {status} {body}")
    status, body = api_call(base, "/nope")
    ok &= check(status == 404, f"unknown route -> HTTP {status}")

    step("traffic stats")
    status, body = api_call(base, "/stats")
    if status == 200:
        ok &= check(body["sources"], f"{len(body['sources'])} source(s) tracked")
        for source in body["sources"]:
            print(
                f"    {source['listener']} {source['ip']}"
                f" packets={source['packets']}"
                f" ports={source['distinct_source_ports']}"
                f" ok={source['n_ok']} throttled={source['n_throttled']}"
                f" last={source['last_payload_text']!r}"
            )
    else:
        ok &= check(False, f"GET /stats -> HTTP {status}")

    step("auth")
    if args.token:
        status, _ = api_call(base, "/health", token="")
        ok &= check(status == 401, f"no token -> HTTP {status}")
        status, _ = api_call(base, "/health", token="wrong-token")
        ok &= check(status == 401, f"wrong token -> HTTP {status}")
    else:
        print("    WARN no --token given: API is unauthenticated or untested")
    if scheme == "http":
        print("    WARN plaintext HTTP: the token is readable on the network path")

    if args.keep:
        step("keeping stored samples (--keep)")
        _, body = api_call(base, "/samples", params={"drain": "false"})
        print(f"    {body['count']} sample(s) left in the store")
    else:
        step("drain (drain=true)")
        status, body = api_call(base, "/samples", params={"drain": "true"})
        ok &= check(status == 200, f"drained {body['count']} sample(s)")
        for sample in body["samples"]:
            print(f"    id={sample['id']} {base64.b64decode(sample['data_b64'])!r}")
        _, body = api_call(base, "/samples", params={"drain": "false"})
        ok &= check(body["count"] == 0, "store empty after drain")

    print(f"\n{'PASS' if ok else 'FAIL'}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
