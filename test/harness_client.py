#!/usr/bin/env python3
"""Client for the sample REST API, for use from a test harness.

Replaces the old flow of "open TCP 3002, send b'foobar', parse the text blob".

    from harness_client import SampleApiClient

    api = SampleApiClient("testserver", token=os.environ["REST_API_TOKEN"])
    api.clear()                              # start from a known-empty store
    dut.run_connectivity_test()              # DUT sends datagrams to udp/3001
    payloads = api.collect(count=1)          # [b'\\x00\\x00\\x00...']

Also usable directly for a quick look at a running server:

    python3 test/harness_client.py --host testserver --token "$REST_API_TOKEN" drain
    python3 test/harness_client.py --token "$REST_API_TOKEN" stats
"""

import argparse
import base64
import json
import os
import sys
import time

import requests

DEFAULT_REST_PORT = 8080


class SampleApiClient:
    """Thin wrapper over /api/v1. Methods raise for HTTP errors."""

    def __init__(self, host, token="", port=DEFAULT_REST_PORT, scheme="http",
                 verify=True, timeout=5.0):
        self.host = host
        self.token = token
        self.rest_port = port
        self.scheme = scheme
        self.verify = verify
        self.timeout = timeout
        self.session = requests.Session()

    @property
    def api(self):
        return f"{self.scheme}://{self.host}:{self.rest_port}/api/v1"

    @property
    def headers(self):
        return {"Authorization": f"Bearer {self.token}"} if self.token else {}

    def request(self, method, path, **kwargs):
        """Raw request with auth applied; no status checking."""
        headers = dict(self.headers)
        headers.update(kwargs.pop("headers", None) or {})
        kwargs.setdefault("timeout", self.timeout)
        kwargs.setdefault("verify", self.verify)
        return self.session.request(method, f"{self.api}{path}", headers=headers, **kwargs)

    def _json(self, method, path, **kwargs):
        response = self.request(method, path, **kwargs)
        response.raise_for_status()
        return response.json()

    # -- samples ----------------------------------------------------------

    @staticmethod
    def _params(drain, limit):
        params = {"drain": "true" if drain else "false"}
        if limit is not None:
            params["limit"] = limit
        return params

    def cursor(self):
        """Current end of the log. Take this *before* starting the DUT."""
        return self._json("GET", "/cursor")["last_id"]

    def peek(self, limit=None, since=0):
        """Read samples without consuming them."""
        params = self._params(False, limit)
        if since:
            params["since"] = since
        return self._json("GET", "/samples", params=params)["samples"]

    def drain(self, limit=None):
        """Read and consume samples.

        Unsafe when test runs overlap: this destroys the samples every other
        run is waiting for. Use cursor() + flows_since() instead.
        """
        return self._json("GET", "/samples", params=self._params(True, limit))["samples"]

    def count(self, since=0):
        params = self._params(False, None)
        if since:
            params["since"] = since
        return self._json("GET", "/samples", params=params)["count"]

    def flows_since(self, cursor=0, min_packets=1, include_ongoing=False):
        """Samples grouped by source (ip, port) — one flow per DUT boot.

        Only flows that *started* after `cursor` count, so a neighbouring
        device that was already streaming cannot vouch for your board.
        """
        params = {
            "since": cursor,
            "min_packets": min_packets,
            "include_ongoing": "true" if include_ongoing else "false",
        }
        return self._json("GET", "/flows", params=params)["flows"]

    def wait_for_flow(self, cursor=0, min_packets=3, timeout=30.0, poll=0.5):
        """Wait for a flow with at least `min_packets` to appear after `cursor`.

        Returns every qualifying flow, newest last, as soon as one qualifies.
        Nothing is consumed, so concurrent runs do not interfere.

        Caveat: with several runs in flight this cannot prove the flow belongs
        to *your* device — only that some device sent that many packets in your
        window. See "Concurrent test runs" in the README.
        """
        deadline = time.monotonic() + timeout
        while True:
            flows = self.flows_since(cursor, min_packets)
            if flows:
                return flows
            if time.monotonic() >= deadline:
                seen = self.flows_since(cursor)
                raise TimeoutError(
                    f"no flow reached {min_packets} packets within {timeout}s; "
                    f"saw {len(seen)} flow(s): "
                    + ", ".join(f"{f['ip']}:{f['port']}={f['packets']}" for f in seen)
                )
            time.sleep(poll)

    def clear(self):
        """Discard everything stored; returns how many were dropped."""
        return self._json("DELETE", "/samples")["cleared"]

    def inject(self, data):
        """Store a sample without a DUT (bypasses the marker filter)."""
        if isinstance(data, str):
            body = {"text": data}
        else:
            body = {"data_b64": base64.b64encode(data).decode()}
        return self._json("POST", "/samples", json=body)

    def wait_for_samples(self, count=1, timeout=10.0, poll=0.1):
        """Block until at least `count` samples are stored, without consuming.

        UDP delivery is asynchronous, so a harness that GETs immediately after
        triggering the DUT will usually race and see an empty store.
        """
        deadline = time.monotonic() + timeout
        while True:
            samples = self.peek()
            if len(samples) >= count:
                return samples
            if time.monotonic() >= deadline:
                raise TimeoutError(
                    f"expected {count} sample(s) within {timeout}s, got {len(samples)}"
                )
            time.sleep(poll)

    def collect(self, count=1, timeout=10.0):
        """Wait for `count` samples, then drain and return the raw payloads."""
        self.wait_for_samples(count, timeout)
        return [self.payload(sample) for sample in self.drain()]

    @staticmethod
    def payload(sample):
        """Raw bytes of a sample dict from peek()/drain()."""
        return base64.b64decode(sample["data_b64"])

    # -- diagnostics ------------------------------------------------------

    def health(self):
        return self._json("GET", "/health")

    def stats(self):
        """Per-source UDP traffic counters: who connected, from which ports."""
        return self._json("GET", "/stats")


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "command",
        choices=["health", "stats", "peek", "drain", "clear", "count", "cursor", "flows"],
    )
    parser.add_argument("--host", default="localhost")
    parser.add_argument("--port", type=int, default=DEFAULT_REST_PORT)
    parser.add_argument("--token", default=os.environ.get("REST_API_TOKEN", ""))
    parser.add_argument("--limit", type=int)
    parser.add_argument("--since", type=int, default=0, help="only ids above this")
    parser.add_argument("--min-packets", type=int, default=1, help="flows: minimum size")
    parser.add_argument("--https", action="store_true")
    parser.add_argument("--insecure", action="store_true", help="skip cert checks")
    args = parser.parse_args()

    api = SampleApiClient(
        args.host,
        token=args.token,
        port=args.port,
        scheme="https" if args.https else "http",
        verify=not args.insecure,
    )

    try:
        if args.command == "peek":
            samples = api.peek(limit=args.limit, since=args.since)
        elif args.command == "drain":
            samples = api.drain(limit=args.limit)
        else:
            samples = None

        if samples is not None:
            for sample in samples:
                print(
                    f"id={sample['id']} {sample['received_at']} from {sample['source']} "
                    f"{sample['length']}B {api.payload(sample)!r}"
                )
            print(f"{len(samples)} sample(s)")
        elif args.command == "flows":
            flows = api.flows_since(args.since, args.min_packets)
            for flow in flows:
                print(
                    f"{flow['ip']}:{flow['port']} packets={flow['packets']} "
                    f"ids={flow['first_id']}-{flow['last_id']} "
                    f"span={flow['duration_s']}s first={flow['first_seen']}"
                )
            print(f"{len(flows)} flow(s)")
        elif args.command == "cursor":
            print(api.cursor())
        elif args.command == "clear":
            print(f"cleared {api.clear()} sample(s)")
        elif args.command == "count":
            print(api.count(since=args.since))
        else:
            print(json.dumps(getattr(api, args.command)(), indent=2))
    except requests.HTTPError as exc:
        print(f"error: {exc}\n{exc.response.text}", file=sys.stderr)
        return 1
    except requests.RequestException as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
