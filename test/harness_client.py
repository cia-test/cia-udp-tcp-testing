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

    def peek(self, limit=None):
        """Read samples without consuming them."""
        return self._json("GET", "/samples", params=self._params(False, limit))["samples"]

    def drain(self, limit=None):
        """Read and consume samples (the old TCP behaviour)."""
        return self._json("GET", "/samples", params=self._params(True, limit))["samples"]

    def count(self):
        return self._json("GET", "/samples", params=self._params(False, None))["count"]

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
        "command", choices=["health", "stats", "peek", "drain", "clear", "count"]
    )
    parser.add_argument("--host", default="localhost")
    parser.add_argument("--port", type=int, default=DEFAULT_REST_PORT)
    parser.add_argument("--token", default=os.environ.get("REST_API_TOKEN", ""))
    parser.add_argument("--limit", type=int)
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
        if args.command in ("peek", "drain"):
            samples = getattr(api, args.command)(limit=args.limit)
            for sample in samples:
                print(
                    f"id={sample['id']} {sample['received_at']} from {sample['source']} "
                    f"{sample['length']}B {api.payload(sample)!r}"
                )
            print(f"{len(samples)} sample(s)")
        elif args.command == "clear":
            print(f"cleared {api.clear()} sample(s)")
        elif args.command == "count":
            print(api.count())
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
