"""Shared fixtures for the protocol tests.

By default a server is spawned locally as a subprocess so `pytest` works with
no setup. To test an already-running instance (docker compose, a test node,
...) set CIA_SERVER_HOST, e.g.:

    CIA_SERVER_HOST=localhost CIA_REST_TOKEN=<token> pytest test/
    CIA_SERVER_HOST=node-test-07 CIA_REST_PORT=8080 pytest test/
"""

import os
import subprocess
import sys
import time
from pathlib import Path

import pytest
import requests

from harness_client import SampleApiClient

REPO_ROOT = Path(__file__).resolve().parent.parent
SERVER = REPO_ROOT / "src" / "server.py"

PONG_PORT = int(os.environ.get("CIA_PONG_PORT", 3000))
SAMPLE_PORT = int(os.environ.get("CIA_SAMPLE_PORT", 3001))
REST_PORT = int(os.environ.get("CIA_REST_PORT", 8080))

# Token used for the locally spawned server; overridden by CIA_REST_TOKEN when
# testing an external instance.
TEST_TOKEN = "test-token-not-a-secret-0123456789"


class ServerHandle(SampleApiClient):
    """The harness client plus the UDP/TCP port numbers the tests send on."""

    def __init__(self, host, token):
        super().__init__(host, token=token, port=REST_PORT)
        self.pong_port = PONG_PORT
        self.sample_port = SAMPLE_PORT


def _wait_for_health(handle, timeout=15.0):
    deadline = time.monotonic() + timeout
    last_error = None
    while time.monotonic() < deadline:
        try:
            response = handle.request("GET", "/health", timeout=1.0)
            if response.ok:
                return
            last_error = f"HTTP {response.status_code} {response.text[:200]}"
        except requests.RequestException as exc:
            last_error = exc
        time.sleep(0.1)
    raise RuntimeError(f"REST API at {handle.api} never became healthy: {last_error}")


@pytest.fixture(scope="session")
def server():
    external = os.environ.get("CIA_SERVER_HOST")
    if external:
        handle = ServerHandle(external, os.environ.get("CIA_REST_TOKEN", ""))
        _wait_for_health(handle)
        yield handle
        return

    env = dict(
        os.environ,
        PONG_PROTOCOL_PORT=str(PONG_PORT),
        UDP_SAMPLE_DUT_PORT=str(SAMPLE_PORT),
        REST_API_PORT=str(REST_PORT),
        REST_API_TOKEN=TEST_TOKEN,
        # The tests hammer UDP faster than any real DUT would.
        UDP_GLOBAL_RATE="0",
        UDP_PER_IP_RATE="0",
    )
    env.pop("ALLOWED_SOURCES", None)
    env.pop("REST_TLS_CERT", None)
    env.pop("REST_TLS_KEY", None)
    process = subprocess.Popen(
        [sys.executable, "-u", str(SERVER)],
        cwd=str(SERVER.parent),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    handle = ServerHandle("localhost", TEST_TOKEN)
    try:
        try:
            _wait_for_health(handle)
        except RuntimeError:
            if process.poll() is not None:
                raise RuntimeError(
                    f"server exited with {process.returncode}:\n{process.stdout.read()}"
                ) from None
            raise
        yield handle
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()


@pytest.fixture
def clean_store(server):
    """Start each test from an empty sample store."""
    server.request("DELETE", "/samples").raise_for_status()
    return server
