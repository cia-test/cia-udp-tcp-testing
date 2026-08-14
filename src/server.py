import asyncio
import base64
import binascii
import ipaddress
import json
import os
import secrets
import ssl
import sys
import time
from collections import deque
from datetime import datetime, timezone

from aiohttp import web

PONG_PROTOCOL_PORT = int(os.environ.get("PONG_PROTOCOL_PORT", 3000))
UDP_SAMPLE_DUT_PORT = int(os.environ.get("UDP_SAMPLE_DUT_PORT", 3001))
REST_API_PORT = int(os.environ.get("REST_API_PORT", 8080))

# Retention. Reads are non-destructive, so the store is bounded by all three of
# these instead of by consumers draining it: whichever limit is hit first evicts
# the oldest samples. The age limit is the meaningful one for concurrent tests —
# it must comfortably exceed a test's run time plus its polling.
SAMPLE_STORE_LIMIT = int(os.environ.get("SAMPLE_STORE_LIMIT", 10000))
SAMPLE_STORE_BYTES = int(os.environ.get("SAMPLE_STORE_BYTES", 64 * 1024 * 1024))
SAMPLE_RETENTION_S = float(os.environ.get("SAMPLE_RETENTION_S", 900))
MAX_SAMPLE_BYTES = int(os.environ.get("MAX_SAMPLE_BYTES", 65536))

# A datagram on UDP_SAMPLE_DUT_PORT is only stored if it carries this marker.
SAMPLE_MARKER = b"\x00\x00\x00"

# Shared secret for the REST API. Unset means the API refuses to start unless
# ALLOW_NO_AUTH is set explicitly (see check_auth_config).
REST_API_TOKEN = os.environ.get("REST_API_TOKEN", "")
ALLOW_NO_AUTH = os.environ.get("ALLOW_NO_AUTH", "") not in ("", "0", "false", "no")

# Optional TLS for the REST API. Without it the bearer token crosses the
# network in plaintext (see README, "Security").
REST_TLS_CERT = os.environ.get("REST_TLS_CERT", "")
REST_TLS_KEY = os.environ.get("REST_TLS_KEY", "")

# Comma-separated IPs/CIDRs permitted to reach any listener. Empty = allow all.
ALLOWED_SOURCES = os.environ.get("ALLOWED_SOURCES", "")

# UDP rate limits, applied as separate bucket sets per listener. The global
# bucket is what actually caps reflection damage: per-IP limits are trivially
# bypassed with spoofed source addresses, and are per *address*, so DUTs behind
# one carrier NAT share a single per-IP budget.
#
# Sized for a small fleet (<10 devices at ~1 pps each, so ~10 pps expected).
# The headroom is deliberate: a global bucket near the real traffic level lets
# anyone starve the whole fleet's connectivity checks with a trivial flood.
UDP_GLOBAL_RATE = float(os.environ.get("UDP_GLOBAL_RATE", 500))
UDP_PER_IP_RATE = float(os.environ.get("UDP_PER_IP_RATE", 100))
UDP_RATE_TRACKED_IPS = int(os.environ.get("UDP_RATE_TRACKED_IPS", 4096))

# Source ports we never reply to: our own (self-sustaining echo loop if someone
# spoofs our address) and other well-known UDP services that would loop with us.
NO_REPLY_PORTS = frozenset({7, 13, 17, 19, 53, 123, 161, 389, 1900, 5353, 11211})

# Traffic accounting. Aggregate per-source counters are logged as JSON lines
# every STATS_INTERVAL seconds and exposed at GET /api/v1/stats, so a multi-day
# run can be analysed without a log line per packet.
STATS_INTERVAL = float(os.environ.get("STATS_INTERVAL", 300))
MAX_TRACKED_SOURCES = int(os.environ.get("MAX_TRACKED_SOURCES", 1024))
PAYLOAD_PREVIEW_BYTES = int(os.environ.get("PAYLOAD_PREVIEW_BYTES", 16))
LOG_EVERY_PACKET = os.environ.get("LOG_EVERY_PACKET", "") not in ("", "0", "false", "no")

# Per-source cap on how many distinct source ports we remember individually.
MAX_SOURCE_PORTS = 32

API_ROOT = "/api/v1"


def _now():
    return datetime.now(timezone.utc).isoformat()


def parse_allowed_sources(spec):
    networks = []
    for entry in spec.split(","):
        entry = entry.strip()
        if entry:
            networks.append(ipaddress.ip_network(entry, strict=False))
    return networks


def source_allowed(networks, host):
    """True if `host` is covered by `networks` (an empty list allows all)."""
    if not networks:
        return True
    if host is None:
        return False
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    return any(address in network for network in networks)


class TokenBucket:
    def __init__(self, rate, burst=None):
        self.rate = float(rate)
        self.burst = float(burst if burst is not None else max(rate * 2, 1))
        self.tokens = self.burst
        self.updated = None

    def allow(self, now):
        if self.rate <= 0:
            return True
        if self.updated is None:
            self.updated = now
        self.tokens = min(self.burst, self.tokens + max(0.0, now - self.updated) * self.rate)
        self.updated = now
        if self.tokens >= 1.0:
            self.tokens -= 1.0
            return True
        return False


class UdpRateLimiter:
    """Global + per-source-IP token buckets with a bounded tracking table."""

    def __init__(self, global_rate, per_ip_rate, max_tracked):
        self._global = TokenBucket(global_rate)
        self._per_ip_rate = per_ip_rate
        self._max_tracked = max_tracked
        self._buckets = {}
        self.throttled = 0
        self.table_resets = 0

    def allow(self, host, now=None):
        now = time.monotonic() if now is None else now
        if self._per_ip_rate > 0 and host is not None:
            bucket = self._buckets.get(host)
            if bucket is None:
                # Spoofed sources would otherwise grow this table without bound.
                if len(self._buckets) >= self._max_tracked:
                    self._buckets.clear()
                    self.table_resets += 1
                bucket = self._buckets[host] = TokenBucket(self._per_ip_rate)
            if not bucket.allow(now):
                self.throttled += 1
                return False
        if not self._global.allow(now):
            self.throttled += 1
            return False
        return True


class SourceRecord:
    """Aggregate counters for one (listener, source IP) pair."""

    EVENTS = ("ok", "throttled", "blocked", "refused_port", "no_marker", "oversize")

    def __init__(self, listener, host):
        self.listener = listener
        self.host = host
        self.first_seen = _now()
        self.last_seen = self.first_seen
        self.packets = 0
        self.bytes = 0
        self.packets_window = 0
        self.bytes_window = 0
        self.events = dict.fromkeys(self.EVENTS, 0)
        self.source_ports = {}
        self.source_ports_untracked = 0
        self.last_payload_hex = ""
        self.last_payload_text = ""

    def observe(self, port, data, event):
        self.last_seen = _now()
        self.packets += 1
        self.packets_window += 1
        if data is not None:
            self.bytes += len(data)
            self.bytes_window += len(data)
        self.events[event] = self.events.get(event, 0) + 1

        if port is not None:
            if port in self.source_ports:
                self.source_ports[port] += 1
            elif len(self.source_ports) < MAX_SOURCE_PORTS:
                self.source_ports[port] = 1
            else:
                # Carrier NAT rotates source ports; remembering every one would
                # be unbounded, so only the count of the rest is kept.
                self.source_ports_untracked += 1

        if data and event == "ok":
            preview = data[:PAYLOAD_PREVIEW_BYTES]
            self.last_payload_hex = preview.hex()
            self.last_payload_text = "".join(
                chr(b) if 32 <= b < 127 else "." for b in preview
            )

    def to_dict(self, window_seconds=None):
        body = {
            "listener": self.listener,
            "ip": self.host,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "packets": self.packets,
            "bytes": self.bytes,
            "distinct_source_ports": len(self.source_ports) + self.source_ports_untracked,
            "source_ports": dict(sorted(self.source_ports.items())),
            "source_ports_untracked": self.source_ports_untracked,
            "last_payload_hex": self.last_payload_hex,
            "last_payload_text": self.last_payload_text,
            **{f"n_{name}": count for name, count in self.events.items()},
        }
        if window_seconds:
            body["packets_window"] = self.packets_window
            body["bytes_window"] = self.bytes_window
            body["pps_window"] = round(self.packets_window / window_seconds, 3)
        return body


class TrafficStats:
    """Who is talking to us, on which listener, from which source ports.

    Bounded at max_sources. Unlike the rate limiter's table this does *not*
    reset when full: established sources keep accumulating and new ones are
    only counted, so a flood of spoofed addresses cannot erase days of data.
    """

    def __init__(self, max_sources=None):
        self._max_sources = MAX_TRACKED_SOURCES if max_sources is None else max_sources
        self._records = {}
        self.untracked_sources = 0

    def record(self, listener, host, port=None, data=None, event="ok"):
        key = (listener, host)
        record = self._records.get(key)
        if record is None:
            if len(self._records) >= self._max_sources:
                self.untracked_sources += 1
                return None
            record = self._records[key] = SourceRecord(listener, host)
        record.observe(port, data, event)
        return record

    def snapshot(self):
        return [record.to_dict() for record in self._sorted()]

    def flush_window(self, window_seconds):
        """Return dicts for sources active since the last flush, then reset."""
        active = []
        for record in self._sorted():
            if record.packets_window:
                active.append(record.to_dict(window_seconds))
                record.packets_window = 0
                record.bytes_window = 0
        return active

    def _sorted(self):
        return sorted(self._records.values(), key=lambda r: (r.listener, r.host or ""))

    def __len__(self):
        return len(self._records)


async def stats_logger(stats, limiters, interval):
    """Emit one JSON line per active source per interval, plus a summary."""
    while True:
        await asyncio.sleep(interval)
        timestamp = _now()
        for body in stats.flush_window(interval):
            print(json.dumps({"type": "traffic", "ts": timestamp, **body}), flush=True)
        print(
            json.dumps(
                {
                    "type": "traffic_summary",
                    "ts": timestamp,
                    "window_s": interval,
                    "tracked_sources": len(stats),
                    "untracked_sources": stats.untracked_sources,
                    "throttled": {name: lim.throttled for name, lim in limiters.items()},
                }
            ),
            flush=True,
        )


class Sample:
    """One stored datagram. `monotonic` is internal, for retention only."""

    __slots__ = ("id", "received_at", "monotonic", "ip", "port", "length",
                 "data_b64", "data_hex")

    def __init__(self, sample_id, data, ip=None, port=None):
        self.id = sample_id
        self.received_at = _now()
        self.monotonic = time.monotonic()
        self.ip = ip
        self.port = port
        self.length = len(data)
        self.data_b64 = base64.b64encode(data).decode()
        self.data_hex = data.hex()

    @property
    def flow(self):
        """The only identity a DUT has: its source address and port.

        LTE devices get a fresh IP and port on every boot, so one flow is one
        boot session, and packets from concurrent tests land in different flows.
        """
        return (self.ip, self.port)

    def to_dict(self):
        return {
            "id": self.id,
            "received_at": self.received_at,
            "source": f"{self.ip}:{self.port}" if self.ip else None,
            "ip": self.ip,
            "port": self.port,
            "length": self.length,
            "data_b64": self.data_b64,
            "data_hex": self.data_hex,
        }


class SampleStore:
    """Ordered store of samples, bounded by count, bytes and age.

    Reads are non-destructive by default (see `since`), because a drain-on-read
    store cannot serve concurrent test runs: whoever reads first consumes
    everyone else's packets.
    """

    def __init__(self, maxlen=None, max_bytes=None, retention_s=None):
        self._maxlen = SAMPLE_STORE_LIMIT if maxlen is None else maxlen
        self._max_bytes = SAMPLE_STORE_BYTES if max_bytes is None else max_bytes
        self._retention_s = SAMPLE_RETENTION_S if retention_s is None else retention_s
        self._samples = deque()
        self._bytes = 0
        self._next_id = 1
        self.dropped = 0
        self.evictions = {"count": 0, "bytes": 0, "expired": 0}

    # -- writing ----------------------------------------------------------

    def add(self, data, ip=None, port=None):
        sample = Sample(self._next_id, data, ip, port)
        self._next_id += 1
        self._samples.append(sample)
        self._bytes += sample.length
        self._evict()
        return sample.to_dict()

    def _drop_oldest(self, reason):
        sample = self._samples.popleft()
        self._bytes -= sample.length
        self.dropped += 1
        self.evictions[reason] += 1

    def _evict(self):
        if self._retention_s > 0:
            cutoff = time.monotonic() - self._retention_s
            while self._samples and self._samples[0].monotonic < cutoff:
                self._drop_oldest("expired")
        while self._maxlen > 0 and len(self._samples) > self._maxlen:
            self._drop_oldest("count")
        while self._max_bytes > 0 and self._bytes > self._max_bytes and self._samples:
            self._drop_oldest("bytes")

    # -- reading ----------------------------------------------------------

    @property
    def last_id(self):
        """Cursor: take this before starting a DUT, then read with since=it."""
        return self._next_id - 1

    def _select(self, since=0):
        self._evict()
        return [s for s in self._samples if s.id > since]

    def peek(self, limit=None, since=0):
        """Read samples without consuming them (oldest first)."""
        selected = self._select(since)
        if limit is not None:
            selected = selected[:limit]
        return [s.to_dict() for s in selected]

    def count(self, since=0):
        return len(self._select(since))

    def take(self, limit=None):
        """Read and consume samples. Unsafe when tests run concurrently."""
        self._evict()
        if limit is None:
            limit = len(self._samples)
        taken = []
        for _ in range(min(limit, len(self._samples))):
            sample = self._samples.popleft()
            self._bytes -= sample.length
            taken.append(sample.to_dict())
        return taken

    def flows(self, since=0, min_packets=1, include_ongoing=False):
        """Group samples by source flow, oldest flow first.

        A flow is one (ip, port) pair, which for these devices is one boot, and
        grouping is what lets a run tell its own device's packets apart from the
        packets of every other run in flight.

        By default only flows whose *first ever* packet arrived after `since`
        are returned. That distinction matters: a neighbouring device that was
        already streaming when you took your cursor would otherwise look like a
        brand new flow inside your window, and its packets would vouch for a
        board that never sent anything. Pass include_ongoing=True to see those
        too, reported with `new: false`.
        """
        grouped = {}
        for sample in self._select(0):
            flow = grouped.get(sample.flow)
            if flow is None:
                flow = grouped[sample.flow] = {
                    "ip": sample.ip,
                    "port": sample.port,
                    "packets": 0,
                    "packets_since": 0,
                    "bytes": 0,
                    "first_id": sample.id,
                    "last_id": sample.id,
                    "first_seen": sample.received_at,
                    "last_seen": sample.received_at,
                    "_first_monotonic": sample.monotonic,
                    "_last_monotonic": sample.monotonic,
                }
            flow["packets"] += 1
            flow["bytes"] += sample.length
            flow["last_id"] = sample.id
            flow["last_seen"] = sample.received_at
            flow["_last_monotonic"] = sample.monotonic
            if sample.id > since:
                flow["packets_since"] += 1

        result = []
        for flow in sorted(grouped.values(), key=lambda f: f["first_id"]):
            flow["new"] = flow["first_id"] > since
            span = flow.pop("_last_monotonic") - flow.pop("_first_monotonic")
            flow["duration_s"] = round(span, 3)
            if not flow["new"] and not include_ongoing:
                continue
            if flow["packets_since"] < min_packets:
                continue
            result.append(flow)
        return result

    def clear(self):
        count = len(self._samples)
        self._samples.clear()
        self._bytes = 0
        return count

    def __len__(self):
        self._evict()
        return len(self._samples)


class UdpPong(asyncio.DatagramProtocol):
    """Echoes datagrams back. Note this is a traffic reflector by design: see
    the README before exposing this port to untrusted networks."""

    def __init__(self, limiter, allowed, stats=None, listener=None):
        self.limiter = limiter
        self.allowed = allowed
        self.stats = stats if stats is not None else TrafficStats()
        self.listener = listener or f"udp/{PONG_PROTOCOL_PORT}"
        self.counter = 0

    def connection_made(self, transport):
        print(f"udp: pong connected ({self.listener})")
        self.transport = transport

    def datagram_received(self, data, addr):
        host, port = (addr[0], addr[1]) if addr else (None, None)

        if not source_allowed(self.allowed, host):
            self.stats.record(self.listener, host, port, data, "blocked")
            return
        if port in NO_REPLY_PORTS or port == PONG_PROTOCOL_PORT:
            # Replying here risks an endless packet exchange with another
            # service (or with ourselves, via a spoofed source address).
            self.stats.record(self.listener, host, port, data, "refused_port")
            if LOG_EVERY_PACKET:
                print(f"udp: pong refusing reply to {host}:{port}")
            return
        if not self.limiter.allow(host):
            self.stats.record(self.listener, host, port, data, "throttled")
            return

        self.stats.record(self.listener, host, port, data, "ok")
        if LOG_EVERY_PACKET:
            print(f"udp: pong {host}:{port} {data!r}")
        self.counter += 1
        self.transport.sendto(b"PONG: " + data, addr)


class UdpSampleTest(asyncio.DatagramProtocol):
    """Collects DUT samples for later retrieval over the REST API."""

    def __init__(self, store, limiter, allowed, stats=None, listener=None):
        self.store = store
        self.limiter = limiter
        self.allowed = allowed
        self.stats = stats if stats is not None else TrafficStats()
        self.listener = listener or f"udp/{UDP_SAMPLE_DUT_PORT}"

    def connection_made(self, transport):
        print(f"udp: UdpSampleTest ready ({self.listener})")
        self.transport = transport

    def datagram_received(self, data, addr):
        host, port = (addr[0], addr[1]) if addr else (None, None)

        if not source_allowed(self.allowed, host):
            self.stats.record(self.listener, host, port, data, "blocked")
            return
        if not self.limiter.allow(host):
            self.stats.record(self.listener, host, port, data, "throttled")
            return
        if SAMPLE_MARKER not in data:
            self.stats.record(self.listener, host, port, data, "no_marker")
            if LOG_EVERY_PACKET:
                print(f"udp: rx {len(data)} bytes from {addr}, no marker, dropped")
            return
        if len(data) > MAX_SAMPLE_BYTES:
            self.stats.record(self.listener, host, port, data, "oversize")
            if LOG_EVERY_PACKET:
                print(f"udp: rx {len(data)} bytes from {addr}, over size limit, dropped")
            return

        self.stats.record(self.listener, host, port, data, "ok")
        sample = self.store.add(data, host, port)
        if LOG_EVERY_PACKET:
            print(
                f"udp: stored sample {sample['id']} ({sample['length']} bytes) "
                f"from {sample['source']}"
            )


class TcpPong:
    def __init__(self, allowed, stats=None, listener=None):
        self.allowed = allowed
        self.stats = stats if stats is not None else TrafficStats()
        self.listener = listener or f"tcp/{PONG_PROTOCOL_PORT}"

    async def __call__(self, reader, writer):
        peer = writer.get_extra_info("peername")
        host, port = (peer[0], peer[1]) if peer else (None, None)
        if not source_allowed(self.allowed, host):
            self.stats.record(self.listener, host, port, None, "blocked")
            writer.close()
            return

        data = await reader.read(2048)
        self.stats.record(self.listener, host, port, data, "ok")
        if LOG_EVERY_PACKET:
            print(f"tcp: pong {host}:{port} {data!r}")
        writer.write(b"PONG: " + data)
        await writer.drain()
        writer.close()


# ---------------------------------------------------------------------------
# REST API (replaces the old "send foobar on TCP 3002" protocol)
# ---------------------------------------------------------------------------


def _bool_param(request, name, default):
    raw = request.query.get(name)
    if raw is None:
        return default
    lowered = raw.strip().lower()
    if lowered in ("1", "true", "yes", "on"):
        return True
    if lowered in ("0", "false", "no", "off"):
        return False
    raise web.HTTPBadRequest(reason=f"invalid boolean for '{name}': {raw!r}")


def _int_param(request, name, default=None):
    raw = request.query.get(name)
    if raw is None:
        return default
    try:
        value = int(raw)
    except ValueError:
        raise web.HTTPBadRequest(reason=f"invalid integer for '{name}': {raw!r}")
    if value < 0:
        raise web.HTTPBadRequest(reason=f"'{name}' must be >= 0")
    return value


async def health(request):
    store = request.app["store"]
    limiters = request.app["limiters"]
    stats = request.app["stats"]
    return web.json_response(
        {
            "status": "ok",
            "stored": len(store),
            "last_id": store.last_id,
            "dropped": store.dropped,
            "evictions": store.evictions,
            "udp_throttled": {name: lim.throttled for name, lim in limiters.items()},
            "tracked_sources": len(stats),
            "ports": {
                "udp_pong": PONG_PROTOCOL_PORT,
                "tcp_pong": PONG_PROTOCOL_PORT,
                "udp_samples": UDP_SAMPLE_DUT_PORT,
                "rest_api": REST_API_PORT,
            },
        }
    )


async def get_stats(request):
    """GET /api/v1/stats — cumulative per-source traffic counters.

    The same data is written to stdout as JSON lines every STATS_INTERVAL, so
    long observation runs can be analysed from the container logs.
    """
    stats = request.app["stats"]
    limiters = request.app["limiters"]
    return web.json_response(
        {
            "generated_at": _now(),
            "tracked_sources": len(stats),
            "untracked_sources": stats.untracked_sources,
            "limits": {
                "udp_global_rate": UDP_GLOBAL_RATE,
                "udp_per_ip_rate": UDP_PER_IP_RATE,
                "throttled": {name: lim.throttled for name, lim in limiters.items()},
            },
            "sources": stats.snapshot(),
        }
    )


async def get_cursor(request):
    """GET /api/v1/cursor — the current end of the log.

    Take this before starting a DUT, then read back with ?since=<last_id> to
    see only what arrived afterwards. Has no side effects, so any number of
    concurrent test runs can use it safely.
    """
    store = request.app["store"]
    return web.json_response(
        {"last_id": store.last_id, "server_time": _now(), "stored": len(store)}
    )


async def get_samples(request):
    """GET /api/v1/samples[?since=N][?drain=true][&limit=N]

    Reads the stored DUT samples. `since` returns only samples newer than that
    id and never consumes anything — the safe mode when tests run concurrently.

    Draining mirrors the consume-on-read behaviour of the TCP protocol this
    replaces. It is still the default for compatibility, but it destroys
    samples belonging to every other run in flight.
    """
    store = request.app["store"]
    since = _int_param(request, "since")
    drain = _bool_param(request, "drain", since is None)
    limit = _int_param(request, "limit")

    if since is not None and drain:
        raise web.HTTPBadRequest(
            reason="'since' cannot be combined with drain=true: a windowed read "
            "must not consume samples other test runs still need"
        )

    samples = store.take(limit) if drain else store.peek(limit, since=since or 0)
    return web.json_response(
        {
            "count": len(samples),
            "drained": drain,
            "since": since or 0,
            "remaining": len(store),
            "last_id": store.last_id,
            "samples": samples,
        }
    )


async def get_flows(request):
    """GET /api/v1/flows[?since=N][&min_packets=N][&include_ongoing=false]

    Samples grouped by source (ip, port). One flow is one DUT boot, which is
    the closest thing to a device identity available here. Only flows that
    started after `since` are returned unless include_ongoing is set.
    """
    store = request.app["store"]
    since = _int_param(request, "since", 0)
    min_packets = _int_param(request, "min_packets", 1)
    include_ongoing = _bool_param(request, "include_ongoing", False)
    flows = store.flows(
        since=since, min_packets=min_packets, include_ongoing=include_ongoing
    )
    return web.json_response(
        {
            "count": len(flows),
            "since": since,
            "min_packets": min_packets,
            "include_ongoing": include_ongoing,
            "last_id": store.last_id,
            "flows": flows,
        }
    )


async def post_sample(request):
    """POST /api/v1/samples

    Injects a sample without going through UDP. Intended for exercising the
    read path from tests; the UDP marker requirement is not applied here.

    Accepts either a raw body (any non-JSON content type) or JSON with
    exactly one of: {"data_b64": ...}, {"data_hex": ...}, {"text": ...}.
    """
    store = request.app["store"]
    body = await request.read()

    if request.content_type == "application/json":
        try:
            payload = await request.json()
        except ValueError:
            raise web.HTTPBadRequest(reason="body is not valid JSON")
        if not isinstance(payload, dict):
            raise web.HTTPBadRequest(reason="JSON body must be an object")
        keys = [k for k in ("data_b64", "data_hex", "text") if k in payload]
        if len(keys) != 1:
            raise web.HTTPBadRequest(
                reason="provide exactly one of 'data_b64', 'data_hex', 'text'"
            )
        key = keys[0]
        value = payload[key]
        if not isinstance(value, str):
            raise web.HTTPBadRequest(reason=f"'{key}' must be a string")
        try:
            if key == "data_b64":
                data = base64.b64decode(value, validate=True)
            elif key == "data_hex":
                data = bytes.fromhex(value)
            else:
                data = value.encode()
        except (binascii.Error, ValueError):
            raise web.HTTPBadRequest(reason=f"could not decode '{key}'")
    else:
        data = body

    if not data:
        raise web.HTTPBadRequest(reason="empty sample")
    if len(data) > MAX_SAMPLE_BYTES:
        raise web.HTTPRequestEntityTooLarge(
            max_size=MAX_SAMPLE_BYTES, actual_size=len(data)
        )

    peer = request.transport.get_extra_info("peername") if request.transport else None
    ip, port = (peer[0], peer[1]) if peer else (None, None)
    sample = store.add(data, ip, port)
    return web.json_response(sample, status=201)


async def delete_samples(request):
    store = request.app["store"]
    return web.json_response({"cleared": store.clear(), "remaining": len(store)})


@web.middleware
async def json_errors(request, handler):
    """Render HTTP errors as JSON so clients get one consistent content type."""
    try:
        return await handler(request)
    except web.HTTPException as exc:
        if exc.status >= 400:
            headers = {}
            challenge = (exc.headers or {}).get("WWW-Authenticate")
            if challenge:
                headers["WWW-Authenticate"] = challenge
            return web.json_response(
                {"error": exc.reason, "status": exc.status},
                status=exc.status,
                headers=headers,
            )
        raise
    except Exception as exc:  # noqa: BLE001 - draft-level catch-all
        print(f"rest: unhandled error: {exc!r}")
        return web.json_response({"error": "internal server error", "status": 500}, status=500)


@web.middleware
async def require_source(request, handler):
    if not source_allowed(request.app["allowed"], request.remote):
        # request.remote is the peer address; it is NOT proxy-aware. Behind a
        # reverse proxy this check must move to the proxy.
        raise web.HTTPForbidden(reason="source address not allowed")
    return await handler(request)


@web.middleware
async def require_token(request, handler):
    """Static bearer token, compared in constant time.

    Over plaintext HTTP this stops untargeted scanners but not an attacker on
    the network path, who can read the token and replay it. Pair with TLS.
    """
    token = request.app["token"]
    if not token:
        return await handler(request)

    header = request.headers.get("Authorization", "")
    scheme, _, presented = header.partition(" ")
    if scheme.lower() != "bearer" or not secrets.compare_digest(presented.strip(), token):
        raise web.HTTPUnauthorized(
            reason="missing or invalid bearer token",
            headers={"WWW-Authenticate": 'Bearer realm="cia-testrunner"'},
        )
    return await handler(request)


def build_app(store, limiters=None, token=REST_API_TOKEN, allowed=(), stats=None):
    app = web.Application(
        middlewares=[json_errors, require_source, require_token],
        client_max_size=MAX_SAMPLE_BYTES,
    )
    app["store"] = store
    app["limiters"] = dict(limiters or {})
    app["stats"] = stats if stats is not None else TrafficStats()
    app["token"] = token
    app["allowed"] = list(allowed)
    app.add_routes(
        [
            web.get(f"{API_ROOT}/health", health),
            web.get(f"{API_ROOT}/stats", get_stats),
            web.get(f"{API_ROOT}/cursor", get_cursor),
            web.get(f"{API_ROOT}/flows", get_flows),
            web.get(f"{API_ROOT}/samples", get_samples),
            web.post(f"{API_ROOT}/samples", post_sample),
            web.delete(f"{API_ROOT}/samples", delete_samples),
        ]
    )
    return app


# ---------------------------------------------------------------------------
# Startup
# ---------------------------------------------------------------------------


def check_auth_config():
    """Fail closed: refuse to serve an unauthenticated API by accident."""
    if REST_API_TOKEN:
        if len(REST_API_TOKEN) < 16:
            print("WARNING: REST_API_TOKEN is shorter than 16 characters")
        return
    if not ALLOW_NO_AUTH:
        sys.exit(
            "REST_API_TOKEN is not set. Set it to a random secret "
            "(python3 -c 'import secrets; print(secrets.token_urlsafe(32))'), "
            "or set ALLOW_NO_AUTH=1 to serve the API with no authentication."
        )
    print("WARNING: REST API is running with NO AUTHENTICATION (ALLOW_NO_AUTH set)")


def build_tls_context():
    if not REST_TLS_CERT and not REST_TLS_KEY:
        print(
            "WARNING: REST API is plaintext HTTP; the bearer token is readable "
            "by anyone on the network path. Set REST_TLS_CERT/REST_TLS_KEY or "
            "terminate TLS in a reverse proxy."
        )
        return None
    if not (REST_TLS_CERT and REST_TLS_KEY):
        sys.exit("REST_TLS_CERT and REST_TLS_KEY must be set together")
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(REST_TLS_CERT, REST_TLS_KEY)
    return context


async def start_udp_endpoints(store, limiters, allowed, stats):
    loop = asyncio.get_running_loop()

    sample_endpoint = await loop.create_datagram_endpoint(
        lambda: UdpSampleTest(store, limiters["samples"], allowed, stats),
        local_addr=("0.0.0.0", UDP_SAMPLE_DUT_PORT),
    )
    pong_endpoint = await loop.create_datagram_endpoint(
        lambda: UdpPong(limiters["pong"], allowed, stats),
        local_addr=("0.0.0.0", PONG_PROTOCOL_PORT),
    )
    return [sample_endpoint[0], pong_endpoint[0]]


async def start_rest_api(store, limiters, allowed, stats):
    runner = web.AppRunner(
        build_app(store, limiters, REST_API_TOKEN, allowed, stats), access_log=None
    )
    await runner.setup()
    site = web.TCPSite(runner, "0.0.0.0", REST_API_PORT, ssl_context=build_tls_context())
    await site.start()
    scheme = "https" if (REST_TLS_CERT and REST_TLS_KEY) else "http"
    print(f"rest: listening on {scheme}://0.0.0.0:{REST_API_PORT}{API_ROOT}")
    return runner


async def main():
    check_auth_config()
    allowed = parse_allowed_sources(ALLOWED_SOURCES)
    if allowed:
        print(f"net: restricting all listeners to {[str(n) for n in allowed]}")
    else:
        print("WARNING: no ALLOWED_SOURCES set; all listeners accept any source address")

    store = SampleStore(SAMPLE_STORE_LIMIT)
    stats = TrafficStats()
    # Separate buckets per listener so a pong flood cannot starve sample
    # ingestion, which carries the actual test data.
    limiters = {
        name: UdpRateLimiter(UDP_GLOBAL_RATE, UDP_PER_IP_RATE, UDP_RATE_TRACKED_IPS)
        for name in ("pong", "samples")
    }
    print(
        f"net: udp limits per listener: {UDP_GLOBAL_RATE}/s global, "
        f"{UDP_PER_IP_RATE}/s per source IP (burst = 2x)"
    )

    transports = await start_udp_endpoints(store, limiters, allowed, stats)
    pong_server = await asyncio.start_server(
        TcpPong(allowed, stats), "0.0.0.0", PONG_PROTOCOL_PORT
    )
    runner = await start_rest_api(store, limiters, allowed, stats)

    logger_task = None
    if STATS_INTERVAL > 0:
        logger_task = asyncio.create_task(stats_logger(stats, limiters, STATS_INTERVAL))
        print(f"stats: JSON traffic lines every {STATS_INTERVAL}s (also at {API_ROOT}/stats)")

    try:
        await asyncio.Event().wait()
    finally:
        if logger_task is not None:
            logger_task.cancel()
        pong_server.close()
        await pong_server.wait_closed()
        for transport in transports:
            transport.close()
        await runner.cleanup()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
