# cia-udp-tcp-testing

Test server for DUT connectivity checks.

| Endpoint | Purpose |
| --- | --- |
| `udp/3000`, `tcp/3000` | Pong: echoes back `PONG: <payload>` |
| `udp/3001` | Sample sink: datagrams containing `\x00\x00\x00` are stored |
| `tcp/8080` | REST API for reading stored samples |

The REST API replaces the old "send `foobar` on `tcp/3002`" protocol.

**Read [Security](#security) before exposing this to the internet.** The pong
ports are a traffic reflector and cannot be made safe by authentication.

## Configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| `PONG_PROTOCOL_PORT` | `3000` | UDP + TCP pong port |
| `UDP_SAMPLE_DUT_PORT` | `3001` | UDP sample sink |
| `REST_API_PORT` | `8080` | REST API port |
| `REST_API_TOKEN` | *(none)* | Bearer token; **required** unless `ALLOW_NO_AUTH` is set |
| `ALLOW_NO_AUTH` | unset | Set to `1` to run the API with no auth (refuses to start otherwise) |
| `REST_TLS_CERT` / `REST_TLS_KEY` | *(none)* | Enable HTTPS; must be set together |
| `ALLOWED_SOURCES` | *(empty = all)* | Comma-separated IPs/CIDRs allowed on **all** listeners |
| `SAMPLE_STORE_LIMIT` | `10000` | Max retained samples; oldest are evicted and counted in `dropped` |
| `SAMPLE_STORE_BYTES` | `64 MiB` | Total payload budget; oldest evicted when exceeded |
| `SAMPLE_RETENTION_S` | `900` | Age limit; must exceed a test's run time plus its polling |
| `MAX_SAMPLE_BYTES` | `65536` | Per-sample size cap (also the HTTP body cap) |
| `UDP_GLOBAL_RATE` | `500` | Datagrams/s across all sources, per listener (`0` disables) |
| `UDP_PER_IP_RATE` | `100` | Datagrams/s per source IP, per listener (`0` disables) |
| `UDP_RATE_TRACKED_IPS` | `4096` | Bound on the per-IP bucket table |
| `STATS_INTERVAL` | `300` | Seconds between JSON traffic log lines (`0` disables) |
| `MAX_TRACKED_SOURCES` | `1024` | Bound on the traffic-stats table |
| `PAYLOAD_PREVIEW_BYTES` | `16` | Bytes of the last payload kept per source |
| `LOG_EVERY_PACKET` | `0` | Set to `1` for a log line per packet (debugging only) |

Buckets allow a burst of twice their rate. Worst-case store memory is roughly
`SAMPLE_STORE_LIMIT * MAX_SAMPLE_BYTES` (64 MB at defaults).

## REST API (`/api/v1`)

All endpoints require `Authorization: Bearer $REST_API_TOKEN` when a token is
configured, `/health` included.

### `GET /api/v1/health`

```json
{"status": "ok", "stored": 0, "dropped": 0,
 "udp_throttled": {"pong": 0, "samples": 0}, "tracked_sources": 3,
 "ports": {"udp_pong": 3000, "tcp_pong": 3000, "udp_samples": 3001, "rest_api": 8080}}
```

### `GET /api/v1/stats`

Cumulative per-source traffic counters — the same data as the JSON log lines.
See [Observing traffic](#observing-traffic).

### `GET /api/v1/cursor`

`{"last_id": 42, "server_time": "...", "stored": 17}` — the current end of the
log, with no side effects. Take this before starting a DUT.

### `GET /api/v1/flows`

Samples grouped by source `(ip, port)`; one flow per DUT boot.

- `since` — only flows that started after this sample id.
- `min_packets` — only flows with at least this many packets in the window.
- `include_ongoing` (default `false`) — also report flows that started earlier,
  marked `"new": false`.

```json
{"count": 1, "since": 10, "min_packets": 3, "include_ongoing": false, "last_id": 25,
 "flows": [{"ip": "10.0.0.5", "port": 41234, "packets": 15, "packets_since": 15,
            "bytes": 150, "first_id": 11, "last_id": 25, "first_seen": "...",
            "last_seen": "...", "new": true, "duration_s": 14.02}]}
```

### `GET /api/v1/samples`

Reads stored samples, oldest first.

- `since` — only samples newer than this id; never consumes. Cannot be combined
  with `drain=true` (that returns `400`).
- `drain` (default `true`, or `false` when `since` is given) — consume on read,
  matching the old TCP behaviour. **Destroys samples belonging to other runs in
  flight**; see [Concurrent test runs](#concurrent-test-runs).
- `limit` — return at most N samples.

```json
{"count": 1, "drained": true, "remaining": 0,
 "samples": [{"id": 1, "received_at": "2026-08-14T09:00:00+00:00",
              "source": "10.0.0.5:41234", "length": 4,
              "data_b64": "AAAAqg==", "data_hex": "000000aa"}]}
```

Payloads are binary, so each sample carries both `data_b64` and `data_hex`.

### `POST /api/v1/samples`

Injects a sample without a DUT — a testing aid for the read path. Body is
either raw bytes (non-JSON content type) or JSON with exactly one of
`data_b64`, `data_hex`, `text`. Returns `201` and the stored sample. The
`\x00\x00\x00` marker requirement is **not** applied to injected samples.

### `DELETE /api/v1/samples`

Clears the store: `{"cleared": 3, "remaining": 0}`.

Errors are JSON: `{"error": "<reason>", "status": 400}`. Auth failures return
`401` with a `WWW-Authenticate` challenge; a blocked source address gets `403`;
an oversized body gets `413`.

## Test harness integration

The old flow — open `tcp/3002`, send `b"foobar"`, parse the returned text blob —
becomes an authenticated HTTP GET. **If more than one test run can be in flight
at a time, read [Concurrent test runs](#concurrent-test-runs) first**; the
erase-run-read cycle below is only safe when runs are serialised.

1. `GET /cursor` to note where the log ends.
2. Trigger the DUT; it sends datagrams to `udp/3001` as before.
3. Poll `GET /flows?since=<cursor>&min_packets=3` until a flow qualifies — **UDP
   delivery is asynchronous, so a single GET straight after the trigger will
   usually race and see nothing.**

Nothing is consumed, so concurrent runs do not destroy each other's data.
Payloads are binary, so each sample carries `data_b64` and `data_hex` rather
than raw bytes.

### Python (`requests`)

`test/harness_client.py` is importable from a harness and doubles as a CLI. It
is the same client the test suite uses, so it stays exercised.

```python
import os
from harness_client import SampleApiClient

api = SampleApiClient("testserver", token=os.environ["REST_API_TOKEN"])

cursor = api.cursor()                 # before power-on
dut.run_connectivity_test()           # your existing trigger; board sends 1/s
flows = api.wait_for_flow(cursor, min_packets=3, timeout=30)

assert flows, "no device sent 3 packets in this window"
print(flows[0]["ip"], flows[0]["port"], flows[0]["packets"])
```

`wait_for_flow` polls `/flows` and consumes nothing, so it is safe with
concurrent runs — subject to the attribution limit described in [Concurrent test
runs](#concurrent-test-runs).

When runs are serialised, the simpler consuming form still works. `collect()` is
`wait_for_samples()` followed by `drain()`:

```python
api.clear()
dut.run_connectivity_test()
payloads = api.collect(count=3)     # [b'\x00\x00\x00...', ...]
```

Use the pieces directly when you need the metadata (`id`, `received_at`,
`source`, `length`):

```python
samples = api.wait_for_samples(count=2, timeout=10)   # blocks, does not consume
for sample in api.drain():
    print(sample["id"], sample["source"], SampleApiClient.payload(sample))

api.inject(b"\x00\x00\x00synthetic")   # store a sample with no DUT involved
print(api.count(), api.health(), api.stats())
```

`wait_for_samples` raises `TimeoutError`; every other method raises
`requests.HTTPError` on a non-2xx response. For TLS, pass
`scheme="https"` (and `verify=False` or a CA bundle path for a self-signed cert).

Without the helper, plain `requests` is:

```python
import base64, requests

API = "http://testserver:8080/api/v1"
AUTH = {"Authorization": f"Bearer {os.environ['REST_API_TOKEN']}"}

requests.delete(f"{API}/samples", headers=AUTH, timeout=5).raise_for_status()
# ... trigger the DUT, poll until count > 0 ...
response = requests.get(f"{API}/samples", headers=AUTH, params={"drain": "true"}, timeout=5)
response.raise_for_status()
for sample in response.json()["samples"]:
    print(sample["source"], base64.b64decode(sample["data_b64"]))
```

### curl

```sh
API=http://testserver:8080/api/v1
AUTH="Authorization: Bearer $REST_API_TOKEN"

# 1. note where the log ends, before power-on
CURSOR=$(curl -sf -H "$AUTH" "$API/cursor" | jq .last_id)

# 2. boot the board, then poll for a flow of >= 3 packets (don't assume)
for _ in $(seq 60); do
  FLOWS=$(curl -sf -H "$AUTH" "$API/flows?since=$CURSOR&min_packets=3")
  [ "$(echo "$FLOWS" | jq .count)" -gt 0 ] && break
  sleep 0.5
done
echo "$FLOWS" | jq '.flows[] | {ip, port, packets, duration_s}'

# serialised runs only: the consuming form destroys other runs' samples
curl -sf -X DELETE -H "$AUTH" "$API/samples"
curl -sf -H "$AUTH" "$API/samples?drain=true" | jq

# payloads as text
curl -sf -H "$AUTH" "$API/samples?drain=true" | jq -r '.samples[].data_b64' | base64 -d

# read-only inspection, newest 10
curl -sf -H "$AUTH" "$API/samples?drain=false&limit=10" | jq '.samples[] | {id, source, data_hex}'

# who has been talking to the UDP ports
curl -sf -H "$AUTH" "$API/stats" | jq '.sources[] | {listener, ip, packets, n_ok, n_throttled}'
curl -sf -H "$AUTH" "$API/health" | jq
```

`-f` makes curl exit non-zero on HTTP errors, which is what you want in CI — but
it also suppresses the JSON error body, so drop it when debugging a 401/403.

The CLI form of the client is handy for poking at a live server:

```sh
python3 test/harness_client.py --host testserver --token "$REST_API_TOKEN" drain
python3 test/harness_client.py --token "$REST_API_TOKEN" stats
python3 test/harness_client.py --token "$REST_API_TOKEN" clear
```

## Concurrent test runs

The workload: a board boots, sends a zero-payload datagram every second, and
after 15 s the harness checks that at least 3 arrived. Several such runs overlap,
and **every boot gets a fresh IP and source port**, so a run cannot recognise its
own device by address.

### Why erase-run-read produced false negatives

`DELETE /samples` + run + `GET /samples?drain=true` mutates state shared by every
run in flight. Run B's `DELETE` throws away packets run A is still waiting for,
and B's drain consumes them. Both runs then report failures that never happened.
Measured with `test/simulate_concurrent_runs.py` (4 runs, 1 dead board): **2 of 4
runs wrong, both false negatives.**

### The windowed, flow-grouped read

Two changes remove the shared mutable state:

- **Reads are non-destructive.** `GET /cursor` returns the current end of the
  log; `?since=<cursor>` returns only what arrived afterwards. Neither consumes
  anything, so any number of runs can read concurrently. The store is bounded by
  age, count and bytes instead of by consumers draining it.
- **Samples are grouped into flows.** One flow is one `(ip, port)` pair, which
  for these devices is one boot. `GET /flows?since=&min_packets=3` asks the
  question a test actually cares about — *did one device send 3 packets?* —
  rather than *did 3 packets arrive from anyone?*

Only flows whose **first ever** packet arrived after your cursor are returned.
This matters: a neighbouring board that was already streaming when you took your
cursor would otherwise look like a brand new flow inside your window and vouch
for a board that never sent anything. Pass `include_ongoing=true` to see those,
marked `"new": false`.

```python
cursor = api.cursor()                                   # before power-on
boot_dut()
flows = api.wait_for_flow(cursor, min_packets=3, timeout=30)
```

Measured on the same 4-run scenario: **0 false negatives**, in both
simultaneous and staggered starts.

### The limit, stated plainly

This does not make the check sound. With no identity in the traffic, a run cannot
distinguish *my board sent 3 packets* from *somebody's board sent 3 packets*. So
the flakiness moves rather than vanishing: in the 4-run scenario with one dead
board, the dead board's run **passes on a neighbour's flow** — one false positive
in place of two false negatives.

That is a better trade for CI stability but a worse failure mode, because the run
that should have failed is exactly the one this test exists to catch. Reproduce
both with:

```sh
python3 test/simulate_concurrent_runs.py --token "$REST_API_TOKEN" \
    --runs 4 --broken-runs 3 --duration 15 --stagger 1
```

Closing the gap needs identity in the traffic, and both options are cheap if the
harness already configures the DUT:

1. **A destination port per run.** Give each concurrent slot its own UDP port
   (3001, 3002, …) and tell the board which to use. Attribution becomes exact
   and server-side — no payload change, no heuristics. Best option if the test
   configuration already carries the server address.
2. **An identifier in the payload.** Even two bytes of run id makes attribution
   exact regardless of addressing. Requires touching the firmware or test
   payload, which "zero-data packets" may not allow.

Failing both, a server-side **exclusive flow claim** (each run claims one
distinct flow, first-come) would guarantee that exactly one run fails per dead
board, though possibly not the right one — enough for a retry to resolve it.
Not implemented; ask if you want it.

### Two things to check on the device side

- **Truly empty datagrams are dropped.** The store requires the `\x00\x00\x00`
  marker, so a zero-*length* payload is discarded outright and no read strategy
  will help. A zero-*filled* payload of 3 bytes or more is fine. `n_no_marker`
  in `/stats` counts these.
- **The source port must be stable for a whole boot.** Flow grouping assumes one
  socket per boot. If the firmware opens a new socket per packet, every packet
  becomes its own flow and `min_packets` can never be met. Check
  `distinct_source_ports` in `/stats` against the packet count.

## Observing traffic

The pong port has to stay public — the LTE DUTs use it to verify their
networking still works — so the practical question is who is actually talking to
it. Every listener keeps aggregate counters per `(listener, source IP)`:
packets, bytes, per-source-port counts, per-event counts, first/last seen, and a
16-byte preview of the last accepted payload.

Per-packet logging is **off** by default (`LOG_EVERY_PACKET=1` re-enables it for
short debugging runs). Instead, one JSON line per active source is written to
stdout every `STATS_INTERVAL` seconds:

```json
{"type": "traffic", "ts": "...", "listener": "udp/3000", "ip": "127.0.0.1",
 "first_seen": "...", "last_seen": "...", "packets": 3, "bytes": 36,
 "distinct_source_ports": 3, "source_ports": {"51317": 1, "55217": 1, "57711": 1},
 "source_ports_untracked": 0, "last_payload_hex": "4455542d303720616c697665",
 "last_payload_text": "DUT-07 alive", "n_ok": 3, "n_throttled": 0, "n_blocked": 0,
 "n_refused_port": 0, "n_no_marker": 0, "n_oversize": 0,
 "packets_window": 3, "bytes_window": 36, "pps_window": 1.5}
```

Each window closes with a `traffic_summary` line carrying tracked-source and
throttle totals. At 300 s that is a few thousand lines over several days, and
`compose.yaml` caps the log driver at 20 MB × 5 files.

### Running an observation

```sh
docker compose up --build -d          # ALLOWED_SOURCES empty, so nothing is filtered

# ... let it run for a few days ...

docker compose logs --no-log-prefix app | python3 test/analyze_traffic.py --ports
curl -sH "Authorization: Bearer $REST_API_TOKEN" localhost:8080/api/v1/stats | jq
```

`analyze_traffic.py` folds the windows into a per-source table, flags sources
using many source ports (the carrier-NAT signature), and prints a suggested
`ALLOWED_SOURCES` line:

```
listener / source     packets  peak/s  ports  events
----------------------------------------------------
udp/3000 127.0.0.1         12    3.00     12  ok=12
                    last payload: 'DUT-07 alive'
udp/3001 127.0.0.1          4    1.00      4  ok=4

1 distinct source IP(s) across 2 listener/source pairs
throttled (cumulative): {'pong': 0, 'samples': 0}
Suggested ALLOWED_SOURCES: 127.0.0.1
```

It tolerates `docker compose logs` prefixes, so either form of the pipe works.

Two things to read off the result. **Distinct source IPs** tell you whether the
fleet shares carrier NAT addresses — few IPs with many rotating source ports
means NAT, and per-IP rate limits then apply to the whole pool at once. **A
non-zero `n_throttled` or `throttled` total** means the limits are dropping real
traffic and should go up. If your test payloads carry a device identifier, the
`last_payload_text` preview attributes traffic to a specific DUT even when the
addresses are shared.

Analysis with `jq`, if you prefer it raw:

```sh
# busiest sources
docker compose logs --no-log-prefix app | grep '"type": "traffic"' \
  | jq -r '[.ip, .listener, .packets, .pps_window] | @tsv' | sort -u

# peak pps ever seen, to size UDP_GLOBAL_RATE
docker compose logs --no-log-prefix app | grep '"type": "traffic"' \
  | jq -s 'map(.pps_window) | max'
```

The stats table is bounded at `MAX_TRACKED_SOURCES` and, unlike the rate-limiter
table, **never resets** — established sources keep accumulating and new ones are
only counted (`untracked_sources`), so a flood of spoofed addresses cannot erase
days of history.

## Rate limits

Each UDP listener gets its own pair of token buckets, so a pong flood cannot
starve sample ingestion. Every datagram must pass the per-IP bucket and then the
global one; a bucket's burst is twice its rate.

| Bucket | Default | Burst | Notes |
| --- | --- | --- | --- |
| Per-IP | 100/s | 200 | Keyed on source *address* — a carrier NAT pool shares one budget |
| Global | 500/s | 1000 | The only bucket that constrains a spoofed flood |

Rejected datagrams are dropped with no reply and counted in `n_throttled` for
that source, plus the per-listener `throttled` totals in `/health`.

**Sizing.** The defaults assume the real fleet: under 10 devices at ~1 pps, so
about 10 pps aggregate — roughly 50× headroom. That margin is deliberate. A
global bucket set close to real traffic hands anyone a cheap kill switch: the
bucket is first-come-first-served, so an attacker sending `A` pps while the fleet
sends `L` gets your devices only `rate × L/(A+L)` through, and a failed pong
looks like "LTE is down" to the DUT. At 500/s an attacker needs to sustain a real
flood before your tests notice, and the cap still limits how much reflected
traffic this host can contribute.

Per-IP limiting is the weaker of the two here: it cannot tell your devices apart
behind NAT, and a spoofed flood gets a fresh bucket per forged address. Keep it
generous — it exists to catch one runaway device, not attacks.

## Security

### The pong ports are the biggest exposure, not the REST API

`udp/3000` replies to any datagram, which makes it a **DDoS reflector**: an
attacker spoofs a victim's source address, and this server sends the traffic to
the victim. The reply is 6 bytes larger than the request, so it amplifies too.
Internet-wide scanners find open UDP echo services within hours, and the
consequence is an abuse notice or a null-route from the hosting provider.

This port is required to be public: the LTE DUTs use it as their
"is my networking still up" check, and the DUT-side protocol is a bare datagram,
so no authentication is possible. Mitigations in place:

- **Per-listener global and per-IP rate limits** (see [Rate
  limits](#rate-limits)). The global bucket is the one that constrains a spoofed
  flood.
- **No replies to `NO_REPLY_PORTS`** (7, 13, 17, 19, 53, 123, 161, 389, 1900,
  5353, 11211) or to our own pong port. Without this, a datagram spoofed to
  appear to come from our own address makes the server talk to itself forever,
  each round trip 6 bytes larger.
- **`ALLOWED_SOURCES`**, if the DUTs turn out to sit in known carrier ranges —
  the only control that removes the reflection risk outright. Run an
  [observation](#observing-traffic) first to find out.

Rate limiting bounds the damage; it does not stop the server being used as a
reflector. As long as this port is public, budget for the eventual abuse report
from the hosting provider, and keep `ALLOWED_SOURCES` in mind as the escape
hatch once the real source addresses are known.

### `udp/3001` cannot be authenticated either

Anyone who can reach it can fill the store with junk, evicting real DUT samples
(watch `dropped` in `/health`). The `\x00\x00\x00` marker is a format check, not
a secret. `ALLOWED_SOURCES` is the real control.

### Is a token pointless without TLS?

No — but be clear about what it buys. Over plaintext HTTP a static bearer token:

- **Stops** untargeted internet scanners and bots, which is essentially all of
  the traffic that will actually hit an open port. This is a large, real
  reduction in risk.
- **Does not stop** an attacker on the network path (ISP, transit, hostile
  Wi-Fi). They read the token off the wire and replay it forever, and they can
  read the sample data regardless of any auth scheme.

So a token over HTTP is worth having, and is not a substitute for TLS. Without
auth, any passer-by can drain the store — destroying test evidence and breaking
whatever run was in flight — poison it via `POST`, or wipe it via `DELETE`.

Ranked by how much they actually help. The REST API has no reason to be public
even though the pong port does, so the first item is the one to reach for:

1. **Don't expose the REST port.** Bind it behind WireGuard/Tailscale, or leave
   it off the public interface entirely — the DUTs never touch it, only your test
   runners do. The UDP pong port stays public regardless; that is a separate
   problem and is covered above.
2. **`ALLOWED_SOURCES`** with your test-runner ranges. Note this is a
   peer-address check and is not proxy-aware; behind a reverse proxy it must move
   to the proxy.
3. **TLS + token.** Terminating TLS in a reverse proxy (Caddy gets a
   Let's Encrypt certificate with a three-line config) is less work than the
   in-process option and keeps certificate renewal out of this code.
4. **Token over plaintext HTTP** — the floor. Scanner protection only.

The server fails closed: it refuses to start without `REST_API_TOKEN` unless
`ALLOW_NO_AUTH=1` is set explicitly, and warns loudly when serving plaintext.

### The old certificates are compromised

`src/server.crt`, `src/server.key`, `src/client.crt` and `src/client.key` were
self-signed 2018 leftovers with `CN=example.com` and no SAN, used only by
`src/client.py` against a TLS port on 2443 that this server never served. All
five files have been deleted.

**Deleting them does not undo the exposure.** The private keys were committed to
this repository, so they remain in git history (commit `5e1bf50`) and must be
treated as public — never reuse them or their certificates anywhere. Generate a
fresh key/certificate for `REST_TLS_CERT`/`REST_TLS_KEY`, and keep it out of the
repo (mount it into the container instead).

### Other notes

- `POST /api/v1/samples` bypasses the marker filter. It exists for tests; drop
  the route if this ever faces anything untrusted.
- Sample `source` fields expose DUT IP addresses to anyone holding the token.
- `MAX_SAMPLE_BYTES` bounds both a single HTTP body and a stored datagram, and
  with `SAMPLE_STORE_LIMIT` bounds total memory.
- TCP pong is not a reflection risk (the handshake defeats spoofing) and is not
  rate limited. It is still counted in the traffic stats as `tcp/3000`.
- `last_payload_text` / `last_payload_hex` in `/stats` retain up to
  `PAYLOAD_PREVIEW_BYTES` of DUT traffic. Lower it to `0` if the payloads carry
  anything sensitive.

## Running

```sh
export REST_API_TOKEN="$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')"
docker compose up --build          # ports 3000/udp, 3000/tcp, 3001/udp, 8080/tcp

# or directly
pip install -r requirements.txt
REST_API_TOKEN=... ALLOWED_SOURCES=10.0.0.0/8 python3 -u src/server.py
```

## Tests

```sh
pip install -r requirements.txt -r requirements-test.txt

pytest test/ -v          # spawns its own server subprocess with a known token
CIA_SERVER_HOST=localhost CIA_REST_TOKEN="$REST_API_TOKEN" pytest test/ -v

python3 test/exercise_flow.py --token "$REST_API_TOKEN"     # stdlib-only driver
python3 test/exercise_flow.py --host node-test-07 --https --insecure --count 5 --keep
```

`test/test_security.py` covers auth, size caps and the source allowlist over the
wire, and unit tests the rate limiter directly so timing stays deterministic.
`test/test_stats.py` covers the traffic counters and the JSON log format.
`test/analyze_traffic.py` summarises a completed observation run — see
[Observing traffic](#observing-traffic).
