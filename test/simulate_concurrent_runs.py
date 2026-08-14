#!/usr/bin/env python3
"""Measure read strategies against overlapping test runs, without hardware.

Models the real case: each run boots a device that sends a zero-payload
datagram every second, and the run then checks that at least 3 arrived. Runs
overlap, and every boot gets a fresh source IP/port, so a run cannot recognise
its own device by address.

Because the simulator knows which socket belongs to which run, it can compare
each strategy's verdict against the truth and count false negatives (a healthy
device reported as failing) and false positives (a dead device reported as
passing — the dangerous kind).

    python3 test/simulate_concurrent_runs.py --token "$REST_API_TOKEN"
    python3 test/simulate_concurrent_runs.py --runs 6 --broken 2 --duration 15

Strategies:
  drain       erase-run-read: DELETE, run, drain, count  (what you have now)
  flows       cursor, run, any flow after the cursor with >= min-packets
  first-flow  cursor, run, only the *earliest* new flow counts
"""

import argparse
import os
import socket
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from harness_client import SampleApiClient  # noqa: E402

ZERO_PAYLOAD = b"\x00" * 10
STRATEGIES = ("drain", "flows", "first-flow")


class FakeDut(threading.Thread):
    """One boot: attach delay, then a fixed-rate stream from one socket."""

    def __init__(self, target, packets, interval, attach_delay):
        super().__init__(daemon=True)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        # Read once: the socket is closed when the run finishes.
        self.source_port = self.sock.getsockname()[1]
        self.target = target
        self.packets = packets
        self.interval = interval
        self.attach_delay = attach_delay
        self.sent = 0

    def run(self):
        time.sleep(self.attach_delay)
        for _ in range(self.packets):
            self.sock.sendto(ZERO_PAYLOAD, self.target)
            self.sent += 1
            time.sleep(self.interval)
        self.sock.close()


class TestRun(threading.Thread):
    def __init__(self, index, api, args, packets):
        super().__init__()
        self.index = index
        self.api = api
        self.args = args
        self.packets = packets
        self.healthy = packets >= args.min_packets
        self.verdict = None
        self.detail = ""
        self.dut = None

    def run(self):
        time.sleep(self.index * self.args.stagger)
        args = self.args
        target = (args.host, args.sample_port)
        window = args.duration + args.attach_delay + 2

        if args.strategy == "drain":
            self.api.clear()
        cursor = self.api.cursor()

        self.dut = FakeDut(target, self.packets, args.interval, args.attach_delay)
        self.dut.start()
        # A real harness runs the board for a fixed wall-clock window and then
        # checks, whether or not the board actually sent anything. Waiting on
        # the DUT instead would let a dead board read the store early, before
        # its neighbours had accumulated enough packets to be mistaken for it.
        time.sleep(window)

        if args.strategy == "drain":
            arrived = len(self.api.drain())
            self.verdict = arrived >= args.min_packets
            self.detail = f"{arrived} packet(s) drained"
            return

        flows = self.api.flows_since(cursor)
        if args.strategy == "first-flow":
            flows = flows[:1]
        qualifying = [f for f in flows if f["packets"] >= args.min_packets]
        self.verdict = bool(qualifying)
        self.detail = ", ".join(
            f"{f['port']}={f['packets']}" for f in flows
        ) or "no flows"
        self.claimed = qualifying[0]["port"] if qualifying else None


def run_strategy(args, strategy):
    args.strategy = strategy
    api_args = dict(token=args.token, port=args.rest_port)
    if args.broken_runs:
        broken = {int(i) for i in args.broken_runs.split(",") if i.strip()}
    else:
        broken = set(range(args.broken))
    runs = []
    for i in range(args.runs):
        packets = 1 if i in broken else int(args.duration / args.interval)
        runs.append(TestRun(i, SampleApiClient(args.host, **api_args), args, packets))

    for run in runs:
        run.start()
    for run in runs:
        run.join()

    print(f"\n=== strategy: {strategy}")
    false_neg = false_pos = correct = 0
    for run in runs:
        truth = "healthy" if run.healthy else "BROKEN "
        if run.verdict == run.healthy:
            outcome = "ok"
            correct += 1
        elif run.healthy:
            outcome = "FALSE NEGATIVE"
            false_neg += 1
        else:
            outcome = "FALSE POSITIVE"
            false_pos += 1
        own = run.dut.source_port if run.dut else "?"
        print(
            f"  run {run.index}: {truth} sent={run.dut.sent if run.dut else 0:>2} "
            f"own_port={own} verdict={'pass' if run.verdict else 'fail':<4} "
            f"{outcome:<14} [{run.detail}]"
        )
    print(
        f"  -> {correct}/{len(runs)} correct, "
        f"{false_neg} false negative(s), {false_pos} false positive(s)"
    )
    return correct, false_neg, false_pos


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--host", default="localhost")
    parser.add_argument("--rest-port", type=int, default=8080)
    parser.add_argument("--sample-port", type=int, default=3001)
    parser.add_argument("--token", default=os.environ.get("REST_API_TOKEN", ""))
    parser.add_argument("--runs", type=int, default=4, help="concurrent test runs")
    parser.add_argument("--broken", type=int, default=1, help="first N runs send 1 packet")
    parser.add_argument("--broken-runs", default="",
                        help="explicit run indices to break, e.g. '3' (worst case: a "
                             "broken run starting while healthy devices already stream)")
    parser.add_argument("--duration", type=float, default=6.0, help="seconds of sending")
    parser.add_argument("--interval", type=float, default=1.0, help="packet interval")
    parser.add_argument("--attach-delay", type=float, default=1.5,
                        help="boot-to-first-packet gap (LTE attach)")
    parser.add_argument("--stagger", type=float, default=1.0, help="delay between run starts")
    parser.add_argument("--min-packets", type=int, default=3)
    parser.add_argument("--strategy", choices=STRATEGIES + ("all",), default="all")
    args = parser.parse_args()

    strategies = STRATEGIES if args.strategy == "all" else (args.strategy,)
    results = {}
    for strategy in strategies:
        results[strategy] = run_strategy(args, strategy)
        time.sleep(1)

    print("\n=== summary "
          f"({args.runs} concurrent runs, {args.broken} broken, "
          f"stagger {args.stagger}s, attach {args.attach_delay}s)")
    print(f"{'strategy':<12} {'correct':>8} {'false neg':>10} {'false pos':>10}")
    for strategy, (correct, false_neg, false_pos) in results.items():
        print(f"{strategy:<12} {correct:>8} {false_neg:>10} {false_pos:>10}")
    print(
        "\nFalse negatives are flaky tests; false positives are worse — a dead\n"
        "board reported as working. Exact attribution needs a per-run "
        "destination\nport or an identifier in the payload; see the README."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
