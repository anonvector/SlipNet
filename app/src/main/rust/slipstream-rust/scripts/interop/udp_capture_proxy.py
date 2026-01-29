#!/usr/bin/env python3
"""
UDP proxy with sorted delay assignment and controlled low reordering.

Features:
- Delay distribution comes from a sorted pool of samples (preserves mean/stddev while
  preventing natural reordering even with large jitter).
- Reordering is injected explicitly via periodic adjacent swaps driven by reorder-rate.
- Compatible with the existing CLI flags used by the bench/test harnesses.
"""

import argparse
import heapq
import json
import random
import socket
import sys
import time
from select import select
from typing import Dict, List, Optional, Tuple


def parse_hostport(value: str) -> Tuple[str, int]:
    if value.startswith("["):
        end = value.find("]")
        if end == -1:
            raise ValueError("invalid IPv6 address")
        host = value[1:end]
        rest = value[end + 1 :]
        if not rest.startswith(":"):
            raise ValueError("missing port")
        return host, int(rest[1:])
    if ":" not in value:
        raise ValueError("missing port")
    host, port_str = value.rsplit(":", 1)
    return host, int(port_str)


def addr_to_string(addr: Tuple[str, int]) -> str:
    host, port = addr
    return f"[{host}]:{port}" if ":" in host else f"{host}:{port}"


class SortedDelayModel:
    """
    Samples delays from a sorted pool to avoid natural reordering while matching jitter.
    """

    def __init__(
        self,
        base_ms: float,
        jitter_ms: float,
        pool_size: int = 20000,
        expected_packets: int = 20000,
        dist: str = "normal",
        seed: Optional[int] = None,
    ):
        self.base_ms = base_ms
        self.jitter_ms = jitter_ms
        self.pool_size = max(1, pool_size)
        self.expected_packets = max(1, expected_packets)
        self.dist = dist
        self.rng = random.Random(seed)
        self.stride = self.pool_size / float(self.expected_packets)
        self._generate_pool()
        self.state: Dict[str, Dict[str, float]] = {}

    def _generate_pool(self) -> None:
        """Generate a sorted delay pool from the configured distribution."""
        delays = []
        for _ in range(self.pool_size):
            if self.jitter_ms <= 0:
                jitter = 0.0
            elif self.dist == "uniform":
                jitter = self.rng.uniform(-self.jitter_ms, self.jitter_ms)
            else:
                jitter = self.rng.gauss(0.0, self.jitter_ms)
            delays.append(max(0.0, self.base_ms + jitter))
        delays.sort()
        self.sorted_pool = delays

    def _get_state(self, direction: str) -> Dict[str, float]:
        if direction not in self.state:
            # Start from a random offset so both directions draw the full distribution.
            self.state[direction] = {"float_index": self.rng.random() * self.pool_size}
        return self.state[direction]

    def sample(self, direction: str) -> float:
        """Sample a delay for the given direction."""
        state = self._get_state(direction)
        idx = int(state["float_index"]) % self.pool_size
        if idx == 0 and state["float_index"] >= self.pool_size:
            self._generate_pool()
            state["float_index"] = 0.0
            idx = 0

        delay_ms = self.sorted_pool[idx]
        state["float_index"] += self.stride
        return delay_ms


class ReorderController:
    """
    Injects controlled reordering by swapping adjacent packets at a fixed cadence.
    """

    def __init__(
        self,
        reorder_rate: float,
        min_gap_ms: float = 0.1,
        idle_timeout_ms: float = 50.0,
    ):
        self.reorder_rate = max(0.0, reorder_rate)
        self.min_gap_s = max(0.0, min_gap_ms) / 1000.0
        self.idle_timeout_s = max(0.0, idle_timeout_ms) / 1000.0
        self.interval = (
            int(round(1.0 / self.reorder_rate)) if self.reorder_rate > 0 else 0
        )
        self.state: Dict[str, Dict[str, object]] = {}
        self.stats = {
            "client_to_server": {"total": 0, "reordered": 0},
            "server_to_client": {"total": 0, "reordered": 0},
        }

    def _get_state(self, direction: str) -> Dict[str, object]:
        if direction not in self.state:
            self.state[direction] = {
                "floor": 0.0,
                "prev": None,
                "count": 0,
                "last_recv": 0.0,
            }
        return self.state[direction]

    def process(
        self,
        direction: str,
        recv_time: float,
        natural_delay_ms: float,
        data: bytes,
        src: Tuple[str, int],
        dst: Tuple[str, int],
    ) -> List[Tuple[float, float, bytes, Tuple[str, int], Tuple[str, int]]]:
        """
        Process a packet and return scheduled send entries as
        (send_at, natural_delay_ms, data, src, dst).
        """
        state = self._get_state(direction)
        state["count"] += 1
        self.stats[direction]["total"] += 1

        floor = state["floor"]  # type: float
        prev = state["prev"]
        state["last_recv"] = recv_time

        natural_send_at = recv_time + (natural_delay_ms / 1000.0)
        send_at = natural_send_at if natural_send_at >= floor else floor + self.min_gap_s

        if self.interval == 0:
            state["prev"] = None
            state["floor"] = send_at
            return [(send_at, natural_delay_ms, data, src, dst)]

        # First packet: just stash and wait for the next one.
        if prev is None:
            state["prev"] = (send_at, natural_delay_ms, data, src, dst)
            return []

        prev_send_at, prev_delay_ms, prev_data, prev_src, prev_dst = prev
        should_reorder = self.interval > 0 and state["count"] % self.interval == 0

        if should_reorder:
            first_entry = (send_at, natural_delay_ms, data, src, dst)
            second_send_at = max(send_at + self.min_gap_s, prev_send_at)
            second_entry = (second_send_at, prev_delay_ms, prev_data, prev_src, prev_dst)
            state["prev"] = None
            state["floor"] = second_send_at
            self.stats[direction]["reordered"] += 1
            return [first_entry, second_entry]

        # Normal case: send the previous packet now and keep the current one queued.
        scheduled_prev = max(prev_send_at, floor)
        state["floor"] = scheduled_prev
        state["prev"] = (send_at, natural_delay_ms, data, src, dst)
        return [(scheduled_prev, prev_delay_ms, prev_data, prev_src, prev_dst)]

    def flush(
        self, direction: str
    ) -> List[Tuple[float, float, bytes, Tuple[str, int], Tuple[str, int]]]:
        """Flush any held packet at shutdown."""
        state = self._get_state(direction)
        prev = state["prev"]
        if prev is None:
            return []
        state["prev"] = None
        send_at, delay_ms, data, src, dst = prev
        send_at = max(send_at, state["floor"])
        state["floor"] = send_at
        return [(send_at, delay_ms, data, src, dst)]

    def release_idle(
        self, now: float
    ) -> List[Tuple[str, Tuple[float, float, bytes, Tuple[str, int], Tuple[str, int]]]]:
        """
        Release any pending previous packet if we've been idle for too long.
        Returns a list of (direction, entry) where entry matches the process() return tuple.
        """
        entries: List[
            Tuple[str, Tuple[float, float, bytes, Tuple[str, int], Tuple[str, int]]]
        ] = []
        for direction, state in self.state.items():
            prev = state.get("prev")
            last_recv = state.get("last_recv", 0.0)
            if prev is None:
                continue
            if now - last_recv < self.idle_timeout_s:
                continue
            send_at, delay_ms, data, src, dst = prev
            send_at = max(send_at, state["floor"])
            state["floor"] = send_at
            state["prev"] = None
            entries.append((direction, (send_at, delay_ms, data, src, dst)))
        return entries

    def next_idle_deadline(self) -> Optional[float]:
        """Return the earliest time at which we should flush an idle packet."""
        deadline: Optional[float] = None
        for state in self.state.values():
            prev = state.get("prev")
            last_recv = state.get("last_recv", 0.0)
            if prev is None:
                continue
            candidate = last_recv + self.idle_timeout_s
            if deadline is None or candidate < deadline:
                deadline = candidate
        return deadline

    def get_stats(self) -> Dict[str, Dict[str, float]]:
        result = {}
        for direction, s in self.stats.items():
            total = s["total"]
            reordered = s["reordered"]
            result[direction] = {
                "total": total,
                "reordered": reordered,
                "reorder_pct": (reordered / total * 100.0) if total else 0.0,
            }
        return result


def main() -> int:
    parser = argparse.ArgumentParser(
        description="UDP proxy with sorted delay assignment and controlled reordering",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--listen", required=True, help="Listen address (host:port)")
    parser.add_argument("--upstream", required=True, help="Upstream address (host:port)")
    parser.add_argument("--log", default="-", help="Log file path (default: stdout)")
    parser.add_argument("--max-packets", type=int, default=0, help="Stop after N packets")
    parser.add_argument("--seed", type=int, default=None, help="Random seed")

    parser.add_argument("--delay-ms", type=float, default=0.0, help="Base delay (ms)")
    parser.add_argument("--jitter-ms", type=float, default=0.0, help="Jitter std dev (ms)")
    parser.add_argument("--dist", choices=("normal", "uniform"), default="normal")
    parser.add_argument(
        "--reorder-rate",
        type=float,
        default=0.0,
        help="Target reorder rate 0.0-1.0 (0 disables reordering)",
    )
    parser.add_argument(
        "--reorder-prob",
        type=float,
        default=None,
        help="Alias for --reorder-rate (deprecated)",
    )
    parser.add_argument(
        "--expected-packets",
        type=int,
        default=20000,
        help="Expected packets per transfer (controls delay sampling stride)",
    )

    # Compatibility flags retained for callers; currently ignored.
    parser.add_argument("--min-gap-ms", type=float, default=0.1)
    parser.add_argument("--burst-correlation", type=float, default=0.0)
    parser.add_argument("--burst-window-ms", type=float, default=10.0)
    parser.add_argument("--jitter-slice-ms", type=float, default=100.0)

    args = parser.parse_args()
    reorder_rate = args.reorder_prob if args.reorder_prob is not None else args.reorder_rate

    listen = parse_hostport(args.listen)
    upstream = parse_hostport(args.upstream)

    family = socket.AF_INET6 if ":" in listen[0] else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_DGRAM)
    sock.bind(listen)

    log_fp = sys.stdout if args.log == "-" else open(args.log, "w", encoding="utf-8")

    delay_model = SortedDelayModel(
        base_ms=args.delay_ms,
        jitter_ms=args.jitter_ms,
        pool_size=max(1, args.expected_packets),
        expected_packets=max(1, args.expected_packets),
        dist=args.dist,
        seed=args.seed,
    )
    reorder_ctrl = ReorderController(reorder_rate=reorder_rate, min_gap_ms=args.min_gap_ms)

    last_client: Optional[Tuple[str, int]] = None
    packet_count = 0
    pending: List[Tuple[float, int, bytes, Tuple[str, int]]] = []
    push_seq = 0

    def log_and_enqueue(
        direction: str,
        entry: Tuple[float, float, bytes, Tuple[str, int], Tuple[str, int]],
    ) -> None:
        nonlocal push_seq
        send_at, natural_delay_ms, pkt_data, pkt_src, pkt_dst = entry
        log_fp.write(
            json.dumps(
                {
                    "ts": time.time(),
                    "direction": direction,
                    "len": len(pkt_data),
                    "src": addr_to_string(pkt_src),
                    "dst": addr_to_string(pkt_dst),
                    "hex": pkt_data.hex().upper(),
                    "delay_ms": natural_delay_ms,
                }
            )
            + "\n"
        )
        log_fp.flush()
        push_seq += 1
        heapq.heappush(pending, (send_at, push_seq, pkt_data, pkt_dst))

    print(f"UDP proxy listening on {addr_to_string(listen)}", file=sys.stderr)
    print(f"  Upstream: {addr_to_string(upstream)}", file=sys.stderr)
    print(
        f"  Delay: {args.delay_ms}ms ± {args.jitter_ms}ms (sorted assignment)",
        file=sys.stderr,
    )
    print(f"  Target reorder rate: {reorder_rate * 100:.4f}%", file=sys.stderr)

    try:
        while True:
            now = time.monotonic()
            # Release any pending packets that have been waiting without traffic.
            for direction, entry in reorder_ctrl.release_idle(now):
                log_and_enqueue(direction, entry)

            while pending and pending[0][0] <= now:
                _, _, data, dst = heapq.heappop(pending)
                sock.sendto(data, dst)

            timeout = max(0.0, pending[0][0] - now) if pending else None
            idle_deadline = reorder_ctrl.next_idle_deadline()
            if idle_deadline is not None:
                idle_timeout = max(0.0, idle_deadline - now)
                timeout = idle_timeout if timeout is None else min(timeout, idle_timeout)
            ready, _, _ = select([sock], [], [], timeout)
            if not ready:
                continue

            data, addr = sock.recvfrom(65535)
            recv_time = time.monotonic()

            if addr == upstream:
                direction = "server_to_client"
                dst = last_client
            else:
                direction = "client_to_server"
                dst = upstream
                last_client = addr

            if dst is None:
                continue

            natural_delay_ms = delay_model.sample(direction)
            scheduled = reorder_ctrl.process(
                direction, recv_time, natural_delay_ms, data, addr, dst
            )

            for entry in scheduled:
                log_and_enqueue(direction, entry)

            packet_count += 1
            if args.max_packets and packet_count >= args.max_packets:
                break

    except KeyboardInterrupt:
        pass
    finally:
        # Flush any held packet.
        for d in ("client_to_server", "server_to_client"):
            for entry in reorder_ctrl.flush(d):
                log_and_enqueue(d, entry)

        # Drain pending queue.
        while pending:
            send_at, _, data, dst = heapq.heappop(pending)
            wait = send_at - time.monotonic()
            if wait > 0:
                time.sleep(wait)
            sock.sendto(data, dst)

        stats = reorder_ctrl.get_stats()
        print(f"\n=== Reorder Statistics ===", file=sys.stderr)
        for direction, s in stats.items():
            print(
                f"  {direction}: {s['reordered']}/{s['total']} ({s['reorder_pct']:.4f}%)",
                file=sys.stderr,
            )

        if log_fp is not sys.stdout:
            log_fp.close()
        sock.close()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
