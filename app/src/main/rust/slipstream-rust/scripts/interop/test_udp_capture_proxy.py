#!/usr/bin/env python3
"""
Lightweight functional check for udp_capture_proxy ordering when jitter/reorder is disabled.

Usage:
    python3 scripts/interop/test_udp_capture_proxy.py

The test sends a burst of numbered UDP datagrams through the proxy with zero delay/jitter
and asserts in-order delivery. It requires permission to bind local UDP sockets.

There is also a reorder-rate + delay-distribution smoke test that can be enabled via the env
flags below to exercise jitter + reorder probability and sanity-check delay mean/stddev.
"""

import json
import os
import socket
import statistics
import subprocess
import sys
import tempfile
import threading
import time


def pick_free_udp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def run_order_test(total_packets: int) -> int:
    listen_port = pick_free_udp_port()
    upstream_port = pick_free_udp_port()
    listen_host = upstream_host = "127.0.0.1"

    err_fd, err_path = tempfile.mkstemp(prefix="udp_proxy_err_", suffix=".log")
    os.close(err_fd)

    with open(err_path, "w") as err_handle:
        proxy = subprocess.Popen(
            [
                sys.executable,
                os.path.join(os.path.dirname(__file__), "udp_capture_proxy.py"),
                "--listen",
                f"{listen_host}:{listen_port}",
                "--upstream",
                f"{upstream_host}:{upstream_port}",
                "--delay-ms",
                "0",
                "--jitter-ms",
                "0",
                "--max-packets",
                str(total_packets),
                "--expected-packets",
                str(total_packets),
                "--log",
                os.devnull,
            ],
            stdout=subprocess.DEVNULL,
            stderr=err_handle,
        )

    sink_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sink_sock.bind((upstream_host, upstream_port))
    sink_sock.settimeout(5)
    received = []

    def sink():
        try:
            while len(received) < total_packets:
                data, _ = sink_sock.recvfrom(65535)
                received.append(int.from_bytes(data, "big"))
        except socket.timeout:
            # Expected: stop once packets stop arriving.
            pass

    sink_thread = threading.Thread(target=sink)
    sink_thread.start()

    client_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client_sock.settimeout(1)
    # Give proxy a moment to bind before sending.
    time.sleep(0.1)
    for i in range(total_packets):
        client_sock.sendto(i.to_bytes(4, "big"), (listen_host, listen_port))

    sink_thread.join(timeout=5)
    client_sock.close()
    sink_sock.close()
    try:
        proxy.wait(timeout=2)
    except subprocess.TimeoutExpired:
        proxy.terminate()
        proxy.wait()

    proxy_err = ""
    try:
        with open(err_path, "r") as err_handle:
            proxy_err = err_handle.read().strip()
    finally:
        try:
            os.remove(err_path)
        except OSError:
            # Best-effort cleanup of the temporary error log.
            pass

    if received != list(range(total_packets)):
        missing = set(range(total_packets)) - set(received)
        print(
            f"FAIL: out of order or missing; "
            f"first few received={received[:10]}, missing={sorted(list(missing))[:10]} "
            f"proxy_ret={proxy.returncode} proxy_err={proxy_err!r}"
        )
        return 1

    print("proxy order test (no jitter, no reorder) passed")
    return 0


def run_reorder_smoke(
    total_packets: int,
    delay_ms: float,
    jitter_ms: float,
    burst_correlation: float,
    reorder_prob: float,
) -> int:
    listen_port = pick_free_udp_port()
    upstream_port = pick_free_udp_port()
    listen_host = upstream_host = "127.0.0.1"

    log_fd, log_path = tempfile.mkstemp(prefix="udp_proxy_log_", suffix=".jsonl")
    os.close(log_fd)

    err_fd, err_path = tempfile.mkstemp(prefix="udp_proxy_err_", suffix=".log")
    os.close(err_fd)

    with open(err_path, "w") as err_handle:
        proxy = subprocess.Popen(
            [
                sys.executable,
                os.path.join(os.path.dirname(__file__), "udp_capture_proxy.py"),
                "--listen",
                f"{listen_host}:{listen_port}",
                "--upstream",
                f"{upstream_host}:{upstream_port}",
                "--delay-ms",
                str(delay_ms),
                "--jitter-ms",
                str(jitter_ms),
                "--reorder-rate",
                str(reorder_prob),
                "--burst-correlation",
                str(burst_correlation),
                "--expected-packets",
                str(total_packets),
                "--log",
                log_path,
            ],
            stdout=subprocess.DEVNULL,
            stderr=err_handle,
        )

    sink_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sink_sock.bind((upstream_host, upstream_port))
    sink_sock.settimeout(1)
    # Allow bursts without losing packets locally.
    sink_sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
    received = []

    client_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client_sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4 * 1024 * 1024)
    client_sock.settimeout(1)
    time.sleep(0.1)
    for i in range(total_packets):
        client_sock.sendto(i.to_bytes(4, "big"), (listen_host, listen_port))
        # Light pacing to avoid overrunning local buffers while still stressing ordering.
        time.sleep(0.0005)
        if i and i % 500 == 0:
            time.sleep(0.002)

    deadline = time.time() + max(30.0, total_packets / 200.0)
    while len(received) < total_packets and time.time() < deadline:
        try:
            data, _ = sink_sock.recvfrom(65535)
            received.append(int.from_bytes(data, "big"))
        except socket.timeout:
            continue

    client_sock.close()
    sink_sock.close()
    try:
        proxy.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proxy.terminate()
        try:
            proxy.wait(timeout=2)
        except subprocess.TimeoutExpired:
            proxy.kill()
            proxy.wait()

    proxy_err = ""
    try:
        with open(err_path, "r") as err_handle:
            proxy_err = err_handle.read().strip()
    finally:
        try:
            os.remove(err_path)
        except OSError:
            # Best-effort cleanup of the temporary error log.
            pass

    missing = total_packets - len(received)
    highest = -1
    reorders = 0
    for seq in received:
        if seq < highest:
            reorders += 1
        else:
            highest = seq

    # Parse delays from proxy log for basic distribution sanity.
    delays = []
    try:
        with open(log_path, "r", encoding="utf-8") as handle:
            for line in handle:
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if "delay_ms" in obj:
                    delays.append(float(obj["delay_ms"]))
    finally:
        try:
            os.remove(log_path)
        except OSError:
            # Best-effort cleanup of the temporary delay log.
            pass

    reorder_rate = (reorders / max(1, len(received))) * 100
    if missing:
        print(f"FAIL: missing {missing} packets proxy_ret={proxy.returncode} proxy_err={proxy_err!r}")
        return 1

    delay_mean = statistics.mean(delays) if delays else 0.0
    delay_std = statistics.pstdev(delays) if len(delays) > 1 else 0.0
    delay_min = min(delays) if delays else 0.0
    delay_max = max(delays) if delays else 0.0

    # Wide bounds keep this smoke test stable for very low reorder probabilities.
    reorder_expected_low = reorder_prob * 0.5 * 100
    reorder_expected_high = reorder_prob * 2 * 100

    ok = True
    # Delay stats are reported for visibility but not enforced here.
    if reorder_rate < reorder_expected_low or reorder_rate > reorder_expected_high:
        print(
            f"FAIL: reorder rate {reorder_rate:.3f}% outside expected range "
            f"[{reorder_expected_low:.3f}%, {reorder_expected_high:.3f}%]"
        )
        ok = False

    print(
        f"proxy reorder smoke: delay_ms={delay_ms} jitter_ms={jitter_ms} "
        f"reorder_prob={reorder_prob} => reorder_rate={reorder_rate:.3f}% "
        f"(count={reorders} of {len(received)}), "
        f"delay_mean={delay_mean:.2f}ms delay_std={delay_std:.2f}ms "
        f"delay_min={delay_min:.2f}ms delay_max={delay_max:.2f}ms"
    )
    return 0 if ok else 1


def main() -> int:
    # Always run the ordering test with jitter/reorder disabled.
    if run_order_test(total_packets=200):
        return 1

    # Optional smoke test for jitter + reorder, controlled via env for CI friendliness.
    if os.getenv("UDP_PROXY_REORDER_SMOKE") == "1":
        smoke_count = int(os.getenv("UDP_PROXY_REORDER_COUNT", "2000"))
        return run_reorder_smoke(
            total_packets=smoke_count,
            delay_ms=400,
            jitter_ms=100,
            burst_correlation=0.9,
            reorder_prob=0.0006,
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
