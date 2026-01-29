#!/usr/bin/env python3
import argparse
import json
import socket
import sys
import time


def parse_hostport(value: str):
    if value.startswith("["):
        end = value.find("]")
        if end == -1:
            raise ValueError("invalid IPv6 address, missing closing bracket")
        host = value[1:end]
        rest = value[end + 1 :]
        if not rest.startswith(":"):
            raise ValueError("missing port for IPv6 address")
        port = int(rest[1:])
        return host, port
    if ":" not in value:
        raise ValueError("missing port (expected host:port)")
    host, port_str = value.rsplit(":", 1)
    return host, int(port_str)


def open_log(path: str):
    if path == "-":
        return sys.stdout
    return open(path, "w", encoding="utf-8")


def log_event(log_fp, event: dict) -> None:
    log_fp.write(json.dumps(event) + "\n")
    log_fp.flush()


def summarize(label: str, total: int, elapsed: float) -> None:
    mib = total / (1024 * 1024)
    mib_s = mib / elapsed if elapsed > 0 else 0.0
    print(f"{label}: bytes={total} secs={elapsed:.3f} MiB/s={mib_s:.2f}")


def run_server(args: argparse.Namespace) -> int:
    host, port = parse_hostport(args.listen)
    log_fp = open_log(args.log)
    mode = args.mode
    if mode not in ("sink", "source"):
        raise ValueError("mode must be sink or source")

    with socket.create_server((host, port)) as server:
        server.settimeout(args.timeout)
        log_event(log_fp, {"ts": time.time(), "event": "listening", "listen": args.listen, "mode": mode})
        conn, addr = server.accept()
        with conn:
            conn.settimeout(args.timeout)
            peer = f"{addr[0]}:{addr[1]}"
            log_event(log_fp, {"ts": time.time(), "event": "accept", "peer": peer, "mode": mode})
            total = 0
            start = None
            first_payload_ts = None
            last_payload_ts = None
            if mode == "sink":
                while True:
                    data = conn.recv(args.chunk_size)
                    if not data:
                        break
                    if first_payload_ts is None:
                        first_payload_ts = time.time()
                        start = time.perf_counter()
                    total += len(data)
                    last_payload_ts = time.time()
                    if args.bytes and total >= args.bytes:
                        break
            else:
                remaining_preface = args.preface_bytes
                while remaining_preface > 0:
                    data = conn.recv(min(args.chunk_size, remaining_preface))
                    if not data:
                        break
                    remaining_preface -= len(data)
                remaining = args.bytes
                chunk = b"a" * args.chunk_size
                while remaining > 0:
                    send_len = args.chunk_size if remaining > args.chunk_size else remaining
                    if first_payload_ts is None:
                        first_payload_ts = time.time()
                        start = time.perf_counter()
                    conn.sendall(chunk[:send_len])
                    last_payload_ts = time.time()
                    remaining -= send_len
                total = args.bytes
            elapsed = time.perf_counter() - start if start is not None else 0.0
            log_event(
                log_fp,
                {
                    "ts": time.time(),
                    "event": "done",
                    "mode": mode,
                    "bytes": total,
                    "secs": elapsed,
                    "first_payload_ts": first_payload_ts,
                    "last_payload_ts": last_payload_ts,
                },
            )
            summarize(f"server {mode}", total, elapsed)
            if mode == "source" and args.linger_secs > 0:
                time.sleep(args.linger_secs)

    if log_fp is not sys.stdout:
        log_fp.close()

    if args.bytes and total < args.bytes:
        return 1
    return 0


def run_client(args: argparse.Namespace) -> int:
    host, port = parse_hostport(args.connect)
    log_fp = open_log(args.log)
    mode = args.mode
    if mode not in ("send", "recv"):
        raise ValueError("mode must be send or recv")

    with socket.create_connection((host, port), timeout=args.timeout) as sock:
        sock.settimeout(args.timeout)
        log_event(log_fp, {"ts": time.time(), "event": "connect", "peer": args.connect, "mode": mode})
        total = 0
        start = None
        first_payload_ts = None
        last_payload_ts = None
        if mode == "send":
            remaining = args.bytes
            chunk = b"b" * args.chunk_size
            while remaining > 0:
                send_len = args.chunk_size if remaining > args.chunk_size else remaining
                if first_payload_ts is None:
                    first_payload_ts = time.time()
                    start = time.perf_counter()
                sock.sendall(chunk[:send_len])
                last_payload_ts = time.time()
                remaining -= send_len
            total = args.bytes
        else:
            if args.preface_bytes:
                remaining = args.preface_bytes
                chunk = b"p" * args.chunk_size
                while remaining > 0:
                    send_len = args.chunk_size if remaining > args.chunk_size else remaining
                    sock.sendall(chunk[:send_len])
                    remaining -= send_len
            while True:
                data = sock.recv(args.chunk_size)
                if not data:
                    break
                if first_payload_ts is None:
                    first_payload_ts = time.time()
                    start = time.perf_counter()
                total += len(data)
                last_payload_ts = time.time()
                if args.bytes and total >= args.bytes:
                    break
        elapsed = time.perf_counter() - start if start is not None else 0.0
        log_event(
            log_fp,
            {
                "ts": time.time(),
                "event": "done",
                "mode": mode,
                "bytes": total,
                "secs": elapsed,
                "first_payload_ts": first_payload_ts,
                "last_payload_ts": last_payload_ts,
            },
        )
        summarize(f"client {mode}", total, elapsed)
        if mode == "send":
            if args.linger_secs > 0:
                time.sleep(args.linger_secs)
            sock.shutdown(socket.SHUT_WR)

    if log_fp is not sys.stdout:
        log_fp.close()

    if args.bytes and total < args.bytes:
        return 1
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="TCP benchmark helper")
    subparsers = parser.add_subparsers(dest="command", required=True)

    server_parser = subparsers.add_parser("server", help="run sink/source server")
    server_parser.add_argument("--listen", required=True, help="listen address, host:port")
    server_parser.add_argument("--mode", required=True, choices=("sink", "source"))
    server_parser.add_argument("--bytes", type=int, default=0)
    server_parser.add_argument("--chunk-size", type=int, default=16384)
    server_parser.add_argument("--timeout", type=float, default=30)
    server_parser.add_argument("--preface-bytes", type=int, default=0)
    server_parser.add_argument("--linger-secs", type=float, default=0)
    server_parser.add_argument("--log", default="-", help="log file path (default: stdout)")

    client_parser = subparsers.add_parser("client", help="run send/recv client")
    client_parser.add_argument("--connect", required=True, help="connect address, host:port")
    client_parser.add_argument("--mode", required=True, choices=("send", "recv"))
    client_parser.add_argument("--bytes", type=int, default=0)
    client_parser.add_argument("--chunk-size", type=int, default=16384)
    client_parser.add_argument("--timeout", type=float, default=30)
    client_parser.add_argument("--preface-bytes", type=int, default=0)
    client_parser.add_argument("--linger-secs", type=float, default=0)
    client_parser.add_argument("--log", default="-", help="log file path (default: stdout)")

    args = parser.parse_args()
    if args.command == "server":
        return run_server(args)
    return run_client(args)


if __name__ == "__main__":
    raise SystemExit(main())
