#!/usr/bin/env python3
import argparse
import json
import socketserver
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


class EchoHandler(socketserver.StreamRequestHandler):
    def handle(self):
        server = self.server
        log_fp = getattr(server, "log_fp", None)
        peer = f"{self.client_address[0]}:{self.client_address[1]}"
        if log_fp:
            log_fp.write(json.dumps({"ts": time.time(), "event": "connect", "peer": peer}) + "\n")
            log_fp.flush()

        while True:
            data = self.rfile.read(4096)
            if not data:
                break
            self.wfile.write(data)
            self.wfile.flush()
            if log_fp:
                log_fp.write(
                    json.dumps({"ts": time.time(), "event": "echo", "peer": peer, "len": len(data)}) + "\n"
                )
                log_fp.flush()

        if log_fp:
            log_fp.write(json.dumps({"ts": time.time(), "event": "disconnect", "peer": peer}) + "\n")
            log_fp.flush()


class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True


def main() -> int:
    parser = argparse.ArgumentParser(description="Simple TCP echo server")
    parser.add_argument("--listen", required=True, help="listen address, host:port")
    parser.add_argument("--log", default="-", help="log file path (default: stdout)")
    args = parser.parse_args()

    listen = parse_hostport(args.listen)
    log_fp = sys.stdout if args.log == "-" else open(args.log, "w", encoding="utf-8")

    with ThreadedTCPServer(listen, EchoHandler) as server:
        server.log_fp = log_fp
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            if log_fp is not sys.stdout:
                log_fp.close()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
