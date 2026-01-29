# Interop and local testing

Interop harnesses live under scripts/interop and produce artifacts under .interop/.
They are intended for development and compatibility validation.

## Prereqs (C interop)

The C harnesses require the original C repo checked out next to this repo:

- Default path: ../slipstream
- Override with: SLIPSTREAM_DIR

You will also need meson, ninja, cmake, pkg-config, libssl-dev, and python3.

## Harnesses

- scripts/interop/run_local.sh
  C client <-> C server baseline, DNS capture in .interop/run-<timestamp>/

- scripts/interop/run_rust_client.sh
  Rust client <-> C server

- scripts/interop/run_rust_server.sh
  C client <-> Rust server

- scripts/interop/run_rust_rust.sh
  Rust client <-> Rust server

Each run captures:

- dns_capture.jsonl
- server.log, client.log
- tcp_echo.jsonl

## Quick run

```
./scripts/interop/run_local.sh
./scripts/interop/run_rust_client.sh
./scripts/interop/run_rust_server.sh
./scripts/interop/run_rust_rust.sh
```

## Log format

dns_capture.jsonl entries are JSON objects with:

- ts: Unix timestamp (float)
- direction: client_to_server or server_to_client
- len: packet length in bytes
- src: source address as host:port
- dst: destination address as host:port (or null when unknown)
- hex: uppercase hex payload of the UDP datagram

## Common configuration

Environment variables (defaults in parentheses):

- SLIPSTREAM_DIR (../slipstream) - C repo path (C harnesses only)
- SLIPSTREAM_BUILD_DIR (.interop/slipstream-build) - C build output (C harnesses only)
- CERT_DIR (fixtures/certs) - test-only TLS certs (use your own for production)
- DNS_LISTEN_PORT (8853)
- PROXY_PORT (5300)
- TCP_TARGET_PORT (5201)
- CLIENT_TCP_PORT (7000)
- DOMAIN (test.com)
- CLIENT_PAYLOAD (slipstream-rust) - payload for echo validation
- SOCKET_TIMEOUT (10) - TCP socket timeout (Rust interop harnesses)

## Manual Rust <-> Rust smoke check

You can run the Rust server and client manually (requires a UDP proxy and TCP echo
as shown in scripts/interop/run_rust_server.sh):

Server:

```
cargo run -p slipstream-server -- \
  --dns-listen-port 8853 \
  --target-address 127.0.0.1:5201 \
  --domain test.com \
  --cert fixtures/certs/cert.pem \
  --key fixtures/certs/key.pem
```

The certs under `fixtures/certs/` are test-only; generate your own for any
real deployment.

Client:

```
cargo run -p slipstream-client -- \
  --tcp-listen-port 7000 \
  --resolver 127.0.0.1:5300 \
  --domain test.com
```

## IPv4 listener validation

For a quick check that the DNS listener behaves correctly when bound to IPv4,
run:

```
./scripts/verify_ipv4_listener.sh
```

Override ports or certificates with `DNS_PORT`, `TCP_PORT`, `CERT`, and `KEY`.

## CI

The GitHub Actions workflow .github/workflows/interop-smoke.yml runs the Rust
client and server interop harnesses against the C implementation.

## Shutdown behavior

The Rust server interop harness sends SIGTERM to the server and expects it to
exit cleanly after closing active QUIC connections. The Rust server uses an
immediate QUIC close on shutdown, so peers should not expect a graceful close
when SIGTERM is received.

## Notes

- The server congestion control algorithm is compiled locally from
  crates/slipstream-ffi/cc/slipstream_server_cc.c, so the C server object is not required.
