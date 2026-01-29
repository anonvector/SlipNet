# Usage

This page documents the CLI surface for the Rust client and server binaries.

## slipstream-client

Required flags:

- --domain <DOMAIN>
- --resolver <IP:PORT> and/or --authoritative <IP:PORT> (repeatable; at least one total, order preserved)

These can also be supplied via SIP003 environment variables; see docs/sip003.md.

Common flags:

- --tcp-listen-host <HOST> (default: ::)
- --tcp-listen-port <PORT> (default: 5201)
- --congestion-control <bbr|dcubic> (optional; overrides congestion control for all resolvers)
- --cert <PATH> (optional; PEM-encoded server certificate for strict leaf pinning)
- --authoritative <IP:PORT> (repeatable; mark a resolver path as authoritative and use pacing-based polling)
- --gso (currently not implemented in the Rust loop; prints a warning)
- --keep-alive-interval <SECONDS> (default: 400)

Example:

```
./target/release/slipstream-client \
  --tcp-listen-port 7000 \
  --authoritative 127.0.0.1:8853 \
  --resolver 1.1.1.1:53 \
  --domain example.com
```

Notes:

- Resolver addresses may be IPv4 or bracketed IPv6; mixed families are supported.
- IPv6 resolvers must be bracketed, for example: [2001:db8::1]:53.
- IPv4 resolvers require an IPv6 dual-stack UDP socket; slipstream attempts to set IPV6_V6ONLY=0, but some OSes may still require sysctl changes.
- Provide --cert to enable strict leaf pinning; omit it for legacy/no-verification behavior.
- The pinned certificate must match the server leaf exactly; CA bundles are not supported.
- Resolver order follows the CLI; the first resolver becomes path 0.
- Resolver addresses must be unique; duplicates are rejected.
- --authoritative keeps the DNS wire format unchanged and remains C interop safe.
- Use --authoritative only when you control the resolver/server path and can absorb high QPS bursts.
- When --congestion-control is omitted, authoritative paths default to bbr and recursive paths default to dcubic.
- Authoritative polling derives its QPS budget from picoquic’s pacing rate (scaled by the DNS payload size and RTT proxy) and falls back to cwnd if pacing is unavailable; `--debug-poll` logs the pacing rate, target QPS, and inflight polls.
- When QUIC has ready stream data queued, authoritative polling yields to data-bearing queries unless flow control blocks progress.
- Expect higher CPU usage and detectability risk; misusing it can overload resolvers/servers.

## slipstream-server

Required flags:

- --domain <DOMAIN> (repeatable)
- --cert <PATH>
- --key <PATH>

These can also be supplied via SIP003 environment variables; see docs/sip003.md.

Common flags:

- --dns-listen-host <HOST> (default: ::)
- --dns-listen-port <PORT> (default: 53)
- --target-address <HOST:PORT> (default: 127.0.0.1:5201)
- --max-connections <COUNT> (default: 256; caps concurrent QUIC connections)
- --fallback <HOST:PORT> (optional; forward non-DNS packets to this UDP endpoint)
- --idle-timeout-seconds <SECONDS> (default: 1200; set to 0 to disable)
- --reset-seed <PATH> (optional; 32 hex chars / 16 bytes; auto-created if missing)
- When binding to ::, slipstream attempts to enable dual-stack (IPV6_V6ONLY=0); if your OS disallows it, IPv4 DNS clients require sysctl changes or binding to an IPv4 address.
- With --fallback enabled, peers that have recently sent DNS stay DNS-only; while active they switch to fallback only after 16 consecutive non-DNS packets to avoid diverting DNS on stray traffic. DNS-only classification expires after an idle timeout without DNS traffic.
- Fallback sessions are created per source address without a hard cap; untrusted or spoofed UDP traffic can consume file descriptors/CPU. Use network filtering or rate limiting when exposing fallback to the public Internet, or disable --fallback if this is a concern.

Example:

```
./target/release/slipstream-server \
  --dns-listen-port 8853 \
  --target-address 127.0.0.1:5201 \
  --domain example.com \
  --domain tunnel.example.com \
  --cert ./cert.pem \
  --key ./key.pem \
  --reset-seed ./reset-seed
```

For quick tests you can use the sample certs in `fixtures/certs/` (test-only).
If the configured cert/key paths are missing, the server auto-generates a
self-signed ECDSA P-256 certificate (1000-year validity). To generate your
own manually:

```
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout key.pem -out cert.pem -days 365 \
  -subj "/CN=slipstream"
```

## Local testing

For a local smoke test, the Rust to Rust interop script spins up a UDP proxy and TCP echo:

```
./scripts/interop/run_rust_rust.sh
```

See docs/interop.md for full details and C interop variants.

When multiple --domain values are provided, the server matches the longest
suffix in incoming QNAMEs.

## SIP003 plugin mode

See docs/sip003.md for SIP003 environment variable support and option syntax.
