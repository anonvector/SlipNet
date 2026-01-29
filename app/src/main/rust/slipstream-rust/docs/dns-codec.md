# DNS codec and vectors

This document captures the DNS codec behavior and how it is validated.

## Canonical behavior (summary)

- Base32: RFC4648 alphabet, uppercase, no padding on encode; decode is case-insensitive.
- Inline dots: insert '.' every 57 characters from the right, never add a trailing dot.
- QNAME format: <base32(payload) with inline dots>.<domain>.
- Servers may be configured with multiple domains; the QNAME suffix must match one.
- DNS query: QTYPE=TXT, QCLASS=IN, RD=1, EDNS0 OPT always included.
- Server decode rules:
  - QR=1 or QDCOUNT!=1 -> FORMAT_ERROR.
  - QTYPE!=TXT -> NAME_ERROR.
  - Empty subdomain or suffix mismatch -> NAME_ERROR.
  - If multiple suffixes match, use the longest matching domain.
  - Base32 decode failure -> SERVER_FAILURE.
  - Parse errors -> drop the message (no response).
- Client decode rules: accept only QR=1, RCODE=OK, ANCOUNT=1, TXT answer;
  reassemble multi-part TXT payloads in order.
- QUIC stateless reset packets, when generated, are carried as normal TXT payloads
  with RCODE=OK.

For the full protocol overview, see docs/protocol.md.

## Vectors and fixtures

Golden vectors live in fixtures/vectors/dns-vectors.json (schema v2).
Generator input is tools/vector_gen/vectors.txt.

Regenerate vectors (requires the C repo):

```
./scripts/gen_vectors.sh
```

Set SLIPSTREAM_DIR if the C repo is not at ../slipstream.

## Tests

Run the codec tests:

```
cargo test -p slipstream-dns
```

This validates query/response encoding, error behavior, and raw packet drop cases.

## CLI validation notes

The Rust CLI enforces the following constraints:

- Client requires --domain and at least one --resolver.
- Resolver parsing supports IPv4, bracketed IPv6, and optional :port.
- Resolver lists may mix IPv4 and IPv6 entries.
- Server requires at least one --domain (repeatable); --target-address defaults to 127.0.0.1:5201.
