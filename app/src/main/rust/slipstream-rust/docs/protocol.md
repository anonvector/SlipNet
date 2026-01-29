# Protocol

Slipstream encapsulates QUIC packets inside DNS TXT queries and responses. The DNS
codec is intentionally minimal and focused on speed and compatibility.

## Domain suffix

- The configured domain is appended to every QNAME as a suffix.
- The domain is expected without a trailing dot; the implementation appends it.
- Servers may be configured with multiple domains and must accept any matching suffix.

## Base32 and inline dots

- Base32 alphabet: RFC4648 (A-Z2-7), uppercase, no padding.
- Encoding: no padding, no hex alphabet.
- Decoding: case-insensitive and removes all '.' characters before decoding.
- Inline dot insertion: insert '.' every 57 characters from the right so labels
  are <= 57 chars.

## DNS query format (client -> server)

- QNAME: <base32(payload) with inline dots>.<domain>.
- QTYPE: TXT (RR_TXT)
- QCLASS: IN (CLASS_IN)
- QDCOUNT: 1
- ARCOUNT: 1 with EDNS0 OPT record:
  - name: "."
  - type: RR_OPT (41)
  - class: 65535
  - ttl: 0
  - udp_payload: 1232
- RD is set. Other flags default.
- ID is a 16-bit value (random in C; any 16-bit value is valid for interop).

## DNS response format (server -> client)

- Mirrors the query ID.
- QR = 1, OPCODE = QUERY
- AA = 1
- RD and CD are copied from the query.
- QDCOUNT = 1 with the same question as the query.
- ARCOUNT = 1 with EDNS0 OPT record (same fields as query).

### Response payload cases

- If payload length > 0:
  - RCODE = OK
  - ANCOUNT = 1
  - Answer is TXT:
    - name = query QNAME
    - type = TXT
    - class = query class
    - ttl = 60
    - text = raw payload bytes (no base32)
- If payload length == 0 and no error:
  - RCODE = NAME_ERROR (NXDOMAIN)
  - ANCOUNT = 0

## Server-side decode rules

- If the DNS message is not a query (QR=1): respond with FORMAT_ERROR.
- If QDCOUNT != 1: respond with FORMAT_ERROR.
- If QTYPE != TXT: respond with NAME_ERROR (ignore query).
- If the QNAME subdomain is empty: respond with NAME_ERROR.
- If base32 decode fails: respond with SERVER_FAILURE.
- If the DNS parser fails (decode error): drop the message (no response).
- The server must verify that QNAME ends with a configured domain suffix; if not, respond with NAME_ERROR.
- If multiple suffixes match, the server selects the longest matching suffix.

## Client-side decode rules

The client treats the response as data only when:

- QR = 1, RCODE = OK, ANCOUNT = 1, and the answer type is TXT.

Otherwise, the response is ignored (including NAME_ERROR, which signals no data).

## Segmentation rules

- The client may split a payload into multiple DNS queries when segmentation is used.
- Each segment is encoded into its own DNS query; segment length is fixed for the batch.
- The caller must ensure payload_len is a multiple of segment_len if segmentation is used.
- The server responds with exactly one DNS message per query (no segmentation on server).

## QUIC-specific behavior

- Poll frames are used to request data when the client has no payload to send.
- Poll frame type is 0x20 (single-byte frame with no payload).
- Poll frames are only emitted when there is no other frame to send.
- Poll frames are treated as non-ACK-eliciting but still influence congestion tracking.
- If the server receives a 1-RTT packet for an unknown connection ID and picoquic has
  queued a stateless reset for that ID, it returns that QUIC stateless reset payload
  in the DNS response; otherwise it responds DNS-only.

## Backpressure and buffering

- Connection-level max_data is set to stream_write_buffer_bytes (default 8 MiB).
- When only one stream is active, stream data consumption tracks TCP write
  drain and a small reserve window (SLIPSTREAM_CONN_RESERVE_BYTES) is kept
  open to allow new streams to send their first bytes.
- When multiple streams are active, each stream enforces a per-stream receive
  cap (SLIPSTREAM_STREAM_QUEUE_MAX_BYTES). On overflow, the receiver sends
  STOP_SENDING, discards data for that stream, and continues consuming to
  avoid connection-level stalls.
- Once a connection enters multi-stream mode it stays there for the remainder
  of the connection.

## Path handling

- The server overwrites the source address with a dummy address before passing to QUIC.
- Real peer/local addresses are stored per packet and used only for replying.
- QUIC path validation and migration semantics are effectively disabled at the server.

## Limits and constraints

- MAX_DNS_QUERY_SIZE is 512 bytes (traditional DNS UDP limit).
- Inline dots ensure label length <= 57 chars.
- EDNS0 is always included on outbound messages and advertises udp_payload=1232;
  incoming messages are accepted regardless of OPT presence.
- Client MTU is derived from the domain length: floor((240 - domain_len) / 1.6).
- Server MTU is fixed at 900.

## References

- DNS codec: crates/slipstream-dns/src/dns.rs
- Vectors: fixtures/vectors/dns-vectors.json
- Vector tests: crates/slipstream-dns/tests/vectors.rs
