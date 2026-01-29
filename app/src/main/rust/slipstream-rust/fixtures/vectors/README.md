# DNS vector schema

`dns-vectors.json` is generated from the C implementation and used as golden test input for the Rust rewrite.

Schema (version 2):

- `schema_version`: integer
- `generated_by`: generator path
- `vectors`: array of vector objects

Vector object fields:

- `name`: short identifier
- `domain`: domain suffix used for QNAME
- `id`: DNS query ID (decimal)
- `payload_len`: payload length in bytes
- `payload_hex`: uppercase hex of payload bytes (raw QUIC packet)
- `mode`: vector mode (`normal`, `invalid_base32`, `suffix_mismatch`, `non_txt`, `empty_subdomain`, `qdcount_zero`, `not_query`, or custom)
- `expected_action`: `reply` or `drop`
- `qname`: full QNAME with trailing dot (empty string for raw packet cases)
- `query`: object with `packet_len`, `packet_hex`
- `response_ok`: object with `rcode`, `packet_len`, `packet_hex` (or `null` if not applicable)
- `response_no_data`: object with `rcode`, `packet_len`, `packet_hex` (or `null` if not applicable)
- `response_error`: object with `rcode`, `packet_len`, `packet_hex` (optional)

Regenerate:

```
./scripts/gen_vectors.sh
```

Set `SLIPSTREAM_DIR` to point at the C repo if it is not at `../slipstream`.
