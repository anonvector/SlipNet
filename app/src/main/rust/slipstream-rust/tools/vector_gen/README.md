# Vector generator

`gen_vectors.c` builds DNS queries and responses using the same SPCDNS + base32 + dotify logic as the C implementation.
It reads `vectors.txt` and writes JSON to stdout.

## Prereqs

- The slipstream C repo checked out with submodules:
  https://github.com/EndPositive/slipstream
- A C compiler (`cc`).

The helper script `scripts/gen_vectors.sh` builds the generator against the C
repo (default `../slipstream`, override with `SLIPSTREAM_DIR`) and writes
`fixtures/vectors/dns-vectors.json`.

Format of `vectors.txt`:

```
name,id,domain,payload_hex[,mode,qname_override,error_rcode,raw_query_hex]
```

- `payload_hex` may be `-` for an empty payload (only valid with `mode != normal`).
- `mode` defaults to `normal`.
- `qname_override` is required for `invalid_base32`, `suffix_mismatch`, and `empty_subdomain`, and must include a trailing dot.
- `raw_query_hex` is required for `raw_query_hex` mode and is interpreted as a hex-encoded UDP payload.
- Use `-` as a placeholder to skip optional fields (the CSV parser does not preserve empty fields).
- `error_rcode` is optional; when set, `response_error` is emitted. Defaults are used for `invalid_base32` and `suffix_mismatch`.

Built-in modes:

- `normal`
- `invalid_base32`
- `suffix_mismatch`
- `non_txt`
- `empty_subdomain`
- `qdcount_zero`
- `not_query`
- `raw_query_hex`

Typical use:

```
./scripts/gen_vectors.sh
```

This compiles the generator against the slipstream C repo at `../slipstream`
(override with `SLIPSTREAM_DIR`) and requires the C repo submodules to be
initialized.
