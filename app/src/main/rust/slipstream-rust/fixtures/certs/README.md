# Test TLS certificates

The certificates in this directory are **test-only** and are checked into the
repository solely to support local interop and benchmark scripts. Do not use
these keys in production or anywhere you require real security guarantees.

Files:
- `cert.pem`
- `key.pem`
- `alt_cert.pem` (mismatched cert for pinning tests)
- `alt_key.pem`

To generate your own cert/key pair:

```
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout key.pem -out cert.pem -days 365 \
  -subj "/CN=slipstream"
```

Pass custom paths with `--cert` and `--key` when running `slipstream-server`.
For client verification, pass the pinned server certificate via `--cert`.
