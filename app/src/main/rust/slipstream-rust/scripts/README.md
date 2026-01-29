# Scripts

This directory contains developer tooling. "Public" scripts are supported for
contributors; "dev-only" scripts are internal or experimental.

## Prereqs

- Bash shell and coreutils.
- Rust toolchain (cargo, rustfmt, clippy).
- C compiler for vector generation (`cc`).
- cmake, pkg-config, and OpenSSL headers for picoquic builds.
- python3 for interop and benchmark harnesses.
- meson + ninja and the C slipstream repo for C interop/bench scripts.
  Set `SLIPSTREAM_DIR` to point to the C repo if it is not at `../slipstream`.

## Expected outputs

- `.interop/` contains capture logs and benchmark artifacts (untracked).
- `fixtures/vectors/dns-vectors.json` is written by `scripts/gen_vectors.sh`.
- `tools/vector_gen/build/` stores the compiled generator.
- `.picoquic-build/` holds picoquic build output.

## Public scripts

- `scripts/build_picoquic.sh`: build picoquic for the Rust FFI layer.
- `scripts/gen_vectors.sh`: regenerate DNS vectors (requires the C repo).
- `scripts/interop/run_rust_rust.sh`: Rust client/server interop harness (set `DOMAINS` and `CLIENT_DOMAIN` to exercise multi-domain).
- `scripts/bench/run_rust_rust_10mb.sh`: Rust<->Rust throughput benchmark (set `RESOLVER_MODE=mixed` for mixed resolver runs).
- `scripts/bench/run_rust_rust_mem.sh`: Rust<->Rust memory benchmark.


## Dev-only or experimental scripts

- `scripts/dev/repro_high_cpu.sh`: profiling helper for post-load CPU behavior.
- `scripts/interop/run_local.sh`: C↔C baseline (requires C repo).
- `scripts/interop/run_rust_client.sh`: Rust client ↔ C server (requires C repo).
- `scripts/interop/run_rust_server.sh`: C client ↔ Rust server (requires C repo).
- `scripts/bench/run_c_c_10mb.sh`: C↔C benchmark (requires C repo).
- `scripts/bench/run_dnstt_10mb.sh`: dnstt comparison benchmark.
- `scripts/interop/*.py`: local harness utilities.

## Certificates

Sample certs live in `fixtures/certs/` for tests only. Use your own cert/key
pairs for real deployments and pass them via `--cert` and `--key`.
