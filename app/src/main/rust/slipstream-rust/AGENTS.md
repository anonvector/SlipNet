# Repository Guidelines

## Project Structure & Module Organization
- `crates/` hosts the Cargo workspace (shared core utilities, DNS codec, and client/server CLIs). Tests live in `crates/*/tests/`.
- `docs/` contains design notes and protocol docs (for example, `docs/protocol.md`, `docs/dns-codec.md`).
- `fixtures/vectors/` stores golden DNS vectors used by Rust tests.
- `fixtures/certs/` holds test-only TLS certs/keys for interop and benchmarks.
- `tools/vector_gen/` contains the C vector generator and its CSV input.
- `scripts/` holds automation utilities, including `scripts/interop/` and `scripts/bench/`.
- `.interop/` is runtime output for captures/builds; keep it untracked.

## Build, Test, and Development Commands
- `cargo test` runs all Rust tests in the workspace.
- `cargo test -p slipstream-dns` runs the vector-based DNS codec suite.
- `cargo fmt` formats Rust code and `cargo clippy --workspace --all-targets -- -D warnings` runs the CI lint suite. Run both whenever there are code changes.
- `cargo run -p slipstream-client -- --resolver=IP:PORT --domain=example.com` runs the client CLI.
- `cargo run -p slipstream-server -- --target-address=IP:PORT --domain=example.com` runs the server CLI.
- `./scripts/gen_vectors.sh` regenerates `fixtures/vectors/dns-vectors.json` from the C implementation.
- `cargo build -p slipstream-dns --bin bench_dns --release` builds the DNS microbench; run `/usr/bin/time -v ./target/release/bench_dns --iterations=20000 --payload-len=256` for timing + RSS stats.
- `TRANSFER_BYTES=10485760 ./scripts/bench/run_rust_rust_10mb.sh` runs the Rust↔Rust 10MB benchmark.

## Coding Style & Naming Conventions
- Rust follows `cargo fmt`; prefer explicit error handling over panics.
- Indentation: 4 spaces in C/Python, 2 spaces in shell scripts.
- Keep bash scripts in strict mode (`set -euo pipefail`) and use descriptive variable names.
- Use ASCII by default; keep filenames and Rust modules in `snake_case`.

## Testing Guidelines
- `fixtures/vectors/dns-vectors.json` is the source of truth for DNS behavior.
- `crates/slipstream-dns/tests/vectors.rs` must pass for DNS changes.
- Interop harness captures live in `.interop/` for manual verification.
- When protocol behavior changes, update vectors and `docs/protocol.md` plus `docs/dns-codec.md`.
- Interop suites: `./scripts/interop/run_local.sh`, `./scripts/interop/run_rust_client.sh`, `./scripts/interop/run_rust_server.sh`, `./scripts/interop/run_rust_rust.sh` (some require `SLIPSTREAM_DIR`).

## Commit & Pull Request Guidelines
- Keep commit messages short and imperative (for example, "Add DNS label parser").
- PRs should include a brief summary, rationale, and commands run.
- Regenerate vectors and update docs when DNS behavior or CLI defaults change.

## Configuration & Dependencies
- The Rust client/server link to picoquic via `slipstream-ffi`; default builds use the `vendor/picoquic` submodule and `./scripts/build_picoquic.sh` (outputs to `.picoquic-build/`).
- Control builds with `PICOQUIC_AUTO_BUILD=0` or `PICOQUIC_FETCH_PTLS=OFF`; override paths with `PICOQUIC_DIR`, `PICOQUIC_BUILD_DIR`, or `PICOQUIC_LIB_DIR`.
