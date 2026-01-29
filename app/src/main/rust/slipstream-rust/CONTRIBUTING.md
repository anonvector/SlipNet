# Contributing

Thanks for your interest in Slipstream Rust.

## Before you start

- Please read AGENTS.md for repo-specific guidelines and commands.
- Keep changes focused and easy to review.
- Use ASCII unless a file already uses Unicode.

## Development workflow

Format:

```
cargo fmt
```

Tests:

```
cargo test -p slipstream-dns
cargo test
```

DNS behavior changes:

- Update fixtures/vectors/dns-vectors.json via:

```
./scripts/gen_vectors.sh
```

- Update the protocol docs (docs/protocol.md and docs/dns-codec.md).

Interop:

- See docs/interop.md for local harnesses.

## Style notes

- Rust formatting is enforced by cargo fmt.
- Shell scripts use 2-space indentation and strict mode.
- C/Python use 4-space indentation.

## Pull requests

- Provide a short summary and rationale.
- Include commands run (tests, benchmarks, interop, etc.).
- Cargo.lock is committed for reproducible releases (this repo ships binaries).
  Include it when dependency versions change.
