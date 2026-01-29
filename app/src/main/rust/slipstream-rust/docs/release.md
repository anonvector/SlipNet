# Release Checklist

## Prep
- Update `CHANGELOG.md` with release notes and date.
- Bump versions in `Cargo.toml` (workspace and crates) as needed.
- Ensure `Cargo.lock` is updated and committed.
- Confirm vendor/picoquic is at the intended commit and submodules are initialized.

## Validation
- `cargo fmt`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test -p slipstream-dns`
- `cargo test`

## Hygiene
- Verify build outputs stay untracked: `.interop/`, `.picoquic-build/`, `target/`.
- Regenerate vectors and docs if DNS behavior changed:
  `./scripts/gen_vectors.sh`, `docs/protocol.md`, `docs/dns-codec.md`.

## Release
- Tag the release and push tags.
- Publish artifacts if applicable.
