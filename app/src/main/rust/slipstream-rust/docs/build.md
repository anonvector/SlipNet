# Build

## Prereqs

- Rust toolchain (stable)
- C toolchain (cc/clang)
- cmake
- pkg-config
- OpenSSL development headers and libs
- python3 (for interop and benchmark scripts)

## picoquic submodule

This repo uses a picoquic fork as a submodule under vendor/picoquic.
Initialize it before building:

```
git submodule update --init --recursive
```

## Default build (auto-build picoquic)

The build script in crates/slipstream-ffi will auto-build picoquic if the
headers and libs are missing. It uses vendor/picoquic and writes outputs to
.picoquic-build/ (ignored). Set PICOQUIC_FETCH_PTLS=OFF to skip the picotls
fetch.

```
cargo build -p slipstream-client -p slipstream-server
```

You can disable auto-build with:

```
PICOQUIC_AUTO_BUILD=0 cargo build -p slipstream-client -p slipstream-server
```

## Manual picoquic build

If you prefer to build picoquic yourself, run:

```
./scripts/build_picoquic.sh
```

Then point Cargo at the build output if needed:

- PICOQUIC_DIR: picoquic source tree (default: vendor/picoquic)
- PICOQUIC_INCLUDE_DIR: headers (default: vendor/picoquic/picoquic)
- PICOTLS_INCLUDE_DIR: picotls headers (default: .picoquic-build/_deps/picotls-src/include)
- PICOQUIC_BUILD_DIR: build output (default: .picoquic-build)
- PICOQUIC_LIB_DIR: directory containing picoquic and picotls libs

## Tests

Run the DNS vector tests:

```
cargo test -p slipstream-dns
```

Run the full workspace tests:

```
cargo test
```
