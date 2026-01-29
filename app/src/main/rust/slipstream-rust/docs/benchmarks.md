# Benchmarks

Benchmark harnesses live under scripts/bench and write artifacts under .interop/.

## Method

- Run the Rust <-> Rust harness:
  TRANSFER_BYTES=10485760 ./scripts/bench/run_rust_rust_10mb.sh
- Run the Rust <-> Rust mixed resolver harness:
  TRANSFER_BYTES=10485760 RESOLVER_MODE=mixed ./scripts/bench/run_rust_rust_10mb.sh
- Run the Rust <-> Rust memory sampler:
  TRANSFER_BYTES=10485760 ./scripts/bench/run_rust_rust_mem.sh
- Run the C <-> C harness:
  TRANSFER_BYTES=10485760 ./scripts/bench/run_c_c_10mb.sh
- Artifacts are written under .interop/bench-*-<timestamp>/.
- Use RUNS=5 to repeat runs; multi-run outputs are stored under run-N/.
- End-to-end timing is measured from the first payload byte sent to the last
  payload byte received.
- Rust <-> Rust runs enforce minimum average MiB/s thresholds:
  MIN_AVG_MIB_S_EXFIL (default 5) and MIN_AVG_MIB_S_DOWNLOAD (default 10).
  Set MIN_AVG_MIB_S to override both with a single value.
- The Rust <-> Rust memory sampler enforces MAX_RSS_MB (default 80). Set MAX_RSS_MB=0
  to disable the threshold.
- The memory sampler defaults MIN_AVG_MIB_S=0 so bandwidth checks are disabled unless overridden.

## Timing and delay injection

- To simulate RTT/jitter on loopback, set NETEM_DELAY_MS (and optional
  NETEM_JITTER_MS, NETEM_DIST, NETEM_IFACE) to apply a temporary tc netem rule.
  The harness will attempt to use sudo -n unless run as root.
- If you cannot use tc, set PROXY_DELAY_MS (and optional PROXY_JITTER_MS,
  PROXY_DIST, PROXY_PORT) to inject delay via the UDP capture proxy without sudo.

## Notes

- The TCP bench drains --preface-bytes before sending to avoid abortive closes
  when the client sends a preface that the source would otherwise ignore.
- The TCP bench records first_payload_ts and last_payload_ts so send/recv timers
  reflect payload delivery only.
- C <-> C runs use scripts/bench/run_c_c_10mb.sh against the slipstream build in
  .interop/slipstream-build. The harness uses TCP_LINGER_SECS (default 5s) to
  keep TCP sockets open long enough for QUIC flushes to complete.
- Set SLIPSTREAM_GSO=1 to pass -g to the C client when testing GSO impact.

## Results

Benchmark results are tracked in docs/benchmarks-results.md.
