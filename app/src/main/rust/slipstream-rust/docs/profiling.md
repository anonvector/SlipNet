# Profiling

## Method

- Build the benchmark binary:
  cargo build -p slipstream-dns --bin bench_dns --release
- Capture runtime stats with time:
  /usr/bin/time -v ./target/release/bench_dns --iterations=20000 --payload-len=256
- Capture software perf counters:
  perf stat -e task-clock,context-switches,cpu-migrations,page-faults -- ./target/release/bench_dns --iterations=20000 --payload-len=256

Hardware counters (cycles/instructions) are not supported on this host, so use
software counters for now.

## Results (2026-01-03)

- Payload clamped to 150 for test.com (base32 + dots + suffix).
- build_qname: 0.723us/iter, 198 MiB/s
- encode_query: 0.093us/iter, 2888 MiB/s
- decode_query: 0.862us/iter, 312 MiB/s
- encode_response: 0.110us/iter, 3856 MiB/s
- decode_response: 0.482us/iter, 881 MiB/s
- /usr/bin/time -v: user 0.04s, wall 0.04s, max RSS 2048 KB
- perf stat (software counters): task-clock 45.75 ms, context-switches 0,
  cpu-migrations 0, page-faults 79, elapsed 0.046 s

## Notes

- No targeted optimizations applied yet; this is the baseline for future comparisons.
- Re-run with a longer domain or different payload sizes to compare clamping behavior.
- If perf access is enabled, prefer:
  perf stat -- ./target/release/bench_dns --iterations=20000 --payload-len=256
  for CPU counters.
