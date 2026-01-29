# Benchmark results

See docs/benchmarks.md for method and harness details.

## Results (2026-01-05, 10MB end-to-end, n=5)

C <-> C (TCP_LINGER_SECS=5):

- Exfil MiB/s: 1.57, 1.55, 1.95, 1.63, 2.02 (avg 1.75, sigma 0.20).
- Exfil secs: 6.364, 6.468, 5.116, 6.126, 4.947 (avg 5.80, sigma 0.64).
- Download MiB/s: 10.55, 10.23, 7.91, 10.25, 10.17 (avg 9.82, sigma 0.96).
- Download secs: 0.948, 0.978, 1.264, 0.975, 0.983 (avg 1.03, sigma 0.12).

## Results (2026-01-05, 10MB end-to-end, n=5, Rust <-> Rust, UDP proxy delay 11.3ms / jitter 2.7ms)

Rust <-> Rust:

- Exfil MiB/s: 2.25, 0.70, 1.71, 2.33, 0.89 (avg 1.58, sigma 0.67).
- Exfil secs: 4.435, 14.185, 5.862, 4.297, 11.196 (avg 8.00, sigma 3.99).
- Download MiB/s: 2.59, 6.28, 4.94, 4.89, 6.11 (avg 4.96, sigma 1.32).
- Download secs: 3.858, 1.592, 2.025, 2.045, 1.637 (avg 2.23, sigma 0.84).

## Results (2026-01-06, 10MB end-to-end, n=5, Rust <-> Rust)

Rust <-> Rust:

- Exfil MiB/s: 10.06, 10.37, 10.29, 10.79, 10.61 (avg 10.42, sigma 0.25).
- Exfil secs: 0.994, 0.964, 0.972, 0.926, 0.943 (avg 0.96, sigma 0.02).
- Download MiB/s: 9.82, 15.15, 8.77, 9.53, 9.94 (avg 10.64, sigma 2.29).
- Download secs: 1.018, 0.660, 1.141, 1.049, 1.006 (avg 0.97, sigma 0.16).
