# Picoquic Changes and Internal API Usage

This document tracks local changes to the `vendor/picoquic` submodule (authored by Mygod)
and the internal picoquic APIs that slipstream relies on, plus why they are needed.

## Submodule changes (author: Mygod)

- 7b5aa781 (2026-01-07) "fix: Closed streams never deleted when exiting deferred consumption"
  - Files: `vendor/picoquic/picoquic/quicctx.c`
  - What changed:
    - When disabling deferred consumption, consume any delivered offsets and update TLS stream offsets,
      which allows closed streams to be deleted.
  - Why:
    - Without this, streams can remain in a closed-but-not-deleted state if deferred consumption was
      enabled and later disabled, leaking stream state.

- 00315b3a (2026-01-06) "feat: add stream data consumption deferral mode"
  - Files: `vendor/picoquic/picoquic/frames.c`, `vendor/picoquic/picoquic/quicctx.c`,
    `vendor/picoquic/picoquic/picoquic.h`, `vendor/picoquic/picoquic/picoquic_internal.h`
  - What changed:
    - Added `picoquic_set_stream_data_consumption_mode` and a `defer_stream_data_consumption` flag.
    - Added `delivered_offset` for streams and routed ordered callbacks through delivered vs consumed offsets.
    - Prevented stream deletion while data is delivered but not consumed.
  - Why:
    - Slipstream needs to delay flow-control credit until data is actually written to TCP.
      This bounds memory while still using connection-level flow control.

- 25966ecb (2026-01-05) "feat: add default direct receive callback"
  - Files: `vendor/picoquic/picoquic/frames.c`, `vendor/picoquic/picoquic/quicctx.c`,
    `vendor/picoquic/picoquic/sender.c`, `vendor/picoquic/picoquic/picoquic.h`,
    `vendor/picoquic/picoquic/picoquic_internal.h`
  - What changed:
    - Added `picoquic_set_default_direct_receive_callback` (applies to new inbound streams).
    - Added `picoquic_stream_data_consumed` API and `data_consumed` tracking in the connection.
    - Updated MAX_DATA updates to use `data_consumed` rather than `data_received`.
  - Why:
    - Slipstream relies on explicit consumption to drive connection-level flow control.
      Using `data_consumed` ensures MAX_DATA frames reflect actual app drain, not mere receipt.

- local (2026-01-08) "feat: per-path slipstream mode + ack-delay override"
  - Files: `vendor/picoquic/picoquic/picoquic_internal.h`, `vendor/picoquic/picoquic/frames.c`
  - What changed:
    - Added `slipstream_path_mode` and `slipstream_no_ack_delay` fields to `picoquic_path_t`.
    - ACK scheduling now checks the per-path no-ack-delay flag in addition to the connection flag.
  - Why:
    - Mixed authoritative/recursive multipath needs per-path congestion control selection and
      per-path delayed-ACK behavior instead of connection-wide toggles.

## Internal picoquic APIs used by slipstream

The following use `picoquic_internal.h` and therefore depend on picoquic internals:

- `cnx->is_poll_requested`
  - Wrapper: `slipstream_request_poll` in `crates/slipstream-ffi/cc/slipstream_poll.c`.
  - Why: DNS is request/response; the client must request polls when idle to elicit server data.

- `cnx->flow_blocked` and `cnx->stream_blocked`
  - Wrapper: `slipstream_is_flow_blocked` in `crates/slipstream-ffi/cc/slipstream_poll.c`.
  - Why: With deferred consumption, the client needs to send poll queries only when flow/stream
    blocked so MAX_DATA updates can arrive without spamming polls. The Rust client also
    suppresses extra polls when stream data is ready unless flow control is blocking.

- `picoquic_find_ready_stream`
  - Wrapper: `slipstream_has_ready_stream` in `crates/slipstream-ffi/cc/slipstream_poll.c`.
  - Why: Avoid sending extra polls while QUIC has stream data queued to send.

- `picoquic_find_path_by_address` and `picoquic_path_t` internals (`peer_addr`,
  `path_is_demoted`, `path_abandon_received`, `path_abandon_sent`, `cnx->nb_paths`)
  - Wrapper: `slipstream_find_path_id_by_addr` in `crates/slipstream-ffi/cc/slipstream_poll.c`.
  - Why: Keep resolver path IDs aligned after path deletion/compaction and avoid polling
    demoted or abandoned paths.

- `cnx->no_ack_delay`
  - Wrapper: `slipstream_disable_ack_delay` in `crates/slipstream-ffi/cc/slipstream_poll.c`.
  - Why: The server disables delayed ACK to reduce DNS round-trip latency for small packets.

- `quic->max_data_limit` and `quic->defer_stream_data_consumption`
  - Wrapper: `slipstream_test_get_max_data_limit` and
    `slipstream_test_get_defer_stream_data_consumption` in
    `crates/slipstream-ffi/cc/slipstream_test_helpers.c`.
  - Why: Tests need to assert that backpressure configuration is applied in the QUIC context.

- `picoquic_path_t` internals (`cwin`, `is_cc_data_updated`, `congestion_alg_state`)
  - Usage: `crates/slipstream-ffi/cc/slipstream_server_cc.c`.
  - Why: The server congestion algorithm is customized to effectively remove CC limits so
    DNS polling and application backpressure control throughput instead of packet-level CC.

- `picoquic_path_t` internals (`slipstream_path_mode`, `slipstream_no_ack_delay`)
  - Usage: `crates/slipstream-ffi/cc/slipstream_mixed_cc.c`.
  - Why: The mixed-mode client selects congestion control per path and toggles delayed ACK per path.
  - Note: The client sets the default path mode before probing a new path so CC init picks
    the correct algorithm, then locks in per-path modes with `slipstream_set_path_mode`.
    Dynamic path mode changes are not supported.
  - Note: Per-path quality data is fetched via the public `picoquic_get_path_quality` API in Rust.

- `quic->pending_stateless_packet`, `picoquic_stateless_packet_t`, `picoquic_parse_packet_header`,
  and `picoquic_create_cnxid_reset_secret`
  - Wrapper: `slipstream_take_stateless_packet_for_cid` in
    `crates/slipstream-ffi/cc/slipstream_stateless_packet.c`.
  - Why: DNS fallback must dequeue and route queued stateless packets (retry, server busy,
    stateless reset) to the matching peer without misrouting.

- `cnx->max_stream_id_bidir_remote` and `cnx->remote_parameters_received`
  - Wrapper: `slipstream_get_max_streams_bidir_remote` in
    `crates/slipstream-ffi/cc/slipstream_poll.c`.
  - Why: The client gates TCP accepts on the negotiated MAX_STREAMS limit to avoid
    creating local connections that cannot send on QUIC yet.

## Public picoquic APIs relied on by slipstream

- `picoquic_get_pacing_rate`
  - Wrapper: `get_pacing_rate` in `crates/slipstream-ffi/src/picoquic.rs`.
  - Why: The authoritative client derives its DNS poll QPS budget from picoquic's pacing rate and
    uses cwnd as a fallback when pacing is unavailable.

## Notes

- Internal usage means the submodule version is coupled to slipstream. Any picoquic update
  should re-validate these fields and wrappers.
- Public APIs added above are called from Rust via `crates/slipstream-ffi/src/picoquic.rs`.
