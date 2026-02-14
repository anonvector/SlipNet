use crate::pacing::PacingBudgetSnapshot;
use tracing::debug;

use super::resolver::ResolverState;

const DEBUG_REPORT_INTERVAL_US: u64 = 1_000_000;

pub(crate) struct DebugMetrics {
    pub(crate) enabled: bool,
    pub(crate) last_report_at: u64,
    pub(crate) dns_responses: u64,
    pub(crate) zero_send_loops: u64,
    pub(crate) zero_send_with_streams: u64,
    pub(crate) enqueued_bytes: u64,
    pub(crate) send_packets: u64,
    pub(crate) send_bytes: u64,
    pub(crate) polls_sent: u64,
    pub(crate) last_enqueue_at: u64,
    pub(crate) last_report_dns: u64,
    pub(crate) last_report_zero: u64,
    pub(crate) last_report_zero_streams: u64,
    pub(crate) last_report_enqueued: u64,
    pub(crate) last_report_send_packets: u64,
    pub(crate) last_report_send_bytes: u64,
    pub(crate) last_report_polls: u64,
}

impl DebugMetrics {
    pub(crate) fn new(enabled: bool) -> Self {
        Self {
            enabled,
            last_report_at: 0,
            dns_responses: 0,
            zero_send_loops: 0,
            zero_send_with_streams: 0,
            enqueued_bytes: 0,
            send_packets: 0,
            send_bytes: 0,
            polls_sent: 0,
            last_enqueue_at: 0,
            last_report_dns: 0,
            last_report_zero: 0,
            last_report_zero_streams: 0,
            last_report_enqueued: 0,
            last_report_send_packets: 0,
            last_report_send_bytes: 0,
            last_report_polls: 0,
        }
    }
}

pub(crate) fn maybe_report_debug(
    resolver: &mut ResolverState,
    now: u64,
    streams_len: usize,
    pending_polls: usize,
    inflight_polls: usize,
    pacing_snapshot: Option<PacingBudgetSnapshot>,
    is_idle: bool,
) {
    let label = resolver.label();
    let debug = &mut resolver.debug;
    if !debug.enabled {
        return;
    }
    if debug.last_report_at == 0 {
        debug.last_report_at = now;
        return;
    }
    let elapsed = now.saturating_sub(debug.last_report_at);
    if elapsed < DEBUG_REPORT_INTERVAL_US {
        return;
    }
    let dns_delta = debug.dns_responses.saturating_sub(debug.last_report_dns);
    let zero_delta = debug.zero_send_loops.saturating_sub(debug.last_report_zero);
    let zero_stream_delta = debug
        .zero_send_with_streams
        .saturating_sub(debug.last_report_zero_streams);
    let enq_delta = debug
        .enqueued_bytes
        .saturating_sub(debug.last_report_enqueued);
    let send_pkt_delta = debug
        .send_packets
        .saturating_sub(debug.last_report_send_packets);
    let send_bytes_delta = debug
        .send_bytes
        .saturating_sub(debug.last_report_send_bytes);
    let polls_delta = debug.polls_sent.saturating_sub(debug.last_report_polls);
    let enqueue_ms = if debug.last_enqueue_at == 0 {
        0
    } else {
        now.saturating_sub(debug.last_enqueue_at) / 1_000
    };
    let pacing_summary = if let Some(snapshot) = pacing_snapshot {
        format!(
            " pacing_rate={} qps_target={:.2} target_inflight={} gain={:.2}",
            snapshot.pacing_rate, snapshot.qps, snapshot.target_inflight, snapshot.gain
        )
    } else {
        String::new()
    };
    debug!(
        "debug: {} dns+={} send_pkts+={} send_bytes+={} polls+={} zero_send+={} zero_send_streams+={} streams={} enqueued+={} last_enqueue_ms={} pending_polls={} inflight_polls={} idle={}{}",
        label,
        dns_delta,
        send_pkt_delta,
        send_bytes_delta,
        polls_delta,
        zero_delta,
        zero_stream_delta,
        streams_len,
        enq_delta,
        enqueue_ms,
        pending_polls,
        inflight_polls,
        is_idle,
        pacing_summary
    );
    debug.last_report_at = now;
    debug.last_report_dns = debug.dns_responses;
    debug.last_report_zero = debug.zero_send_loops;
    debug.last_report_zero_streams = debug.zero_send_with_streams;
    debug.last_report_enqueued = debug.enqueued_bytes;
    debug.last_report_send_packets = debug.send_packets;
    debug.last_report_send_bytes = debug.send_bytes;
    debug.last_report_polls = debug.polls_sent;
}
