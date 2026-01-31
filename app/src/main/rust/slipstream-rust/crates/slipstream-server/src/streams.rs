use crate::server::{Command, StreamKey, StreamWrite};
use crate::target::spawn_target_connector;
use slipstream_core::flow_control::{
    conn_reserve_bytes, consume_error_log_message, consume_stream_data, handle_stream_receive,
    overflow_log_message, promote_error_log_message, promote_streams, reserve_target_offset,
    FlowControlState, HasFlowControlState, PromoteEntry, StreamReceiveConfig, StreamReceiveOps,
};
use slipstream_core::invariants::InvariantReporter;
#[cfg(test)]
use slipstream_core::test_support::FailureCounter;
use slipstream_ffi::picoquic::{
    picoquic_call_back_event_t, picoquic_close, picoquic_close_immediate, picoquic_cnx_t,
    picoquic_current_time, picoquic_get_first_cnx, picoquic_get_next_cnx,
    picoquic_mark_active_stream, picoquic_provide_stream_data_buffer, picoquic_quic_t,
    picoquic_reset_stream, picoquic_stop_sending, picoquic_stream_data_consumed,
};
use slipstream_ffi::{abort_stream_bidi, SLIPSTREAM_FILE_CANCEL_ERROR, SLIPSTREAM_INTERNAL_ERROR};
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, watch};
use tracing::{debug, error, warn};

static INVARIANT_REPORTER: InvariantReporter = InvariantReporter::new(1_000_000);

pub(crate) struct ServerState {
    target_addr: SocketAddr,
    streams: HashMap<StreamKey, ServerStream>,
    multi_streams: HashSet<usize>,
    command_tx: mpsc::UnboundedSender<Command>,
    debug_streams: bool,
    debug_commands: bool,
    command_counts: CommandCounts,
    last_command_report: Instant,
    last_mark_active_fail_log_at: u64,
    #[cfg(test)]
    mark_active_stream_failures: FailureCounter,
}

#[derive(Default)]
pub(crate) struct ServerStreamMetrics {
    pub(crate) streams_total: usize,
    pub(crate) streams_with_write_tx: usize,
    pub(crate) streams_with_data_rx: usize,
    pub(crate) streams_with_pending_data: usize,
    pub(crate) pending_chunks_total: usize,
    pub(crate) pending_bytes_total: u64,
    pub(crate) queued_bytes_total: u64,
    pub(crate) streams_with_pending_fin: usize,
    pub(crate) streams_with_fin_enqueued: usize,
    pub(crate) streams_with_target_fin_pending: usize,
    pub(crate) streams_with_send_pending: usize,
    pub(crate) streams_with_send_stash: usize,
    pub(crate) send_stash_bytes_total: u64,
    pub(crate) streams_discarding: usize,
    pub(crate) streams_close_after_flush: usize,
    pub(crate) multi_stream: bool,
}

#[allow(dead_code)]
#[derive(Debug)]
pub(crate) struct BacklogStreamSummary {
    pub(crate) stream_id: u64,
    pub(crate) send_pending: bool,
    pub(crate) send_stash_bytes: usize,
    pub(crate) target_fin_pending: bool,
    pub(crate) close_after_flush: bool,
    pub(crate) pending_fin: bool,
    pub(crate) fin_enqueued: bool,
    pub(crate) queued_bytes: u64,
    pub(crate) pending_chunks: usize,
}

impl ServerStreamMetrics {
    pub(crate) fn has_send_backlog(&self) -> bool {
        self.streams_with_send_pending > 0
            || self.streams_with_send_stash > 0
            || self.streams_with_target_fin_pending > 0
    }
}

impl ServerState {
    pub(crate) fn new(
        target_addr: SocketAddr,
        command_tx: mpsc::UnboundedSender<Command>,
        debug_streams: bool,
        debug_commands: bool,
    ) -> Self {
        Self {
            target_addr,
            streams: HashMap::new(),
            multi_streams: HashSet::new(),
            command_tx,
            debug_streams,
            debug_commands,
            command_counts: CommandCounts::default(),
            last_command_report: Instant::now(),
            last_mark_active_fail_log_at: 0,
            #[cfg(test)]
            mark_active_stream_failures: FailureCounter::new(),
        }
    }

    pub(crate) fn stream_debug_metrics(&self, cnx_id: usize) -> ServerStreamMetrics {
        let mut metrics = ServerStreamMetrics {
            multi_stream: self.multi_streams.contains(&cnx_id),
            ..ServerStreamMetrics::default()
        };
        for (key, stream) in self.streams.iter() {
            if key.cnx != cnx_id {
                continue;
            }
            metrics.streams_total = metrics.streams_total.saturating_add(1);
            if stream.write_tx.is_some() {
                metrics.streams_with_write_tx = metrics.streams_with_write_tx.saturating_add(1);
            }
            if stream.data_rx.is_some() {
                metrics.streams_with_data_rx = metrics.streams_with_data_rx.saturating_add(1);
            }
            let queued = stream.flow.queued_bytes as u64;
            metrics.queued_bytes_total = metrics.queued_bytes_total.saturating_add(queued);
            if !stream.pending_data.is_empty() {
                metrics.streams_with_pending_data =
                    metrics.streams_with_pending_data.saturating_add(1);
                metrics.pending_chunks_total = metrics
                    .pending_chunks_total
                    .saturating_add(stream.pending_data.len());
                let pending_bytes: u64 = stream
                    .pending_data
                    .iter()
                    .map(|chunk| chunk.len() as u64)
                    .sum();
                metrics.pending_bytes_total =
                    metrics.pending_bytes_total.saturating_add(pending_bytes);
            }
            if stream.pending_fin {
                metrics.streams_with_pending_fin =
                    metrics.streams_with_pending_fin.saturating_add(1);
            }
            if stream.fin_enqueued {
                metrics.streams_with_fin_enqueued =
                    metrics.streams_with_fin_enqueued.saturating_add(1);
            }
            if stream.target_fin_pending {
                metrics.streams_with_target_fin_pending =
                    metrics.streams_with_target_fin_pending.saturating_add(1);
            }
            if let Some(flag) = stream.send_pending.as_ref() {
                if flag.load(Ordering::SeqCst) {
                    metrics.streams_with_send_pending =
                        metrics.streams_with_send_pending.saturating_add(1);
                }
            }
            if let Some(stash) = stream.send_stash.as_ref() {
                if !stash.is_empty() {
                    metrics.streams_with_send_stash =
                        metrics.streams_with_send_stash.saturating_add(1);
                    metrics.send_stash_bytes_total = metrics
                        .send_stash_bytes_total
                        .saturating_add(stash.len() as u64);
                }
            }
            if stream.flow.discarding {
                metrics.streams_discarding = metrics.streams_discarding.saturating_add(1);
            }
            if stream.close_after_flush {
                metrics.streams_close_after_flush =
                    metrics.streams_close_after_flush.saturating_add(1);
            }
        }
        metrics
    }

    pub(crate) fn stream_send_backlog_summaries(
        &self,
        cnx_id: usize,
        limit: usize,
    ) -> Vec<BacklogStreamSummary> {
        let mut summaries = Vec::new();
        for (key, stream) in self.streams.iter() {
            if key.cnx != cnx_id {
                continue;
            }
            let send_pending = stream
                .send_pending
                .as_ref()
                .map(|flag| flag.load(Ordering::SeqCst))
                .unwrap_or(false);
            let send_stash_bytes = stream
                .send_stash
                .as_ref()
                .map(|data| data.len())
                .unwrap_or(0);
            if send_pending || send_stash_bytes > 0 || stream.target_fin_pending {
                summaries.push(BacklogStreamSummary {
                    stream_id: key.stream_id,
                    send_pending,
                    send_stash_bytes,
                    target_fin_pending: stream.target_fin_pending,
                    close_after_flush: stream.close_after_flush,
                    pending_fin: stream.pending_fin,
                    fin_enqueued: stream.fin_enqueued,
                    queued_bytes: stream.flow.queued_bytes as u64,
                    pending_chunks: stream.pending_data.len(),
                });
                if summaries.len() >= limit {
                    break;
                }
            }
        }
        summaries
    }
}

#[cfg(test)]
mod test_helpers {
    use super::ServerState;

    pub(super) fn set_mark_active_stream_failures(state: &mut ServerState, count: usize) {
        state.mark_active_stream_failures.set(count);
    }

    pub(super) fn take_mark_active_stream_failure(state: &ServerState) -> bool {
        state.mark_active_stream_failures.take()
    }
}

fn report_invariant<F>(message: F)
where
    F: FnOnce() -> String,
{
    let now = unsafe { picoquic_current_time() };
    INVARIANT_REPORTER.report(now, message, |msg| error!("{}", msg));
}

fn check_stream_invariants(state: &ServerState, key: StreamKey, context: &str) {
    let Some(stream) = state.streams.get(&key) else {
        return;
    };
    if stream.close_after_flush && !stream.target_fin_pending {
        report_invariant(|| {
            format!(
                "server invariant violated: close_after_flush without target_fin_pending stream={} context={} queued={} pending_fin={} fin_enqueued={} target_fin_pending={} close_after_flush={}",
                key.stream_id,
                context,
                stream.flow.queued_bytes,
                stream.pending_fin,
                stream.fin_enqueued,
                stream.target_fin_pending,
                stream.close_after_flush
            )
        });
    }
    if stream.pending_fin && stream.fin_enqueued {
        report_invariant(|| {
            format!(
                "server invariant violated: pending_fin with fin_enqueued stream={} context={} queued={} pending_chunks={} target_fin_pending={} close_after_flush={}",
                key.stream_id,
                context,
                stream.flow.queued_bytes,
                stream.pending_data.len(),
                stream.target_fin_pending,
                stream.close_after_flush
            )
        });
    }
    if stream.write_tx.is_some() != stream.send_pending.is_some() {
        report_invariant(|| {
            format!(
                "server invariant violated: write_tx/send_pending mismatch stream={} context={} write_tx={} send_pending={} data_rx={}",
                key.stream_id,
                context,
                stream.write_tx.is_some(),
                stream.send_pending.is_some(),
                stream.data_rx.is_some()
            )
        });
    }
}

#[derive(Default)]
struct CommandCounts {
    stream_connected: u64,
    stream_connect_error: u64,
    stream_closed: u64,
    stream_readable: u64,
    stream_read_error: u64,
    stream_write_error: u64,
    stream_write_drained: u64,
}

impl CommandCounts {
    fn bump(&mut self, command: &Command) {
        match command {
            Command::StreamConnected { .. } => self.stream_connected += 1,
            Command::StreamConnectError { .. } => self.stream_connect_error += 1,
            Command::StreamClosed { .. } => self.stream_closed += 1,
            Command::StreamReadable { .. } => self.stream_readable += 1,
            Command::StreamReadError { .. } => self.stream_read_error += 1,
            Command::StreamWriteError { .. } => self.stream_write_error += 1,
            Command::StreamWriteDrained { .. } => self.stream_write_drained += 1,
        }
    }

    fn total(&self) -> u64 {
        self.stream_connected
            + self.stream_connect_error
            + self.stream_closed
            + self.stream_readable
            + self.stream_read_error
            + self.stream_write_error
            + self.stream_write_drained
    }

    fn reset(&mut self) {
        *self = CommandCounts::default();
    }
}

struct ServerStream {
    write_tx: Option<mpsc::UnboundedSender<StreamWrite>>,
    data_rx: Option<mpsc::Receiver<Vec<u8>>>,
    send_pending: Option<Arc<AtomicBool>>,
    send_stash: Option<Vec<u8>>,
    shutdown_tx: watch::Sender<bool>,
    tx_bytes: u64,
    target_fin_pending: bool,
    close_after_flush: bool,
    pending_data: VecDeque<Vec<u8>>,
    pending_fin: bool,
    fin_enqueued: bool,
    flow: FlowControlState,
}

impl HasFlowControlState for ServerStream {
    fn flow_control(&self) -> &FlowControlState {
        &self.flow
    }

    fn flow_control_mut(&mut self) -> &mut FlowControlState {
        &mut self.flow
    }
}

fn mark_multi_stream(state: &mut ServerState, cnx_id: usize) -> bool {
    if state.multi_streams.contains(&cnx_id) {
        return false;
    }
    let count = state.streams.keys().filter(|key| key.cnx == cnx_id).count();
    if count > 1 {
        state.multi_streams.insert(cnx_id);
        true
    } else {
        false
    }
}

pub(crate) unsafe extern "C" fn server_callback(
    cnx: *mut picoquic_cnx_t,
    stream_id: u64,
    bytes: *mut u8,
    length: libc::size_t,
    fin_or_event: picoquic_call_back_event_t,
    callback_ctx: *mut std::ffi::c_void,
    _stream_ctx: *mut std::ffi::c_void,
) -> libc::c_int {
    if callback_ctx.is_null() {
        return 0;
    }
    let state = &mut *(callback_ctx as *mut ServerState);

    match fin_or_event {
        picoquic_call_back_event_t::picoquic_callback_stream_data
        | picoquic_call_back_event_t::picoquic_callback_stream_fin => {
            let fin = matches!(
                fin_or_event,
                picoquic_call_back_event_t::picoquic_callback_stream_fin
            );
            let data = if length > 0 && !bytes.is_null() {
                unsafe { std::slice::from_raw_parts(bytes as *const u8, length) }
            } else {
                &[]
            };
            handle_stream_data(cnx, state, stream_id, fin, data);
        }
        picoquic_call_back_event_t::picoquic_callback_stream_reset
        | picoquic_call_back_event_t::picoquic_callback_stop_sending => {
            let reason = match fin_or_event {
                picoquic_call_back_event_t::picoquic_callback_stream_reset => "stream_reset",
                picoquic_call_back_event_t::picoquic_callback_stop_sending => "stop_sending",
                _ => "unknown",
            };
            let key = StreamKey {
                cnx: cnx as usize,
                stream_id,
            };
            if let Some(stream) = shutdown_stream(state, key) {
                warn!(
                    "stream {:?}: reset event={} tx_bytes={} rx_bytes={} consumed_offset={} queued={} pending_chunks={} pending_fin={} fin_enqueued={} fin_offset={:?} target_fin_pending={} close_after_flush={}",
                    key.stream_id,
                    reason,
                    stream.tx_bytes,
                    stream.flow.rx_bytes,
                    stream.flow.consumed_offset,
                    stream.flow.queued_bytes,
                    stream.pending_data.len(),
                    stream.pending_fin,
                    stream.fin_enqueued,
                    stream.flow.fin_offset,
                    stream.target_fin_pending,
                    stream.close_after_flush
                );
            } else {
                warn!(
                    "stream {:?}: reset event={} (unknown stream)",
                    stream_id, reason
                );
            }
            let _ = picoquic_reset_stream(cnx, stream_id, SLIPSTREAM_FILE_CANCEL_ERROR);
        }
        picoquic_call_back_event_t::picoquic_callback_close
        | picoquic_call_back_event_t::picoquic_callback_application_close
        | picoquic_call_back_event_t::picoquic_callback_stateless_reset => {
            remove_connection_streams(state, cnx as usize);
            let _ = picoquic_close(cnx, 0);
        }
        picoquic_call_back_event_t::picoquic_callback_prepare_to_send => {
            if bytes.is_null() {
                return 0;
            }
            let key = StreamKey {
                cnx: cnx as usize,
                stream_id,
            };
            let mut remove_stream = false;
            if let Some(stream) = state.streams.get_mut(&key) {
                let pending_flag = stream
                    .send_pending
                    .as_ref()
                    .map(|flag| flag.load(Ordering::SeqCst))
                    .unwrap_or(false);
                let has_stash = stream
                    .send_stash
                    .as_ref()
                    .is_some_and(|data| !data.is_empty());
                let has_pending = pending_flag || has_stash;

                if length == 0 {
                    if pending_flag && !has_stash && !stream.target_fin_pending {
                        let rx_empty = stream
                            .data_rx
                            .as_ref()
                            .map(|rx| rx.is_empty())
                            .unwrap_or(true);
                        if rx_empty {
                            let send_stash_bytes = stream
                                .send_stash
                                .as_ref()
                                .map(|data| data.len())
                                .unwrap_or(0);
                            let queued_bytes = stream.flow.queued_bytes;
                            let pending_chunks = stream.pending_data.len();
                            let tx_bytes = stream.tx_bytes;
                            let target_fin_pending = stream.target_fin_pending;
                            let close_after_flush = stream.close_after_flush;
                            let now = unsafe { picoquic_current_time() };
                            INVARIANT_REPORTER.report(
                                now,
                                || {
                                    format!(
                                        "cnx {} stream {:?}: zero-length send callback saw pending flag with empty queue send_pending={} send_stash_bytes={} target_fin_pending={} close_after_flush={} queued={} pending_chunks={} tx_bytes={}",
                                        key.cnx,
                                        key.stream_id,
                                        pending_flag,
                                        send_stash_bytes,
                                        target_fin_pending,
                                        close_after_flush,
                                        queued_bytes,
                                        pending_chunks,
                                        tx_bytes
                                    )
                                },
                                |msg| warn!("{}", msg),
                            );
                        }
                    }
                    let still_active = if has_pending || stream.target_fin_pending {
                        1
                    } else {
                        0
                    };
                    if still_active == 0 {
                        if let Some(flag) = stream.send_pending.as_ref() {
                            flag.store(false, Ordering::SeqCst);
                        }
                    }
                    let _ =
                        picoquic_provide_stream_data_buffer(bytes as *mut _, 0, 0, still_active);
                    return 0;
                }

                let mut send_data: Option<Vec<u8>> = None;
                if let Some(mut stash) = stream.send_stash.take() {
                    if stash.len() > length {
                        let remainder = stash.split_off(length);
                        stream.send_stash = Some(remainder);
                    }
                    send_data = Some(stash);
                } else if let Some(rx) = stream.data_rx.as_mut() {
                    match rx.try_recv() {
                        Ok(mut data) => {
                            if data.len() > length {
                                let remainder = data.split_off(length);
                                stream.send_stash = Some(remainder);
                            }
                            send_data = Some(data);
                        }
                        Err(mpsc::error::TryRecvError::Empty) => {}
                        Err(mpsc::error::TryRecvError::Disconnected) => {
                            stream.data_rx = None;
                            stream.target_fin_pending = true;
                            stream.close_after_flush = true;
                        }
                    }
                }

                if let Some(data) = send_data {
                    let send_len = data.len();
                    let buffer =
                        picoquic_provide_stream_data_buffer(bytes as *mut _, send_len, 0, 1);
                    if buffer.is_null() {
                        if let Some(stream) = shutdown_stream(state, key) {
                            error!(
                                "stream {:?}: provide_stream_data_buffer returned null send_len={} queued={} pending_chunks={} tx_bytes={}",
                                key.stream_id,
                                send_len,
                                stream.flow.queued_bytes,
                                stream.pending_data.len(),
                                stream.tx_bytes
                            );
                        } else {
                            error!(
                                "stream {:?}: provide_stream_data_buffer returned null send_len={}",
                                key.stream_id, send_len
                            );
                        }
                        unsafe { abort_stream_bidi(cnx, stream_id, SLIPSTREAM_INTERNAL_ERROR) };
                        return 0;
                    }
                    unsafe {
                        std::ptr::copy_nonoverlapping(data.as_ptr(), buffer, data.len());
                    }
                    stream.tx_bytes = stream.tx_bytes.saturating_add(data.len() as u64);
                } else if stream.target_fin_pending {
                    stream.target_fin_pending = false;
                    if stream.close_after_flush {
                        remove_stream = true;
                    }
                    if let Some(flag) = stream.send_pending.as_ref() {
                        flag.store(false, Ordering::SeqCst);
                    }
                    let _ = picoquic_provide_stream_data_buffer(bytes as *mut _, 0, 1, 0);
                } else {
                    if let Some(flag) = stream.send_pending.as_ref() {
                        flag.store(false, Ordering::SeqCst);
                    }
                    let _ = picoquic_provide_stream_data_buffer(bytes as *mut _, 0, 0, 0);
                }
            } else {
                let _ = picoquic_provide_stream_data_buffer(bytes as *mut _, 0, 0, 0);
            }

            if remove_stream {
                shutdown_stream(state, key);
            }
        }
        _ => {}
    }

    0
}

fn handle_stream_data(
    cnx: *mut picoquic_cnx_t,
    state: &mut ServerState,
    stream_id: u64,
    fin: bool,
    data: &[u8],
) {
    let key = StreamKey {
        cnx: cnx as usize,
        stream_id,
    };
    let debug_streams = state.debug_streams;
    let mut reset_stream = false;
    let mut remove_stream = false;

    if !state.streams.contains_key(&key) {
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        if debug_streams {
            debug!("stream {:?}: connecting", key.stream_id);
        }
        spawn_target_connector(
            key,
            state.target_addr,
            state.command_tx.clone(),
            debug_streams,
            shutdown_rx,
        );
        state.streams.insert(
            key,
            ServerStream {
                write_tx: None,
                data_rx: None,
                send_pending: None,
                send_stash: None,
                shutdown_tx,
                tx_bytes: 0,
                target_fin_pending: false,
                close_after_flush: false,
                pending_data: VecDeque::new(),
                pending_fin: false,
                fin_enqueued: false,
                flow: FlowControlState::default(),
            },
        );
    }

    if mark_multi_stream(state, key.cnx) {
        promote_streams(
            state
                .streams
                .iter_mut()
                .filter(|(entry_key, _)| entry_key.cnx == key.cnx)
                .map(|(entry_key, stream)| PromoteEntry {
                    stream_id: entry_key.stream_id,
                    rx_bytes: stream.flow.rx_bytes,
                    consumed_offset: &mut stream.flow.consumed_offset,
                    discarding: stream.flow.discarding,
                }),
            |stream_id, new_offset| unsafe {
                picoquic_stream_data_consumed(cnx, stream_id, new_offset)
            },
            |stream_id, ret, consumed_offset, rx_bytes| {
                warn!(
                    "{}",
                    promote_error_log_message(stream_id, ret, consumed_offset, rx_bytes)
                );
            },
        );
    }
    let multi_stream = state.multi_streams.contains(&key.cnx);
    let reserve_bytes = if multi_stream {
        0
    } else {
        conn_reserve_bytes()
    };

    {
        let stream = match state.streams.get_mut(&key) {
            Some(stream) => stream,
            None => return,
        };

        if handle_stream_receive(
            stream,
            data.len(),
            StreamReceiveConfig::new(multi_stream, reserve_bytes),
            StreamReceiveOps {
                enqueue: |stream: &mut ServerStream| {
                    if let Some(write_tx) = stream.write_tx.as_ref() {
                        if write_tx.send(StreamWrite::Data(data.to_vec())).is_err() {
                            return Err(());
                        }
                    } else {
                        stream.pending_data.push_back(data.to_vec());
                    }
                    Ok(())
                },
                on_overflow: |stream: &mut ServerStream| {
                    stream.pending_data.clear();
                    stream.pending_fin = false;
                    stream.fin_enqueued = false;
                    stream.data_rx = None;
                    stream.write_tx = None;
                    stream.send_pending = None;
                    stream.send_stash = None;
                    stream.target_fin_pending = false;
                    stream.close_after_flush = false;
                    let _ = stream.shutdown_tx.send(true);
                },
                consume: |new_offset| unsafe {
                    picoquic_stream_data_consumed(cnx, stream_id, new_offset)
                },
                stop_sending: || {
                    let _ =
                        unsafe { picoquic_stop_sending(cnx, stream_id, SLIPSTREAM_INTERNAL_ERROR) };
                },
                log_overflow: |queued, incoming, max| {
                    warn!("{}", overflow_log_message(stream_id, queued, incoming, max));
                },
                on_consume_error: |ret, current, target| {
                    warn!(
                        "{}",
                        consume_error_log_message(stream_id, "", ret, current, target)
                    );
                },
            },
        ) {
            reset_stream = true;
        }

        if fin {
            if stream.flow.discarding {
                if !reset_stream {
                    remove_stream = true;
                }
            } else {
                if stream.flow.fin_offset.is_none() {
                    stream.flow.fin_offset = Some(stream.flow.rx_bytes);
                }
                if !stream.fin_enqueued {
                    if stream.write_tx.is_some() && stream.pending_data.is_empty() {
                        if let Some(write_tx) = stream.write_tx.as_ref() {
                            if write_tx.send(StreamWrite::Fin).is_err() {
                                reset_stream = true;
                            } else {
                                stream.fin_enqueued = true;
                                stream.pending_fin = false;
                            }
                        }
                    } else {
                        stream.pending_fin = true;
                    }
                }
            }
        }
    }

    if remove_stream {
        shutdown_stream(state, key);
        return;
    }

    if reset_stream {
        if debug_streams {
            debug!("stream {:?}: resetting", stream_id);
        }
        if !state
            .streams
            .get(&key)
            .map(|stream| stream.flow.discarding)
            .unwrap_or(false)
        {
            shutdown_stream(state, key);
        }
        unsafe { abort_stream_bidi(cnx, stream_id, SLIPSTREAM_INTERNAL_ERROR) };
    }

    check_stream_invariants(state, key, "handle_stream_data");
}

pub(crate) fn remove_connection_streams(state: &mut ServerState, cnx: usize) {
    let keys: Vec<StreamKey> = state
        .streams
        .keys()
        .filter(|key| key.cnx == cnx)
        .cloned()
        .collect();
    for key in keys {
        shutdown_stream(state, key);
    }
    state.multi_streams.remove(&cnx);
}

fn shutdown_stream(state: &mut ServerState, key: StreamKey) -> Option<ServerStream> {
    if let Some(stream) = state.streams.remove(&key) {
        let _ = stream.shutdown_tx.send(true);
        return Some(stream);
    }
    None
}

pub(crate) fn drain_commands(
    state_ptr: *mut ServerState,
    command_rx: &mut mpsc::UnboundedReceiver<Command>,
) {
    while let Ok(command) = command_rx.try_recv() {
        handle_command(state_ptr, command);
    }
}

pub(crate) fn handle_command(state_ptr: *mut ServerState, command: Command) {
    let state = unsafe { &mut *state_ptr };
    if state.debug_commands {
        state.command_counts.bump(&command);
    }
    match command {
        Command::StreamConnected {
            cnx_id,
            stream_id,
            write_tx,
            data_rx,
            send_pending,
        } => {
            let key = StreamKey {
                cnx: cnx_id,
                stream_id,
            };
            let mut reset_stream = false;
            {
                let Some(stream) = state.streams.get_mut(&key) else {
                    return;
                };
                if state.debug_streams {
                    debug!("stream {:?}: target connected", stream_id);
                }
                if stream.flow.discarding {
                    stream.pending_data.clear();
                    stream.pending_fin = false;
                    stream.fin_enqueued = false;
                    let _ = stream.shutdown_tx.send(true);
                    return;
                }
                stream.write_tx = Some(write_tx);
                stream.data_rx = Some(data_rx);
                stream.send_pending = Some(send_pending);
                if let Some(write_tx) = stream.write_tx.as_ref() {
                    while let Some(chunk) = stream.pending_data.pop_front() {
                        if write_tx.send(StreamWrite::Data(chunk)).is_err() {
                            warn!(
                                "stream {:?}: pending write flush failed queued={} pending_chunks={} tx_bytes={}",
                                stream_id,
                                stream.flow.queued_bytes,
                                stream.pending_data.len(),
                                stream.tx_bytes
                            );
                            reset_stream = true;
                            break;
                        }
                    }
                    if !reset_stream && stream.pending_fin && !stream.fin_enqueued {
                        if write_tx.send(StreamWrite::Fin).is_err() {
                            warn!(
                                "stream {:?}: pending fin flush failed queued={} pending_chunks={} tx_bytes={}",
                                stream_id,
                                stream.flow.queued_bytes,
                                stream.pending_data.len(),
                                stream.tx_bytes
                            );
                            reset_stream = true;
                        } else {
                            stream.fin_enqueued = true;
                            stream.pending_fin = false;
                        }
                    }
                }
            }
            if reset_stream {
                let cnx = cnx_id as *mut picoquic_cnx_t;
                shutdown_stream(state, key);
                unsafe { abort_stream_bidi(cnx, stream_id, SLIPSTREAM_INTERNAL_ERROR) };
            }
            check_stream_invariants(state, key, "StreamConnected");
        }
        Command::StreamConnectError { cnx_id, stream_id } => {
            let cnx = cnx_id as *mut picoquic_cnx_t;
            let key = StreamKey {
                cnx: cnx_id,
                stream_id,
            };
            if shutdown_stream(state, key).is_some() {
                unsafe { abort_stream_bidi(cnx, stream_id, SLIPSTREAM_INTERNAL_ERROR) };
                warn!("stream {:?}: target connect failed", stream_id);
            }
        }
        Command::StreamClosed { cnx_id, stream_id } => {
            let key = StreamKey {
                cnx: cnx_id,
                stream_id,
            };
            let mut remove_stream = false;
            if state.streams.contains_key(&key) {
                #[cfg(test)]
                let forced_failure = test_helpers::take_mark_active_stream_failure(state);
                #[cfg(not(test))]
                let forced_failure = false;

                let Some(stream) = state.streams.get_mut(&key) else {
                    return;
                };
                stream.target_fin_pending = true;
                stream.close_after_flush = true;
                if state.debug_streams {
                    debug!(
                        "stream {:?}: closed by target tx_bytes={}",
                        stream_id, stream.tx_bytes
                    );
                }
                if let Some(pending) = stream.send_pending.as_ref() {
                    pending.store(true, Ordering::SeqCst);
                }
                let cnx = cnx_id as *mut picoquic_cnx_t;
                #[cfg(test)]
                let ret = if forced_failure {
                    test_hooks::FORCED_MARK_ACTIVE_STREAM_ERROR
                } else {
                    assert!(
                        cnx_id >= 0x1000,
                        "mark_active_stream called with synthetic cnx_id; set test failure counter"
                    );
                    unsafe { picoquic_mark_active_stream(cnx, stream_id, 1, std::ptr::null_mut()) }
                };
                #[cfg(not(test))]
                let ret =
                    unsafe { picoquic_mark_active_stream(cnx, stream_id, 1, std::ptr::null_mut()) };
                if ret != 0 {
                    const MARK_ACTIVE_FAIL_LOG_INTERVAL_US: u64 = 1_000_000;
                    let now = unsafe { picoquic_current_time() };
                    if now.saturating_sub(state.last_mark_active_fail_log_at)
                        >= MARK_ACTIVE_FAIL_LOG_INTERVAL_US
                    {
                        let send_pending = stream
                            .send_pending
                            .as_ref()
                            .map(|pending| pending.load(Ordering::SeqCst))
                            .unwrap_or(false);
                        let send_stash_bytes = stream
                            .send_stash
                            .as_ref()
                            .map(|stash| stash.len())
                            .unwrap_or(0);
                        let backlog = BacklogStreamSummary {
                            stream_id,
                            send_pending,
                            send_stash_bytes,
                            target_fin_pending: stream.target_fin_pending,
                            close_after_flush: stream.close_after_flush,
                            pending_fin: stream.pending_fin,
                            fin_enqueued: stream.fin_enqueued,
                            queued_bytes: stream.flow.queued_bytes as u64,
                            pending_chunks: stream.pending_data.len(),
                        };
                        warn!(
                            "stream {:?}: mark_active_stream fin failed ret={} backlog={:?}",
                            stream_id, ret, backlog
                        );
                        state.last_mark_active_fail_log_at = now;
                    }
                    if !forced_failure {
                        unsafe { abort_stream_bidi(cnx, stream_id, SLIPSTREAM_INTERNAL_ERROR) };
                    }
                    remove_stream = true;
                }
            }
            if remove_stream {
                shutdown_stream(state, key);
            }
            check_stream_invariants(state, key, "StreamClosed");
        }
        Command::StreamReadable { cnx_id, stream_id } => {
            let key = StreamKey {
                cnx: cnx_id,
                stream_id,
            };
            if !state.streams.contains_key(&key) {
                return;
            }
            #[cfg(test)]
            let forced_failure = test_helpers::take_mark_active_stream_failure(state);
            #[cfg(not(test))]
            let forced_failure = false;
            let cnx = cnx_id as *mut picoquic_cnx_t;
            #[cfg(test)]
            let ret = if forced_failure {
                test_hooks::FORCED_MARK_ACTIVE_STREAM_ERROR
            } else {
                assert!(
                    cnx_id >= 0x1000,
                    "mark_active_stream called with synthetic cnx_id; set test failure counter"
                );
                unsafe { picoquic_mark_active_stream(cnx, stream_id, 1, std::ptr::null_mut()) }
            };
            #[cfg(not(test))]
            let ret =
                unsafe { picoquic_mark_active_stream(cnx, stream_id, 1, std::ptr::null_mut()) };
            if ret != 0 {
                if let Some(stream) = shutdown_stream(state, key) {
                    warn!(
                        "stream {:?}: mark_active_stream readable failed ret={} tx_bytes={} rx_bytes={} consumed_offset={} queued={} fin_offset={:?}",
                        stream_id,
                        ret,
                        stream.tx_bytes,
                        stream.flow.rx_bytes,
                        stream.flow.consumed_offset,
                        stream.flow.queued_bytes,
                        stream.flow.fin_offset
                    );
                    if !forced_failure {
                        unsafe { abort_stream_bidi(cnx, stream_id, SLIPSTREAM_INTERNAL_ERROR) };
                    }
                } else if state.debug_streams {
                    debug!(
                        "stream {:?}: mark_active_stream readable failed ret={}",
                        stream_id, ret
                    );
                }
            }
        }
        Command::StreamReadError { cnx_id, stream_id } => {
            let cnx = cnx_id as *mut picoquic_cnx_t;
            let key = StreamKey {
                cnx: cnx_id,
                stream_id,
            };
            if let Some(stream) = shutdown_stream(state, key) {
                warn!(
                    "stream {:?}: target read error tx_bytes={} rx_bytes={} consumed_offset={} queued={} fin_offset={:?}",
                    stream_id,
                    stream.tx_bytes,
                    stream.flow.rx_bytes,
                    stream.flow.consumed_offset,
                    stream.flow.queued_bytes,
                    stream.flow.fin_offset
                );
                unsafe { abort_stream_bidi(cnx, stream_id, SLIPSTREAM_INTERNAL_ERROR) };
            }
        }
        Command::StreamWriteError { cnx_id, stream_id } => {
            let cnx = cnx_id as *mut picoquic_cnx_t;
            let key = StreamKey {
                cnx: cnx_id,
                stream_id,
            };
            if let Some(stream) = shutdown_stream(state, key) {
                warn!(
                    "stream {:?}: target write failed tx_bytes={} rx_bytes={} consumed_offset={} queued={} fin_offset={:?}",
                    stream_id,
                    stream.tx_bytes,
                    stream.flow.rx_bytes,
                    stream.flow.consumed_offset,
                    stream.flow.queued_bytes,
                    stream.flow.fin_offset
                );
                unsafe { abort_stream_bidi(cnx, stream_id, SLIPSTREAM_INTERNAL_ERROR) };
            }
        }
        Command::StreamWriteDrained {
            cnx_id,
            stream_id,
            bytes,
        } => {
            let key = StreamKey {
                cnx: cnx_id,
                stream_id,
            };
            let mut reset_stream = false;
            if let Some(stream) = state.streams.get_mut(&key) {
                if stream.flow.discarding {
                    return;
                }
                stream.flow.queued_bytes = stream.flow.queued_bytes.saturating_sub(bytes);
                if !state.multi_streams.contains(&cnx_id) {
                    let new_offset = reserve_target_offset(
                        stream.flow.rx_bytes,
                        stream.flow.queued_bytes,
                        stream.flow.fin_offset,
                        conn_reserve_bytes(),
                    );
                    if !consume_stream_data(
                        &mut stream.flow.consumed_offset,
                        new_offset,
                        |new_offset| unsafe {
                            picoquic_stream_data_consumed(
                                cnx_id as *mut picoquic_cnx_t,
                                stream_id,
                                new_offset,
                            )
                        },
                        |ret, current, target| {
                            warn!(
                                "{}",
                                consume_error_log_message(stream_id, "", ret, current, target)
                            );
                        },
                    ) {
                        reset_stream = true;
                    }
                }
            }
            if reset_stream {
                shutdown_stream(state, key);
                unsafe {
                    abort_stream_bidi(
                        cnx_id as *mut picoquic_cnx_t,
                        stream_id,
                        SLIPSTREAM_INTERNAL_ERROR,
                    )
                };
            }
            check_stream_invariants(state, key, "StreamWriteDrained");
        }
    }
}

pub(crate) fn maybe_report_command_stats(state_ptr: *mut ServerState) {
    let state = unsafe { &mut *state_ptr };
    if !state.debug_commands {
        return;
    }
    let now = Instant::now();
    if now.duration_since(state.last_command_report) < Duration::from_secs(1) {
        return;
    }
    let total = state.command_counts.total();
    if total > 0 {
        debug!(
            "debug: commands total={} connected={} connect_err={} closed={} readable={} read_err={} write_err={} write_drained={}",
            total,
            state.command_counts.stream_connected,
            state.command_counts.stream_connect_error,
            state.command_counts.stream_closed,
            state.command_counts.stream_readable,
            state.command_counts.stream_read_error,
            state.command_counts.stream_write_error,
            state.command_counts.stream_write_drained
        );
    }
    state.command_counts.reset();
    state.last_command_report = now;
}

pub(crate) fn handle_shutdown(quic: *mut picoquic_quic_t, state: &mut ServerState) -> bool {
    let mut cnx = unsafe { picoquic_get_first_cnx(quic) };
    while !cnx.is_null() {
        let next = unsafe { picoquic_get_next_cnx(cnx) };
        unsafe { picoquic_close_immediate(cnx) };
        remove_connection_streams(state, cnx as usize);
        cnx = next;
    }
    state.streams.clear();
    state.multi_streams.clear();
    true
}

#[cfg(test)]
mod test_hooks {
    pub(super) const FORCED_MARK_ACTIVE_STREAM_ERROR: i32 = 0x400 + 36;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::net::SocketAddr;
    use std::sync::atomic::AtomicBool;
    use std::sync::Arc;
    use tokio::sync::{mpsc, watch};

    #[test]
    fn mark_active_stream_failure_should_remove_stream() {
        let (command_tx, _command_rx) = mpsc::unbounded_channel();
        let target_addr = SocketAddr::from(([127, 0, 0, 1], 0));
        let mut state = ServerState::new(target_addr, command_tx, false, false);
        let key = StreamKey {
            cnx: 0x1,
            stream_id: 4,
        };
        let (shutdown_tx, _shutdown_rx) = watch::channel(false);

        state.streams.insert(
            key,
            ServerStream {
                write_tx: None,
                data_rx: None,
                send_pending: Some(Arc::new(AtomicBool::new(false))),
                send_stash: None,
                shutdown_tx,
                tx_bytes: 0,
                target_fin_pending: false,
                close_after_flush: false,
                pending_data: VecDeque::new(),
                pending_fin: false,
                fin_enqueued: false,
                flow: FlowControlState::default(),
            },
        );

        test_helpers::set_mark_active_stream_failures(&mut state, 1);

        handle_command(
            &mut state as *mut _,
            Command::StreamClosed {
                cnx_id: key.cnx,
                stream_id: key.stream_id,
            },
        );

        assert!(
            !state.streams.contains_key(&key),
            "stream state should be removed when mark_active_stream fails"
        );
    }

    #[test]
    fn mark_active_stream_readable_failure_should_not_leave_send_pending_stuck() {
        let (command_tx, _command_rx) = mpsc::unbounded_channel();
        let target_addr = SocketAddr::from(([127, 0, 0, 1], 0));
        let mut state = ServerState::new(target_addr, command_tx, false, false);
        let key = StreamKey {
            cnx: 0x1,
            stream_id: 4,
        };
        let (shutdown_tx, _shutdown_rx) = watch::channel(false);
        let send_pending = Arc::new(AtomicBool::new(true));
        let send_pending_handle = Arc::clone(&send_pending);

        state.streams.insert(
            key,
            ServerStream {
                write_tx: None,
                data_rx: None,
                send_pending: Some(send_pending_handle),
                send_stash: None,
                shutdown_tx,
                tx_bytes: 0,
                target_fin_pending: false,
                close_after_flush: false,
                pending_data: VecDeque::new(),
                pending_fin: false,
                fin_enqueued: false,
                flow: FlowControlState::default(),
            },
        );

        test_helpers::set_mark_active_stream_failures(&mut state, 1);

        handle_command(
            &mut state as *mut _,
            Command::StreamReadable {
                cnx_id: key.cnx,
                stream_id: key.stream_id,
            },
        );

        assert!(
            !state.streams.contains_key(&key),
            "stream state should be removed when mark_active_stream fails"
        );
        assert_eq!(
            Arc::strong_count(&send_pending),
            1,
            "send_pending should be dropped when the stream is removed"
        );
    }
}
