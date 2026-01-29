use crate::config::{ensure_cert_key, load_or_create_reset_seed, ResetSeed};
use crate::udp_fallback::{handle_packet, FallbackManager, PacketContext, MAX_UDP_PACKET_SIZE};
use slipstream_core::{
    net::is_transient_udp_error, normalize_dual_stack_addr, resolve_host_port, HostPort,
};
use slipstream_dns::{encode_response, Question, Rcode, ResponseParams};
use slipstream_ffi::picoquic::{
    picoquic_cnx_t, picoquic_create, picoquic_current_time, picoquic_delete_cnx,
    picoquic_get_first_cnx, picoquic_get_next_cnx, picoquic_prepare_packet_ex, picoquic_quic_t,
    slipstream_has_ready_stream, slipstream_is_flow_blocked, slipstream_server_cc_algorithm,
    PICOQUIC_MAX_PACKET_SIZE, PICOQUIC_PACKET_LOOP_RECV_MAX,
};
use slipstream_ffi::{
    configure_quic_with_custom, socket_addr_to_storage, take_crypto_errors, QuicGuard,
};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::collections::HashMap;
use std::ffi::CString;
use std::fmt;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::{lookup_host, UdpSocket as TokioUdpSocket};
use tokio::sync::mpsc;
use tokio::time::sleep;

use crate::streams::{
    drain_commands, handle_command, handle_shutdown, maybe_report_command_stats,
    remove_connection_streams, server_callback, ServerState,
};

// Protocol defaults; see docs/config.md for details.
const SLIPSTREAM_ALPN: &str = "picoquic_sample";
const DNS_MAX_QUERY_SIZE: usize = 512;
const IDLE_SLEEP_MS: u64 = 10;
const IDLE_GC_INTERVAL: Duration = Duration::from_secs(1);
// Default QUIC MTU for server packets; see docs/config.md for details.
const QUIC_MTU: u32 = 900;
pub(crate) const STREAM_READ_CHUNK_BYTES: usize = 4096;
pub(crate) const DEFAULT_TCP_RCVBUF_BYTES: usize = 256 * 1024;
pub(crate) const TARGET_WRITE_COALESCE_DEFAULT_BYTES: usize = 256 * 1024;
const FLOW_BLOCKED_LOG_INTERVAL_US: u64 = 1_000_000;

static SHOULD_SHUTDOWN: AtomicBool = AtomicBool::new(false);

extern "C" fn handle_sigterm(_signum: libc::c_int) {
    SHOULD_SHUTDOWN.store(true, Ordering::Relaxed);
}

#[derive(Debug)]
pub struct ServerError {
    message: String,
}

impl ServerError {
    pub(crate) fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for ServerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for ServerError {}

pub struct ServerConfig {
    pub dns_listen_host: String,
    pub dns_listen_port: u16,
    pub target_address: HostPort,
    pub fallback_address: Option<HostPort>,
    pub cert: String,
    pub key: String,
    pub reset_seed_path: Option<String>,
    pub domains: Vec<String>,
    pub max_connections: u32,
    pub idle_timeout_seconds: u64,
    pub debug_streams: bool,
    pub debug_commands: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct StreamKey {
    pub(crate) cnx: usize,
    pub(crate) stream_id: u64,
}

pub(crate) enum StreamWrite {
    Data(Vec<u8>),
    Fin,
}

#[allow(clippy::enum_variant_names)]
pub(crate) enum Command {
    StreamConnected {
        cnx_id: usize,
        stream_id: u64,
        write_tx: mpsc::UnboundedSender<StreamWrite>,
        data_rx: mpsc::Receiver<Vec<u8>>,
        send_pending: Arc<AtomicBool>,
    },
    StreamConnectError {
        cnx_id: usize,
        stream_id: u64,
    },
    StreamClosed {
        cnx_id: usize,
        stream_id: u64,
    },
    StreamReadable {
        cnx_id: usize,
        stream_id: u64,
    },
    StreamReadError {
        cnx_id: usize,
        stream_id: u64,
    },
    StreamWriteError {
        cnx_id: usize,
        stream_id: u64,
    },
    StreamWriteDrained {
        cnx_id: usize,
        stream_id: u64,
        bytes: usize,
    },
}

pub(crate) struct Slot {
    pub(crate) peer: SocketAddr,
    pub(crate) id: u16,
    pub(crate) rd: bool,
    pub(crate) cd: bool,
    pub(crate) question: Question,
    pub(crate) rcode: Option<Rcode>,
    pub(crate) cnx: *mut picoquic_cnx_t,
    pub(crate) path_id: libc::c_int,
    pub(crate) payload_override: Option<Vec<u8>>,
}

pub async fn run_server(config: &ServerConfig) -> Result<i32, ServerError> {
    let cert_path = Path::new(&config.cert);
    let key_path = Path::new(&config.key);
    let generated = ensure_cert_key(cert_path, key_path).map_err(ServerError::new)?;
    if generated {
        tracing::warn!(
            "Generated self-signed TLS cert/key at {} and {} (ECDSA P-256, 1000y validity); replace for production use",
            cert_path.display(),
            key_path.display()
        );
    }

    let reset_seed: Option<ResetSeed> = if let Some(path) = &config.reset_seed_path {
        let seed = load_or_create_reset_seed(Path::new(path)).map_err(ServerError::new)?;
        if seed.created {
            tracing::warn!(
                "Reset seed created at {}; stateless resets will now survive restarts",
                path
            );
        } else {
            tracing::debug!("Loaded reset seed from {}", path);
        }
        Some(seed)
    } else {
        tracing::warn!(
            "Reset seed not configured; stateless resets will not survive server restarts"
        );
        None
    };

    let target_addr = resolve_host_port(&config.target_address)
        .map_err(|err| ServerError::new(err.to_string()))?;
    let fallback_addr = match &config.fallback_address {
        Some(address) => {
            Some(resolve_host_port(address).map_err(|err| ServerError::new(err.to_string()))?)
        }
        None => None,
    };

    let alpn = CString::new(SLIPSTREAM_ALPN)
        .map_err(|_| ServerError::new("ALPN contains an unexpected null byte"))?;
    let cert = CString::new(config.cert.clone())
        .map_err(|_| ServerError::new("Cert path contains an unexpected null byte"))?;
    let key = CString::new(config.key.clone())
        .map_err(|_| ServerError::new("Key path contains an unexpected null byte"))?;
    let (command_tx, mut command_rx) = mpsc::unbounded_channel();
    let debug_streams = config.debug_streams;
    let debug_commands = config.debug_commands;
    let idle_timeout = Duration::from_secs(config.idle_timeout_seconds);
    let mut state = Box::new(ServerState::new(
        target_addr,
        command_tx,
        debug_streams,
        debug_commands,
    ));
    let state_ptr: *mut ServerState = &mut *state;
    let _state = state;

    let current_time = unsafe { picoquic_current_time() };
    let reset_seed_ptr = reset_seed
        .as_ref()
        .map(|seed| seed.bytes.as_ptr())
        .unwrap_or(std::ptr::null());
    let quic = unsafe {
        picoquic_create(
            config.max_connections,
            cert.as_ptr(),
            key.as_ptr(),
            std::ptr::null(),
            alpn.as_ptr(),
            Some(server_callback),
            state_ptr as *mut _,
            None,
            std::ptr::null_mut(),
            reset_seed_ptr,
            current_time,
            std::ptr::null_mut(),
            std::ptr::null(),
            std::ptr::null(),
            0,
        )
    };
    if quic.is_null() {
        let crypto_errors = take_crypto_errors();
        if crypto_errors.is_empty() {
            return Err(ServerError::new("Could not create QUIC context"));
        }
        return Err(ServerError::new(format!(
            "Could not create QUIC context (TLS errors: {})",
            crypto_errors.join("; ")
        )));
    }
    let _quic_guard = QuicGuard::new(quic);
    unsafe {
        if slipstream_server_cc_algorithm.is_null() {
            return Err(ServerError::new(
                "Slipstream server congestion algorithm is unavailable",
            ));
        }
        configure_quic_with_custom(quic, slipstream_server_cc_algorithm, QUIC_MTU);
    }

    let udp = Arc::new(bind_udp_socket(&config.dns_listen_host, config.dns_listen_port).await?);
    let udp_local_addr = udp.local_addr().map_err(map_io)?;
    let map_ipv4_peers = matches!(udp_local_addr, SocketAddr::V6(_));
    let local_addr_storage = socket_addr_to_storage(udp_local_addr);
    if let Some(addr) = fallback_addr {
        if addr == udp_local_addr {
            tracing::warn!(
                "Fallback address matches DNS listen address ({}); non-DNS packets will loop. \
                 Configure a different fallback address.",
                addr
            );
        }
    }
    let mut fallback_mgr =
        fallback_addr.map(|addr| FallbackManager::new(udp.clone(), addr, map_ipv4_peers));
    warn_overlapping_domains(&config.domains);
    let domains: Vec<&str> = config.domains.iter().map(String::as_str).collect();
    if domains.is_empty() {
        return Err(ServerError::new("At least one domain must be configured"));
    }

    unsafe {
        let handler = handle_sigterm as *const () as libc::sighandler_t;
        libc::signal(libc::SIGTERM, handler);
    }

    let recv_buf_len = if fallback_mgr.is_some() {
        MAX_UDP_PACKET_SIZE
    } else {
        DNS_MAX_QUERY_SIZE
    };
    let mut recv_buf = vec![0u8; recv_buf_len];
    let mut send_buf = vec![0u8; PICOQUIC_MAX_PACKET_SIZE];
    let mut last_seen = HashMap::new();
    let mut last_idle_gc = Instant::now();
    let mut last_flow_block_log_at: u64 = 0;

    loop {
        drain_commands(state_ptr, &mut command_rx);

        if SHOULD_SHUTDOWN.load(Ordering::Relaxed) {
            let state = unsafe { &mut *state_ptr };
            if handle_shutdown(quic, state) {
                break;
            }
        }

        let mut slots = Vec::new();
        if let Some(manager) = fallback_mgr.as_mut() {
            manager.cleanup();
        }

        tokio::select! {
            command = command_rx.recv() => {
                if let Some(command) = command {
                    handle_command(state_ptr, command);
                }
            }
            recv = udp.recv_from(&mut recv_buf) => {
                match recv {
                    Ok((size, peer)) => {
                        let loop_time = unsafe { picoquic_current_time() };
                        let context = PacketContext {
                            domains: &domains,
                            quic,
                            current_time: loop_time,
                            local_addr_storage: &local_addr_storage,
                        };
                        handle_packet(
                            &mut slots,
                            &recv_buf[..size],
                            peer,
                            &context,
                            &mut fallback_mgr,
                        )
                        .await?;
                        for _ in 1..PICOQUIC_PACKET_LOOP_RECV_MAX {
                            match udp.try_recv_from(&mut recv_buf) {
                                Ok((size, peer)) => {
                                    handle_packet(
                                        &mut slots,
                                        &recv_buf[..size],
                                        peer,
                                        &context,
                                        &mut fallback_mgr,
                                    )
                                    .await?;
                                }
                                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => break,
                                Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
                                Err(err) => {
                                    if is_transient_udp_error(&err) {
                                        break;
                                    }
                                    return Err(map_io(err));
                                }
                            }
                        }
                    }
                    Err(err) => {
                        if !is_transient_udp_error(&err) {
                            return Err(map_io(err));
                        }
                    }
                }
            }
            _ = sleep(Duration::from_millis(IDLE_SLEEP_MS)) => {}
        }

        let now = Instant::now();
        if idle_timeout != Duration::ZERO {
            note_active_connections(&mut last_seen, &slots, now);
            maybe_gc_idle_connections(
                quic,
                state_ptr,
                &mut last_seen,
                idle_timeout,
                &mut last_idle_gc,
                now,
            );
        }

        drain_commands(state_ptr, &mut command_rx);
        maybe_report_command_stats(state_ptr);

        if slots.is_empty() {
            continue;
        }

        let loop_time = unsafe { picoquic_current_time() };

        for slot in slots.iter_mut() {
            let mut send_length = 0usize;
            let mut addr_to: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
            let mut addr_from: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
            let mut if_index: libc::c_int = 0;

            if slot.payload_override.is_none() && slot.rcode.is_none() && !slot.cnx.is_null() {
                let ret = unsafe {
                    picoquic_prepare_packet_ex(
                        slot.cnx,
                        slot.path_id,
                        loop_time,
                        send_buf.as_mut_ptr(),
                        send_buf.len(),
                        &mut send_length,
                        &mut addr_to,
                        &mut addr_from,
                        &mut if_index,
                        std::ptr::null_mut(),
                    )
                };
                if ret < 0 {
                    return Err(ServerError::new("Failed to prepare QUIC packet"));
                }

                if send_length == 0 {
                    let cnx_id = slot.cnx as usize;
                    let metrics = unsafe { (&*state_ptr).stream_debug_metrics(cnx_id) };
                    if metrics.streams_total > 0
                        && metrics.has_send_backlog()
                        && loop_time.saturating_sub(last_flow_block_log_at)
                            >= FLOW_BLOCKED_LOG_INTERVAL_US
                    {
                        let flow_blocked = unsafe { slipstream_is_flow_blocked(slot.cnx) != 0 };
                        let has_ready_stream =
                            unsafe { slipstream_has_ready_stream(slot.cnx) != 0 };
                        let send_backlog =
                            unsafe { (&*state_ptr).stream_send_backlog_summaries(cnx_id, 8) };
                        tracing::warn!(
                            "server connection stalled: cnx={} streams={} streams_with_write_tx={} streams_with_data_rx={} queued_bytes_total={} streams_with_pending_data={} pending_chunks_total={} pending_bytes_total={} streams_with_pending_fin={} streams_with_fin_enqueued={} streams_with_target_fin_pending={} streams_with_send_pending={} streams_with_send_stash={} send_stash_bytes_total={} streams_discarding={} streams_close_after_flush={} multi_stream={} flow_blocked={} has_ready_stream={} send_backlog={:?}",
                            cnx_id,
                            metrics.streams_total,
                            metrics.streams_with_write_tx,
                            metrics.streams_with_data_rx,
                            metrics.queued_bytes_total,
                            metrics.streams_with_pending_data,
                            metrics.pending_chunks_total,
                            metrics.pending_bytes_total,
                            metrics.streams_with_pending_fin,
                            metrics.streams_with_fin_enqueued,
                            metrics.streams_with_target_fin_pending,
                            metrics.streams_with_send_pending,
                            metrics.streams_with_send_stash,
                            metrics.send_stash_bytes_total,
                            metrics.streams_discarding,
                            metrics.streams_close_after_flush,
                            metrics.multi_stream,
                            flow_blocked,
                            has_ready_stream,
                            send_backlog
                        );
                        last_flow_block_log_at = loop_time;
                    }
                }
            }

            let payload_override = slot.payload_override.as_deref();
            let (payload, rcode) = if let Some(payload) = payload_override {
                (Some(payload), slot.rcode)
            } else if send_length > 0 {
                (Some(&send_buf[..send_length]), slot.rcode)
            } else if slot.rcode.is_none() {
                // No QUIC payload ready; still answer the poll with NOERROR and empty payload to clear it.
                (None, Some(slipstream_dns::Rcode::Ok))
            } else {
                (None, slot.rcode)
            };
            let response = encode_response(&ResponseParams {
                id: slot.id,
                rd: slot.rd,
                cd: slot.cd,
                question: &slot.question,
                payload,
                rcode,
            })
            .map_err(|err| ServerError::new(err.to_string()))?;
            let peer = if map_ipv4_peers {
                normalize_dual_stack_addr(slot.peer)
            } else {
                slot.peer
            };
            if let Err(err) = udp.send_to(&response, peer).await {
                if !is_transient_udp_error(&err) {
                    return Err(map_io(err));
                }
            }
        }
    }

    Ok(0)
}

async fn bind_udp_socket(host: &str, port: u16) -> Result<TokioUdpSocket, ServerError> {
    let addrs: Vec<SocketAddr> = lookup_host((host, port)).await.map_err(map_io)?.collect();
    if addrs.is_empty() {
        return Err(ServerError::new(format!(
            "No addresses resolved for {}:{}",
            host, port
        )));
    }
    let mut last_err = None;
    for addr in addrs {
        match bind_udp_socket_addr(addr) {
            Ok(socket) => return Ok(socket),
            Err(err) => last_err = Some(err),
        }
    }
    Err(last_err.unwrap_or_else(|| {
        ServerError::new(format!("Failed to bind UDP socket on {}:{}", host, port))
    }))
}

fn bind_udp_socket_addr(addr: SocketAddr) -> Result<TokioUdpSocket, ServerError> {
    let domain = match addr {
        SocketAddr::V4(_) => Domain::IPV4,
        SocketAddr::V6(_) => Domain::IPV6,
    };
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP)).map_err(map_io)?;
    if let SocketAddr::V6(_) = addr {
        if let Err(err) = socket.set_only_v6(false) {
            tracing::warn!(
                "Failed to enable dual-stack UDP listener on {}: {}",
                addr,
                err
            );
        }
    }
    let sock_addr = SockAddr::from(addr);
    socket.bind(&sock_addr).map_err(map_io)?;
    socket.set_nonblocking(true).map_err(map_io)?;
    let std_socket: std::net::UdpSocket = socket.into();
    TokioUdpSocket::from_std(std_socket).map_err(map_io)
}

pub(crate) fn map_io(err: std::io::Error) -> ServerError {
    ServerError::new(err.to_string())
}

fn note_active_connections(last_seen: &mut HashMap<usize, Instant>, slots: &[Slot], now: Instant) {
    for slot in slots {
        if !slot.cnx.is_null() {
            last_seen.insert(slot.cnx as usize, now);
        }
    }
}

fn collect_active_connections(quic: *mut picoquic_quic_t) -> HashMap<usize, *mut picoquic_cnx_t> {
    let mut active = HashMap::new();
    let mut cnx = unsafe { picoquic_get_first_cnx(quic) };
    while !cnx.is_null() {
        active.insert(cnx as usize, cnx);
        cnx = unsafe { picoquic_get_next_cnx(cnx) };
    }
    active
}

fn prune_and_collect_idle<T>(
    last_seen: &mut HashMap<usize, Instant>,
    active: &HashMap<usize, T>,
    idle_timeout: Duration,
    now: Instant,
) -> Vec<usize> {
    last_seen.retain(|cnx_id, _| active.contains_key(cnx_id));
    let mut idle = Vec::new();
    for (cnx_id, last) in last_seen.iter() {
        if now.duration_since(*last) >= idle_timeout {
            idle.push(*cnx_id);
        }
    }
    idle
}

fn maybe_gc_idle_connections(
    quic: *mut picoquic_quic_t,
    state_ptr: *mut ServerState,
    last_seen: &mut HashMap<usize, Instant>,
    idle_timeout: Duration,
    last_gc: &mut Instant,
    now: Instant,
) {
    if last_seen.is_empty() {
        return;
    }
    if now.duration_since(*last_gc) < IDLE_GC_INTERVAL {
        return;
    }

    let active = collect_active_connections(quic);
    if active.is_empty() {
        last_seen.clear();
        *last_gc = now;
        return;
    }

    if last_seen.is_empty() {
        *last_gc = now;
        return;
    }

    let idle = prune_and_collect_idle(last_seen, &active, idle_timeout, now);

    if idle.is_empty() {
        *last_gc = now;
        return;
    }

    let state = unsafe { &mut *state_ptr };
    for cnx_id in idle {
        if let Some(&cnx) = active.get(&cnx_id) {
            remove_connection_streams(state, cnx_id);
            if let Some(last) = last_seen.get(&cnx_id) {
                tracing::debug!(
                    "idle gc: closing connection cnx_id={} idle_for_ms={}",
                    cnx_id,
                    now.duration_since(*last).as_millis()
                );
            }
            unsafe {
                picoquic_delete_cnx(cnx);
            }
            last_seen.remove(&cnx_id);
        }
    }
    *last_gc = now;
}

fn warn_overlapping_domains(domains: &[String]) {
    if domains.len() < 2 {
        return;
    }

    let trimmed: Vec<String> = domains
        .iter()
        .map(|domain| domain.trim_end_matches('.').to_ascii_lowercase())
        .collect();

    for i in 0..trimmed.len() {
        for j in (i + 1)..trimmed.len() {
            let left = &trimmed[i];
            let right = &trimmed[j];

            if left == right {
                tracing::warn!(
                    "Duplicate domain configured: '{}' and '{}'",
                    domains[i],
                    domains[j]
                );
                continue;
            }

            if is_label_suffix(left, right) || is_label_suffix(right, left) {
                tracing::warn!(
                    "Configured domains overlap; longest suffix wins: '{}' and '{}'",
                    domains[i],
                    domains[j]
                );
            }
        }
    }
}

fn is_label_suffix(domain: &str, suffix: &str) -> bool {
    if domain.len() <= suffix.len() {
        return false;
    }
    if !domain.ends_with(suffix) {
        return false;
    }
    domain.as_bytes()[domain.len() - suffix.len() - 1] == b'.'
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prune_and_collect_idle_prunes_and_collects() {
        let now = Instant::now();
        let idle_timeout = Duration::from_secs(10);
        let mut last_seen = HashMap::new();
        last_seen.insert(1, now - Duration::from_secs(11));
        last_seen.insert(2, now - Duration::from_secs(5));
        last_seen.insert(3, now - Duration::from_secs(12));

        let mut active = HashMap::new();
        active.insert(1, ());
        active.insert(2, ());

        let mut idle = prune_and_collect_idle(&mut last_seen, &active, idle_timeout, now);
        idle.sort_unstable();

        assert_eq!(idle, vec![1]);
        assert!(last_seen.contains_key(&1));
        assert!(last_seen.contains_key(&2));
        assert!(!last_seen.contains_key(&3));
    }
}
