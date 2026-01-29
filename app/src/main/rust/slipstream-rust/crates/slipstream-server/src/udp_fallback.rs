use slipstream_core::{net::is_transient_udp_error, normalize_dual_stack_addr};
use slipstream_dns::{decode_query_with_domains, DecodeQueryError};
use slipstream_ffi::picoquic::{
    picoquic_cnx_t, picoquic_incoming_packet_ex, picoquic_quic_t, slipstream_disable_ack_delay,
};
use slipstream_ffi::{socket_addr_to_storage, take_stateless_packet_for_cid};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::net::UdpSocket as TokioUdpSocket;
use tokio::sync::watch;
use tokio::task::JoinHandle;

use crate::server::{map_io, ServerError, Slot};

pub(crate) const MAX_UDP_PACKET_SIZE: usize = 65535;
const FALLBACK_IDLE_TIMEOUT: Duration = Duration::from_secs(180);
const FALLBACK_CLEANUP_INTERVAL: Duration = Duration::from_secs(30);
const NON_DNS_STREAK_THRESHOLD: usize = 16;

enum DecodeSlotOutcome {
    Slot(Slot),
    DnsOnly,
    Drop,
}

struct FallbackSession {
    socket: Arc<TokioUdpSocket>,
    last_seen: Arc<Mutex<Instant>>,
    shutdown_tx: watch::Sender<bool>,
    reply_task: JoinHandle<()>,
}

struct DnsPeerState {
    last_seen: Instant,
    non_dns_streak: usize,
}

pub(crate) struct PacketContext<'a> {
    pub(crate) domains: &'a [&'a str],
    pub(crate) quic: *mut picoquic_quic_t,
    pub(crate) current_time: u64,
    pub(crate) local_addr_storage: &'a libc::sockaddr_storage,
}

/// Tracks per-peer routing for UDP fallback based on DNS decoding outcomes.
///
/// The first packet sets the initial classification:
/// - Packets that decode as DNS (including DNS error replies we generate) mark the peer as DNS-only.
/// - Packets that fail DNS decoding are forwarded to fallback and create a fallback session.
///
/// For DNS-only peers, a streak of non-DNS packets can switch the peer to fallback once it
/// reaches the non-DNS streak threshold. Classification is per source address and expires after
/// idle timeout.
pub(crate) struct FallbackManager {
    fallback_addr: SocketAddr,
    main_socket: Arc<TokioUdpSocket>,
    map_ipv4_peers: bool,
    dns_peers: HashMap<SocketAddr, DnsPeerState>,
    sessions: HashMap<SocketAddr, FallbackSession>,
    last_cleanup: Instant,
}

impl FallbackManager {
    pub(crate) fn new(
        main_socket: Arc<TokioUdpSocket>,
        fallback_addr: SocketAddr,
        map_ipv4_peers: bool,
    ) -> Self {
        tracing::info!("non-DNS packets will be forwarded to {}", fallback_addr);
        Self {
            fallback_addr,
            main_socket,
            map_ipv4_peers,
            dns_peers: HashMap::new(),
            sessions: HashMap::new(),
            last_cleanup: Instant::now(),
        }
    }

    pub(crate) fn cleanup(&mut self) {
        let now = Instant::now();
        if now.duration_since(self.last_cleanup) < FALLBACK_CLEANUP_INTERVAL {
            return;
        }
        self.last_cleanup = now;

        self.dns_peers
            .retain(|_, state| now.duration_since(state.last_seen) <= FALLBACK_IDLE_TIMEOUT);

        let mut expired = Vec::new();
        for (peer, session) in &self.sessions {
            let last_seen = match session.last_seen.lock() {
                Ok(last_seen) => *last_seen,
                Err(_) => {
                    tracing::warn!(
                        "fallback session for {} has poisoned mutex, marking for cleanup",
                        peer
                    );
                    expired.push(*peer);
                    continue;
                }
            };
            if now.duration_since(last_seen) > FALLBACK_IDLE_TIMEOUT {
                expired.push(*peer);
            }
        }

        for peer in expired {
            self.end_session(peer);
        }
    }

    fn end_session(&mut self, peer: SocketAddr) {
        if let Some(session) = self.sessions.remove(&peer) {
            let _ = session.shutdown_tx.send(true);
            tracing::debug!("ending fallback session for {}", peer);
        }
    }

    fn mark_dns(&mut self, peer: SocketAddr) {
        let now = Instant::now();
        self.dns_peers
            .entry(peer)
            .and_modify(|state| {
                state.last_seen = now;
                state.non_dns_streak = 0;
            })
            .or_insert(DnsPeerState {
                last_seen: now,
                non_dns_streak: 0,
            });
    }

    fn is_active_fallback_peer(&mut self, peer: SocketAddr) -> bool {
        let mut should_end = false;
        let last_seen = match self.sessions.get(&peer) {
            Some(session) => match session.last_seen.lock() {
                Ok(last_seen) => *last_seen,
                Err(_) => {
                    tracing::warn!(
                        "fallback session for {} has poisoned mutex, marking for cleanup",
                        peer
                    );
                    should_end = true;
                    Instant::now()
                }
            },
            None => return false,
        };

        if should_end {
            self.end_session(peer);
            return false;
        }

        let now = Instant::now();
        if now.duration_since(last_seen) > FALLBACK_IDLE_TIMEOUT {
            self.end_session(peer);
            return false;
        }

        true
    }

    async fn forward_existing(&mut self, packet: &[u8], peer: SocketAddr) {
        self.forward_packet(packet, peer).await;
    }

    async fn handle_non_dns(&mut self, packet: &[u8], peer: SocketAddr) {
        let mut should_forward = true;
        let mut should_remove = false;
        if let Some(state) = self.dns_peers.get_mut(&peer) {
            state.non_dns_streak = state.non_dns_streak.saturating_add(1);
            if state.non_dns_streak < NON_DNS_STREAK_THRESHOLD {
                should_forward = false;
            } else {
                should_remove = true;
            }
        }
        if should_remove {
            self.dns_peers.remove(&peer);
        }
        if !should_forward {
            return;
        }
        self.forward_packet(packet, peer).await;
    }

    async fn forward_packet(&mut self, packet: &[u8], peer: SocketAddr) {
        let socket = match self.ensure_session(peer).await {
            Some(socket) => socket,
            None => return,
        };
        if let Err(err) = socket.send(packet).await {
            if !is_transient_udp_error(&err) {
                tracing::warn!(
                    "fallback write to {} for client {} failed: {}",
                    self.fallback_addr,
                    peer,
                    err
                );
            }
        }
    }

    async fn ensure_session(&mut self, peer: SocketAddr) -> Option<Arc<TokioUdpSocket>> {
        let reset_session = self
            .sessions
            .get(&peer)
            .map(|session| session.reply_task.is_finished())
            .unwrap_or(false);
        if reset_session {
            self.sessions.remove(&peer);
            tracing::debug!("fallback reply loop ended for {}; recreating session", peer);
        }
        if !self.sessions.contains_key(&peer) {
            if let Err(err) = self.create_session(peer).await {
                tracing::warn!("failed to create fallback session for {}: {}", peer, err);
                return None;
            }
        }

        let socket = if let Some(session) = self.sessions.get_mut(&peer) {
            if let Ok(mut last_seen) = session.last_seen.lock() {
                *last_seen = Instant::now();
            }
            session.socket.clone()
        } else {
            return None;
        };

        Some(socket)
    }

    async fn create_session(&mut self, peer: SocketAddr) -> Result<(), ServerError> {
        let bind_addr = fallback_bind_addr(self.fallback_addr);
        let socket = TokioUdpSocket::bind(bind_addr).await.map_err(map_io)?;
        socket.connect(self.fallback_addr).await.map_err(map_io)?;
        let socket = Arc::new(socket);
        let last_seen = Arc::new(Mutex::new(Instant::now()));
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let proxy_socket = socket.clone();
        let main_socket = self.main_socket.clone();
        let last_seen_update = last_seen.clone();
        let map_ipv4_peers = self.map_ipv4_peers;
        let reply_task = tokio::spawn(async move {
            forward_fallback_replies(
                proxy_socket,
                main_socket,
                peer,
                map_ipv4_peers,
                last_seen_update,
                shutdown_rx,
            )
            .await;
        });
        self.sessions.insert(
            peer,
            FallbackSession {
                socket,
                last_seen,
                shutdown_tx,
                reply_task,
            },
        );
        tracing::debug!("created fallback session for {}", peer);
        Ok(())
    }
}

pub(crate) async fn handle_packet(
    slots: &mut Vec<Slot>,
    packet: &[u8],
    peer: SocketAddr,
    context: &PacketContext<'_>,
    fallback_mgr: &mut Option<FallbackManager>,
) -> Result<(), ServerError> {
    if let Some(manager) = fallback_mgr.as_mut() {
        if manager.is_active_fallback_peer(peer) {
            manager.forward_existing(packet, peer).await;
            return Ok(());
        }
    }

    match decode_slot(
        packet,
        peer,
        context.domains,
        context.quic,
        context.current_time,
        context.local_addr_storage,
    )? {
        DecodeSlotOutcome::Slot(slot) => {
            if let Some(manager) = fallback_mgr.as_mut() {
                manager.mark_dns(peer);
            }
            slots.push(slot);
        }
        DecodeSlotOutcome::DnsOnly => {
            if let Some(manager) = fallback_mgr.as_mut() {
                manager.mark_dns(peer);
            }
        }
        DecodeSlotOutcome::Drop => {
            if let Some(manager) = fallback_mgr.as_mut() {
                manager.handle_non_dns(packet, peer).await;
            }
        }
    }

    Ok(())
}

fn decode_slot(
    packet: &[u8],
    peer: SocketAddr,
    domains: &[&str],
    quic: *mut picoquic_quic_t,
    current_time: u64,
    local_addr_storage: &libc::sockaddr_storage,
) -> Result<DecodeSlotOutcome, ServerError> {
    match decode_query_with_domains(packet, domains) {
        Ok(query) => {
            let mut peer_storage = dummy_sockaddr_storage();
            let mut local_storage = unsafe { std::ptr::read(local_addr_storage) };
            let mut first_cnx: *mut picoquic_cnx_t = std::ptr::null_mut();
            let mut first_path: libc::c_int = -1;
            let ret = unsafe {
                picoquic_incoming_packet_ex(
                    quic,
                    query.payload.as_ptr() as *mut u8,
                    query.payload.len(),
                    &mut peer_storage as *mut _ as *mut libc::sockaddr,
                    &mut local_storage as *mut _ as *mut libc::sockaddr,
                    0,
                    0,
                    &mut first_cnx,
                    &mut first_path,
                    current_time,
                )
            };
            if ret < 0 {
                return Err(ServerError::new("Failed to process QUIC packet"));
            }
            if first_cnx.is_null() {
                if let Some(payload) =
                    unsafe { take_stateless_packet_for_cid(quic, &query.payload) }
                {
                    if !payload.is_empty() {
                        return Ok(DecodeSlotOutcome::Slot(Slot {
                            peer,
                            id: query.id,
                            rd: query.rd,
                            cd: query.cd,
                            question: query.question,
                            rcode: None,
                            cnx: std::ptr::null_mut(),
                            path_id: -1,
                            payload_override: Some(payload),
                        }));
                    }
                }
                return Ok(DecodeSlotOutcome::DnsOnly);
            }
            unsafe {
                slipstream_disable_ack_delay(first_cnx);
            }
            Ok(DecodeSlotOutcome::Slot(Slot {
                peer,
                id: query.id,
                rd: query.rd,
                cd: query.cd,
                question: query.question,
                rcode: None,
                cnx: first_cnx,
                path_id: first_path,
                payload_override: None,
            }))
        }
        Err(DecodeQueryError::Drop) => Ok(DecodeSlotOutcome::Drop),
        Err(DecodeQueryError::Reply {
            id,
            rd,
            cd,
            question,
            rcode,
        }) => {
            let Some(question) = question else {
                // Treat empty-question queries (QDCOUNT=0) as non-DNS for fallback.
                return Ok(DecodeSlotOutcome::Drop);
            };
            Ok(DecodeSlotOutcome::Slot(Slot {
                peer,
                id,
                rd,
                cd,
                question,
                rcode: Some(rcode),
                cnx: std::ptr::null_mut(),
                path_id: -1,
                payload_override: None,
            }))
        }
    }
}

fn fallback_bind_addr(fallback_addr: SocketAddr) -> SocketAddr {
    match fallback_addr {
        SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        SocketAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
    }
}

async fn forward_fallback_replies(
    proxy_socket: Arc<TokioUdpSocket>,
    main_socket: Arc<TokioUdpSocket>,
    client_addr: SocketAddr,
    map_ipv4_peers: bool,
    last_seen: Arc<Mutex<Instant>>,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    let client_send_addr = if map_ipv4_peers {
        normalize_dual_stack_addr(client_addr)
    } else {
        client_addr
    };
    let mut buf = vec![0u8; MAX_UDP_PACKET_SIZE];
    loop {
        tokio::select! {
            recv = proxy_socket.recv(&mut buf) => {
                match recv {
                    Ok(size) => {
                        if let Ok(mut last_seen) = last_seen.lock() {
                            *last_seen = Instant::now();
                        }
                        if let Err(err) = main_socket.send_to(&buf[..size], client_send_addr).await {
                            if !is_transient_udp_error(&err) {
                                tracing::warn!(
                                    "fallback write to client {} failed: {}",
                                    client_addr,
                                    err
                                );
                            }
                        }
                    }
                    Err(err) => {
                        if is_transient_udp_error(&err) {
                            continue;
                        }
                        tracing::warn!(
                            "fallback read for client {} failed: {}",
                            client_addr,
                            err
                        );
                        break;
                    }
                }
            }
            changed = shutdown_rx.changed() => {
                if changed.is_err() || *shutdown_rx.borrow() {
                    break;
                }
            }
        }
    }
}

fn dummy_sockaddr_storage() -> libc::sockaddr_storage {
    socket_addr_to_storage(SocketAddr::new(
        IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
        12345,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use slipstream_dns::{encode_query, QueryParams, CLASS_IN, RR_A};
    use tokio::sync::mpsc;
    use tokio::time::{timeout, Duration};

    fn build_dns_query(name: &str) -> Vec<u8> {
        encode_query(&QueryParams {
            id: 1,
            qname: name,
            qtype: RR_A,
            qclass: CLASS_IN,
            rd: true,
            cd: false,
            qdcount: 1,
            is_query: true,
        })
        .expect("dns query")
    }

    fn spawn_fallback_echo(socket: Arc<TokioUdpSocket>, notify_tx: mpsc::UnboundedSender<Vec<u8>>) {
        tokio::spawn(async move {
            let mut buf = vec![0u8; MAX_UDP_PACKET_SIZE];
            loop {
                let (size, peer) = match socket.recv_from(&mut buf).await {
                    Ok(result) => result,
                    Err(_) => break,
                };
                let payload = buf[..size].to_vec();
                let _ = notify_tx.send(payload.clone());
                let _ = socket.send_to(&payload, peer).await;
            }
        });
    }

    fn build_empty_question_query() -> Vec<u8> {
        let mut out = Vec::with_capacity(12);
        out.extend_from_slice(&1u16.to_be_bytes());
        out.extend_from_slice(&0x0100u16.to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes());
        out
    }

    async fn recv_with_timeout(socket: &TokioUdpSocket, buf: &mut [u8]) -> (usize, SocketAddr) {
        timeout(Duration::from_secs(1), socket.recv_from(buf))
            .await
            .expect("recv timeout")
            .expect("recv failed")
    }

    #[tokio::test]
    async fn fallback_forwards_non_dns_then_sticks() {
        let main_socket = Arc::new(TokioUdpSocket::bind("127.0.0.1:0").await.unwrap());
        let main_addr = main_socket.local_addr().unwrap();
        let client_socket = TokioUdpSocket::bind("127.0.0.1:0").await.unwrap();
        let fallback_socket = Arc::new(TokioUdpSocket::bind("127.0.0.1:0").await.unwrap());
        let fallback_addr = fallback_socket.local_addr().unwrap();
        let (notify_tx, mut notify_rx) = mpsc::unbounded_channel();
        spawn_fallback_echo(fallback_socket, notify_tx);

        let mut fallback_mgr = Some(FallbackManager::new(
            main_socket.clone(),
            fallback_addr,
            false,
        ));
        let domains = vec!["example.com"];
        let local_addr_storage = dummy_sockaddr_storage();
        let context = PacketContext {
            domains: &domains,
            quic: std::ptr::null_mut(),
            current_time: 0,
            local_addr_storage: &local_addr_storage,
        };

        let non_dns = b"nope";
        client_socket.send_to(non_dns, main_addr).await.unwrap();
        let mut recv_buf = [0u8; 64];
        let (size, peer) = recv_with_timeout(&main_socket, &mut recv_buf).await;
        let mut slots = Vec::new();
        handle_packet(
            &mut slots,
            &recv_buf[..size],
            peer,
            &context,
            &mut fallback_mgr,
        )
        .await
        .unwrap();

        let mut client_buf = [0u8; 64];
        let (size, _) = recv_with_timeout(&client_socket, &mut client_buf).await;
        assert_eq!(&client_buf[..size], non_dns);
        let echoed = timeout(Duration::from_secs(1), notify_rx.recv())
            .await
            .expect("fallback receive timeout")
            .expect("fallback receive");
        assert_eq!(echoed, non_dns);

        let dns_packet = build_dns_query("example.com");
        client_socket.send_to(&dns_packet, main_addr).await.unwrap();
        let (size, peer) = recv_with_timeout(&main_socket, &mut recv_buf).await;
        let mut slots = Vec::new();
        handle_packet(
            &mut slots,
            &recv_buf[..size],
            peer,
            &context,
            &mut fallback_mgr,
        )
        .await
        .unwrap();

        let (size, _) = recv_with_timeout(&client_socket, &mut client_buf).await;
        assert_eq!(&client_buf[..size], dns_packet);
        let echoed = timeout(Duration::from_secs(1), notify_rx.recv())
            .await
            .expect("fallback receive timeout")
            .expect("fallback receive");
        assert_eq!(echoed, dns_packet);

        if let Some(manager) = fallback_mgr.as_mut() {
            for session in manager.sessions.values() {
                let _ = session.shutdown_tx.send(true);
            }
        }
    }

    #[tokio::test]
    async fn fallback_forwards_empty_question_query() {
        let main_socket = Arc::new(TokioUdpSocket::bind("127.0.0.1:0").await.unwrap());
        let main_addr = main_socket.local_addr().unwrap();
        let client_socket = TokioUdpSocket::bind("127.0.0.1:0").await.unwrap();
        let fallback_socket = Arc::new(TokioUdpSocket::bind("127.0.0.1:0").await.unwrap());
        let fallback_addr = fallback_socket.local_addr().unwrap();
        let (notify_tx, mut notify_rx) = mpsc::unbounded_channel();
        spawn_fallback_echo(fallback_socket, notify_tx);

        let mut fallback_mgr = Some(FallbackManager::new(
            main_socket.clone(),
            fallback_addr,
            false,
        ));
        let domains = vec!["example.com"];
        let local_addr_storage = dummy_sockaddr_storage();
        let context = PacketContext {
            domains: &domains,
            quic: std::ptr::null_mut(),
            current_time: 0,
            local_addr_storage: &local_addr_storage,
        };

        let qdcount_zero = build_empty_question_query();
        client_socket
            .send_to(&qdcount_zero, main_addr)
            .await
            .unwrap();
        let mut recv_buf = [0u8; 64];
        let (size, peer) = recv_with_timeout(&main_socket, &mut recv_buf).await;
        let mut slots = Vec::new();
        handle_packet(
            &mut slots,
            &recv_buf[..size],
            peer,
            &context,
            &mut fallback_mgr,
        )
        .await
        .unwrap();

        let mut client_buf = [0u8; 64];
        let (size, _) = recv_with_timeout(&client_socket, &mut client_buf).await;
        assert_eq!(&client_buf[..size], qdcount_zero.as_slice());
        let echoed = timeout(Duration::from_secs(1), notify_rx.recv())
            .await
            .expect("fallback receive timeout")
            .expect("fallback receive");
        assert_eq!(echoed, qdcount_zero);

        if let Some(manager) = fallback_mgr.as_mut() {
            for session in manager.sessions.values() {
                let _ = session.shutdown_tx.send(true);
            }
        }
    }

    #[tokio::test]
    async fn fallback_switches_after_non_dns_streak() {
        let main_socket = Arc::new(TokioUdpSocket::bind("127.0.0.1:0").await.unwrap());
        let main_addr = main_socket.local_addr().unwrap();
        let client_socket = TokioUdpSocket::bind("127.0.0.1:0").await.unwrap();
        let fallback_socket = Arc::new(TokioUdpSocket::bind("127.0.0.1:0").await.unwrap());
        let fallback_addr = fallback_socket.local_addr().unwrap();
        let (notify_tx, mut notify_rx) = mpsc::unbounded_channel();
        spawn_fallback_echo(fallback_socket, notify_tx);

        let mut fallback_mgr = Some(FallbackManager::new(
            main_socket.clone(),
            fallback_addr,
            false,
        ));
        let domains = vec!["example.com"];
        let local_addr_storage = dummy_sockaddr_storage();
        let context = PacketContext {
            domains: &domains,
            quic: std::ptr::null_mut(),
            current_time: 0,
            local_addr_storage: &local_addr_storage,
        };

        let dns_packet = build_dns_query("example.com");
        client_socket.send_to(&dns_packet, main_addr).await.unwrap();
        let mut recv_buf = [0u8; 64];
        let (size, peer) = recv_with_timeout(&main_socket, &mut recv_buf).await;
        let mut slots = Vec::new();
        handle_packet(
            &mut slots,
            &recv_buf[..size],
            peer,
            &context,
            &mut fallback_mgr,
        )
        .await
        .unwrap();

        if let Some(manager) = fallback_mgr.as_ref() {
            assert!(manager.dns_peers.contains_key(&peer));
        }

        let non_dns = b"nope";
        for _ in 0..(NON_DNS_STREAK_THRESHOLD - 1) {
            client_socket.send_to(non_dns, main_addr).await.unwrap();
            let (size, peer) = recv_with_timeout(&main_socket, &mut recv_buf).await;
            let mut slots = Vec::new();
            handle_packet(
                &mut slots,
                &recv_buf[..size],
                peer,
                &context,
                &mut fallback_mgr,
            )
            .await
            .unwrap();
        }

        assert!(notify_rx.try_recv().is_err());

        client_socket.send_to(non_dns, main_addr).await.unwrap();
        let (size, peer) = recv_with_timeout(&main_socket, &mut recv_buf).await;
        let mut slots = Vec::new();
        handle_packet(
            &mut slots,
            &recv_buf[..size],
            peer,
            &context,
            &mut fallback_mgr,
        )
        .await
        .unwrap();

        let echoed = timeout(Duration::from_secs(1), notify_rx.recv())
            .await
            .expect("fallback receive timeout")
            .expect("fallback receive");
        assert_eq!(echoed, non_dns);

        if let Some(manager) = fallback_mgr.as_mut() {
            for session in manager.sessions.values() {
                let _ = session.shutdown_tx.send(true);
            }
        }
    }

    #[tokio::test]
    async fn fallback_session_expires_before_forwarding() {
        let main_socket = Arc::new(TokioUdpSocket::bind("127.0.0.1:0").await.unwrap());
        let main_addr = main_socket.local_addr().unwrap();
        let client_socket = TokioUdpSocket::bind("127.0.0.1:0").await.unwrap();
        let fallback_socket = Arc::new(TokioUdpSocket::bind("127.0.0.1:0").await.unwrap());
        let fallback_addr = fallback_socket.local_addr().unwrap();
        let (notify_tx, mut notify_rx) = mpsc::unbounded_channel();
        spawn_fallback_echo(fallback_socket, notify_tx);

        let mut fallback_mgr = Some(FallbackManager::new(
            main_socket.clone(),
            fallback_addr,
            false,
        ));
        let domains = vec!["example.com"];
        let local_addr_storage = dummy_sockaddr_storage();
        let context = PacketContext {
            domains: &domains,
            quic: std::ptr::null_mut(),
            current_time: 0,
            local_addr_storage: &local_addr_storage,
        };

        let non_dns = b"nope";
        client_socket.send_to(non_dns, main_addr).await.unwrap();
        let mut recv_buf = [0u8; 64];
        let (size, peer) = recv_with_timeout(&main_socket, &mut recv_buf).await;
        let mut slots = Vec::new();
        handle_packet(
            &mut slots,
            &recv_buf[..size],
            peer,
            &context,
            &mut fallback_mgr,
        )
        .await
        .unwrap();

        let echoed = timeout(Duration::from_secs(1), notify_rx.recv())
            .await
            .expect("fallback receive timeout")
            .expect("fallback receive");
        assert_eq!(echoed, non_dns);

        if let Some(manager) = fallback_mgr.as_mut() {
            if let Some(session) = manager.sessions.get(&peer) {
                if let Ok(mut last_seen) = session.last_seen.lock() {
                    *last_seen = Instant::now() - FALLBACK_IDLE_TIMEOUT - Duration::from_secs(1);
                }
            }
        }

        let dns_packet = build_dns_query("example.com");
        client_socket.send_to(&dns_packet, main_addr).await.unwrap();
        let (size, peer) = recv_with_timeout(&main_socket, &mut recv_buf).await;
        let mut slots = Vec::new();
        handle_packet(
            &mut slots,
            &recv_buf[..size],
            peer,
            &context,
            &mut fallback_mgr,
        )
        .await
        .unwrap();

        assert!(
            timeout(Duration::from_millis(200), notify_rx.recv())
                .await
                .is_err(),
            "fallback endpoint should not see DNS query after idle"
        );

        if let Some(manager) = fallback_mgr.as_mut() {
            for session in manager.sessions.values() {
                let _ = session.shutdown_tx.send(true);
            }
        }
    }
}
