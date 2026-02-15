use crate::error::ClientError;
use slipstream_dns::decode_response;
use slipstream_ffi::picoquic::{
    picoquic_cnx_t, picoquic_current_time, picoquic_incoming_packet_ex, picoquic_quic_t,
    PICOQUIC_PACKET_LOOP_RECV_MAX,
};
use slipstream_ffi::{socket_addr_to_storage, ResolverMode};
use std::net::SocketAddr;

use super::resolver::ResolverState;
use slipstream_core::normalize_dual_stack_addr;

const MAX_POLL_BURST: usize = PICOQUIC_PACKET_LOOP_RECV_MAX;

pub(crate) struct DnsResponseContext<'a> {
    pub(crate) quic: *mut picoquic_quic_t,
    pub(crate) local_addr_storage: &'a libc::sockaddr_storage,
    pub(crate) resolvers: &'a mut [ResolverState],
}

pub(crate) fn handle_dns_response(
    buf: &[u8],
    peer: SocketAddr,
    ctx: &mut DnsResponseContext<'_>,
) -> Result<(), ClientError> {
    let peer = normalize_dual_stack_addr(peer);
    let response_id = dns_response_id(buf);
    if let Some(payload) = decode_response(buf) {
        let resolver_index = ctx
            .resolvers
            .iter()
            .position(|resolver| resolver.addr == peer);
        let mut peer_storage = socket_addr_to_storage(peer);
        let mut local_storage = if let Some(index) = resolver_index {
            ctx.resolvers[index]
                .local_addr_storage
                .as_ref()
                .map(|storage| unsafe { std::ptr::read(storage) })
                .unwrap_or_else(|| unsafe { std::ptr::read(ctx.local_addr_storage) })
        } else {
            unsafe { std::ptr::read(ctx.local_addr_storage) }
        };
        let mut first_cnx: *mut picoquic_cnx_t = std::ptr::null_mut();
        let mut first_path: libc::c_int = -1;
        let current_time = unsafe { picoquic_current_time() };
        let ret = unsafe {
            picoquic_incoming_packet_ex(
                ctx.quic,
                payload.as_ptr() as *mut u8,
                payload.len(),
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
            return Err(ClientError::new("Failed processing inbound QUIC packet"));
        }
        let resolver = if let Some(resolver) = find_resolver_by_path_id(ctx.resolvers, first_path) {
            Some(resolver)
        } else {
            find_resolver_by_addr(ctx.resolvers, peer)
        };
        if let Some(resolver) = resolver {
            if first_path >= 0 && resolver.path_id != first_path {
                resolver.path_id = first_path;
                resolver.added = true;
            }
            resolver.debug.dns_responses = resolver.debug.dns_responses.saturating_add(1);
            if let Some(response_id) = response_id {
                if resolver.mode == ResolverMode::Authoritative {
                    resolver.inflight_poll_ids.remove(&response_id);
                }
            }
            // Both modes: each response triggers a demand-driven poll.
            // For authoritative mode this provides a floor so that the poll
            // rate never drops below the actual response rate, even when BBR's
            // pacing estimate is conservative.
            resolver.pending_polls =
                resolver.pending_polls.saturating_add(1).min(MAX_POLL_BURST);
        }
    } else if let Some(response_id) = response_id {
        if let Some(resolver) = find_resolver_by_addr(ctx.resolvers, peer) {
            resolver.debug.dns_responses = resolver.debug.dns_responses.saturating_add(1);
            if resolver.mode == ResolverMode::Authoritative {
                resolver.inflight_poll_ids.remove(&response_id);
            }
        }
    }
    Ok(())
}

fn find_resolver_by_path_id(
    resolvers: &mut [ResolverState],
    path_id: libc::c_int,
) -> Option<&mut ResolverState> {
    if path_id < 0 {
        return None;
    }
    resolvers
        .iter_mut()
        .find(|resolver| resolver.added && resolver.path_id == path_id)
}

fn find_resolver_by_addr(
    resolvers: &mut [ResolverState],
    peer: SocketAddr,
) -> Option<&mut ResolverState> {
    let peer = normalize_dual_stack_addr(peer);
    resolvers.iter_mut().find(|resolver| resolver.addr == peer)
}

fn dns_response_id(packet: &[u8]) -> Option<u16> {
    if packet.len() < 12 {
        return None;
    }
    let id = u16::from_be_bytes([packet[0], packet[1]]);
    let flags = u16::from_be_bytes([packet[2], packet[3]]);
    if flags & 0x8000 == 0 {
        return None;
    }
    Some(id)
}
