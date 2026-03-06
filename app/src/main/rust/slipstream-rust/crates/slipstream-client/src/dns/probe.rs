use crate::dns::ResolverState;
use slipstream_core::net::is_transient_udp_error;
use slipstream_dns::{build_qname, encode_query, QueryParams, CLASS_IN, RR_TXT};
use std::time::Duration;
use tokio::net::UdpSocket as TokioUdpSocket;
use tokio::time::sleep;
use tracing::{debug, warn};

/// Default probe timeout in milliseconds.
pub(crate) const PROBE_TIMEOUT_MS: u64 = 2000;

/// Send a lightweight DNS TXT query to every resolver in parallel and return
/// the index of the first one that responds.  If only one resolver is
/// configured the probe is skipped entirely.  Returns `None` when no resolver
/// answers within the timeout (caller should fall back to the current primary).
pub(crate) async fn probe_resolvers(
    udp: &TokioUdpSocket,
    resolvers: &[ResolverState],
    domain: &str,
    timeout_ms: u64,
) -> Option<usize> {
    if resolvers.len() <= 1 {
        return Some(0);
    }

    // Build a minimal DNS TXT query for the bare domain (empty payload).
    let qname = match build_qname(&[], domain) {
        Ok(q) => q,
        Err(err) => {
            warn!("probe: failed to build qname: {}", err);
            return None;
        }
    };

    // Use a high base ID to avoid collisions with the main loop's dns_id
    // which starts at 1 and counts up.  Each resolver gets base + index.
    let base_id: u16 = 0xF000;

    for (idx, resolver) in resolvers.iter().enumerate() {
        let probe_id = base_id.wrapping_add(idx as u16);
        let params = QueryParams {
            id: probe_id,
            qname: &qname,
            qtype: RR_TXT,
            qclass: CLASS_IN,
            rd: true,
            cd: false,
            qdcount: 1,
            is_query: true,
        };
        let packet = match encode_query(&params) {
            Ok(p) => p,
            Err(err) => {
                warn!("probe: failed to encode query for resolver {}: {}", idx, err);
                continue;
            }
        };
        if let Err(err) = udp.send_to(&packet, resolver.addr).await {
            if !is_transient_udp_error(&err) {
                warn!("probe: send_to {} failed: {}", resolver.addr, err);
            }
        }
    }

    debug!(
        "probe: sent queries to {} resolvers, waiting up to {}ms",
        resolvers.len(),
        timeout_ms
    );

    let mut recv_buf = [0u8; 512];
    let deadline = sleep(Duration::from_millis(timeout_ms));
    tokio::pin!(deadline);

    loop {
        tokio::select! {
            result = udp.recv_from(&mut recv_buf) => {
                match result {
                    Ok((size, _peer)) => {
                        // A valid DNS response is at least 12 bytes (header)
                        // and has the QR bit (0x80) set in the flags byte.
                        if size >= 12 && (recv_buf[2] & 0x80) != 0 {
                            let resp_id = u16::from_be_bytes([recv_buf[0], recv_buf[1]]);
                            if resp_id >= base_id && resp_id < base_id.wrapping_add(resolvers.len() as u16) {
                                let idx = (resp_id - base_id) as usize;
                                debug!("probe: resolver {} ({}) responded first", idx, resolvers[idx].addr);
                                return Some(idx);
                            }
                            // Response ID doesn't match our probes — ignore
                            // (could be a stale response from a previous session).
                        }
                    }
                    Err(err) => {
                        if !is_transient_udp_error(&err) {
                            warn!("probe: recv_from error: {}", err);
                            return None;
                        }
                    }
                }
            }
            _ = &mut deadline => {
                debug!("probe: timeout after {}ms, no resolver responded", timeout_ms);
                return None;
            }
        }
    }
}
