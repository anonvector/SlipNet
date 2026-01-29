use crate::error::ClientError;
use crate::pacing::{PacingBudgetSnapshot, PacingPollBudget};
use slipstream_core::{normalize_dual_stack_addr, resolve_host_port};
use slipstream_ffi::{socket_addr_to_storage, ResolverMode, ResolverSpec};
use std::collections::HashMap;
use std::net::SocketAddr;
use tracing::warn;

use super::debug::DebugMetrics;

pub(crate) struct ResolverState {
    pub(crate) addr: SocketAddr,
    pub(crate) storage: libc::sockaddr_storage,
    pub(crate) local_addr_storage: Option<libc::sockaddr_storage>,
    pub(crate) mode: ResolverMode,
    pub(crate) added: bool,
    pub(crate) path_id: libc::c_int,
    pub(crate) unique_path_id: Option<u64>,
    pub(crate) probe_attempts: u32,
    pub(crate) next_probe_at: u64,
    pub(crate) pending_polls: usize,
    pub(crate) inflight_poll_ids: HashMap<u16, u64>,
    pub(crate) pacing_budget: Option<PacingPollBudget>,
    pub(crate) last_pacing_snapshot: Option<PacingBudgetSnapshot>,
    pub(crate) debug: DebugMetrics,
}

impl ResolverState {
    pub(crate) fn label(&self) -> String {
        format!(
            "path_id={} unique_id={:?} resolver={} mode={:?}",
            self.path_id, self.unique_path_id, self.addr, self.mode
        )
    }
}

pub(crate) fn resolve_resolvers(
    resolvers: &[ResolverSpec],
    mtu: u32,
    debug_poll: bool,
) -> Result<Vec<ResolverState>, ClientError> {
    let mut resolved = Vec::with_capacity(resolvers.len());
    let mut seen = HashMap::new();
    for (idx, resolver) in resolvers.iter().enumerate() {
        let addr = resolve_host_port(&resolver.resolver)
            .map_err(|err| ClientError::new(err.to_string()))?;
        let addr = normalize_dual_stack_addr(addr);
        if let Some(existing_mode) = seen.get(&addr) {
            return Err(ClientError::new(format!(
                "Duplicate resolver address {} (modes: {:?} and {:?})",
                addr, existing_mode, resolver.mode
            )));
        }
        seen.insert(addr, resolver.mode);
        let is_primary = idx == 0;
        resolved.push(ResolverState {
            addr,
            storage: socket_addr_to_storage(addr),
            local_addr_storage: None,
            mode: resolver.mode,
            added: is_primary,
            path_id: if is_primary { 0 } else { -1 },
            unique_path_id: if is_primary { Some(0) } else { None },
            probe_attempts: 0,
            next_probe_at: 0,
            pending_polls: 0,
            inflight_poll_ids: HashMap::new(),
            pacing_budget: match resolver.mode {
                ResolverMode::Authoritative => Some(PacingPollBudget::new(mtu)),
                ResolverMode::Recursive => None,
            },
            last_pacing_snapshot: None,
            debug: DebugMetrics::new(debug_poll),
        });
    }
    Ok(resolved)
}

pub(crate) fn reset_resolver_path(resolver: &mut ResolverState) {
    warn!(
        "Path for resolver {} became unavailable; resetting state",
        resolver.addr
    );
    resolver.added = false;
    resolver.path_id = -1;
    resolver.unique_path_id = None;
    resolver.local_addr_storage = None;
    resolver.pending_polls = 0;
    resolver.inflight_poll_ids.clear();
    resolver.last_pacing_snapshot = None;
    resolver.probe_attempts = 0;
    resolver.next_probe_at = 0;
}

pub(crate) fn sockaddr_storage_to_socket_addr(
    storage: &libc::sockaddr_storage,
) -> Result<SocketAddr, ClientError> {
    slipstream_ffi::sockaddr_storage_to_socket_addr(storage).map_err(ClientError::new)
}

#[cfg(test)]
mod tests {
    use super::resolve_resolvers;
    use slipstream_core::{AddressFamily, HostPort};
    use slipstream_ffi::{ResolverMode, ResolverSpec};

    #[test]
    fn rejects_duplicate_resolver_addr() {
        let resolvers = vec![
            ResolverSpec {
                resolver: HostPort {
                    host: "127.0.0.1".to_string(),
                    port: 8853,
                    family: AddressFamily::V4,
                },
                mode: ResolverMode::Recursive,
            },
            ResolverSpec {
                resolver: HostPort {
                    host: "127.0.0.1".to_string(),
                    port: 8853,
                    family: AddressFamily::V4,
                },
                mode: ResolverMode::Authoritative,
            },
        ];

        match resolve_resolvers(&resolvers, 900, false) {
            Ok(_) => panic!("expected duplicate resolver error"),
            Err(err) => assert!(err.to_string().contains("Duplicate resolver address")),
        }
    }
}
