#[cfg(feature = "openssl-vendored")]
#[allow(unused_imports)]
use openssl_sys as _;
use slipstream_core::HostPort;

pub mod picoquic;
pub mod runtime;

pub use picoquic::get_pacing_rate;
pub use picoquic::get_rtt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum ResolverMode {
    Recursive = 1,
    Authoritative = 2,
}

#[derive(Debug, Clone)]
pub struct ResolverSpec {
    pub resolver: HostPort,
    pub mode: ResolverMode,
}

#[derive(Debug)]
pub struct ClientConfig<'a> {
    pub tcp_listen_host: &'a str,
    pub tcp_listen_port: u16,
    pub resolvers: &'a [ResolverSpec],
    pub domain: &'a str,
    pub cert: Option<&'a str>,
    pub congestion_control: Option<&'a str>,
    pub gso: bool,
    pub keep_alive_interval: usize,
    pub debug_poll: bool,
    pub debug_streams: bool,
    pub idle_poll_interval_ms: u64,
}

pub use runtime::{
    abort_stream_bidi, configure_quic, configure_quic_with_custom, sockaddr_storage_to_socket_addr,
    socket_addr_to_storage, take_crypto_errors, take_stateless_packet_for_cid,
    write_stream_or_reset, QuicGuard, SLIPSTREAM_FILE_CANCEL_ERROR, SLIPSTREAM_INTERNAL_ERROR,
};
