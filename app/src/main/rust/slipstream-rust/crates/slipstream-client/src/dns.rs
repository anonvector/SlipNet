mod debug;
mod path;
mod poll;
mod resolver;
mod response;

pub(crate) use debug::maybe_report_debug;
pub(crate) use path::{add_paths, refresh_resolver_path, resolver_mode_to_c};
pub(crate) use poll::{expire_inflight_polls, send_poll_queries};
pub(crate) use resolver::{
    reset_resolver_path, resolve_resolvers, sockaddr_storage_to_socket_addr, ResolverState,
};
pub(crate) use response::{handle_dns_response, DnsResponseContext};
