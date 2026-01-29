use std::fmt;

pub mod flow_control;
pub mod invariants;
mod macros;
pub mod net;
pub mod sip003;
pub mod stream;
pub mod tcp;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, ToSocketAddrs};

#[cfg(feature = "test-support")]
#[doc(hidden)]
pub mod test_support;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressFamily {
    V4,
    V6,
}

#[derive(Debug, Clone)]
pub struct HostPort {
    pub host: String,
    pub port: u16,
    pub family: AddressFamily,
}

#[derive(Debug, Clone)]
pub struct ConfigError {
    message: String,
}

impl ConfigError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for ConfigError {}

#[derive(Debug, Clone, Copy)]
pub enum AddressKind {
    Resolver,
    Target,
    Fallback,
}

impl AddressKind {
    fn label(self) -> &'static str {
        match self {
            AddressKind::Resolver => "resolver",
            AddressKind::Target => "target",
            AddressKind::Fallback => "fallback",
        }
    }
}

pub fn normalize_domain(input: &str) -> Result<String, ConfigError> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(ConfigError::new("Domain must not be empty"));
    }
    let without_dot = trimmed.trim_end_matches('.');
    if without_dot.is_empty() {
        return Err(ConfigError::new("Domain must not be empty"));
    }
    Ok(without_dot.to_string())
}

pub fn parse_resolver_addresses(addrs: &[String]) -> Result<Vec<HostPort>, ConfigError> {
    let mut parsed = Vec::with_capacity(addrs.len());

    for addr in addrs {
        let parsed_addr = parse_host_port(addr, 53, AddressKind::Resolver)?;
        parsed.push(parsed_addr);
    }

    Ok(parsed)
}

pub fn parse_host_port(
    input: &str,
    default_port: u16,
    kind: AddressKind,
) -> Result<HostPort, ConfigError> {
    if let Some(rest) = input.strip_prefix('[') {
        let Some(end) = rest.find(']') else {
            return Err(ConfigError::new(format!(
                "Invalid IPv6 address format (missing closing bracket): {}",
                input
            )));
        };

        let host = &rest[..end];
        if host.is_empty() {
            return Err(ConfigError::new(format!(
                "Invalid IPv6 address in {}: {}",
                kind.label(),
                input
            )));
        }

        let remainder = &rest[end + 1..];
        let port = if remainder.is_empty() {
            default_port
        } else if let Some(port_str) = remainder.strip_prefix(':') {
            parse_port(port_str, input, kind)?
        } else {
            return Err(ConfigError::new(format!(
                "Invalid IPv6 address format (missing closing bracket): {}",
                input
            )));
        };

        return Ok(HostPort {
            host: host.to_string(),
            port,
            family: AddressFamily::V6,
        });
    }

    let mut host = input;
    let mut port = default_port;
    if let Some((left, right)) = input.split_once(':') {
        if right.is_empty() {
            return Err(ConfigError::new(format!(
                "Invalid port number in {} address: {}",
                kind.label(),
                input
            )));
        }
        if right.chars().all(|c| c.is_ascii_digit()) {
            host = left;
            port = parse_port(right, input, kind)?;
        } else {
            return Err(ConfigError::new(format!(
                "Invalid port number in {} address: {}",
                kind.label(),
                input
            )));
        }
    }

    if host.is_empty() {
        return Err(ConfigError::new(format!(
            "Invalid {} address: {}",
            kind.label(),
            input
        )));
    }

    Ok(HostPort {
        host: host.to_string(),
        port,
        family: AddressFamily::V4,
    })
}

pub fn parse_host_port_parts(
    host: &str,
    port: u16,
    kind: AddressKind,
) -> Result<HostPort, ConfigError> {
    let trimmed = host.trim();
    if trimmed.is_empty() {
        return Err(ConfigError::new(format!(
            "Invalid {} address: {}",
            kind.label(),
            host
        )));
    }

    let family = if trimmed.parse::<Ipv4Addr>().is_ok() {
        AddressFamily::V4
    } else if trimmed.parse::<Ipv6Addr>().is_ok() {
        AddressFamily::V6
    } else if trimmed.contains(':') {
        return Err(ConfigError::new(format!(
            "Invalid {} address: {}",
            kind.label(),
            host
        )));
    } else {
        AddressFamily::V4
    };

    Ok(HostPort {
        host: trimmed.to_string(),
        port,
        family,
    })
}

pub fn resolve_host_port(address: &HostPort) -> Result<SocketAddr, ConfigError> {
    match address.family {
        AddressFamily::V4 => {
            if let Ok(ip) = address.host.parse::<Ipv4Addr>() {
                return Ok(SocketAddr::V4(SocketAddrV4::new(ip, address.port)));
            }
        }
        AddressFamily::V6 => {
            if let Ok(ip) = address.host.parse::<Ipv6Addr>() {
                return Ok(SocketAddr::V6(SocketAddrV6::new(ip, address.port, 0, 0)));
            }
        }
    }

    let addr_str = match address.family {
        AddressFamily::V4 => format!("{}:{}", address.host, address.port),
        AddressFamily::V6 => format!("[{}]:{}", address.host, address.port),
    };
    let addrs = addr_str
        .to_socket_addrs()
        .map_err(|_| ConfigError::new(format!("Cannot resolve {}", address.host)))?;

    for addr in addrs {
        match (address.family, addr) {
            (AddressFamily::V4, SocketAddr::V4(_)) => return Ok(addr),
            (AddressFamily::V6, SocketAddr::V6(_)) => return Ok(addr),
            _ => {}
        }
    }

    Err(ConfigError::new(format!(
        "No {} address found for {}",
        match address.family {
            AddressFamily::V4 => "IPv4",
            AddressFamily::V6 => "IPv6",
        },
        address.host
    )))
}

pub fn normalize_dual_stack_addr(addr: SocketAddr) -> SocketAddr {
    match addr {
        SocketAddr::V4(v4) => {
            SocketAddr::V6(SocketAddrV6::new(v4.ip().to_ipv6_mapped(), v4.port(), 0, 0))
        }
        SocketAddr::V6(v6) => SocketAddr::V6(v6),
    }
}

fn parse_port(port_str: &str, input: &str, kind: AddressKind) -> Result<u16, ConfigError> {
    let port: u16 = port_str.parse().map_err(|_| {
        ConfigError::new(format!(
            "Invalid port number in {} address: {}",
            kind.label(),
            input
        ))
    })?;
    if port == 0 {
        return Err(ConfigError::new(format!(
            "Invalid port number in {} address: {}",
            kind.label(),
            input
        )));
    }
    Ok(port)
}
