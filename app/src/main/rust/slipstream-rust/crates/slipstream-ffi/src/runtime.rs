use crate::picoquic::{
    picoquic_clear_crypto_errors, picoquic_cnx_t, picoquic_congestion_algorithm_t,
    picoquic_disable_port_blocking, picoquic_explain_crypto_error, picoquic_free, picoquic_quic_t,
    picoquic_reset_stream, picoquic_set_cookie_mode, picoquic_set_default_congestion_algorithm,
    picoquic_set_default_congestion_algorithm_by_name, picoquic_set_default_multipath_option,
    picoquic_set_default_priority, picoquic_set_initial_send_mtu,
    picoquic_set_key_log_file_from_env, picoquic_set_max_data_control, picoquic_set_mtu_max,
    picoquic_set_preemptive_repeat_policy, picoquic_set_stream_data_consumption_mode,
    picoquic_stop_sending, slipstream_take_stateless_packet_for_cid, PICOQUIC_MAX_PACKET_SIZE,
};
use libc::{c_char, c_int, c_ulong, size_t, sockaddr_storage};
use slipstream_core::tcp::stream_write_buffer_bytes;
use std::ffi::CStr;
use std::io::Write;
use std::net::{Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, SocketAddrV4, SocketAddrV6, TcpStream};

pub const SLIPSTREAM_INTERNAL_ERROR: u64 = 0x101;
pub const SLIPSTREAM_FILE_CANCEL_ERROR: u64 = 0x105;

extern "C" {
    fn ERR_error_string_n(e: c_ulong, buf: *mut c_char, len: size_t);
}

pub struct QuicGuard {
    quic: *mut picoquic_quic_t,
}

impl QuicGuard {
    pub fn new(quic: *mut picoquic_quic_t) -> Self {
        Self { quic }
    }
}

impl Drop for QuicGuard {
    fn drop(&mut self) {
        if !self.quic.is_null() {
            // SAFETY: QuicGuard owns the quic pointer returned by picoquic_create.
            unsafe { picoquic_free(self.quic) };
        }
    }
}

/// # Safety
/// Caller must pass valid picoquic pointers and a valid null-terminated congestion
/// control algorithm name.
pub unsafe fn configure_quic(quic: *mut picoquic_quic_t, cc_algo: *const c_char, mtu: u32) {
    configure_quic_common(quic, mtu);
    picoquic_set_default_congestion_algorithm_by_name(quic, cc_algo);
}

/// # Safety
/// Caller must pass valid picoquic pointers and a congestion algorithm pointer
/// that remains valid for the lifetime of the QUIC context.
pub unsafe fn configure_quic_with_custom(
    quic: *mut picoquic_quic_t,
    algo: *mut picoquic_congestion_algorithm_t,
    mtu: u32,
) {
    configure_quic_common(quic, mtu);
    picoquic_set_default_congestion_algorithm(quic, algo);
}

/// Configure shared QUIC defaults.
/// Connection-level `max_data` is still configured. Stream handlers apply a small reserve in
/// single-stream mode, then switch to per-stream caps with STOP_SENDING + discard when multiple
/// streams are active to avoid connection-wide stalls.
///
/// # Safety
/// `quic` must be a valid picoquic context and `mtu` must be non-zero.
unsafe fn configure_quic_common(quic: *mut picoquic_quic_t, mtu: u32) {
    picoquic_set_cookie_mode(quic, 0);
    picoquic_set_default_priority(quic, 2);
    picoquic_set_default_multipath_option(quic, 1);
    picoquic_set_preemptive_repeat_policy(quic, 1);
    picoquic_disable_port_blocking(quic, 1);
    picoquic_set_stream_data_consumption_mode(quic, 1);
    picoquic_set_max_data_control(quic, stream_write_buffer_bytes() as u64);
    picoquic_set_mtu_max(quic, mtu);
    picoquic_set_initial_send_mtu(quic, mtu, mtu);
    picoquic_set_key_log_file_from_env(quic);
}

pub fn take_crypto_errors() -> Vec<String> {
    let mut errors = Vec::new();
    loop {
        let mut file: *const c_char = std::ptr::null();
        let mut line: c_int = 0;
        let code = unsafe { picoquic_explain_crypto_error(&mut file, &mut line) };
        if code == 0 {
            break;
        }
        let mut description = None;
        let mut buffer = vec![0 as c_char; 256];
        unsafe {
            ERR_error_string_n(code as c_ulong, buffer.as_mut_ptr(), buffer.len());
        }
        let text = unsafe { CStr::from_ptr(buffer.as_ptr()) }
            .to_string_lossy()
            .trim()
            .to_string();
        if !text.is_empty() {
            description = Some(text);
        }
        let file = if file.is_null() {
            "?".to_string()
        } else {
            // SAFETY: picoquic supplies a null-terminated error file string.
            unsafe { CStr::from_ptr(file) }
                .to_string_lossy()
                .into_owned()
        };
        if let Some(description) = description {
            errors.push(format!(
                "crypto error {} ({}) at {}:{}",
                code, description, file, line
            ));
        } else {
            errors.push(format!("crypto error {} at {}:{}", code, file, line));
        }
    }
    unsafe {
        picoquic_clear_crypto_errors();
    }
    errors
}

pub fn socket_addr_to_storage(addr: SocketAddr) -> sockaddr_storage {
    match addr {
        SocketAddr::V4(addr) => {
            // SAFETY: sockaddr_storage is plain-old-data; zeroing is valid.
            let mut storage: sockaddr_storage = unsafe { std::mem::zeroed() };
            let sockaddr = libc::sockaddr_in {
                #[cfg(any(
                    target_vendor = "apple",
                    target_os = "freebsd",
                    target_os = "openbsd",
                    target_os = "netbsd",
                    target_os = "dragonfly",
                ))]
                sin_len: std::mem::size_of::<libc::sockaddr_in>() as u8,
                sin_family: libc::AF_INET as libc::sa_family_t,
                sin_port: addr.port().to_be(),
                sin_addr: libc::in_addr {
                    s_addr: u32::from_be_bytes(addr.ip().octets()),
                },
                sin_zero: [0; 8],
            };
            // SAFETY: storage is properly aligned and large enough for sockaddr_in.
            unsafe {
                std::ptr::write(&mut storage as *mut _ as *mut libc::sockaddr_in, sockaddr);
            }
            storage
        }
        SocketAddr::V6(addr) => {
            // SAFETY: sockaddr_storage is plain-old-data; zeroing is valid.
            let mut storage: sockaddr_storage = unsafe { std::mem::zeroed() };
            let sockaddr = libc::sockaddr_in6 {
                #[cfg(any(
                    target_vendor = "apple",
                    target_os = "freebsd",
                    target_os = "openbsd",
                    target_os = "netbsd",
                    target_os = "dragonfly",
                ))]
                sin6_len: std::mem::size_of::<libc::sockaddr_in6>() as u8,
                sin6_family: libc::AF_INET6 as libc::sa_family_t,
                sin6_port: addr.port().to_be(),
                sin6_flowinfo: addr.flowinfo(),
                sin6_addr: libc::in6_addr {
                    s6_addr: addr.ip().octets(),
                },
                sin6_scope_id: addr.scope_id(),
            };
            // SAFETY: storage is properly aligned and large enough for sockaddr_in6.
            unsafe {
                std::ptr::write(&mut storage as *mut _ as *mut libc::sockaddr_in6, sockaddr);
            }
            storage
        }
    }
}

pub fn sockaddr_storage_to_socket_addr(storage: &sockaddr_storage) -> Result<SocketAddr, String> {
    match storage.ss_family as libc::c_int {
        libc::AF_INET => {
            // SAFETY: ss_family identifies an IPv4 sockaddr layout.
            let addr_in: &libc::sockaddr_in =
                unsafe { &*(storage as *const _ as *const libc::sockaddr_in) };
            let ip = Ipv4Addr::from(addr_in.sin_addr.s_addr);
            let port = u16::from_be(addr_in.sin_port);
            Ok(SocketAddr::V4(SocketAddrV4::new(ip, port)))
        }
        libc::AF_INET6 => {
            // SAFETY: ss_family identifies an IPv6 sockaddr layout.
            let addr_in6: &libc::sockaddr_in6 =
                unsafe { &*(storage as *const _ as *const libc::sockaddr_in6) };
            let ip = Ipv6Addr::from(addr_in6.sin6_addr.s6_addr);
            let port = u16::from_be(addr_in6.sin6_port);
            Ok(SocketAddr::V6(SocketAddrV6::new(
                ip,
                port,
                addr_in6.sin6_flowinfo,
                addr_in6.sin6_scope_id,
            )))
        }
        _ => Err("Unsupported sockaddr family".to_string()),
    }
}

/// # Safety
/// Caller must ensure `quic` points to a valid picoquic context for the duration of the call.
pub unsafe fn take_stateless_packet_for_cid(
    quic: *mut picoquic_quic_t,
    packet: &[u8],
) -> Option<Vec<u8>> {
    if quic.is_null() {
        return None;
    }

    let mut buffer = vec![0u8; PICOQUIC_MAX_PACKET_SIZE];
    let mut length: size_t = 0;
    let ret = slipstream_take_stateless_packet_for_cid(
        quic,
        packet.as_ptr(),
        packet.len(),
        buffer.as_mut_ptr(),
        buffer.len(),
        &mut length,
    );
    if ret <= 0 {
        return None;
    }
    buffer.truncate(length as usize);
    Some(buffer)
}

/// # Safety
/// Caller must ensure `cnx` points to a valid picoquic connection.
pub unsafe fn write_stream_or_reset(
    stream: &mut TcpStream,
    data: &[u8],
    cnx: *mut picoquic_cnx_t,
    stream_id: u64,
) -> bool {
    if let Err(err) = stream.write_all(data) {
        let code = if err.kind() == std::io::ErrorKind::BrokenPipe {
            SLIPSTREAM_FILE_CANCEL_ERROR
        } else {
            SLIPSTREAM_INTERNAL_ERROR
        };
        // SAFETY: caller guarantees cnx is a valid picoquic connection.
        unsafe { abort_stream_bidi(cnx, stream_id, code) };
        let _ = stream.shutdown(Shutdown::Both);
        return true;
    }
    false
}

/// # Safety
/// Caller must ensure `cnx` points to a valid picoquic connection.
pub unsafe fn abort_stream_bidi(cnx: *mut picoquic_cnx_t, stream_id: u64, app_error: u64) {
    let _ = picoquic_stop_sending(cnx, stream_id, app_error);
    let _ = picoquic_reset_stream(cnx, stream_id, app_error);
}
