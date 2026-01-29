#[cfg(unix)]
use std::os::unix::io::AsRawFd;
use std::sync::Once;

pub const STREAM_WRITE_BUFFER_BYTES: usize = 8 * 1024 * 1024;
pub const STREAM_READ_BUFFER_MIN_BYTES: usize = 4 * 1024 * 1024;
pub const STREAM_READ_BUFFER_MAX_BYTES: usize = 16 * 1024 * 1024;

static STREAM_WRITE_BUFFER_INIT: Once = Once::new();
static mut STREAM_WRITE_BUFFER_BYTES_OVERRIDE: usize = STREAM_WRITE_BUFFER_BYTES;

pub fn stream_write_buffer_bytes() -> usize {
    STREAM_WRITE_BUFFER_INIT.call_once(|| {
        let override_bytes = std::env::var("SLIPSTREAM_STREAM_WRITE_BUFFER_BYTES")
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .filter(|value| *value > 0)
            .unwrap_or(STREAM_WRITE_BUFFER_BYTES);
        unsafe {
            STREAM_WRITE_BUFFER_BYTES_OVERRIDE = override_bytes;
        }
    });
    unsafe { STREAM_WRITE_BUFFER_BYTES_OVERRIDE }
}

fn clamp_stream_read_buffer_bytes(bytes: usize) -> usize {
    bytes.clamp(STREAM_READ_BUFFER_MIN_BYTES, STREAM_READ_BUFFER_MAX_BYTES)
}

#[cfg(unix)]
pub fn stream_read_limit_chunks<T: AsRawFd>(
    stream: &T,
    default_buffer_bytes: usize,
    chunk_bytes: usize,
) -> usize {
    let buffer_bytes = tcp_recv_buffer_bytes(stream).unwrap_or(default_buffer_bytes);
    let buffer_bytes = clamp_stream_read_buffer_bytes(buffer_bytes);
    let chunks = buffer_bytes / chunk_bytes;
    if chunks == 0 {
        1
    } else {
        chunks
    }
}

#[cfg(not(unix))]
pub fn stream_read_limit_chunks<T>(
    _stream: &T,
    default_buffer_bytes: usize,
    chunk_bytes: usize,
) -> usize {
    let buffer_bytes = clamp_stream_read_buffer_bytes(default_buffer_bytes);
    let chunks = buffer_bytes / chunk_bytes;
    if chunks == 0 {
        1
    } else {
        chunks
    }
}

pub fn within_stream_buffer(queued_bytes: usize, incoming_len: usize) -> bool {
    queued_bytes.saturating_add(incoming_len) <= stream_write_buffer_bytes()
}

#[cfg(unix)]
pub fn tcp_recv_buffer_bytes<T: AsRawFd>(stream: &T) -> Option<usize> {
    use std::mem::size_of;

    let mut value: libc::c_int = 0;
    let mut len = size_of::<libc::c_int>() as libc::socklen_t;
    let ret = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_RCVBUF,
            &mut value as *mut _ as *mut _,
            &mut len as *mut _,
        )
    };
    if ret == 0 && value > 0 {
        Some(value as usize)
    } else {
        None
    }
}

#[cfg(unix)]
pub fn tcp_send_buffer_bytes<T: AsRawFd>(stream: &T) -> Option<usize> {
    use std::mem::size_of;

    let mut value: libc::c_int = 0;
    let mut len = size_of::<libc::c_int>() as libc::socklen_t;
    let ret = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_SNDBUF,
            &mut value as *mut _ as *mut _,
            &mut len as *mut _,
        )
    };
    if ret == 0 && value > 0 {
        Some(value as usize)
    } else {
        None
    }
}

#[cfg(not(unix))]
pub fn tcp_recv_buffer_bytes<T>(_stream: &T) -> Option<usize> {
    None
}

#[cfg(not(unix))]
pub fn tcp_send_buffer_bytes<T>(_stream: &T) -> Option<usize> {
    None
}

#[cfg(test)]
mod tests {
    use super::{stream_write_buffer_bytes, within_stream_buffer};

    #[test]
    fn stream_buffer_allows_exact_limit() {
        let limit = stream_write_buffer_bytes();
        assert!(within_stream_buffer(0, limit));
        assert!(within_stream_buffer(limit - 1, 1));
    }

    #[test]
    fn stream_buffer_rejects_overflow() {
        let limit = stream_write_buffer_bytes();
        assert!(!within_stream_buffer(limit, 1));
        assert!(!within_stream_buffer(limit - 1, 2));
    }
}
