use std::env;
use std::ffi::CString;
use std::ptr;

use slipstream_core::tcp::stream_write_buffer_bytes;
use slipstream_ffi::picoquic::{
    picoquic_create, picoquic_current_time, slipstream_test_get_defer_stream_data_consumption,
    slipstream_test_get_max_data_limit,
};
use slipstream_ffi::{configure_quic, QuicGuard};

struct EnvVarGuard {
    key: &'static str,
    original: Option<String>,
}

impl EnvVarGuard {
    fn set(key: &'static str, value: &str) -> Self {
        let original = env::var(key).ok();
        env::set_var(key, value);
        Self { key, original }
    }
}

impl Drop for EnvVarGuard {
    fn drop(&mut self) {
        match self.original.as_ref() {
            Some(value) => env::set_var(self.key, value),
            None => env::remove_var(self.key),
        }
    }
}

#[test]
fn configures_connection_level_backpressure() {
    let _env_guard = EnvVarGuard::set("SLIPSTREAM_STREAM_WRITE_BUFFER_BYTES", "16384");
    let expected = stream_write_buffer_bytes() as u64;
    assert_eq!(
        expected,
        16 * 1024,
        "stream buffer override should be applied before QUIC config"
    );

    let alpn = CString::new("test").expect("ALPN should be valid");
    // SAFETY: picoquic_current_time has no pointer inputs.
    let now = unsafe { picoquic_current_time() };
    // SAFETY: picoquic_create accepts null for optional pointers and uses a valid ALPN C string.
    let quic = unsafe {
        picoquic_create(
            1,
            ptr::null(),
            ptr::null(),
            ptr::null(),
            alpn.as_ptr(),
            None,
            ptr::null_mut(),
            None,
            ptr::null_mut(),
            ptr::null(),
            now,
            ptr::null_mut(),
            ptr::null(),
            ptr::null(),
            0,
        )
    };
    assert!(!quic.is_null(), "picoquic_create returned null");
    let _guard = QuicGuard::new(quic);

    let cc_algo = CString::new("dcubic").expect("congestion control should be valid");
    // SAFETY: quic is a valid picoquic context and cc_algo is a valid C string.
    unsafe {
        configure_quic(quic, cc_algo.as_ptr(), 1200);
    }

    // SAFETY: test helpers require a valid picoquic context.
    let max_data = unsafe { slipstream_test_get_max_data_limit(quic) };
    let defer = unsafe { slipstream_test_get_defer_stream_data_consumption(quic) };
    assert_eq!(
        max_data, expected,
        "connection-level max_data should track stream_write_buffer_bytes"
    );
    assert_eq!(
        defer, 1,
        "stream data consumption should be deferred to enforce backpressure"
    );
}
