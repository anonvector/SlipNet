#![allow(non_camel_case_types, non_snake_case, non_upper_case_globals)]

use libc::{c_char, c_int, c_uint, c_void, size_t, sockaddr, sockaddr_storage};

pub const PICOQUIC_CONNECTION_ID_MAX_SIZE: usize = 20;
pub const PICOQUIC_MAX_PACKET_SIZE: usize = 1536;
pub const PICOQUIC_RESET_SECRET_SIZE: usize = 16;
pub const PICOQUIC_PACKET_LOOP_RECV_MAX: usize = 10;
pub const PICOQUIC_PACKET_LOOP_SEND_MAX: usize = 10;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct picoquic_connection_id_t {
    pub id: [u8; PICOQUIC_CONNECTION_ID_MAX_SIZE],
    pub id_len: u8,
}

#[repr(C)]
pub struct picoquic_quic_t {
    _private: [u8; 0],
}

#[repr(C)]
pub struct picoquic_cnx_t {
    _private: [u8; 0],
}

#[repr(C)]
pub struct ptls_t {
    _private: [u8; 0],
}

#[repr(C)]
pub struct picoquic_congestion_algorithm_t {
    _private: [u8; 0],
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct picoquic_path_quality_t {
    pub receive_rate_estimate: u64,
    pub pacing_rate: u64,
    pub cwin: u64,
    pub rtt: u64,
    pub rtt_sample: u64,
    pub rtt_variant: u64,
    pub rtt_min: u64,
    pub rtt_max: u64,
    pub sent: u64,
    pub lost: u64,
    pub timer_losses: u64,
    pub spurious_losses: u64,
    pub max_spurious_rtt: u64,
    pub max_reorder_delay: u64,
    pub max_reorder_gap: u64,
    pub bytes_in_transit: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ptls_iovec_t {
    pub base: *mut u8,
    pub len: size_t,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum picoquic_state_enum {
    picoquic_state_client_init = 0,
    picoquic_state_client_init_sent = 1,
    picoquic_state_client_renegotiate = 2,
    picoquic_state_client_retry_received = 3,
    picoquic_state_client_init_resent = 4,
    picoquic_state_server_init = 5,
    picoquic_state_server_handshake = 6,
    picoquic_state_client_handshake_start = 7,
    picoquic_state_handshake_failure = 8,
    picoquic_state_handshake_failure_resend = 9,
    picoquic_state_client_almost_ready = 10,
    picoquic_state_server_false_start = 11,
    picoquic_state_server_almost_ready = 12,
    picoquic_state_client_ready_start = 13,
    picoquic_state_ready = 14,
    picoquic_state_disconnecting = 15,
    picoquic_state_closing_received = 16,
    picoquic_state_closing = 17,
    picoquic_state_draining = 18,
    picoquic_state_disconnected = 19,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum picoquic_call_back_event_t {
    picoquic_callback_stream_data = 0,
    picoquic_callback_stream_fin = 1,
    picoquic_callback_stream_reset = 2,
    picoquic_callback_stop_sending = 3,
    picoquic_callback_stateless_reset = 4,
    picoquic_callback_close = 5,
    picoquic_callback_application_close = 6,
    picoquic_callback_stream_gap = 7,
    picoquic_callback_prepare_to_send = 8,
    picoquic_callback_almost_ready = 9,
    picoquic_callback_ready = 10,
    picoquic_callback_datagram = 11,
    picoquic_callback_version_negotiation = 12,
    picoquic_callback_request_alpn_list = 13,
    picoquic_callback_set_alpn = 14,
    picoquic_callback_pacing_changed = 15,
    picoquic_callback_prepare_datagram = 16,
    picoquic_callback_datagram_acked = 17,
    picoquic_callback_datagram_lost = 18,
    picoquic_callback_datagram_spurious = 19,
    picoquic_callback_path_available = 20,
    picoquic_callback_path_suspended = 21,
    picoquic_callback_path_deleted = 22,
    picoquic_callback_path_quality_changed = 23,
    picoquic_callback_path_address_observed = 24,
    picoquic_callback_app_wakeup = 25,
}

pub type ptls_verify_sign_cb_fn = Option<
    unsafe extern "C" fn(
        verify_ctx: *mut c_void,
        algo: u16,
        data: ptls_iovec_t,
        sign: ptls_iovec_t,
    ) -> c_int,
>;

#[repr(C)]
pub struct ptls_verify_certificate_t {
    pub cb: Option<
        unsafe extern "C" fn(
            self_ptr: *mut ptls_verify_certificate_t,
            tls: *mut ptls_t,
            server_name: *const c_char,
            verify_sign: *mut ptls_verify_sign_cb_fn,
            verify_sign_ctx: *mut *mut c_void,
            certs: *mut ptls_iovec_t,
            num_certs: size_t,
        ) -> c_int,
    >,
    pub algos: *const u16,
}

pub type picoquic_stream_data_cb_fn = Option<
    unsafe extern "C" fn(
        cnx: *mut picoquic_cnx_t,
        stream_id: u64,
        bytes: *mut u8,
        length: size_t,
        fin_or_event: picoquic_call_back_event_t,
        callback_ctx: *mut c_void,
        stream_ctx: *mut c_void,
    ) -> c_int,
>;

pub type picoquic_stream_direct_receive_fn = Option<
    unsafe extern "C" fn(
        cnx: *mut picoquic_cnx_t,
        stream_id: u64,
        fin: c_int,
        bytes: *const u8,
        offset: u64,
        length: size_t,
        direct_receive_ctx: *mut c_void,
    ) -> c_int,
>;

pub type picoquic_connection_id_cb_fn = Option<
    unsafe extern "C" fn(
        quic: *mut picoquic_quic_t,
        cnx_id_local: picoquic_connection_id_t,
        cnx_id_remote: picoquic_connection_id_t,
        cnx_id_cb_data: *mut c_void,
        cnx_id_returned: *mut picoquic_connection_id_t,
    ),
>;

extern "C" {
    pub fn picoquic_current_time() -> u64;

    pub fn picoquic_create(
        max_nb_connections: c_uint,
        cert_file_name: *const c_char,
        key_file_name: *const c_char,
        cert_root_file_name: *const c_char,
        default_alpn: *const c_char,
        default_callback_fn: picoquic_stream_data_cb_fn,
        default_callback_ctx: *mut c_void,
        cnx_id_callback: picoquic_connection_id_cb_fn,
        cnx_id_callback_data: *mut c_void,
        reset_seed: *const u8,
        current_time: u64,
        p_simulated_time: *mut u64,
        ticket_file_name: *const c_char,
        ticket_encryption_key: *const u8,
        ticket_encryption_key_length: size_t,
    ) -> *mut picoquic_quic_t;

    pub fn picoquic_free(quic: *mut picoquic_quic_t);

    pub fn picoquic_set_cookie_mode(quic: *mut picoquic_quic_t, cookie_mode: c_int);
    pub fn picoquic_set_default_priority(quic: *mut picoquic_quic_t, default_stream_priority: u8);
    pub fn picoquic_set_default_direct_receive_callback(
        quic: *mut picoquic_quic_t,
        direct_receive_fn: picoquic_stream_direct_receive_fn,
        direct_receive_ctx: *mut c_void,
    );
    pub fn picoquic_set_stream_data_consumption_mode(
        quic: *mut picoquic_quic_t,
        defer_stream_data_consumption: c_int,
    );
    pub fn picoquic_set_default_congestion_algorithm_by_name(
        quic: *mut picoquic_quic_t,
        alg_name: *const c_char,
    );
    pub fn picoquic_set_default_congestion_algorithm(
        quic: *mut picoquic_quic_t,
        alg: *mut picoquic_congestion_algorithm_t,
    );
    pub fn picoquic_set_default_multipath_option(
        quic: *mut picoquic_quic_t,
        multipath_option: c_int,
    );
    pub fn picoquic_set_preemptive_repeat_policy(quic: *mut picoquic_quic_t, do_repeat: c_int);
    pub fn picoquic_disable_port_blocking(
        quic: *mut picoquic_quic_t,
        is_port_blocking_disabled: c_int,
    );
    pub fn picoquic_set_max_data_control(quic: *mut picoquic_quic_t, max_data: u64);
    pub fn picoquic_set_mtu_max(quic: *mut picoquic_quic_t, mtu_max: u32);
    pub fn picoquic_set_initial_send_mtu(
        quic: *mut picoquic_quic_t,
        initial_mtu_ipv4: u32,
        initial_mtu_ipv6: u32,
    );
    pub fn picoquic_set_key_log_file_from_env(quic: *mut picoquic_quic_t);
    pub fn picoquic_enable_path_callbacks_default(quic: *mut picoquic_quic_t, are_enabled: c_int);

    pub fn picoquic_explain_crypto_error(
        err_file: *mut *const c_char,
        err_line: *mut c_int,
    ) -> c_int;
    pub fn picoquic_clear_crypto_errors();

    pub fn picoquic_set_verify_certificate_callback(
        quic: *mut picoquic_quic_t,
        cb: *mut ptls_verify_certificate_t,
        free_fn: Option<unsafe extern "C" fn(*mut ptls_verify_certificate_t)>,
    );

    // Test helpers defined in cc/slipstream_test_helpers.c.
    pub fn slipstream_test_get_max_data_limit(quic: *mut picoquic_quic_t) -> u64;
    pub fn slipstream_test_get_defer_stream_data_consumption(quic: *mut picoquic_quic_t) -> c_int;
    pub fn slipstream_take_stateless_packet_for_cid(
        quic: *mut picoquic_quic_t,
        packet: *const u8,
        packet_len: size_t,
        out_bytes: *mut u8,
        out_capacity: size_t,
        out_len: *mut size_t,
    ) -> c_int;

    pub static mut slipstream_server_cc_algorithm: *mut picoquic_congestion_algorithm_t;
    pub static mut slipstream_mixed_cc_algorithm: *mut picoquic_congestion_algorithm_t;

    pub fn picoquic_create_client_cnx(
        quic: *mut picoquic_quic_t,
        addr: *mut sockaddr,
        start_time: u64,
        preferred_version: c_uint,
        sni: *const c_char,
        alpn: *const c_char,
        callback_fn: picoquic_stream_data_cb_fn,
        callback_ctx: *mut c_void,
    ) -> *mut picoquic_cnx_t;
    pub fn picoquic_start_client_cnx(cnx: *mut picoquic_cnx_t) -> c_int;
    pub fn picoquic_set_callback(
        cnx: *mut picoquic_cnx_t,
        callback_fn: picoquic_stream_data_cb_fn,
        callback_ctx: *mut c_void,
    );
    pub fn picoquic_enable_path_callbacks(cnx: *mut picoquic_cnx_t, are_enabled: c_int);
    pub fn picoquic_close(cnx: *mut picoquic_cnx_t, application_reason_code: u64) -> c_int;
    pub fn picoquic_close_immediate(cnx: *mut picoquic_cnx_t);
    pub fn picoquic_delete_cnx(cnx: *mut picoquic_cnx_t);

    pub fn picoquic_enable_keep_alive(cnx: *mut picoquic_cnx_t, interval: u64);
    pub fn picoquic_disable_keep_alive(cnx: *mut picoquic_cnx_t);

    pub fn picoquic_get_next_wake_delay(
        quic: *mut picoquic_quic_t,
        current_time: u64,
        delay_max: i64,
    ) -> i64;
    pub fn picoquic_get_rtt(cnx: *mut picoquic_cnx_t) -> u64;
    pub fn picoquic_get_cwin(cnx: *mut picoquic_cnx_t) -> u64;
    pub fn picoquic_get_pacing_rate(cnx: *mut picoquic_cnx_t) -> u64;
    pub fn picoquic_get_default_path_quality(
        cnx: *mut picoquic_cnx_t,
        quality: *mut picoquic_path_quality_t,
    );
    pub fn picoquic_get_path_quality(
        cnx: *mut picoquic_cnx_t,
        unique_path_id: u64,
        quality: *mut picoquic_path_quality_t,
    ) -> c_int;

    pub fn slipstream_request_poll(cnx: *mut picoquic_cnx_t);
    pub fn slipstream_is_flow_blocked(cnx: *mut picoquic_cnx_t) -> c_int;
    pub fn slipstream_has_ready_stream(cnx: *mut picoquic_cnx_t) -> c_int;
    pub fn slipstream_disable_ack_delay(cnx: *mut picoquic_cnx_t);
    pub fn slipstream_find_path_id_by_addr(
        cnx: *mut picoquic_cnx_t,
        addr_peer: *const sockaddr,
    ) -> c_int;
    pub fn slipstream_get_path_id_from_unique(
        cnx: *mut picoquic_cnx_t,
        unique_path_id: u64,
    ) -> c_int;
    pub fn slipstream_get_max_streams_bidir_remote(cnx: *mut picoquic_cnx_t) -> u64;
    pub fn slipstream_set_cc_override(alg_name: *const c_char);
    pub fn slipstream_set_default_path_mode(mode: c_int);
    pub fn slipstream_set_path_mode(cnx: *mut picoquic_cnx_t, path_id: c_int, mode: c_int);
    pub fn slipstream_set_path_ack_delay(cnx: *mut picoquic_cnx_t, path_id: c_int, disable: c_int);

    pub fn picoquic_get_first_cnx(quic: *mut picoquic_quic_t) -> *mut picoquic_cnx_t;
    pub fn picoquic_get_next_cnx(cnx: *mut picoquic_cnx_t) -> *mut picoquic_cnx_t;
    pub fn picoquic_get_cnx_state(cnx: *mut picoquic_cnx_t) -> picoquic_state_enum;
    pub fn picoquic_get_close_reasons(
        cnx: *mut picoquic_cnx_t,
        local_reason: *mut u64,
        remote_reason: *mut u64,
        local_application_reason: *mut u64,
        remote_application_reason: *mut u64,
    );

    pub fn picoquic_connection_disconnect(cnx: *mut picoquic_cnx_t);

    pub fn picoquic_prepare_next_packet_ex(
        quic: *mut picoquic_quic_t,
        current_time: u64,
        send_buffer: *mut u8,
        send_buffer_max: size_t,
        send_length: *mut size_t,
        p_addr_to: *mut sockaddr_storage,
        p_addr_from: *mut sockaddr_storage,
        if_index: *mut c_int,
        log_cid: *mut picoquic_connection_id_t,
        p_last_cnx: *mut *mut picoquic_cnx_t,
        send_msg_size: *mut size_t,
    ) -> c_int;

    pub fn picoquic_prepare_packet_ex(
        cnx: *mut picoquic_cnx_t,
        path_id_request: c_int,
        current_time: u64,
        send_buffer: *mut u8,
        send_buffer_max: size_t,
        send_length: *mut size_t,
        p_addr_to: *mut sockaddr_storage,
        p_addr_from: *mut sockaddr_storage,
        if_index: *mut c_int,
        send_msg_size: *mut size_t,
    ) -> c_int;

    pub fn picoquic_incoming_packet_ex(
        quic: *mut picoquic_quic_t,
        bytes: *mut u8,
        packet_length: size_t,
        addr_from: *mut sockaddr,
        addr_to: *mut sockaddr,
        if_index_to: c_int,
        received_ecn: u8,
        first_cnx: *mut *mut picoquic_cnx_t,
        first_path_id: *mut c_int,
        current_time: u64,
    ) -> c_int;

    pub fn picoquic_provide_stream_data_buffer(
        context: *mut c_void,
        nb_bytes: size_t,
        is_fin: c_int,
        is_still_active: c_int,
    ) -> *mut u8;

    pub fn picoquic_add_to_stream(
        cnx: *mut picoquic_cnx_t,
        stream_id: u64,
        data: *const u8,
        length: size_t,
        set_fin: c_int,
    ) -> c_int;
    pub fn picoquic_reset_stream(
        cnx: *mut picoquic_cnx_t,
        stream_id: u64,
        local_stream_error: u64,
    ) -> c_int;
    pub fn picoquic_stop_sending(
        cnx: *mut picoquic_cnx_t,
        stream_id: u64,
        local_stream_error: u64,
    ) -> c_int;
    pub fn picoquic_stream_data_consumed(
        cnx: *mut picoquic_cnx_t,
        stream_id: u64,
        new_offset: u64,
    ) -> c_int;
    pub fn picoquic_get_next_local_stream_id(cnx: *mut picoquic_cnx_t, is_unidir: c_int) -> u64;

    pub fn picoquic_set_app_stream_ctx(
        cnx: *mut picoquic_cnx_t,
        stream_id: u64,
        app_stream_ctx: *mut c_void,
    ) -> c_int;
    pub fn picoquic_unlink_app_stream_ctx(cnx: *mut picoquic_cnx_t, stream_id: u64);
    pub fn picoquic_mark_active_stream(
        cnx: *mut picoquic_cnx_t,
        stream_id: u64,
        is_active: c_int,
        v_stream_ctx: *mut c_void,
    ) -> c_int;

    pub fn picoquic_probe_new_path_ex(
        cnx: *mut picoquic_cnx_t,
        addr_peer: *const sockaddr,
        addr_local: *const sockaddr,
        if_index: c_int,
        current_time: u64,
        to_preferred_address: c_int,
        path_id_p: *mut c_int,
    ) -> c_int;

    pub fn picoquic_get_path_addr(
        cnx: *mut picoquic_cnx_t,
        unique_path_id: u64,
        local: c_int,
        addr: *mut sockaddr_storage,
    ) -> c_int;
}

/// # Safety
/// `cnx` must be null or point to a valid picoquic connection for the duration
/// of the call.
pub unsafe fn get_cwin(cnx: *mut picoquic_cnx_t) -> u64 {
    if cnx.is_null() {
        0
    } else {
        // SAFETY: caller guarantees cnx is a valid picoquic connection.
        picoquic_get_cwin(cnx)
    }
}

/// # Safety
/// `cnx` must be null or point to a valid picoquic connection for the duration
/// of the call.
pub unsafe fn get_rtt(cnx: *mut picoquic_cnx_t) -> u64 {
    if cnx.is_null() {
        0
    } else {
        // SAFETY: caller guarantees cnx is a valid picoquic connection.
        picoquic_get_rtt(cnx)
    }
}

/// # Safety
/// `cnx` must be null or point to a valid picoquic connection for the duration
/// of the call.
pub unsafe fn get_pacing_rate(cnx: *mut picoquic_cnx_t) -> u64 {
    if cnx.is_null() {
        0
    } else {
        // SAFETY: caller guarantees cnx is a valid picoquic connection.
        picoquic_get_pacing_rate(cnx)
    }
}

/// # Safety
/// `cnx` must be null or point to a valid picoquic connection for the duration
/// of the call.
pub unsafe fn get_bytes_in_transit(cnx: *mut picoquic_cnx_t) -> u64 {
    if cnx.is_null() {
        0
    } else {
        let mut quality = picoquic_path_quality_t::default();
        // SAFETY: caller guarantees cnx is valid; quality is a properly initialized out parameter.
        picoquic_get_default_path_quality(cnx, &mut quality as *mut _);
        quality.bytes_in_transit
    }
}
