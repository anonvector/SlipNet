/*
* Author: Christian Huitema
* Copyright (c) 2017, Private Octopus, Inc.
* All rights reserved.
*
* Permission to use, copy, modify, and distribute this software for any
* purpose with or without fee is hereby granted, provided that the above
* copyright notice and this permission notice appear in all copies.
*
* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
* ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
* WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
* DISCLAIMED. IN NO EVENT SHALL Private Octopus, Inc. BE LIABLE FOR ANY
* DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
* (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
* LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
* ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
* SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/
#ifdef _WINDOWS
#include "getopt.h"
#endif
#include "picoquic.h"
#include "picoquic_utils.h"
#include "picoquictest.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void picoquic_tls_api_unload();

typedef struct st_picoquic_test_def_t {
    char const* test_name;
    int (*test_fn)();
} picoquic_test_def_t;

typedef enum {
    test_not_run = 0,
    test_excluded,
    test_success,
    test_failed
} test_status_t;

static const picoquic_test_def_t test_table[] = {
    { "connection_id_print", util_connection_id_print_test },
    { "connection_id_parse", util_connection_id_parse_test },
    { "sprintf", util_sprintf_test },
    { "memcmp", util_memcmp_test },
    { "threading", util_threading_test },
    { "picohash", picohash_test },
    { "picohash_embedded", picohash_embedded_test },
    { "bytestream", bytestream_test },
    { "sockloop_basic", sockloop_basic_test },
    { "sockloop_eio", sockloop_eio_test },
    { "sockloop_errsock", sockloop_errsock_test },
    { "sockloop_ipv4", sockloop_ipv4_test },
    { "sockloop_migration", sockloop_migration_test },
    { "sockloop_nat", sockloop_nat_test },
    { "sockloop_thread", sockloop_thread_test },
    { "sockloop_thread_name", sockloop_thread_name_test },
    { "splay", splay_test },
    { "create_cnx", create_cnx_test },
    { "create_quic", create_quic_test },
    { "parseheader", parseheadertest },
    { "incoming_initial", incoming_initial_test },
    { "header_length", header_length_test },
    { "pn2pn64", pn2pn64test },
    { "intformat", intformattest },
    { "varint", varint_test },
    { "sqrt_for_test", sqrt_for_test_test },
    { "ack_sack", sacktest },
    { "frames_skip", skip_frame_test },
    { "frames_parse", parse_frame_test },
    { "frames_repeat", frames_repeat_test },
    { "frames_ackack_error", frames_ackack_error_test },
    { "frames_format", frames_format_test },
    { "logger", logger_test },
    { "binlog", binlog_test },
    { "app_message_overflow", app_message_overflow_test },
    { "TlsStreamFrame", TlsStreamFrameTest },
    { "StreamZeroFrame", StreamZeroFrameTest },
    { "stream_splay", stream_splay_test },
    { "stream_output", stream_output_test },
    { "stream_retransmit_copy", test_copy_for_retransmit },
    { "dataqueue_copy", dataqueue_copy_test },
    { "dataqueue_packet", dataqueue_packet_test },
    { "stateless_blowback", test_stateless_blowback },
    { "ack_send", sendacktest },
    { "ack_loop", sendack_loop_test },
    { "ack_range", ackrange_test },
    { "ack_disorder", ack_disorder_test },
    { "ack_horizon", ack_horizon_test },
    { "ack_of_ack", ack_of_ack_test },
    { "ackfrq_basic", ackfrq_basic_test },
    { "ackfrq_short", ackfrq_short_test },
    { "sim_link", sim_link_test },
    { "clear_text_aead", cleartext_aead_test },
    { "pn_ctr", pn_ctr_test },
    { "cleartext_pn_enc", cleartext_pn_enc_test },
    { "cid_for_lb", cid_for_lb_test },
    { "cid_for_lb_cli", cid_for_lb_cli_test },
    { "retry_protection_vector", retry_protection_vector_test },
    { "retry_protection_v2", retry_protection_v2_test },
    { "draft17_vector", draft17_vector_test },
    { "dtn_basic", dtn_basic_test },
    { "dtn_data", dtn_data_test },
    { "dtn_silence", dtn_silence_test },
    { "dtn_twenty", dtn_twenty_test },
    { "pn_enc_1rtt", pn_enc_1rtt_test },
    { "new_cnxid_stash", cnxid_stash_test },
    { "new_cnxid", new_cnxid_test },
    { "pacing", pacing_test },
    { "pacing_repeat", pacing_repeat_test },
#if 0
    /* The TLS API connect test is only useful when debugging issues step by step */
    { "tls_api_connect", tls_api_connect_test },
#endif
    { "tls_api", tls_api_test },
    { "tls_api_inject_hs_ack", tls_api_inject_hs_ack_test },
    { "null_sni", null_sni_test },
    { "silence_test", tls_api_silence_test },
    { "code_version", code_version_test },
    { "version_negotiation", tls_api_version_negotiation_test },
    { "version_invariant", tls_api_version_invariant_test },
    { "version_negotiation_spoof", test_version_negotiation_spoof },
    { "first_loss", tls_api_client_first_loss_test },
    { "second_loss", tls_api_client_second_loss_test },
    { "SH_loss", tls_api_server_first_loss_test },
    { "client_losses", tls_api_client_losses_test },
    { "server_losses", tls_api_server_losses_test },
    { "many_losses", tls_api_many_losses },
    { "initial_ping", initial_ping_test },
    { "initial_ping_ack", initial_ping_ack_test },
    { "datagram", datagram_test },
    { "datagram_rt", datagram_rt_test },
    { "datagram_rt_skip", datagram_rt_skip_test },
    { "datagram_rtnew_skip", datagram_rtnew_skip_test },
    { "datagram_loss", datagram_loss_test },
    { "datagram_size", datagram_size_test },
    { "datagram_small", datagram_small_test },
    { "datagram_small_new", datagram_small_new_test },
    { "datagram_small_packet", datagram_small_packet_test },
    { "datagram_wifi", datagram_wifi_test },
    { "ddos_amplification", ddos_amplification_test },
    { "ddos_amplification_0rtt", ddos_amplification_0rtt_test },
    { "ddos_amplification_8k", ddos_amplification_8k_test },
    { "blackhole", blackhole_test },
    { "no_ack_frequency", no_ack_frequency_test },
    { "immediate_ack", immediate_ack_test },
    { "connection_drop", connection_drop_test },
    { "vn_tp", vn_tp_test },
    { "vn_compat", vn_compat_test },
    { "stream_rank", stream_rank_test },
    { "provide_stream_buffer", provide_stream_buffer_test },
    { "transport_param", transport_param_test },
    { "tls_api_sni", tls_api_sni_test },
    { "tls_api_alpn", tls_api_alpn_test },
    { "tls_api_wrong_alpn", tls_api_wrong_alpn_test },
    { "tls_api_oneway_stream", tls_api_oneway_stream_test },
    { "tls_api_q_and_r_stream", tls_api_q_and_r_stream_test },
    { "tls_api_q2_and_r2_stream", tls_api_q2_and_r2_stream_test },
    { "implicit_ack", implicit_ack_test },
    { "stateless_reset", stateless_reset_test },
    { "stateless_reset_bad", stateless_reset_bad_test },
    { "stateless_reset_client", stateless_reset_client_test },
    { "stateless_reset_handshake", stateless_reset_handshake_test },
    { "immediate_close", immediate_close_test },
    { "tls_api_very_long_stream", tls_api_very_long_stream_test },
    { "tls_api_very_long_max", tls_api_very_long_max_test },
    { "tls_api_very_long_with_err", tls_api_very_long_with_err_test },
    { "tls_api_very_long_congestion", tls_api_very_long_congestion_test },
    { "many_short_loss", many_short_loss_test },
    { "retry", tls_api_retry_test },
    { "retry_large", tls_api_retry_large_test},
    { "retry_token", tls_retry_token_test },
    { "retry_token_valid", tls_retry_token_valid_test },
    { "two_connections", tls_api_two_connections_test },
    { "multiple_versions", tls_api_multiple_versions_test },
    { "keep_alive", keep_alive_test },
    { "integrity_limit", integrity_limit_test },
    { "excess_repeat", excess_repeat_test },
    { "netperf_basic", netperf_basic_test },
    { "netperf_bbr", netperf_bbr_test },
    { "nat_attack", nat_attack_test },
    { "sockets", socket_test },
    { "socket_ecn", socket_ecn_test },
    { "ticket_store", ticket_store_test },
    { "ticket_seed", ticket_seed_test },
    { "ticket_seed_from_bdp_frame", ticket_seed_from_bdp_frame_test },
    { "token_store", token_store_test },
    { "token_reuse_api", token_reuse_api_test },
    { "session_resume", session_resume_test },
    { "zero_rtt", zero_rtt_test },
    { "zero_rtt_loss", zero_rtt_loss_test },
    { "stop_sending", stop_sending_test },
    { "stop_sending_loss", stop_sending_loss_test },
    { "discard_stream", discard_stream_test },
    { "unidir", unidir_test },
    { "mtu_discovery", mtu_discovery_test },
    { "mtu_blocked", mtu_blocked_test },
    { "mtu_delayed", mtu_delayed_test },
    { "mtu_required", mtu_required_test },
    { "mtu_max", mtu_max_test },
    { "mtu_drop_bbr", mtu_drop_bbr_test },
    { "mtu_drop_cubic", mtu_drop_cubic_test },
    { "mtu_drop_dcubic", mtu_drop_dcubic_test },
    { "mtu_drop_fast", mtu_drop_fast_test },
    { "mtu_drop_newreno", mtu_drop_newreno_test },
    { "red_bbr", red_bbr_test },
    { "red_cubic", red_cubic_test },
    { "red_dcubic", red_dcubic_test },
    { "red_fast", red_fast_test },
    { "red_newreno", red_newreno_test },
    { "multi_segment", multi_segment_test },
    { "pacing_bbr", pacing_bbr_test },
    { "pacing_cubic", pacing_cubic_test },
    { "pacing_dcubic", pacing_dcubic_test },
    { "pacing_fast", pacing_fast_test },
    { "pacing_newreno", pacing_newreno_test },
    { "heavy_loss", heavy_loss_test },
    { "heavy_loss_inter", heavy_loss_inter_test },
    { "heavy_loss_total", heavy_loss_total_test },
    { "spurious_retransmit", spurious_retransmit_test },
    { "tls_zero_share", tls_zero_share_test },
    { "transport_param_log", transport_param_log_test },
    { "bad_certificate", bad_certificate_test },
    { "set_verify_certificate_callback_test", set_verify_certificate_callback_test },
    { "virtual_time" , virtual_time_test },
    { "different_params", tls_different_params_test },
    { "quant_params", tls_quant_params_test },
    { "set_certificate_and_key", set_certificate_and_key_test },
    { "request_client_authentication", request_client_authentication_test },
    { "bad_client_certificate", bad_client_certificate_test },
    { "nat_rebinding", nat_rebinding_test },
    { "nat_rebinding_loss", nat_rebinding_loss_test },
    { "nat_rebinding_zero", nat_rebinding_zero_test },
    { "nat_rebinding_latency", nat_rebinding_latency_test },
    { "nat_rebinding_fast", fast_nat_rebinding_test},
    { "spinbit", spinbit_test },
    { "spinbit_bad", spinbit_bad_test },
    { "spinbit_null", spinbit_null_test },
    { "spinbit_randclient", spinbit_randclient_test },
    { "spinbit_random", spinbit_random_test },
    { "loss_bit", loss_bit_test},
    { "client_error", client_error_test },
    { "client_only", client_only_test },
    { "packet_enc_dec", packet_enc_dec_test},
    { "pn_vector", cleartext_pn_vector_test },
    { "zero_rtt_spurious", zero_rtt_spurious_test },
    { "zero_rtt_retry", zero_rtt_retry_test },
    { "zero_rtt_no_coal", zero_rtt_no_coal_test },
    { "zero_rtt_many_losses", zero_rtt_many_losses_test },
    { "zero_rtt_long", zero_rtt_long_test },
    { "zero_rtt_delay", zero_rtt_delay_test },
    { "random_tester", random_tester_test},
    { "random_gauss", random_gauss_test},
    { "random_public_tester", random_public_tester_test},
    { "cnxid_transmit", transmit_cnxid_test },
    { "cnxid_transmit_disable", transmit_cnxid_disable_test },
    { "cnxid_transmit_r_before", transmit_cnxid_retire_before_test },
    { "cnxid_transmit_r_disable", transmit_cnxid_retire_disable_test },
    { "cnxid_transmit_r_early", transmit_cnxid_retire_early_test },
    { "probe_api", probe_api_test },
    { "migration" , migration_test },
    { "migration_long", migration_test_long },
    { "migration_with_loss", migration_test_loss },
    { "migration_zero", migration_zero_test },
    { "migration_fail", migration_fail_test },
    { "preferred_address", preferred_address_test},
    { "preferred_address_dis_mig", preferred_address_dis_mig_test },
    { "preferred_address_zero", preferred_address_zero_test },
    { "cnxid_renewal",  cnxid_renewal_test },
    { "retire_cnxid", retire_cnxid_test },
    { "not_before_cnxid", not_before_cnxid_test },
    { "server_busy", server_busy_test },
    { "initial_close", initial_close_test },
    { "initial_server_close", initial_server_close_test },
    { "new_rotated_key", new_rotated_key_test },
    { "key_rotation", key_rotation_test },
    { "key_rotation_server", key_rotation_auto_server },
    { "key_rotation_client", key_rotation_auto_client },
    { "false_migration", false_migration_test },
    { "nat_handshake", nat_handshake_test },
    { "key_rotation_vector", key_rotation_vector_test },
    { "key_rotation_stress", key_rotation_stress_test },
    { "short_initial_cid", short_initial_cid_test },
    { "stream_id_max", stream_id_max_test },
    { "padding_test", padding_test },
    { "packet_trace", packet_trace_test },
    { "qlog_trace", qlog_trace_test },
    { "qlog_trace_auto", qlog_trace_auto_test },
    { "qlog_trace_only", qlog_trace_only_test },
    { "qlog_trace_ecn", qlog_trace_ecn_test },
    { "perflog", perflog_test },
    { "nat_rebinding_stress", rebinding_stress_test },
    { "random_padding", random_padding_test },
    { "ec00_zero", ec00_zero_test },
    { "ec2f_second_flight", ec2f_second_flight_nack_test },
    { "eccf_corrupted_fuzz", eccf_corrupted_file_fuzz_test },
    { "eca1_amplification_loss", eca1_amplification_loss_test },
    { "ecf1_final_loss", ecf1_final_loss_test },
    { "ec5c_silly_cid", ec5c_silly_cid_test },
    { "ec9a_preemptive_amok", ec9a_preemptive_amok_test },
    { "error_reason", error_reason_test },
    { "idle_server", idle_server_test },
    { "idle_timeout", idle_timeout_test },
    { "reset_ack_max", reset_ack_max_test },
    { "reset_ack_reset", reset_ack_reset_test },
    { "reset_extra_max", reset_extra_max_test },
    { "reset_extra_reset", reset_extra_reset_test },
    { "reset_extra_stop", reset_extra_stop_test },
    { "reset_need_max", reset_need_max_test },
    { "reset_need_reset", reset_need_reset_test },
    { "reset_need_stop", reset_need_stop_test },
    { "initial_pto", initial_pto_test },
    { "initial_pto_srv", initial_pto_srv_test },
    { "ready_to_send", ready_to_send_test },
    { "ready_to_skip", ready_to_skip_test },
    { "ready_to_zfin", ready_to_zfin_test },
    { "ready_to_zero", ready_to_zero_test },
    { "crypto_hs_offset", crypto_hs_offset_test },
    { "cubic", cubic_test },
    { "cubic_jitter", cubic_jitter_test },
    { "fastcc", fastcc_test },
    { "fastcc_jitter", fastcc_jitter_test },
    { "bbr", bbr_test },
    { "bbr_jitter", bbr_jitter_test },
    { "bbr_long", bbr_long_test },
    { "bbr_performance", bbr_performance_test },
    { "bbr_slow_long", bbr_slow_long_test },
    { "bbr_one_second", bbr_one_second_test },
    { "bbr_gbps", gbps_performance_test },
    { "bbr_asym100", bbr_asym100_test },
    { "bbr_asym100_nodelay", bbr_asym100_nodelay_test },
    { "bbr_asym400", bbr_asym400_test },
    { "bbr1", bbr1_test },
    { "bbr1_long", bbr1_long_test },
    { "l4s_reno", l4s_reno_test },
    { "l4s_prague", l4s_prague_test },
    { "l4s_prague_updown", l4s_prague_updown_test },
    { "l4s_bbr", l4s_bbr_test },
    { "l4s_bbr_updown", l4s_bbr_updown_test },
    { "long_rtt", long_rtt_test },
    { "high_latency_basic", high_latency_basic_test },
    { "high_latency_bbr", high_latency_bbr_test },
    { "high_latency_cubic", high_latency_cubic_test },
    { "high_latency_probeRTT", high_latency_probeRTT_test },
    { "satellite_basic", satellite_basic_test },
    { "satellite_seeded", satellite_seeded_test },
    { "satellite_seeded_bbr1", satellite_seeded_bbr1_test },
    { "satellite_loss", satellite_loss_test },
    { "satellite_loss_fc", satellite_loss_fc_test},
    { "satellite_jitter", satellite_jitter_test },
    { "satellite_medium", satellite_medium_test },
    { "satellite_preemptive", satellite_preemptive_test },
    { "satellite_preemptive_fc", satellite_preemptive_fc_test },
    { "satellite_small", satellite_small_test },
    { "satellite_small_up", satellite_small_up_test },
    { "satellite_bbr1", satellite_bbr1_test },
    { "satellite_cubic", satellite_cubic_test },
    { "satellite_cubic_seeded", satellite_cubic_seeded_test },
    { "satellite_cubic_loss", satellite_cubic_loss_test },
    { "bdp_basic", bdp_basic_test },
    { "bdp_delay", bdp_delay_test },
    { "bdp_ip", bdp_ip_test },
    { "bdp_rtt", bdp_rtt_test },
    { "bdp_reno", bdp_reno_test },
#if 0
    { "bdp_cubic", bdp_cubic_test },
#endif
    { "bdp_bbr1", bdp_bbr1_test },
    { "bdp_short", bdp_short_test },
    { "bdp_short_hi", bdp_short_hi_test },
    { "bdp_short_lo", bdp_short_lo_test },
    { "cid_length", cid_length_test },
    { "optimistic_ack", optimistic_ack_test },
    { "optimistic_hole", optimistic_hole_test },
    { "bad_coalesce", bad_coalesce_test },
    { "bad_cnxid", bad_cnxid_test },
    { "document_addresses", document_addresses_test },
    { "large_client_hello", large_client_hello_test },
    { "limited_reno", limited_reno_test },
    { "limited_cubic", limited_cubic_test },
    { "limited_bbr", limited_bbr_test },
    { "limited_batch", limited_batch_test },
    { "limited_safe", limited_safe_test },
    { "send_stream_blocked", send_stream_blocked_test },
    { "stream_ack", stream_ack_test },
    { "queue_network_input", queue_network_input_test },
    { "pacing_update", pacing_update_test },
    { "quality_update", quality_update_test },
    { "direct_receive", direct_receive_test },
    { "address_discovery", address_discovery_test },
    { "app_limit_cc", app_limit_cc_test },
    { "app_limited_bbr", app_limited_bbr_test },
    { "app_limited_cubic", app_limited_cubic_test },
    { "app_limited_reno", app_limited_reno_test },
    { "app_limited_rpr", app_limited_rpr_test },
    { "cwin_max", cwin_max_test },
    { "initial_race", initial_race_test },
    { "chacha20", chacha20_test },
    { "cnx_limit", cnx_limit_test },
    { "cert_verify_bad_cert", cert_verify_bad_cert_test },
    { "cert_verify_bad_sni", cert_verify_bad_sni_test },
    { "cert_verify_null", cert_verify_null_test },
    { "cert_verify_null_sni", cert_verify_null_sni_test },
    { "cert_verify_rsa", cert_verify_rsa_test },
    { "cid_quiescence", cid_quiescence_test },
    { "client_auth", request_client_authentication_test },
    { "client_cert_callback", set_verify_certificate_callback_test },
    { "mediatest_video", mediatest_video_test },
    { "mediatest_video_audio", mediatest_video_audio_test },
    { "mediatest_video_data_audio", mediatest_video_data_audio_test },
    { "mediatest_video2_down", mediatest_video2_down_test },
    { "mediatest_video2_back", mediatest_video2_back_test },
    { "mediatest_video2_probe", mediatest_video2_probe_test },
    { "mediatest_wifi", mediatest_wifi_test },
    { "mediatest_worst", mediatest_worst_test },
    { "mediatest_suspension", mediatest_suspension_test },
    { "mediatest_suspension2", mediatest_suspension2_test },
    { "warptest_video", warptest_video_test },
    { "warptest_video_audio", warptest_video_audio_test },
    { "warptest_video_data_audio", warptest_video_data_audio_test },
    { "warptest_worst", warptest_worst_test },
    { "warptest_param", warptest_param_test },
    { "wifi_bbr", wifi_bbr_test },
    { "wifi_bbr_hard", wifi_bbr_hard_test },
    { "wifi_bbr_long", wifi_bbr_long_test },
    { "wifi_bbr_many", wifi_bbr_many_test },
    { "wifi_bbr_shadow", wifi_bbr_shadow_test },
    { "wifi_bbr1", wifi_bbr1_test },
    { "wifi_bbr1_hard", wifi_bbr1_hard_test },
    { "wifi_bbr1_long", wifi_bbr1_long_test },
    { "wifi_cubic", wifi_cubic_test },
    { "wifi_cubic_hard", wifi_cubic_hard_test },
    { "wifi_cubic_long", wifi_cubic_long_test },
    { "wifi_reno", wifi_reno_test },
    { "wifi_reno_hard", wifi_reno_hard_test },
    { "wifi_reno_long", wifi_reno_long_test },
    { "migration_controlled", migration_controlled_test },
    { "migration_mtu_drop", migration_mtu_drop_test },
    { "minicrypto", minicrypto_test },
    { "minicrypto_is_last", minicrypto_is_last_test },
#ifdef PICOQUIC_WITH_MBEDTLS
    { "mbedtls", mbedtls_test },
    { "mbedtls_crypto", mbedtls_crypto_test },
    { "mbedtls_load_key", mbedtls_load_key_test },
    { "mbedtls_load_key_fail", mbedtls_load_key_fail_test },
    { "mbedtls_retrieve_pubkey", mbedtls_retrieve_pubkey_test },
    { "mbedtls_sign_verify", mbedtls_sign_verify_test },
    { "mbedtls_configure", mbedtls_configure_test },
#endif
    { "openssl_cert", openssl_cert_test },
    { "monopath_basic", monopath_basic_test },
    { "monopath_hole", monopath_hole_test },
    { "monopath_rotation", monopath_rotation_test },
    { "monopath_0rtt", monopath_0rtt_test },
    { "monopath_0rtt_loss", monopath_0rtt_loss_test },
    { "multipath_aead", multipath_aead_test },
    { "multipath_basic", multipath_basic_test },
    { "multipath_drop_first", multipath_drop_first_test },
    { "multipath_drop_second", multipath_drop_second_test },
    { "multipath_fail", multipath_fail_test },
    { "multipath_ab1", multipath_ab1_test },
    { "multipath_sat_plus", multipath_sat_plus_test },
    { "multipath_renew", multipath_renew_test },
    { "multipath_rotation", multipath_rotation_test },
    { "multipath_break1", multipath_break1_test },
    { "multipath_socket_error", multipath_socket_error_test },
    { "multipath_abandon", multipath_abandon_test },
    { "multipath_back1", multipath_back1_test },
    { "multipath_nat", multipath_nat_test },
    { "multipath_nat_challenge", multipath_nat_challenge_test },
    { "multipath_perf", multipath_perf_test },
    { "multipath_callback", multipath_callback_test },
    { "multipath_quality", multipath_quality_test },
    { "multipath_stream_af", multipath_stream_af_test },
    { "multipath_datagram", multipath_datagram_test },
    { "multipath_dg_af", multipath_dg_af_test },
    { "multipath_standby", multipath_standby_test },
    { "multipath_standup", multipath_standup_test },
    { "multipath_discovery", multipath_discovery_test },
    { "multipath_qlog", multipath_qlog_test },
    { "multipath_tunnel", multipath_tunnel_test },
    { "monopath_0rtt", monopath_0rtt_test },
    { "monopath_0rtt_loss", monopath_0rtt_loss_test },
    { "getter", getter_test },
    { "grease_quic_bit", grease_quic_bit_test },
    { "grease_quic_bit_one_way", grease_quic_bit_one_way_test },
    { "pn_random", pn_random_test },
    { "port_blocked", port_blocked_test },
    { "cplusplus", cplusplustest },
    { "stress", stress_test },
    { "fuzz", fuzz_test },
    { "fuzz_initial", fuzz_initial_test},
    { "cnx_stress", cnx_stress_unit_test },
    { "cnx_ddos", cnx_ddos_unit_test },
    { "config_option", config_option_test },
    { "config_option_letters", config_option_letters_test },
    { "config_quic", config_quic_test },
    { "config_usage", config_usage_test }
    
};

static size_t const nb_tests = sizeof(test_table) / sizeof(picoquic_test_def_t);

static int do_one_test(size_t i, FILE* F)
{
    int ret = 0;

    if (i >= nb_tests) {
        fprintf(F, "Invalid test number %" PRIst "\n", i);
        ret = -1;
    } else {
        fprintf(F, "Starting test number %" PRIst ", %s\n", i, test_table[i].test_name);

        fflush(F);

        ret = test_table[i].test_fn();
        if (ret == 0) {
            fprintf(F, "    Success.\n");
        } else {
            fprintf(F, "    Fails, error: %d.\n", ret);
        }
    }

    fflush(F);

    return ret;
}

int usage(char const * argv0)
{
    fprintf(stderr, "PicoQUIC test execution\n");
    fprintf(stderr, "Usage: picoquic_ct [-x <excluded>] [<list of tests]\n");
    fprintf(stderr, "\nUsage: %s [test1 [test2 ..[testN]]]\n\n", argv0);
    fprintf(stderr, "   Or: %s [-x test]*", argv0);
    fprintf(stderr, "Valid test names are: \n");
    for (size_t x = 0; x < nb_tests; x++) {
        fprintf(stderr, "    ");

        for (int j = 0; j < 4 && x < nb_tests; j++, x++) {
            fprintf(stderr, "%s, ", test_table[x].test_name);
        }
        fprintf(stderr, "\n");
    }
    fprintf(stderr, "Options: \n");
    fprintf(stderr, "  -x test           Do not run the specified test.\n");
    fprintf(stderr, "  -o n1 n2          Only run test numbers in range [n1,n2]");
    fprintf(stderr, "  -s nnn            Run stress for nnn minutes.\n");
    fprintf(stderr, "  -f nnn            Run fuzz for nnn minutes.\n");
    fprintf(stderr, "  -C ccc            Use nnn stress clients in parallel.\n");
    fprintf(stderr, "  -c nnn ccc        Run connection stress for nnn minutes, ccc connections.\n");
    fprintf(stderr, "  -d ppp uuu dir    Run connection ddoss for ppp packets, uuu usec intervals,\n");
    fprintf(stderr, "                    logs in dir. No logs if dir=\"-\"");
    fprintf(stderr, "  -F nnn            Run the corrupt file fuzzer nnn times,\n");
    fprintf(stderr, "  -n                Disable debug prints.\n");
    fprintf(stderr, "  -r                Retry failed tests with debug print enabled.\n");
    fprintf(stderr, "  -h                Print this help message\n");
    fprintf(stderr, "  -S solution_dir   Set the path to the source files to find the default files\n");

    return -1;
}

int get_test_number(char const * test_name)
{
    int test_number = -1;

    for (size_t i = 0; i < nb_tests; i++) {
        if (strcmp(test_name, test_table[i].test_name) == 0) {
            test_number = (int)i;
        }
    }

    return test_number;
}

int main(int argc, char** argv)
{
    int ret = 0;
    int nb_test_tried = 0;
    int nb_test_failed = 0;
    int stress_minutes = 0;
    int stress_clients = 0;
    int auto_bypass = 0;
    int cf_rounds = 0;
    test_status_t * test_status = (test_status_t *) calloc(nb_tests, sizeof(test_status_t));
    int opt;
    int do_fuzz = 0;
    int do_stress = 0;
    int do_cnx_stress = 0;
    int do_cnx_ddos = 0;
    int do_cf_fuzz = 0;
    int disable_debug = 0;
    int retry_failed_test = 0;
    int cnx_stress_minutes = 0;
    int cnx_stress_nb_cnx = 0;
    int cnx_ddos_packets = 0;
    int cnx_ddos_interval = 0;
    size_t first_test = 0;
    size_t last_test = 10000;

    char const* cnx_ddos_dir = NULL;

    debug_printf_push_stream(stderr);

    if (test_status == NULL)
    {
        fprintf(stderr, "Could not allocate memory.\n");
        ret = -1;
    }
    else
    {
        memset(test_status, 0, nb_tests * sizeof(test_status_t));

        while (ret == 0 && (opt = getopt(argc, argv, "c:C:d:f:F:s:S:x:o:nrh")) != -1) {
            switch (opt) {
            case 'x': {
                optind--;
                while (optind < argc) {
                    char const* tn = argv[optind];
                    if (tn[0] == '-') {
                        break;
                    }
                    else {
                        int test_number = get_test_number(tn);

                        if (test_number < 0) {
                            fprintf(stderr, "Incorrect test name: %s\n", tn);
                            ret = usage(argv[0]);
                        }
                        else {
                            test_status[test_number] = test_excluded;
                        }
                        optind++;
                    }
                }
                break;
            }
            case 'o':
                if (optind + 1 > argc) {
                    fprintf(stderr, "option requires more arguments -- o\n");
                    ret = usage(argv[0]);
                }
                else {
                    int i_first_test = atoi(optarg);
                    int i_last_test = atoi(argv[optind++]);
                    if (i_first_test < 0 || i_last_test < 0) {
                        fprintf(stderr, "Incorrect first/last: %s %s\n", optarg, argv[optind - 1]);
                        ret = usage(argv[0]);
                    }
                    else {
                        first_test = (size_t)i_first_test;
                        last_test = (size_t)i_last_test;
                    }
                }
                break;
            case 'f':
                do_fuzz = 1;
                stress_minutes = atoi(optarg);
                if (stress_minutes <= 0) {
                    fprintf(stderr, "Incorrect stress minutes: %s\n", optarg);
                    ret = usage(argv[0]);
                }
                break;
            case 'F':
                do_cf_fuzz = 1;
                cf_rounds = atoi(optarg);
                if (cf_rounds <= 0) {
                    fprintf(stderr, "Incorrect number of cf_fuzz rounds: %s\n", optarg);
                    ret = usage(argv[0]);
                }
                break;
            case 's':
                do_stress = 1;
                stress_minutes = atoi(optarg);
                if (stress_minutes <= 0) {
                    fprintf(stderr, "Incorrect stress minutes: %s\n", optarg);
                    ret = usage(argv[0]);
                }
                break;
            case 'C':
                do_stress = 1;
                stress_clients = atoi(optarg);
                if (stress_clients <= 0) {
                    fprintf(stderr, "Incorrect number of stress clients: %s\n", optarg);
                    ret = usage(argv[0]);
                }
                break;

            case 'c':
                if (optind + 1 > argc) {
                    fprintf(stderr, "option requires more arguments -- c\n");
                    ret = usage(argv[0]);
                }
                do_cnx_stress = 1;
                cnx_stress_minutes = atoi(optarg);
                cnx_stress_nb_cnx = atoi(argv[optind++]);
                if (cnx_stress_minutes <= 0) {
                    fprintf(stderr, "Incorrect cnx stress minutes: %s\n", optarg);
                    ret = usage(argv[0]);
                }
                else if (cnx_stress_nb_cnx < 0) {
                    fprintf(stderr, "Incorrect cnx stress number of connections: %s\n", argv[optind - 1]);
                    ret = usage(argv[0]);
                }
                break;
            case 'd':
                if (optind + 2 > argc) {
                    fprintf(stderr, "option requires more arguments -- c\n");
                    ret = usage(argv[0]);
                }
                do_cnx_ddos = 1;
                cnx_ddos_packets = atoi(optarg);
                cnx_ddos_interval = atoi(argv[optind++]);
                cnx_ddos_dir = argv[optind++];
                if (cnx_ddos_packets <= 0) {
                    fprintf(stderr, "Incorrect cnx ddos packets: %s\n", optarg);
                    ret = usage(argv[0]);
                }
                else if (cnx_stress_nb_cnx < 0) {
                    fprintf(stderr, "Incorrect cnx ddos interval: %s\n", argv[optind - 1]);
                    ret = usage(argv[0]);
                }
                break;
            case 'S':
                picoquic_set_solution_dir(optarg);
                break;
            case 'n':
                disable_debug = 1;
                break;
            case 'r':
                retry_failed_test = 1;
                break;
            case 'h':
                usage(argv[0]);
                exit(0);
                break;
            default:
                ret = usage(argv[0]);
                break;
            }
        }
        /* If one of the stressers was specified, do not run any other test by default */
        if (do_stress || do_fuzz || do_cnx_stress || do_cnx_ddos || do_cf_fuzz) {
            auto_bypass = 1;
            for (size_t i = 0; i < nb_tests; i++) {
                test_status[i] = test_excluded;
            }
        }

        /* If the argument list ends with a list of selected tests, mark all other tests as excluded */
        if (optind < argc) {
            auto_bypass = 1;
            for (size_t i = 0; i < nb_tests; i++) {
                test_status[i] = test_excluded;
            }
            while (optind < argc) {
                int test_number = get_test_number(argv[optind]);

                if (test_number < 0) {
                    fprintf(stderr, "Incorrect test name: %s\n", optarg);
                    ret = usage(argv[0]);
                }
                else {
                    test_status[test_number] = 0;
                }
                optind++;
            }
        }

        /* If one of the stressers is requested, just execute it,
         */

        if (ret == 0 && (do_stress || do_fuzz || do_cnx_stress || do_cnx_ddos || do_cf_fuzz)) {
            debug_printf_suspend();
            if (do_stress || do_fuzz) {
                picoquic_stress_test_duration = stress_minutes;
                picoquic_stress_test_duration *= 60000000;
                picoquic_stress_nb_clients = stress_clients;
            }

            for (size_t i = 0; i < nb_tests; i++) {
                if ((do_stress && strcmp(test_table[i].test_name, "stress") == 0) ||
                    (do_fuzz && strcmp(test_table[i].test_name, "fuzz") == 0)) {
                    /* Run the stress test or the fuzz test as specified */
                    nb_test_tried++;
                    if (do_one_test(i, stdout) != 0) {
                        test_status[i] = test_failed;
                        nb_test_failed++;
                        ret = -1;
                    }
                    else {
                        test_status[i] = test_success;
                    }
                }
                else if (do_cnx_stress && strcmp(test_table[i].test_name, "cnx_stress") == 0) {
                    uint64_t duration = ((uint64_t)cnx_stress_minutes) * 60000000ull;
                    nb_test_tried++;
                    if (cnx_stress_do_test(duration, cnx_stress_nb_cnx, 1) != 0) {
                        test_status[i] = test_failed;
                        nb_test_failed++;
                        ret = -1;
                    }
                    else {
                        test_status[i] = test_success;
                    }
                }
                else if (do_cnx_ddos && strcmp(test_table[i].test_name, "cnx_ddos") == 0) {
                    nb_test_tried++;
                    if (cnx_ddos_test_loop(cnx_ddos_packets, cnx_ddos_interval, cnx_ddos_dir) != 0) {
                        test_status[i] = test_failed;
                        nb_test_failed++;
                        ret = -1;
                    }
                    else {
                        test_status[i] = test_success;
                    }
                }
                else if (do_cf_fuzz && strcmp(test_table[i].test_name, "eccf_corrupted_fuzz") == 0) {
                    uint64_t r_seed = picoquic_current_time();
                    FILE* F = picoquic_file_open("ECCF_Fuzz_report.csv", "w");

                    if (F == NULL) {
                        test_status[i] = test_failed;
                        nb_test_failed++;
                        ret = -1;
                    }
                    else {
                        (void)fprintf(F, "Seed_hex, Seed, Ret, Elapsed\n");
                        eccf_corrupted_file_fuzz(cf_rounds, r_seed, F);
                        picoquic_file_close(F);
                        test_status[i] = test_success;
                    }
                }
            }
            debug_printf_resume();
        }


        if (disable_debug) {
            debug_printf_suspend();
        }
        else {
            debug_printf_resume();
        }

        /* Execute now all the tests that were not excluded */
        if (ret == 0) {
            for (size_t i = 0; i < nb_tests; i++) {
                if (test_status[i] == test_not_run) {
                    nb_test_tried++;
                    if (i >= first_test && i <= last_test && do_one_test(i, stdout) != 0) {
                        test_status[i] = test_failed;
                        nb_test_failed++;
                        ret = -1;
                    }
                    else {
                        test_status[i] = test_success;
                    }
                }
                else if (!auto_bypass && test_status[i] == test_excluded) {
                    fprintf(stdout, "Test number %d (%s) is bypassed.\n", (int)i, test_table[i].test_name);
                }
            }
        }

        /* Report status, and if specified retry 
         */

        if (nb_test_tried > 1) {
            fprintf(stdout, "Tried %d tests, %d fail%s.\n", nb_test_tried,
                nb_test_failed, (nb_test_failed > 1) ? "" : "s");
        }

        if (nb_test_failed > 0) {
            fprintf(stdout, "Failed test(s): ");
            for (size_t i = 0; i < nb_tests; i++) {
                if (test_status[i] == test_failed) {
                    fprintf(stdout, "%s ", test_table[i].test_name);
                }
            }
            fprintf(stdout, "\n");

            if (disable_debug && retry_failed_test) {
                debug_printf_resume();
                ret = 0;
                for (size_t i = 0; i < nb_tests; i++) {
                    if (test_status[i] == test_failed) {
                        if (strcmp("stress", test_table[i].test_name) == 0 ||
                            strcmp("fuzz", test_table[i].test_name) == 0 ||
                            strcmp("fuzz_initial", test_table[i].test_name) == 0 ||
                            strcmp(test_table[i].test_name, "cnx_stress") == 0 ||
                            strcmp(test_table[i].test_name, "cnx_ddos") == 0 ||
                            strcmp(test_table[i].test_name, "eccf_corrupted_fuzz") == 0)
                        {
                            fprintf(stdout, "Cannot retry %s:\n", test_table[i].test_name);
                            ret = -1;
                        }
                        else {
                            fprintf(stdout, "Retrying %s:\n", test_table[i].test_name);
                            if (do_one_test(i, stdout) != 0) {
                                test_status[i] = test_failed;
                                ret = -1;
                            }
                            else {
                                /* This was a Heisenbug.. */
                                test_status[i] = test_success;
                            }
                        }
                    }
                }
                if (ret == 0) {
                    fprintf(stdout, "All tests pass after second try.\n");
                }
                else {
                    fprintf(stdout, "Still failing: ");
                    for (size_t i = 0; i < nb_tests; i++) {
                        if (test_status[i] == test_failed) {
                            fprintf(stdout, "%s ", test_table[i].test_name);
                        }
                    }
                    fprintf(stdout, "\n");
                }
            }
        }

        free(test_status);
        picoquic_tls_api_unload();
    }
    return (ret);
}
