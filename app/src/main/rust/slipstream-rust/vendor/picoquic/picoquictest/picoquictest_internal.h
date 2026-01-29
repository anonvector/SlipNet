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

#ifndef PICOQUICTEST_INTERNAL_H
#define PICOQUICTEST_INTERNAL_H

#ifdef __cplusplus
extern "C" {
#endif

#include "picoquic_internal.h"

/*  ALPN used for test
 */

#define PICOQUIC_TEST_ALPN "picoquic-test"

#define PICOQUIC_TEST_SNI "test.example.com"
#define PICOQUIC_TEST_ALPN "picoquic-test"
#define PICOQUIC_TEST_WRONG_ALPN "picoquic-bla-bla"
#define PICOQUIC_TEST_MAX_TEST_STREAMS 100

#define RANDOM_PUBLIC_TEST_SEED 0xDEADBEEFCAFEC001ull


 /* Callback function for sending and receiving datagrams.
  */
typedef int (*picoquic_datagram_send_fn)(picoquic_cnx_t* cnx, uint64_t unique_path_id,
    uint8_t* bytes, size_t length, void* datagram_ctx);
typedef int (*picoquic_datagram_recv_fn)(picoquic_cnx_t* cnx, uint64_t unique_path_id,
    uint8_t* bytes, size_t length, void* datagram_ctx);
typedef int (*picoquic_datagram_ack_fn)(picoquic_cnx_t* cnx,
    picoquic_call_back_event_t d_event, uint8_t* bytes, size_t length, uint64_t sent_time, void* datagram_ctx);

/* Example functions for datagrams. */
typedef struct st_test_datagram_send_recv_ctx_t {
    uint32_t dg_max_size;
    uint32_t dg_small_size;
    int dg_target[2];
    int dg_sent[2];
    int dg_recv[2];
    int dg_acked[2];
    int dg_nacked[2];
    int dg_spurious[2];
    int batch_size[2];
    int batch_sent[2];
    uint64_t dg_time_ready[2];
    uint64_t dg_latency_max[2];
    uint64_t dg_received_last[2];
    uint64_t dg_number_delta_max[2];
    uint64_t dg_latency_target[2];
    uint64_t dg_number_delta_target[2];
    uint64_t link_latency;
    uint64_t picosec_per_byte;
    uint64_t send_delay;
    uint64_t next_gen_time[2];
    uint64_t duration_max;
    int is_ready[2];
    int max_packets_received;
    int nb_recv_path_0[2];
    int nb_recv_path_other[2];
    int nb_trials_max;

    unsigned int use_extended_provider_api;
    unsigned int do_skip_test[2];
    unsigned int is_skipping[2];
    unsigned int test_affinity;
    unsigned int test_wifi;
    unsigned int one_datagram_per_packet;

} test_datagram_send_recv_ctx_t;

uint64_t test_datagram_next_time_ready(test_datagram_send_recv_ctx_t* dg_ctx);
int test_datagram_check_ready(test_datagram_send_recv_ctx_t* dg_ctx, int client_mode, uint64_t current_time);
int test_datagram_send(picoquic_cnx_t* cnx, uint64_t unique_path_id,
    uint8_t* bytes, size_t length, void* datagram_ctx);
int test_datagram_recv(picoquic_cnx_t* cnx, uint64_t unique_path_id,
    uint8_t* bytes, size_t length, void* datagram_ctx);
int test_datagram_ack(picoquic_cnx_t* cnx,
    picoquic_call_back_event_t d_event, uint8_t* bytes, size_t length, uint64_t sent_time, void* datagram_ctx);

/* Test context
 */

typedef enum {
    test_api_fail_data_on_unknown_stream = 1,
    test_api_fail_recv_larger_than_sent = 2,
    test_api_fail_fin_received_twice = 4,
    test_api_fail_cannot_send_response = 8,
    test_api_fail_cannot_send_query = 16,
    test_api_fail_data_does_not_match = 32,
    test_api_fail_unexpected_frame = 64,
    test_api_bad_stream0_data = 128
} test_api_fail_mode;

typedef struct st_test_api_stream_desc_t {
    uint64_t stream_id;
    uint64_t previous_stream_id;
    size_t q_len;
    size_t r_len;
} test_api_stream_desc_t;

typedef struct st_test_api_stream_hole_t {
    struct st_test_api_stream_hole_t* next_hole;
    uint64_t offset;
    uint64_t last_offset;
} test_api_stream_hole_t;

typedef struct st_test_api_stream_t {
    uint64_t stream_id;
    uint64_t previous_stream_id;
    int q_sent;
    int r_sent;
    picoquic_call_back_event_t q_received;
    picoquic_call_back_event_t r_received;
    size_t q_len;
    size_t q_recv_nb;
    size_t r_len;
    size_t r_recv_nb;
    uint64_t next_direct_offset;
    struct st_test_api_stream_hole_t* first_direct_hole;
    int direct_fin_received;
    uint8_t* q_src;
    uint8_t* q_rcv;
    uint8_t* r_src;
    uint8_t* r_rcv;
} test_api_stream_t;

typedef enum {
    sim_action_none = 0,
    sim_action_stateless_packet = 1,
    sim_action_client_departure,
    sim_action_server_departure,
    sim_action_client_arrival,
    sim_action_server_arrival,
    sim_action_client_arrival2,
    sim_action_server_arrival2,
    sim_action_client_dequeue,
    sim_action_server_dequeue
} tls_api_sim_action_enum;

typedef struct st_picoquic_test_endpoint_t {
    /* configuration parameters */
    uint64_t prepare_cpu_time;
    uint64_t incoming_cpu_time;
    size_t packet_queue_max;
    /* next time endpoint ready */
    uint64_t next_time_ready;
    /* last time client sent something */
    uint64_t last_send_time;
    int ready_to_send;
    /* packet queue waiting to be processed. */
    size_t queue_size;
    picoquictest_sim_packet_t* first_packet;
    picoquictest_sim_packet_t* last_packet;
} picoquic_test_endpoint_t;

typedef struct st_test_api_callback_t {
    int client_mode;
    int fin_received;
    int error_detected;
    uint32_t nb_bytes_received;
} test_api_callback_t;

typedef struct st_picoquic_test_tls_api_ctx_t {
    picoquic_quic_t* qclient;
    picoquic_quic_t* qserver;
    picoquic_cnx_t* cnx_client;
    picoquic_cnx_t* cnx_server;
    int client_use_nat;
    int server_use_multiple_addresses;
    int client_use_multiple_addresses;
    int do_bad_coalesce_test;
    struct sockaddr_in client_addr;
    struct sockaddr_in client_addr_natted; /* When simulating NAT (client use NAT) */
    struct sockaddr_in client_addr_2; /* for use in multipath tests */
    struct sockaddr_in server_addr;
    test_api_callback_t client_callback;
    test_api_callback_t server_callback;
    size_t nb_test_streams;
    test_api_stream_t test_stream[PICOQUIC_TEST_MAX_TEST_STREAMS];
    uint64_t loss_mask_default;
    picoquictest_sim_link_t* c_to_s_link;
    picoquictest_sim_link_t* c_to_s_link_2; /* for use in multipath tests */
    picoquictest_sim_link_t* s_to_c_link;
    picoquictest_sim_link_t* s_to_c_link_2;
    /* Simulation of CPU limited sender or receiver */
    picoquic_test_endpoint_t client_endpoint;
    picoquic_test_endpoint_t server_endpoint;
    /* Management of UDP multiple message simulation */
    uint8_t* send_buffer;
    size_t send_buffer_size;
    int use_udp_gso;

    /* Stream 0 is reserved for the "infinite stream" simulation */
    size_t stream0_target;
    size_t stream0_sent;
    size_t stream0_received;
    int stream0_test_option;
    int stream0_flow_release;
    /* Flags */
    int received_version_negotiation;
    int sum_data_received_at_server;
    int sum_data_received_at_client;
    int test_finished;
    int streams_finished;
    int reset_received;
    int immediate_exit;
    /* Checking that addresses are discovered */
    int nb_address_observed;

    /* Blackhole period if needed */
    uint64_t blackhole_start;
    uint64_t blackhole_end;

    /* ECN simulation */
    uint8_t packet_ecn_default;
    uint8_t recv_ecn_client;
    uint8_t recv_ecn_server;

    /* File used to test bandwidth notification */
    FILE* bw_update;
    /* File used to test path notifications */
    FILE* path_events;
    /* File used to test default path quality updates */
    FILE* default_path_update;
    /* Datagram test functions */
    void* datagram_ctx;
    picoquic_datagram_send_fn datagram_send_fn;
    picoquic_datagram_recv_fn datagram_recv_fn;
    picoquic_datagram_ack_fn datagram_ack_fn;
} picoquic_test_tls_api_ctx_t;

typedef struct st_test_skip_frames_t {
    char const* name;
    uint8_t* val;
    size_t len;
    int is_pure_ack;
    int must_be_last;
    int epoch;
    uint64_t expected_error;
    int skip_fails;
    int mpath;
    int nb_varints;
} test_skip_frames_t;

extern test_skip_frames_t test_skip_list[];

extern size_t nb_test_skip_list;

typedef struct st_test_vary_link_spec_t {
    uint64_t duration;
    uint64_t bits_per_second_up;
    uint64_t bits_per_second_down;
    uint64_t microsec_latency;
} test_vary_link_spec_t;



#define TEST_CLIENT_READY (test_ctx->cnx_client->cnx_state == picoquic_state_ready || test_ctx->cnx_client->cnx_state == picoquic_state_client_ready_start)
#define TEST_SERVER_READY (test_ctx->cnx_server != NULL &&(test_ctx->cnx_server->cnx_state == picoquic_state_ready || test_ctx->cnx_server->cnx_state == picoquic_state_server_false_start))

int test_api_callback(picoquic_cnx_t* cnx,
    uint64_t stream_id, uint8_t* bytes, size_t length,
    picoquic_call_back_event_t fin_or_event, void* callback_ctx, void* v_stream_ctx);

int tls_api_init_ctx(picoquic_test_tls_api_ctx_t** pctx, uint32_t proposed_version,
    char const* sni, char const* alpn, uint64_t* p_simulated_time,
    char const* ticket_file_name, char const* token_file_name, 
    int force_zero_share, int delayed_init, int use_bad_crypt);

int tls_api_init_ctx_ex(picoquic_test_tls_api_ctx_t** pctx, uint32_t proposed_version,
    char const* sni, char const* alpn, uint64_t* p_simulated_time,
    char const* ticket_file_name, char const* token_file_name,
    int force_zero_share, int delayed_init, int use_bad_crypt,
    picoquic_connection_id_t * initial_cid);

int tls_api_init_ctx_ex2(picoquic_test_tls_api_ctx_t** pctx, uint32_t proposed_version,
    char const* sni, char const* alpn, uint64_t* p_simulated_time,
    char const* ticket_file_name, char const* token_file_name,
    int force_zero_share, int delayed_init, int use_bad_crypt,
    picoquic_connection_id_t* icid, uint32_t nb_connections, int cid_zero,
    size_t send_buffer_size, int use_ecdsa);

void tls_api_delete_ctx(picoquic_test_tls_api_ctx_t* test_ctx);
void test_api_delete_test_streams(picoquic_test_tls_api_ctx_t* test_ctx);

int tls_api_one_sim_round(picoquic_test_tls_api_ctx_t* test_ctx,
    uint64_t* simulated_time, uint64_t time_out, int* was_active);

int tls_api_one_scenario_init_ex(picoquic_test_tls_api_ctx_t** p_test_ctx, uint64_t* simulated_time, uint32_t proposed_version, picoquic_tp_t* client_params, picoquic_tp_t* server_params, picoquic_connection_id_t* icid, int cid_zero);

int tls_api_one_scenario_init(
    picoquic_test_tls_api_ctx_t** p_test_ctx, uint64_t* simulated_time,
    uint32_t proposed_version,
    picoquic_tp_t* client_params, picoquic_tp_t* server_params);

int tls_api_connection_loop(picoquic_test_tls_api_ctx_t* test_ctx,
    uint64_t* loss_mask, uint64_t queue_delay_max, uint64_t* simulated_time);

int tls_api_test_with_loss_final(picoquic_test_tls_api_ctx_t* test_ctx, uint32_t proposed_version,
    char const* sni, char const* alpn, uint64_t* simulated_time);

int test_api_init_send_recv_scenario(picoquic_test_tls_api_ctx_t* test_ctx,
    test_api_stream_desc_t* stream_desc, size_t size_of_scenarios);

int test_api_queue_initial_queries(picoquic_test_tls_api_ctx_t* test_ctx, uint64_t stream_id);

int tls_api_one_scenario_body_connect(picoquic_test_tls_api_ctx_t* test_ctx,
    uint64_t* simulated_time, size_t stream0_target, uint64_t max_data, uint64_t queue_delay_max);

int tls_api_data_sending_loop(picoquic_test_tls_api_ctx_t* test_ctx,
    uint64_t* loss_mask, uint64_t* simulated_time, int max_trials);

int tls_api_wait_for_timeout(picoquic_test_tls_api_ctx_t* test_ctx,
    uint64_t* simulated_time, uint64_t time_out_delay);

int session_resume_wait_for_ticket(picoquic_test_tls_api_ctx_t* test_ctx,
    uint64_t* simulated_time);

int tls_api_one_scenario_body_verify(picoquic_test_tls_api_ctx_t* test_ctx,
    uint64_t* simulated_time,
    uint64_t max_completion_microsec);

int tls_api_close_with_losses(
    picoquic_test_tls_api_ctx_t* test_ctx, uint64_t* simulated_time, uint64_t loss_mask);

int tls_api_one_scenario_body_ex(picoquic_test_tls_api_ctx_t* test_ctx, uint64_t* simulated_time, test_api_stream_desc_t* scenario,
    size_t sizeof_scenario, size_t stream0_target, uint64_t init_loss_mask, uint64_t max_data, uint64_t queue_delay_max, uint64_t max_completion_microsec,
    size_t nb_link_states, test_vary_link_spec_t* link_state);

int tls_api_one_scenario_body(picoquic_test_tls_api_ctx_t* test_ctx, uint64_t* simulated_time, test_api_stream_desc_t* scenario, size_t sizeof_scenario, size_t stream0_target, uint64_t init_loss_mask, uint64_t max_data, uint64_t queue_delay_max, uint64_t max_completion_microsec);

int tls_api_one_scenario_verify(picoquic_test_tls_api_ctx_t* test_ctx);

int wait_client_connection_ready(picoquic_test_tls_api_ctx_t* test_ctx,
    uint64_t* simulated_time);

int tls_api_synch_to_empty_loop(picoquic_test_tls_api_ctx_t* test_ctx,
    uint64_t* simulated_time, int max_trials,
    int path_target, int wait_for_ready);

void picoquic_set_test_address(struct sockaddr_in * addr, uint32_t addr_val, uint16_t port);

int test_one_pn_enc_pair(uint8_t * seqnum, size_t seqnum_len, void * pn_enc, void * pn_dec, uint8_t * sample);

int picoquic_compare_lines(char const* b1, char const* b2);
int picoquic_test_compare_text_files(char const* fname1, char const* fname2);
int picoquic_test_compare_binary_files(char const* fname1, char const* fname2);

uint64_t picoquic_sum_text_file(char const* fname);

int tls_api_one_scenario_test(test_api_stream_desc_t* scenario,
    size_t sizeof_scenario, size_t stream0_target,
    uint64_t init_loss_mask, uint64_t max_data, uint64_t queue_delay_max,
    uint32_t proposed_version, uint64_t max_completion_microsec,
    picoquic_tp_t* client_params, picoquic_tp_t* server_params);

void qlog_trace_cid_fn(picoquic_quic_t* quic, picoquic_connection_id_t cnx_id_local, picoquic_connection_id_t cnx_id_remote, void* cnx_id_cb_data, picoquic_connection_id_t* cnx_id_returned);

uint64_t picoquic_sqrt_for_tests(uint64_t y);

int picoquic_test_set_minimal_cnx(picoquic_quic_t** quic, picoquic_cnx_t** cnx);
int picoquic_test_reset_minimal_cnx(picoquic_quic_t* quic, picoquic_cnx_t** cnx);
void picoquic_test_delete_minimal_cnx(picoquic_quic_t** quic, picoquic_cnx_t** cnx);

#ifdef __cplusplus
}
#endif

#endif