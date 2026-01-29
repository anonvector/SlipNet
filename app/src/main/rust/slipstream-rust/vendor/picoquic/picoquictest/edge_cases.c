/*
* Author: Christian Huitema
* Copyright (c) 2020, Private Octopus, Inc.
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


#include <stdlib.h>
#include <string.h>
#include "picoquic.h"
#include "picoquic_internal.h"
#include "picoquictest_internal.h"
#include "tls_api.h"
#include "picoquic_binlog.h"
#include "logreader.h"
#include "qlog.h"


/* This file includes a series of tests covering edge cases, typically
 * derived from observing failures in the interop runner. The failures
 * correspond to specific sequences in which specific packets were dropped,
 * leading to a failure state from which the connection did not
 * recover. Many of these failures involve 0-RTT connections.
 */

static char const* edge_case_ticket_file = "edge_case_ticket_file.bin";
static char const* edge_case_token_file = "edge_case_token_file.bin";

static test_api_stream_desc_t test_scenario_edge_case[] = {
    { 4, 0, 128, 1000 }
};

void edge_case_reset_scenario(picoquic_test_tls_api_ctx_t* test_ctx)
{

    for (size_t i = 0; i < test_ctx->nb_test_streams; i++) {
        test_ctx->test_stream[i].q_received = 0;
        test_ctx->test_stream[i].q_sent = 0;
        test_ctx->test_stream[i].r_received = 0;
        test_ctx->test_stream[i].r_sent = 0;
        test_ctx->test_stream[i].q_recv_nb = 0;
        test_ctx->test_stream[i].r_recv_nb = 0;
    }
    test_ctx->sum_data_received_at_server = 0;
    test_ctx->sum_data_received_at_client = 0;
    test_ctx->test_finished = 0;
    test_ctx->streams_finished = 0;
}

int edge_case_prepare(picoquic_test_tls_api_ctx_t** p_test_ctx, uint8_t edge_case_id, int zero_rtt, uint64_t* simulated_time, uint64_t loss_mask, int nb_init_rounds)
{
    picoquic_connection_id_t initial_cid = { { 0xed, 0x9e, 0xca, 0x5e, 0, 0, 0, 0}, 8 };
    uint64_t latency = 17000;
    int ret = 0;
    FILE* F;

    initial_cid.id[4] = edge_case_id;
    initial_cid.id[5] = zero_rtt;

    /* Make sure that the ticket and token files are empty */
    F = picoquic_file_open(edge_case_ticket_file, "wb");
    if (F != NULL) {
        picoquic_file_close(F);
    }
    F = picoquic_file_open(edge_case_token_file, "wb");
    if (F != NULL) {
        picoquic_file_close(F);
    }
    /* Create the test context */
    if (ret == 0) {
        ret = tls_api_init_ctx_ex(p_test_ctx, PICOQUIC_INTERNAL_TEST_VERSION_1,
            PICOQUIC_TEST_SNI, PICOQUIC_TEST_ALPN, simulated_time, edge_case_ticket_file, edge_case_token_file, 0, 1, 0, &initial_cid);
    }
    /* Set the binlog */
    if (ret == 0) {
        picoquic_set_binlog((*p_test_ctx)->qclient, ".");
        picoquic_set_binlog((*p_test_ctx)->qserver, ".");
    }
    /* Set the link latency */
    if (ret == 0) {
        (*p_test_ctx)->c_to_s_link->microsec_latency = latency;
        (*p_test_ctx)->s_to_c_link->microsec_latency = latency;
    }
    /* Set PMTUD policy & ACK Frequency policy */
    if (ret == 0){
        if (edge_case_id == 0xcf) {
            (*p_test_ctx)->cnx_client->local_parameters.min_ack_delay = 0;
            picoquic_cnx_set_pmtud_policy((*p_test_ctx)->cnx_client, picoquic_pmtud_blocked);
        }
        else if (edge_case_id == 0xa1) {
            (*p_test_ctx)->cnx_client->local_parameters.min_ack_delay = 0;
            (*p_test_ctx)->qserver->test_large_server_flight = 1;
            picoquic_cnx_set_pmtud_policy((*p_test_ctx)->cnx_client, picoquic_pmtud_blocked);
        }
        else if (edge_case_id == 0xf1) {
            (*p_test_ctx)->cnx_client->local_parameters.min_ack_delay = 0;
            picoquic_cnx_set_pmtud_policy((*p_test_ctx)->cnx_client, picoquic_pmtud_blocked);
        }
        else if (edge_case_id == 0x5c) {
            (*p_test_ctx)->cnx_client->local_parameters.min_ack_delay = 0;
            picoquic_cnx_set_pmtud_policy((*p_test_ctx)->cnx_client, picoquic_pmtud_blocked);
        }
        else {
            picoquic_cnx_set_pmtud_policy((*p_test_ctx)->cnx_client, picoquic_pmtud_delayed);
            picoquic_set_default_pmtud_policy((*p_test_ctx)->qclient, picoquic_pmtud_delayed);
        }
    }

    /* Prepare to send data */
    if (ret == 0) {
        ret = test_api_init_send_recv_scenario(*p_test_ctx, test_scenario_edge_case, sizeof(test_scenario_edge_case));

        if (ret != 0)
        {
            DBG_PRINTF("Init send receive scenario returns %d\n", ret);
        }
    }

    /* If zero RTT is required, run a single connection */
    if (ret == 0) {
        if (!zero_rtt) {
            int ret = picoquic_start_client_cnx((*p_test_ctx)->cnx_client);

            if (ret != 0)
            {
                DBG_PRINTF("%s", "Could not initialize connection for the client\n");
            }
        }
        else {
            uint32_t ticket_version = 0;
            int ret = tls_api_one_scenario_body_connect(*p_test_ctx, simulated_time, 0, 0, 0);

            /* Finish sending data */
            if (ret == 0) {
                uint64_t zero_loss = 0;
                ret = tls_api_data_sending_loop(*p_test_ctx, &zero_loss, simulated_time, 0);

                if (ret != 0)
                {
                    DBG_PRINTF("Data sending loop returns %d\n", ret);
                }
            }

            if (ret == 0) {
                /* wait for the session ticket to arrive */
                ret = session_resume_wait_for_ticket(*p_test_ctx, simulated_time);
            }

            if (ret == 0) {
                ret = tls_api_one_scenario_body_verify(*p_test_ctx, simulated_time, 1000000);
            }

            if (ret == 0 && (*p_test_ctx)->qclient->p_first_ticket == NULL) {
                DBG_PRINTF("No session ticket after first connection, t=%" PRIu64, *simulated_time);
            }
            else {
                ticket_version = (*p_test_ctx)->qclient->p_first_ticket->version;
            }

            if (ret == 0) {
                /* delete the client connection and create a new one. */
                picoquic_delete_cnx((*p_test_ctx)->cnx_client);
                (*p_test_ctx)->cnx_client = NULL;
                (*p_test_ctx)->cnx_server = NULL;
                edge_case_reset_scenario(*p_test_ctx);
                initial_cid.id[5] = 0;

                (*p_test_ctx)->cnx_client = picoquic_create_cnx((*p_test_ctx)->qclient, initial_cid,
                    picoquic_null_connection_id,
                    (struct sockaddr*)&(*p_test_ctx)->server_addr, *simulated_time,
                    ticket_version, PICOQUIC_TEST_SNI, PICOQUIC_TEST_ALPN, 1);

                if ((*p_test_ctx)->cnx_client == NULL) {
                    ret = -1;

                    if (ret != 0)
                    {
                        DBG_PRINTF("Create second connection returns %d\n", ret);
                    }
                }
            }
            if (ret == 0) {
                /* Start the client connection */
                ret = picoquic_start_client_cnx((*p_test_ctx)->cnx_client);

                if (ret != 0)
                {
                    DBG_PRINTF("Start second connection returns %d\n", ret);
                }
                else {
                    ret = test_api_queue_initial_queries((*p_test_ctx), 0);

                    if (ret != 0)
                    {
                        DBG_PRINTF("Restart scenario returns %d\n", ret);
                    }
                }
            }
        }
    }


    /* Execute the expected number of rounds */
    if (ret == 0) {
        int nb_trials = 0;
        int nb_inactive = 0;
        uint64_t loss_target = loss_mask >> nb_init_rounds;
        loss_target |= loss_mask << (64 - nb_init_rounds);

        (*p_test_ctx)->c_to_s_link->loss_mask = &loss_mask;
        (*p_test_ctx)->s_to_c_link->loss_mask = &loss_mask;

        /* Set preemtive repeat on server */
        if (edge_case_id != 0xf1 && edge_case_id != 0x5c) {
            picoquic_set_preemptive_repeat_policy((*p_test_ctx)->qserver, 1);
        }

        while (ret == 0 && nb_trials < 4*nb_init_rounds && nb_inactive < 256 && loss_mask != loss_target) {
            int was_active = 0;

            nb_trials++;

            ret = tls_api_one_sim_round(*p_test_ctx, simulated_time, 0, &was_active);

            if (ret < 0)
            {
                break;
            }

            if (was_active) {
                nb_inactive = 0;
            }
            else {
                nb_inactive++;
            }

            if ((*p_test_ctx)->test_finished) {
                break;
            }
        }
        if (loss_mask != loss_target) {
            DBG_PRINTF("Stop after %d trials, %d inactive, loss_mask = %" PRIu64,
                nb_trials, nb_inactive, loss_mask);
        }
    }

    return ret;
}

int edge_case_complete(picoquic_test_tls_api_ctx_t* test_ctx, uint64_t* simulated_time, uint64_t duration_max)
{
    int ret = 0;
    uint64_t loss_mask = 0;

    ret = tls_api_connection_loop(test_ctx, &loss_mask, 0, simulated_time);
    if (ret != 0)
    {
        DBG_PRINTF("Connect loop returns %d\n", ret);
    }

    /* Finish sending data */
    test_ctx->immediate_exit = 1;

    if (ret == 0) {
        ret = tls_api_data_sending_loop(test_ctx, &loss_mask, simulated_time, 0);

        if (ret != 0)
        {
            DBG_PRINTF("Data sending loop returns %d\n", ret);
        }
    }

    if (ret == 0) {
        ret = tls_api_one_scenario_body_verify(test_ctx, simulated_time, duration_max);
    }

    return ret;
}

/* Edge case zero: verify that the common code
 * works.
 */
int ec00_zero_test()
{
    uint64_t simulated_time = 0;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    int ret = edge_case_prepare(&test_ctx, 0, 1, &simulated_time, 0, 4);

    if (ret == 0) {
        ret = edge_case_complete(test_ctx, &simulated_time, 100000);
    }

    if (ret == 0) {
        if (test_ctx->cnx_client->nb_zero_rtt_acked == 0) {
            DBG_PRINTF("Nb 0RTT acked = %d", test_ctx->cnx_client->nb_zero_rtt_acked);
            ret = -1;
        }
    }

    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }

    return ret;
}

/* Reproduce and fix a specific error:
 * - 0RTT packet was lost
 * - Client second flight arrives at peer, but handshake ACK is lost
 * - Handshake Done is lost
 * Client appears stuck repeating second flight, intead of trying to
 * make progress and send data.
 * 
 * This is unlocked by enabling retransmission of data in "client almost ready"
 * state. 
 */

int ec2f_second_flight_nack_test()
{
    uint64_t simulated_time = 0;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    uint64_t initial_losses = 0b111000001;
    uint8_t test_case_id = 0x2f;
    int ret = edge_case_prepare(&test_ctx, test_case_id, 1, &simulated_time, initial_losses, 9);

    if (ret == 0) {
        if (test_ctx->cnx_client->cnx_state >= picoquic_state_ready ||
            test_ctx->cnx_server->cnx_state != picoquic_state_ready) {
            DBG_PRINTF("Unexpected state, client: %d, server: %d",
                test_ctx->cnx_client->cnx_state, test_ctx->cnx_server->cnx_state);
            ret = -1;
        }
    }

    if (ret == 0) {
        ret = edge_case_complete(test_ctx, &simulated_time, 360000);
    }

    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }

    return ret;
}

/* Try reproduce a corrupt file transmission occuring
 * during a lossy handshake. At some point, the server
 * sent random content instead of repeating the original packet
 * content. Attempts to just reproduce the sequence in
 * the interop runner failed, so instead we add a specialized
 * fuzzer. Running that fuzzer in ASAN/UBSAN builds might
 * detect the corruption some day.
 */

void eccf_corrupted_file_fuzz(int nb_trials, uint64_t seed, FILE* F)
{
    uint64_t random_context = (seed == 0)?0x1234567887654321ull:seed;

    for (int i = 0; i < nb_trials; i++) {
        uint64_t simulated_time = 0;
        picoquic_test_tls_api_ctx_t* test_ctx = NULL;
        uint64_t initial_losses = random_context & 0xFFFFFFFF86ull;
        uint8_t test_case_id = 0xcf;
        int ret = 0;

        (void)picoquic_test_random(&random_context);

        ret = edge_case_prepare(&test_ctx, test_case_id, 0, &simulated_time, initial_losses, 40);

        if (ret == 0) {
            ret = edge_case_complete(test_ctx, &simulated_time, 15000000);
        }

        if (ret != 0 && F != NULL) {
            fprintf(F, "0x%" PRIx64 ", %" PRIu64 ", %d, %" PRIu64 "\n",
                initial_losses, initial_losses, ret, simulated_time);
        }

        if (test_ctx != NULL) {
            tls_api_delete_ctx(test_ctx);
            test_ctx = NULL;
        }
    }
}

int eccf_corrupted_file_fuzz_test()
{
    int ret = 0;
    FILE* F = picoquic_file_open("ECCF_Fuzz_report.csv", "w");
    if (F == NULL) {
        ret = -1;
    }
    else {
        (void)fprintf(F, "Seed_hex, Seed, Ret, Elapsed\n");
        eccf_corrupted_file_fuzz(50, 0, F);
        picoquic_file_close(F);
    }
    return ret;
}

/* Amplification test using large 
 * server hello with losses.
 */
int eca1_amplification_loss_test()
{
    uint64_t simulated_time = 0;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    uint64_t initial_losses = 0b0111111110100;
    uint8_t test_case_id = 0xa1;
    int ret = edge_case_prepare(&test_ctx, test_case_id, 0, &simulated_time, initial_losses, 16);

    if (ret == 0) {
        ret = edge_case_complete(test_ctx, &simulated_time, 15000000);
    }

    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }

    return ret;
}

/* Loss of final closing packet, verify that overall time
 * is acceptable.
 */

int ecf1_final_loss_test()
{
    uint64_t simulated_time = 0;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    uint64_t final_losses = 0xb10;
    uint8_t test_case_id = 0xf1;
    int ret = edge_case_prepare(&test_ctx, test_case_id, 0, &simulated_time, 0, 20);
    uint64_t zero_loss_mask = 0;

    /* Finish the connection */
    if (ret == 0) {
        ret = tls_api_connection_loop(test_ctx, &zero_loss_mask, 0, &simulated_time);
        if (ret != 0)
        {
            DBG_PRINTF("Connect loop returns %d\n", ret);
        }
    }
    /* Finish sending data */
    test_ctx->immediate_exit = 1;

    if (ret == 0) {
        ret = tls_api_data_sending_loop(test_ctx, &zero_loss_mask, &simulated_time, 0);

        if (ret != 0)
        {
            DBG_PRINTF("Data sending loop returns %d\n", ret);
        }
    }
    /* Simulate losses during closing */
    if (ret == 0) {
        ret = tls_api_close_with_losses(test_ctx, &simulated_time, final_losses);
    }

    if (ret == 0 && simulated_time > 10000000) {
        DBG_PRINTF("Took %" PRIu64 "us to complete, too long", simulated_time);
        ret = -1;
    }

    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }

    return ret;
}

/* Some traces show the CID packet from the server being dropped,
 * then repeated a couple time, with one success but a drop
 * of the clien't ack, and the server then sending a bogus repeat.
 */

int ec5c_silly_cid_test()
{
    uint64_t simulated_time = 0;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    uint64_t initial_losses = 0b0000011110000010000100;
    uint8_t test_case_id = 0x5c;
    int ret = edge_case_prepare(&test_ctx, test_case_id, 0, &simulated_time, initial_losses, 48);

    if (ret == 0) {
        if (test_ctx->cnx_server == NULL) {
            DBG_PRINTF("Unexpected state, client: %d, server: NULL",
                test_ctx->cnx_client->cnx_state);

        } else if (test_ctx->cnx_client->cnx_state != picoquic_state_ready ||
            test_ctx->cnx_server->cnx_state != picoquic_state_ready) {
            DBG_PRINTF("Unexpected state, client: %d, server: %d",
                test_ctx->cnx_client->cnx_state, test_ctx->cnx_server->cnx_state);
            ret = -1;
        }
    }

    if (ret == 0) {
        ret = edge_case_complete(test_ctx, &simulated_time, 3000000);
    }

    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }

    return ret;
}

/* Some traces show that if a connection close from the client is dropped and
 * then the client goes away, the server can produce a vast number of
 * preemptive repeats before giving up. Repro, then verify.
 */

int ec9a_preemptive_amok_test()
{
    uint64_t simulated_time = 0;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    uint64_t initial_losses = 0b100000000000;
    uint8_t test_case_id = 0x9a;
    uint64_t cnx_server_idle_timeout = 0;
    uint64_t cnx_server_nb_preemptive_repeat = 0;
    int ret = edge_case_prepare(&test_ctx, test_case_id, 0, &simulated_time, initial_losses, 12);

    if (ret == 0) {
        if (test_ctx->cnx_server == NULL) {
            DBG_PRINTF("Unexpected state, client: %d, server: NULL",
                test_ctx->cnx_client->cnx_state);
            ret = -1;
        }
        else if ( test_ctx->cnx_server->cnx_state != picoquic_state_ready ||
            !test_ctx->test_finished || 
            test_ctx->cnx_server->pkt_ctx[picoquic_packet_context_application].pending_first == NULL){
            DBG_PRINTF("Unexpected state, server: %d, test finished: %d, queue for repeat %s",
                test_ctx->cnx_server->cnx_state, test_ctx->test_finished, 
                (test_ctx->cnx_server->pkt_ctx[picoquic_packet_context_application].pending_first == NULL)?"empty":"full");
            ret = -1;
        }
    }
    /* Do a loop involving only the server */
    if (ret == 0) {
        uint8_t buffer[PICOQUIC_MAX_PACKET_SIZE];
        size_t send_length;
        size_t send_msg_size;
        struct sockaddr_storage addr_to;
        struct sockaddr_storage addr_from;
        int if_index;
        picoquic_connection_id_t log_id;
        picoquic_cnx_t * last_cnx;
        int loop_count = 0;
        int send_count = 0;
        const int send_count_max = 50;
        uint64_t repeat_begin = simulated_time;
        uint64_t repeat_duration = 0;

        cnx_server_idle_timeout = test_ctx->cnx_server->idle_timeout;
        cnx_server_nb_preemptive_repeat = test_ctx->cnx_server->nb_preemptive_repeat;

        picoquic_reinsert_by_wake_time(test_ctx->qserver, test_ctx->cnx_server, simulated_time);

        while (test_ctx->qserver->current_number_connections > 0 && test_ctx->cnx_server->cnx_state == picoquic_state_ready && loop_count < 10000 && ret == 0) {
            loop_count++;
            cnx_server_nb_preemptive_repeat = test_ctx->cnx_server->nb_preemptive_repeat;
            simulated_time = picoquic_get_next_wake_time(test_ctx->qserver, simulated_time);
            ret = picoquic_prepare_next_packet_ex(test_ctx->qserver, simulated_time, buffer,
                sizeof(buffer), &send_length, &addr_to, &addr_from, &if_index, &log_id,
                &last_cnx, &send_msg_size);
            if (ret != 0) {
                DBG_PRINTF("Prepare next returns an error: %d (0x%x)", ret, ret);
            }
            else if (send_length > 0) {
                send_count++;
            }
        }

        if (ret == 0) {
            repeat_duration = simulated_time - repeat_begin;
            if (send_count > send_count_max) {
                DBG_PRINTF("Repeated %d packets, more that the %d expected",
                    send_count, send_count_max);
                ret = -1;
            }
            else if (repeat_duration > cnx_server_idle_timeout) {
                DBG_PRINTF("End at t=%" PRIu64 ", later than %" PRIu64,
                    simulated_time, cnx_server_idle_timeout);
                ret = -1;
            }
            else if (cnx_server_nb_preemptive_repeat == 0) {
                DBG_PRINTF("%s", "No preemptive repeat");
                ret = -1;
            }
        }
    }

    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }

    return ret;
}

/* testing the negotiation of the idle timeout.
*/
int idle_timeout_test_one(uint8_t test_id, uint64_t client_timeout, uint64_t server_timeout, uint64_t expected_timeout)
{
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    uint64_t simulated_time = 0;
    uint64_t loss_mask = 0;
    picoquic_connection_id_t initial_cid = { { 0x41, 0x9e, 0x00, 0x94, 0, 0, 0, 0}, 8 };
    uint64_t half_time = (expected_timeout == UINT64_MAX) ? 20000000 : (expected_timeout / 2);
    uint64_t full_time = (expected_timeout == UINT64_MAX) ? 600000000 : (half_time + 100000);
    int ret = 0;

    initial_cid.id[4] = test_id;

    /* Create the test context */
    if (ret == 0) {
        ret = tls_api_init_ctx_ex(&test_ctx, PICOQUIC_INTERNAL_TEST_VERSION_1,
            PICOQUIC_TEST_SNI, PICOQUIC_TEST_ALPN, &simulated_time, NULL, NULL, 0, 1, 0, &initial_cid);
    }
    /* Set the binlog */
    if (ret == 0) {
        picoquic_set_binlog(test_ctx->qclient, ".");
        picoquic_set_binlog(test_ctx->qserver, ".");
        /* Set the timeout */
        picoquic_set_default_idle_timeout(test_ctx->qclient, client_timeout);
        picoquic_set_default_idle_timeout(test_ctx->qserver, server_timeout);
        /* Directly set the timeout in the client parameters,
           because the connection context is already created */
        test_ctx->cnx_client->local_parameters.max_idle_timeout = client_timeout;
    }

    /* Do the connection */
    if (ret == 0) {
        test_ctx->cnx_client->max_early_data_size = 0;

        if ((ret = picoquic_start_client_cnx(test_ctx->cnx_client)) == 0) {
            ret = tls_api_connection_loop(test_ctx, &loss_mask, 0, &simulated_time);
        }
    }

    /* Verify the timer negotiation */
    if (ret == 0) {
        if (test_ctx->cnx_client->local_parameters.max_idle_timeout != client_timeout) {
            DBG_PRINTF("Idle timeout test %d. Client parameter set to %" PRIu64 " instead of %" PRIu64 "\n",
                test_id, test_ctx->cnx_client->local_parameters.max_idle_timeout, client_timeout);
            ret = -1;
        }
        if (test_ctx->cnx_server->local_parameters.max_idle_timeout != server_timeout) {
            DBG_PRINTF("Idle timeout test %d. Server parameter set to %" PRIu64 " instead of %" PRIu64 "\n",
                test_id, test_ctx->cnx_server->local_parameters.max_idle_timeout, server_timeout);
            ret = -1;
        }
        if (test_ctx->cnx_client->idle_timeout != expected_timeout) {
            DBG_PRINTF("Idle timeout test %d. Client negotiated %" PRIu64 " instead of %" PRIu64 "\n",
                test_id, test_ctx->cnx_client->idle_timeout, expected_timeout);
            ret = -1;
        }
        if (test_ctx->cnx_server->idle_timeout != expected_timeout) {
            DBG_PRINTF("Idle timeout test %d. Server negotiated %" PRIu64 " instead of %" PRIu64 "\n",
                test_id, test_ctx->cnx_server->idle_timeout, expected_timeout);
            ret = -1;
        }
    }

    if (ret == 0) {
        /* Wait for half time. Expectation: connections are still up */
        ret = tls_api_wait_for_timeout(test_ctx, &simulated_time, half_time);
        if (ret != 0 || !((TEST_CLIENT_READY && TEST_SERVER_READY))) {
            DBG_PRINTF("Idle timeout test %d. Broke early, time = %" PRIu64 "\n", test_id, simulated_time);
            ret = -1;
        }
    }

    if (ret == 0) {
        /* Wait for full time. Expectation: connections are down, unless timeout == 0 */
        ret = tls_api_wait_for_timeout(test_ctx, &simulated_time, full_time);

        if (ret == 0){
            if (TEST_CLIENT_READY && TEST_SERVER_READY) {
                if (expected_timeout != UINT64_MAX) {
                    DBG_PRINTF("Idle timeout test %d. Waited too long, time = %" PRIu64 "\n", test_id, simulated_time);
                    ret = -1;
                }
            }
            else {
                if (expected_timeout == UINT64_MAX) {
                    DBG_PRINTF("Idle timeout test %d. Broke early, time = %" PRIu64 "\n", test_id, simulated_time);
                    ret = -1;
                }
            }
        }
    }

    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }

    return ret;
}

int idle_timeout_test()
{
    int ret = 0;

    if ((ret = idle_timeout_test_one(1, 30000, 30000, 30000000)) == 0 &&
        (ret = idle_timeout_test_one(2, 60000, 20000, 20000000)) == 0 &&
        (ret = idle_timeout_test_one(3, 20000, 60000, 20000000)) == 0 &&
        (ret = idle_timeout_test_one(4, 5000, 300000, 5000000)) == 0 &&
        (ret = idle_timeout_test_one(5, 300000, 5000, 5000000)) == 0 &&
        (ret = idle_timeout_test_one(6, 0, 5000, 5000000)) == 0 &&
        (ret = idle_timeout_test_one(7, 0, 60000, 60000000)) == 0 &&
        (ret = idle_timeout_test_one(8, 5000, 0, 5000000)) == 0 &&
        (ret = idle_timeout_test_one(9, 60000, 0, 60000000)) == 0 &&
        (ret = idle_timeout_test_one(10, 0, 0, UINT64_MAX)) == 0) {
        DBG_PRINTF("%s", "All idle timeout tests pass.\n");
    }
    return ret;
}

/* Testing that connection attempt against a non responding server
 * finishes after the timeout value.
 */

int idle_server_test_one(uint8_t test_id, uint64_t client_timeout, uint64_t handshake_timeout, uint64_t expected_timeout)
{
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    uint64_t simulated_time = 0;
    uint64_t target_timeout;
    picoquic_connection_id_t initial_cid = { { 0x41, 0x9e, 0xc0, 0x99, 0, 0, 0, 0}, 8 };
    uint8_t send_buffer[PICOQUIC_MAX_PACKET_SIZE];
    int ret = 0;

    initial_cid.id[4] = test_id;

    /* derive target timeout form spec */
    target_timeout = handshake_timeout;
    if (handshake_timeout == 0) {
        target_timeout = client_timeout * 1000;
        if (client_timeout == 0) {
            target_timeout = PICOQUIC_MICROSEC_HANDSHAKE_MAX;
        }
    }

    /* Create the test context */
    if (ret == 0) {
        ret = tls_api_init_ctx_ex(&test_ctx, PICOQUIC_INTERNAL_TEST_VERSION_1,
            PICOQUIC_TEST_SNI, PICOQUIC_TEST_ALPN, &simulated_time, NULL, NULL, 0, 1, 0, &initial_cid);
    }

    /* Set the binlog */
    if (ret == 0) {
        picoquic_set_binlog(test_ctx->qclient, ".");
        /* Set the timeout */
        picoquic_set_default_idle_timeout(test_ctx->qclient, client_timeout);
        if (handshake_timeout > 0) {
            picoquic_set_default_handshake_timeout(test_ctx->qclient, handshake_timeout);
        }
        /* Directly set the timeout in the client parameters,
        because the connection context is already created */
        test_ctx->cnx_client->local_parameters.max_idle_timeout = client_timeout;
        /* Start the client */
        ret = picoquic_start_client_cnx(test_ctx->cnx_client);
    }

    /* Run a simulation loop -- the server never responds. */
    if (ret == 0) {
        int nb_trials = 0;
        while (ret == 0 && simulated_time < expected_timeout) {
            size_t send_length = 0;
            struct sockaddr_storage addr_to;
            struct sockaddr_storage addr_from;

            ret = picoquic_prepare_packet_ex(test_ctx->cnx_client, -1, simulated_time,
                send_buffer, sizeof(send_buffer), &send_length,
                &addr_to, &addr_from, 0, NULL);
            if (ret != 0) {
                break;
            }
            else if (test_ctx->cnx_client->cnx_state == picoquic_state_disconnected) {
                break;
            }
            else if (simulated_time > test_ctx->cnx_client->next_wake_time) {
                DBG_PRINTF("Idle server test %d. Bug, simulation is walking back in time.", test_id);
                ret = -1;
            }
            else if (nb_trials >= 512) {
                DBG_PRINTF("Idle server test %d. Bug, simulation exceeds %d steps.", test_id, nb_trials);
                ret = -1;
            }
            else {
                nb_trials++;
                simulated_time = test_ctx->cnx_client->next_wake_time;
            }
        }
    }

    if ((ret == 0 && test_ctx->cnx_client->cnx_state == picoquic_state_disconnected) ||
        ret == PICOQUIC_ERROR_DISCONNECTED) {
        if (simulated_time < target_timeout) {
            DBG_PRINTF("Idle server test %d. Client gave up too soon, time = %" PRIu64 "\n", test_id, simulated_time);
            ret = -1;
        }
        else {
            ret = 0;
        }
    }
    else if (ret == 0) {
        DBG_PRINTF("Idle server test %d. Client did not disconnect, time = %" PRIu64 "\n", test_id, simulated_time);
        ret = -1;
    }
    else {
        DBG_PRINTF("Idle server test %d. ret=0x%x, time = %" PRIu64 "\n", ret, test_id, simulated_time);
    }

    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }

    return ret;
}

int idle_server_test()
{
    int ret = 0;

    if ((ret = idle_server_test_one(1, 30000, 0, 30100000)) == 0 &&
        (ret = idle_server_test_one(2, 60000, 0, 60100000)) == 0 &&
        (ret = idle_server_test_one(3, 5000, 0, 5100000)) == 0 &&
        (ret = idle_server_test_one(4, 0, 0, 30100000)) == 0 &&
        (ret = idle_server_test_one(5, 0, 10000, 10100000)) == 0 &&
        (ret = idle_server_test_one(6, 20000, 60000, 60100000)) == 0 &&
        (ret = idle_server_test_one(7, 60000, 5000, 5100000)) == 0){
        DBG_PRINTF("%s", "All idle timeout tests pass.\n");
    }
    return ret;
}

/*
* Testing issues caused by frame events after a stream is reset.
* 
* We are concerned with possible errors when copies of "old"
* frames cause processing of a stream after the stream has been
* closed. This includes:
* 
* - reset stream frames,
* - stop sending frames,
* - max stream data frames.
* 
* We are concerned with three events:
* 
* - processing the ACK of a packet that contained the frame, because
*   the ACK may be received after the reset after the stream context
*   was deleted,
* - receiving extra copies of the frames after the stream is deleted.
*   These extra copies shall be ignored with no side effect.
* - processing of frames in packets detected as lost after the
*   stream was deleted. The stack whether the packets needs to
*   be repeated.
* 
* The combination of "ack/extra/need" with three frame types produces
* 9 possible tests. However, there is no acking processing for
* stop sending frames, so we do not implement a test for
* "reset_ack_stop_sending".
 */

typedef enum {
    reset_ack_max_stream = 0,
    reset_ack_reset,
    reset_ack_stop_sending,
    reset_extra_max_stream,
    reset_extra_reset,
    reset_extra_stop_sending,
    reset_need_max_stream,
    reset_need_reset,
    reset_need_stop_sending
} reset_test_enum;

static test_api_stream_desc_t test_scenario_edge_reset[] = {
    { 4, 0, 1000000, 1000000 }
};

int picoquic_process_ack_of_reset_stream_frame(picoquic_cnx_t* cnx, const uint8_t* bytes, size_t bytes_size, size_t* consumed);
int picoquic_process_ack_of_max_stream_data_frame(picoquic_cnx_t* cnx, const uint8_t* bytes,
    size_t bytes_size, size_t* consumed);

int reset_repeat_test_receive_frame(int test_id, picoquic_cnx_t * cnx, const uint8_t * frame, size_t frame_size,
    uint64_t simulated_time, uint64_t stream_id, int do_not_create)
{
    picoquic_stream_data_node_t dn;
    int ret = picoquic_decode_frames(cnx, cnx->path[0], frame, frame_size,
        &dn, picoquic_epoch_1rtt,
        (struct sockaddr*)&cnx->path[0]->peer_addr,
        (struct sockaddr*)&cnx->path[0]->local_addr,
        123, 0, simulated_time);

    if (ret != 0 || cnx->cnx_state > picoquic_state_ready) {
        DBG_PRINTF("Test %d. Error after stop sending, ret = 0x%x.", test_id, ret);
        ret = -1;
    }
    else if (ret == 0 && stream_id != UINT64_MAX && do_not_create && picoquic_find_stream(cnx, stream_id) != NULL) {
        DBG_PRINTF("Test %d. Stream %" PRIu64 " was created.", test_id, stream_id);
        ret = -1;
    }
    return ret;
}

int reset_repeat_test_need_repeat(int test_id, picoquic_cnx_t* cnx, const uint8_t* frame, size_t frame_size,
    uint64_t simulated_time, uint64_t stream_id, int do_not_create)
{
    int no_need_to_repeat = 0;
    int do_not_detect_spurious = 0;
    int is_preemptive_needed = 0;

    int ret = picoquic_check_frame_needs_repeat(cnx, frame, frame_size, picoquic_packet_1rtt_protected,
        &no_need_to_repeat, &do_not_detect_spurious, &is_preemptive_needed);

    if (ret != 0 || cnx->cnx_state > picoquic_state_ready || !no_need_to_repeat) {
        DBG_PRINTF("Test %d. Error after ack of frame 0x%x, ret = 0x%x.", test_id, frame[0], ret);
        ret = -1;
    }
    return ret;
}

int reset_loop_check_stream_opened(picoquic_test_tls_api_ctx_t* test_ctx, uint64_t data_stream_id)
{
    int is_opened = 0;
    if (test_ctx->cnx_client != NULL && test_ctx->cnx_server != NULL) {
        picoquic_stream_head_t* c_stream = picoquic_find_stream(test_ctx->cnx_client, data_stream_id);
        if (c_stream != NULL && c_stream->sent_offset > 10000) {
            picoquic_stream_head_t* s_stream = picoquic_find_stream(test_ctx->cnx_server, data_stream_id);
            if (s_stream != NULL) {
                is_opened = 1;
            }
        }
    }
    return is_opened;
}

int reset_loop_wait_stream_opened(picoquic_test_tls_api_ctx_t* test_ctx,
    uint64_t* simulated_time, uint64_t data_stream_id, uint64_t loop1_time)
{
    int ret = 0;
    int nb_inactive = 0;
    uint64_t time_out = *simulated_time + loop1_time;
    int was_active = 0;
    int is_opened = 0;

    while (ret == 0 && *simulated_time < time_out &&
        TEST_CLIENT_READY &&
        TEST_SERVER_READY &&
        nb_inactive < 64) {

        if (reset_loop_check_stream_opened(test_ctx, data_stream_id)) {
            is_opened = 1;
            break;
        }

        was_active = 0;

        ret = tls_api_one_sim_round(test_ctx, simulated_time, 0, &was_active);

        if (was_active) {
            nb_inactive = 0;
        }
        else {
            nb_inactive++;
        }
    }
    if (!is_opened) {
        ret = -1;
    }
    return ret;
}

int reset_repeat_test_one(uint8_t test_id)
{
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    uint64_t simulated_time = 0;
    uint64_t loss_mask = 0;
    uint64_t data_stream_id = 4;
    uint64_t loop1_time = 50000;
    uint64_t loop2_time = 1000000;
    picoquic_connection_id_t initial_cid = { { 0x8e, 0x5e, 0x48, 0xe9, 0, 0, 0, 0}, 8 };
    int ret = 0;
    uint8_t stop_sending_frame[3] = {
        (uint8_t)picoquic_frame_type_stop_sending,
        (uint8_t)data_stream_id,
        0x17 };
    uint8_t max_stream_data_frame[3] = {
        (uint8_t)picoquic_frame_type_max_stream_data,
        (uint8_t)data_stream_id,
        63 };
    uint8_t reset_frame[4] = {
        (uint8_t)picoquic_frame_type_reset_stream,
        (uint8_t)data_stream_id,
        1,
        1 };

    initial_cid.id[4] = test_id;

    /* Create the test context */
    if (ret == 0) {
        ret = tls_api_init_ctx_ex(&test_ctx, PICOQUIC_INTERNAL_TEST_VERSION_1,
            PICOQUIC_TEST_SNI, PICOQUIC_TEST_ALPN, &simulated_time, NULL, NULL, 0, 1, 0, &initial_cid);
    }

    /* Set the binlog */
    if (ret == 0) {
        picoquic_set_binlog(test_ctx->qclient, ".");
        ret = picoquic_start_client_cnx(test_ctx->cnx_client);
    }

    /* set the connection */
    if (ret == 0) {
        ret = tls_api_connection_loop(test_ctx, &loss_mask, 0, &simulated_time);
    }

    /* Prepare to send data */
    if (ret == 0) {
        ret = test_api_init_send_recv_scenario(test_ctx, test_scenario_edge_reset, sizeof(test_scenario_edge_reset));

        if (ret != 0)
        {
            DBG_PRINTF("Init send receive scenario returns %d\n", ret);
        }
    }

    /* Run for a short time, so the stream is created and the transfer started */
    if (ret == 0) {
        ret = reset_loop_wait_stream_opened(test_ctx, &simulated_time, data_stream_id, loop1_time);
        if (ret != 0) {
            DBG_PRINTF("Test #%d. Loop wait stream failed!", test_id);
            ret = -1;
        }
    }

    /* Verify that the stream #4 is present, and the
     * transmission has not stopped.
     */
    if (ret == 0 && (!(TEST_CLIENT_READY) || !(TEST_SERVER_READY))) {
        DBG_PRINTF("%s", "Server or client not ready!");
        ret = -1;
    }
    if (ret == 0) {
        picoquic_stream_head_t* stream = picoquic_find_stream(test_ctx->cnx_client, data_stream_id);
        if (stream == NULL || stream->fin_sent) {
            DBG_PRINTF("Waited too long, stream is %s\n", (stream == NULL) ? "deleted" : "finished");
            ret = -1;
        }
    }
    /* Reset the stream, then run the connection for a short time.
     */
    if (ret == 0) {
        ret = picoquic_reset_stream(test_ctx->cnx_client, data_stream_id, 0);
    }
    if (ret == 0) {
        ret = picoquic_reset_stream(test_ctx->cnx_server, data_stream_id, 0);
    }
    if (ret == 0) {
        int was_active = 0;
        int nb_inactive = 0;
        int client_stream_gone = 0;
        uint64_t time_out = simulated_time + loop2_time;
        while (ret == 0 && simulated_time < time_out &&
            TEST_CLIENT_READY &&
            TEST_SERVER_READY &&
            nb_inactive < 64) {
            was_active = 0;

            ret = tls_api_one_sim_round(test_ctx, &simulated_time, time_out, &was_active);

            if (was_active) {
                nb_inactive = 0;
            }
            else {
                nb_inactive++;
            }
            if (picoquic_find_stream(test_ctx->cnx_client, data_stream_id) == NULL) {
                client_stream_gone = 1;
                break;
            }
        }
        if (!client_stream_gone) {
            DBG_PRINTF("%s", "Did not wait long enough, stream is still there.");
            ret = -1;
        }
    }
    /* Perform the specified test.
     */
    switch (test_id) {
    case reset_ack_max_stream: {
        size_t consumed = 0;
        ret = picoquic_process_ack_of_max_stream_data_frame(test_ctx->cnx_client, reset_frame, sizeof(reset_frame), &consumed);

        if (ret != 0 || test_ctx->cnx_client->cnx_state > picoquic_state_ready) {
            DBG_PRINTF("Test %d. Error after ack of max stream, ret = 0x%x.", test_id, ret);
            ret = -1;
        }
        break;
    }
    case reset_ack_reset:/* spurious ack of reset frame. */ {
        size_t consumed = 0;
        ret = picoquic_process_ack_of_reset_stream_frame(test_ctx->cnx_client, reset_frame, sizeof(reset_frame), &consumed);

        if (ret != 0 || test_ctx->cnx_client->cnx_state > picoquic_state_ready) {
            DBG_PRINTF("Test %d. Error after ack of reset, ret = 0x%x.", test_id, ret);
            ret = -1;
        }
        break;
    }
    case reset_ack_stop_sending:
        /* TODO: there is no code yet for processing acks of stop sending frame. */
        ret = -1;
        break;
    case reset_extra_max_stream:
        /* arrival of stream related frame on a non existing stream.
        * this is a bit more subtle than the ACK test.
        * - if this is a remotely created stream:
        *     - if it is bidir, this could be an out of order request to
        *       not send response, or it could be an old stream that was
        *       already deleted.
        *     - if it is monodir, it does not make sense.
        * - if it is locally created:
        *     - if it is closed, just ignore it.
        *     - if it is not created yet, this is a protocol error.
        */
        ret = reset_repeat_test_receive_frame(test_id, test_ctx->cnx_client, max_stream_data_frame, sizeof(max_stream_data_frame),
            simulated_time, data_stream_id, 1);
        break;
    case reset_extra_reset:
        /* arrival of extra reset frame.
        * see, arrival of stop sending.
        */
        ret = reset_repeat_test_receive_frame(test_id, test_ctx->cnx_client, reset_frame, sizeof(reset_frame),
            simulated_time, data_stream_id, 1);
        break;
    case reset_extra_stop_sending:
        ret = reset_repeat_test_receive_frame(test_id, test_ctx->cnx_client, stop_sending_frame, sizeof(stop_sending_frame),
            simulated_time, data_stream_id, 1);
        break;
    case reset_need_max_stream:
        /* Check whether a frame needs to be repeated.
        * this should never cause an error! If the stream is not
        * there any more, this means the original reset was
        * successful, there is no need to resend it.
        */
        ret = reset_repeat_test_need_repeat(test_id, test_ctx->cnx_client, max_stream_data_frame, sizeof(max_stream_data_frame),
            simulated_time, data_stream_id, 1);
        break;
    case reset_need_reset:
        ret = reset_repeat_test_need_repeat(test_id, test_ctx->cnx_client, reset_frame, sizeof(reset_frame),
            simulated_time, data_stream_id, 1);
        break;
    case reset_need_stop_sending:
        ret = reset_repeat_test_need_repeat(test_id, test_ctx->cnx_client, stop_sending_frame, sizeof(stop_sending_frame),
            simulated_time, data_stream_id, 1);
        break;
    default:
        DBG_PRINTF("What test is that: %d?", test_id);
        ret = -1;
        break;
    }

    /* Clean up */
    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }

    return ret;
}

int reset_ack_max_test()
{
    return reset_repeat_test_one(reset_ack_max_stream);
}

int reset_ack_reset_test()
{
    return reset_repeat_test_one(reset_ack_reset);
}

int reset_extra_max_test()
{
    return reset_repeat_test_one(reset_extra_max_stream);
}

int reset_extra_reset_test()
{
    return reset_repeat_test_one(reset_extra_reset);
}

int reset_extra_stop_test()
{
    return reset_repeat_test_one(reset_extra_stop_sending);
}

int reset_need_max_test()
{
    return reset_repeat_test_one(reset_need_max_stream);
}

int reset_need_reset_test()
{
    return reset_repeat_test_one(reset_need_reset);
}

int reset_need_stop_test()
{
    return reset_repeat_test_one(reset_need_stop_sending);
}

/*
* Initial PTO test:
* Test the scenario in which:
* - the client sends an initial message
* - the server sends an ACK
* - no further packets from the server, either because they are lost
*   or because the server is hitting the amplification limit.
* Verify that the client sends a message after a PTO commensurate
* with the RTT.
*/

int initial_pto_prepare(picoquic_test_tls_api_ctx_t* test_ctx, uint64_t* p_simulated_time,
    size_t *length)
{
    int ret = 0;
    uint8_t buf[PICOQUIC_MAX_PACKET_SIZE];
    struct sockaddr_storage addr_to;
    struct sockaddr_storage addr_from;
    int path_id = -1;

    ret = picoquic_prepare_packet(test_ctx->cnx_client, *p_simulated_time,
        buf, PICOQUIC_MAX_PACKET_SIZE, length,
        &addr_to, &addr_from, NULL);

    if (ret == 0) {
        /* Submit initial packet to server context, so we get the
         * crypto context created */
        ret = picoquic_incoming_packet_ex(test_ctx->qserver, buf, *length, 
            (struct sockaddr*)&addr_from, (struct sockaddr*)&addr_to, 0, 0,
            &test_ctx->cnx_server, &path_id, *p_simulated_time);
        if (ret == 0 && test_ctx->cnx_server == NULL) {
            ret = -1;
        }
    }
    return ret;
}

int initial_pto_wait(picoquic_test_tls_api_ctx_t* test_ctx, uint64_t* p_simulated_time,
    uint64_t max_wait, size_t* length_sent)
{
    int ret = 0;
    size_t length = 0;
    *length_sent = 0;
    while (ret == 0 && *p_simulated_time < max_wait) {
        uint64_t client_departure = test_ctx->cnx_client->next_wake_time;

        if (client_departure >= max_wait) {
            *p_simulated_time = max_wait;
            break;
        }
        else {
            if (*p_simulated_time < client_departure) {
                *p_simulated_time = client_departure;
            }
            ret = initial_pto_prepare(test_ctx, p_simulated_time, &length);
            if (length > 0 || test_ctx->cnx_client->cnx_state >= picoquic_state_handshake_failure) {
                *length_sent = length;
                break;
            }
        }
    }
    return ret;
}

int initial_pto_ack(picoquic_test_tls_api_ctx_t* test_ctx, uint64_t* p_simulated_time)
{
    int ret = 0;
    uint8_t buf[PICOQUIC_INITIAL_MTU_IPV6];
    uint8_t send_buffer[PICOQUIC_MAX_PACKET_SIZE];
    picoquic_packet_type_enum packet_type = picoquic_packet_initial;
    picoquic_packet_context_enum pc = picoquic_packet_context_initial;
    size_t checksum_overhead = 16;
    uint8_t * bytes_max = buf + PICOQUIC_INITIAL_MTU_IPV6 - checksum_overhead;
    uint8_t* bytes_next = buf;
    size_t length = 0;
    size_t header_length = 0;
    int more_data = 0;
    size_t send_length = 0;
    /* Format the header */
    header_length = picoquic_predict_packet_header_length(test_ctx->cnx_server, packet_type,
        &test_ctx->cnx_server->pkt_ctx[pc]);
    bytes_next += header_length;
    /* add ack, function of client sequence number */
    bytes_next = picoquic_format_ack_frame(test_ctx->cnx_server, bytes_next, bytes_max, &more_data,
        *p_simulated_time, pc, 0);
    /* add padding to minimum length */
    length = picoquic_pad_to_target_length(buf, bytes_next - buf,
        PICOQUIC_INITIAL_MTU_IPV6 - checksum_overhead);

    /* Finalize */
    send_length = picoquic_protect_packet(test_ctx->cnx_server, packet_type, buf, 0,
        length, header_length,
        send_buffer, PICOQUIC_MAX_PACKET_SIZE, 
        test_ctx->cnx_server->crypto_context[picoquic_epoch_initial].aead_encrypt,
        test_ctx->cnx_server->crypto_context[picoquic_epoch_initial].pn_enc,
        test_ctx->cnx_server->path[0], *p_simulated_time);
    /* Submit to client. */
    if (send_length == 0) {
        ret = -1;
    }
    else {
        picoquic_cnx_t* last_cnx = NULL;
        int path_id = -1;
        ret = picoquic_incoming_packet_ex(test_ctx->qclient, send_buffer, send_length,
            (struct sockaddr*)&test_ctx->server_addr, (struct sockaddr*)&test_ctx->client_addr, 0, 0,
            &last_cnx, &path_id, *p_simulated_time);
    }
    return ret;
}

int initial_pto_test()
{
    int ret = 0;
    picoquic_test_tls_api_ctx_t *test_ctx = NULL;
    size_t length = 0;
    uint64_t simulated_time = 0;
    uint64_t simulated_rtt = 20000;
    uint64_t simulated_pto = 4*simulated_rtt;
    picoquic_connection_id_t initial_cid = { { 0x94, 0x01, 0x41, 0, 0, 0, 0, 0}, 8 };

    /* Create a client. */
    ret = tls_api_init_ctx_ex(&test_ctx, PICOQUIC_INTERNAL_TEST_VERSION_1,
            PICOQUIC_TEST_SNI, PICOQUIC_TEST_ALPN, &simulated_time, NULL, NULL, 0, 1, 0, &initial_cid);
    if (ret != 0) {
        DBG_PRINTF("Cannot initialize context, ret = 0x%x", ret);
    }
    else {
        /* Set the binlog */
        picoquic_set_binlog(test_ctx->qclient, ".");
        /* start the client connection */
        ret = picoquic_start_client_cnx(test_ctx->cnx_client);
    }
    /* Send the initial packet */
    if (ret == 0) {
        ret = initial_pto_prepare(test_ctx, &simulated_time, &length);
        if (ret == 0 && length < 1200) {
            length = -1;
        }
    }
    /* get the initial message, wait until next client time >= time of ACK */
    if (ret == 0 && simulated_time < 20000) {
        ret = initial_pto_wait(test_ctx, &simulated_time, simulated_rtt, &length);
    }
    /* format an ACK packet, apply initial protection, submit ACK to client */
    if (ret == 0) {
        ret = initial_pto_ack(test_ctx, &simulated_time);
    }
    /* Wait until next client time >= expected response, or
     * client is ready to send and does send. */
    if (ret == 0 && simulated_time < simulated_pto) {
        ret = initial_pto_wait(test_ctx, &simulated_time, simulated_pto, &length);
        if (ret == 0 && length < 1200) {
            /* Did not send the PTO */
            ret = -1;
        }
    }
    /* Clean up */
    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }

    return ret;
}

/* Skip through packets, document types and next pointer */
const uint8_t* v1_header_skip(const uint8_t* bytes, const uint8_t* bytes_max, picoquic_packet_type_enum* ptype)
{
    uint8_t first_byte = *bytes++;

    *ptype = picoquic_packet_error;

    if ((first_byte & 0x80) == 0) {
        bytes = bytes_max;
        *ptype = picoquic_packet_1rtt_protected;
    }
    else {
        uint8_t lcid;
        if (bytes + 5 > bytes_max) {
            bytes = NULL;
        }
        else {
            bytes += 4; /* skip version */
            lcid = *bytes++;
            bytes = picoquic_frames_fixed_skip(bytes, bytes_max, lcid);

            if (bytes == NULL || bytes + 1 >= bytes_max) {
                bytes = NULL;
            }
            else {
                lcid = *bytes++;
                bytes = picoquic_frames_fixed_skip(bytes, bytes_max, lcid);
            }
        }
        if (bytes != NULL) {
            /* The next part is not version invariant. We assume v1 */
            int p_type_number = ((first_byte) >> 4) & 3;
            /* int number_length = ((first_byte) & 3) + 1; */
            uint64_t length = 0;
            uint64_t token_length = 0;

            if (p_type_number == 0) {
                *ptype = picoquic_packet_initial;
                if ((bytes = picoquic_frames_varint_decode(bytes, bytes_max, &token_length)) != NULL &&
                    (bytes = picoquic_frames_fixed_skip(bytes, bytes_max, token_length)) != NULL &&
                    (bytes = picoquic_frames_varint_decode(bytes, bytes_max, &length)) != NULL /* &&
                    (bytes = picoquic_frames_fixed_skip(bytes, bytes_max, number_length)) != NULL */) {
                    bytes = picoquic_frames_fixed_skip(bytes, bytes_max, length);
                }
            }
            else if (p_type_number == 2) {
                *ptype = picoquic_packet_handshake;
                if ((bytes = picoquic_frames_varint_decode(bytes, bytes_max, &length)) != NULL /* &&
                    (bytes = picoquic_frames_fixed_skip(bytes, bytes_max, number_length)) != NULL */) {
                    bytes = picoquic_frames_fixed_skip(bytes, bytes_max, length);
                }
            }
            else {
                /* unexpected in our scenario */
                bytes = NULL;
            }
        }
    }
    return bytes;
}


/* test that when the initial packet is repeated, a handshake is included */
int pto_server_prepare(picoquic_test_tls_api_ctx_t* test_ctx, uint64_t simulated_time, int * has_packet, int* has_initial, int* has_handshake)
{
    int ret = 0;
    uint8_t buf[PICOQUIC_MAX_PACKET_SIZE];
    struct sockaddr_storage addr_to;
    struct sockaddr_storage addr_from;
    size_t length;

    ret = picoquic_prepare_packet(test_ctx->cnx_server, simulated_time,
        buf, PICOQUIC_MAX_PACKET_SIZE, &length,
        &addr_to, &addr_from, NULL);
    if (ret == 0 && length > 0) {
        *has_packet = 1;
        const uint8_t* bytes = buf;
        const uint8_t* bytes_max = buf + length;

        while (bytes < bytes_max) {
            picoquic_packet_type_enum ptype;
            if ((bytes = v1_header_skip(bytes, bytes_max, &ptype)) == NULL) {
                break;
            }
            else {
                if (ptype == picoquic_packet_initial) {
                    *has_initial = 1;
                }
                else if (ptype == picoquic_packet_handshake) {
                    *has_handshake = 1;
                }
            }
        }
    }
    return ret;
}

int initial_pto_srv_test()
{
    int ret = 0;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    size_t length = 0;
    int has_packet;
    int has_initial;
    int has_handshake;
    uint64_t simulated_time = 0;
    picoquic_connection_id_t initial_cid = { { 0x94, 0x01, 0x85, 0, 0, 0, 0, 0}, 8 };

    /* Create a client. */
    ret = tls_api_init_ctx_ex(&test_ctx, PICOQUIC_INTERNAL_TEST_VERSION_1,
        PICOQUIC_TEST_SNI, PICOQUIC_TEST_ALPN, &simulated_time, NULL, NULL, 0, 1, 0, &initial_cid);
    if (ret != 0) {
        DBG_PRINTF("Cannot initialize context, ret = 0x%x", ret);
    }
    else {
        /* Set the binlog */
        picoquic_set_binlog(test_ctx->qserver, ".");
        /* start the client connection */
        ret = picoquic_start_client_cnx(test_ctx->cnx_client);
    }
    /* Send the initial packet */
    if (ret == 0) {
        ret = initial_pto_prepare(test_ctx, &simulated_time, &length);
        if (ret == 0 && length < 1200) {
            length = -1;
        }
    }
    if (ret == 0) {
        /* pretend that the address is validated, so the server sends ACKS, etc. */
        test_ctx->cnx_server->initial_validated = 1;
        /* Set the time to server next wake. */
        simulated_time = picoquic_get_next_wake_time(test_ctx->qserver, simulated_time);
        has_initial = 0;
        has_handshake = 0;
        /* Get the first flight. */
        do {
            has_packet = 0;
            ret = pto_server_prepare(test_ctx, simulated_time, &has_packet, &has_initial, &has_handshake);
        } while (ret == 0 && has_packet);
    }

    /* verify that the packet has Initial and Handshake */
    if (ret == 0) {
        /* Set the time to server next wake. */
        has_initial = 0;
        has_handshake = 0;
        simulated_time = picoquic_get_next_wake_time(test_ctx->qserver, simulated_time);
        /* Get the PTO. */
        do {
            has_packet = 0;
            ret = pto_server_prepare(test_ctx, simulated_time, &has_packet, &has_initial, &has_handshake);
        } while (ret == 0 && has_packet);

        if (ret == 0 && !(has_initial && has_handshake)) {
            /* Bug. The server out to repeat both the initial packet and some handshake packet */
            ret = -1;
        }
    }

    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }

    return ret;
}


/* Test of out of order crypto packets.
* We test that by injecting a crypto handshake frame with an
* offset of 64K in the crypto context. There will be three tests,
* for initial, handshake and 1 rtt contexts.
 */


int crypto_hs_offset_test_one(picoquic_packet_context_enum pc)
{
    int ret = 0;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    uint64_t simulated_time = 0;
    picoquic_connection_id_t initial_cid = { { 0xC0, 0xFF, 0x5E, 0x40, 0, 0, 0, 0}, 8 };
    uint8_t bad_crypto_hs[] = { picoquic_frame_type_crypto_hs, 0x80, 0x01, 0, 0, 4, 1, 2, 3, 4 };

    initial_cid.id[4] = (uint8_t)pc;

    /* Create a client. */
    ret = tls_api_init_ctx_ex(&test_ctx, PICOQUIC_INTERNAL_TEST_VERSION_1,
        PICOQUIC_TEST_SNI, PICOQUIC_TEST_ALPN, &simulated_time, NULL, NULL, 0, 1, 0, &initial_cid);
    if (ret != 0) {
        DBG_PRINTF("Cannot initialize context, ret = 0x%x", ret);
    }
    else {
        /* Set the binlog */
        picoquic_set_binlog(test_ctx->qserver, ".");
        /* start the client connection */
        ret = picoquic_start_client_cnx(test_ctx->cnx_client);
    }

    if (ret == 0) {
        /* Inject the  made up packet */
        ret = picoquic_queue_misc_frame(test_ctx->cnx_client, bad_crypto_hs, sizeof(bad_crypto_hs), 1, pc);
    }


    /* Try to establish the connection */
    if (ret == 0) {
        if (wait_client_connection_ready(test_ctx, &simulated_time) == 0) {
            if (test_ctx->cnx_server != NULL) {
                if (test_ctx->cnx_server->cnx_state != picoquic_state_handshake_failure &&
                    test_ctx->cnx_server->cnx_state < picoquic_state_disconnecting) {
                    /* Should wait for ready state */
                    DBG_PRINTF("Unexpected success, pc=%d\n", pc);
                    ret = -1;
                }
            }
        }
    }

    if (ret == 0 && test_ctx->cnx_client->remote_error != PICOQUIC_TRANSPORT_CRYPTO_BUFFER_EXCEEDED) {
        DBG_PRINTF("For pc=%d, expected error 0x%x, got 0x%x\n", pc,
            PICOQUIC_TRANSPORT_CRYPTO_BUFFER_EXCEEDED, test_ctx->cnx_client->remote_error);
        ret = -1;
    }

    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }

    return ret;
}

int crypto_hs_offset_test()
{
    picoquic_packet_context_enum pc[] = { picoquic_packet_context_initial,
        picoquic_packet_context_handshake, picoquic_packet_context_application };
    size_t nb_pc = sizeof(pc) / sizeof(picoquic_packet_context_enum);
    int ret = 0;

    for (size_t i = 0; i < nb_pc && ret == 0; i++) {
        ret = crypto_hs_offset_test_one(pc[i]);
    }

    return ret;
}