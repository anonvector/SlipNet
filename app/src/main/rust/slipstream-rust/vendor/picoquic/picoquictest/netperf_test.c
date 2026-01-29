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

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <picotls.h>
#include "picoquic.h"
#include "picoquic_utils.h"
#include "picoquic_internal.h"
#include "tls_api.h"
#include "picoquictest_internal.h"
#ifdef _WINDOWS
#include "wincompat.h"
#else
#include <signal.h>
#endif

/* Test the coalesced Send API.
 * The simulation here involves:
 * - simulating the coalesced send implementation,
 * - filing each of the cooalesced packets as separate 
 *   packets on the link.
 * - (TODO) simulating the coalesced receive by packing
 *   consecutive packets in a receive folder, modulo 
 *   arrival time.
 * - Getting statistics on the effectiveness of the
 *   coalescing process.
 */
int netperf_next_arrival(picoquictest_sim_link_t * link, picoquic_quic_t * quic, uint64_t simulated_time, int* was_active,
    struct sockaddr * srce_addr)
{
    /* TODO: simulate accumulating packets when queue building up at receiver. */
    int ret = 0;

    /* If there is something to receive, do it now */
    picoquictest_sim_packet_t* packet = picoquictest_sim_link_dequeue(link, simulated_time);

    if (packet != NULL) {
        *was_active = 1;

        if (packet->addr_from.ss_family == 0) {
            picoquic_store_addr(&packet->addr_from, srce_addr);
        }

        ret = picoquic_incoming_packet(quic, packet->bytes, (uint32_t)packet->length,
            (struct sockaddr*) & packet->addr_from,
            (struct sockaddr*) & packet->addr_to, 0, 0, simulated_time);

        if (ret != 0)
        {
            /* useless test, but makes it easier to add a breakpoint under debugger */
            ret = -1;
        }

        free(packet);
    }

    return ret;
}

int netperf_next_departure(picoquic_quic_t* quic, picoquictest_sim_link_t* target_link, uint64_t simulated_time, int* was_active,
    uint8_t* send_buffer, size_t send_buffer_size)
{
    int ret = 0;
    int if_index = 0;
    picoquic_connection_id_t log_cid;
    picoquic_cnx_t * last_cnx = NULL;
    picoquictest_sim_packet_t* packet = picoquictest_sim_link_create_packet();

    if (packet == NULL) {
        ret = -1;
    }
    else  if (send_buffer == NULL) {
        ret = picoquic_prepare_next_packet(quic, simulated_time,
            packet->bytes, PICOQUIC_MAX_PACKET_SIZE, &packet->length,
            &packet->addr_to, &packet->addr_from, &if_index, &log_cid, &last_cnx);
        /* TODO: simulate losses. */
        if (packet->length > 0) {
            *was_active = 1;
            picoquictest_sim_link_submit(target_link, packet, simulated_time);
            packet = NULL;
        }
    }
    else {
        /* Try coalescing multiple packets */
        size_t send_length = 0;
        size_t send_msg_size = 0;
        size_t sent_so_far = 0;

        ret = picoquic_prepare_next_packet_ex(quic, simulated_time,
            send_buffer, send_buffer_size, &send_length,
            &packet->addr_to, &packet->addr_from, &if_index, &log_cid, &last_cnx, &send_msg_size);

        if (send_msg_size > PICOQUIC_MAX_PACKET_SIZE ||
            send_length > send_buffer_size) {
            ret = -1;
        }

        while (ret == 0 && send_msg_size > 0 && sent_so_far + send_msg_size < send_length) {
            picoquictest_sim_packet_t* coal_packet = picoquictest_sim_link_create_packet();
            if (coal_packet == NULL) {
                ret = -1;
            }
            else {
                *was_active = 1;
                picoquic_store_addr(&coal_packet->addr_from, (struct sockaddr*) & packet->addr_from);
                picoquic_store_addr(&coal_packet->addr_to, (struct sockaddr*) & packet->addr_to);
                coal_packet->length = send_msg_size;
                memcpy(coal_packet->bytes, send_buffer + sent_so_far, send_msg_size);
                sent_so_far += coal_packet->length;
                picoquictest_sim_link_submit(target_link, coal_packet, simulated_time);
            }
        }

        if (ret == 0 && sent_so_far < send_length) {
            packet->length = send_length - sent_so_far;
            *was_active = 1;
            memcpy(packet->bytes, send_buffer + sent_so_far, packet->length);
            picoquictest_sim_link_submit(target_link, packet, simulated_time);
            packet = NULL;
        }
    }

    if (packet != NULL) {
        free(packet);
    }

    return ret;
}

int netperf_step(picoquic_test_tls_api_ctx_t* test_ctx, uint64_t * simulated_time, int * was_active,
    uint8_t * send_buffer, size_t send_buffer_size)
{
    int ret = 0;
    int next_action = -1;
    uint64_t next_time = UINT64_MAX;
    uint64_t action_time;

    *was_active = 0;

    if ((action_time = picoquictest_sim_link_next_arrival(test_ctx->s_to_c_link, next_time)) < next_time) {
        next_action = 0;
        next_time = action_time;
    }

    if ((action_time = picoquictest_sim_link_next_arrival(test_ctx->c_to_s_link, next_time)) < next_time) {
        next_action = 1;
        next_time = action_time;
    }

    if ((action_time = picoquic_get_next_wake_time(test_ctx->qclient, *simulated_time)) < next_time) {
        next_action = 2;
        next_time = action_time;
    }

    if ((action_time = picoquic_get_next_wake_time(test_ctx->qserver, *simulated_time)) < next_time) {
        next_action = 3;
        next_time = action_time;
    }

    if (next_time == UINT64_MAX) {
        /* No more action possible */
        ret = -1;
    }
    else {
        if (next_time > *simulated_time) {
            *simulated_time = next_time;
        }

        switch (next_action) {
        case 0:
            ret = netperf_next_arrival(test_ctx->s_to_c_link, test_ctx->qclient, *simulated_time, was_active,
                (struct sockaddr *)&test_ctx->server_addr);
            break;
        case 1:
            ret = netperf_next_arrival(test_ctx->c_to_s_link, test_ctx->qserver, *simulated_time, was_active,
                (struct sockaddr*) & test_ctx->client_addr);
            if (test_ctx->cnx_server == NULL) {
                test_ctx->cnx_server = test_ctx->qserver->cnx_list;
            }
            break;
        case 2:
            ret = netperf_next_departure(test_ctx->qclient, test_ctx->c_to_s_link, *simulated_time, was_active, send_buffer, send_buffer_size);
            break;
        case 3:
            ret = netperf_next_departure(test_ctx->qserver, test_ctx->s_to_c_link, *simulated_time, was_active, send_buffer, send_buffer_size);
            break;
        default:
            ret = -1;
            break;
        }
    }

    return ret;
}

/* Connection loop with large packets */
int netperf_connection_loop(picoquic_test_tls_api_ctx_t* test_ctx,
    uint64_t* loss_mask, uint64_t queue_delay_max, uint64_t* simulated_time,
    uint8_t* send_buffer, size_t send_buffer_size)
{
    int ret = 0;
    int nb_trials = 0;
    int nb_inactive = 0;

    test_ctx->c_to_s_link->loss_mask = loss_mask;
    test_ctx->s_to_c_link->loss_mask = loss_mask;

    test_ctx->c_to_s_link->queue_delay_max = queue_delay_max;
    test_ctx->s_to_c_link->queue_delay_max = queue_delay_max;

    while (ret == 0 && nb_trials < 1024 && nb_inactive < 512 && (!TEST_CLIENT_READY || (test_ctx->cnx_server == NULL || !TEST_SERVER_READY))) {
        int was_active = 0;
        nb_trials++;

        ret = netperf_step(test_ctx, simulated_time, &was_active, send_buffer, send_buffer_size);

        if (test_ctx->cnx_client->cnx_state == picoquic_state_disconnected &&
            (test_ctx->cnx_server == NULL || test_ctx->cnx_server->cnx_state == picoquic_state_disconnected)) {
            break;
        }

        if (nb_trials == 512) {
            DBG_PRINTF("After %d trials, client state = %d, server state = %d",
                nb_trials, (int)test_ctx->cnx_client->cnx_state,
                (test_ctx->cnx_server == NULL) ? -1 : test_ctx->cnx_server->cnx_state);
        }

        if (was_active) {
            nb_inactive = 0;
        }
        else {
            nb_inactive++;
        }
    }

    return ret;
}

int netperf_scenario_body_connect(picoquic_test_tls_api_ctx_t* test_ctx,
    uint64_t* simulated_time, size_t stream0_target, uint64_t max_data, uint64_t queue_delay_max,
    uint8_t* send_buffer, size_t send_buffer_size)
{
    uint64_t loss_mask = 0;
    int ret = picoquic_start_client_cnx(test_ctx->cnx_client);

    if (ret != 0)
    {
        DBG_PRINTF("%s", "Could not initialize connection for the client\n");
    }
    else {
        ret = netperf_connection_loop(test_ctx, &loss_mask, queue_delay_max, simulated_time, send_buffer, send_buffer_size);

        if (ret != 0)
        {
            DBG_PRINTF("Connection loop returns error %d\n", ret);
        }
    }

    if (ret == 0 && max_data != 0) {
        test_ctx->cnx_client->maxdata_local = max_data;
        test_ctx->cnx_client->maxdata_remote = max_data;
        test_ctx->cnx_server->maxdata_local = max_data;
        test_ctx->cnx_server->maxdata_remote = max_data;
    }

    return ret;
}

int netperf_data_sending_loop(picoquic_test_tls_api_ctx_t* test_ctx,
    uint64_t* loss_mask, uint64_t* simulated_time, int max_trials,
    uint8_t* send_buffer, size_t send_buffer_size)
{
    int ret = 0;
    int nb_trials = 0;
    int nb_inactive = 0;

    test_ctx->c_to_s_link->loss_mask = loss_mask;
    test_ctx->s_to_c_link->loss_mask = loss_mask;

    if (max_trials <= 0) {
        max_trials = 4000000;
    }

    while (ret == 0 && nb_trials < max_trials && nb_inactive < 256 && TEST_CLIENT_READY && TEST_SERVER_READY) {
        int was_active = 0;

        nb_trials++;

        ret = netperf_step(test_ctx, simulated_time, &was_active, send_buffer, send_buffer_size);

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

        if (test_ctx->test_finished) {
            if (picoquic_is_cnx_backlog_empty(test_ctx->cnx_client) && picoquic_is_cnx_backlog_empty(test_ctx->cnx_server)) {
                break;
            }
        }
    }

    return ret; /* end of sending loop */
}

static int netperf_attempt_to_close(
    picoquic_test_tls_api_ctx_t* test_ctx, uint64_t* simulated_time,
    uint8_t* send_buffer, size_t send_buffer_size)
{
    int ret = 0;
    int nb_rounds = 0;

    ret = picoquic_close(test_ctx->cnx_client, 0);

    if (ret == 0) {
        /* packet from client to server */
        /* Do not simulate losses there, as there is no way to correct them */

        test_ctx->c_to_s_link->loss_mask = 0;
        test_ctx->s_to_c_link->loss_mask = 0;

        while (ret == 0 && (test_ctx->cnx_client->cnx_state != picoquic_state_disconnected || test_ctx->cnx_server->cnx_state != picoquic_state_disconnected) && nb_rounds < 100000) {
            int was_active = 0;
            ret = netperf_step(test_ctx, simulated_time, &was_active, send_buffer, send_buffer_size);
            nb_rounds++;
        }
    }

    if (ret == 0 && (test_ctx->cnx_client->cnx_state != picoquic_state_disconnected || test_ctx->cnx_server->cnx_state != picoquic_state_disconnected)) {
        ret = -1;
    }

    return ret;
}

/* Test a connection scenario, using large send buffers */
int netperf_one_scenario(test_api_stream_desc_t* scenario,
    size_t sizeof_scenario, picoquic_congestion_algorithm_t * cc_algo, size_t stream0_target,
    uint64_t init_loss_mask, uint64_t max_data, uint64_t queue_delay_max,
    uint32_t proposed_version, uint64_t max_completion_microsec,
    picoquic_tp_t* client_params, picoquic_tp_t* server_params,
    size_t send_buffer_size)
{
    uint64_t simulated_time = 0;
    uint64_t loss_mask;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    uint8_t* send_buffer = NULL;

    int ret = tls_api_one_scenario_init(&test_ctx, &simulated_time,
        proposed_version, client_params, server_params);

    if (ret == 0 && send_buffer_size > 0) {
        send_buffer = (uint8_t*)malloc(send_buffer_size);
        if (send_buffer == 0) {
            ret = -1;
        }
    }

    if (ret == 0 && cc_algo != NULL) {
        test_ctx->qserver->padding_multiple_default = 128;
        test_ctx->qclient->padding_multiple_default = 128;
        picoquic_set_packet_train_mode(test_ctx->qserver, 1);
        picoquic_set_packet_train_mode(test_ctx->qclient, 1);
        picoquic_set_default_congestion_algorithm(test_ctx->qserver, cc_algo);
        picoquic_set_congestion_algorithm(test_ctx->cnx_client, cc_algo);
    }

    if (ret == 0) {
        ret = netperf_scenario_body_connect(test_ctx, &simulated_time, stream0_target,
            max_data, queue_delay_max, send_buffer, send_buffer_size);

        /* Prepare to send data */
        if (ret == 0) {
            test_ctx->stream0_target = stream0_target;
            loss_mask = init_loss_mask;
            ret = test_api_init_send_recv_scenario(test_ctx, scenario, sizeof_scenario);

            if (ret != 0)
            {
                DBG_PRINTF("Init send receive scenario returns %d\n", ret);
            }
        }

        /* Perform a data sending loop */
        if (ret == 0) {
            ret = netperf_data_sending_loop(test_ctx, &loss_mask, &simulated_time, 0, send_buffer, send_buffer_size);

            if (ret != 0)
            {
                DBG_PRINTF("Data sending loop returns %d\n", ret);
            }
        }

        if (ret == 0) {
            uint64_t close_time = 0;
            ret = tls_api_one_scenario_verify(test_ctx);

            if (ret == 0) {
                if (test_ctx->cnx_server == NULL) {
                    DBG_PRINTF("%s", "Cannot check server stats\n");
                    ret = -1;
                }
                else if ((3* test_ctx->cnx_server->nb_trains_sent)/2 > test_ctx->cnx_server->nb_packets_sent) {
                    DBG_PRINTF("Datagram coalescing fails, %" PRIu64 " trains for %" PRIu64 "packets\n",
                        test_ctx->cnx_server->nb_trains_sent, test_ctx->cnx_server->nb_packets_sent);
                    ret = -1;
                }
                else if (20 * test_ctx->cnx_server->nb_retransmission_total > test_ctx->cnx_server->nb_packets_sent) {
                    DBG_PRINTF("Too many losses, %" PRIu64 " losses for %" PRIu64 "packets\n",
                        test_ctx->cnx_server->nb_retransmission_total, test_ctx->cnx_server->nb_packets_sent);
                    ret = -1;

                }
            }

            if (ret == 0) {
                close_time = simulated_time;
                netperf_attempt_to_close(test_ctx, &simulated_time, send_buffer, send_buffer_size);
                if (ret != 0)
                {
                    DBG_PRINTF("Attempt to close returns %d\n", ret);
                }
            }

            if (ret == 0 && max_completion_microsec != 0) {
                uint64_t completion_time = close_time - test_ctx->cnx_client->start_time;
                if (completion_time > max_completion_microsec)
                {
                    DBG_PRINTF("Scenario completes in %llu microsec, more than %llu\n",
                        (unsigned long long)completion_time, (unsigned long long)max_completion_microsec);
                    ret = -1;
                }
            }
        }
    }

    if (send_buffer != NULL) {
        free(send_buffer);
    }

    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }

    return ret;
}

static test_api_stream_desc_t netperf_scenario_basic[] = {
    { 4, 0, 257, 1000000 }
};

int netperf_basic_test()
{
    int ret = netperf_one_scenario(netperf_scenario_basic, sizeof(netperf_scenario_basic),
        NULL,
        0, 0, 0, 0, 0, 1000000, NULL, NULL, 10 * PICOQUIC_MAX_PACKET_SIZE);

    return ret;
}

int netperf_bbr_test()
{
    int ret = netperf_one_scenario(netperf_scenario_basic, sizeof(netperf_scenario_basic),
        picoquic_bbr_algorithm,
        0, 0, 0, 0, 0, 1000000, NULL, NULL, 10 * PICOQUIC_MAX_PACKET_SIZE);

    return ret;
}



/* Address natting stress.
 * The attacker has the capability to intercept traffic and rewrite addresses.
 * It waits for a client to start a connection, and then keeps changing the
 * "source IP" that appears in the client's packets. The test verifies simply that
 * the server remains functional.
 */

void natattack_port_rewrite(struct sockaddr_storage* addr, struct sockaddr* ref, uint16_t offset)
{
    if (addr->ss_family == AF_INET) {
        ((struct sockaddr_in*)addr)->sin_port = ((struct sockaddr_in*)ref)->sin_port + offset;
    }
    else if (addr->ss_family == AF_INET6) {
        ((struct sockaddr_in6*)addr)->sin6_port = ((struct sockaddr_in6*)ref)->sin6_port + offset;
    }
}

int nat_attack_loop_step(picoquic_test_tls_api_ctx_t* test_ctx, uint64_t* simulated_time, int* was_active,
    uint8_t* send_buffer, size_t send_buffer_size, int nb_loops, int do_attack)
{
    int ret = 0;
    int next_action = -1;
    uint64_t next_time = UINT64_MAX;
    uint64_t action_time;

    *was_active = 0;

    if ((action_time = picoquictest_sim_link_next_arrival(test_ctx->s_to_c_link, next_time)) < next_time) {
        next_action = 0;
        next_time = action_time;
    }

    if ((action_time = picoquictest_sim_link_next_arrival(test_ctx->c_to_s_link, next_time)) < next_time) {
        next_action = 1;
        next_time = action_time;
    }

    if ((action_time = picoquic_get_next_wake_time(test_ctx->qclient, *simulated_time)) < next_time) {
        next_action = 2;
        next_time = action_time;
    }

    if ((action_time = picoquic_get_next_wake_time(test_ctx->qserver, *simulated_time)) < next_time) {
        next_action = 3;
        next_time = action_time;
    }

    if (next_time == UINT64_MAX) {
        /* No more action possible */
        ret = -1;
    }
    else {
        if (next_time > * simulated_time) {
            *simulated_time = next_time;
        }

        switch (next_action) {
        case 0:
            /* rewrite destination address to client address, simulating NAT */
            if (test_ctx->s_to_c_link->first_packet != NULL && do_attack) {
                picoquic_store_addr(&test_ctx->s_to_c_link->first_packet->addr_to,
                    (struct sockaddr*) & test_ctx->client_addr);
            }
            ret = netperf_next_arrival(test_ctx->s_to_c_link, test_ctx->qclient, *simulated_time, was_active,
                (struct sockaddr*) & test_ctx->server_addr);
            break;
        case 1:
            /* Randomize client address, simulating broken NAT */
            if (test_ctx->c_to_s_link->first_packet != NULL && do_attack) {
                natattack_port_rewrite(&test_ctx->c_to_s_link->first_packet->addr_from,
                    (struct sockaddr*) & test_ctx->client_addr, (uint16_t)nb_loops);
            }
            ret = netperf_next_arrival(test_ctx->c_to_s_link, test_ctx->qserver, *simulated_time, was_active,
                (struct sockaddr*) & test_ctx->client_addr);
            if (test_ctx->cnx_server == NULL) {
                test_ctx->cnx_server = test_ctx->qserver->cnx_list;
            }
            break;
        case 2:
            ret = netperf_next_departure(test_ctx->qclient, test_ctx->c_to_s_link, *simulated_time, was_active, send_buffer, send_buffer_size);
            break;
        case 3:
            ret = netperf_next_departure(test_ctx->qserver, test_ctx->s_to_c_link, *simulated_time, was_active, send_buffer, send_buffer_size);
            break;
        default:
            ret = -1;
            break;
        }
    }

    return ret;
}

int nat_attack_loop(picoquic_test_tls_api_ctx_t* test_ctx, uint64_t * simulated_time, 
    uint8_t * send_buffer, size_t send_buffer_size, int do_attack)
{
    int ret = 0;
    int was_active = 0;
    int nb_loops = 0;
    int nb_inactive = 0;

    /* Run a simplified simulation */
    while (ret == 0 && test_ctx->cnx_client != NULL && test_ctx->cnx_client->cnx_state != picoquic_state_disconnected)
    {
        ret = nat_attack_loop_step(test_ctx, simulated_time, &was_active, send_buffer, send_buffer_size, nb_loops, do_attack);
        if (was_active) {
            nb_inactive = 0;
        }
        else {
            nb_inactive++;
            if (nb_inactive > 64) {
                DBG_PRINTF("Loop appears stuck, nb_inactive = %d", nb_inactive);
                ret = -1;
                break;
            }
        }
        nb_loops++;
        if (nb_loops > 100000) {
            DBG_PRINTF("Too many loops %d", nb_loops);
            ret = -1;
            break;
        }
        if (ret != 0) {
            break;
        }

        if (test_ctx->test_finished) {
            if (picoquic_is_cnx_backlog_empty(test_ctx->cnx_client) && test_ctx->cnx_server != NULL &&
                picoquic_is_cnx_backlog_empty(test_ctx->cnx_server)) {
                break;
            }
        }
    }

    return ret;
}

static test_api_stream_desc_t nat_attack_scenario[] = {
    { 4, 0, 256000, 1000000 },
    { 8, 0, 256000, 1000000 },
    { 12, 0, 256000, 1000000 },
    { 16, 0, 256000, 1000000 },
    { 20, 0, 256000, 1000000 },
    { 24, 0, 256000, 1000000 },
    { 28, 0, 256000, 1000000 },
    { 32, 0, 256000, 1000000 }
};

int nat_attack_test()
{
    /* Create a connection context */
    uint64_t simulated_time = 0;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    uint8_t* send_buffer = NULL;
    size_t send_buffer_size = PICOQUIC_MAX_PACKET_SIZE;
    int ret = tls_api_one_scenario_init(&test_ctx, &simulated_time, PICOQUIC_INTERNAL_TEST_VERSION_1, NULL, NULL);

    if (ret == 0 && test_ctx == NULL) {
        ret = -1;
    }

    if (ret == 0 && send_buffer_size > 0) {
        send_buffer = (uint8_t*)malloc(send_buffer_size);
        if (send_buffer == 0) {
            ret = -1;
        }
    }

    if (ret == 0)
    {
        ret = picoquic_start_client_cnx(test_ctx->cnx_client);
    }

    if (ret == 0) {
        ret = test_api_init_send_recv_scenario(test_ctx, nat_attack_scenario, sizeof(nat_attack_scenario));
    }

    /* Run a simplified simulation */
    if (ret == 0) {
        ret = nat_attack_loop(test_ctx, &simulated_time, send_buffer, send_buffer_size, 1);
    }

    /* If the client connection is still up, verify that data was properly received. */
    if (ret == 0 && test_ctx->cnx_client->cnx_state == picoquic_state_ready) {
        ret = tls_api_one_scenario_verify(test_ctx);
    }

    if (ret == 0) {
        DBG_PRINTF("Exit attack loop at time %" PRIu64 ", received %" PRIu64 " packets at client.",
            simulated_time, test_ctx->cnx_client->nb_packets_received);
    }

    if (send_buffer != NULL) {
        free(send_buffer);
    }

    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }

    return ret;
}
