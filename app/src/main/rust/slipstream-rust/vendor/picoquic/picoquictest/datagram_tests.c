/*
* Author: Christian Huitema
* Copyright (c) 2021, Private Octopus, Inc.
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

/*
* Datagram communication tests.
*/


#include "picoquic_internal.h"
#include "picoquic_utils.h"
#include "tls_api.h"
#include "picoquictest_internal.h"
#ifdef _WINDOWS
#include "wincompat.h"
#endif
#include <picotls.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "picoquic_binlog.h"
#include "csv.h"
#include "qlog.h"
#include "autoqlog.h"
#include "picoquic_logger.h"
#include "performance_log.h"
#include "picoquictest.h"

/*
 * Test whether datagrams are sent and received properly
 */


uint64_t test_datagram_next_time_ready(test_datagram_send_recv_ctx_t* dg_ctx)
{
    uint64_t next_time = 0;

    for (int client_mode = 0; client_mode < 2; client_mode++) {
        if (!dg_ctx->is_ready[client_mode] && dg_ctx->dg_sent[client_mode] < dg_ctx->dg_target[client_mode]
            && (dg_ctx->next_gen_time[client_mode] < next_time || next_time == 0)) {
            next_time = dg_ctx->next_gen_time[client_mode];
        }
    }
    return next_time;
}

int test_datagram_check_ready(test_datagram_send_recv_ctx_t* dg_ctx, int client_mode, uint64_t current_time)
{
    if (!dg_ctx->is_ready[client_mode] && dg_ctx->dg_sent[client_mode] < dg_ctx->dg_target[client_mode] &&
        current_time >= dg_ctx->next_gen_time[client_mode]) {
        dg_ctx->is_ready[client_mode] = 1;
        dg_ctx->dg_time_ready[client_mode] = current_time;
    }
    return dg_ctx->is_ready[client_mode];
}

int test_datagram_send(picoquic_cnx_t* cnx, uint64_t unique_path_id,
    uint8_t* bytes, size_t length, void* datagram_ctx)
{
    int ret = 0;
    int skipping = 0;
    int is_active = 1;
    size_t available = 0;
    test_datagram_send_recv_ctx_t* dg_ctx = datagram_ctx;
    uint64_t current_time = picoquic_get_quic_time(picoquic_get_quic_ctx(cnx));

    if (!cnx->client_mode && length > dg_ctx->dg_max_size) {
        ret = -1;
    }
    else if (length < 24) {
        ret = 0;
    }
    else if (dg_ctx->do_skip_test[cnx->client_mode] && !dg_ctx->is_skipping[cnx->client_mode]){
        dg_ctx->is_skipping[cnx->client_mode] = 1;
        skipping = 1;
        if (dg_ctx->use_extended_provider_api) {
            is_active = test_datagram_check_ready(dg_ctx, cnx->client_mode, current_time);
            (void)picoquic_provide_datagram_buffer_ex(bytes, 0, (is_active && !dg_ctx->one_datagram_per_packet));
        }
    }
    else if (!dg_ctx->is_ready[cnx->client_mode] || (dg_ctx->test_affinity && unique_path_id != 0)) {
        /* Datagram callback when the client was not ready. */
        is_active = 0;
        (void)picoquic_provide_datagram_buffer_ex(bytes, 0, (picoquic_datagram_active_enum)0);
    }
    else {
        uint8_t* buffer = NULL;

        dg_ctx->is_skipping[cnx->client_mode] = 0;
        available = length - (size_t)(dg_ctx->dg_sent[cnx->client_mode]%6) - 8;

        if (dg_ctx->dg_small_size > 0){
            if (available >= dg_ctx->dg_small_size) {
                available = dg_ctx->dg_small_size;
            }
            else {
                available = 0;
            }
        }
        if (dg_ctx->use_extended_provider_api) {
            picoquic_datagram_active_enum is_active = picoquic_datagram_active_any_path;
            if (dg_ctx->test_affinity) {
                is_active = picoquic_datagram_active_this_path_only;
            }
            is_active &= !dg_ctx->one_datagram_per_packet;
            buffer = picoquic_provide_datagram_buffer_ex(bytes, available, is_active);
            dg_ctx->is_ready[cnx->client_mode] = is_active;
        }
        else {
            buffer = picoquic_provide_datagram_buffer(bytes, available);
        }
        if (buffer != NULL) {
            uint8_t* buffer_bytes;
            uint64_t send_time = (dg_ctx->dg_sent[cnx->client_mode] == 0) ? current_time : dg_ctx->dg_time_ready[cnx->client_mode];
            dg_ctx->dg_sent[cnx->client_mode]++;

            if ((buffer_bytes = picoquic_frames_uint64_encode(buffer, buffer + available,
                dg_ctx->dg_sent[cnx->client_mode])) == NULL ||
                (buffer_bytes = picoquic_frames_uint64_encode(buffer_bytes, buffer + available,
                    send_time)) == NULL) {
                ret = -1;
            }
            else {
                memset(buffer_bytes, 'd', available - (buffer_bytes - buffer));
                if (dg_ctx->batch_size[cnx->client_mode] == 0 ||
                    (dg_ctx->dg_sent[cnx->client_mode] % dg_ctx->batch_size[cnx->client_mode]) == 0) {
                    dg_ctx->next_gen_time[cnx->client_mode] += dg_ctx->send_delay;
                    dg_ctx->is_ready[cnx->client_mode] = 0;
                }
            }
        }
        else {
            ret = -1;
        }
    }

    if (ret == 0 && !skipping && !dg_ctx->use_extended_provider_api) {
        (void)test_datagram_check_ready(dg_ctx, cnx->client_mode, current_time);
        if (dg_ctx->test_affinity) {
            picoquic_mark_datagram_ready_path(cnx, 0, dg_ctx->is_ready[cnx->client_mode]);
        }
        else {
            picoquic_mark_datagram_ready(cnx, dg_ctx->is_ready[cnx->client_mode]);
        }
    }
    return ret;
}

int test_datagram_recv(picoquic_cnx_t* cnx, uint64_t unique_path_id,
    uint8_t* bytes, size_t length, void* datagram_ctx)
{
    test_datagram_send_recv_ctx_t* dg_ctx = datagram_ctx;
    dg_ctx->dg_recv[cnx->client_mode] += 1;

    if (length > 16) {
        uint64_t current_time = picoquic_get_quic_time(picoquic_get_quic_ctx(cnx));
        const uint8_t* dg_bytes;
        uint64_t time_sent;
        uint64_t number_sent;

        if (unique_path_id == 0) {
            dg_ctx->nb_recv_path_0[cnx->client_mode] += 1;
        }
        else {
            dg_ctx->nb_recv_path_other[cnx->client_mode] += 1;
        }

        if ((dg_bytes = picoquic_frames_uint64_decode(bytes, bytes + length, &number_sent)) != NULL &&
            (dg_bytes = picoquic_frames_uint64_decode(dg_bytes, bytes + length, &time_sent)) != NULL &&
             time_sent <= current_time ) {
            uint64_t latency = current_time - time_sent;
            
            if (latency > dg_ctx->dg_latency_max[cnx->client_mode]) {
                dg_ctx->dg_latency_max[cnx->client_mode] = latency;
            }
            if (number_sent >= dg_ctx->dg_received_last[cnx->client_mode]) {
                dg_ctx->dg_received_last[cnx->client_mode] = number_sent;
            }
            else {
                uint64_t number_delta = dg_ctx->dg_received_last[cnx->client_mode] - number_sent;
                if (number_delta > dg_ctx->dg_number_delta_max[cnx->client_mode]) {
                    dg_ctx->dg_number_delta_max[cnx->client_mode] = number_sent;
                }
            }
        }
    }
    return 0;
}

int test_datagram_ack(picoquic_cnx_t* cnx,
    picoquic_call_back_event_t d_event, uint8_t* bytes, size_t length, uint64_t sent_time, void* datagram_ctx)
{
    int ret = 0;
    test_datagram_send_recv_ctx_t* dg_ctx = datagram_ctx;
    switch (d_event) {
    case picoquic_callback_datagram_acked:
        dg_ctx->dg_acked[cnx->client_mode] += 1;
        break;
    case picoquic_callback_datagram_lost:
        dg_ctx->dg_nacked[cnx->client_mode] += 1;
        break;
    case picoquic_callback_datagram_spurious:
        dg_ctx->dg_spurious[cnx->client_mode] += 1;
        break;
    default:
        ret = -1;
        break;
    }
    return ret;
}

int datagram_test_one(uint8_t test_id, test_datagram_send_recv_ctx_t *dg_ctx, uint64_t loss_mask_init)
{
    uint64_t simulated_time = 0;
    uint64_t loss_mask = 0;
    uint64_t all_sent_time = 0;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    picoquic_connection_id_t initial_cid = { {0xda, 0xda, 0x01, 0, 0, 0, 0, 0}, 8 };
    picoquic_congestion_algorithm_t* ccalgo = picoquic_bbr_algorithm;
    /* picoquic_tp_t server_parameters; */
    picoquic_tp_t client_parameters;
    int nb_trials = 0;
    int nb_inactive = 0;
    int ret;
    int wifi_todo = dg_ctx->test_wifi;
    uint64_t wifi_test_time = 1000000;
    uint64_t wifi_interval = 250000;
    int nb_trial_max = (dg_ctx->nb_trials_max == 0) ? 2048 : dg_ctx->nb_trials_max;


    initial_cid.id[3] = test_id;

    ret = tls_api_init_ctx_ex(&test_ctx, PICOQUIC_INTERNAL_TEST_VERSION_1,
        PICOQUIC_TEST_SNI, PICOQUIC_TEST_ALPN, &simulated_time, NULL, NULL, 0, 1, 0,
        &initial_cid);
    
    if (ret == 0) {
        /* Set the test contexts for sending and receiving datagrams */
        test_ctx->datagram_ctx = dg_ctx;
        test_ctx->datagram_recv_fn = test_datagram_recv;
        test_ctx->datagram_send_fn = test_datagram_send;
        test_ctx->datagram_ack_fn = test_datagram_ack;
        /* Set the congestion control  */
        picoquic_set_default_congestion_algorithm(test_ctx->qserver, ccalgo);
        picoquic_set_congestion_algorithm(test_ctx->cnx_client, ccalgo);
        /* request logs */
        test_ctx->qserver->use_long_log = 1;
        picoquic_set_binlog(test_ctx->qserver, ".");
        test_ctx->qclient->use_long_log = 1;
        picoquic_set_binlog(test_ctx->qclient, ".");
        binlog_new_connection(test_ctx->cnx_client);
        /* set latency to non default, if desired */
        if (dg_ctx->link_latency != 0) {
            test_ctx->c_to_s_link->microsec_latency = dg_ctx->link_latency;
            test_ctx->s_to_c_link->microsec_latency = dg_ctx->link_latency;
        }
        if (dg_ctx->picosec_per_byte != 0) {
            test_ctx->c_to_s_link->picosec_per_byte = dg_ctx->picosec_per_byte;
            test_ctx->s_to_c_link->picosec_per_byte = dg_ctx->picosec_per_byte;
        }
        /* Set parameters */
        picoquic_init_transport_parameters(&client_parameters, 1);
        client_parameters.max_datagram_frame_size = dg_ctx->dg_max_size;
        picoquic_set_transport_parameters(test_ctx->cnx_client, &client_parameters);
        ret = picoquic_start_client_cnx(test_ctx->cnx_client);
    }

    if (ret == 0) {
        /* Perform a connection loop to verify it goes OK 
         * If testing WiFi spike, set the queue delay max to a high value.
         */
        ret = tls_api_connection_loop(test_ctx, &loss_mask,
            2 * test_ctx->c_to_s_link->microsec_latency + 
            (dg_ctx->test_wifi)?275000:0, &simulated_time);

        if (ret != 0)
        {
            DBG_PRINTF("Connection loop returns %d\n", ret);
        }
        else {
            /* Verify datagrams are negotiated */
            if (test_ctx->cnx_client->remote_parameters.max_datagram_frame_size != PICOQUIC_MAX_PACKET_SIZE ||
                test_ctx->cnx_server->remote_parameters.max_datagram_frame_size != dg_ctx->dg_max_size) {
                DBG_PRINTF("Datagram size badly negotiated: %zu, %zu",
                    test_ctx->cnx_client->remote_parameters.max_datagram_frame_size,
                    test_ctx->cnx_server->remote_parameters.max_datagram_frame_size);
                ret = -1;
            }
        }
    }
    /* Mark that datagrams are ready */
    if (ret == 0) {
        picoquic_mark_datagram_ready(test_ctx->cnx_client, 1);
        picoquic_mark_datagram_ready(test_ctx->cnx_server, 1);
        dg_ctx->is_ready[0] = 1;
        dg_ctx->is_ready[1] = 1;
        dg_ctx->dg_time_ready[0] = simulated_time;
        dg_ctx->dg_time_ready[1] = simulated_time;
    }

    /* Set the loss mask */
    if (ret == 0) {
        loss_mask = loss_mask_init;
    }

    /* Send datagrams for specified time */
    while (ret == 0 && nb_trials < nb_trial_max && nb_inactive < 16) {
        int was_active = 0;
        uint64_t time_out = test_datagram_next_time_ready(dg_ctx);

        nb_trials++;

        if (wifi_todo) {
            if (simulated_time >= wifi_test_time) {
                uint64_t resume_time = simulated_time + wifi_interval;
                picoquic_test_simlink_suspend(test_ctx->c_to_s_link, resume_time, 0);
                picoquic_test_simlink_suspend(test_ctx->s_to_c_link, resume_time, 1);
                wifi_todo = 0;
            }
            else if (time_out > wifi_test_time) {
                time_out = wifi_test_time;
            }
        }

        ret = tls_api_one_sim_round(test_ctx, &simulated_time, time_out, &was_active);

        if (was_active) {
            nb_inactive = 0;
        }
        else {
            nb_inactive++;
        }
        if (dg_ctx->dg_recv[0] == dg_ctx->dg_target[1] &&
            dg_ctx->dg_recv[1] == dg_ctx->dg_target[0]) {
            break;
        }
        else if ((loss_mask_init != 0 || dg_ctx->test_wifi != 0) &&
            dg_ctx->dg_sent[0] == dg_ctx->dg_target[0] &&
            dg_ctx->dg_sent[1] == dg_ctx->dg_target[1]) {
            if (all_sent_time == 0) {
                /* Queue a Ping frame to trigger acks */
                uint8_t ping_frame[] = { picoquic_frame_type_ping };
                picoquic_queue_misc_frame(test_ctx->cnx_client, ping_frame, sizeof(ping_frame), 0,
                    picoquic_packet_context_application);
                picoquic_queue_misc_frame(test_ctx->cnx_server, ping_frame, sizeof(ping_frame), 0,
                    picoquic_packet_context_application);
                loss_mask = 0;
                all_sent_time = simulated_time;
            }
            else if (picoquic_is_cnx_backlog_empty(test_ctx->cnx_server)  &&
                picoquic_is_cnx_backlog_empty(test_ctx->cnx_client))
            {
                break;
            }
        }
        /* Simulate wake up when data is ready for real time operation */
        if (!dg_ctx->is_ready[0] && test_datagram_check_ready(dg_ctx, 0, simulated_time)) {
            picoquic_mark_datagram_ready(test_ctx->cnx_server, 1);
        }
        if (!dg_ctx->is_ready[1] && test_datagram_check_ready(dg_ctx, 1, simulated_time)) {
            picoquic_mark_datagram_ready(test_ctx->cnx_client, 1);
        }

        if ((dg_ctx->is_ready[0] && !test_ctx->cnx_server->is_datagram_ready) ||
            (dg_ctx->is_ready[1] && !test_ctx->cnx_client->is_datagram_ready))
        {
            DBG_PRINTF("%s", "Datagram ready out of synch!");
        }
    }

    if (ret == 0) {
        if (loss_mask_init == 0  ||
            (dg_ctx->dg_recv[0] == dg_ctx->dg_target[1] &&
                dg_ctx->dg_recv[1] == dg_ctx->dg_target[0])) {
            /* Verify datagrams have been received */
            if (dg_ctx->dg_recv[0] != dg_ctx->dg_target[1] ||
                dg_ctx->dg_recv[1] != dg_ctx->dg_target[0]) {
                DBG_PRINTF("Did not receive expected datagrams after %d trials, %d inactive",
                    nb_trials, nb_inactive);
                for (int i = 0; i < 2; i++) {
                    DBG_PRINTF("dg_target[%d]=%d, dg_sent[%d]=%d, dg_recv[%d]=%d",
                        i, dg_ctx->dg_target[i], i, dg_ctx->dg_sent[i], 1 - i, dg_ctx->dg_recv[1 - i]);
                }
                ret = -1;
            }
            /* Verify that all NACK are counted spurious */
            if (ret == 0 && (
                dg_ctx->dg_nacked[0] != dg_ctx->dg_spurious[0] ||
                dg_ctx->dg_nacked[1] != dg_ctx->dg_spurious[1])) {
                for (int i = 0; i < 2; i++) {
                    DBG_PRINTF("dg_nacked[%d]=%d != dg_spurious[%d]=%d",
                        i, dg_ctx->dg_nacked[i], i, dg_ctx->dg_spurious[i]);
                    DBG_PRINTF("dg_nacked[%d]=%d != dg_spurious[%d]=%d",
                        i, dg_ctx->dg_nacked[i], i, dg_ctx->dg_spurious[i]);
                }
                ret = -1;
            }
            /* Verify that the number of packets is as expected */
            if (ret == 0 && dg_ctx->max_packets_received > 0) {
                if (test_ctx->cnx_client->nb_packets_received > dg_ctx->max_packets_received) {
                    DBG_PRINTF("Expected at most %d packets for %d datagrams, batch by %d, got %d",
                        dg_ctx->max_packets_received, dg_ctx->dg_recv[1], dg_ctx->batch_size[0], test_ctx->cnx_client->nb_packets_received);
                    ret = -1;
                }
            }

            if (ret == 0 && dg_ctx->duration_max > 0 && dg_ctx->duration_max < simulated_time) {
                DBG_PRINTF("Expected test complete in %" PRIu64 ", but simulation lasted until %" PRIu64,
                    dg_ctx->duration_max, simulated_time);
                ret = -1;

            }
        }
        else {
            /* In a loss test, check that ACK and NACK are as expected */
            if (dg_ctx->dg_recv[0] != (dg_ctx->dg_acked[1] + dg_ctx->dg_spurious[1]) ||
                dg_ctx->dg_recv[1] != (dg_ctx->dg_acked[0] + dg_ctx->dg_spurious[0])) {
                DBG_PRINTF("Did not receive expected datagrams ACKs after %d trials, %d inactive",
                    nb_trials, nb_inactive);
                for (int i = 0; i < 2; i++) {
                    DBG_PRINTF("dg_recv[%d]=%d, dg_acked[%d]=%d, dg_spurious[%d]=%d",
                        i, dg_ctx->dg_recv[i], 1 - i, dg_ctx->dg_acked[1 - i], 1 - i, dg_ctx->dg_spurious[1 - i]);
                }
                ret = -1;
            }

            if (ret == 0) {
                if (dg_ctx->dg_recv[0] + dg_ctx->dg_nacked[1] - dg_ctx->dg_spurious[1] != dg_ctx->dg_sent[1] ||
                    dg_ctx->dg_recv[1] + dg_ctx->dg_nacked[0] - dg_ctx->dg_spurious[0] != dg_ctx->dg_sent[0]) {
                    DBG_PRINTF("Did not receive expected datagrams NACKs after %d trials, %d inactive",
                        nb_trials, nb_inactive);
                    for (int i = 0; i < 2; i++) {
                        DBG_PRINTF("dg_recv[%d]=%d, dg_nacked[%d]=%d, dg_spurious[%d]=%d, dg_sent[%d]=%d",
                            i, dg_ctx->dg_recv[i], 1 - i, dg_ctx->dg_acked[1 - i],
                            1 - i, dg_ctx->dg_spurious[1 - i], 1 - i, dg_ctx->dg_sent[1 - i]);
                    }
                    ret = -1;
                }
            }
        }
        for (int i = 0; ret == 0 && i < 2; i++) {
            if (dg_ctx->dg_latency_target[i] > 0 &&
                dg_ctx->dg_latency_max[i] > dg_ctx->dg_latency_target[i]) {
                DBG_PRINTF("latency max[%d]=%" PRIu64 ", latency target[%d] = %" PRIu64,
                    i, dg_ctx->dg_latency_max[i], i, dg_ctx->dg_latency_target[i]);
                ret = -1;
            }
            if (dg_ctx->dg_number_delta_max[i] > dg_ctx->dg_number_delta_target[i]) {
                DBG_PRINTF("delta number max[%d]=%" PRIu64 ", delta number max[%d] = %" PRIu64,
                    i, dg_ctx->dg_number_delta_max[i], i, dg_ctx->dg_number_delta_target[i]);
            }
        }

    }

    /* And then free the resource */

    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }

    return ret;
}

int datagram_test()
{
    test_datagram_send_recv_ctx_t dg_ctx = { 0 };
    dg_ctx.dg_max_size = PICOQUIC_MAX_PACKET_SIZE;
    dg_ctx.dg_target[0] = 5;
    dg_ctx.dg_target[1] = 5;

    return datagram_test_one(1, &dg_ctx, 0);
}

int datagram_rt_test()
{
    test_datagram_send_recv_ctx_t dg_ctx = { 0 };
    dg_ctx.dg_max_size = PICOQUIC_MAX_PACKET_SIZE;
    dg_ctx.dg_target[0] = 100;
    dg_ctx.dg_target[1] = 100;
    dg_ctx.send_delay = 20000;
    dg_ctx.next_gen_time[0] = 100000;
    dg_ctx.next_gen_time[1] = 100000;
    dg_ctx.dg_latency_target[0] = 18000;
    dg_ctx.dg_latency_target[1] = 18000;

    return datagram_test_one(2, &dg_ctx, 0);
}

int datagram_rt_skip_test()
{
    test_datagram_send_recv_ctx_t dg_ctx = { 0 };
    dg_ctx.dg_max_size = PICOQUIC_MAX_PACKET_SIZE;
    dg_ctx.dg_target[0] = 100;
    dg_ctx.dg_target[1] = 10;
    dg_ctx.send_delay = 20000;
    dg_ctx.next_gen_time[0] = 100000;
    dg_ctx.next_gen_time[1] = 100000;
    dg_ctx.dg_latency_target[0] = 13000;
    dg_ctx.dg_latency_target[1] = 20000;
    dg_ctx.do_skip_test[0] = 1;
    dg_ctx.do_skip_test[1] = 1;

    return datagram_test_one(3, &dg_ctx, 0);
}

int datagram_rtnew_skip_test()
{
    test_datagram_send_recv_ctx_t dg_ctx = { 0 };
    dg_ctx.dg_max_size = PICOQUIC_MAX_PACKET_SIZE;
    dg_ctx.dg_target[0] = 100;
    dg_ctx.dg_target[1] = 10;
    dg_ctx.send_delay = 20000;
    dg_ctx.next_gen_time[0] = 100000;
    dg_ctx.next_gen_time[1] = 100000;
    dg_ctx.dg_latency_target[0] = 13000;
    dg_ctx.dg_latency_target[1] = 20000;
    dg_ctx.do_skip_test[0] = 1;
    dg_ctx.do_skip_test[1] = 1;
    dg_ctx.use_extended_provider_api = 1;

    return datagram_test_one(7, &dg_ctx, 0);
}


int datagram_loss_test()
{
    test_datagram_send_recv_ctx_t dg_ctx = { 0 };
    dg_ctx.dg_max_size = PICOQUIC_MAX_PACKET_SIZE;
    dg_ctx.dg_target[0] = 100;
    dg_ctx.dg_target[1] = 100;
    dg_ctx.send_delay = 20000;
    dg_ctx.next_gen_time[0] = 100000;
    dg_ctx.next_gen_time[1] = 100000;

    return datagram_test_one(4, &dg_ctx, 0x040080100200400ull);
}

int datagram_size_test()
{
    test_datagram_send_recv_ctx_t dg_ctx = { 0 };
    dg_ctx.dg_max_size = 512;
    dg_ctx.dg_target[0] = 100;
    dg_ctx.dg_target[1] = 100;
    dg_ctx.send_delay = 5000;

    return datagram_test_one(5, &dg_ctx, 0);
}

int datagram_small_test()
{
    test_datagram_send_recv_ctx_t dg_ctx = { 0 };
    dg_ctx.dg_max_size = 512;
    dg_ctx.dg_small_size = 64;
    dg_ctx.batch_size[0] = 4;
    dg_ctx.batch_size[1] = 4;
    dg_ctx.dg_target[0] = 100;
    dg_ctx.dg_target[1] = 100;
    dg_ctx.send_delay = 5000;
    dg_ctx.next_gen_time[0] = 50000;
    dg_ctx.next_gen_time[1] = 50000;
    dg_ctx.max_packets_received = 55;

    return datagram_test_one(6, &dg_ctx, 0);
}

int datagram_small_new_test()
{
    test_datagram_send_recv_ctx_t dg_ctx = { 0 };
    dg_ctx.dg_max_size = 512;
    dg_ctx.dg_small_size = 64;
    dg_ctx.batch_size[0] = 4;
    dg_ctx.batch_size[1] = 4;
    dg_ctx.dg_target[0] = 100;
    dg_ctx.dg_target[1] = 100;
    dg_ctx.send_delay = 5000;
    dg_ctx.next_gen_time[0] = 50000;
    dg_ctx.next_gen_time[1] = 50000;
    dg_ctx.max_packets_received = 55;
    dg_ctx.use_extended_provider_api = 1;

    return datagram_test_one(7, &dg_ctx, 0);
}

int datagram_wifi_test()
{
    test_datagram_send_recv_ctx_t dg_ctx = { 0 };
    dg_ctx.dg_max_size = PICOQUIC_MAX_PACKET_SIZE;
    dg_ctx.dg_target[0] = 1000;
    dg_ctx.dg_target[1] = 1000;
    dg_ctx.send_delay = 2000;
    dg_ctx.next_gen_time[0] = 100000;
    dg_ctx.next_gen_time[1] = 100000;
    dg_ctx.dg_latency_target[0] = 305000;
    dg_ctx.dg_latency_target[1] = 280000;
    dg_ctx.test_wifi = 1;
    dg_ctx.nb_trials_max = 64000;
    dg_ctx.link_latency = 25000;

    return datagram_test_one(8, &dg_ctx, 0);
}

int datagram_small_packet_test()
{
    test_datagram_send_recv_ctx_t dg_ctx = { 0 };
    dg_ctx.dg_max_size = 512;
    dg_ctx.dg_small_size = 64;
    dg_ctx.dg_target[0] = 100;
    dg_ctx.dg_target[1] = 20000;
    dg_ctx.send_delay = 100;
    dg_ctx.next_gen_time[0] = 50000;
    dg_ctx.next_gen_time[1] = 50000;
    dg_ctx.link_latency = 10000;
    dg_ctx.picosec_per_byte = 20000; /* 400 Mbps */
    dg_ctx.dg_latency_target[0] = 20000;
    dg_ctx.dg_latency_target[1] = 13500;
    dg_ctx.use_extended_provider_api = 1;
    dg_ctx.one_datagram_per_packet = 1;
    dg_ctx.nb_trials_max = 200000;
    dg_ctx.duration_max = 2060000;

    return datagram_test_one(9, &dg_ctx, 0);
}