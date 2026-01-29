/*
* Author: Christian Huitema
* Copyright (c) 2023, Private Octopus, Inc.
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
#include <inttypes.h>
#include "picoquic.h"
#include "picoquic_internal.h"
#include "picoquictest_internal.h"
#include "tls_api.h"
#include "picoquic_binlog.h"
#include "logreader.h"
#include "qlog.h"

/* Add a series of tests to study the behavior of rate limited
* clients, such as those sending at a sustained rate lower
* than the link capacity. We want to test several bug reports
* showing the following possible issues:
* 
* - Initial window growing higher than expected, due to congestion
*   control never exiting slow start;
* - Congestion window growing higher than expected, due to increased
*   window in congestion avoidance phase;
* - Pacing rate growing higher than the available bandwidth;
* - Preemptive repeat getting confused when packets contain data from
*   both finished and unfinished streams.
* 
* We need to engineer a server that provides two kinds of streams:
* - a steady "control" stream at a specified fixed rate, sending
*   data frames smaller than the MTU so we will have multiple
*   streams in a packet. That stream will have higher priority
*   than the other streams.
* - in start-up and preemptive tests, a second data stream that
*   forces the end of slow start and tests preemtive repeat.
* - in congestion avoidance tests, a third data stream that
*   tests for over-large congestion windows.
* 
* The loop will include monitoring of pacing rate, congestion
* window and rtt. We want to run these tests with a variety of congestion
* controls. 
*/

#define APP_LIMITED_TEST_ALPN "app_limited_test"
#define APP_LIMITED_ERROR_INTERNAL 1

typedef struct st_app_limited_test_config_t {
    uint8_t test_id;
    picoquic_congestion_algorithm_t* ccalgo;
    int do_preemptive_repeat;
    size_t stream_0_packet_size;
    size_t stream_0_packet_interval;
    uint64_t data_stream_size;
    uint64_t time_to_stream[3];
    uint64_t loss_mask;
    uint64_t completion_target;
    uint64_t rtt_max;
    uint64_t cwin_max;
    uint64_t data_rate_max;
    uint64_t nb_losses_max;
} app_limited_test_config_t;

typedef struct st_app_limited_stream_ctx_t {
    uint64_t stream_id; /* ID for the test streams */
    size_t data_size; /* How much data to send on each stream */
    size_t octets_sent; /* Octets sent by server on each stream */
    size_t octets_recv; /* Octets received by slient on each stream */
    int fin_received;
    int is_fin_sent;
    int rank;
} app_limited_stream_ctx_t;

typedef struct st_app_limited_cnx_ctx_t {
    picoquic_cnx_t* cnx;
    int is_server;
    app_limited_stream_ctx_t stream_ctx[3];
    struct st_app_limited_ctx_t* al_ctx;
} app_limited_cnx_ctx_t;

typedef struct st_app_limited_ctx_t {
    uint64_t simulated_time;
    uint64_t loss_mask;
    uint64_t stream0_next_time;
    uint64_t stream0_bytes_sent_this_packet;
    int nb_client_streams_completed;
    uint64_t last_interaction_time;
    uint64_t rtt_max;
    uint64_t cwin_max;
    uint64_t data_rate_max;
    app_limited_cnx_ctx_t client_cnx_ctx;
    app_limited_cnx_ctx_t server_cnx_ctx;
    app_limited_test_config_t* config;
} app_limited_ctx_t;

app_limited_cnx_ctx_t* app_limited_initialize_cnx_context(app_limited_ctx_t* callback_ctx,  picoquic_cnx_t* cnx, int is_server )
{
    app_limited_cnx_ctx_t* cnx_ctx = NULL;

    if (is_server) {
        cnx_ctx = &callback_ctx->server_cnx_ctx;
    }
    else {
        cnx_ctx = &callback_ctx->client_cnx_ctx;
    }

    cnx_ctx->cnx = cnx;

    return cnx_ctx;
}

app_limited_stream_ctx_t * app_limited_find_or_create_stream(uint64_t stream_id, app_limited_cnx_ctx_t * cnx_ctx)
{
    app_limited_stream_ctx_t* stream_ctx = NULL;

    for (int i = 0; i < 3; i++) {
        if (stream_id == cnx_ctx->stream_ctx[i].stream_id ||
            cnx_ctx->stream_ctx[i].stream_id == UINT64_MAX) {
            stream_ctx = &cnx_ctx->stream_ctx[i];
            stream_ctx->stream_id = stream_id;
            stream_ctx->rank = i;
            break;
        }
    }
    return stream_ctx;
}

int app_limited_receive_stream_data(app_limited_cnx_ctx_t* cnx_ctx,
    app_limited_stream_ctx_t* stream_ctx, uint8_t* bytes, size_t length, int is_fin)
{
    int ret = 0;
    if (is_fin && stream_ctx->fin_received) {
        ret = -1;
    }
    else {
        for (size_t i = 0; i < length; i++) {
            uint8_t b = bytes[i];
            if (b == (uint8_t)(stream_ctx->octets_recv & 0xff)) {
                stream_ctx->octets_recv++;
            }
            else {
                ret = -1;
                break;
            }
        }
        if (stream_ctx->octets_recv > stream_ctx->data_size) {
            ret = -1;
        }
        else if (is_fin) {
            cnx_ctx->al_ctx->nb_client_streams_completed += 1;
            stream_ctx->fin_received = 1;
            if (stream_ctx->octets_recv != stream_ctx->data_size) {
                ret = -1;
            }
        }
    }

    return ret;
}

void app_limited_prepare_to_send_on_stream(app_limited_cnx_ctx_t* cnx_ctx,
    app_limited_stream_ctx_t* stream_ctx, uint8_t* context, size_t length, uint64_t simulated_time)
{
    uint64_t available = stream_ctx->data_size - stream_ctx->octets_sent;
    int is_fin = 0;
    int is_still_active = 1;
    uint8_t* buffer = NULL;

    /* Compute how much to send */
    if (stream_ctx->rank == 0) {
        /* Implement here the rate pacing of stream 0. */
        if (length > (cnx_ctx->al_ctx->config->stream_0_packet_size - cnx_ctx->al_ctx->stream0_bytes_sent_this_packet)) {
            /* cannot only send as much as the packet indicates */
            available = cnx_ctx->al_ctx->config->stream_0_packet_size - cnx_ctx->al_ctx->stream0_bytes_sent_this_packet;
        } else {
            available = length;
        }

        cnx_ctx->al_ctx->stream0_bytes_sent_this_packet += (size_t)available;
        if (cnx_ctx->al_ctx->stream0_bytes_sent_this_packet >= cnx_ctx->al_ctx->config->stream_0_packet_size){
            /* the whole packet was scheduled */
            cnx_ctx->al_ctx->stream0_bytes_sent_this_packet = 0;
            cnx_ctx->al_ctx->stream0_next_time += cnx_ctx->al_ctx->config->stream_0_packet_interval;
            if (simulated_time < cnx_ctx->al_ctx->stream0_next_time) {
                is_still_active = 0;
            }
        }
    }
    else if (available > length) {
        available = length;
    }

    if (available + stream_ctx->octets_sent >= stream_ctx->data_size) {
        is_fin = 1;
    }

    buffer = (uint8_t*)picoquic_provide_stream_data_buffer(context, (size_t)available, is_fin, is_still_active);
    if (buffer != NULL) {
        stream_ctx->is_fin_sent = is_fin;
        /* fill the bytes */
        for (size_t i = 0; i < (size_t)available; i++) {
            uint8_t b = (uint8_t)(stream_ctx->octets_sent & 0xff);
            buffer[i] = b;
            stream_ctx->octets_sent++;
        }
    }
}

 /* Callback from Quic
 */
int app_limited_callback(picoquic_cnx_t* cnx,
    uint64_t stream_id, uint8_t* bytes, size_t length,
    picoquic_call_back_event_t fin_or_event, void* callback_ctx, void* v_stream_ctx)
{

    int ret = 0;
    app_limited_cnx_ctx_t* cnx_ctx = (app_limited_cnx_ctx_t*)callback_ctx;
    app_limited_stream_ctx_t* stream_ctx = (app_limited_stream_ctx_t*)v_stream_ctx;

    /* If this is the first reference to the connection, the application context is set
    * to the default value defined for the server. This default value contains the pointer
    * to the global context in which streams and roles are defined.
    */
    if (callback_ctx == NULL || callback_ctx == picoquic_get_default_callback_context(picoquic_get_quic_ctx(cnx))) {
        if (fin_or_event == picoquic_callback_close) {
            picoquic_set_callback(cnx, NULL, NULL);
            return 0;
        }
        else {
            cnx_ctx = app_limited_initialize_cnx_context((app_limited_ctx_t*)callback_ctx, cnx, 1);
            if (cnx_ctx == NULL) {
                /* cannot handle the connection */
                picoquic_close(cnx, PICOQUIC_ERROR_MEMORY);
                return -1;
            }
            else {
                cnx_ctx->is_server = 1;
                picoquic_set_callback(cnx, app_limited_callback, cnx_ctx);
            }
        }
    }

    if (ret == 0) {
        switch (fin_or_event) {
        case picoquic_callback_stream_data:
        case picoquic_callback_stream_fin:
            /* Data arrival on stream #x, maybe with fin mark */
            if (stream_ctx == NULL) {
                /* Retrieve, or create and initialize stream context */
                stream_ctx = app_limited_find_or_create_stream(stream_id, cnx_ctx);
            }

            if (stream_ctx == NULL) {
                /* Internal error */
                (void)picoquic_reset_stream(cnx, stream_id, APP_LIMITED_ERROR_INTERNAL);
                ret = -1;
            }
            else if (cnx_ctx->is_server) {
                ret = -1;
            } else {
                ret = app_limited_receive_stream_data(cnx_ctx, stream_ctx, bytes, length, (fin_or_event == picoquic_callback_stream_fin));
            }
            break;
        case picoquic_callback_prepare_to_send:
            /* Active sending API */
            if (stream_ctx == NULL) {
                /* This should never happen */
                picoquic_log_app_message(cnx, "app_limited callback returns %d, event %d", ret, fin_or_event);
                DBG_PRINTF("Prepare to send on NULL context, steam: %" PRIu64, stream_id);
                ret = -1;
            }
            else {
                app_limited_prepare_to_send_on_stream(cnx_ctx, stream_ctx, bytes, length, cnx_ctx->al_ctx->simulated_time);
            }
            break;
        case picoquic_callback_datagram:
        case picoquic_callback_prepare_datagram:
            /* not expected */
            ret = -1;
            break;
        case picoquic_callback_stream_reset: /* Client reset stream #x */
        case picoquic_callback_stop_sending: /* Client asks server to reset stream #x */
                                             /* TODO: react to abandon stream, etc. */
            break;
        case picoquic_callback_stateless_reset: /* Received an error message */
        case picoquic_callback_close: /* Received connection close */
        case picoquic_callback_application_close: /* Received application close */
                                                  /* Remove the connection from the context, and then delete it */
            cnx_ctx->cnx = NULL;
            picoquic_set_callback(cnx, NULL, NULL);
            break;
        case picoquic_callback_version_negotiation:
            /* The server should never receive a version negotiation response */
            break;
        case picoquic_callback_stream_gap:
            /* This callback is never used. */
            break;
        case picoquic_callback_almost_ready:
        case picoquic_callback_ready:
            /* should mark the first stream as ready, create it if necessary */
            break;
        case picoquic_callback_datagram_acked:
            /* Ack for packet carrying datagram-object received from peer */
        case picoquic_callback_datagram_lost:
            /* Packet carrying datagram-object probably lost */
        case picoquic_callback_datagram_spurious:
            /* Packet carrying datagram-object was not really lost */
            break;
        case picoquic_callback_pacing_changed:
            /* Notification of rate change from congestion controller */
            break;
        default:
            /* unexpected */
            break;
        }
    }

    if (ret != 0) {
        picoquic_log_app_message(cnx, "app_limited callback returns %d, event %d", ret, fin_or_event);
        DBG_PRINTF("app_limited callback returns %d, event %d", ret, fin_or_event);
    }

    return ret;
}

void app_limited_initialize_context(app_limited_ctx_t* al_ctx, app_limited_test_config_t* config)
{
    memset(al_ctx, 0, sizeof(app_limited_ctx_t));
    for (int i = 0; i < 3; i++) {
        uint64_t data_size = (i != 0) ? config->data_stream_size : ((config->time_to_stream[2] + 1000000) * config->stream_0_packet_size) / config->stream_0_packet_interval;
        al_ctx->client_cnx_ctx.stream_ctx[i].stream_id = UINT64_MAX;
        al_ctx->client_cnx_ctx.stream_ctx[i].data_size = (size_t)data_size;
        al_ctx->client_cnx_ctx.stream_ctx[i].rank = i;
        al_ctx->server_cnx_ctx.stream_ctx[i].stream_id = UINT64_MAX;
        al_ctx->server_cnx_ctx.stream_ctx[i].data_size = (size_t)data_size;
        al_ctx->server_cnx_ctx.stream_ctx[i].rank = i;
    }
    al_ctx->client_cnx_ctx.al_ctx = al_ctx;
    al_ctx->server_cnx_ctx.al_ctx = al_ctx;
    al_ctx->loss_mask = config->loss_mask;
    al_ctx->config = config;
}

/* app_limited_get_timeout:
 * If time above connection 2, start connection 2
 *     else timeout = connection 2
 * If time above connection 1, start connection 1
 *     else timeout = connection 1
 * If time above next interval,
 *     mark connection 0 active
 *     else timeout = next interval
 * If nothing in particular to do, timeout = 0
 * 
 */
int app_limited_get_timeout(app_limited_ctx_t* al_ctx, uint64_t simulated_time, uint64_t * timeout)
{
    int ret = 0;
    
    *timeout = 0;

    if (al_ctx->server_cnx_ctx.cnx != NULL) {
        for (int i = 0; i < 3; i++) {
            if (al_ctx->server_cnx_ctx.stream_ctx[i].stream_id == UINT64_MAX) {
                if (simulated_time >= al_ctx->config->time_to_stream[i]) {
                    uint64_t stream_id = picoquic_get_next_local_stream_id(al_ctx->server_cnx_ctx.cnx, 1);
                    al_ctx->server_cnx_ctx.stream_ctx[i].stream_id = stream_id;
                    ret = picoquic_mark_active_stream(al_ctx->server_cnx_ctx.cnx, stream_id, 1,
                        (void*)&al_ctx->server_cnx_ctx.stream_ctx[i]);
                    if (i == 0) {
                        al_ctx->stream0_next_time = simulated_time;
                    }
                }
                else {
                    *timeout = al_ctx->config->time_to_stream[i];
                }
                break;
            }
        }

        if (ret == 0) {
            if (al_ctx->server_cnx_ctx.stream_ctx[0].stream_id != UINT64_MAX) {
                if (simulated_time < al_ctx->stream0_next_time) {
                    if (*timeout == 0 || al_ctx->stream0_next_time < *timeout) {
                        *timeout = al_ctx->stream0_next_time;
                    }
                }
                else if (!al_ctx->server_cnx_ctx.stream_ctx[0].is_fin_sent) {
                    picoquic_mark_active_stream(al_ctx->server_cnx_ctx.cnx,
                        al_ctx->server_cnx_ctx.stream_ctx[0].stream_id, 1,
                        (void*)&al_ctx->server_cnx_ctx.stream_ctx[0]);
                }
            }
        }
    }

    return ret;
}

void app_limited_monitor(app_limited_ctx_t* al_ctx)
{
    if (al_ctx->server_cnx_ctx.cnx != NULL) {
        picoquic_path_t* path_x = al_ctx->server_cnx_ctx.cnx->path[0];

        if (path_x->rtt_max > al_ctx->rtt_max) {
            al_ctx->rtt_max = path_x->rtt_max;
        }
        if (path_x->cwin > al_ctx->cwin_max) {
            al_ctx->cwin_max = path_x->cwin;
        }
        if (path_x->pacing.rate > al_ctx->data_rate_max) {
            al_ctx->data_rate_max = path_x->pacing.rate;
        }
    }
}

static int app_limited_test_one(app_limited_test_config_t * config)
{
    uint64_t time_out;
    int nb_trials = 0;
    int was_active = 0;
    uint64_t picosec_per_byte = (1000000ull * 8) / 10;
    uint64_t queue_delay_max = 40000;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    app_limited_ctx_t al_ctx;
    picoquic_connection_id_t initial_cid = { {0xab, 0xbl, 0x1b, 0x17, 0xed, 0, 0, 0}, 8 };
    int ret = 0;

    app_limited_initialize_context(&al_ctx, config);
    initial_cid.id[7] = config->test_id;

    if (ret == 0) {
        ret = tls_api_init_ctx_ex2(&test_ctx,
            PICOQUIC_INTERNAL_TEST_VERSION_1,
            PICOQUIC_TEST_SNI, APP_LIMITED_TEST_ALPN, &al_ctx.simulated_time, NULL, NULL, 0, 1, 0, &initial_cid, 8, 0, 0, 0);

        if (ret == 0) {
            al_ctx.client_cnx_ctx.cnx = test_ctx->cnx_client;

            picoquic_set_default_congestion_algorithm(test_ctx->qserver, config->ccalgo);
            picoquic_set_congestion_algorithm(test_ctx->cnx_client, config->ccalgo);

            picoquic_set_binlog(test_ctx->qserver, ".");
            test_ctx->qserver->use_long_log = 1;
            picoquic_set_binlog(test_ctx->qclient, ".");
            if (config->do_preemptive_repeat) {
                picoquic_set_preemptive_repeat_policy(test_ctx->qserver, 1);
                picoquic_set_preemptive_repeat_per_cnx(test_ctx->cnx_client, 1);
            }
            test_ctx->s_to_c_link->picosec_per_byte = picosec_per_byte;
            test_ctx->c_to_s_link->picosec_per_byte = picosec_per_byte;
        }
    }

    /* The default procedure creates connections using the test callback.
    * We want to replace that by the demo client callback */

    if (ret == 0) {
        /* TODO: proper call back context */
        picoquic_set_default_callback(test_ctx->qserver, app_limited_callback, &al_ctx);
        picoquic_set_callback(test_ctx->cnx_client, app_limited_callback, &al_ctx.client_cnx_ctx);
        if (ret == 0) {
            ret = picoquic_start_client_cnx(test_ctx->cnx_client);
        }
    }

    if (ret == 0) {
        ret = tls_api_connection_loop(test_ctx, &al_ctx.loss_mask, queue_delay_max, &al_ctx.simulated_time);
    }

    while (ret == 0 && picoquic_get_cnx_state(test_ctx->cnx_client) != picoquic_state_disconnected) {
        /* Look at the timeout. Set it to the next wake up time if needed. */
        if ((ret = app_limited_get_timeout(&al_ctx, al_ctx.simulated_time, &time_out)) != 0) {
            break;
        }

        /* Progress. */
        if ((ret = tls_api_one_sim_round(test_ctx, &al_ctx.simulated_time, time_out, &was_active)) != 0) {
            break;
        }

        if (picoquic_is_cnx_backlog_empty(test_ctx->cnx_client) &&
            al_ctx.nb_client_streams_completed >= 3) {
            ret = picoquic_close(test_ctx->cnx_client, 0);
        }

        /* monitor cwin, rate max, etc. */
        app_limited_monitor(&al_ctx);

        if (++nb_trials > 1000000) {
            ret = -1;
            break;
        }
    }

    if (ret == 0 && config->completion_target != 0) {
        if (al_ctx.simulated_time > config->completion_target) {
            DBG_PRINTF("Test uses %llu microsec instead of %llu", al_ctx.simulated_time, config->completion_target);
            ret = -1;
        }
    }

    if (ret == 0 && test_ctx->qclient->nb_data_nodes_allocated > test_ctx->qclient->nb_data_nodes_in_pool) {
        ret = -1;
    }
    else if (ret == 0 && test_ctx->qserver->nb_data_nodes_allocated > test_ctx->qserver->nb_data_nodes_in_pool) {
        ret = -1;
    }

    if (ret == 0) {
        /* check CWIN, losses, etc againt targets */
        if (al_ctx.rtt_max > config->rtt_max) {
            DBG_PRINTF("Max RTT %llu microsec instead of %llu", al_ctx.rtt_max, config->rtt_max);
            ret = -1;
        }

        if (al_ctx.cwin_max > config->cwin_max) {
            DBG_PRINTF("Max CWIN %llu instead of %llu", al_ctx.cwin_max, config->cwin_max);
            ret = -1;
        }

        if (al_ctx.data_rate_max > config->data_rate_max) {
            DBG_PRINTF("Data rate max %llu instead of %llu", al_ctx.data_rate_max, config->data_rate_max);
            ret = -1;
        }

        if (test_ctx->cnx_server != NULL && test_ctx->cnx_server->nb_retransmission_total > config->nb_losses_max) {
            DBG_PRINTF("Nb retransmission %llu instead of %llu", test_ctx->cnx_server->nb_retransmission_total, config->nb_losses_max);
            ret = -1;
        }
    }

    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }

    return ret;
}

static void app_limited_config_set_default( app_limited_test_config_t* config, uint8_t test_id)
{
    memset(config, 0, sizeof(app_limited_test_config_t));
    config->test_id = test_id;
    config->ccalgo = picoquic_newreno_algorithm;
    config->stream_0_packet_size = 511;
    config->stream_0_packet_interval = 800;
    config->data_stream_size = 1000000;
    config->time_to_stream[0] = 0;
    config->time_to_stream[1] = 2500000;
    config->time_to_stream[2] = 7500000;
    config->completion_target = 12000000;
    config->rtt_max = 62000;
    config->cwin_max = 100000;
    config->data_rate_max = 4000000;
    config->nb_losses_max = 10;
}

int app_limited_reno_test()
{
    app_limited_test_config_t config;
    app_limited_config_set_default(&config, 1);
    config.ccalgo = picoquic_newreno_algorithm;

    return app_limited_test_one(&config);
}

int app_limited_cubic_test()
{
    app_limited_test_config_t config;
    app_limited_config_set_default(&config, 2);
    config.ccalgo = picoquic_cubic_algorithm;
    config.nb_losses_max = 64;
    config.data_rate_max = 4013000;

    return app_limited_test_one(&config);
}

int app_limited_bbr_test()
{
    app_limited_test_config_t config;
    app_limited_config_set_default(&config, 3);
    config.ccalgo = picoquic_bbr_algorithm;

    return app_limited_test_one(&config);
}

int app_limited_rpr_test()
{
    app_limited_test_config_t config;
    app_limited_config_set_default(&config, 4);
    config.ccalgo = picoquic_cubic_algorithm;
    config.do_preemptive_repeat = 1;
    config.loss_mask = 0x1482481224818214ull;
    config.completion_target = 46000000;
    config.nb_losses_max = 1980;
    config.rtt_max = 275000;

    return app_limited_test_one(&config);
}

#if 0
int app_limited_safe_test()
{
    app_limited_test_config_t config;
    app_limited_config_set_default(&config, 5);
    config.ccalgo = picoquic_cubic_algorithm;
    config.max_completion_time = 5100000;
    config.nb_losses_max = 1;
    config.flow_control_max = 57344;

    return app_limited_test_one(&config);
}
#endif