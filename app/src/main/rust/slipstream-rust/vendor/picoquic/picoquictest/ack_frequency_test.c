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

/* Verify that the ack frequency is correctly set.
 */

typedef enum {
    ackfrq_test_basic = 0
} ackfrq_test_enum;

typedef struct st_ackfrq_test_spec_t {
    ackfrq_test_enum test_id;
    uint64_t latency;
    uint64_t picosec_per_byte_down;
    uint64_t picosec_per_byte_up;
    picoquic_congestion_algorithm_t* ccalgo;
    uint64_t target_time;
    uint64_t max_ack_delay_remote;
    uint64_t max_ack_gap_remote;
    uint64_t min_ack_delay_remote;
    uint64_t target_interval;
} ackfrq_test_spec_t;

static test_api_stream_desc_t test_scenario_ackfrq[] = {
    { 4, 0, 257, 1000000 }
};

static int ackfrq_test_one(ackfrq_test_spec_t * spec)
{
    uint64_t simulated_time = 0;
    picoquic_connection_id_t initial_cid = { {0xac, 0xf8, 0, 0, 0, 0, 0, 0}, 8 };
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    uint64_t loss_mask = 0;
    int ret = 0;

    initial_cid.id[2] = spec->test_id;

    ret = tls_api_one_scenario_init_ex(&test_ctx, &simulated_time, PICOQUIC_INTERNAL_TEST_VERSION_1, NULL, NULL, &initial_cid, 0);

    if (ret == 0 && test_ctx == NULL) {
        ret = -1;
    }

    if (ret == 0) {
        picoquic_set_default_congestion_algorithm(test_ctx->qserver, spec->ccalgo);
        picoquic_set_congestion_algorithm(test_ctx->cnx_client, spec->ccalgo);

        test_ctx->c_to_s_link->microsec_latency = spec->latency;
        test_ctx->s_to_c_link->microsec_latency = spec->latency;

        if (spec->picosec_per_byte_down > 0) {
            test_ctx->s_to_c_link->picosec_per_byte = spec->picosec_per_byte_down;
        }
        if (spec->picosec_per_byte_up > 0) {
            test_ctx->c_to_s_link->picosec_per_byte = spec->picosec_per_byte_up;
        }

        /* set the binary logs on both sides */
        picoquic_set_binlog(test_ctx->qclient, ".");
        picoquic_set_binlog(test_ctx->qserver, ".");
        picoquic_set_log_level(test_ctx->qserver, 1);
        picoquic_set_log_level(test_ctx->qclient, 1);
        test_ctx->qclient->use_long_log = 1;
        test_ctx->qserver->use_long_log = 1;
        /* Since the client connection was created before the binlog was set, force log of connection header */
        binlog_new_connection(test_ctx->cnx_client);
        /* Initialize the client connection */
        picoquic_start_client_cnx(test_ctx->cnx_client);
    }

    /* establish the connection */
    if (ret == 0) {
        ret = tls_api_connection_loop(test_ctx, &loss_mask, 0, &simulated_time);
    }

    /* wait until the client (and thus the server) is ready */
    if (ret == 0) {
        ret = wait_client_connection_ready(test_ctx, &simulated_time);
    }

    /* Prepare to send data */
    if (ret == 0) {
        ret = test_api_init_send_recv_scenario(test_ctx, test_scenario_ackfrq, sizeof(test_scenario_ackfrq));

        if (ret != 0)
        {
            DBG_PRINTF("Init send receive scenario returns %d\n", ret);
        }
    }

    if (ret == 0) {
        ret = tls_api_data_sending_loop(test_ctx, &loss_mask, &simulated_time, 0);
    }

    /* Check that the transmission succeeded */
    if (ret == 0) {
        ret = tls_api_one_scenario_body_verify(test_ctx, &simulated_time, spec->target_time);
    }


    /* TODO: verify that the ack frequency option is negotiated */
    if (ret == 0 && !test_ctx->cnx_client->is_ack_frequency_negotiated){
        DBG_PRINTF("%s", "Ack Frequency not negotiated at client");
        ret = -1;
    }

    if (ret == 0 && !test_ctx->cnx_server->is_ack_frequency_negotiated) {
        DBG_PRINTF("%s", "Ack Frequency not negotiated at server");
        ret = -1;
    }
    /* Verify that the ack gap and ack delay are what we expected */
    if (ret == 0 && test_ctx->cnx_client->max_ack_delay_remote > spec->max_ack_delay_remote) {
        DBG_PRINTF("Max Ack Delay %" PRIu64 " > " PRIu64, test_ctx->cnx_client->max_ack_delay_remote, spec->max_ack_delay_remote);
        ret = -1;
    }
    if (ret == 0 && test_ctx->cnx_client->min_ack_delay_remote > spec->min_ack_delay_remote) {
        DBG_PRINTF("Min Ack Delay %" PRIu64 " < " PRIu64, test_ctx->cnx_client->min_ack_delay_remote, spec->min_ack_delay_remote);
        ret = -1;
    }
    if (ret == 0 && test_ctx->cnx_client->max_ack_gap_remote > spec->max_ack_gap_remote) {
        DBG_PRINTF("Max Ack Gap %" PRIu64 " > " PRIu64, test_ctx->cnx_client->max_ack_gap_remote, spec->max_ack_gap_remote);
        ret = -1;
    }

    if (ret == 0) {
        uint64_t duration = simulated_time - test_ctx->cnx_server->start_time;
        uint64_t interval = duration / test_ctx->cnx_server->nb_packets_received;
        uint64_t interval_min = interval - (interval >> 2);
        uint64_t interval_max = interval + (interval >> 2);

        if (spec->target_interval < interval_min || spec->target_interval > interval_max) {
            DBG_PRINTF("Interval %" PRIu64 " <> " PRIu64, interval, spec->target_interval);
            ret = -1;
        }
    }

    /* Verify that the average time between ACK is close to expectations */
    /* Delete the context */
    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
    }

    return ret;
}

int ackfrq_basic_test()
{
    ackfrq_test_spec_t spec = { 0 };
    spec.test_id = ackfrq_test_basic;
    spec.latency = 10000;
    spec.picosec_per_byte_up = 80000;
    spec.picosec_per_byte_down = 80000;
    spec.ccalgo = picoquic_cubic_algorithm;
    spec.max_ack_delay_remote = 6000;
    spec.max_ack_gap_remote = 40;
    spec.min_ack_delay_remote = 1000;
    spec.target_interval = 4000;

    return ackfrq_test_one(&spec);
}

int ackfrq_short_test()
{
    ackfrq_test_spec_t spec = { 0 };
    spec.test_id = ackfrq_test_basic;
    spec.latency = 10;
    spec.picosec_per_byte_up = 80000;
    spec.picosec_per_byte_down = 80000;
    spec.ccalgo = picoquic_cubic_algorithm;
    spec.max_ack_delay_remote = 1000;
    spec.max_ack_gap_remote = 32;
    spec.min_ack_delay_remote = 1000;
    spec.target_interval = 1500;

    return ackfrq_test_one(&spec);
}