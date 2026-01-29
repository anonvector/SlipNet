/*
* Author: Christian Huitema
* Copyright (c) 2019, Private Octopus, Inc.
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
#include <stdint.h>
#include <math.h>
#include "picoquic.h"
#include "picoquic_utils.h"
#include "picoquictest_internal.h"
#include "autoqlog.h"
#include "picoquic_binlog.h"

/* Wifi test: explore the behavior of QUIC over Wi-Fi links.
* 
* We are particularly concern over reporta that WiFi links sometimes
* become unavailable for a "scanning" interval of 100 to 250ms. In the worse
* case scenario, there may be several consecutive intervals. The intervals
* may happen on the sending link or on the receiving link.
* 
* The first test looks at a single interval, either on up or down link.
* The interval typically happens every 5 seconds or so, so we can rig
* a simulation that lasts at least 5 seconds. The Wi-Fi link is about
* 100 mbps, but we will simulate a lower datarate so we can test without
* spending too much CPU.
* 
* This required adding a "spike" simulation in the link simulator,
* which is provided by the new "suspend" API.
* 
* 
* TODO: develop a version of the "hard" test to validate an adaptive
* response. Use the "max_rtt", which is dynamic, in pretty much the
* same way that the "shadow rtt" is used in the current code. 
* 
*/

typedef enum {
    wifi_test_reno = 0,
    wifi_test_cubic,
    wifi_test_bbr,
    wifi_test_reno_hard,
    wifi_test_cubic_hard,
    wifi_test_bbr_hard,
    wifi_test_reno_long,
    wifi_test_cubic_long,
    wifi_test_bbr_long,
    wifi_test_bbr_shadow,
    wifi_test_bbr_many,
    wifi_test_bbr1,
    wifi_test_bbr1_hard,
    wifi_test_bbr1_long
} wifi_test_enum;

typedef struct st_wifi_test_suspension_t {
    uint64_t suspend_time;
    uint64_t suspend_interval;
} wifi_test_suspension_t;

typedef struct st_wifi_test_spec_t {
    size_t nb_suspend;
    uint64_t latency;
    wifi_test_suspension_t * suspension;
    picoquic_congestion_algorithm_t* ccalgo;
    uint64_t target_time;
    int simulate_receive_block;
    uint64_t wifi_shadow_rtt;
    uint64_t queue_max_delay;
} wifi_test_spec_t;

static test_api_stream_desc_t test_scenario_wifi[] = {
    { 4, 0, 257, 1000000 },
    { 8, 0, 4, 1000000 },
    { 12, 0, 8, 1000000 }
};

static int wifi_test_one(wifi_test_enum test_id, wifi_test_spec_t * spec)
{
    uint64_t simulated_time = 0;
    picoquic_connection_id_t initial_cid = { {0x81, 0xf1, 0, 0, 0, 0, 0, 0}, 8 };
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    uint64_t loss_mask = 0;
    int ret = 0;
    
    initial_cid.id[2] = test_id;

    ret = tls_api_one_scenario_init_ex(&test_ctx, &simulated_time, PICOQUIC_INTERNAL_TEST_VERSION_1, NULL, NULL, &initial_cid, 0);

    if (ret == 0 && test_ctx == NULL) {
        ret = -1;
    }

    if (ret == 0) {
        if (spec->wifi_shadow_rtt > 0) {
            picoquic_set_default_wifi_shadow_rtt(test_ctx->qserver, spec->wifi_shadow_rtt);
            picoquic_set_default_wifi_shadow_rtt(test_ctx->qclient, spec->wifi_shadow_rtt);
        }

        picoquic_set_default_congestion_algorithm(test_ctx->qserver, spec->ccalgo);
        picoquic_set_congestion_algorithm(test_ctx->cnx_client, spec->ccalgo);

        test_ctx->c_to_s_link->microsec_latency = spec->latency;
        test_ctx->s_to_c_link->microsec_latency = spec->latency;
        test_ctx->immediate_exit = 1;

        picoquic_cnx_set_pmtud_required(test_ctx->cnx_client, 1);

        /* set the binary logs on both sides */
        picoquic_set_qlog(test_ctx->qclient, ".");
        picoquic_set_qlog(test_ctx->qserver, ".");
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
        ret = tls_api_connection_loop(test_ctx, &loss_mask, spec->queue_max_delay, &simulated_time);
    }

    /* wait until the client (and thus the server) is ready */
    if (ret == 0) {
        ret = wait_client_connection_ready(test_ctx, &simulated_time);
    }

    /* Prepare to send data */
    if (ret == 0) {
        ret = test_api_init_send_recv_scenario(test_ctx, test_scenario_wifi, sizeof(test_scenario_wifi));

        if (ret != 0)
        {
            DBG_PRINTF("Init send receive scenario returns %d\n", ret);
        }
    }

    if (ret == 0) {
        for (size_t i = 0; i < spec->nb_suspend; i++) {
            ret = tls_api_wait_for_timeout(test_ctx, &simulated_time, spec->suspension[i].suspend_time - simulated_time);
            if (ret == 0) {
                /* suspension blocks both directions, as the client can neither send not receive */
                uint64_t resume_time = spec->suspension[i].suspend_time + spec->suspension[i].suspend_interval;
                picoquic_test_simlink_suspend(test_ctx->c_to_s_link, resume_time, 0);
                picoquic_test_simlink_suspend(test_ctx->s_to_c_link, resume_time, spec->simulate_receive_block);
            }
            else {
                DBG_PRINTF("Timeout wait %d returns %d\n", i, ret);
            }
        }
    }

    if (ret == 0) {
        ret = tls_api_data_sending_loop(test_ctx, &loss_mask, &simulated_time, 0);
    }

    /* Check that the transmission succeeded */
    if (ret == 0) {
        ret = tls_api_one_scenario_body_verify(test_ctx, &simulated_time, spec->target_time);
    }

    /* Check that RTT max is consistent with suspension time.
     * Test on server only, as client is only sending ACKs.
     */
    if (ret == 0) {
        if (test_ctx->cnx_server->path[0]->rtt_max < spec->suspension->suspend_interval) {
            DBG_PRINTF("Expected rtt_max > %" PRIu64 ", got %" PRIu64, spec->suspension->suspend_interval,
                test_ctx->cnx_server->path[0]->rtt_max);
            ret = -1;
        }
    }

    /* Delete the context */
    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
    }

    return ret;
}

static wifi_test_suspension_t suspension_basic[] = {
    { 1000000, 250000 }
};

static size_t nb_suspension_basic = sizeof(suspension_basic) / sizeof(wifi_test_suspension_t);

void wifi_test_set_default_spec(wifi_test_spec_t* spec, picoquic_congestion_algorithm_t* ccalgo, uint64_t target_time)
{
    memset(spec, 0, sizeof(wifi_test_spec_t));

    spec->nb_suspend = nb_suspension_basic;
    spec->latency = 3000;
    spec->suspension = suspension_basic;
    spec->ccalgo = ccalgo;
    spec->target_time = target_time;
    spec->simulate_receive_block = 0;
    spec->wifi_shadow_rtt = 0;
    spec->queue_max_delay = 260000;
}

int wifi_bbr_test()
{
    wifi_test_spec_t spec;
    wifi_test_set_default_spec(&spec, picoquic_bbr_algorithm, 2800000);
    int ret = wifi_test_one(wifi_test_bbr, &spec);

    return ret;
}

int wifi_bbr1_test()
{
    wifi_test_spec_t spec;
    wifi_test_set_default_spec(&spec, picoquic_bbr1_algorithm, 2800000);
    int ret = wifi_test_one(wifi_test_bbr, &spec);

    return ret;
}

int wifi_cubic_test()
{
    wifi_test_spec_t spec;
    wifi_test_set_default_spec(&spec, picoquic_cubic_algorithm, 2870000);

    int ret = wifi_test_one(wifi_test_cubic, &spec);

    return ret;
}

int wifi_reno_test()
{
    wifi_test_spec_t spec;
    wifi_test_set_default_spec(&spec, picoquic_newreno_algorithm, 2800000);
    int ret = wifi_test_one(wifi_test_reno, &spec);

    return ret;
}

static wifi_test_suspension_t suspension_hard[] = {
    { 1000000, 250000 },
    { 1255000, 250000 },
    { 1510000, 250000 },
    { 1765000, 250000 },
    { 2020000, 250000 },
    { 2275000, 250000 },
};

static size_t nb_suspension_hard = sizeof(suspension_hard) / sizeof(wifi_test_suspension_t);

int wifi_bbr_hard_test()
{
    wifi_test_spec_t spec = {
        nb_suspension_hard,
        3000,
        suspension_hard,
        picoquic_bbr_algorithm,
        4060000,
        0 };
    int ret = wifi_test_one(wifi_test_bbr_hard, &spec);

    return ret;
}

int wifi_bbr1_hard_test()
{
    wifi_test_spec_t spec = {
        nb_suspension_hard,
        3000,
        suspension_hard,
        picoquic_bbr1_algorithm,
        4060000,
        0 };
    int ret = wifi_test_one(wifi_test_bbr1_hard, &spec);

    return ret;
}

int wifi_cubic_hard_test()
{
    wifi_test_spec_t spec = {
        nb_suspension_hard,
        3000,
        suspension_hard,
        picoquic_cubic_algorithm,
        4700000,
        0 };
    int ret = wifi_test_one(wifi_test_cubic_hard, &spec);

    return ret;
}

int wifi_reno_hard_test()
{
    wifi_test_spec_t spec = {
        nb_suspension_hard,
        3000,
        suspension_hard,
        picoquic_newreno_algorithm,
        4250000,
        0 };
    int ret = wifi_test_one(wifi_test_reno_hard, &spec);

    return ret;
}

int wifi_bbr_long_test()
{
    wifi_test_spec_t spec = {
        nb_suspension_basic,
        50000,
        suspension_basic,
        picoquic_bbr_algorithm,
        3400000,
        1 };
    int ret = wifi_test_one(wifi_test_bbr_long, &spec);

    return ret;
}

int wifi_bbr1_long_test()
{
    wifi_test_spec_t spec = {
        nb_suspension_basic,
        50000,
        suspension_basic,
        picoquic_bbr1_algorithm,
        3400000,
        1 };
    int ret = wifi_test_one(wifi_test_bbr1_long, &spec);

    return ret;
}

int wifi_cubic_long_test()
{
    wifi_test_spec_t spec;
    wifi_test_set_default_spec(&spec, picoquic_cubic_algorithm, 3100000);
    spec.latency = 50000;
    spec.simulate_receive_block = 1;
    int ret = wifi_test_one(wifi_test_cubic_long, &spec);

    return ret;
}

int wifi_reno_long_test()
{
    wifi_test_spec_t spec;
    wifi_test_set_default_spec(&spec, picoquic_newreno_algorithm, 3000000);
    spec.latency = 50000;
    spec.simulate_receive_block = 1;

    int ret = wifi_test_one(wifi_test_reno_long, &spec);

    return ret;
}

int wifi_bbr_shadow_test()
{
    wifi_test_spec_t spec;
    wifi_test_set_default_spec(&spec, picoquic_bbr_algorithm, 2750000);
    spec.wifi_shadow_rtt = 250000;
    spec.queue_max_delay = 600000;
    spec.simulate_receive_block = 1;

    int ret = wifi_test_one(wifi_test_bbr_shadow, &spec);

    return ret;
}

static wifi_test_suspension_t suspension_many[] = {
    { 1000000, 250000 },
    { 1500000, 250000 },
    { 2000000, 250000 },
    { 2500000, 250000 },
    { 3000000, 250000 },
    { 3500000, 250000 },
};

static size_t nb_suspension_many = sizeof(suspension_many) / sizeof(wifi_test_suspension_t);

int wifi_bbr_many_test()
{
    wifi_test_spec_t spec = {
        nb_suspension_many,
        3000,
        suspension_many,
        picoquic_bbr_algorithm,
        4070000,
        0 };
    int ret = wifi_test_one(wifi_test_bbr_many, &spec);

    return ret;
}