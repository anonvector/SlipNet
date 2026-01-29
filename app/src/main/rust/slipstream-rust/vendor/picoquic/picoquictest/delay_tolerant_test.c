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


/* Delay tolerant networking tests.
 *  
 * These tests are added at the request of Marc Blanchet, who would like
 * to study usability of QUIC in "deep space" scenarios. The pre-existing
 * "high latency" test demonstrate use of a non-modified QUIC stack with
 * latency of 5 seconds, or RTT of 10 seconds. This is enough for lunar
 * communication, but not adequate for communication with distant planets,
 * let alone communication with probes leaving the solar system. In
 * contrast with the basic high latency tests, the delay tolerant tests
 * assume that the QUIC stack is reconfigured to handle large delays,
 * with special configuration of both clients and servers. The tests
 * help us design the corresponding extension.
 */

typedef struct st_dtn_test_spec_t {
    uint64_t latency;
    uint64_t max_completion_time;
    picoquic_congestion_algorithm_t* ccalgo;
    test_api_stream_desc_t* scenario;
    size_t sizeof_scenario;
    uint64_t mbps_up;
    uint64_t mbps_down;
    uint64_t initial_flow_control_credit;
    uint64_t max_number_of_packets;
    int has_loss;
} dtn_test_spec_t;

static int dtn_test_one(uint8_t test_id, dtn_test_spec_t * spec)
{
    uint64_t simulated_time = 0;
    uint64_t picoseq_per_byte_up = (1000000ull * 8) / spec->mbps_up;
    uint64_t picoseq_per_byte_down = (1000000ull * 8) / spec->mbps_down;
    picoquic_tp_t client_parameters;
    picoquic_tp_t server_parameters;
    picoquic_connection_id_t initial_cid = { {0xde, 0x40, 0, 0, 0, 0, 0, 0}, 8 };
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    int ret = 0;

    initial_cid.id[2] = test_id;

    memset(&client_parameters, 0, sizeof(picoquic_tp_t));
    picoquic_init_transport_parameters(&client_parameters, 1);
    client_parameters.enable_time_stamp = 3;
    client_parameters.max_idle_timeout = (uint32_t)((spec->latency * 5)/1000);
    if (spec->initial_flow_control_credit > client_parameters.initial_max_data) {
        client_parameters.initial_max_data = spec->initial_flow_control_credit;
    }
    if (spec->initial_flow_control_credit > client_parameters.initial_max_stream_data_bidi_local ) {
        client_parameters.initial_max_stream_data_bidi_local = spec->initial_flow_control_credit;
    }
    if (spec->initial_flow_control_credit > client_parameters.initial_max_stream_data_bidi_remote ) {
        client_parameters.initial_max_stream_data_bidi_remote = spec->initial_flow_control_credit;
    }
    memset(&server_parameters, 0, sizeof(picoquic_tp_t));
    picoquic_init_transport_parameters(&server_parameters, 0);
    server_parameters.enable_time_stamp = 3;
    server_parameters.max_idle_timeout = client_parameters.max_idle_timeout;

    ret = tls_api_one_scenario_init_ex(&test_ctx, &simulated_time, PICOQUIC_INTERNAL_TEST_VERSION_1, &client_parameters, &server_parameters, &initial_cid, 0);

    if (ret == 0 && test_ctx == NULL) {
        ret = -1;
    }

    if (ret == 0) {
        picoquic_set_default_congestion_algorithm(test_ctx->qserver, spec->ccalgo);
        picoquic_set_congestion_algorithm(test_ctx->cnx_client, spec->ccalgo);

        test_ctx->c_to_s_link->microsec_latency = spec->latency;
        test_ctx->c_to_s_link->picosec_per_byte = picoseq_per_byte_up;
        test_ctx->s_to_c_link->microsec_latency = spec->latency;
        test_ctx->s_to_c_link->picosec_per_byte = picoseq_per_byte_down;
        test_ctx->stream0_flow_release = 1;
        test_ctx->immediate_exit = 1;

        picoquic_cnx_set_pmtud_required(test_ctx->cnx_client, 1);

        /* Set the binary log on the server side */
        picoquic_set_qlog(test_ctx->qserver, ".");
        test_ctx->qserver->use_long_log = 1;

        /* set the binary log on the client side */
        picoquic_set_qlog(test_ctx->qclient, ".");
        test_ctx->qclient->use_long_log = 1;
        /* Since the client connection was created before the binlog was set, force log of connection header */
        binlog_new_connection(test_ctx->cnx_client);

        if (ret == 0) {
            ret = tls_api_one_scenario_body(test_ctx, &simulated_time,
                spec->scenario, spec->sizeof_scenario, 0, (spec->has_loss) ? 0x10000000 : 0, 0, 2 * spec->latency, spec->max_completion_time);
        }
    }

    /* Free the resource, which will close the log file.
     */

    if (test_ctx != NULL) {
        if (spec->max_number_of_packets != 0 && ret == 0) {
            if (test_ctx->cnx_client != NULL) {
                uint64_t number_of_packets = test_ctx->cnx_client->nb_packets_sent + test_ctx->cnx_client->nb_packets_received;

                if (number_of_packets > spec->max_number_of_packets) {
                    DBG_PRINTF("Expected at most %" PRIu64 "packets, got %" PRIu64,
                        spec->max_number_of_packets, number_of_packets);
                    ret = -1;
                }
            }
            else {
                DBG_PRINTF("%s", "Cannot estimate number of packets");
                ret = -1;
            }
        }
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }

    return ret;
}

/* Basic test. Just verify that the handshake completes, and that a small
 * document can be downloaded
 */

static test_api_stream_desc_t dtn_scenario_basic[] = {
    { 4, 0, 257, 2000 }
};

void dtn_set_basic_test_spec(dtn_test_spec_t* spec)
{
    memset(spec, 0, sizeof(dtn_test_spec_t));
    spec->latency = 60000000;
    spec->max_completion_time = 8* spec->latency;
    spec->ccalgo = picoquic_newreno_algorithm;
    spec->scenario = dtn_scenario_basic;
    spec->sizeof_scenario = sizeof(dtn_scenario_basic);
    spec->mbps_up = 10;
    spec->mbps_down = 10;
    spec->has_loss = 0;
}

int dtn_basic_test()
{
    /* Simple test. */
    dtn_test_spec_t spec;
    dtn_set_basic_test_spec(&spec);
    spec.max_number_of_packets = 120;

    return dtn_test_one(0xba, &spec);
}

static test_api_stream_desc_t dtn_scenario_data[] = {
    { 4, 0, 257, 100000000 }
};


int dtn_data_test()
{
    /* Simple test. */
    dtn_test_spec_t spec;
    dtn_set_basic_test_spec(&spec);
    spec.scenario = dtn_scenario_data;
    spec.sizeof_scenario = sizeof(dtn_scenario_data);
    spec.initial_flow_control_credit = 100000000; /* 100 MB, same as data size in scenario */
    spec.max_completion_time = 500000000; /* 8 minutes and 20 sec, including 2 minutes handshae, 2 minutes req/resp, 2 minutes chirp... */
    return dtn_test_one(0xda, &spec);
}


static test_api_stream_desc_t dtn_scenario_silence[] = {
    { 4, 0, 257, 257 },
    { 8, 4, 257, 257 },
    { 12, 8, 257, 257 }
};

int dtn_silence_test()
{
    /* Simple test. */
    dtn_test_spec_t spec;
    dtn_set_basic_test_spec(&spec);
    spec.scenario = dtn_scenario_silence;
    spec.sizeof_scenario = sizeof(dtn_scenario_silence);
    spec.max_number_of_packets = 120; /* Check that the number of packets does not increase wildly */
    spec.max_completion_time = 481000000; /* 8 minutes: 2 for handshake, plus 2 per transaction */
    return dtn_test_one(0x51, &spec);
}

int dtn_twenty_test()
{
    /* Simple test. */
    dtn_test_spec_t spec;
    dtn_set_basic_test_spec(&spec);
    spec.latency = 20 * 60000000;
    spec.max_completion_time = 8* spec.latency;

    spec.max_number_of_packets = 190;

    return dtn_test_one(0x20, &spec);
}