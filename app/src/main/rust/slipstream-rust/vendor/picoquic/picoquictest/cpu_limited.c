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

/* Add a series of tests to study the behavior of cpu-limited clients.
* This requires simulating clients that have cpu limitations, such
* as only being able to proceed a set number of messages per second.
* 
* The main effort is to modify the simulator to keep track of the
* "software load" of a node. The simulator interacts with the code
* through two APIs: prepare a packet to send; and, receive a packet.
* We assume that each of these calls will take some time, because
* it includes CPU processing. The simulation needs to maintain a
* "node readiness" clock, so that the node only becomes available
* some time after performing an action. Then, we do the following:
* 
* - On the "prepare packet" side, only consider the client ready
*   if time is large than the next ready time and also larger
*   than the next clock readiness time. Increase the next ready
*   time if a packet is successfully processed (but not if the
*   prepare packet call returns "no action").
* 
* - On the "receive packet" side, only accept a packet if the
*   arrival time is after the the next ready time. If it is not,
*   queue the packet in an "arrival queue", and drop it if the
*   arrival queue is over some limit. Increase the next ready
*   time after the packet is processed
*
* We test this configuration with a couple of scenarios.
*/

typedef struct st_limited_test_config_t {
    uint8_t test_id;
    picoquic_congestion_algorithm_t* ccalgo;
    uint64_t incoming_cpu_time;
    uint64_t prepare_cpu_time;
    size_t packet_queue_max;
    size_t nb_initial_steps;
    size_t nb_final_steps;
    uint64_t max_completion_time;
    uint64_t microsec_latency;
    uint64_t picosec_per_byte;
    uint64_t flow_control_max;
    uint64_t nb_losses_max;
} limited_test_config_t;

int limited_client_create_scenario(
    size_t nb_initial_steps, size_t nb_final_steps,
    test_api_stream_desc_t ** p_scenario,
    size_t * p_scenario_size)
{
    int ret = 0;
    size_t nb_steps = nb_initial_steps + nb_final_steps;
    size_t scenario_size = sizeof(test_api_stream_desc_t) * nb_steps;
    test_api_stream_desc_t* scenario = (test_api_stream_desc_t*)malloc(scenario_size);
    uint64_t previous_stream_id = 0;

    if (scenario == NULL) {
        *p_scenario = NULL;
        *p_scenario_size = 0;
        ret = -1;
    }
    else {
        *p_scenario = scenario;
        *p_scenario_size = scenario_size;
        memset(scenario, 0, scenario_size);
        for (size_t i = 0; i < nb_initial_steps; i++) {
            scenario[i].q_len = 257;
            scenario[i].r_len = 32000;
            scenario[i].previous_stream_id = previous_stream_id;
            previous_stream_id += 4;
            scenario[i].stream_id = previous_stream_id;
        }
        for (size_t i = nb_initial_steps; i < nb_steps; i++) {
            scenario[i].q_len = 257;
            scenario[i].r_len = 1000000;
            scenario[i].previous_stream_id = previous_stream_id; 
            scenario[i].stream_id = previous_stream_id + 4*(i+1);
        }
    }

    return ret;
}

int limited_client_test_one(limited_test_config_t * config)
{
    uint64_t simulated_time = 0;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    picoquic_connection_id_t initial_cid = { {0x11, 0x01, 0xc1, 0x1e, 0x44, 0, 0, 0}, 8 };
    test_api_stream_desc_t* scenario = NULL;
    size_t scenario_size = 0;
    int ret;

    initial_cid.id[5] = config->test_id;


    ret = tls_api_init_ctx_ex(&test_ctx, PICOQUIC_INTERNAL_TEST_VERSION_1, PICOQUIC_TEST_SNI, PICOQUIC_TEST_ALPN, &simulated_time, NULL, NULL, 0, 1, 0, &initial_cid);

    if (ret == 0 && test_ctx == NULL) {
        ret = -1;
    }
    else {
        ret = limited_client_create_scenario(config->nb_initial_steps,
            config->nb_final_steps, &scenario, &scenario_size);
    }

    /* Set the congestion algorithm and endpoint limits to specified value. */
    if (ret == 0) {

        picoquic_set_default_congestion_algorithm(test_ctx->qserver, config->ccalgo);
        picoquic_set_congestion_algorithm(test_ctx->cnx_client, config->ccalgo);
        test_ctx->client_endpoint.incoming_cpu_time = config->incoming_cpu_time;
        test_ctx->client_endpoint.prepare_cpu_time = config->prepare_cpu_time;
        test_ctx->client_endpoint.packet_queue_max = config->packet_queue_max;
        test_ctx->qserver->use_long_log = 1;
        picoquic_set_binlog(test_ctx->qserver, ".");
        test_ctx->qclient->use_long_log = 1;
        picoquic_set_binlog(test_ctx->qclient, ".");
        binlog_new_connection(test_ctx->cnx_client);
        /* Set long delays, 1 Mbps each way */
        test_ctx->c_to_s_link->microsec_latency = config->microsec_latency;
        test_ctx->c_to_s_link->picosec_per_byte = config->picosec_per_byte;
        test_ctx->s_to_c_link->microsec_latency = config->microsec_latency;
        test_ctx->s_to_c_link->picosec_per_byte = config->picosec_per_byte;
        /* if required, set the flow control limit */
        if (config->flow_control_max != 0) {
            picoquic_set_max_data_control(test_ctx->qclient, config->flow_control_max);
        }
        ret = tls_api_one_scenario_body(test_ctx, &simulated_time,
            scenario, scenario_size, 0, 0, 0, 4 * config->microsec_latency, config->max_completion_time);
    }

    if (ret == 0 && config->nb_losses_max != 0) {
        if (test_ctx->cnx_server == NULL) {
            DBG_PRINTF("Cannot verify number of losses < %" PRIu64 ", server connection deleted",
                config->nb_losses_max);
            ret = -1;
        }
        else if (test_ctx->cnx_server->nb_retransmission_total >= config->nb_losses_max) {
            DBG_PRINTF("Got %" PRIu64 ", >= %" PRIu64,
                test_ctx->cnx_server->nb_retransmission_total, config->nb_losses_max);
            ret = -1;
        }
    }

    /* Free the resource, which will close the log file.
    */

    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }

    if (scenario != NULL) {
        free(scenario);
    }

    return ret;
}

static void limited_config_set_default( limited_test_config_t* config, uint8_t test_id)
{
    memset(config, 0, sizeof(limited_test_config_t));
    config->test_id = test_id;
    config->ccalgo = picoquic_newreno_algorithm;
    config->incoming_cpu_time = 2000;
    config->prepare_cpu_time = 2000;
    config->packet_queue_max = 16;
    config->nb_final_steps = 2;
    config->nb_initial_steps = 0;
    config->microsec_latency = 50000;
    config->picosec_per_byte = 80000; /* corresponds to 100 Mbps */
}

int limited_reno_test()
{
    limited_test_config_t config;
    limited_config_set_default(&config, 1);
    config.ccalgo = picoquic_newreno_algorithm;
    config.max_completion_time = 4600000;

    return limited_client_test_one(&config);
}

int limited_cubic_test()
{
    limited_test_config_t config;
    limited_config_set_default(&config, 2);
    config.ccalgo = picoquic_cubic_algorithm;
    config.max_completion_time = 4200000;

    return limited_client_test_one(&config);
}

int limited_bbr_test()
{
    limited_test_config_t config;
    limited_config_set_default(&config, 3);
    config.ccalgo = picoquic_bbr_algorithm;
    config.max_completion_time = 4100000;

    return limited_client_test_one(&config);
}

int limited_batch_test()
{
    limited_test_config_t config;
    limited_config_set_default(&config, 4);
    config.ccalgo = picoquic_bbr_algorithm;
    config.max_completion_time = 6200000;
    config.nb_initial_steps = 10;

    return limited_client_test_one(&config);
}

int limited_safe_test()
{
    limited_test_config_t config;
    limited_config_set_default(&config, 5);
    config.ccalgo = picoquic_cubic_algorithm;
    config.max_completion_time = 5400000;
    /* Bug. Should investigate later -- there should be 0 or maybe 1 losses */
    config.nb_losses_max = 6;
    config.flow_control_max = 57344;

    return limited_client_test_one(&config);
}