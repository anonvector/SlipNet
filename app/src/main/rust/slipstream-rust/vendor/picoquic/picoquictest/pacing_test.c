/*
* Author: Christian Huitema
* Copyright (c) 2024, Private Octopus, Inc.
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

#include "tls_api.h"
#include "picoquic_internal.h"
#include "picoquictest_internal.h"
#include <stdlib.h>
#include <string.h>

#include "logreader.h"
#include "picoquic_binlog.h"
#include "picoquic_logger.h"
#include "qlog.h"

/* Test of the pacing functions.
*/

int pacing_test()
{
    /* Create a connection so as to instantiate the pacing context */
    int ret = 0;
    uint64_t current_time = 0;
    picoquic_quic_t* quic = NULL;
    picoquic_cnx_t* cnx = NULL;
    struct sockaddr_in saddr;
    const uint64_t test_byte_per_sec = 1250000;
    const uint64_t test_quantum = 0x4000;
    int nb_sent = 0;
    int nb_round = 0;
    const int nb_target = 10000;

    quic = picoquic_create(8, NULL, NULL, NULL, NULL, NULL,
        NULL, NULL, NULL, NULL, current_time,
        &current_time, NULL, NULL, 0);

    memset(&saddr, 0, sizeof(struct sockaddr_in));
    saddr.sin_family = AF_INET;
    saddr.sin_port = 1000;

    if (quic == NULL) {
        DBG_PRINTF("%s", "Cannot create QUIC context\n");
        ret = -1;
    }
    else {
        cnx = picoquic_create_cnx(quic,
            picoquic_null_connection_id, picoquic_null_connection_id, (struct sockaddr*) & saddr,
            current_time, 0, "test-sni", "test-alpn", 1);

        if (cnx == NULL) {
            DBG_PRINTF("%s", "Cannot create connection\n");
            ret = -1;
        }
    }

    if (ret == 0) {
        /* Set pacing parameters to specified value */
        picoquic_update_pacing_rate(cnx, cnx->path[0], (double)test_byte_per_sec, test_quantum);
        /* Run a loop of N tests based on next wake time. */
        while (ret == 0 && nb_sent < nb_target) {
            nb_round++;
            if (nb_round > 4 * nb_target) {
                DBG_PRINTF("Pacing needs more that %d rounds for %d packets", nb_round, nb_target);
                ret = -1;
            }
            else {
                uint64_t next_time = current_time + 10000000;
                if (picoquic_is_sending_authorized_by_pacing(cnx, cnx->path[0], current_time, &next_time)) {
                    nb_sent++;
                    picoquic_update_pacing_after_send(cnx->path[0], cnx->path[0]->send_mtu, current_time);
                }
                else {
                    if (current_time < next_time) {
                        current_time = next_time;
                    }
                    else {
                        DBG_PRINTF("Pacing next = %" PRIu64", current = %d" PRIu64, next_time, current_time);
                        ret = -1;
                    }
                }
            }
        }

        /* Verify that the total send time matches expectations */
        if (ret == 0) {
            uint64_t volume_sent = ((uint64_t)nb_target) * cnx->path[0]->send_mtu;
            uint64_t time_max = ((volume_sent * 1000000) / test_byte_per_sec) + 1;
            uint64_t time_min = (((volume_sent - test_quantum) * 1000000) / test_byte_per_sec) + 1;

            if (current_time > time_max) {
                DBG_PRINTF("Pacing used = %" PRIu64", expected max = %d" PRIu64, current_time, time_max);
                ret = -1;
            }
            else if (current_time < time_min) {
                DBG_PRINTF("Pacing used = %" PRIu64", expected min = %d" PRIu64, current_time, time_min);
                ret = -1;
            }
        }
    }

    if (quic != NULL) {
        picoquic_free(quic);
    }

    return ret;
}

/* Test effects of leaky bucket pacer
*/

static test_api_stream_desc_t test_scenario_pacing[] = {
    { 4, 0, 257, 1000000 }
};
static int pacing_cc_algotest(picoquic_congestion_algorithm_t* cc_algo, uint64_t target_time, uint64_t loss_target)
{
    uint64_t simulated_time = 0;
    uint64_t loss_mask = 0;
    const uint64_t latency_target = 7500;
    const double bucket_increase_per_microsec = 1.25; /* 1.25 bytes per microsec = 10 Mbps */
    const uint64_t bucket_max = 16 * PICOQUIC_MAX_PACKET_SIZE;
    const uint64_t picosec_per_byte = (1000000ull * 8) / 100; /* Underlying rate = 100 Mbps */
    uint64_t observed_loss = 0;

    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    picoquic_connection_id_t initial_cid = { {0x9a, 0xc1, 0xcc, 0xa1, 0x90, 6, 7, 8}, 8 };
    int ret;

    initial_cid.id[4] = cc_algo->congestion_algorithm_number;

    ret = tls_api_init_ctx_ex(&test_ctx, PICOQUIC_INTERNAL_TEST_VERSION_1,
        PICOQUIC_TEST_SNI, PICOQUIC_TEST_ALPN, &simulated_time, NULL, NULL, 0, 0, 0, &initial_cid);

    if (ret == 0) {
        /* Set link  */
        test_ctx->c_to_s_link->microsec_latency = latency_target;
        test_ctx->c_to_s_link->picosec_per_byte = picosec_per_byte;
        test_ctx->s_to_c_link->microsec_latency = latency_target;
        test_ctx->s_to_c_link->picosec_per_byte = picosec_per_byte;
        /* Set leaky bucket parameters */
        test_ctx->c_to_s_link->bucket_increase_per_microsec = bucket_increase_per_microsec;
        test_ctx->c_to_s_link->bucket_max = bucket_max;
        test_ctx->c_to_s_link->bucket_current = (double)bucket_max;
        test_ctx->c_to_s_link->bucket_arrival_last = simulated_time;
        test_ctx->s_to_c_link->bucket_increase_per_microsec = bucket_increase_per_microsec;
        test_ctx->s_to_c_link->bucket_max = bucket_max;
        test_ctx->s_to_c_link->bucket_current = (double)bucket_max;
        test_ctx->s_to_c_link->bucket_arrival_last = simulated_time;
        /* Set the CC algorithm to selected value */
        picoquic_set_default_congestion_algorithm(test_ctx->qserver, cc_algo);
        picoquic_set_binlog(test_ctx->qserver, ".");
        test_ctx->qserver->use_long_log = 1;
    }

    if (ret == 0) {
        ret = tls_api_connection_loop(test_ctx, &loss_mask, latency_target, &simulated_time);
    }

    /* Prepare to send data */
    if (ret == 0) {
        ret = test_api_init_send_recv_scenario(test_ctx, test_scenario_pacing, sizeof(test_scenario_pacing));
    }

    /* Try to complete the data sending loop */
    if (ret == 0) {
        ret = tls_api_data_sending_loop(test_ctx, &loss_mask, &simulated_time, 0);
    }

    if (ret == 0) {
        observed_loss = (test_ctx->cnx_server == NULL) ? UINT64_MAX : test_ctx->cnx_server->nb_retransmission_total;
    }

    /* verify that the transmission was complete */
    if (ret == 0) {
        ret = tls_api_one_scenario_body_verify(test_ctx, &simulated_time, target_time);
    }

    if (ret == 0 && observed_loss > loss_target) {
        DBG_PRINTF("Pacing, for cc=%s, expected %" PRIu64 " losses, got %" PRIu64 "\n",
            cc_algo->congestion_algorithm_id, loss_target, observed_loss);
        ret = -1;
    }

    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }

    return ret;
}

int pacing_bbr_test()
{
    /* BBRv3 includes a short term loop that detects losses and tune the
    * sending rate accordingly. The packet losses cause startup to 
    * give up too soon, but this is fixed by probing up "quickly"
    * after exiting startup. The packet losses occur during startup
    * and during the probing periods.
    */
    int ret = pacing_cc_algotest(picoquic_bbr_algorithm, 900000, 160);
    return ret;
}

int pacing_cubic_test()
{
    int ret = pacing_cc_algotest(picoquic_cubic_algorithm, 900000, 210);
    return ret;
}

int pacing_dcubic_test()
{
    int ret = pacing_cc_algotest(picoquic_dcubic_algorithm, 900000, 240);
    return ret;
}

int pacing_fast_test()
{
    int ret = pacing_cc_algotest(picoquic_fastcc_algorithm, 1000000, 180);
    return ret;
}

int pacing_newreno_test()
{
    int ret = pacing_cc_algotest(picoquic_newreno_algorithm, 900000, 100);
    return ret;
}


/* Verify that pacing provides repeatable results
 */

typedef struct st_pacing_test_t {
    uint64_t current_time;
    size_t length;
    size_t send_mtu;
    uint64_t cwin;
    int slow_start;
    uint64_t rtt;
    uint64_t rate;
    uint64_t quantum;
    int expected_ok;
    uint64_t expected_packet_nanosec;
    int64_t expected_bucket_nanosec;
    uint64_t expected_next_time;
} pacing_test_t;

pacing_test_t pacing_events[] = {
    { 0, 0, 1280, 0, 0, 10000, 125000, 8096, 0, 10000000, 64768000, 0 },
    { 0, 0, 1280, 0, 0, 10000, 1250000, 8096, 0, 1024000, 6476800, 0 },
    { 0, 0, 1280, 0, 0, 10000, 12500000, 8096, 0, 102400, 647680, 0 },
    { 0, 0, 1280, 0, 0, 10000, 12500000, 16192, 0, 102400, 1295360, 0 },
    { 0, 0, 1280, 0, 0, 10000, 125000000, 16192, 0, 10240, 129536, 0 },
    { 0, 0, 1280, 0, 0, 10000, 1250000000, 16192, 0, 1024, 12953, 0 },
    { 0, 0, 1280, 0, 0, 10000, 12500000000ull, 16192, 0, 102, 1295, 0 },
    {   0,    0, 1280, 16000, 1, 10000, 2000000, 0, 0, 640000, 2000000, 0 },
    {   0,    0, 1536, 153600, 1, 10000, 19200000, 0, 0, 80000, 1280000, 0 },
    {   0,    0, 1536, 153600, 0, 10000, 15360000, 0, 0, 100000, 1600000, 0 },
    {1000, 1536, 1536,      0, 0, 10000, 0,        0, 1,      0,  900000, UINT64_MAX  },
    {1000, 1536, 1536,      0, 0, 10000, 0,        0, 1,      0,  800000, UINT64_MAX  },
    {1000, 1536, 1536,      0, 0, 10000, 0,        0, 1,      0,  700000, UINT64_MAX  },
    {1000, 1536, 1536,      0, 0, 10000, 0,        0, 1,      0,  600000, UINT64_MAX  },
    {1000, 1536, 1536,      0, 0, 10000, 0,        0, 1,      0,  500000, UINT64_MAX  },
    {1000, 1536, 1536,      0, 0, 10000, 0,        0, 1,      0,  400000, UINT64_MAX  },
    {1000, 1536, 1536,      0, 0, 10000, 0,        0, 1,      0,  300000, UINT64_MAX  },
    {1000, 1536, 1536,      0, 0, 10000, 0,        0, 1,      0,  200000, UINT64_MAX  },
    {1000, 1536, 1536,      0, 0, 10000, 0,        0, 1,      0,  100000, UINT64_MAX  },
    {1000, 1536, 1536,      0, 0, 10000, 0,        0, 1,      0,       0, UINT64_MAX  },
    {1000, 1536, 1536,      0, 0, 10000, 0,        0, 0,      0,       0, 1101  },
    {1050, 1536, 1536,      0, 0, 10000, 0,        0, 0,      0,   50000, 1101  },
    {1101, 1536, 1536,      0, 0, 10000, 0,        0, 1,      0,    1000, UINT64_MAX  }
};

size_t nb_pacing_events = sizeof(pacing_events) / sizeof(pacing_test_t);

int pacing_repeat_test()
{
    int ret = 0;
    picoquic_pacing_t pacing = { 0 };

    /* set either CWIN or data rate to expected value */
    for (size_t i = 0; ret == 0 && i < nb_pacing_events; i++) {
        if (pacing_events[i].length == 0) {
            /* This is a set up event */
            if (pacing_events[i].cwin == 0) {
                /* directly set the quantum and rate */
                picoquic_update_pacing_parameters(&pacing, (double)pacing_events[i].rate, 
                    pacing_events[i].quantum, pacing_events[i].send_mtu, pacing_events[i].rtt,
                    NULL);
            }
            else {
                /* Set control based on CWIN and RTT */
                picoquic_update_pacing_window(&pacing, pacing_events[i].slow_start,
                    pacing_events[i].cwin, pacing_events[i].send_mtu, pacing_events[i].rtt, NULL);
            }
            /* Check that the value are as expected */
            if (pacing.rate != pacing_events[i].rate ||
                pacing.packet_time_nanosec != pacing_events[i].expected_packet_nanosec ||
                pacing.bucket_max != pacing_events[i].expected_bucket_nanosec) {
                DBG_PRINTF("Event %d, expected rate: " PRIu64 ", Packet_n: " PRIu64 ", Bucket: " PRIu64,
                    i, pacing.rate, pacing.packet_time_nanosec, pacing.bucket_max);
                ret = -1;
            }
        }
        else {
            /* Set using CWIN and RTT */
            uint64_t next_time = UINT64_MAX;
            int is_ok = picoquic_is_authorized_by_pacing(&pacing, pacing_events[i].current_time, &next_time, 0, NULL);
            if (is_ok != pacing_events[i].expected_ok) {
                DBG_PRINTF("Event %d, expected OK: %d", i, is_ok);
                ret = -1;
            }
            else {
                if (is_ok) {
                    picoquic_update_pacing_data_after_send(&pacing, pacing_events[i].length, pacing_events[i].send_mtu, pacing_events[i].current_time);
                }
            }
            if (pacing.bucket_nanosec != pacing_events[i].expected_bucket_nanosec ||
                next_time != pacing_events[i].expected_next_time) {
                DBG_PRINTF("Event %d, expected bucket: " PRIu64,
                    i, pacing.rate, pacing.bucket_nanosec);
                ret = -1;
            }
        }
    }
    return ret;
}