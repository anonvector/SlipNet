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

#include "tls_api.h"
#include "picoquic_internal.h"
#include "picoquictest_internal.h"
#include <stdlib.h>
#include <string.h>

#include "logreader.h"
#include "picoquic_binlog.h"
#include "picoquic_logger.h"
#include "qlog.h"

static test_api_stream_desc_t test_scenario_congestion[] = {
    { 4, 0, 257, 1000000 },
    { 8, 4, 257, 1000000 },
    { 12, 8, 257, 1000000 },
    { 16, 12, 257, 1000000 }
};

static test_api_stream_desc_t test_scenario_10mb[] = {
    { 4, 0, 257, 1000000 },
    { 8, 0, 257, 1000000 },
    { 12, 0, 257, 1000000 },
    { 16, 0, 257, 1000000 },
    { 20, 0, 257, 1000000 },
    { 24, 0, 257, 1000000 },
    { 28, 0, 257, 1000000 },
    { 32, 0, 257, 1000000 },
    { 36, 0, 257, 1000000 },
    { 40, 0, 257, 1000000 }
};

static test_api_stream_desc_t test_scenario_very_long[] = {
    { 4, 0, 257, 1000000 }
};


static char const* ticket_file_name = "resume_tests_tickets.bin";

static int congestion_control_test(picoquic_congestion_algorithm_t* ccalgo, uint64_t max_completion_time, uint64_t jitter, uint8_t jitter_id)
{
    uint64_t simulated_time = 0;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    picoquic_connection_id_t initial_cid = { {0xcc, 0xcc, 0, 0, 0, 0, 0, 0}, 8 };
    int ret;

    initial_cid.id[2] = ccalgo->congestion_algorithm_number;
    initial_cid.id[3] = jitter_id;

    ret = tls_api_init_ctx_ex(&test_ctx, PICOQUIC_INTERNAL_TEST_VERSION_1, PICOQUIC_TEST_SNI, PICOQUIC_TEST_ALPN, &simulated_time, NULL, NULL, 0, 1, 0, &initial_cid);

    if (ret == 0 && test_ctx == NULL) {
        ret = -1;
    }

    /* Set the congestion algorithm to specified value. Also, request a packet trace */
    if (ret == 0) {

        picoquic_set_default_congestion_algorithm(test_ctx->qserver, ccalgo);
        picoquic_set_congestion_algorithm(test_ctx->cnx_client, ccalgo);

        test_ctx->c_to_s_link->jitter = jitter;
        test_ctx->s_to_c_link->jitter = jitter;

        picoquic_set_binlog(test_ctx->qserver, ".");

        ret = tls_api_one_scenario_body(test_ctx, &simulated_time,
            test_scenario_congestion, sizeof(test_scenario_congestion), 0, 0, 0, 20000 + 2 * jitter, max_completion_time);
    }

    /* Free the resource, which will close the log file.
     */

    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }

    return ret;
}

int cubic_test()
{
    return congestion_control_test(picoquic_cubic_algorithm, 3500000, 0, 0);
}

int cubic_jitter_test()
{
    return congestion_control_test(picoquic_cubic_algorithm, 3550000, 5000, 5);
}

int fastcc_test()
{
    return congestion_control_test(picoquic_fastcc_algorithm, 3700000, 0, 0);
}

int fastcc_jitter_test()
{
    return congestion_control_test(picoquic_fastcc_algorithm, 4050000, 5000, 5);
}

int bbr_test()
{
    return congestion_control_test(picoquic_bbr_algorithm, 3500000, 0, 0);
}

int bbr_jitter_test()
{
    return congestion_control_test(picoquic_bbr_algorithm, 3600000, 5000, 5);
}

static int congestion_long_test(picoquic_congestion_algorithm_t* ccalgo)
{
    uint64_t simulated_time = 0;
    uint64_t loss_mask = 0;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    picoquic_connection_id_t initial_cid = { {0xbb, 0xcc, 0x10, 0, 0, 0, 0, 0}, 8 };
    int ret;


    ret = tls_api_init_ctx_ex(&test_ctx, PICOQUIC_INTERNAL_TEST_VERSION_1, PICOQUIC_TEST_SNI, PICOQUIC_TEST_ALPN, &simulated_time, NULL, NULL, 0, 1, 0, &initial_cid);

    if (ret == 0 && test_ctx == NULL) {
        ret = -1;
    }

    /* Set the congestion algorithm to specified value. Also, request a packet trace */
    if (ret == 0) {
        picoquic_set_default_congestion_algorithm(test_ctx->qserver, ccalgo);
        picoquic_set_congestion_algorithm(test_ctx->cnx_client, ccalgo);


        test_ctx->c_to_s_link->jitter = 0;
        test_ctx->s_to_c_link->jitter = 0;
        test_ctx->c_to_s_link->picosec_per_byte = 8000000; /* Simulate 1 Mbps */

        picoquic_set_binlog(test_ctx->qserver, ".");
        test_ctx->qserver->use_long_log = 1;

        ret = tls_api_one_scenario_body_connect(test_ctx, &simulated_time, 0, 0, 0);
        if (ret != 0)
        {
            DBG_PRINTF("Connection loop returns %d\n", ret);
        }
    }

    /* Prepare to send data */
    if (ret == 0) {
        ret = test_api_init_send_recv_scenario(test_ctx, test_scenario_congestion, sizeof(test_scenario_congestion));

        if (ret != 0)
        {
            DBG_PRINTF("Init send receive scenario returns %d\n", ret);
        }
    }

    /* Run a data sending loop for 1024 rounds, causing BBR to detect a low RTT */
    if (ret == 0) {
        ret = tls_api_data_sending_loop(test_ctx, &loss_mask, &simulated_time, 1024);

        if (ret != 0)
        {
            DBG_PRINTF("Data sending loop returns %d\n", ret);
        }
    }

    /* Increase the RTT from the previous value, which will cause the bandwidth to drop unless RTT is reset  */
    if (ret == 0) {
        test_ctx->c_to_s_link->microsec_latency = 5 * test_ctx->c_to_s_link->microsec_latency;
        test_ctx->s_to_c_link->microsec_latency = 5 * test_ctx->s_to_c_link->microsec_latency;
    }


    /* Perform a data sending loop */
    if (ret == 0) {
        ret = tls_api_data_sending_loop(test_ctx, &loss_mask, &simulated_time, 0);

        if (ret != 0)
        {
            DBG_PRINTF("Data sending loop returns %d\n", ret);
        }
    }

    if (ret == 0) {
        ret = tls_api_one_scenario_body_verify(test_ctx, &simulated_time, 15000000);
    }

    /* Free the resource, which will close the log file. */

    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }

    return ret;
}

int bbr_long_test()
{
    return congestion_long_test(picoquic_bbr_algorithm);
}


int bbr1_test()
{
    return congestion_control_test(picoquic_bbr1_algorithm, 3600000, 0, 0);
}

int bbr1_long_test()
{
    return congestion_long_test(picoquic_bbr1_algorithm);
}

/* Performance test.
 * Check a variety of challenging scenarios
 */

int performance_test_one(uint64_t max_completion_time, uint64_t mbps, uint64_t rkbps, uint64_t latency,
    uint64_t jitter, uint64_t buffer_size, picoquic_tp_t* server_parameters)
{
    uint64_t simulated_time = 0x0005a138fbde8743; /* Init to non zero time to test handling of time in cc algorithm */
    uint64_t picoseq_per_byte_100 = (1000000ull * 8) / mbps;
    uint64_t picoseq_per_byte_return = (rkbps == 0) ? picoseq_per_byte_100 : (1000000000ull * 8) / rkbps;
    picoquic_connection_id_t initial_cid = { {0xbb, 0xcc, 0, 0, 0, 0, 0, 0}, 8 };
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    picoquic_congestion_algorithm_t* ccalgo = picoquic_bbr_algorithm;
    uint64_t buffer_id = (buffer_size * 16) / (latency + jitter);
    int ret = 0;


    initial_cid.id[3] = (rkbps > 0xff) ? 0xff : (uint8_t)rkbps;
    initial_cid.id[4] = (mbps > 0xff) ? 0xff : (uint8_t)mbps;
    initial_cid.id[5] = (latency > 2550000) ? 0xff : (uint8_t)(latency / 10000);
    initial_cid.id[6] = (jitter > 255000) ? 0xff : (uint8_t)(jitter / 1000);
    initial_cid.id[7] = (buffer_id > 255) ? 0xff : (uint8_t)buffer_id;

    ret = tls_api_one_scenario_init_ex(&test_ctx, &simulated_time, PICOQUIC_INTERNAL_TEST_VERSION_1, NULL, server_parameters, &initial_cid, 0);

    if (ret == 0 && test_ctx == NULL) {
        ret = -1;
    }

    if (ret == 0) {
        picoquic_set_default_congestion_algorithm(test_ctx->qserver, ccalgo);
        picoquic_set_congestion_algorithm(test_ctx->cnx_client, ccalgo);
        test_ctx->qserver->use_long_log = 1;

        picoquic_set_binlog(test_ctx->qserver, ".");
        picoquic_set_binlog(test_ctx->qclient, ".");

        test_ctx->c_to_s_link->jitter = jitter;
        test_ctx->c_to_s_link->microsec_latency = latency;
        test_ctx->c_to_s_link->picosec_per_byte = picoseq_per_byte_return;
        test_ctx->s_to_c_link->microsec_latency = latency;
        test_ctx->s_to_c_link->picosec_per_byte = picoseq_per_byte_100;
        test_ctx->s_to_c_link->jitter = jitter;

        if (ret == 0) {
            ret = tls_api_one_scenario_body(test_ctx, &simulated_time, test_scenario_10mb, sizeof(test_scenario_10mb), 0, 0, 0, buffer_size, max_completion_time);
        }
    }

    /* Free the resource, which will close the log file.
     */

    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }

    return ret;
}

int performance_test(uint64_t max_completion_time, uint64_t mbps, uint64_t latency, uint64_t jitter, uint64_t buffer_size)
{
    return performance_test_one(max_completion_time, mbps, 0, latency, jitter, buffer_size, NULL);
}

/* BBR Performance test.
 * Verify that 10 MB can be downloaded in less than 1 second on a 100 mbps link.
 */

int bbr_performance_test()
{
    uint64_t max_completion_time = 1050000;
    uint64_t latency = 10000;
    uint64_t jitter = 3000;
    uint64_t buffer = 2 * (latency + jitter);
    uint64_t mbps = 100;

    int ret = performance_test(max_completion_time, mbps, latency, jitter, buffer);

    return ret;
}

/* BBR Performance test on a slow long link
 * Verify that 10 MB can be downloaded in less than 100 seconds on a 1 mbps link.
 */

int bbr_slow_long_test()
{
    uint64_t max_completion_time = 81000000;
    uint64_t latency = 300000;
    uint64_t jitter = 3000;
    uint64_t buffer = 2 * (latency + jitter);
    uint64_t mbps = 1;

    int ret = performance_test(max_completion_time, mbps, latency, jitter, buffer);

    return ret;
}

/* BBR Performance test on a pathological long link, with 2 seconds RTT
 * Verify that 10 MB can be downloaded in less than 128 seconds on a 1 mbps link.
 */

int bbr_one_second_test()
{
    uint64_t max_completion_time = 90000000;
    uint64_t latency = 1000000;
    uint64_t jitter = 3000;
    uint64_t buffer = 2 * (latency + jitter);
    uint64_t mbps = 1;

    int ret = performance_test(max_completion_time, mbps, latency, jitter, buffer);

    return ret;
}


/* AWS like performance test
 * Verify that 10MB can be downloaded very fast on a low latency Gbps link. */
int gbps_performance_test()
{
    uint64_t max_completion_time = 250000;
    uint64_t latency = 4000;
    uint64_t jitter = 2000;
    uint64_t buffer = 2 * (latency + jitter);
    uint64_t mbps = 1000;

    int ret = performance_test(max_completion_time, mbps, latency, jitter, buffer);

    return ret;
}


/* Asymmetric test.
 * Verify that 10MB can be downloaded reasonably fast on a low latency 10Mbps link with 100kbps return path
 * The buffer size is set to a high value, which allows queues to grow and delays to build up. In theory,
 * BBR should minimize these queues, but the test verifies that it actually does.
 */
int bbr_asym100_test()
{
    uint64_t max_completion_time = 8500000;
    uint64_t latency = 1000;
    uint64_t jitter = 750;
    uint64_t buffer = 50000;
    uint64_t mbps = 10;
    uint64_t kbps = 100;

    int ret = performance_test_one(max_completion_time, mbps, kbps, latency, jitter, buffer, NULL);

    return ret;
}

/* Asymmetric test, no delay.
 * Variant in which the negotiation of delayed ACK is disabled.
 */
int bbr_asym100_nodelay_test()
{
    uint64_t max_completion_time = 8500000;
    uint64_t latency = 1000;
    uint64_t jitter = 750;
    uint64_t buffer = 50000;
    uint64_t mbps = 10;
    uint64_t kbps = 100;
    picoquic_tp_t server_parameters;

    memset(&server_parameters, 0, sizeof(picoquic_tp_t));
    picoquic_init_transport_parameters(&server_parameters, 1);
    server_parameters.min_ack_delay = 0;

    int ret = performance_test_one(max_completion_time, mbps, kbps, latency, jitter, buffer,
        &server_parameters);

    return ret;
}

/* Asymmetric test.
 * Variant using 400 kbps return path and a 40 Mbps link
 */
int bbr_asym400_test()
{
    uint64_t max_completion_time = 2350000;
    uint64_t latency = 1000;
    uint64_t jitter = 750;
    uint64_t buffer = 50000;
    uint64_t mbps = 40;
    uint64_t kbps = 400;

    int ret = performance_test_one(max_completion_time, mbps, kbps, latency, jitter, buffer, NULL);

    return ret;
}

/* Tests of BDP option.
 * = Verify that a download works faster with BDP option enabled
 * = Verify that the BDP option is not validated if the min rtt changes
 * - Verify that the BDP option is not validated if the IP address changes
 * - Verify that the BDP option is not validated if the delay is too long
 */

typedef enum {
    bdp_test_option_none = 0,
    bdp_test_option_basic,
    bdp_test_option_rtt,
    bdp_test_option_ip,
    bdp_test_option_delay,
    bdp_test_option_reno,
    bdp_test_option_cubic,
    bdp_test_option_short,
    bdp_test_option_short_lo,
    bdp_test_option_short_hi,
    bdp_test_option_bbr1
} bdp_test_option_enum;

int bdp_option_test_one(bdp_test_option_enum bdp_test_option)
{
    uint64_t simulated_time = 0;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    char const* sni = PICOQUIC_TEST_SNI;
    char const* alpn = PICOQUIC_TEST_ALPN;
    uint32_t proposed_version = 0;
    uint64_t max_completion_time = 6800000;
    uint64_t latency = 300000ull;
    uint64_t buffer_size = 2 * latency;
    picoquic_connection_id_t initial_cid = { {0xbd, 0x80, 0, 0, 0, 0, 0, 0}, 8 };
    picoquic_congestion_algorithm_t* ccalgo = picoquic_bbr_algorithm;
    picoquic_tp_t server_parameters;
    picoquic_tp_t client_parameters;

    int ret = 0;

    /* Initialize an empty ticket store */
    ret = picoquic_save_tickets(NULL, simulated_time, ticket_file_name);

    for (int i = 0; ret == 0 && i < 2; i++) {
        /* If testing delay, insert a delay before the second connection attempt */
        if (i == 1 && bdp_test_option == bdp_test_option_delay) {
            simulated_time += 48ull * 3600ull * 1000000ull;
        }
        initial_cid.id[2] = i;
        initial_cid.id[3] = (uint8_t)bdp_test_option;
        /* Set up the context, while setting the ticket store parameter for the client */
        ret = tls_api_init_ctx_ex(&test_ctx,
            (i == 0) ? 0 : proposed_version, sni, alpn, &simulated_time, ticket_file_name, NULL, 0, 1, 0, &initial_cid);
        /* Set the various parameters */
        if (ret == 0) {
            test_ctx->c_to_s_link->microsec_latency = latency;
            test_ctx->s_to_c_link->microsec_latency = latency;
            test_ctx->c_to_s_link->picosec_per_byte = (1000000ull * 8) / 20;
            test_ctx->s_to_c_link->picosec_per_byte = (1000000ull * 8) / 20;

            if (bdp_test_option == bdp_test_option_short ||
                bdp_test_option == bdp_test_option_short_lo ||
                bdp_test_option == bdp_test_option_short_hi) {
                /* Test that the BDP option also works well if delay < 250 ms */
                max_completion_time = 4500000;
                test_ctx->c_to_s_link->microsec_latency = 100000ull;
                test_ctx->s_to_c_link->microsec_latency = 100000ull;
                buffer_size = 2 * test_ctx->c_to_s_link->microsec_latency;
                if (i == 0) {
                    if (bdp_test_option == bdp_test_option_short_lo) {
                        test_ctx->c_to_s_link->picosec_per_byte *= 2;
                        test_ctx->s_to_c_link->picosec_per_byte *= 2;
                    }
                    else if (bdp_test_option == bdp_test_option_short_hi) {
                        test_ctx->c_to_s_link->picosec_per_byte /= 2;
                        test_ctx->s_to_c_link->picosec_per_byte /= 2;
                    }
                }
                else if (i == 1 && bdp_test_option == bdp_test_option_short_lo) {
                    max_completion_time = 4650000;
                }
            }
            else if (i > 0) {
                switch (bdp_test_option) {
                case bdp_test_option_none:
                    break;
                case bdp_test_option_basic:
                    max_completion_time = 5900000;
                    break;
                case bdp_test_option_rtt:
                    max_completion_time = 4610000;
                    test_ctx->c_to_s_link->microsec_latency = 50000ull;
                    test_ctx->s_to_c_link->microsec_latency = 50000ull;
                    buffer_size = 2 * test_ctx->c_to_s_link->microsec_latency;
                    break;
                case bdp_test_option_ip:
                    picoquic_set_test_address(&test_ctx->client_addr, 0x08080808, 2345);
                    max_completion_time = 9000000;
                    break;
                case bdp_test_option_delay:
                    max_completion_time = 8000000;
                    break;
                case bdp_test_option_reno:
                    max_completion_time = 6750000;
                    break;
                default:
                    break;
                }
            }
            if (bdp_test_option == bdp_test_option_reno) {
                ccalgo = picoquic_newreno_algorithm;
            }
            else if (bdp_test_option == bdp_test_option_cubic) {
                ccalgo = picoquic_cubic_algorithm;
                max_completion_time = 10000000;
            }
            else if (bdp_test_option == bdp_test_option_bbr1) {
                ccalgo = picoquic_bbr1_algorithm;
            }
            picoquic_set_default_congestion_algorithm(test_ctx->qserver, ccalgo);
            picoquic_set_congestion_algorithm(test_ctx->cnx_client, ccalgo);
            picoquic_set_default_bdp_frame_option(test_ctx->qclient, 1);
            picoquic_set_default_bdp_frame_option(test_ctx->qserver, 1);
            test_ctx->qserver->use_long_log = 1;
            picoquic_set_binlog(test_ctx->qserver, ".");
            /* Set parameters */
            picoquic_init_transport_parameters(&server_parameters, 0);
            picoquic_init_transport_parameters(&client_parameters, 1);
            server_parameters.enable_bdp_frame = 1;
            client_parameters.enable_bdp_frame = 1;
            client_parameters.initial_max_stream_data_bidi_remote = 1000000;
            client_parameters.initial_max_data = 10000000;
            picoquic_set_transport_parameters(test_ctx->cnx_client, &client_parameters);
            ret = picoquic_set_default_tp(test_ctx->qserver, &server_parameters);

            if (ret == 0) {
                ret = tls_api_one_scenario_body(test_ctx, &simulated_time, test_scenario_10mb, sizeof(test_scenario_10mb), 0, 0, 0, buffer_size,
                    (i == 0) ? 0 : max_completion_time);
            }

            /* Verify that the BDP option was set and processed */
            if (ret == 0) {
                if (i == 1 && test_ctx->cnx_client->nb_zero_rtt_acked == 0 && bdp_test_option != bdp_test_option_delay) {
                    DBG_PRINTF("BDP RTT test (bdp test: %d), cnx %d, no zero RTT data acked.\n",
                        bdp_test_option, i);
                    ret = -1;
                }
                if (!test_ctx->cnx_client->send_receive_bdp_frame) {
                    DBG_PRINTF("BDP RTT test (bdp test: %d), cnx %d, bdp option not negotiated on client.\n",
                        bdp_test_option, i);
                    ret = -1;
                }
                if (!test_ctx->cnx_server->send_receive_bdp_frame) {
                    DBG_PRINTF("BDP RTT test (bdp test: %d), cnx %d, bdp option not negotiated on server.\n",
                        bdp_test_option, i);
                    ret = -1;
                }
                if (ret == 0 && i == 1) {
                    if (test_ctx->cnx_server->nb_retransmission_total * 10 >
                        test_ctx->cnx_server->nb_packets_sent &&
                        bdp_test_option != bdp_test_option_cubic &&
                        bdp_test_option != bdp_test_option_delay &&
                        bdp_test_option != bdp_test_option_ip) {
                        DBG_PRINTF("BDP RTT test (bdp test: %d), cnx %d, too many losses, %"PRIu64"/%"PRIu64".\n",
                            bdp_test_option, i, test_ctx->cnx_server->nb_retransmission_total,
                            test_ctx->cnx_server->nb_packets_sent);
                        ret = -1;

                    }
                    /* Verify bdp test option was executed */
                    if (!test_ctx->cnx_client->path[0]->is_bdp_sent) {
                        DBG_PRINTF("BDP RTT test (bdp test: %d), cnx %d, bdp frame not sent by client.\n",
                            bdp_test_option, i);
                        ret = -1;
                    }
                    else if (bdp_test_option == bdp_test_option_basic ||
                        bdp_test_option == bdp_test_option_reno ||
                        bdp_test_option == bdp_test_option_short ||
                        bdp_test_option == bdp_test_option_short_hi ||
                        bdp_test_option == bdp_test_option_short_lo ||
                        bdp_test_option == bdp_test_option_cubic ||
                        bdp_test_option == bdp_test_option_bbr1) {
                        if (!test_ctx->cnx_server->cwin_notified_from_seed) {
                            DBG_PRINTF("BDP RTT test (bdp test: %d), cnx %d, cwin not seed on server.\n",
                                bdp_test_option, i);
                            ret = -1;
                        }
                    }
                    else if (test_ctx->cnx_server->cwin_notified_from_seed) {
                        DBG_PRINTF("BDP RTT test (bdp test: %d), cnx %d, unexpected cwin seed on server.\n",
                            bdp_test_option, i);
                        ret = -1;
                    }
                }
            }

            /* Save the session tickets */
            if (ret == 0) {
                if (test_ctx->qclient->p_first_ticket == NULL) {
                    DBG_PRINTF("BDP RTT test (bdp option: %d), cnx %d, no ticket received.\n",
                        bdp_test_option, i);
                    ret = -1;
                }
                else {
                    ret = picoquic_save_tickets(test_ctx->qclient->p_first_ticket, simulated_time, ticket_file_name);
                    if (ret != 0) {
                        DBG_PRINTF("Zero RTT test (bdp test option: %d), cnx %d, ticket save error (0x%x).\n",
                            bdp_test_option, i, ret);
                    }
                }
            }

            /* Free the resource, which will close the log file. */
            if (test_ctx != NULL) {
                tls_api_delete_ctx(test_ctx);
                test_ctx = NULL;
            }
        }
    }

    return ret;
}

int bdp_basic_test()
{
    return bdp_option_test_one(bdp_test_option_basic);
}

int bdp_rtt_test()
{
    /* TODO: this test succeeds for the wrong reason.
    * The goal of the test is to verify that the BDP is NOT set
    * if the RTT on the second connection does not match the RTT
    * on the first one. The test does that, but only because the
    * second connection's RTT is lower than BBRLongRttThreshold,
    * thus uses regular BBR startup, in which the BDP option is
    * not implemented.
     */
    return bdp_option_test_one(bdp_test_option_rtt);
}

int bdp_ip_test()
{
    return bdp_option_test_one(bdp_test_option_ip);
}

int bdp_delay_test()
{
    return bdp_option_test_one(bdp_test_option_delay);
}

int bdp_reno_test()
{
    return bdp_option_test_one(bdp_test_option_reno);
}

int bdp_short_test()
{
    return bdp_option_test_one(bdp_test_option_short);
}

int bdp_short_hi_test()
{
    return bdp_option_test_one(bdp_test_option_short_hi);
}

int bdp_short_lo_test()
{
    return bdp_option_test_one(bdp_test_option_short_lo);
}

#if defined(_WINDOWS) && !defined(_WINDOWS64)
int bdp_cubic_test()
{
    /* We do not run this test in Win32 builds. */
    return 0;
}
#else
int bdp_cubic_test()
{
    return bdp_option_test_one(bdp_test_option_cubic);
}
#endif

int bdp_bbr1_test()
{
    return bdp_option_test_one(bdp_test_option_bbr1);
}

/*
 * The "blackhole" test simulates a link breakage of 2 seconds, during which all packets
 * are lost. The connection is expected to survive the blackhole, and then recover.
*/

static int blackhole_test_one(picoquic_congestion_algorithm_t* ccalgo, uint64_t max_completion_time, uint64_t jitter)
{
    uint64_t simulated_time = 0;
    uint64_t latency = 15000;
    uint64_t picoseq_per_byte_10 = (1000000ull * 8) / 10;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    int ret = 0;

    ret = tls_api_one_scenario_init(&test_ctx, &simulated_time, PICOQUIC_INTERNAL_TEST_VERSION_1, NULL, NULL);

    if (ret == 0 && test_ctx == NULL) {
        ret = -1;
    }

    /* Simulate 10 ms link, 15ms latency, 2 seconds blackhole */
    if (ret == 0) {
        picoquic_set_default_congestion_algorithm(test_ctx->qserver, ccalgo);
        picoquic_set_congestion_algorithm(test_ctx->cnx_client, ccalgo);

        test_ctx->c_to_s_link->jitter = jitter;
        test_ctx->c_to_s_link->microsec_latency = latency;
        test_ctx->c_to_s_link->picosec_per_byte = picoseq_per_byte_10;
        test_ctx->s_to_c_link->microsec_latency = latency;
        test_ctx->s_to_c_link->picosec_per_byte = picoseq_per_byte_10;
        test_ctx->s_to_c_link->jitter = jitter;
        test_ctx->blackhole_end = 7000000;
        test_ctx->blackhole_start = 5000000;

        if (ret == 0) {
            ret = tls_api_one_scenario_body(test_ctx, &simulated_time, test_scenario_10mb, sizeof(test_scenario_10mb), 0, 0, 0, 2 * latency, max_completion_time);
        }
    }

    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }

    return ret;
}

int blackhole_test()
{
    int ret = blackhole_test_one(picoquic_bbr_algorithm, 15000000, 0);

    return ret;
}

/*
* Application limited test.
* The application is set to limit the max data values to stay lower than a set flow control window.
* We verify that in these scenario the CWIN does not grow too much above the flow control window.
*/
#define APP_LIMIT_TRACE_CSV "app_limit_trace.csv"
#define APP_LIMIT_TRACE_BIN "acc1020304050607.server.log"

int app_limit_cc_test_one(
    picoquic_congestion_algorithm_t* ccalgo, uint64_t max_completion_time)
{
    uint64_t simulated_time = 0;
    uint64_t latency = 300000;
    uint64_t picoseq_per_byte_1 = (1000000ull * 8) / 1;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    picoquic_tp_t client_parameters;
    uint64_t cwin_limit = 120000;
    picoquic_connection_id_t initial_cid = { {0xac, 0xc1, 2, 3, 4, 5, 6, 7}, 8 };
    int ret = 0;

    (void)picoquic_file_delete(APP_LIMIT_TRACE_BIN, NULL);

    memset(&client_parameters, 0, sizeof(picoquic_tp_t));
    picoquic_init_transport_parameters(&client_parameters, 1);
    client_parameters.initial_max_data = 40000;

    ret = tls_api_one_scenario_init_ex(&test_ctx, &simulated_time, PICOQUIC_INTERNAL_TEST_VERSION_1, &client_parameters,
        NULL, &initial_cid, 0);

    if (ret == 0 && test_ctx == NULL) {
        ret = -1;
    }

    if (ret == 0) {

        picoquic_set_default_congestion_algorithm(test_ctx->qserver, ccalgo);
        picoquic_set_congestion_algorithm(test_ctx->cnx_client, ccalgo);
        picoquic_set_binlog(test_ctx->qserver, ".");
        test_ctx->qserver->use_long_log = 1;
        picoquic_set_max_data_control(test_ctx->qclient, client_parameters.initial_max_data);

        test_ctx->c_to_s_link->jitter = 0;
        test_ctx->c_to_s_link->microsec_latency = latency;
        test_ctx->c_to_s_link->picosec_per_byte = picoseq_per_byte_1;
        test_ctx->s_to_c_link->microsec_latency = latency;
        test_ctx->s_to_c_link->picosec_per_byte = picoseq_per_byte_1;
        test_ctx->s_to_c_link->jitter = 0;

        if (ret == 0) {
            ret = tls_api_one_scenario_body(test_ctx, &simulated_time,
                test_scenario_very_long, sizeof(test_scenario_very_long), 0, 0, 0, 2 * latency, max_completion_time);
        }
    }

    /* Free the resource, which will close the log file.
     */

    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }

    /* Create a CSV file from the .bin log file */
    if (ret == 0) {
        ret = picoquic_cc_log_file_to_csv(APP_LIMIT_TRACE_BIN, APP_LIMIT_TRACE_CSV);
    }

    /* Compute the max CWIN from the trace file */
    if (ret == 0)
    {
        FILE* F = picoquic_file_open(APP_LIMIT_TRACE_CSV, "r");
        uint64_t transit_max = 0;

        if (F == NULL) {
            DBG_PRINTF("Cannot open <%s>", APP_LIMIT_TRACE_CSV);
            ret = -1;
        }
        else {
            char buffer[512];

            while (fgets(buffer, 512, F) != NULL) {
                /* only consider number lines line */
                if (buffer[0] >= '0' && buffer[0] <= '9') {
                    uint64_t transit = 0;
                    int nb_comma = 0;
                    int c_index = 0;

                    while (nb_comma < 24 && c_index < 512 && buffer[c_index] != 0) {
                        if (buffer[c_index] == ',') {
                            nb_comma++;
                        }
                        c_index++;
                    }
                    while (c_index < 512 && buffer[c_index] == ' ') {
                        c_index++;
                    }
                    while (c_index < 512 && buffer[c_index] >= '0' && buffer[c_index] <= '9') {
                        transit *= 10;
                        transit += (uint64_t)buffer[c_index] - '0';
                        c_index++;
                    }
                    if (transit > transit_max) {
                        transit_max = transit;
                    }
                }
            }

            (void)picoquic_file_close(F);

            if (transit_max > cwin_limit) {
                DBG_PRINTF("MAX Transit = %" PRIu64 ", larger than %" PRIu64, transit_max, cwin_limit);
                ret = -1;
            }
        }
    }

    return ret;
}

int app_limit_cc_test()
{
    picoquic_congestion_algorithm_t* ccalgos[] = {
        picoquic_newreno_algorithm,
        picoquic_cubic_algorithm,
        picoquic_dcubic_algorithm,
        picoquic_bbr_algorithm,
        picoquic_fastcc_algorithm,
        picoquic_bbr1_algorithm
    };
    uint64_t max_completion_times[] = {
        22000000,
        23500000,
        22000000,
        21000000,
        25000000,
        25000000
    };
    int ret = 0;

    for (size_t i = 0; i < sizeof(ccalgos) / sizeof(picoquic_congestion_algorithm_t*); i++) {
        ret = app_limit_cc_test_one(ccalgos[i], max_completion_times[i]);
        if (ret != 0) {
            DBG_PRINTF("Appplication limited congestion test fails for <%s>", ccalgos[i]->congestion_algorithm_id);
            break;
        }
    }

    return ret;
}

/* Test the effectiveness of the CWIN MAX option
 */

#define CWIN_MAX_TRACE_CSV "cwin_max_trace.csv"
#define CWIN_MAX_TRACE_BIN "c9149a0102030405.server.log"

int cwin_max_test_one(
    picoquic_congestion_algorithm_t* ccalgo, uint64_t cwin_limit, uint64_t max_completion_time)
{
    uint64_t simulated_time = 0;
    uint64_t latency = 300000;
    uint64_t picoseq_per_byte_1 = (1000000ull * 8) / 100;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    picoquic_tp_t client_parameters;
    picoquic_connection_id_t initial_cid = { {0xc9, 0x14, 0x9a, 1, 2, 3, 4, 5}, 8 };
    int ret = 0;

    (void)picoquic_file_delete(APP_LIMIT_TRACE_BIN, NULL);

    memset(&client_parameters, 0, sizeof(picoquic_tp_t));
    picoquic_init_transport_parameters(&client_parameters, 1);

    ret = tls_api_one_scenario_init_ex(&test_ctx, &simulated_time, PICOQUIC_INTERNAL_TEST_VERSION_1, &client_parameters,
        NULL, &initial_cid, 0);

    if (ret == 0 && test_ctx == NULL) {
        ret = -1;
    }

    if (ret == 0) {

        picoquic_set_default_congestion_algorithm(test_ctx->qserver, ccalgo);
        picoquic_set_congestion_algorithm(test_ctx->cnx_client, ccalgo);
        picoquic_set_cwin_max(test_ctx->qserver, 0x10000);
        picoquic_set_binlog(test_ctx->qserver, ".");
        test_ctx->qserver->use_long_log = 1;
        picoquic_set_max_data_control(test_ctx->qclient, client_parameters.initial_max_data);

        test_ctx->c_to_s_link->jitter = 0;
        test_ctx->c_to_s_link->microsec_latency = latency;
        test_ctx->c_to_s_link->picosec_per_byte = picoseq_per_byte_1;
        test_ctx->s_to_c_link->microsec_latency = latency;
        test_ctx->s_to_c_link->picosec_per_byte = picoseq_per_byte_1;
        test_ctx->s_to_c_link->jitter = 0;

        if (ret == 0) {
            ret = tls_api_one_scenario_body(test_ctx, &simulated_time,
                test_scenario_very_long, sizeof(test_scenario_very_long), 0, 0, 0, 2 * latency, max_completion_time);
        }
    }

    /* Free the resource, which will close the log file.
    */

    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }

    /* Create a CSV file from the .bin log file */
    if (ret == 0) {
        ret = picoquic_cc_log_file_to_csv(CWIN_MAX_TRACE_BIN, CWIN_MAX_TRACE_CSV);
    }

    /* Compute the max CWIN from the trace file */
    if (ret == 0)
    {
        FILE* F = picoquic_file_open(CWIN_MAX_TRACE_CSV, "r");

        if (F == NULL) {
            DBG_PRINTF("Cannot open <%s>", CWIN_MAX_TRACE_CSV);
            ret = -1;
        }
        else {
            char buffer[512];
            uint64_t bytes_in_flight_max = 0;

            while (fgets(buffer, 512, F) != NULL) {
                /* only consider number lines line */
                if (buffer[0] >= '0' && buffer[0] <= '9') {
                    uint64_t bytes_in_flight = 0;
                    int nb_comma = 0;
                    int c_index = 0;

                    while (nb_comma < 24 && c_index < 512 && buffer[c_index] != 0) {
                        if (buffer[c_index] == ',') {
                            nb_comma++;
                        }
                        c_index++;
                    }
                    while (c_index < 512 && buffer[c_index] == ' ') {
                        c_index++;
                    }
                    while (c_index < 512 && buffer[c_index] >= '0' && buffer[c_index] <= '9') {
                        bytes_in_flight *= 10;
                        bytes_in_flight += (uint64_t)buffer[c_index] - '0';
                        c_index++;
                    }
                    if (bytes_in_flight > bytes_in_flight_max) {
                        bytes_in_flight_max = bytes_in_flight;
                    }
                }
            }

            (void)picoquic_file_close(F);

            if (bytes_in_flight_max > cwin_limit) {
                DBG_PRINTF("MAX In Flight = %" PRIu64 ", larger than %" PRIu64, bytes_in_flight_max, cwin_limit);
                ret = -1;
            }
        }
    }

    return ret;
}

int cwin_max_test()
{
    picoquic_congestion_algorithm_t* ccalgos[] = {
        picoquic_newreno_algorithm,
        picoquic_cubic_algorithm,
        picoquic_dcubic_algorithm,
        picoquic_bbr_algorithm,
        picoquic_fastcc_algorithm,
        picoquic_bbr1_algorithm
    };
    uint64_t max_completion_times[] = {
        11000000,
        11000000,
        11000000,
        11000000,
        12100000,
        11000000
    };
    int ret = 0;

    for (size_t i = 0; i < sizeof(ccalgos) / sizeof(picoquic_congestion_algorithm_t*); i++) {
        ret = cwin_max_test_one(ccalgos[i], 68000, max_completion_times[i]);
        if (ret != 0) {
            DBG_PRINTF("CWIN Max test fails for <%s>", ccalgos[i]->congestion_algorithm_id);
            break;
        }
    }

    return ret;
}