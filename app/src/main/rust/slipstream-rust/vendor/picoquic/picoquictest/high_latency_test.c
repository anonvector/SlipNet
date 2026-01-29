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


/* Very high latency test. This requires relaxing the handshake timer, so that it covers
 * at least one rtt.
 */
static int high_latency_one(uint8_t test_id, picoquic_congestion_algorithm_t* ccalgo,
    test_api_stream_desc_t* scenario, size_t sizeof_scenario,
    uint64_t max_completion_time, uint64_t latency, uint64_t mbps_up,
    uint64_t mbps_down, uint64_t jitter, int has_loss, int do_preemptive, int seed_bw)
{
    uint64_t simulated_time = 0;
    uint64_t picoseq_per_byte_up = (1000000ull * 8) / mbps_up;
    uint64_t picoseq_per_byte_down = (1000000ull * 8) / mbps_down;
    picoquic_tp_t client_parameters;
    picoquic_tp_t server_parameters;
    picoquic_connection_id_t initial_cid = { {0x1a, 0x7e, 0, 0, 0, 0, 0, 0}, 8 };
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    int ret = 0;

    initial_cid.id[2] = test_id;
    initial_cid.id[3] = (mbps_up > 0xff) ? 0xff : (uint8_t)mbps_up;
    initial_cid.id[4] = (mbps_down > 0xff) ? 0xff : (uint8_t)mbps_down;
    initial_cid.id[5] = (latency > 16000000) ? 0xff : (uint8_t)(latency / 100000);
    initial_cid.id[6] = (jitter > 255000) ? 0xff : (uint8_t)(jitter / 1000);
    initial_cid.id[7] = (has_loss) ? 0x30 : 0x00;
    if (seed_bw) {
        initial_cid.id[7] |= 0x80;
    }
    if (do_preemptive) {
        initial_cid.id[7] ^= 0x0f;
    }

    memset(&client_parameters, 0, sizeof(picoquic_tp_t));
    picoquic_init_transport_parameters(&client_parameters, 1);
    client_parameters.enable_time_stamp = 3;
    memset(&server_parameters, 0, sizeof(picoquic_tp_t));
    picoquic_init_transport_parameters(&server_parameters, 0);
    server_parameters.enable_time_stamp = 3;

    ret = tls_api_one_scenario_init_ex(&test_ctx, &simulated_time, PICOQUIC_INTERNAL_TEST_VERSION_1, &client_parameters, &server_parameters, &initial_cid, 0);

    if (ret == 0 && test_ctx == NULL) {
        ret = -1;
    }

    /* Simulate satellite links: 250 mbps, 300ms delay in each direction */
    /* Set the congestion algorithm to specified value. Also, request a packet trace */
    if (ret == 0) {
        picoquic_set_default_congestion_algorithm(test_ctx->qserver, ccalgo);
        picoquic_set_congestion_algorithm(test_ctx->cnx_client, ccalgo);
        picoquic_set_preemptive_repeat_policy(test_ctx->qserver, do_preemptive);
        picoquic_set_preemptive_repeat_per_cnx(test_ctx->cnx_client, do_preemptive);

        test_ctx->c_to_s_link->jitter = jitter;
        test_ctx->c_to_s_link->microsec_latency = latency;
        test_ctx->c_to_s_link->picosec_per_byte = picoseq_per_byte_up;
        test_ctx->s_to_c_link->microsec_latency = latency;
        test_ctx->s_to_c_link->picosec_per_byte = picoseq_per_byte_down;
        test_ctx->s_to_c_link->jitter = jitter;
        test_ctx->stream0_flow_release = 1;
        test_ctx->immediate_exit = 1;

        if (seed_bw) {
            uint8_t* ip_addr;
            uint8_t ip_addr_length;
            uint64_t estimated_rtt = 2 * latency;
            uint64_t estimated_bdp = (125000ull * mbps_up) * estimated_rtt / 1000000ull;
            picoquic_get_ip_addr((struct sockaddr*)&test_ctx->server_addr, &ip_addr, &ip_addr_length);

            picoquic_seed_bandwidth(test_ctx->cnx_client, estimated_rtt, estimated_bdp,
                ip_addr, ip_addr_length);
        }

        picoquic_cnx_set_pmtud_required(test_ctx->cnx_client, 1);

        /* Set the binary log on the server side */
        picoquic_set_binlog(test_ctx->qserver, ".");
        test_ctx->qserver->use_long_log = 1;

        /* set the binary log on the client side */
        picoquic_set_binlog(test_ctx->qclient, ".");
        test_ctx->qclient->use_long_log = 1;
        /* Since the client connection was created before the binlog was set, force log of connection header */
        binlog_new_connection(test_ctx->cnx_client);

        if (ret == 0) {
            ret = tls_api_one_scenario_body(test_ctx, &simulated_time,
                scenario, sizeof_scenario, 0, (has_loss) ? 0x10000000 : 0, 0, 2 * latency, max_completion_time);
        }

        if (ret == 00 && do_preemptive) {
            DBG_PRINTF("Preemptive repeats: %" PRIu64, test_ctx->cnx_client->nb_preemptive_repeat);
            if (test_ctx->cnx_client->nb_preemptive_repeat == 0) {
                ret = -1;
            }
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

/* Basic test. Just verify that the handshake completes, and that a small
 * document can be downloaded
 */

static test_api_stream_desc_t hilat_scenario_basic[] = {
    { 4, 0, 257, 2000 }
};

int high_latency_basic_test()
{
    /* Simple test. */
    uint64_t latency = 5000000;
    uint64_t expected_completion = latency*7;

    return high_latency_one(0xba, picoquic_newreno_algorithm, 
        hilat_scenario_basic, sizeof(hilat_scenario_basic),
        expected_completion, latency, 10, 10, 0, 0, 0, 0);
}



static test_api_stream_desc_t hilat_scenario_100mb[] = {
    { 4, 0, 257, 1000000 },
    { 8, 0, 257, 1000000 },
    { 12, 0, 257, 1000000 },
    { 16, 0, 257, 1000000 },
    { 20, 0, 257, 1000000 },
    { 24, 0, 257, 1000000 },
    { 28, 0, 257, 1000000 },
    { 32, 0, 257, 1000000 },
    { 36, 0, 257, 1000000 },
    { 40, 0, 257, 1000000 },
    { 44, 0, 257, 1000000 },
    { 48, 0, 257, 1000000 },
    { 52, 0, 257, 1000000 },
    { 56, 0, 257, 1000000 },
    { 60, 0, 257, 1000000 },
    { 64, 0, 257, 1000000 },
    { 68, 0, 257, 1000000 },
    { 72, 0, 257, 1000000 },
    { 76, 0, 257, 1000000 },
    { 80, 0, 257, 1000000 },
    { 84, 0, 257, 1000000 },
    { 88, 0, 257, 1000000 },
    { 92, 0, 257, 1000000 },
    { 96, 0, 257, 1000000 },
    { 100, 0, 257, 1000000 },
    { 104, 0, 257, 1000000 },
    { 108, 0, 257, 1000000 },
    { 112, 0, 257, 1000000 },
    { 116, 0, 257, 1000000 },
    { 120, 0, 257, 1000000 },
    { 124, 0, 257, 1000000 },
    { 128, 0, 257, 1000000 },
    { 132, 0, 257, 1000000 },
    { 136, 0, 257, 1000000 },
    { 140, 0, 257, 1000000 },
    { 144, 0, 257, 1000000 },
    { 148, 0, 257, 1000000 },
    { 152, 0, 257, 1000000 },
    { 156, 0, 257, 1000000 },
    { 160, 0, 257, 1000000 },
    { 164, 0, 257, 1000000 },
    { 168, 0, 257, 1000000 },
    { 172, 0, 257, 1000000 },
    { 176, 0, 257, 1000000 },
    { 180, 0, 257, 1000000 },
    { 184, 0, 257, 1000000 },
    { 188, 0, 257, 1000000 },
    { 192, 0, 257, 1000000 },
    { 196, 0, 257, 1000000 },
    { 200, 0, 257, 1000000 },
    { 204, 0, 257, 1000000 },
    { 208, 0, 257, 1000000 },
    { 212, 0, 257, 1000000 },
    { 216, 0, 257, 1000000 },
    { 220, 0, 257, 1000000 },
    { 224, 0, 257, 1000000 },
    { 228, 0, 257, 1000000 },
    { 232, 0, 257, 1000000 },
    { 236, 0, 257, 1000000 },
    { 240, 0, 257, 1000000 },
    { 244, 0, 257, 1000000 },
    { 248, 0, 257, 1000000 },
    { 252, 0, 257, 1000000 },
    { 256, 0, 257, 1000000 },
    { 260, 0, 257, 1000000 },
    { 264, 0, 257, 1000000 },
    { 268, 0, 257, 1000000 },
    { 272, 0, 257, 1000000 },
    { 276, 0, 257, 1000000 },
    { 280, 0, 257, 1000000 },
    { 284, 0, 257, 1000000 },
    { 288, 0, 257, 1000000 },
    { 292, 0, 257, 1000000 },
    { 296, 0, 257, 1000000 },
    { 300, 0, 257, 1000000 },
    { 304, 0, 257, 1000000 },
    { 308, 0, 257, 1000000 },
    { 312, 0, 257, 1000000 },
    { 316, 0, 257, 1000000 },
    { 320, 0, 257, 1000000 },
    { 324, 0, 257, 1000000 },
    { 328, 0, 257, 1000000 },
    { 332, 0, 257, 1000000 },
    { 336, 0, 257, 1000000 },
    { 340, 0, 257, 1000000 },
    { 344, 0, 257, 1000000 },
    { 348, 0, 257, 1000000 },
    { 352, 0, 257, 1000000 },
    { 356, 0, 257, 1000000 },
    { 360, 0, 257, 1000000 },
    { 364, 0, 257, 1000000 },
    { 368, 0, 257, 1000000 },
    { 372, 0, 257, 1000000 },
    { 376, 0, 257, 1000000 },
    { 380, 0, 257, 1000000 },
    { 384, 0, 257, 1000000 },
    { 388, 0, 257, 1000000 },
    { 392, 0, 257, 1000000 },
    { 396, 0, 257, 1000000 },
    { 400, 0, 257, 1000000 }
};


/* Transfer test, 100MB file over a 10 MB link, using BBR.
 * In theory, this should require 1 RTT for handshake, then 1RTT for
 * requesting the file and 8 seconds for transferring it. But the
 * connection will not reach full bandwidth before going out
 * of slow start, so we can expect a much longer time.
 * 
 * The first iteration of this test surfaced a bug in the
 * way hystart tests for 'excessive" delays. There was some leftover
 * code to set a tight delay bound in long delay links, which
 * cause hystart to exit too soon.
 * 
 * Final iteration shows appropriate behavior with BBR completing
 * the transfer in 141 seconds -- 121 if we substract the delay
 * for handshake and file request. In theory, transfering 100MB
 * over a 10Mbps link lasts 80 seconds. The 40 second penalty is
 * the "start-up" time.
 * 
 * With Cubic, the transfer last 160 seconds. The additional
 * delay is due to Cubic saturating the link, causing packet losses
 * that then have to be corrected.
 */

int high_latency_bbr_test()
{
    uint64_t latency = 5000000;
    uint64_t expected_completion = 145000000;

    return high_latency_one(0xbb, picoquic_bbr_algorithm,
        hilat_scenario_100mb, sizeof(hilat_scenario_100mb),
        expected_completion, latency, 10, 10, 0, 0, 0, 0);
}

#if defined(_WINDOWS) && !defined(_WINDOWS64)
int high_latency_cubic_test()
{
    /* we do not run this test on Win32 builds */
    return 0;
}
#else
int high_latency_cubic_test()
{
    /* Simple test. */
    uint64_t latency = 5000000;
    uint64_t expected_completion = 200000000;

    return high_latency_one(0xcb, picoquic_cubic_algorithm,
        hilat_scenario_100mb, sizeof(hilat_scenario_100mb),
        expected_completion, latency, 10, 10, 0, 0, 0, 0);
}
#endif

/* Test a long duration connection, to detect possible issues with
 * BBR transitioning to "probe RTT" after 10 seconds. No issue
 * detected, but still some code verifications to do.
 */

int high_latency_probeRTT_test()
{
    /* Simple test. */
    uint64_t latency = 5000000;
    uint64_t expected_completion = 839000000;

    return high_latency_one(0xf1, picoquic_bbr_algorithm,
        hilat_scenario_100mb, sizeof(hilat_scenario_100mb),
        expected_completion, latency, 1, 1, 0, 0, 0, 0);
}
