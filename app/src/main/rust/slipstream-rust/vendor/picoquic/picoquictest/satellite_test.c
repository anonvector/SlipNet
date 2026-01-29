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


/* This is similar to the long rtt test, but operating at a higher speed.
 * We allow for loss simulation and jitter simulation to simulate wi-fi + satellite.
 * Also, we want to check overhead targets, such as ratio of data bytes over control bytes.
 *
 * The satellite link that we define here corresponds to models suggested by
 * John Border of Hughes: 250 Mbps for the server to client link, 3 Mbps for the client
 * to server link. We reverse the role, as our test sends data from the cleint to the
 * server. John suggested tested with a 1GB download; we compromise here to 100MB,
 * in order to execut the test in reasonable time. There should be two test
 * variants: 0% loss, and 1 %loss.
 */
static int satellite_test_one(picoquic_congestion_algorithm_t* ccalgo, size_t data_size, uint64_t max_completion_time,
    uint64_t mbps_up, uint64_t mbps_down, uint64_t jitter, int has_loss, int do_preemptive, int seed_bw, int low_flow, int flow_control)
{
    uint64_t simulated_time = 0;
    uint64_t latency = 300000;
    uint64_t picoseq_per_byte_up = (1000000ull * 8) / mbps_up;
    uint64_t picoseq_per_byte_down = (1000000ull * 8) / mbps_down;
    picoquic_tp_t client_parameters;
    picoquic_tp_t server_parameters;
    picoquic_connection_id_t initial_cid = { {0x5a, 0x4e, 0, 0, 0, 0, 0, 0}, 8 };
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    int ret = 0;

    initial_cid.id[2] = ccalgo->congestion_algorithm_number;
    initial_cid.id[3] = (mbps_up > 0xff) ? 0xff : (uint8_t)mbps_up;
    initial_cid.id[4] = (mbps_down > 0xff) ? 0xff : (uint8_t)mbps_down;
    initial_cid.id[5] = (latency > 2550000) ? 0xff : (uint8_t)(latency / 10000);
    initial_cid.id[6] = (jitter > 255000) ? 0xff : (uint8_t)(jitter / 1000);
    initial_cid.id[7] = (has_loss) ? 0x30 : 0x00;
    if (seed_bw) {
        initial_cid.id[7] |= 0x80;
    }
    if (do_preemptive) {
        initial_cid.id[7] |= 0x40;
    }
    if (has_loss) {
        initial_cid.id[7] |= 0x20;

    }
    if (low_flow) {
        initial_cid.id[7] |= 0x10;
    }
    if (flow_control) {
        initial_cid.id[7] |= 0x08;
    }

    memset(&client_parameters, 0, sizeof(picoquic_tp_t));
    picoquic_init_transport_parameters(&client_parameters, 1);
    client_parameters.enable_time_stamp = 3;
    memset(&server_parameters, 0, sizeof(picoquic_tp_t));
    picoquic_init_transport_parameters(&server_parameters, 0);
    server_parameters.enable_time_stamp = 3;
    if (low_flow || flow_control) {
        /* For the flow control parameters to a small value */
        uint64_t bdp_s = (mbps_up * latency * 2) / 8;
        uint64_t bdp_c = (mbps_up * latency * 2) / 8;

        if (low_flow) {
            bdp_s /= 2;
            bdp_c /= 2;
        }
        else {
            bdp_s += bdp_s;
            bdp_c += bdp_c;
        }

        server_parameters.initial_max_data = bdp_s;
        client_parameters.initial_max_data = bdp_c;
    }
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

        if (low_flow || flow_control) {
            picoquic_set_max_data_control(test_ctx->qserver, server_parameters.initial_max_data);
        }

        picoquic_cnx_set_pmtud_required(test_ctx->cnx_client, 1);

        /* set the binary log on the client side */
        picoquic_set_binlog(test_ctx->qclient, ".");
        test_ctx->qclient->use_long_log = 1;
        /* Since the client connection was created before the binlog was set, force log of connection header */
        binlog_new_connection(test_ctx->cnx_client);

        if (ret == 0) {
            ret = tls_api_one_scenario_body(test_ctx, &simulated_time,
                NULL, 0, data_size, (has_loss) ? 0x10000000 : 0, 0, 2 * latency, max_completion_time);
        }

        if (ret == 0 && do_preemptive) {
            DBG_PRINTF("Preemptive repeats: %" PRIu64, test_ctx->cnx_client->nb_preemptive_repeat);
            if (test_ctx->cnx_client->nb_preemptive_repeat == 0) {
                ret = -1;
            }
            else {
                uint64_t bdp = mbps_up * latency * 2;
                uint64_t bdp_p = bdp / (8 * test_ctx->cnx_client->path[0]->send_mtu);
                uint64_t bdp_p_plus = bdp_p + (bdp_p / 2);

                if (test_ctx->cnx_client->nb_preemptive_repeat > bdp_p_plus) {
                    DBG_PRINTF("Preemptive repeats > BDP(packets): %" PRIu64 " vs %" PRIu64, 
                        test_ctx->cnx_client->nb_preemptive_repeat, bdp_p);
                    ret = -1;
                }
            }
        }

        if (ret == 0 && flow_control) {
            uint64_t bdp = mbps_up * latency * 2;
            uint64_t bdp_p = bdp/ (8 * test_ctx->cnx_client->path[0]->send_mtu);
            uint64_t nb_max = 3 * bdp_p;

            if (test_ctx->qserver->nb_data_nodes_allocated_max > nb_max){
                DBG_PRINTF("Allocated nodes: %" PRIu64 " > 3*%" PRIu64, 
                    test_ctx->qserver->nb_data_nodes_allocated_max, bdp_p);
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

int satellite_basic_test()
{
    /* Should be less than 7 sec per draft etosat. */
    return satellite_test_one(picoquic_bbr_algorithm, 100000000, 5300000, 250, 3, 0, 0, 0, 0, 0, 0);
}

int satellite_seeded_test()
{
    /* Simulate remembering RTT and BW from previous connection */
    return satellite_test_one(picoquic_bbr_algorithm, 100000000, 4900000, 250, 3, 0, 0, 0, 1, 0, 0);
}

int satellite_seeded_bbr1_test()
{
    /* Simulate remembering RTT and BW from previous connection */
    return satellite_test_one(picoquic_bbr1_algorithm, 100000000, 5300000, 250, 3, 0, 0, 0, 1, 0, 0);
}

int satellite_loss_test()
{
    /* Should be less than 10 sec per draft etosat. */
    return satellite_test_one(picoquic_bbr_algorithm, 100000000, 8000000, 250, 3, 0, 1, 0, 0, 0, 0);
}

int satellite_loss_fc_test()
{
    /* Should be less than 10 sec per draft etosat.
     * The flow control option sets the "max data" to 2 BDP, with the effect
     * of reducing the memory consumption, while the transmission is slowed. */
    return satellite_test_one(picoquic_bbr_algorithm, 100000000, 10800000, 250, 3, 0, 1, 0, 0, 0, 1);
}

int satellite_preemptive_test()
{
    /* Variation of the loss test, using preemptive repeat*/
    /* Should be less than 10 sec per draft etosat.  */
    return satellite_test_one(picoquic_bbr_algorithm, 100000000, 7100000, 250, 3, 0, 1, 1, 0, 0, 0);
}

int satellite_jitter_test()
{
    /* Should be less than 7 sec per draft etosat. */
    return satellite_test_one(picoquic_bbr_algorithm, 100000000, 6700000, 250, 3, 3000, 0, 0, 0, 0, 0);
}

int satellite_medium_test()
{
    /* Should be less than 20 sec per draft etosat. */
    return satellite_test_one(picoquic_bbr_algorithm, 100000000, 18200000, 50, 10, 0, 0, 0, 0, 0, 0);
}

int satellite_small_test()
{
    /* Should be less than 85 sec per draft etosat. */
    return satellite_test_one(picoquic_bbr_algorithm, 100000000, 81500000, 10, 2, 0, 0, 0, 0, 0, 0);
}

int satellite_small_up_test()
{
    /* Should be less than 420 sec per draft etosat. */
    return satellite_test_one(picoquic_bbr_algorithm, 100000000, 400000000, 2, 10, 0, 0, 0, 0, 0, 0);
}


int satellite_bbr1_test()
{
    /* Should be less than 7 sec per draft etosat */
    return satellite_test_one(picoquic_bbr1_algorithm, 100000000, 7000000, 250, 3, 0, 0, 0, 0, 0, 0);
}

int satellite_cubic_test()
{
    /* Should be less than 7 sec per draft etosat, but cubic is much slower */
    return satellite_test_one(picoquic_cubic_algorithm, 100000000, 11000000, 250, 3, 0, 0, 0, 0, 0, 0);
}

int satellite_cubic_seeded_test()
{
    return satellite_test_one(picoquic_cubic_algorithm, 100000000, 5000000, 250, 3, 0, 0, 0, 1, 0, 0);
}

int satellite_cubic_loss_test()
{
    /* Should be less than 10 sec per draft etosat, but cubic is a bit slower */
    return satellite_test_one(picoquic_cubic_algorithm, 100000000, 12100000, 250, 3, 0, 1, 0, 0, 0, 0);
}

/* Satellite loss interop test, as shown in https://interop.sedrubal.de/
 * 
 *   File size: 10 MB
 *   RTT: 600 ms
 *   Data Rate: 20 Mbps forward link, 2 Mbps return link
 *  Loss Rate (in SATLOSS test case): 1 %
 *
 * We are specially interested in a flow controlled case, in which the flow control
 * window of the receiver is capped at a low value. In this case, preemptive
 * repeat helps during the last RTT, but causes undue overhead before that. Testing
 * requires:
 * - turning on preemtive repeat and packet loss,
 * - setting an artificial FC cap on the receiver side,
 * - measuring both the completion time and the amount of overhead,
 * - failing the test if the overhead is too high.
 * This requires modifying the library code to implement an optional max FC window,
 * and the test code to measure the transmission overhead.
 */

int satellite_preemptive_fc_test()
{
    /* Should be less than 10 sec per draft etosat, but cubic is a bit slower */
    return satellite_test_one(picoquic_bbr_algorithm, 10000000, 13600000, 20, 2, 0, 1, 1, 0, 1, 0);
}