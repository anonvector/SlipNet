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
#include "picoquic.h"
#include <stdlib.h>
#include <string.h>

#include "logreader.h"
#include "picoquic_binlog.h"
#include "picoquic_logger.h"
#include "qlog.h"


/*
 * Spin bit test. Verify that the bit does spin, and that the number
 * of rotations is plausible given the duration and the min delay
 * for various the spin policies.
 */

static test_api_stream_desc_t test_scenario_spin[] = {
    { 4, 0, 257, 1000000 }
};

int spinbit_test_one(picoquic_spinbit_version_enum spin_policy, picoquic_spinbit_version_enum spin_policy_server)
{
    uint64_t simulated_time = 0;
    uint64_t loss_mask = 0;
    uint64_t spin_duration = 0;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    int spin_count = 0;
    int ret = tls_api_init_ctx(&test_ctx, PICOQUIC_INTERNAL_TEST_VERSION_1,
        PICOQUIC_TEST_SNI, PICOQUIC_TEST_ALPN, &simulated_time, NULL, NULL, 0, 1, 0);

    if (ret != 0)
    {
        DBG_PRINTF("%s", "Could not create the QUIC test contexts\n");
    }

    if (ret == 0) {
        /* force spinbit policy as specified, then start */
        if (picoquic_set_default_spinbit_policy(test_ctx->qserver, spin_policy_server) != 0 ||
            picoquic_set_spinbit_policy(test_ctx->cnx_client, spin_policy) != 0)
        {
            DBG_PRINTF("Invalid policies: %d, %d\n", spin_policy_server, spin_policy);
            ret = -1;
        }
    }
    if (ret == 0) {
        ret = picoquic_start_client_cnx(test_ctx->cnx_client);
        if (ret != 0)
        {
            DBG_PRINTF("%s", "Could not initialize stream zero for the client\n");
        }
    }

    if (ret == 0) {
        ret = tls_api_connection_loop(test_ctx, &loss_mask, 0, &simulated_time);

        if (ret != 0)
        {
            DBG_PRINTF("Connection loop returns error %d\n", ret);
        }
    }

    /* Prepare to send data */
    if (ret == 0) {
        ret = test_api_init_send_recv_scenario(test_ctx, test_scenario_spin, sizeof(test_scenario_spin));

        if (ret != 0)
        {
            DBG_PRINTF("Init send receive scenario returns %d\n", ret);
        }
    }

    /* Explore the data sending loop so we can observe the spin bit  */
    if (ret == 0) {
        uint64_t spin_begin_time = simulated_time;
        uint64_t next_time = simulated_time + 10000000;
        int ret = 0;
        int nb_trials = 0;
        int nb_inactive = 0;
        int max_trials = 100000;
        int current_spin = test_ctx->cnx_client->path[0]->current_spin;

        test_ctx->c_to_s_link->loss_mask = &loss_mask;
        test_ctx->s_to_c_link->loss_mask = &loss_mask;

        while (ret == 0 && nb_trials < max_trials && simulated_time < next_time && nb_inactive < 256 && TEST_CLIENT_READY && TEST_SERVER_READY) {
            int was_active = 0;

            nb_trials++;

            ret = tls_api_one_sim_round(test_ctx, &simulated_time, next_time, &was_active);

            if (ret < 0)
            {
                break;
            }

            if (test_ctx->cnx_client->path[0]->current_spin != current_spin) {
                spin_count++;
                current_spin = test_ctx->cnx_client->path[0]->current_spin;
            }

            if (was_active) {
                nb_inactive = 0;
            }
            else {
                nb_inactive++;
            }

            if (test_ctx->test_finished) {
                if (picoquic_is_cnx_backlog_empty(test_ctx->cnx_client) && picoquic_is_cnx_backlog_empty(test_ctx->cnx_server)) {
                    break;
                }
            }
        }

        spin_duration = simulated_time - spin_begin_time;

        if (ret != 0)
        {
            DBG_PRINTF("Data sending loop fails with ret = %d\n", ret);
        }
    }

    if (ret == 0) {
        ret = picoquic_close(test_ctx->cnx_client, 0);
        if (ret != 0)
        {
            DBG_PRINTF("Picoquic close returns %d\n", ret);
        }
    }

    if (ret == 0) {
        if (spin_policy == picoquic_spinbit_basic) {
            if (spin_policy_server == picoquic_spinbit_on) {
                if (spin_count < 6) {
                    DBG_PRINTF("Unplausible spin bit: %d rotations, rtt_min = %d, duration = %d\n",
                        spin_count, (int)test_ctx->cnx_client->path[0]->rtt_min, (int)spin_duration);
                    ret = -1;
                }
            }
            else if (spin_policy_server == picoquic_spinbit_random) {
                if (spin_count < 100) {
                    DBG_PRINTF("Unplausible spin bit: %d rotations, rtt_min = %d, duration = %d\n",
                        spin_count, (int)test_ctx->cnx_client->path[0]->rtt_min, (int)spin_duration);
                    ret = -1;
                }
            }
            else if (spin_policy_server == picoquic_spinbit_null) {
                if (spin_count >  0) {
                    DBG_PRINTF("Unplausible spin bit: %d rotations, rtt_min = %d, duration = %d\n",
                        spin_count, (int)test_ctx->cnx_client->path[0]->rtt_min, (int)spin_duration);
                    ret = -1;
                }
            }
        }
    }

    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }

    return ret;
}

int spinbit_test()
{
    return spinbit_test_one(picoquic_spinbit_basic, picoquic_spinbit_on);
}

int spinbit_random_test()
{
    return spinbit_test_one(picoquic_spinbit_basic, picoquic_spinbit_random);
}

int spinbit_randclient_test()
{
    return spinbit_test_one(picoquic_spinbit_random, picoquic_spinbit_basic);
}

int spinbit_null_test()
{
    return spinbit_test_one(picoquic_spinbit_basic, picoquic_spinbit_null);
}

int spinbit_bad_test()
{
    int ret = 0;
    if (spinbit_test_one(picoquic_spinbit_on, 123456) == 0 ||
        spinbit_test_one(123455, picoquic_spinbit_null) == 0) {
        ret = -1;
    }
    return ret;
}


