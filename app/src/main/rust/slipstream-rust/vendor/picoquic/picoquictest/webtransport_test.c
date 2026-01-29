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

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "picoquic.h"
#include "picoquic_internal.h"
#include "picoquic_utils.h"
#include "picoquictest_internal.h"
#include "picoquic_binlog.h"
#include "picoquic_logger.h"
#include "picoquic_unified_log.h"
#include "autoqlog.h"
#include "h3zero.h"
#include "h3zero_common.h"
#include "demoserver.h"
#include "pico_webtransport.h"
#include "wt_baton.h"

#ifdef _WINDOWS
#include "wincompat.h"
#include <direct.h>
#else
#include <sys/stat.h>
#include <sys/types.h>
#endif

/*
* The web transport unit tests are based on the "baton" protocol
* which is also used for interop testing. 
* TODO: the current protocol is limited. It does not test sending
* large volume of data, sending large number of streams, or
* sending datagrams. Consider extensions!
*/

wt_baton_app_ctx_t baton_test_ctx = {
    15
};

picohttp_server_path_item_t path_item_list[1] =
{
    {
        "/baton",
        6,
        wt_baton_callback,
        &baton_test_ctx
    }
};

static int picowt_baton_test_one(
    uint8_t test_id, const char* baton_path,
    uint64_t do_losses, uint64_t completion_target, const char* client_qlog_dir,
    const char* server_qlog_dir)
{
    char const* alpn = "h3";
    uint64_t simulated_time = 0;
    uint64_t loss_mask = do_losses;
    uint64_t time_out;
    int nb_trials = 0;
    int was_active = 0;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    wt_baton_ctx_t baton_ctx = { 0 };
    int ret = 0;
    picohttp_server_parameters_t server_param = { 0 };
    picoquic_connection_id_t initial_cid = { {0x77, 0x74, 0xba, 0, 0, 0, 0, 0}, 8 };
    h3zero_callback_ctx_t* h3zero_cb = NULL;

    initial_cid.id[3] = test_id;

    if (ret == 0) {
        ret = tls_api_init_ctx_ex(&test_ctx,
            PICOQUIC_INTERNAL_TEST_VERSION_1,
            PICOQUIC_TEST_SNI, alpn, &simulated_time, NULL, NULL, 0, 1, 0, &initial_cid);

        if (ret == 0 && server_qlog_dir != NULL) {
            picoquic_set_qlog(test_ctx->qserver, server_qlog_dir);
            test_ctx->qserver->use_long_log = 1;
        }

        if (ret == 0 && client_qlog_dir != NULL) {
            picoquic_set_qlog(test_ctx->qclient, client_qlog_dir);
        }

        if (ret == 0) {
            picowt_set_transport_parameters(test_ctx->cnx_client);
        }
    }

    if (ret != 0) {
        DBG_PRINTF("Could not create the QUIC test contexts for V=%x\n", PICOQUIC_INTERNAL_TEST_VERSION_1);
    }
    else if (test_ctx == NULL || test_ctx->cnx_client == NULL || test_ctx->qserver == NULL) {
        DBG_PRINTF("%s", "Connections where not properly created!\n");
        ret = -1;
    }

    /* The default procedure creates connections using the test callback.
    * We want to replace that by the demo client callback */

    if (ret == 0) {
        /* Set the client callback context using as much as possible
        * the generic picowt calls. */
        h3zero_stream_ctx_t* control_stream_ctx = NULL;

        ret = picowt_prepare_client_cnx(test_ctx->qclient, (struct sockaddr*)NULL,
            &test_ctx->cnx_client, &h3zero_cb, &control_stream_ctx, simulated_time, PICOQUIC_TEST_SNI);

        if (ret == 0) {
            ret = wt_baton_prepare_context(test_ctx->cnx_client, &baton_ctx, h3zero_cb,
                control_stream_ctx, PICOQUIC_TEST_SNI, baton_path);
        }

        if (ret == 0) {
            ret = picowt_connect(test_ctx->cnx_client, h3zero_cb, control_stream_ctx,
                baton_ctx.authority, baton_ctx.server_path,
                wt_baton_callback, &baton_ctx);
        }

        if (ret == 0) {
            ret = picoquic_start_client_cnx(test_ctx->cnx_client);
        }

        if (ret == 0) {
            /* Initialize the server -- should include the path setup for connect action */
            memset(&server_param, 0, sizeof(picohttp_server_parameters_t));
            server_param.web_folder = NULL;
            server_param.path_table = path_item_list;
            server_param.path_table_nb = 1;

            picoquic_set_alpn_select_fn(test_ctx->qserver, picoquic_demo_server_callback_select_alpn);
            picoquic_set_default_callback(test_ctx->qserver, h3zero_callback, &server_param);
        }
    }

    /* Establish the connection from client to server. At this stage,
    * this is merely an H3 connection.
    */

    if (ret == 0) {
        ret = tls_api_connection_loop(test_ctx, &loss_mask, 0, &simulated_time);
    }

    /* Simulate the connection from the client side. */
    time_out = simulated_time + 30000000;
    while (ret == 0 && picoquic_get_cnx_state(test_ctx->cnx_client) != picoquic_state_disconnected) {
        ret = tls_api_one_sim_round(test_ctx, &simulated_time, time_out, &was_active);

        if (ret != 0) {
            DBG_PRINTF("Simulation error detected after %d trials\n", nb_trials);
            break;
        }

        /* TODO: insert here the logic of web transport scenarios. */
        if (++nb_trials > 100000) {
            DBG_PRINTF("Simulation not concluded after %d trials\n", nb_trials);
            ret = -1;
            break;
        }
    }

    /* Verify that the web transport scenarios were properly executed  */
    if (ret == 0) {
        if (test_id == 3 || test_id == 4 ||
            ((baton_ctx.baton_state == wt_baton_state_done || baton_ctx.baton_state == wt_baton_state_closed) &&
                baton_ctx.nb_turns >= 8 &&
                baton_ctx.lanes_completed == baton_ctx.nb_lanes &&
                baton_ctx.nb_datagrams_sent > 0 && baton_ctx.nb_datagrams_received > 0)) {
            DBG_PRINTF("Baton test succeeds after %d turns, %d datagrams sent, %d received",
                baton_ctx.nb_turns, baton_ctx.nb_datagrams_sent, baton_ctx.nb_datagrams_received);
        }
        else {
            DBG_PRINTF("Baton test fails after %d turns, state %d",
                baton_ctx.nb_turns, baton_ctx.baton_state);
            ret = -1;
        }
        if (ret == 0 && test_id == 5 && baton_ctx.lanes[0].first_baton != 33) {
            DBG_PRINTF("On URI test, first baton was %d instead of 33",
                baton_ctx.lanes[0].first_baton);
            ret = -1;
        }
    }
    /* Verify that settings were correctly received */
    if (ret == 0 && !h3zero_cb->settings.settings_received) {
        DBG_PRINTF("Settings not received at t: %llu", simulated_time);
        ret = -1;
    }
    /* verify that the execution time is as expected */
    if (ret == 0 && completion_target != 0) {
        if (simulated_time > completion_target) {
            DBG_PRINTF("Test uses %llu microsec instead of %llu", simulated_time, completion_target);
            ret = -1;
        }
    }

    if (h3zero_cb != NULL)
    {
        h3zero_callback_delete_context(test_ctx->cnx_client, h3zero_cb);
    }

    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }

    return ret;
}

int picowt_baton_basic_test()
{
    int ret = picowt_baton_test_one(1, "/baton?baton=240", 0, 2000000, ".", ".");

    return ret;
}

int picowt_baton_error_test()
{
    int ret = picowt_baton_test_one(4, "/baton?inject=1", 0, 2000000, ".", ".");

    return ret;
}

int picowt_baton_long_test()
{
    int ret = picowt_baton_test_one(2, "/baton", 0, 5000000, ".", ".");

    return ret;
}

int picowt_baton_wrong_test()
{
    int ret = picowt_baton_test_one(3, "/wrong_baton", 0, 2000000, ".", ".");

    return ret;
}

int picowt_baton_uri_test()
{
    int ret = picowt_baton_test_one(5, "/baton?baton=33", 0, 5000000, ".", ".");

    return ret;
}

int picowt_baton_multi_test()
{
    int ret = picowt_baton_test_one(6, "/baton?baton=240&count=4", 0, 5000000, ".", ".");

    return ret;
}

int picowt_baton_random_test()
{
    int ret = picowt_baton_test_one(7, "/baton?count=4", 0, 5000000, ".", ".");

    return ret;
}