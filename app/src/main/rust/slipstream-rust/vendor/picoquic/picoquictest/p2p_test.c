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

#include <stdlib.h>
#include <string.h>
#include "picoquic.h"
#include "picoquic_internal.h"
#include "picoquictest_internal.h"
#include "tls_api.h"
#include "picoquic_binlog.h"
#include "logreader.h"
#include "autoqlog.h"

static test_api_stream_desc_t test_scenario_address_discovery[] = {
    { 4, 0, 257, 100000 }
};

int address_discovery_test()
{
    uint64_t simulated_time = 0;
    picoquic_connection_id_t initial_cid = { {0xad, 0xd8, 0xd1, 0x5c, 0, 0, 0, 0}, 8 };
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    uint64_t loss_mask = 0;
    int ret = 0;

    ret = tls_api_one_scenario_init_ex(&test_ctx, &simulated_time, PICOQUIC_INTERNAL_TEST_VERSION_1, NULL, NULL, &initial_cid, 0);

    if (ret == 0 && test_ctx == NULL) {
        ret = -1;
    }

    if (ret == 0) {
        /* set the qlogs on both sides */
        picoquic_set_qlog(test_ctx->qclient, ".");
        picoquic_set_qlog(test_ctx->qserver, ".");
        picoquic_set_log_level(test_ctx->qserver, 1);
        picoquic_set_log_level(test_ctx->qclient, 1);
        test_ctx->qclient->use_long_log = 1;
        test_ctx->qserver->use_long_log = 1;
        /* Set the address discovery option */
        picoquic_set_default_address_discovery_mode(test_ctx->qclient, 3);
        picoquic_set_default_address_discovery_mode(test_ctx->qserver, 1);
        /* Delete the client connection and create a new one,
        * so it picks the parameters.
         */
        picoquic_delete_cnx(test_ctx->cnx_client);
        test_ctx->cnx_client = picoquic_create_cnx(test_ctx->qclient,
            initial_cid, picoquic_null_connection_id,
            (struct sockaddr*)&test_ctx->server_addr, simulated_time,
            0, PICOQUIC_TEST_SNI, PICOQUIC_TEST_ALPN, 1);

        if (test_ctx->cnx_client == NULL) {
            ret = -1;
        }
        else {
            ret = picoquic_start_client_cnx(test_ctx->cnx_client);
        }
    }

    /* establish the connection */
    if (ret == 0) {
        ret = tls_api_connection_loop(test_ctx, &loss_mask, 0, &simulated_time);
    }

    /* wait until the client (and thus the server) is ready */
    if (ret == 0) {
        ret = wait_client_connection_ready(test_ctx, &simulated_time);
    }

    /* Check that the address discovery option is negotiated */
    if (ret == 0) {
        if (test_ctx->cnx_client->is_address_discovery_provider ||
            !test_ctx->cnx_client->is_address_discovery_receiver ||
            !test_ctx->cnx_server->is_address_discovery_provider ||
            test_ctx->cnx_server->is_address_discovery_receiver) {
            DBG_PRINTF("Address discovery not properly negotiated, C:(%u,%u), S:(%u,%u)",
                test_ctx->cnx_client->is_address_discovery_provider,
                test_ctx->cnx_client->is_address_discovery_receiver,
                test_ctx->cnx_server->is_address_discovery_provider,
                test_ctx->cnx_server->is_address_discovery_receiver);
            ret = -1;
        }
    }

    /* Prepare to send data */
    if (ret == 0) {
        ret = test_api_init_send_recv_scenario(test_ctx, test_scenario_address_discovery, sizeof(test_scenario_address_discovery));

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
        ret = tls_api_one_scenario_body_verify(test_ctx, &simulated_time, 1000000);
    }

    /* Check that the address discovery callback was called.
     */
    if (ret == 0) {
        if (test_ctx->nb_address_observed == 0) {
            DBG_PRINTF("Got % addresses observed", test_ctx->nb_address_observed);
            ret = -1;
        }
    }

    /* Check that the observed address was set on the client connection */
    if (ret == 0 && picoquic_compare_addr(
        (struct sockaddr*)&test_ctx->cnx_client->path[0]->local_addr,
        (struct sockaddr*)&test_ctx->cnx_client->path[0]->observed_addr) != 0) {
        char text1[256];
        char text2[256];

        DBG_PRINTF("Local: %s, observed: %s",
            picoquic_addr_text((struct sockaddr*)&test_ctx->cnx_client->path[0]->local_addr, text1, sizeof(text1)),
            picoquic_addr_text((struct sockaddr*)&test_ctx->cnx_client->path[0]->observed_addr, text2, sizeof(text2)));
        ret = -1;
    }

    /* Delete the context */
    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
    }

    return ret;
}
