/*
* Author: Christian Huitema
* Copyright (c) 2020, Private Octopus, Inc.
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
#include "qlog.h"

/* Add the additional links for multipath scenario */
static int multipath_test_add_links(picoquic_test_tls_api_ctx_t* test_ctx, int mtu_drop)
{
    int ret = 0;
    /* Initialize the second client address */
    test_ctx->client_addr_2 = test_ctx->client_addr;
    test_ctx->client_addr_2.sin_port += 17;
    /* register the links */
    test_ctx->c_to_s_link_2 = picoquictest_sim_link_create(0.01, 10000, NULL, 20000, 0);
    test_ctx->s_to_c_link_2 = picoquictest_sim_link_create(0.01, 10000, NULL, 20000, 0);

    if (test_ctx->c_to_s_link_2 == NULL || test_ctx->s_to_c_link_2 == NULL) {
        ret = -1;
    }
    else if (mtu_drop) {
        test_ctx->c_to_s_link_2->path_mtu = (PICOQUIC_INITIAL_MTU_IPV4 + test_ctx->c_to_s_link->path_mtu) / 2;
        test_ctx->s_to_c_link_2->path_mtu = (PICOQUIC_INITIAL_MTU_IPV4 + test_ctx->s_to_c_link->path_mtu) / 2;
    }

    return ret;
}

/* Manage  the additional links for multipath scenario */
static void multipath_test_kill_links(picoquic_test_tls_api_ctx_t* test_ctx, int link_id)
{
    /* Make sure that nothing gets sent on the old links */
    if (link_id == 0) {
        test_ctx->c_to_s_link->next_send_time = UINT64_MAX;
        test_ctx->c_to_s_link->is_switched_off = 1;
        test_ctx->s_to_c_link->next_send_time = UINT64_MAX;
        test_ctx->s_to_c_link->is_switched_off = 1;
    }
    else {
        test_ctx->c_to_s_link_2->next_send_time = UINT64_MAX;
        test_ctx->c_to_s_link_2->is_switched_off = 1;
        test_ctx->s_to_c_link_2->next_send_time = UINT64_MAX;
        test_ctx->s_to_c_link_2->is_switched_off = 1;
    }
}


static void multipath_test_kill_server_links(picoquic_test_tls_api_ctx_t* test_ctx, int link_id)
{
    /* Make sure that nothing gets sent on the old links */
    if (link_id == 0) {
        test_ctx->s_to_c_link->next_send_time = UINT64_MAX;
        test_ctx->s_to_c_link->is_switched_off = 1;
    }
    else {
        test_ctx->s_to_c_link_2->next_send_time = UINT64_MAX;
        test_ctx->s_to_c_link_2->is_switched_off = 1;
    }
}

static void multipath_test_set_unreachable(picoquic_test_tls_api_ctx_t* test_ctx, int link_id)
{
    if (link_id == 0) {
        test_ctx->c_to_s_link->is_unreachable = 1;
        test_ctx->s_to_c_link->is_unreachable = 1;
    }
    else {
        test_ctx->c_to_s_link_2->is_unreachable = 1;
        test_ctx->s_to_c_link_2->is_unreachable = 1;
    }
}

static void multipath_test_unkill_links(picoquic_test_tls_api_ctx_t* test_ctx, int link_id, uint64_t current_time)
{
    /* Make sure that nothing gets sent on the old links */
    if (link_id == 0) {
        test_ctx->c_to_s_link->next_send_time = current_time;
        test_ctx->c_to_s_link->is_switched_off = 0;
        test_ctx->s_to_c_link->next_send_time = current_time;
        test_ctx->s_to_c_link->is_switched_off = 1;
    }
    else {
        test_ctx->c_to_s_link_2->next_send_time = current_time;
        test_ctx->c_to_s_link_2->is_switched_off = 0;
        test_ctx->s_to_c_link_2->next_send_time = current_time;
        test_ctx->s_to_c_link_2->is_switched_off = 0;
    }
}

/* Add the additional links for multipath scenario */
static void multipath_test_sat_links(picoquic_test_tls_api_ctx_t* test_ctx, int link_id)
{
    if (link_id == 0) {
        /* Use low throughput for terrestrial link. */
        test_ctx->c_to_s_link->picosec_per_byte = 8000000ull; /* Simulate 1 Mbps */
        test_ctx->s_to_c_link->picosec_per_byte = 8000000ull; /* Simulate 1 Mbps */
    }
    else {
        /* Use higher latency for satellite link */
        const uint64_t sat_latency = 300000;

        test_ctx->c_to_s_link_2->microsec_latency = sat_latency;
        test_ctx->s_to_c_link_2->microsec_latency = sat_latency;
        test_ctx->c_to_s_link_2->queue_delay_max = 2*sat_latency;
        test_ctx->s_to_c_link_2->queue_delay_max = 2*sat_latency;
    }
}

/* Use higher data rate for multipath perf scenario */
static void multipath_test_perf_links(picoquic_test_tls_api_ctx_t* test_ctx, int link_id)
{
    const uint64_t wifi_latency = 15000;
    const uint64_t lte_latency = 30000;
    const uint64_t wifi_picosec = 8000000ull / 50;
    const uint64_t lte_picosec = 8000000ull / 40;

    if (link_id == 0) {
        test_ctx->c_to_s_link->microsec_latency = wifi_latency;
        test_ctx->s_to_c_link->microsec_latency = wifi_latency;
        test_ctx->c_to_s_link->queue_delay_max = 2 * wifi_latency;
        test_ctx->s_to_c_link->queue_delay_max = 2 * wifi_latency;
        test_ctx->c_to_s_link->picosec_per_byte = wifi_picosec;
        test_ctx->s_to_c_link->picosec_per_byte = wifi_picosec;
    }
    else {
        test_ctx->c_to_s_link_2->microsec_latency = lte_latency;
        test_ctx->s_to_c_link_2->microsec_latency = lte_latency;
        test_ctx->c_to_s_link_2->queue_delay_max = 2 * lte_latency;
        test_ctx->s_to_c_link_2->queue_delay_max = 2 * lte_latency;
        test_ctx->c_to_s_link_2->picosec_per_byte = lte_picosec;
        test_ctx->s_to_c_link_2->picosec_per_byte = lte_picosec;
    }
}

/* wait until the migration completes */
int wait_client_migration_done(picoquic_test_tls_api_ctx_t* test_ctx,
    uint64_t* simulated_time)
{
    int ret = 0;
    uint64_t time_out = *simulated_time + 4000000;
    int nb_trials = 0;
    int nb_inactive = 0;
    int was_active = 0;
    struct sockaddr_storage old_srce;
    struct sockaddr_storage old_dest;

    /* Check the selected path */
    picoquic_store_addr(&old_srce, (struct sockaddr*)&test_ctx->cnx_client->path[0]->local_addr);
    picoquic_store_addr(&old_dest, (struct sockaddr*) & test_ctx->cnx_client->path[0]->peer_addr);


    while (*simulated_time < time_out &&
        test_ctx->cnx_client->cnx_state == picoquic_state_ready &&
        nb_trials < 1024 &&
        nb_inactive < 64 &&
        ret == 0 && (
            (picoquic_compare_addr((struct sockaddr *) & old_srce, (struct sockaddr*) & test_ctx->cnx_client->path[0]->local_addr) == 0 &&
                picoquic_compare_addr((struct sockaddr*) & old_dest, (struct sockaddr*) & test_ctx->cnx_client->path[0]->peer_addr) == 0)
            ||
            (picoquic_compare_addr((struct sockaddr *) & old_srce, (struct sockaddr*) & test_ctx->cnx_server->path[0]->peer_addr) == 0 &&
                picoquic_compare_addr((struct sockaddr*) & old_dest, (struct sockaddr*) & test_ctx->cnx_server->path[0]->local_addr) == 0))){
        was_active = 0;
        nb_trials++;

        ret = tls_api_one_sim_round(test_ctx, simulated_time, time_out, &was_active);

        if (was_active) {
            nb_inactive = 0;
        }
        else {
            nb_inactive++;
        }
    }

    if (ret != 0 || (test_ctx->cnx_client->cnx_state != picoquic_state_ready ||
        (picoquic_compare_addr((struct sockaddr*) & old_srce, (struct sockaddr*) & test_ctx->cnx_client->path[0]->local_addr) == 0 &&
            picoquic_compare_addr((struct sockaddr*) & old_dest, (struct sockaddr*) & test_ctx->cnx_client->path[0]->peer_addr) == 0))
        ||
        (picoquic_compare_addr((struct sockaddr *) & old_srce, (struct sockaddr*) & test_ctx->cnx_server->path[0]->peer_addr) == 0 &&
            picoquic_compare_addr((struct sockaddr*) & old_dest, (struct sockaddr*) & test_ctx->cnx_server->path[0]->local_addr) == 0)){
        DBG_PRINTF("Could not complete migration, client state = %d\n",
            test_ctx->cnx_client->cnx_state);
        ret = -1;
    }

    return ret;
}


/* Controlled migration test.
 * Create a basic connection.
 * Run until the handshake is done.
 * Start a migration.
 * Verify that the transfer completes */

#define MIGRATION_TRACE_BIN "migration_trace.bin"


static test_api_stream_desc_t test_scenario_multipath[] = {
    { 4, 0, 257, 1000000 },
    { 8, 4, 257, 1000000 }
};

static test_api_stream_desc_t test_scenario_multipath_long[] = {
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

int migration_test_one(int mtu_drop)
{
    uint64_t simulated_time = 0;
    uint64_t loss_mask = 0;
    uint64_t max_completion_microsec = 2100000;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    picoquic_connection_id_t initial_cid = { {0x1a, 0x10, 0xc0, 4, 5, 6, 7, 8}, 8 };
    int ret;

    if (mtu_drop) {
        initial_cid.id[2] = 0xcd;
    }
    
    ret = tls_api_init_ctx_ex(&test_ctx, PICOQUIC_INTERNAL_TEST_VERSION_1,
        PICOQUIC_TEST_SNI, PICOQUIC_TEST_ALPN, &simulated_time, NULL, NULL, 0, 0, 0, &initial_cid);

    if (mtu_drop) {
        /* The MTU drop test is specifically orientated towards verifying retransmissions,
         * which requires simulating losses */
        loss_mask |= (((uint64_t)1) << 31);
    }

    if (ret == 0 && test_ctx == NULL) {
        ret = -1;
    }
    else {
        picoquic_set_binlog(test_ctx->qserver, ".");
        test_ctx->qserver->use_long_log = 1;
    }

    /* establish the connection*/
    if (ret == 0) {
        ret = tls_api_connection_loop(test_ctx, &loss_mask, 0, &simulated_time);
    }

    /* Prepare to send data */
    if (ret == 0) {
        ret = test_api_init_send_recv_scenario(test_ctx, test_scenario_multipath, sizeof(test_scenario_multipath));

        if (ret != 0)
        {
            DBG_PRINTF("Init send receive scenario returns %d\n", ret);
        }
    }

    /* wait until the client (and thus the server) is ready */
    if (ret == 0) {
        ret = wait_client_connection_ready(test_ctx, &simulated_time);
    }

    /* Add the multipath links and initiate the migration */
    if (ret == 0) {
        ret = multipath_test_add_links(test_ctx, mtu_drop);
    }

    if (ret == 0) {
        ret = picoquic_probe_new_path(test_ctx->cnx_client, (struct sockaddr*) & test_ctx->server_addr,
            (struct sockaddr*) & test_ctx->client_addr_2, simulated_time);
    }

    /* Check that the migration succeeds */
    if (ret == 0) {
        ret = wait_client_migration_done(test_ctx, &simulated_time);
    }

    /* Kill the old links, so nothing more can be sent there */
    if (ret == 0) {
        multipath_test_kill_links(test_ctx, 0);
    }

    /* Perform a data sending loop */
    if (ret == 0) {
        ret = tls_api_data_sending_loop(test_ctx, &loss_mask, &simulated_time, 0);

        if (ret != 0)
        {
            DBG_PRINTF("Data sending loop returns %d\n", ret);
        }
    }

    /* Check that the transmission succeeded */
    if (ret == 0) {
        ret = tls_api_one_scenario_body_verify(test_ctx, &simulated_time, max_completion_microsec);
    }

    /* Check that the default client address on the server was migrated,
     * as well as the default source address on the client */
    if (ret == 0 && test_ctx->cnx_server == NULL) {
        /* No server connection! */
        ret = -1;
    }

    if (ret == 0) {
        struct sockaddr* c_addr_at_server = NULL;
        struct sockaddr* c_addr_at_client = NULL;
        picoquic_get_peer_addr(test_ctx->cnx_server, &c_addr_at_server);
        picoquic_get_local_addr(test_ctx->cnx_client, &c_addr_at_client);

        if (picoquic_compare_addr((struct sockaddr*) & test_ctx->client_addr_2, c_addr_at_server) != 0 ||
            picoquic_compare_addr((struct sockaddr*) & test_ctx->client_addr_2, c_addr_at_client) != 0) {
            /* Migration was not completed */
            ret = -1;
        }
    }

    /* Delete the context */
    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
    }

    return ret;
}

int migration_controlled_test()
{
    return migration_test_one(0);
}

int migration_mtu_drop_test()
{
    return migration_test_one(1);
}

/*
 * Test of actual multipath, by opposition to only migration.
 */

void multipath_init_params(picoquic_tp_t *test_parameters, int enable_time_stamp)
{
    memset(test_parameters, 0, sizeof(picoquic_tp_t));

    picoquic_init_transport_parameters(test_parameters, 1);
    test_parameters->is_multipath_enabled = 1;
    test_parameters->initial_max_path_id = 2;
    test_parameters->enable_time_stamp = 3;
}

/* wait until the migration completes */
int wait_multipath_ready(picoquic_test_tls_api_ctx_t* test_ctx,
    uint64_t* simulated_time)
{
    int ret = 0;
    uint64_t time_out = *simulated_time + 4000000;
    int nb_trials = 0;
    int nb_inactive = 0;
    int was_active = 0;
    struct sockaddr_storage old_srce;
    struct sockaddr_storage old_dest;

    /* Check the selected path */
    picoquic_store_addr(&old_srce, (struct sockaddr*) & test_ctx->cnx_client->path[0]->local_addr);
    picoquic_store_addr(&old_dest, (struct sockaddr*) & test_ctx->cnx_client->path[0]->peer_addr);

    while (*simulated_time < time_out &&
        ret == 0 &&
        test_ctx->cnx_client->cnx_state == picoquic_state_ready &&
        nb_trials < 5000 &&
        nb_inactive < 64 &&
        (test_ctx->cnx_client->nb_paths != 2 ||
        !test_ctx->cnx_client->path[1]->challenge_verified ||
        (test_ctx->cnx_server == NULL || (test_ctx->cnx_server->nb_paths != 2 ||
        !test_ctx->cnx_server->path[1]->challenge_verified)))){
        nb_trials++;

        ret = tls_api_one_sim_round(test_ctx, simulated_time, time_out, &was_active);

        if (was_active) {
            nb_inactive = 0;
        }
        else {
            nb_inactive++;
        }
    }

    if (ret == 0 && (test_ctx->cnx_client->cnx_state != picoquic_state_ready ||
        (test_ctx->cnx_client->nb_paths != 2 ||
            !test_ctx->cnx_client->path[1]->challenge_verified) ||
            (test_ctx->cnx_server == NULL || (test_ctx->cnx_server->nb_paths != 2 ||
                !test_ctx->cnx_server->path[1]->challenge_verified)))) {
        DBG_PRINTF("Could not establish multipath, client state = %d\n",
            test_ctx->cnx_client->cnx_state);
        ret = -1;
    }

    return ret;
}

typedef enum {
    multipath_test_basic = 0,
    multipath_test_drop_first,
    multipath_test_drop_second,
    multipath_test_sat_plus,
    multipath_test_renew,
    multipath_test_rotation,
    multipath_test_nat,
    multipath_test_nat_challenge,
    multipath_test_break1,
    multipath_test_break2,
    multipath_test_back1,
    multipath_test_perf,
    multipath_test_callback,
    multipath_test_quality,
    multipath_test_quality_server,
    multipath_test_stream_af,
    multipath_test_abandon,
    multipath_test_datagram,
    multipath_test_dg_af,
    multipath_test_standby,
    multipath_test_standup,
    multipath_test_tunnel,
    multipath_test_fail,
    multipath_test_ab1,
    multipath_test_discovery
} multipath_test_enum_t;

#ifdef _WINDOWS
#define PATH_CALLBACK_TEST_REF "picoquictest\\path_callback_ref.txt"
#define PATH_QUALITY_TEST_REF "picoquictest\\path_quality_ref.txt"
#define PATH_QUALITY_SERVER_REF "picoquictest\\path_quality_server_ref.txt"
#else
#define PATH_CALLBACK_TEST_REF "picoquictest/path_callback_ref.txt"
#define PATH_QUALITY_TEST_REF "picoquictest/path_quality_ref.txt"
#define PATH_QUALITY_SERVER_REF "picoquictest/path_quality_server_ref.txt"
#endif
#define PATH_CALLBACK_CSV "path_callback.csv"
#define PATH_QUALITY_CSV "path_quality.csv"
#define PATH_QUALITY_SERVER "path_quality_server.csv"

int multipath_init_callbacks(picoquic_test_tls_api_ctx_t* test_ctx, multipath_test_enum_t test_id)
{
    int ret = 0;
    char const* filename = (test_id == multipath_test_callback) ? PATH_CALLBACK_CSV :
        ((test_id == multipath_test_quality) ? PATH_QUALITY_CSV : PATH_QUALITY_SERVER);
    /* Open a file to log bandwidth updates and document it in context */
    test_ctx->path_events = picoquic_file_open(filename, "w");
    if (test_ctx->path_events == NULL) {
        DBG_PRINTF("Could not write file <%s>", filename);
        ret = -1;
    }
    else {
        if (test_id == multipath_test_quality_server) {
            picoquic_enable_path_callbacks_default(test_ctx->qserver, 1);
            picoquic_default_quality_update(test_ctx->qserver, 50000, 5000);
        }
        else {
            picoquic_enable_path_callbacks(test_ctx->cnx_client, 1);
            if (test_id == multipath_test_quality) {
                picoquic_subscribe_to_quality_update(test_ctx->cnx_client, 50000, 5000);
                ret = picoquic_subscribe_to_quality_update_per_path(test_ctx->cnx_client, 0, 50000, 5000);
            }
        }
        if (test_id == multipath_test_callback) {
            fprintf(test_ctx->path_events, "Time, Path-ID, Event,\n");
        }
        else {
            fprintf(test_ctx->path_events, "Time, Path-ID, Event, Pacing_rate, Receive Rate, CWIN, RTT\n");
        }
    }
    return ret;
}

int multipath_verify_callbacks(multipath_test_enum_t test_id)
{
    int ret = 0;
    char file_ref[512];
    char const* filename = (test_id == multipath_test_callback) ? PATH_CALLBACK_CSV : 
        ((test_id == multipath_test_quality)?PATH_QUALITY_CSV:PATH_QUALITY_SERVER);
    char const* ref_name = (test_id == multipath_test_callback) ? PATH_CALLBACK_TEST_REF : 
        ((test_id == multipath_test_quality)?PATH_QUALITY_TEST_REF:PATH_QUALITY_SERVER_REF);

    ret = picoquic_get_input_path(file_ref, sizeof(file_ref), picoquic_solution_dir, ref_name);

    if (ret != 0) {
        DBG_PRINTF("Cannot set the reference file name for test id: %s.\n", (int)test_id);
    }
    else {
        ret = picoquic_test_compare_text_files(filename, file_ref);
    }
    return ret;
}

static int multipath_test_abandon_cycle(picoquic_test_tls_api_ctx_t* test_ctx, uint64_t* simulated_time)
{
    int ret = 0;
    uint64_t deleted_id = UINT64_MAX;
    picoquic_local_cnxid_list_t* local_cnxid_list = test_ctx->cnx_client->first_local_cnxid_list;

    while (local_cnxid_list != NULL) {
        if (!local_cnxid_list->is_demoted &&
            local_cnxid_list->unique_path_id != 0 &&
            local_cnxid_list->unique_path_id < deleted_id) {
            deleted_id = local_cnxid_list->unique_path_id;
        }
        local_cnxid_list = local_cnxid_list->next_list;
    }
    if (deleted_id == UINT64_MAX) {
        ret = -1;
    }
    else {
        ret = picoquic_abandon_path(test_ctx->cnx_client, deleted_id, 0,
            "cycle of delete", *simulated_time);
        if (ret != 0) {
            DBG_PRINTF("Could not abandon path %" PRIu64 ", ret=%d", deleted_id, ret);
        }
        else {
            /* wait about 250ms for the abandon to be noticed at both ends. */
            ret = tls_api_wait_for_timeout(test_ctx, simulated_time, 250000);
            if (ret != 0) {
                DBG_PRINTF("Issue after abandon path %" PRIu64 ", ret = %d", deleted_id, ret);
            }
        }
    }
    /* Verify that the deleted ID is gone. */
    if (ret == 0) {
        picoquic_local_cnxid_list_t* local_cnxid_list = test_ctx->cnx_client->first_local_cnxid_list;

        while (local_cnxid_list != NULL) {
            if (local_cnxid_list->unique_path_id == deleted_id) {
                DBG_PRINTF("Deleted ID %" PRIu64 " is still present", deleted_id);
                ret = -1;
                break;
            }
            local_cnxid_list = local_cnxid_list->next_list;
        }
    }
    if (ret == 0) {
        int stash_count = 0;
        /* Verify that we have enough remote path ID to continue. */
        for (int i = 0; i <= 10 && ret == 0; i++) {
            picoquic_remote_cnxid_stash_t* remote_cnxid_stash = test_ctx->cnx_client->first_remote_cnxid_stash;

            stash_count = 0;
            while (remote_cnxid_stash != NULL) {
                stash_count++;
                remote_cnxid_stash = remote_cnxid_stash->next_stash;
            }

            if (stash_count >= 2) {
                break;
            }
            else if (i < 10 && stash_count < 2) {
                ret = tls_api_wait_for_timeout(test_ctx, simulated_time, 100000);
            }
        }
        if (stash_count < 2) {
            DBG_PRINTF("Only %d stashes of CID available", stash_count);
            ret = -1;
        }
    }

    return ret;
}

void multipath_init_datagram_ctx(picoquic_test_tls_api_ctx_t* test_ctx, test_datagram_send_recv_ctx_t * dg_ctx)
{
    /* Initialize the datagram targets as a function of the test id */
    memset(dg_ctx, 0, sizeof(test_datagram_send_recv_ctx_t));
    dg_ctx->dg_max_size = PICOQUIC_MAX_PACKET_SIZE;
    dg_ctx->dg_target[0] = 100;
    dg_ctx->dg_target[1] = 100;
    dg_ctx->send_delay = 3000;
    /* Set the test contexts for sending and receiving datagrams */
    test_ctx->datagram_ctx = dg_ctx;
    test_ctx->datagram_recv_fn = test_datagram_recv;
    test_ctx->datagram_send_fn = test_datagram_send;
    test_ctx->datagram_ack_fn = test_datagram_ack;
    /* Enable multipath callbacks */
    picoquic_enable_path_callbacks_default(test_ctx->qserver, 1);
    picoquic_enable_path_callbacks(test_ctx->cnx_client, 1);
    /* Use the extended datagram API */
    dg_ctx->use_extended_provider_api = 1;
}

int multipath_set_datagram_ready(picoquic_test_tls_api_ctx_t* test_ctx, test_datagram_send_recv_ctx_t* dg_ctx, multipath_test_enum_t test_id)
{
    int ret = 0;
    /* Mark datagram ready, start to send. */
    if (test_id == multipath_test_datagram) {
        /* sending on any path */
        ret = picoquic_mark_datagram_ready(test_ctx->cnx_client, 1);
        if (ret == 0) {
            ret = picoquic_mark_datagram_ready(test_ctx->cnx_server, 1);
        }
    }
    else {
        /* Only wake up path 0 */
        dg_ctx->test_affinity = 1;
        ret = picoquic_mark_datagram_ready_path(test_ctx->cnx_client, 0, 1);
        if (ret == 0) {
            ret = picoquic_mark_datagram_ready_path(test_ctx->cnx_server, 0, 1);
        }
    }
    return ret;
}

int multipath_verify_datagram_sent(test_datagram_send_recv_ctx_t* dg_ctx, multipath_test_enum_t test_id)
{
    int ret = 0;

    /* Verify datagrams have been received -- 3/4 will be enough */
    if (4*dg_ctx->dg_recv[0] < 3*dg_ctx->dg_target[1] ||
        4*dg_ctx->dg_recv[1] < 3*dg_ctx->dg_target[0]) {
        DBG_PRINTF("%s", "Did not receive expected datagrams: ");
        for (int i = 0; i < 2; i++) {
            DBG_PRINTF("dg_target[%d]=%d, dg_sent[%d]=%d, dg_recv[%d]=%d",
                i, dg_ctx->dg_target[i], i, dg_ctx->dg_sent[i], 1 - i, dg_ctx->dg_recv[1 - i]);
            ret = -1;
        }
    }
    if (ret == 0) {
        if (test_id == multipath_test_datagram) {
            for (int i = 0; ret == 0 && i < 2; i++) {
                int min_expected = dg_ctx->dg_recv[i] / 8;

                if (dg_ctx->nb_recv_path_0[i] < min_expected ||
                    dg_ctx->nb_recv_path_other[i] < min_expected) {
                    DBG_PRINTF("Datagram not balanced, %s received %d on path 0, %d on others",
                        (i) ? "client" : "server", dg_ctx->nb_recv_path_0[i], dg_ctx->nb_recv_path_other[i]);
                    ret = -1;
                }
            }
        }
        else if (test_id == multipath_test_dg_af) {
            for (int i = 0; ret == 0 && i < 2; i++) {
                if (dg_ctx->nb_recv_path_other[i] > 0) {
                    DBG_PRINTF("Datagram affinity fails, %s received %d on path 0, %d on others",
                        (i) ? "client" : "server", dg_ctx->nb_recv_path_0[i], dg_ctx->nb_recv_path_other[i]);
                    ret = -1;
                }
            }
        }
    }
    return ret;
}

static int multipath_verify_all_cid_available(picoquic_cnx_t* cnx)
{
    int ret = 0;
    uint64_t unique_id_max = 0;
    picoquic_remote_cnxid_stash_t* stash = cnx->first_remote_cnxid_stash;

    while (stash != NULL) {
        if (stash->unique_path_id > unique_id_max) {
            unique_id_max = stash->unique_path_id;
        }
        stash = stash->next_stash;
    }
    if (unique_id_max < cnx->max_path_id_local && unique_id_max < cnx->max_path_id_remote) {
        ret = -1;
    }
    return ret;
}

int multipath_datagram_send_loop(picoquic_test_tls_api_ctx_t* test_ctx,
    test_datagram_send_recv_ctx_t* dg_ctx, uint64_t* loss_mask, uint64_t* simulated_time)
{
    int ret = 0;
    int nb_trials = 0;
    int nb_inactive = 0;

    test_ctx->c_to_s_link->loss_mask = loss_mask;
    test_ctx->s_to_c_link->loss_mask = loss_mask;

    while (ret == 0 && nb_trials < 16000 && nb_inactive < 512 && TEST_CLIENT_READY && TEST_SERVER_READY) {
        int was_active = 0;
        uint64_t time_out = test_datagram_next_time_ready(dg_ctx);
        nb_trials++;

        ret = tls_api_one_sim_round(test_ctx, simulated_time, time_out, &was_active);

        if (ret < 0) {
            break;
        }

        if (was_active) {
            nb_inactive = 0;
        } else {
            nb_inactive++;
        }

        /* Simulate wake up when data is ready for real time operation */
        for (int i = 0; i < 2; i++) {
            picoquic_cnx_t* cnx = (i == 0) ? test_ctx->cnx_server : test_ctx->cnx_client;
            if (!dg_ctx->is_ready[i] && test_datagram_check_ready(dg_ctx, i, *simulated_time)) {
                if (dg_ctx->test_affinity) {
                    picoquic_mark_datagram_ready_path(cnx, 0, 1);
                }
                else {
                    picoquic_mark_datagram_ready(cnx, 1);
                }
            }
        }

        if (test_ctx->test_finished) {
            if (test_ctx->immediate_exit ||
                (picoquic_is_cnx_backlog_empty(test_ctx->cnx_client) && picoquic_is_cnx_backlog_empty(test_ctx->cnx_server))) {
                break;
            }
        }
    }

    return ret;
}

int multipath_test_one(uint64_t max_completion_microsec, multipath_test_enum_t test_id)
{
    uint64_t simulated_time = 0;
    uint64_t loss_mask = 0;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    test_datagram_send_recv_ctx_t dg_ctx = { 0 };
    picoquic_connection_id_t initial_cid = { {0x1b, 0x11, 0xc0, 4, 5, 6, 7, 8}, 8 };
    picoquic_tp_t server_parameters;
    uint64_t original_r_cid_sequence = 0;
    size_t send_buffer_size = 0;
    int ret;

    initial_cid.id[2] = (int)test_id;

    if (test_id == multipath_test_perf) {
        send_buffer_size = 65536;
    }

    /* Create the context but delay initialization, so the multipath option can be set */
    ret = tls_api_init_ctx_ex2(&test_ctx, PICOQUIC_INTERNAL_TEST_VERSION_1,
        PICOQUIC_TEST_SNI, PICOQUIC_TEST_ALPN, &simulated_time, NULL, NULL, 0, 1, 0, &initial_cid,
        8, 0, send_buffer_size, 0);

    if (ret == 0 && test_ctx == NULL) {
        ret = -1;
    }

    if (ret == 0) {
        int is_sat_test = (test_id == multipath_test_sat_plus);
        if (is_sat_test || test_id == multipath_test_break1 || test_id == multipath_test_break2 || test_id == multipath_test_back1) {
            /* Reduce the throughput of path #0 to 1 mbps.
             * This is used to simulate an asymmetric "satellite and landline" scenario,
             * or to simulate a long transfer and test broken path detection or repair */
            multipath_test_sat_links(test_ctx, 0);
        }
        else if (test_id == multipath_test_perf) {
            multipath_test_perf_links(test_ctx, 0);
            picoquic_set_default_congestion_algorithm(test_ctx->qserver, picoquic_bbr_algorithm);
        }
        test_ctx->c_to_s_link->queue_delay_max = 2 * test_ctx->c_to_s_link->microsec_latency;
        test_ctx->s_to_c_link->queue_delay_max = 2 * test_ctx->s_to_c_link->microsec_latency;

        if (test_id == multipath_test_rotation) {
            picoquic_set_default_crypto_epoch_length(test_ctx->qserver, 200);
        }

        if (test_id == multipath_test_callback || test_id == multipath_test_quality || test_id == multipath_test_quality_server || test_id == multipath_test_stream_af) {
            multipath_init_callbacks(test_ctx, test_id);
        }

        if (test_id == multipath_test_datagram || test_id == multipath_test_dg_af) {
            multipath_init_datagram_ctx(test_ctx, &dg_ctx);
        }

        picoquic_set_binlog(test_ctx->qserver, ".");
        test_ctx->qserver->use_long_log = 1;
        /* set the binary log on the client side */
        picoquic_set_binlog(test_ctx->qclient, ".");
        test_ctx->qclient->use_long_log = 1;
        binlog_new_connection(test_ctx->cnx_client);
        /* Set the multipath option at both client and server */
        multipath_init_params(&server_parameters, is_sat_test);
        if (test_id == multipath_test_datagram || test_id == multipath_test_dg_af) {
            server_parameters.max_datagram_frame_size = 1536;
            test_ctx->cnx_client->local_parameters.max_datagram_frame_size = 1536;
        }
        if (test_id == multipath_test_discovery) {
            server_parameters.address_discovery_mode = 1;
            test_ctx->cnx_client->local_parameters.address_discovery_mode = 3;
        }

        picoquic_set_default_tp(test_ctx->qserver, &server_parameters);
        test_ctx->cnx_client->local_parameters.enable_time_stamp = 3;

        test_ctx->cnx_client->local_parameters.is_multipath_enabled = 1;
        test_ctx->cnx_client->local_parameters.initial_max_path_id = 3;
    }

    /* establish the connection */
    if (ret == 0) {
        /* Initialize the client connection */
        picoquic_start_client_cnx(test_ctx->cnx_client);
        ret = tls_api_connection_loop(test_ctx, &loss_mask, 2 * test_ctx->s_to_c_link->microsec_latency, &simulated_time);
    }
    /* verify that multipath is negotiated on both sides */
    if (!test_ctx->cnx_client->is_multipath_enabled || !test_ctx->cnx_server->is_multipath_enabled) {
        DBG_PRINTF("Multipath not fully negotiated (c=%d, s=%d)",
            test_ctx->cnx_client->is_multipath_enabled, test_ctx->cnx_server->is_multipath_enabled);
        ret = -1;
    }
    /* verify that both sides have the same vision of max path id*/
    if (test_ctx->cnx_client->max_path_id_local != test_ctx->cnx_server->max_path_id_remote ||
        test_ctx->cnx_client->max_path_id_remote != test_ctx->cnx_server->max_path_id_local) {
        DBG_PRINTF("No agreement on max path if (c=%u/%u, s=%u/%u)",
            (uint32_t)test_ctx->cnx_client->max_path_id_local, (uint32_t)test_ctx->cnx_client->max_path_id_remote,
            (uint32_t)test_ctx->cnx_server->max_path_id_local, (uint32_t)test_ctx->cnx_server->max_path_id_remote);
        ret = -1;
    }

    /* wait until the client (and thus the server) is ready */
    if (ret == 0) {
        ret = wait_client_connection_ready(test_ctx, &simulated_time);
    }

    if (ret == 0 && test_id == multipath_test_ab1) {
        for (int i = 0; ret == 0 && i < 7; i++) {
            ret = multipath_test_abandon_cycle(test_ctx, &simulated_time);
        }
    }

    /* Prepare to send data */
    if (ret == 0) {
        if (test_id == multipath_test_sat_plus || test_id == multipath_test_perf) {
            ret = test_api_init_send_recv_scenario(test_ctx, test_scenario_multipath_long, sizeof(test_scenario_multipath_long));
        } else {
            ret = test_api_init_send_recv_scenario(test_ctx, test_scenario_multipath, sizeof(test_scenario_multipath));
        }

        if (ret != 0)
        {
            DBG_PRINTF("Init send receive scenario returns %d\n", ret);
        }
    }

    /* Add the multipath links and initiate the path creation */
    if (ret == 0) {
        ret = multipath_test_add_links(test_ctx, 0);
        if (ret == 0) {
            if (test_id == multipath_test_sat_plus) {
                /* Simulate an asymmetric "satellite and landline" scenario */
                multipath_test_sat_links(test_ctx, 1);
            }
            else if (test_id == multipath_test_perf) {
                multipath_test_perf_links(test_ctx, 1);
            }
            else if (test_id == multipath_test_fail) {
                /* Kill link #1 in server to client direction. This will cause path challenges to fail */
                multipath_test_kill_server_links(test_ctx, 1);
            }
        }
    }

    if (ret == 0) {
        ret = picoquic_probe_new_path(test_ctx->cnx_client, (struct sockaddr*) & test_ctx->server_addr,
            (struct sockaddr*) & test_ctx->client_addr_2, simulated_time);
    }

    /* Check that the two paths are established */
    if (ret == 0 && test_id != multipath_test_fail) {
        ret = wait_multipath_ready(test_ctx, &simulated_time);
    }
     if (ret == 0){
        if (test_id == multipath_test_stream_af) {
            ret = picoquic_set_stream_path_affinity(test_ctx->cnx_server, 4, 0);
            if (ret != 0) {
                DBG_PRINTF("Cannot set stream affinity, ret = %d", ret);
            }
        }
        else if (test_id == multipath_test_standby ||
            test_id == multipath_test_standup) {
            ret = picoquic_set_path_status(test_ctx->cnx_client, 1, picoquic_path_status_standby);
        }
    }

    if (ret == 0 && (test_id == multipath_test_drop_first || test_id == multipath_test_drop_second ||
        test_id == multipath_test_renew || test_id == multipath_test_nat || test_id == multipath_test_nat_challenge ||
        test_id == multipath_test_break1 || test_id == multipath_test_break2 ||
        test_id == multipath_test_back1 || test_id == multipath_test_standup ||
        test_id == multipath_test_abandon || test_id == multipath_test_tunnel)) {
        /* If testing a final link drop before completion, perform a 
         * partial sending loop and then kill the initial link.
         * For the tunnel scenario, do the same but kill both links.
         */
        if (ret == 0) {
            uint64_t timeout = 640000;

            ret = tls_api_wait_for_timeout(test_ctx, &simulated_time, timeout);

            if (ret != 0)
            {
                DBG_PRINTF("Wait for %" PRIu64 "us returns %d\n", timeout, ret);
            }
        }
        if (ret == 0) {
            if (test_id == multipath_test_renew) {
                ret = picoquic_renew_connection_id(test_ctx->cnx_client, 1);
            }
            else if (test_id == multipath_test_nat || test_id == multipath_test_nat_challenge) {
                /* Change the client address */
                test_ctx->client_addr_natted = test_ctx->client_addr;
                test_ctx->client_addr_natted.sin_port += 7;
                test_ctx->client_use_nat = 1;
                if (test_id == multipath_test_nat_challenge) {
                    test_ctx->cnx_client->path[0]->challenge_required = 1;
                }
            }
            else if (test_id == multipath_test_abandon) {
                /* Client abandons the path, causes it to be demoted. Server should follow suit. */
                picoquic_abandon_path(test_ctx->cnx_client, 0, 0, "test",
                    simulated_time);
            }
            else if (test_id == multipath_test_break2) {
                /* Trigger "destination unreachable" error on next socket call to link 1 */
                multipath_test_set_unreachable(test_ctx, 1);
            }
            else if (test_id == multipath_test_tunnel) {
                /* Break both links */
                multipath_test_kill_links(test_ctx, 0);
                multipath_test_kill_links(test_ctx, 1);
            } else {
                multipath_test_kill_links(test_ctx, 
                    (test_id == multipath_test_drop_first ||
                        test_id == multipath_test_standup) ? 0 : 1);
            }
        }
    }
    /* For the "backup scenario", wait a small interval, then bring the path # 1 back up
     * For the "tunnel" scenario, do the same but wait 5 seconds and then restore both links.
     */
    if (ret == 0 && (test_id == multipath_test_back1 || test_id == multipath_test_tunnel)) {
        uint64_t timeout = (test_id == multipath_test_tunnel)?5000000:1000000;

        ret = tls_api_wait_for_timeout(test_ctx, &simulated_time, timeout);

        if (ret != 0)
        {
            DBG_PRINTF("Wait for %" PRIu64 "us returns %d\n", timeout, ret);
        }
        else {
            if (test_id == multipath_test_tunnel) {
                multipath_test_unkill_links(test_ctx, 0, simulated_time);
            }
            multipath_test_unkill_links(test_ctx, 1, simulated_time);
        }
    }
    /* In the "abandon" scenario, allow for a bit more than 1 second of delay for clearing of paths */
    if (ret == 0 && test_id == multipath_test_abandon) {
        uint64_t timeout = 1100000;

        ret = tls_api_wait_for_timeout(test_ctx, &simulated_time, timeout);

        if (ret != 0)
        {
            DBG_PRINTF("Wait for %" PRIu64 "us returns %d\n", timeout, ret);
        }
    }

    /* In the datagram scenarios, trigger the datagram transmission */
    if (ret == 0 && (test_id == multipath_test_datagram || test_id == multipath_test_dg_af)) {
        ret = multipath_set_datagram_ready(test_ctx, &dg_ctx, test_id);
    }

    /* Perform a final data sending loop, this time to completion  */
    if (ret == 0) { 
        if (test_id == multipath_test_datagram || test_id == multipath_test_dg_af) {
            ret = multipath_datagram_send_loop(test_ctx, &dg_ctx, &loss_mask, &simulated_time);
        }
        else if (!test_ctx->test_finished ||
            !picoquic_is_cnx_backlog_empty(test_ctx->cnx_client) ||
            !picoquic_is_cnx_backlog_empty(test_ctx->cnx_server)){
            ret = tls_api_data_sending_loop(test_ctx, &loss_mask, &simulated_time, 0);
        }

        if (ret != 0)
        {
            DBG_PRINTF("Data sending loop returns %d\n", ret);
        }
    }

    /* Check that the transmission succeeded */
    if (ret == 0) {
        ret = tls_api_one_scenario_body_verify(test_ctx, &simulated_time, max_completion_microsec);
    }

    if (ret == 0 && test_id == multipath_test_basic) {
        if ((ret = multipath_verify_all_cid_available(test_ctx->cnx_client)) != 0) {
            DBG_PRINTF("%s", "Not received all CID from server");
        }
        else if ((ret = multipath_verify_all_cid_available(test_ctx->cnx_server)) != 0) {
            DBG_PRINTF("%s", "Not received all CID from client");
        }
    }

    if (ret == 0 && test_id == multipath_test_fail) {
        if (test_ctx->cnx_client->nb_paths != 1 ||
            (test_ctx->cnx_server != NULL && test_ctx->cnx_server->nb_paths != 1)) {
            DBG_PRINTF("Delete failing path failed, client = %d paths, server = %d paths\n",
                test_ctx->cnx_client->nb_paths,
                (test_ctx->cnx_server == NULL) ? 0 : test_ctx->cnx_server->nb_paths);
            ret = -1;
        }
    }

    if (ret == 0 && test_id == multipath_test_renew) {
        if (test_ctx->cnx_client->path[1]->p_remote_cnxid->sequence == original_r_cid_sequence) {
            DBG_PRINTF("Remote CID on client path 1 is still %" PRIu64 "\n", original_r_cid_sequence);
            ret = -1;
        } else if (test_ctx->cnx_server->path[1]->p_remote_cnxid->sequence == original_r_cid_sequence) {
            DBG_PRINTF("Remote CID on server path 1 is still %" PRIu64 "\n", original_r_cid_sequence);
            ret = -1;
        }
        else if (test_ctx->cnx_server->path[1]->p_local_cnxid->sequence == original_r_cid_sequence) {
            DBG_PRINTF("Local CID on server path 1 is still %" PRIu64 "\n", original_r_cid_sequence);
            ret = -1;
        }
    }

    if (ret == 0 && test_id == multipath_test_rotation) {
        if (test_ctx->cnx_server->nb_crypto_key_rotations == 0) {
            DBG_PRINTF("%s", "No key rotation observed.\n");
            ret = -1;
        }
    }

    if (ret == 0) {
        uint64_t mask = 0;
        for (int i = 0; ret == 0 && i < test_ctx->cnx_client->nb_paths; i++) {
            if (test_ctx->cnx_client->path[i]->unique_path_id > 63) {
                DBG_PRINTF("Path ID[%d] = %" PRIu64 ", too big!", i, test_ctx->cnx_client->path[i]->unique_path_id);
                ret = -1;
            }
            else if ((mask & (1ull << test_ctx->cnx_client->path[i]->unique_path_id)) != 0) {
                DBG_PRINTF("Path ID[%d] = %" PRIu64 ", reuse!", i, test_ctx->cnx_client->path[i]->unique_path_id);
                ret = -1;
            }
            else if (test_ctx->cnx_client->path[i]->p_local_cnxid != NULL && test_ctx->cnx_client->path[i]->unique_path_id !=
                test_ctx->cnx_client->path[i]->p_local_cnxid->path_id) {
                DBG_PRINTF("Path ID[%d] = %" PRIu64 ", vs. local CID path id: %" PRIu64,
                    i, test_ctx->cnx_client->path[i]->unique_path_id,
                    i, test_ctx->cnx_client->path[i]->p_local_cnxid->path_id);
                ret = -1;
            }
        }
    }


    if (ret == 0 && (test_id == multipath_test_nat || test_id == multipath_test_nat_challenge)) {
        /* Check that the path 0 has the new address */
        if (test_ctx->cnx_server->nb_paths < 2 ||
            test_ctx->cnx_client->nb_paths < 2 ||
            test_ctx->cnx_server->path[0]->unique_path_id != 0 ||
            test_ctx->cnx_client->path[0]->unique_path_id != 0 ||
            picoquic_compare_addr((struct sockaddr*)&test_ctx->cnx_server->path[0]->peer_addr,
                (struct sockaddr*)&test_ctx->client_addr_natted) != 0) {
            DBG_PRINTF("%s", "NAT traversal looks wrong.\n");
            ret = -1;
        }
    }

    if (ret == 0 && (test_id == multipath_test_break1 || test_id == multipath_test_break2 || test_id == multipath_test_abandon)) {
        if (test_ctx->cnx_server->nb_paths != 1) {
            DBG_PRINTF("After break, %d paths on server connection.\n", test_ctx->cnx_server->nb_paths);
            ret = -1;
        } else if (test_ctx->cnx_client->nb_paths != 1) {
            DBG_PRINTF("After break, %d paths on client connection.\n", test_ctx->cnx_client->nb_paths);
            ret = -1;
        }
    }

    if (ret == 0 && test_id == multipath_test_back1) {
        if (test_ctx->cnx_server->nb_paths != 2) {
            DBG_PRINTF("After break and back, %d paths on server connection.\n", test_ctx->cnx_server->nb_paths);
            ret = -1;
        }
        else if (test_ctx->cnx_client->nb_paths != 2) {
            DBG_PRINTF("After break and back, %d paths on server connection.\n", test_ctx->cnx_client->nb_paths);
            ret = -1;
        }
    }

    if (ret == 0 && test_id == multipath_test_stream_af) {
        if (test_ctx->cnx_server->nb_paths != 2) {
            DBG_PRINTF("After break and back, %d paths on server connection.\n", test_ctx->cnx_server->nb_paths);
            ret = -1;
        }
        else if (test_ctx->cnx_server->path[0]->delivered < 1400000) {
            DBG_PRINTF("Not enough data delivered on server path 0 (%" PRIu64 ").\n", test_ctx->cnx_server->path[0]->delivered);
            ret = -1;
        }
        else if (test_ctx->cnx_server->path[1]->delivered > 600000) {
            DBG_PRINTF("Too much data delivered on server path 1 (%" PRIu64 ").\n",
                test_ctx->cnx_server->path[1]->delivered);
            ret = -1;
        }
    }

    /* In the datagram scenarios, verify the datagram transmission */
    if (ret == 0 && (test_id == multipath_test_datagram || test_id == multipath_test_dg_af)) {
        ret = multipath_verify_datagram_sent(&dg_ctx, test_id);
    }

    /* In the standby scenario, verify that the flag is set
    * correctly at the server, and that not too much data is
    * sent on standby path.
    */
    if (ret == 0 && (test_id == multipath_test_standby)) {
        if (!test_ctx->cnx_server->path[1]->path_is_standby) {
            DBG_PRINTF("Standby not set on server path 1 (%d).\n", test_ctx->cnx_server->path[1]->path_is_standby);
            ret = -1;
        }
        else if (test_ctx->cnx_server->path[1]->delivered > 50000) {
            DBG_PRINTF("Too much data delivered on server path 1 (%" PRIu64 ").\n", test_ctx->cnx_server->path[1]->delivered);
            ret = -1;
        }
    }

    if (ret == 0 && test_id == multipath_test_discovery) {
        if (test_ctx->nb_address_observed < 2) {
            DBG_PRINTF("Got % addresses observed", test_ctx->nb_address_observed);
            ret = -1;
        }
        for (int p = 0; p < 2; p++) {
            if (picoquic_compare_addr(
                (struct sockaddr*)&test_ctx->cnx_client->path[p]->local_addr,
                (struct sockaddr*)&test_ctx->cnx_client->path[p]->observed_addr) != 0) {
                char text1[256];
                char text2[256];

                DBG_PRINTF("Path %d, Local: %s, observed: %s", p,
                    picoquic_addr_text((struct sockaddr*)&test_ctx->cnx_client->path[p]->local_addr, text1, sizeof(text1)),
                    picoquic_addr_text((struct sockaddr*)&test_ctx->cnx_client->path[p]->observed_addr, text2, sizeof(text2)));
                ret = -1;
            }
        }
    }
    /* Delete the context */
    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
    }

    /* Check the multipath event logs if collected. */
    if (ret == 0 && (test_id == multipath_test_callback || test_id == multipath_test_quality || test_id == multipath_test_quality_server)) {
        ret = multipath_verify_callbacks(test_id);
    }

    return ret;
}

/* Basic multipath test. Set up two links in parallel, verify that both are used and that
 * the overall transmission is shorterthan if only one link was used.
 */

int multipath_basic_test()
{
    uint64_t max_completion_microsec = 1060000;

    return multipath_test_one(max_completion_microsec, multipath_test_basic);
}

/* Multipath fail test. Same as basic, but the multipath setup is expected to fail.
*/

int multipath_fail_test()
{
    uint64_t max_completion_microsec = 2000000;

    return multipath_test_one(max_completion_microsec, multipath_test_fail);
}

/* Multipath abandon path 1. Same as basic, but abandon a path before it is
* even established. And then repeat a cycle of abandon path / wait for
* new CID to make sure that the peer properly provisions new CID. And then
* create a path for real and use it.
*/

int multipath_ab1_test()
{
    uint64_t max_completion_microsec = 3000000;

    return multipath_test_one(max_completion_microsec, multipath_test_ab1);
}

/* Drop first multipath test. Set up two links in parallel, start using them, then
 * drop the first one of them. Check that the transmission succeeds.
 */

int multipath_drop_first_test()
{
    uint64_t max_completion_microsec = 1490000;

    return multipath_test_one(max_completion_microsec, multipath_test_drop_first);
}

/* Drop second multipath test. Set up two links in parallel, start using them, then
 * drop the second one of them. Check that the transmission succeeds.
 */

int multipath_drop_second_test()
{
    uint64_t max_completion_microsec = 1260000;

    return multipath_test_one(max_completion_microsec, multipath_test_drop_second);
}

/* Simulate the combination of a satellite link and a low latency low bandwidth
 * terrestrial link
 */
int multipath_sat_plus_test()
{
    uint64_t max_completion_microsec = 10000000;

    return  multipath_test_one(max_completion_microsec, multipath_test_sat_plus);
}

/* Test the renewal of the connection ID on a path
 */
int multipath_renew_test()
{
    uint64_t max_completion_microsec = 3000000;

    return  multipath_test_one(max_completion_microsec, multipath_test_renew);
}

/* Test key rotation in a multipath setup
 */
int multipath_rotation_test()
{
    uint64_t max_completion_microsec = 3000000;

    return  multipath_test_one(max_completion_microsec, multipath_test_rotation);
}

/* Test nat traversal in a multipath setup */
int multipath_nat_test()
{
    uint64_t max_completion_microsec = 3000000;

    return  multipath_test_one(max_completion_microsec, multipath_test_nat);
}

int multipath_nat_challenge_test()
{
    uint64_t max_completion_microsec = 3000000;

    return  multipath_test_one(max_completion_microsec, multipath_test_nat_challenge);
}


/* Test that breaking paths are removed after some time
 */
int multipath_break1_test()
{
    uint64_t max_completion_microsec = 10800000;

    return  multipath_test_one(max_completion_microsec, multipath_test_break1);
}

/* Test reaction to socket error on second path
 */
int multipath_socket_error_test()
{
    uint64_t max_completion_microsec = 10900000;

    return  multipath_test_one(max_completion_microsec, multipath_test_break2);
}

/* Test that abandoned paths are removed after some time
 */
int multipath_abandon_test()
{
    uint64_t max_completion_microsec = 3800000;

    return  multipath_test_one(max_completion_microsec, multipath_test_abandon);
}

/* Test that breaking paths can come back up after some time
 */
int multipath_back1_test()
{
    /* TODO: investigate why 3.3 instead of 3.05 with prior implementation of multipath */
    uint64_t max_completion_microsec = 3300000;

    return  multipath_test_one(max_completion_microsec, multipath_test_back1);
}

/* Test that a typical wifi+lte scenario provides good performance */
int multipath_perf_test()
{
    uint64_t max_completion_microsec = 1650000;

    return  multipath_test_one(max_completion_microsec, multipath_test_perf);
}

#if defined(_WINDOWS) && !defined(_WINDOWS64)
int multipath_callback_test()
{
    /* we do not run this test on Win32 builds */
    return 0;
}
#else
int multipath_callback_test()
{
    uint64_t max_completion_microsec = 1000000;

    return multipath_test_one(max_completion_microsec, multipath_test_callback);
}
#endif

#if defined(_WINDOWS) && !defined(_WINDOWS64)
int multipath_quality_test()
{
    /* we do not run this test on Win32 builds */
    return 0;
}
#else
int multipath_quality_test()
{
    uint64_t max_completion_microsec = 1000000;

    return multipath_test_one(max_completion_microsec, multipath_test_quality);
}
#endif

int multipath_stream_af_test()
{
    uint64_t max_completion_microsec = 1500000;

    return multipath_test_one(max_completion_microsec, multipath_test_stream_af);
}

int multipath_datagram_test()
{
    /* TODO: investigate why 1.15 instead of 1.12 with prior implementation of multipath */
    uint64_t max_completion_microsec = 1150000;

    return multipath_test_one(max_completion_microsec, multipath_test_datagram);
}

int multipath_dg_af_test()
{
    uint64_t max_completion_microsec = 1100000;

    return multipath_test_one(max_completion_microsec, multipath_test_dg_af);
}

int multipath_standby_test()
{
    uint64_t max_completion_microsec = 2000000;

    return multipath_test_one(max_completion_microsec, multipath_test_standby);
}

int multipath_standup_test()
{
    uint64_t max_completion_microsec = 3000000;

    return multipath_test_one(max_completion_microsec, multipath_test_standup);
}

int multipath_discovery_test()
{
    uint64_t max_completion_microsec = 2000000;

    return multipath_test_one(max_completion_microsec, multipath_test_discovery);
}

/* Monopath tests:
 * Enable the multipath option, but use only a single path. The gal of the tests is to verify that
 * these "monopath" scenarios perform just as well as if multipath was not enabled.
 */

typedef enum {
    monopath_test_basic = 0,
    monopath_test_hole,
    monopath_test_rotation,
} monopath_test_enum_t;

/* Basic connection with the multicast option enabled. */
int monopath_test_one(monopath_test_enum_t test_case)
{
    uint64_t simulated_time = 0;
    const uint64_t latency = 10000;
    picoquic_tp_t client_parameters;
    picoquic_tp_t server_parameters;
    picoquic_connection_id_t initial_cid = { {0xba, 0xba, 1, 0, 0, 0, 0, 0}, 8 };
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    int ret = 0;

    multipath_init_params(&client_parameters, 0);
    multipath_init_params(&server_parameters, 0);

    ret = tls_api_one_scenario_init_ex(&test_ctx, &simulated_time, PICOQUIC_INTERNAL_TEST_VERSION_1, &client_parameters, &server_parameters, &initial_cid, 0);

    if (ret == 0 && test_ctx == NULL) {
        ret = -1;
    }

    /* Simulate satellite links: 250 mbps, 300ms delay in each direction */
    /* Set the congestion algorithm to specified value. Also, request a packet trace */
    if (ret == 0) {
        /* set the delay estimate, then launch the test */
        test_ctx->c_to_s_link->microsec_latency = latency;
        test_ctx->s_to_c_link->microsec_latency = latency;

        picoquic_set_binlog(test_ctx->qserver, ".");
        test_ctx->qserver->use_long_log = 1;
        /* set the binary log on the client side */
        picoquic_set_binlog(test_ctx->qclient, ".");
        test_ctx->qclient->use_long_log = 1;
        /* Since the client connection was created before the binlog was set, force log of connection header */
        binlog_new_connection(test_ctx->cnx_client);

        if (test_case == monopath_test_hole) {
            /* set the optimistic ack policy, to trigger hole insertion at the server */
            picoquic_set_optimistic_ack_policy(test_ctx->qserver, PICOQUIC_DEFAULT_HOLE_PERIOD);
            /* Reset the uniform random test */
            picoquic_public_random_seed_64(RANDOM_PUBLIC_TEST_SEED, 1);
        }

        if (test_case == monopath_test_rotation) {
            picoquic_set_default_crypto_epoch_length(test_ctx->qserver, 200);
        }

        ret = tls_api_one_scenario_body(test_ctx, &simulated_time,
            test_scenario_multipath, sizeof(test_scenario_multipath), 0, 0, 0, 2 * latency,
            2200000);
    }

    if (ret == 0){
        if (test_case == monopath_test_hole) {
            if (test_ctx->cnx_server->nb_packet_holes_inserted == 0) {
                DBG_PRINTF("%s", "No holes inserted\n");
                ret = -1;
            }
        }
        else if (test_case == monopath_test_rotation) {
            if (test_ctx->cnx_server->nb_crypto_key_rotations == 0) {
                DBG_PRINTF("%s", "No key rotation observed.\n");
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

/* Basic connection with the multicast option enabled. */
int monopath_basic_test()
{
    return monopath_test_one(monopath_test_basic);
}

/* Testing the defense against opportunistic acks. */
int monopath_hole_test()
{
    return monopath_test_one(monopath_test_hole);
}

/* Testing key rotation in monopath context. */
int monopath_rotation_test()
{
    return monopath_test_one(monopath_test_rotation);
}

/* The zero RTT test uses the unipath code, with a special parameter.
 * Test both regular 0RTT set up, and case of losses.
 */
int zero_rtt_test_one(int use_badcrypt, int hardreset, uint64_t early_loss,
    unsigned int no_coal, unsigned int long_data, uint64_t extra_delay, int do_multipath);

int monopath_0rtt_test()
{
    return zero_rtt_test_one(0, 0, 0, 0, 0, 0, 1);
}

int monopath_0rtt_loss_test()
{
    int ret = 0;

    for (unsigned int i = 1; ret == 0 && i < 16; i++) {
        uint64_t early_loss = 1ull << i;
        ret = zero_rtt_test_one(0, 0, early_loss, 0, 0, 0, 1);
        if (ret != 0) {
            DBG_PRINTF("Monopath 0 RTT test fails when packet #%d is lost.\n", i);
        }
    }

    return ret;
}

/*
 * Test the multipath variant of AEAD encrypt and decrypt.
 */
int multipath_aead_test()
{
    int ret = 0;
    const uint8_t mp_aead_secret[32] = {
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
        16, 17, 18, 19, 20, 21, 22, 23, 24, 35, 26, 27, 28, 29, 30, 31
    };
    /* Create AEAD contexts for encryption and decryption */
    void* aead_encrypt = picoquic_setup_test_aead_context(1, mp_aead_secret, PICOQUIC_LABEL_QUIC_V1_KEY_BASE);
    void* aead_decrypt = picoquic_setup_test_aead_context(0, mp_aead_secret, PICOQUIC_LABEL_QUIC_V1_KEY_BASE);

    if (aead_encrypt == NULL || aead_decrypt == NULL) {
        DBG_PRINTF("%s", "Could not create the AEAD contexts.\n");
        ret = -1;
    }
    else {
        /* For a series of path_id, verify that encryption and decryption works */
        const uint64_t path_id_test[] = { 0, 1, 2, 0x0123456789abcdefull };
        const size_t nb_paths = sizeof(path_id_test) / sizeof(uint64_t);
        uint64_t sequence = 12345;
        const char* aad_str = "This is a test";
        const size_t aad_len = strlen(aad_str);
        const uint8_t* aad = (const uint8_t*)aad_str;
        const char* test_input_str = "The quick brown fox jumps over the lazy dog";
        const size_t test_input_len = strlen(test_input_str);
        const uint8_t* test_input = (const uint8_t*)test_input_str;
        uint8_t encrypted[256];
        uint8_t decrypted[256];
        size_t encrypted_length;
        size_t decrypted_length;

        for (size_t i = 0; ret == 0 &&  i < nb_paths; i++) {
            encrypted_length = picoquic_aead_encrypt_mp(encrypted, test_input, test_input_len,
                path_id_test[i], sequence, aad, aad_len, aead_encrypt);
            for (size_t j = 0; ret == 0 && j < nb_paths; j++) {
                decrypted_length = picoquic_aead_decrypt_mp(decrypted, encrypted, encrypted_length,
                    path_id_test[j], sequence, aad, aad_len, aead_decrypt);
                if (i != j) {
                    if (decrypted_length <= encrypted_length) {
                        DBG_PRINTF("Unexpected success, path id encode 0x%" PRIx64 ", decode 0x%"PRIx64"\n",
                            path_id_test[i], path_id_test[j]);
                        ret = -1;
                    }
                }
                else if (decrypted_length > encrypted_length) {
                    DBG_PRINTF("Unexpected error, path id 0x%" PRIx64 "\n", path_id_test[i]);
                    ret = -1;
                }
                else if (decrypted_length != test_input_len) {
                    DBG_PRINTF("Length don't match, path id 0x%" PRIx64 ", in: %zu, out %zu\n",
                        path_id_test[i], test_input_len, decrypted_length);
                    ret = -1;
                }
                else if (memcmp(decrypted, test_input, test_input_len) != 0) {
                    DBG_PRINTF("Decoded doesn't match encoded, path id 0x%" PRIx64 "\n", path_id_test[i]);
                    ret = -1;
                }
            }
        }
    }

    if (aead_encrypt != NULL) {
        picoquic_aead_free(aead_encrypt);
    }
    if (aead_decrypt != NULL) {
        picoquic_aead_free(aead_decrypt);
    }

    return ret;
}

/* Test the log of multipath connections
 */

#define MULTIPATH_TRACE_BIN  "0807060504030201.server.log"
#define MULTIPATH_QLOG "multipath_qlog_test.qlog"
#ifdef _WINDOWS
#define MULTIPATH_QLOG_REF "picoquictest\\multipath_qlog_ref.txt"
#else
#define MULTIPATH_QLOG_REF "picoquictest/multipath_qlog_ref.txt"
#endif

static test_api_stream_desc_t test_scenario_multipath_qlog[] = {
    { 4, 0, 257, 10000 },
    { 8, 4, 257, 10000 }
};

static const picoquic_connection_id_t qlog_multipath_initial_cid = { {8, 7, 6, 5, 4, 3, 2, 1}, 8 };

int multipath_trace_test_one()
{
    uint64_t simulated_time = 0;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    int ret = tls_api_init_ctx(&test_ctx, PICOQUIC_INTERNAL_TEST_VERSION_1, PICOQUIC_TEST_SNI, PICOQUIC_TEST_ALPN, &simulated_time, NULL, NULL, 0, 1, 0);
    
    picoquic_connection_id_t cnxfn_data_client = { {1, 1, 1, 1, 1, 1, 1, 1}, 8 };
    picoquic_connection_id_t cnxfn_data_server = { {2, 2, 2, 2, 2, 2, 2, 2}, 8 };
    uint8_t reset_seed_client[PICOQUIC_RESET_SECRET_SIZE] = { 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25 };
    uint8_t reset_seed_server[PICOQUIC_RESET_SECRET_SIZE] = { 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35 };
    picoquic_tp_t server_parameters;
    picoquic_tp_t client_parameters;
    uint64_t loss_mask = 0;
    
    if (ret == 0 && test_ctx == NULL) {
        ret = -1;
    }

    (void)picoquic_file_delete(MULTIPATH_TRACE_BIN, NULL);

    /* Set the logging policy on the server side, to store data in the
     * current working directory, and run a basic test scenario */
    if (ret == 0) {
        picoquic_set_binlog(test_ctx->qserver, ".");
        (void)picoquic_set_default_spinbit_policy(test_ctx->qserver, picoquic_spinbit_on);
        (void)picoquic_set_default_spinbit_policy(test_ctx->qclient, picoquic_spinbit_on);
        picoquic_set_default_lossbit_policy(test_ctx->qserver, picoquic_lossbit_send_receive);
        picoquic_set_default_lossbit_policy(test_ctx->qclient, picoquic_lossbit_send_receive);
        test_ctx->qserver->cnx_id_callback_ctx = (void*)&cnxfn_data_server;
        test_ctx->qserver->cnx_id_callback_fn = qlog_trace_cid_fn;
        test_ctx->qclient->cnx_id_callback_ctx = (void*)&cnxfn_data_client;
        test_ctx->qclient->cnx_id_callback_fn = qlog_trace_cid_fn;
        memcpy(test_ctx->qclient->reset_seed, reset_seed_client, PICOQUIC_RESET_SECRET_SIZE);
        memcpy(test_ctx->qserver->reset_seed, reset_seed_server, PICOQUIC_RESET_SECRET_SIZE);
        test_ctx->qserver->use_constant_challenges = 1;
        test_ctx->qclient->use_constant_challenges = 1;
        /* Fix the buffer sizes in the simulation */
        test_ctx->c_to_s_link->queue_delay_max = 2 * test_ctx->c_to_s_link->microsec_latency;
        test_ctx->s_to_c_link->queue_delay_max = 2 * test_ctx->s_to_c_link->microsec_latency;
        /* Set the multipath option at both client and server */
        multipath_init_params(&server_parameters, 1);
        picoquic_set_default_tp(test_ctx->qserver, &server_parameters);
        multipath_init_params(&client_parameters, 1);
        picoquic_set_default_tp(test_ctx->qclient, &server_parameters);
        test_ctx->qclient->use_predictable_random = 1;
        test_ctx->qserver->use_predictable_random = 1;

        /* Force ciphersuite to AES128, so Client Hello has a constant format */
        if (picoquic_set_cipher_suite(test_ctx->qclient, PICOQUIC_AES_128_GCM_SHA256) != 0) {
            DBG_PRINTF("Could not set ciphersuite to 0x%04x", PICOQUIC_AES_128_GCM_SHA256);
        }
        if (picoquic_set_key_exchange(test_ctx->qclient, PICOQUIC_GROUP_SECP256R1) != 0) {
            DBG_PRINTF("Could not set key exchange to %d", PICOQUIC_GROUP_SECP256R1);
        }
        /* Delete the old connection */
        picoquic_delete_cnx(test_ctx->cnx_client);
        /* Reset the uniform random test */
        picoquic_public_random_seed_64(RANDOM_PUBLIC_TEST_SEED, 1);
        /* re-create a client connection, this time picking up the required connection ID */
        test_ctx->cnx_client = picoquic_create_cnx(test_ctx->qclient, qlog_multipath_initial_cid, picoquic_null_connection_id,
            (struct sockaddr*) & test_ctx->server_addr, 0,
            PICOQUIC_INTERNAL_TEST_VERSION_1, PICOQUIC_TEST_SNI, PICOQUIC_TEST_ALPN, 1);
        if (test_ctx->cnx_client == NULL) {
            DBG_PRINTF("%s", "Could not create the new client connection");
            ret = -1;
        }
        else {
            /* Initialize the client connection */
            picoquic_start_client_cnx(test_ctx->cnx_client);
        }
    }

    /* establish the connection */
    if (ret == 0) {
        ret = tls_api_connection_loop(test_ctx, &loss_mask, 2 * test_ctx->s_to_c_link->microsec_latency, &simulated_time);
    }

    /* wait until the client (and thus the server) is ready */
    if (ret == 0) {
        ret = wait_client_connection_ready(test_ctx, &simulated_time);
    }

    /* Prepare to send data */
    if (ret == 0) {
        ret = test_api_init_send_recv_scenario(test_ctx, test_scenario_multipath_qlog, sizeof(test_scenario_multipath_qlog));

        if (ret != 0)
        {
            DBG_PRINTF("Init send receive scenario returns %d\n", ret);
        }
    }

    /* Add the multipath links and initiate the migration */
    if (ret == 0) {
        ret = multipath_test_add_links(test_ctx, 0);
    }

    if (ret == 0) {
        ret = picoquic_probe_new_path(test_ctx->cnx_client, (struct sockaddr*) & test_ctx->server_addr,
            (struct sockaddr*) & test_ctx->client_addr_2, simulated_time);
    }

    /* Check that the two paths are established */
    if (ret == 0) {
        ret = wait_multipath_ready(test_ctx, &simulated_time);
    }

    /* Perform a final data sending loop, this time to completion  */
    if (ret == 0) {
        ret = tls_api_data_sending_loop(test_ctx, &loss_mask, &simulated_time, 0);

        if (ret != 0)
        {
            DBG_PRINTF("Data sending loop returns %d\n", ret);
        }
    }

    /* Check that the transmission succeeded */
    if (ret == 0) {
        ret = tls_api_one_scenario_body_verify(test_ctx, &simulated_time, 2000000);
    }

    /* Add a gratuitous bad packet to test "packet dropped" log */
    if (ret == 0 && test_ctx->cnx_server != NULL) {
        uint8_t p[256];

        memset(p, 0, sizeof(p));
        memcpy(p + 1, test_ctx->cnx_server->path[0]->p_local_cnxid->cnx_id.id, test_ctx->cnx_server->path[0]->p_local_cnxid->cnx_id.id_len);
        p[0] |= 64;
        (void)picoquic_incoming_packet(test_ctx->qserver, p, sizeof(p), (struct sockaddr*) & test_ctx->cnx_server->path[0]->peer_addr,
            (struct sockaddr*) & test_ctx->cnx_server->path[0]->local_addr, 0, test_ctx->recv_ecn_server, simulated_time);
    }

    /* Delete the context, which will close the log file. */
    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
    }

    return ret;
}

int multipath_qlog_test()
{
    int ret = 0;
    (void)picoquic_file_delete(MULTIPATH_QLOG, NULL);

    ret = multipath_trace_test_one();

    /* Create a QLOG file from the .log file */
    if (ret == 0) {
        uint64_t log_time = 0;
        uint16_t flags;

        FILE* f_binlog = picoquic_open_cc_log_file_for_read(MULTIPATH_TRACE_BIN, &flags, &log_time);
        if (f_binlog == NULL) {
            ret = -1;
        }
        else {
            ret = qlog_convert(&qlog_multipath_initial_cid, f_binlog, MULTIPATH_TRACE_BIN, 
                MULTIPATH_QLOG, NULL, flags);
            picoquic_file_close(f_binlog);
        }
    }

    /* compare the log file to the expected value */
    if (ret == 0)
    {
        char qlog_trace_test_ref[512];

        ret = picoquic_get_input_path(qlog_trace_test_ref, sizeof(qlog_trace_test_ref),
            picoquic_solution_dir, MULTIPATH_QLOG_REF);

        if (ret != 0) {
            DBG_PRINTF("%s", "Cannot set the qlog trace test ref file name.\n");
        }
        else {
            ret = picoquic_test_compare_text_files(MULTIPATH_QLOG, qlog_trace_test_ref);
        }
    }

    return ret;
}

int multipath_tunnel_test()
{
    uint64_t max_completion_microsec = 12000000;

    return multipath_test_one(max_completion_microsec, multipath_test_tunnel);
}

/* 
 * TODO: Unit test of path selection.
 * The input to path selections include the state of the path,
 * the status set by the peer, the presence of losses, etc.
 * Each test set up a connection context and two path contexts,
 * with stated values for the key variables, then verify that
 * the path selection is as expected.
 * 
 * Key values include:
 * cnx->path[i]->status_set_by_peer
 * cnx->path[i]->path_is_demoted
 * cnx->path[i]->challenge_failed (leads to demotion)
 * cnx->path[i]->response_required (set challenge path)
 * cnx->path[i]->challenge_verified (and next challenge time)
 * cnx->path[i]->challenge_repeat_count
 * cnx->path[i]->nb_retransmit
 * cnx->path[i]->rtt_min
 * picoquic_is_sending_authorized_by_pacing
 * affinity path for the next stream, or is_datagram_ready per path/cnx
 * cnx->path[i]->bytes_in_transit < cnx->path[i]->cwin, cnx->quic->cwin_max
 * then the selection:
 * 1) challenge path;
 * 2) if is_ack_needed, min rtt path for ACK
 * 3) affinity_path, if cwin_ok
 * 4) data path, if cwin ok
 * 5) data path with pacing OK
 * 6) path 0, after setting the timers.
 * 
 * TODO: break that into parts that can be verified!
 */
