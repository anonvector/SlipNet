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

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "picoquic_internal.h"
#include "picoquic_utils.h"
#include "picoquictest_internal.h"
#include "picoquic.h"

/* Verify that the getter/setter functions work as expected 
 */

int getter_test()
{
    /* Create a connection context so we can test the various API */
    uint64_t simulated_time = 0;
    uint64_t loss_mask = 0;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    picoquic_cnx_t* cnx = NULL;
    picoquic_cnx_t* cnx_s = NULL;
    picoquic_connection_id_t initial_cid = { {0x9e, 0x77, 0xe8, 0, 0, 0, 0, 0}, 8 };
    int ret = tls_api_init_ctx_ex2(&test_ctx, PICOQUIC_INTERNAL_TEST_VERSION_1, PICOQUIC_TEST_SNI, PICOQUIC_TEST_ALPN,
        &simulated_time, NULL, NULL,
        0, 1, 0, &initial_cid, 8, 0, 0, 0);

    if (ret == 0) {
        if (picoquic_set_default_connection_id_length(test_ctx->qserver, (uint8_t)255) != PICOQUIC_ERROR_CNXID_CHECK ||
            picoquic_set_default_connection_id_length(test_ctx->qclient, (uint8_t)5) != PICOQUIC_ERROR_CANNOT_CHANGE_ACTIVE_CONTEXT) {
            ret = -1;
        }
    }

    if (ret == 0) {
        if (picoquic_get_default_connection_id_ttl(test_ctx->qserver) != test_ctx->qserver->local_cnxid_ttl) {
            ret = -1;
        }
    }

    if (ret == 0) {
        const picoquic_tp_t* tp = picoquic_get_default_tp(test_ctx->qserver);
        if (tp != &test_ctx->qserver->default_tp) {
            ret = -1;
        }
    }

    if (ret == 0) {
        uint64_t old_max = test_ctx->qserver->cwin_max;
        picoquic_set_cwin_max(test_ctx->qserver, 0);
        if (test_ctx->qserver->cwin_max != UINT64_MAX) {
            ret = -1;
        }
        test_ctx->qserver->cwin_max = old_max;
    }

    if (ret == 0) {
        int partial_match = 0;
        int path_id = picoquic_find_path_by_address(test_ctx->cnx_client, NULL,
            (struct sockaddr*)&test_ctx->cnx_client->path[0]->peer_addr, &partial_match);
        if (path_id != 0 || partial_match == 0) {
            ret = -1;
        }
    }

    if (ret == 0) {
        ret = picoquic_set_local_addr(test_ctx->cnx_client, (struct sockaddr*) &test_ctx->client_addr);
        if (ret == 0 && picoquic_set_local_addr(test_ctx->cnx_client, (struct sockaddr*)&test_ctx->client_addr) == 0) {
            /* Second call should fail because the address is already set */
            ret = -1;
        }
        memset(&test_ctx->cnx_client->path[0]->local_addr, 0, sizeof(struct sockaddr_storage));
    }

    if (ret == 0) {
        uint8_t mf[] = { picoquic_frame_type_max_streams_bidir, 0x41, 0 };
        cnx = test_ctx->cnx_client;
        if (picoquic_queue_misc_frame(cnx, mf, SIZE_MAX, 0, picoquic_packet_context_initial) == 0) {
            ret = -1;
        }
        else if (picoquic_queue_misc_frame(cnx, mf, sizeof(mf), 0, picoquic_packet_context_initial) != 0) {
            ret = -1;
        }
        else {
            picoquic_purge_misc_frames_after_ready(cnx);
            if (cnx->first_misc_frame != NULL) {
                ret = -1;
            }
        }
        if (ret == 0) {
            if (picoquic_queue_misc_frame(cnx, mf, sizeof(mf), 0, picoquic_packet_context_initial) != 0 ||
                picoquic_queue_misc_frame(cnx, mf, sizeof(mf), 0, picoquic_packet_context_initial) != 0) {
                ret = -1;
            }
            else {
                picoquic_delete_misc_or_dg(&cnx->first_misc_frame, &cnx->last_misc_frame, cnx->last_misc_frame);
                if (cnx->first_misc_frame == NULL || cnx->first_misc_frame->next_misc_frame != NULL) {
                    ret = -1;
                }
                picoquic_purge_misc_frames_after_ready(cnx);
            }
        }
    }

    /* Activate a connection so all data are properly initialized */
    if (ret == 0) {
        ret = picoquic_start_client_cnx(test_ctx->cnx_client);
    }
    if (ret == 0) {
        ret = tls_api_connection_loop(test_ctx, &loss_mask, 0, &simulated_time);
    }
    if (ret == 0) {
        cnx_s = test_ctx->cnx_server;
    }
    /* Test a series of getter interfaces */

    if (ret == 0 &&
        picoquic_get_local_if_index(cnx) != cnx->path[0]->if_index_dest) {
        ret = -1;
    }

    if (ret == 0) {
        picoquic_connection_id_t cid = picoquic_get_local_cnxid(cnx);

        if (cid.id_len != cnx->path[0]->p_local_cnxid->cnx_id.id_len ||
            memcmp(cid.id, cnx->path[0]->p_local_cnxid->cnx_id.id, cid.id_len) != 0) {
            ret = -1;
        }
    }

    if (ret == 0) {
        picoquic_connection_id_t cid = picoquic_get_remote_cnxid(cnx);

        if (cid.id_len != cnx->path[0]->p_remote_cnxid->cnx_id.id_len ||
            memcmp(cid.id, cnx->path[0]->p_remote_cnxid->cnx_id.id, cid.id_len) != 0) {
            ret = -1;
        }
    }

    if (ret == 0) {
        picoquic_connection_id_t cid = picoquic_get_initial_cnxid(cnx);

        if (cid.id_len != cnx->initial_cnxid.id_len ||
            memcmp(cid.id, cnx->initial_cnxid.id, cid.id_len) != 0) {
            ret = -1;
        }
    }

    if (ret == 0) {
        picoquic_connection_id_t cid = picoquic_get_client_cnxid(cnx);
        if (cid.id_len != cnx->path[0]->p_local_cnxid->cnx_id.id_len ||
            memcmp(cid.id, cnx->path[0]->p_local_cnxid->cnx_id.id, cid.id_len) != 0) {
            ret = -1;
        }
        else {
            picoquic_connection_id_t cid_s = picoquic_get_client_cnxid(cnx_s);
            if (cid.id_len != cid_s.id_len ||
                memcmp(cid.id, cid_s.id, cid.id_len) != 0) {
                ret = -1;
            }
        }
    }

    if (ret == 0) {
        picoquic_connection_id_t cid = picoquic_get_server_cnxid(cnx);
        if (cid.id_len != cnx->path[0]->p_remote_cnxid->cnx_id.id_len ||
            memcmp(cid.id, cnx->path[0]->p_remote_cnxid->cnx_id.id, cid.id_len) != 0) {
            ret = -1;
        }
        else {
            picoquic_connection_id_t cid_s = picoquic_get_server_cnxid(cnx_s);
            if (cid.id_len != cid_s.id_len ||
                memcmp(cid.id, cid_s.id, cid.id_len) != 0) {
                ret = -1;
            }
        }
    }

    if (ret == 0) {
        uint32_t r_padding_multiple = 256;
        uint32_t r_padding_minsize = 55;
        uint32_t padding_multiple = 0;
        uint32_t padding_minsize = 0;

        picoquic_cnx_set_padding_policy(cnx, r_padding_multiple, r_padding_minsize);
        picoquic_cnx_get_padding_policy(cnx, &padding_multiple, &padding_minsize);
        if (padding_multiple != r_padding_multiple ||
            padding_minsize != r_padding_minsize) {
            ret = -1;
        }
    }

    if (ret == 0) {
        picoquic_spinbit_version_enum spin = picoquic_spinbit_random;
        picoquic_cnx_set_spinbit_policy(cnx, spin);
        if (cnx->spin_policy != spin) {
            ret = -1;
        }
    }

    if (ret == 0) {
        if (picoquic_is_sslkeylog_enabled(test_ctx->qclient) != test_ctx->qclient->enable_sslkeylog) {
            ret = -1;
        }
    }

    if (ret == 0) {
        if (!picoquic_is_handshake_error(PICOQUIC_TLS_HANDSHAKE_FAILED) ||
            !picoquic_is_handshake_error(PICOQUIC_TRANSPORT_CRYPTO_ERROR(123)) ||
            picoquic_is_handshake_error(PICOQUIC_TRANSPORT_FRAME_FORMAT_ERROR)) {
            ret = -1;
        }
    }

    if (ret == 0) {
        char const* alg_name[] = {
            "reno", "cubic", "dcubic", "fast", "bbr", "prague", "bbr1", "abracadabra", NULL
        };
        picoquic_congestion_algorithm_t const* alg[] = {
            picoquic_newreno_algorithm, picoquic_cubic_algorithm, picoquic_dcubic_algorithm,
            picoquic_fastcc_algorithm, picoquic_bbr_algorithm, picoquic_prague_algorithm,
            picoquic_bbr1_algorithm, NULL, NULL
        };
        size_t nb_alg = sizeof(alg_name) / sizeof(char const*);

        for (size_t i = 0; i < nb_alg && ret == 0; i++) {
            if (picoquic_get_congestion_algorithm(alg_name[i]) != alg[i]) {
                ret = -1;
            }
        }
    }

    if (ret == 0) {
        picoquic_set_default_congestion_algorithm_by_name(test_ctx->qclient, "dcubic");
        if (test_ctx->qclient->default_congestion_alg != picoquic_dcubic_algorithm) {
            ret = -1;
        }
    }

    if (ret == 0) {
        uint64_t l_timer = 10000000;
        uint64_t r_timer = cnx->path[0]->retransmit_timer;
        cnx->idle_timeout = 0;
        cnx->local_parameters.max_idle_timeout = r_timer / 500;
        picoquic_enable_keep_alive(cnx, 0);
        if (cnx->keep_alive_interval == 0 ||
            cnx->keep_alive_interval >= 3 * cnx->path[0]->retransmit_timer) {
            ret = -1;
        }
        else {
            picoquic_enable_keep_alive(cnx, l_timer);
            if (cnx->keep_alive_interval != l_timer) {
                ret = -1;
            }
            else {
                picoquic_disable_keep_alive(cnx);
                if (cnx->keep_alive_interval != 0) {
                    ret = -1;
                }
            }
        }
    }

    if (ret == 0) {
        uint64_t app_error = 0x12345678abcdefull;
        cnx->remote_application_error = app_error;
        if (picoquic_get_application_error(cnx) != app_error) {
            ret = -1;
        }
        cnx->remote_application_error = 0;
    }

    if (ret == 0) {
        if (picoquic_get_remote_stream_error(cnx, UINT32_MAX) != 0) {
            ret = -1;
        }
        else {
            uint8_t data[] = { 1, 2, 3, 4 };
            ret = picoquic_add_to_stream(cnx, 0, data, sizeof(data), 0);
            if (ret == 0) {
                uint64_t app_error = 0x12345678abcdefull;
                picoquic_stream_head_t* stream = picoquic_find_stream(cnx, 0);
                if (stream == NULL) {
                    ret = -1;
                }
                else {
                    stream->remote_error = app_error;
                    if (picoquic_get_remote_stream_error(cnx, 0) != app_error) {
                        ret = -1;
                    }
                }
            }
        }
    }

    if (ret == 0 &&
        (ret = picoquic_adjust_max_connections(test_ctx->qserver, 4)) == 0) {
        if (test_ctx->qserver->tentative_max_number_connections != 4) {
            ret = -1;
        }
    }

    if (ret == 0 &&
        picoquic_current_number_connections(test_ctx->qserver) != 1) {
        ret = -1;
    }

    if (ret == 0 &&
        picoquic_get_default_crypto_epoch_length(test_ctx->qserver) !=
        test_ctx->qserver->crypto_epoch_length_max) {
        ret = -1;
    }

    if (ret == 0) {
        picoquic_set_crypto_epoch_length(cnx, 0);
        if (cnx->crypto_epoch_length_max != PICOQUIC_DEFAULT_CRYPTO_EPOCH_LENGTH ||
            picoquic_get_crypto_epoch_length(cnx) != PICOQUIC_DEFAULT_CRYPTO_EPOCH_LENGTH) {
            ret = -1;
        }
    }

    if (ret == 0 &&
        picoquic_get_local_cid_length(test_ctx->qserver) !=
        test_ctx->qserver->local_cnxid_length) {
        ret = -1;
    }

    if (ret == 0) {
        picoquic_connection_id_t cid = { { 1, 2, 3}, 3 };
        if (picoquic_is_local_cid(test_ctx->qclient, &cid) ||
            !picoquic_is_local_cid(test_ctx->qclient, &cnx->path[0]->p_local_cnxid->cnx_id)) {
            ret = -1;
        }
    }

    if (ret == 0) {
        uint32_t max_simul_log = 17;
        picoquic_set_max_simultaneous_logs(test_ctx->qserver, max_simul_log);
        if (picoquic_get_max_simultaneous_logs(test_ctx->qserver) != max_simul_log) {
            ret = -1;
        }
    }


    if (ret == 0) {
        uint32_t max_half_open = 17;
        picoquic_set_max_half_open_retry_threshold(test_ctx->qserver, max_half_open);
        if (picoquic_get_max_half_open_retry_threshold(test_ctx->qserver) != max_half_open) {
            ret = -1;
        }
    }

    if (ret == 0 && picoquic_register_cnx_id(test_ctx->qclient, cnx, cnx->path[0]->p_local_cnxid) == 0) {
        /* Should be already registered ! */
        ret = -1;
    }

    if (ret == 0){
        if (cnx->registered_icid_addr.ss_family == 0 &&
            picoquic_register_net_icid(cnx) != 0) {
            ret = -1;
        }
        else if (picoquic_register_net_icid(cnx) == 0) {
            /* Should be already registered ! */
            ret = -1;
        }
    }

    if (ret == 0 && picoquic_get_quic_ctx(NULL) != NULL) {
        ret = -1;
    }

    if (ret == 0) {
        uint64_t wake_time = picoquic_get_next_wake_time(test_ctx->qclient, UINT64_MAX);

        if (wake_time > 2 && picoquic_get_earliest_cnx_to_wake(test_ctx->qclient, wake_time / 2) != NULL) {
            ret = -1;
        }
    }

    if (ret == 0) {
        int64_t delay = 1000;
        uint64_t test_time = cnx->next_wake_time - delay;
        int64_t sooner = delay / 2;

        if (picoquic_get_wake_delay(cnx, test_time, INT64_MAX) != delay) {
            ret = -1;
        }
        else if (picoquic_get_wake_delay(cnx, test_time, sooner) != sooner) {
            ret = -1;
        }
    }

    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }
    return ret;
}
