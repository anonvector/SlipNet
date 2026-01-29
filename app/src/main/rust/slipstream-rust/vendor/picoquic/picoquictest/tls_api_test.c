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

#include "picoquic_internal.h"
#include "picoquic_utils.h"
#include "picosocks.h"
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

static const uint8_t test_ticket_encrypt_key[32] = {
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31
};

static const uint8_t test_ticket_badcrypt_key[32] = {
    255, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31
};
/*
 * Generic call back function.
 */

static test_api_stream_desc_t test_scenario_oneway[] = {
    { 4, 0, 257, 0 }
};

static test_api_stream_desc_t test_scenario_q_and_r[] = {
    { 4, 0, 257, 2000 }
};

static test_api_stream_desc_t test_scenario_q2_and_r2[] = {
    { 4, 0, 257, 2000 },
    { 8, 0, 531, 11000 }
};

static test_api_stream_desc_t test_scenario_q_and_r5000[] = {
    { 4, 0, 257, 5000 }
};

static test_api_stream_desc_t test_scenario_very_long[] = {
    { 4, 0, 257, 1000000 }
};

static test_api_stream_desc_t test_scenario_quant[] = {
    { 4, 0, 257, 10000 }
};

static test_api_stream_desc_t test_scenario_stop_sending[] = {
    { 4, 0, 257, 1000000 },
    { 8, 4, 531, 11000 }
};

static test_api_stream_desc_t test_scenario_unidir[] = {
    { 2, 0, 4000, 0 },
    { 6, 0, 5000, 0 }
};

static test_api_stream_desc_t test_scenario_mtu_discovery[] = {
    { 2, 0, 100000, 0 }
};

static test_api_stream_desc_t test_scenario_sustained[] = {
    { 4, 0, 257, 1000000 },
    { 8, 4, 257, 1000000 },
    { 12, 8, 257, 1000000 },
    { 16, 12, 257, 1000000 }
};

static test_api_stream_desc_t test_scenario_sustained2[] = {
    { 4, 0, 257, 1000000 },
    { 8, 0, 257, 1000000 },
    { 12, 0, 257, 1000000 },
    { 16, 0, 257, 1000000 },
    { 20, 0, 257, 1000000 },
    { 24, 0, 257, 1000000 },
    { 28, 0, 257, 1000000 },
    { 32, 0, 257, 1000000 }
};

static test_api_stream_desc_t test_scenario_key_rotation[] = {
    { 4, 0, 257, 1000000 },
    { 8, 4, 1000000, 257 }
};

static test_api_stream_desc_t test_scenario_many_streams[] = {
    { 4, 0, 32, 1000 },
    { 8, 0, 32, 1000 },
    { 12, 0, 32, 1000 },
    { 16, 0, 32, 1000 },
    { 20, 0, 32, 350 },
    { 24, 0, 32, 225 },
    { 28, 0, 32, 700 },
    { 32, 0, 32, 32 },
    { 36, 0, 32, 32 },
    { 40, 0, 32, 32 },
    { 44, 0, 32, 32 },
    { 48, 0, 32, 32 }
};

static test_api_stream_desc_t test_scenario_more_streams[] = {
    { 4, 0, 32, 633 },
    { 8, 0, 32, 633 },
    { 12, 0, 32, 633 },
    { 16, 0, 32, 633 },
    { 20, 0, 32, 633 },
    { 24, 0, 32, 633 },
    { 28, 0, 32, 633 },
    { 32, 0, 32, 633 },
    { 36, 0, 32, 633 },
    { 40, 0, 32, 633 },
    { 44, 0, 32, 633 },
    { 48, 0, 32, 633 },
    { 52, 0, 32, 633 },
    { 56, 0, 32, 633 },
    { 60, 0, 32, 633 },
    { 64, 0, 32, 633 },
    { 68, 0, 32, 633 },
    { 72, 0, 32, 633 }
};

static int test_api_init_stream_buffers(size_t len, uint8_t** src_bytes, uint8_t** rcv_bytes)
{
    int ret = 0;

    *src_bytes = (uint8_t*)malloc(len);
    *rcv_bytes = (uint8_t*)malloc(len);

    if (*src_bytes != NULL && *rcv_bytes != NULL) {
        memset(*rcv_bytes, 0, len);

        for (size_t i = 0; i < len; i++) {
            (*src_bytes)[i] = (uint8_t)(i);
        }
    } else {
        ret = -1;

        if (*src_bytes != NULL) {
            free(*src_bytes);
            *src_bytes = NULL;
        }

        if (*rcv_bytes != NULL) {
            free(*rcv_bytes);
            *rcv_bytes = NULL;
        }
    }

    return ret;
}

static int test_api_init_test_stream(test_api_stream_t* test_stream,
    uint64_t stream_id, uint64_t previous_stream_id, size_t q_len, size_t r_len)
{
    int ret = 0;

    memset(test_stream, 0, sizeof(test_api_stream_t));

    if (q_len != 0) {
        ret = test_api_init_stream_buffers(q_len, &test_stream->q_src, &test_stream->q_rcv);
        if (ret == 0) {
            test_stream->q_len = q_len;
        }
    }

    if (ret == 0 && r_len != 0) {
        ret = test_api_init_stream_buffers(r_len, &test_stream->r_src, &test_stream->r_rcv);
        if (ret == 0) {
            test_stream->r_len = r_len;
        }
    }

    if (ret == 0) {
        test_stream->previous_stream_id = previous_stream_id;
        test_stream->stream_id = stream_id;
    }

    return ret;
}

static void test_api_delete_test_stream(test_api_stream_t* test_stream)
{
    if (test_stream->q_src != NULL) {
        free(test_stream->q_src);
    }

    if (test_stream->q_rcv != NULL) {
        free(test_stream->q_rcv);
    }

    if (test_stream->r_src != NULL) {
        free(test_stream->r_src);
    }

    if (test_stream->r_rcv != NULL) {
        free(test_stream->r_rcv);
    }

    while (test_stream->first_direct_hole != NULL) {
        test_api_stream_hole_t* deleted = test_stream->first_direct_hole;
        test_stream->first_direct_hole = test_stream->first_direct_hole->next_hole;
        free(deleted);
    }

    memset(test_stream, 0, sizeof(test_api_stream_t));
}

void test_api_delete_test_streams(picoquic_test_tls_api_ctx_t* test_ctx)
{
    for (size_t i = 0; i < test_ctx->nb_test_streams; i++) {
        test_api_delete_test_stream(&test_ctx->test_stream[i]);
    }
    test_ctx->nb_test_streams = 0;
}

static void test_api_receive_stream_data(
    const uint8_t* bytes, size_t length, picoquic_call_back_event_t fin_or_event,
    uint8_t* buffer, size_t max_len, const uint8_t* reference, size_t* nb_received,
    picoquic_call_back_event_t* received, int* error_detected)
{
    if (bytes != NULL) {
        if (*nb_received + length > max_len) {
            *error_detected |= test_api_fail_recv_larger_than_sent;
        }
        else {
            memcpy(buffer + *nb_received, bytes, length);

            if (memcmp(reference + *nb_received, bytes, length) != 0) {
                *error_detected |= test_api_fail_data_does_not_match;
            }
        }
    }

    *nb_received += length;

    if (fin_or_event != picoquic_callback_stream_data) {
        if (*received != picoquic_callback_stream_data) {
            *error_detected |= test_api_fail_fin_received_twice;
        }

        *received = fin_or_event;
    }
}

static int test_api_stream0_prepare(picoquic_cnx_t* cnx, picoquic_test_tls_api_ctx_t* ctx, uint8_t * context, size_t space)
{
    int ret = -1;

    if (ctx->stream0_test_option == 3 && ctx->stream0_sent > 5000) {
        ret = 0;
        ctx->stream0_test_option = 1;
    }
    else if (ctx->stream0_sent < ctx->stream0_target) {
        uint8_t * buffer;
        size_t available = ctx->stream0_target - ctx->stream0_sent;
        int is_fin = 1;

        if (ctx->stream0_test_option == 4 && ctx->stream0_sent > 5000) {
            available = 0;
            ctx->stream0_test_option = 1;
        } else if (available > space) {
            available = space;
            
            if (ctx->stream0_test_option == 1 && space > 1) {
                available--;
            }
            is_fin = 0;
        }
        else {
            if (ctx->stream0_test_option == 2) {
                is_fin = 0;
            }
        }

        buffer = picoquic_provide_stream_data_buffer(context, available, is_fin, !is_fin);
        if (buffer != NULL) {
            memset(buffer, 0xA5, available);
            ctx->stream0_sent += available;
            ret = 0;
        }
    }
    else if (ctx->stream0_test_option == 2 && ctx->stream0_sent == ctx->stream0_target) {
        (void)picoquic_provide_stream_data_buffer(context, 0, 1, 0);
        ret = 0;
    }

    return ret;
}

static int tls_api_inject_packet(picoquic_test_tls_api_ctx_t* test_ctx, int from_client,
    picoquic_epoch_enum epoch, const uint8_t* payload, size_t p_length, int path_id, uint64_t current_time)
{
    int ret = 0;
    /* Identify the connection */
    picoquic_cnx_t* cnx = (from_client) ? test_ctx->cnx_client : test_ctx->cnx_server;
    picoquic_path_t* path_x = cnx->path[path_id];
    /* Prepare the creation of cleartext and sim packet */
    picoquic_packet_t* packet = picoquic_create_packet(cnx->quic);
    picoquictest_sim_packet_t* sim_packet = picoquictest_sim_link_create_packet();

    if (packet == NULL || sim_packet == NULL) {
        ret = -1;
        if (packet != NULL) {
            picoquic_recycle_packet(cnx->quic, packet);
        }
        if (sim_packet != NULL) {
            free(sim_packet);
        }
    }
    else {
        picoquic_packet_type_enum packet_type;
        picoquic_packet_context_enum pc;
        picoquic_packet_context_t* pkt_ctx;
        size_t length = 0;
        size_t header_length;
        size_t checksum_overhead = picoquic_get_checksum_length(cnx, epoch);
        switch (epoch) {
        case 0:
            packet_type = picoquic_packet_initial;
            pc = picoquic_packet_context_initial;
            break;
        case 1:
            packet_type = picoquic_packet_0rtt_protected;
            pc = picoquic_packet_context_application;
            break;
        case 2:
            packet_type = picoquic_packet_handshake;
            pc = picoquic_packet_context_handshake;
            break;
        case 3:
        default:
            packet_type = picoquic_packet_1rtt_protected;
            pc = picoquic_packet_context_application;
            break;
        }
        pkt_ctx = &cnx->pkt_ctx[pc];
        if (packet_type == picoquic_packet_1rtt_protected && cnx->is_multipath_enabled) {
            pkt_ctx = &path_x->pkt_ctx;
        }

        header_length = picoquic_predict_packet_header_length(cnx, packet_type, pkt_ctx);
        memcpy(packet->bytes + header_length, payload, p_length);
        length = header_length + p_length;

        packet->ptype = packet_type;
        packet->offset = header_length;
        packet->sequence_number = pkt_ctx->send_sequence;
        packet->send_time = current_time;
        packet->send_path = path_x;
        packet->pc = pc;
        packet->length = length;

        picoquic_finalize_and_protect_packet(cnx, packet, 0, length, header_length, checksum_overhead,
            &sim_packet->length, sim_packet->bytes, sizeof(sim_packet->bytes),
            path_x, current_time);
        /* Forward on selected link */
        picoquictest_sim_link_submit((from_client) ? test_ctx->c_to_s_link : test_ctx->s_to_c_link, sim_packet, current_time);
    }

    return ret;
}

int test_api_queue_initial_queries(picoquic_test_tls_api_ctx_t* test_ctx, uint64_t stream_id)
{
    int ret = 0;
    int more_stream = 0;

    for (size_t i = 0; ret == 0 && i < test_ctx->nb_test_streams; i++) {
        if (test_ctx->test_stream[i].previous_stream_id == stream_id) {
            picoquic_cnx_t* cnx = NULL;

            cnx = IS_CLIENT_STREAM_ID(test_ctx->test_stream[i].stream_id) ? test_ctx->cnx_client : test_ctx->cnx_server;

            ret = picoquic_add_to_stream(cnx, test_ctx->test_stream[i].stream_id,
                test_ctx->test_stream[i].q_src,
                test_ctx->test_stream[i].q_len, 1);

            if (ret == 0) {
                test_ctx->test_stream[i].q_sent = 1;
                more_stream = 1;
            }
        }
    }

    if (test_ctx->stream0_target > 0) {
        ret = picoquic_mark_active_stream(test_ctx->cnx_client, 0, 1, NULL);
    }

    /* TODO: check whether the test is actually finished */
    if (!more_stream) {
        for (size_t i = 0; ret == 0 && i < test_ctx->nb_test_streams; i++) {
            if (test_ctx->test_stream[i].r_received == 0) {
                more_stream = 1;
                break;
            }
        }
    }

    if (more_stream == 0) {
        test_ctx->streams_finished = 1;
        if (test_ctx->stream0_received >= test_ctx->stream0_target) {
            test_ctx->test_finished = 1;
        }
        else {
            test_ctx->test_finished = 0;
        }
    } else {
        test_ctx->test_finished = 0;
        test_ctx->streams_finished = 0;
    }

    return ret;
}

static int test_api_direct_receive_callback(picoquic_cnx_t* cnx,
    uint64_t stream_id, int fin, const uint8_t* bytes, uint64_t offset, size_t length, void* direct_receive_ctx)
{
    int ret = 0;
    test_api_callback_t* cb_ctx = (test_api_callback_t*)direct_receive_ctx;
    size_t stream_index;
    picoquic_test_tls_api_ctx_t* ctx = NULL;

    if (cb_ctx->client_mode) {
        ctx = (picoquic_test_tls_api_ctx_t*)(((char*)direct_receive_ctx) - offsetof(struct st_picoquic_test_tls_api_ctx_t, client_callback));
    }
    else {
        /* Only testing the direct receive on the client side */
        ret = -1;
    }

    if (ret == 0) {
        for (stream_index = 0; stream_index < ctx->nb_test_streams; stream_index++) {
            if (ctx->test_stream[stream_index].stream_id == stream_id) {
                break;
            }
        }

        if (stream_index >= ctx->nb_test_streams) {
            cb_ctx->error_detected |= test_api_fail_data_on_unknown_stream;
            ret = -1;
        }
        else if (offset + length > ctx->test_stream[stream_index].r_len) {
            cb_ctx->error_detected |= test_api_fail_data_on_unknown_stream;
            ret = -1;
        }
        else {
            uint64_t last_offset = offset + length;
            memcpy(ctx->test_stream[stream_index].r_rcv, bytes, length);

            if (memcmp(ctx->test_stream[stream_index].r_src + (size_t)offset, bytes, length) != 0)
            {
                cb_ctx->error_detected |= test_api_fail_data_does_not_match;
                ret = -1;
            }
            else if (offset > ctx->test_stream[stream_index].next_direct_offset) {
                /* Need to create a hole. They are ordered from lowest to highest offset */
                test_api_stream_hole_t* hole = ctx->test_stream[stream_index].first_direct_hole;
                test_api_stream_hole_t* previous_hole = NULL;
                test_api_stream_hole_t* new_hole = (test_api_stream_hole_t*)malloc(sizeof(test_api_stream_hole_t));
                if (new_hole == NULL) {
                    ret = PICOQUIC_ERROR_MEMORY;
                }
                else {
                    while (hole != NULL) {
                        previous_hole = ctx->test_stream[stream_index].first_direct_hole;
                        hole = previous_hole->next_hole;
                    }
                    new_hole->offset = ctx->test_stream[stream_index].next_direct_offset;
                    new_hole->last_offset = offset;
                    new_hole->next_hole = NULL;
                    if (previous_hole == NULL) {
                        ctx->test_stream[stream_index].first_direct_hole = new_hole;
                    }
                    else {
                        previous_hole->next_hole = new_hole;
                    }
                    ctx->test_stream[stream_index].r_recv_nb += length;
                    ctx->test_stream[stream_index].next_direct_offset = last_offset;
                }
            }
            else {
                test_api_stream_hole_t* hole = ctx->test_stream[stream_index].first_direct_hole;
                test_api_stream_hole_t* previous_hole = NULL;

                if (last_offset > ctx->test_stream[stream_index].next_direct_offset) {
                    /* At least some of the segment comes after the current max offset */
                    uint64_t new_direct_offset = last_offset;
                    ctx->test_stream[stream_index].r_recv_nb += (size_t)(last_offset - ctx->test_stream[stream_index].next_direct_offset);
                    last_offset = ctx->test_stream[stream_index].next_direct_offset;
                    ctx->test_stream[stream_index].next_direct_offset = new_direct_offset;
                }

                while (hole != NULL && offset < last_offset) {
                    test_api_stream_hole_t* next_hole = hole->next_hole;
                    if (last_offset <= hole->offset) {
                        /* Segment is entirely covered by previously received data */
                        break;
                    }
                    else if (offset <= hole->offset) {
                        /* Beginning of segment already received */
                        offset = hole->offset;
                    }

                    if (offset <= hole->last_offset) {
                        if (last_offset >= hole->last_offset) {
                            /* segment extends past the end of the hole */
                            uint64_t new_offset = hole->last_offset;
                            ctx->test_stream[stream_index].r_recv_nb += (size_t)(hole->last_offset - offset);
                            hole->last_offset = offset;
                            offset = new_offset;
                            if (hole->last_offset == hole->offset) {
                                /* Hole has been filled */
                                if (previous_hole == NULL) {
                                    ctx->test_stream[stream_index].first_direct_hole = next_hole;
                                }
                                else {
                                    previous_hole->next_hole = next_hole;
                                }
                                free(hole);
                            }
                            else {
                                previous_hole = hole;
                            }
                        }
                        else if (offset == hole->offset) {
                            /* segment starts at begining of hole */
                            ctx->test_stream[stream_index].r_recv_nb += (size_t)(last_offset - offset);
                            offset = last_offset;
                            hole->offset = last_offset;
                            previous_hole = hole;
                        }
                        else {
                            /* overlap, need a new hole */
                            test_api_stream_hole_t* new_hole = (test_api_stream_hole_t*)malloc(sizeof(test_api_stream_hole_t));
                            if (new_hole == NULL) {
                                ret = PICOQUIC_ERROR_MEMORY;
                            }
                            else {
                                new_hole->offset = last_offset;
                                new_hole->last_offset = hole->last_offset;
                                new_hole->next_hole = hole->next_hole;
                                hole->last_offset = offset;
                                hole->next_hole = new_hole;
                                ctx->test_stream[stream_index].r_recv_nb += (size_t)(last_offset - offset);
                            }
                            break;
                        }
                    }
                    else {
                        previous_hole = hole;
                    }

                    hole = next_hole;
                }
            }

            /* If fin received and no hole, mark received and signal fin */
            if (fin && ctx->test_stream[stream_index].direct_fin_received == 0) {
                ctx->test_stream[stream_index].direct_fin_received = fin;
            }

            if (ctx->test_stream[stream_index].first_direct_hole == NULL && ctx->test_stream[stream_index].direct_fin_received) {
                ctx->test_stream[stream_index].r_received = 1;
                ret = PICOQUIC_STREAM_RECEIVE_COMPLETE;

                if (cb_ctx->error_detected == 0) {
                    /* queue the new queries initiated by that stream */
                    if (test_api_queue_initial_queries(ctx, stream_id) != 0) {
                        cb_ctx->error_detected |= test_api_fail_cannot_send_query;
                    }
                }
            }
        }
    }

    return ret;
}

int test_api_callback(picoquic_cnx_t* cnx,
    uint64_t stream_id, uint8_t* bytes, size_t length,
    picoquic_call_back_event_t fin_or_event, void* callback_ctx, void* v_stream_ctx)
{
    /* Need to implement the server sending strategy */
    test_api_callback_t* cb_ctx = (test_api_callback_t*)callback_ctx;
    picoquic_test_tls_api_ctx_t* ctx = NULL;
    size_t stream_index;
    picoquic_call_back_event_t stream_finished = picoquic_callback_stream_data;

    if (fin_or_event == picoquic_callback_close ||
        fin_or_event == picoquic_callback_application_close ||
        fin_or_event == picoquic_callback_almost_ready ||
        fin_or_event == picoquic_callback_ready) {
        /* do nothing in our tests */
        return 0;
    }

    if (cb_ctx->client_mode) {
        ctx = (picoquic_test_tls_api_ctx_t*)(((char*)callback_ctx) - offsetof(struct st_picoquic_test_tls_api_ctx_t, client_callback));
    } else {
        ctx = (picoquic_test_tls_api_ctx_t*)(((char*)callback_ctx) - offsetof(struct st_picoquic_test_tls_api_ctx_t, server_callback));
    }


    if (fin_or_event == picoquic_callback_version_negotiation) {
        if (ctx != NULL) {
            ctx->received_version_negotiation = 1;
        }
        return 0;
    }

    if (fin_or_event == picoquic_callback_stateless_reset) {
        /* take note to validate test */
        ctx->reset_received = 1;
        return 0;
    }

    if (fin_or_event == picoquic_callback_prepare_to_send) {
        if (cb_ctx->client_mode && stream_id == 0) {
            return test_api_stream0_prepare(cnx, ctx, bytes, length);
        } else {
            /* unexpected call */
            return -1;
        }
    }

    if (fin_or_event == picoquic_callback_pacing_changed)
    {
        if (ctx->bw_update != NULL) {
            fprintf(ctx->bw_update, "%" PRIu64 ", %" PRIu64 ", %" PRIu64 ", %" PRIu64 ", %" PRIu64 "\n",
                picoquic_get_quic_time(cnx->quic), stream_id, picoquic_get_pacing_rate(cnx),
                picoquic_get_cwin(cnx), picoquic_get_rtt(cnx));
        }
        return 0;
    }

    if (fin_or_event == picoquic_callback_path_address_observed)
    {
        ctx->nb_address_observed++;
        return 0;
    }

    if (fin_or_event == picoquic_callback_prepare_datagram)
    {
        int ret = -1;
        if (ctx->datagram_send_fn != NULL) {
            ret = ctx->datagram_send_fn(cnx, stream_id, bytes, length, ctx->datagram_ctx);
        }
        return ret;
    } else if (fin_or_event == picoquic_callback_datagram)
    {
        int ret = -1;
        if (ctx->datagram_recv_fn != NULL) {
            ret = ctx->datagram_recv_fn(cnx, stream_id, bytes, length, ctx->datagram_ctx);
        }
        return ret;
    }
    else if (fin_or_event == picoquic_callback_datagram_acked ||
        fin_or_event == picoquic_callback_datagram_lost ||
        fin_or_event == picoquic_callback_datagram_spurious)
    {
        int ret = -1;
        if (ctx->datagram_ack_fn != NULL) {
            ret = ctx->datagram_ack_fn(cnx, fin_or_event,
                bytes, length, stream_id /* encode send_time */, ctx->datagram_ctx);
        }
        return ret;
    }
    else if (fin_or_event == picoquic_callback_path_available ||
        fin_or_event == picoquic_callback_path_suspended ||
        fin_or_event == picoquic_callback_path_deleted ||
        fin_or_event == picoquic_callback_path_quality_changed) {
        int ret = 0;
        if (ctx->path_events != NULL) {
            if (fin_or_event == picoquic_callback_path_quality_changed) {
                uint64_t unique_path_id = stream_id;
                picoquic_path_quality_t quality;
                uint64_t current_time = picoquic_get_quic_time(cnx->quic);

                ret = picoquic_get_path_quality(cnx, unique_path_id, &quality);
                if (ret == 0) {
                    fprintf(ctx->path_events,
                        "%" PRIu64 ", %" PRIu64 ", %d, %" PRIu64 ", %" PRIu64 ", %" PRIu64 ", %" PRIu64 "\n",
                        current_time, stream_id, (int)fin_or_event,
                        quality.pacing_rate, quality.receive_rate_estimate, quality.cwin, quality.rtt);
                }
            }
            else {
                fprintf(ctx->path_events, "%" PRIu64 ", %" PRIu64 ", %d,\n",
                    picoquic_get_quic_time(cnx->quic), stream_id, (int)fin_or_event);
            }
        }
        else if (fin_or_event == picoquic_callback_path_quality_changed &&
            ctx->default_path_update != NULL) {
            picoquic_path_quality_t quality;
            uint64_t current_time = picoquic_get_quic_time(cnx->quic);
            picoquic_get_default_path_quality(cnx, &quality);
            fprintf(ctx->default_path_update,
                "%" PRIu64 ", %" PRIu64 ", %d, %" PRIu64 ", %" PRIu64 ", %" PRIu64 ", %" PRIu64 "\n",
                current_time, stream_id, (int)fin_or_event,
                quality.pacing_rate, quality.receive_rate_estimate, quality.cwin, quality.rtt);
        }
        return ret;
    }

    if (bytes != NULL) {
        if (cb_ctx->client_mode) {
            ctx->sum_data_received_at_client += (int) length;
        } else {
            ctx->sum_data_received_at_server += (int) length;
        }
    }

    if (stream_id == 0 && cb_ctx->client_mode == 0 &&
        (fin_or_event == picoquic_callback_stream_data || fin_or_event == picoquic_callback_stream_fin)) {
        if (bytes == NULL && length != 0) {
            cb_ctx->error_detected = test_api_bad_stream0_data;
        }
        else {
            for (size_t i = 0; i < length; i++) {
                if (bytes[i] != 0xA5) {
                    cb_ctx->error_detected = test_api_bad_stream0_data;
                }
            }
        }
        if (ctx->stream0_received == 0 && length > 0 && ctx->stream0_flow_release) {
            (void)picoquic_open_flow_control(cnx, stream_id, ctx->stream0_target);
        }
        ctx->stream0_received += length;
        if (ctx->streams_finished && ctx->stream0_received >= ctx->stream0_target) {
            ctx->test_finished = 1;
        }
    } else {
        for (stream_index = 0; stream_index < ctx->nb_test_streams; stream_index++) {
            if (ctx->test_stream[stream_index].stream_id == stream_id) {
                break;
            }
        }

        if (stream_index >= ctx->nb_test_streams) {
            cb_ctx->error_detected |= test_api_fail_data_on_unknown_stream;
        }
        else if (fin_or_event == picoquic_callback_stop_sending) {
            /* Respond with a reset, no matter what. Should be smarter later */
            picoquic_reset_stream(cnx, stream_id, 0);
        }
        else if (fin_or_event == picoquic_callback_stream_data || fin_or_event == picoquic_callback_stream_fin || fin_or_event == picoquic_callback_stream_reset) {
            if (IS_CLIENT_STREAM_ID(stream_id)) {
                if (cb_ctx->client_mode) {
                    /* this is a response from the server to a client stream */
                    test_api_receive_stream_data(bytes, length, fin_or_event,
                        ctx->test_stream[stream_index].r_rcv,
                        ctx->test_stream[stream_index].r_len,
                        ctx->test_stream[stream_index].r_src,
                        &ctx->test_stream[stream_index].r_recv_nb,
                        &ctx->test_stream[stream_index].r_received,
                        &cb_ctx->error_detected);

                    stream_finished = fin_or_event;
                }
                else {
                    /* this is a query to a server */
                    test_api_receive_stream_data(bytes, length, fin_or_event,
                        ctx->test_stream[stream_index].q_rcv,
                        ctx->test_stream[stream_index].q_len,
                        ctx->test_stream[stream_index].q_src,
                        &ctx->test_stream[stream_index].q_recv_nb,
                        &ctx->test_stream[stream_index].q_received,
                        &cb_ctx->error_detected);

                    if (fin_or_event != 0) {
                        if (ctx->test_stream[stream_index].r_len == 0 || fin_or_event == picoquic_callback_stream_reset) {
                            ctx->test_stream[stream_index].r_received = 1;
                            stream_finished = fin_or_event;
                        }
                        else if (cb_ctx->error_detected == 0) {
                            /* send a response */
                            if (picoquic_add_to_stream(cnx, stream_id,
                                ctx->test_stream[stream_index].r_src,
                                ctx->test_stream[stream_index].r_len, 1)
                                != 0) {
                                cb_ctx->error_detected |= test_api_fail_cannot_send_response;
                            }
                        }
                    }
                }
            }
            else {
                if (cb_ctx->client_mode) {
                    /* this is a query from the server to the client */
                    test_api_receive_stream_data(bytes, length, fin_or_event,
                        ctx->test_stream[stream_index].q_rcv,
                        ctx->test_stream[stream_index].q_len,
                        ctx->test_stream[stream_index].q_src,
                        &ctx->test_stream[stream_index].q_recv_nb,
                        &ctx->test_stream[stream_index].q_received,
                        &cb_ctx->error_detected);

                    if (fin_or_event != 0) {
                        if (ctx->test_stream[stream_index].r_len == 0 || fin_or_event == picoquic_callback_stream_reset) {
                            ctx->test_stream[stream_index].r_received = 1;
                            stream_finished = fin_or_event;
                        }
                        else if (cb_ctx->error_detected == 0) {
                            /* send a response */
                            if (picoquic_add_to_stream(cnx, stream_id,
                                ctx->test_stream[stream_index].r_src,
                                ctx->test_stream[stream_index].r_len, 1)
                                != 0) {
                                cb_ctx->error_detected |= test_api_fail_cannot_send_response;
                            }
                        }
                    }
                }
                else {
                    /* this is a response to the server */
                    test_api_receive_stream_data(bytes, length, fin_or_event,
                        ctx->test_stream[stream_index].r_rcv,
                        ctx->test_stream[stream_index].r_len,
                        ctx->test_stream[stream_index].r_src,
                        &ctx->test_stream[stream_index].r_recv_nb,
                        &ctx->test_stream[stream_index].r_received,
                        &cb_ctx->error_detected);

                    stream_finished = fin_or_event;
                }
            }
        }
        else {
            cb_ctx->error_detected |= test_api_fail_unexpected_frame;
        }

        if (stream_finished != 0
            && cb_ctx->error_detected == 0) {
            /* queue the new queries initiated by that stream */
            if (test_api_queue_initial_queries(ctx, stream_id) != 0) {
                cb_ctx->error_detected |= test_api_fail_cannot_send_query;
            }
        }
    }

    return 0;
}

int test_api_init_send_recv_scenario(picoquic_test_tls_api_ctx_t* test_ctx,
    test_api_stream_desc_t* stream_desc, size_t size_of_scenarios)
{
    int ret = 0;
    size_t nb_stream_desc = size_of_scenarios / sizeof(test_api_stream_desc_t);

    if (nb_stream_desc > PICOQUIC_TEST_MAX_TEST_STREAMS) {
        ret = -1;
    } else {
        test_ctx->nb_test_streams = nb_stream_desc;
        test_ctx->test_finished = 0;

        for (size_t i = 0; ret == 0 && i < nb_stream_desc; i++) {
            ret = test_api_init_test_stream(&test_ctx->test_stream[i],
                stream_desc[i].stream_id, stream_desc[i].previous_stream_id,
                stream_desc[i].q_len, stream_desc[i].r_len);
        }
    }

    if (ret == 0) {
        ret = test_api_queue_initial_queries(test_ctx, 0);
    }

    return ret;
}

static int verify_transport_extension(picoquic_cnx_t* cnx_client, picoquic_cnx_t* cnx_server)
{
    int ret = 0;

    /* verify that local parameters have a sensible value */
    if (cnx_client->local_parameters.max_idle_timeout == 0 || cnx_client->local_parameters.initial_max_data == 0 || cnx_client->local_parameters.initial_max_stream_data_bidi_local == 0 || cnx_client->local_parameters.max_packet_size == 0) {
        ret = -1;
    } else if (cnx_server->local_parameters.max_idle_timeout == 0 || cnx_server->local_parameters.initial_max_data == 0 || cnx_server->local_parameters.initial_max_stream_data_bidi_remote == 0 || cnx_server->local_parameters.max_packet_size == 0) {
        ret = -1;
    }
    /* Verify that the negotiation completed */
    else if (memcmp(&cnx_client->local_parameters, &cnx_server->remote_parameters,
                 sizeof(picoquic_tp_t))
        != 0) {
        ret = -1;
    } else if (memcmp(&cnx_server->local_parameters, &cnx_client->remote_parameters,
                   sizeof(picoquic_tp_t))
        != 0) {
        ret = -1;
    }

    return ret;
}

static int verify_sni(picoquic_cnx_t* cnx_client, picoquic_cnx_t* cnx_server,
    char const* sni)
{
    int ret = 0;
    char const* client_sni = picoquic_tls_get_sni(cnx_client);
    char const* server_sni = picoquic_tls_get_sni(cnx_server);

    if (sni == NULL) {
        if (cnx_client->sni != NULL) {
            ret = -1;
        } else if (client_sni != NULL) {
            ret = -1;
        } else if (server_sni != NULL) {
            ret = -1;
        }
    } else {
        if (cnx_client->sni == NULL) {
            ret = -1;
        } else if (client_sni == NULL) {
            ret = -1;
        } else if (server_sni == NULL) {
            ret = -1;
        } else if (strcmp(cnx_client->sni, sni) != 0) {
            ret = -1;
        } else if (strcmp(client_sni, sni) != 0) {
            ret = -1;
        } else if (strcmp(server_sni, sni) != 0) {
            ret = -1;
        }
    }

    return ret;
}

static int verify_alpn(picoquic_cnx_t* cnx_client, picoquic_cnx_t* cnx_server,
    char const* alpn)
{
    int ret = 0;
    char const* client_alpn = picoquic_tls_get_negotiated_alpn(cnx_client);
    char const* server_alpn = picoquic_tls_get_negotiated_alpn(cnx_server);

    if (alpn == NULL) {
        if (cnx_client->alpn != NULL) {
            ret = -1;
        } else if (client_alpn != NULL) {
            ret = -1;
        } else if (server_alpn != NULL) {
            ret = -1;
        }
    } else {
        if (cnx_client->alpn == NULL) {
            ret = -1;
        } else if (client_alpn == NULL) {
            ret = -1;
        } else if (server_alpn == NULL) {
            ret = -1;
        } else if (strcmp(cnx_client->alpn, alpn) != 0) {
            ret = -1;
        } else if (strcmp(client_alpn, alpn) != 0) {
            ret = -1;
        } else if (strcmp(server_alpn, alpn) != 0) {
            ret = -1;
        }
    }

    return ret;
}

static int verify_version(picoquic_cnx_t* cnx_client, picoquic_cnx_t* cnx_server)
{
    int ret = 0;

    if (cnx_client->version_index != cnx_server->version_index) {
        ret = -1;
    } else if (cnx_client->version_index < 0 || cnx_client->version_index >= (int)picoquic_nb_supported_versions) {
        ret = -1;
    } else {
        for (size_t i = 0; i < picoquic_nb_supported_versions; i++) {
            if (cnx_client->proposed_version != picoquic_supported_versions[cnx_client->version_index].version && cnx_client->proposed_version == picoquic_supported_versions[i].version) {
                ret = -1;
                break;
            }
        }
    }

    return ret;
}

static void tls_api_endpoint_release(
    picoquic_test_endpoint_t* endpoint)
{
    picoquictest_sim_packet_t* packet = endpoint->first_packet;

    while (packet != NULL) {
        picoquictest_sim_packet_t* to_free = packet;

        packet = packet->next_packet;

        free(to_free);
    }
    endpoint->first_packet = NULL;
    endpoint->last_packet = NULL;
}

void tls_api_delete_ctx(picoquic_test_tls_api_ctx_t* test_ctx)
{
    if (test_ctx->qclient != NULL) {
        picoquic_free(test_ctx->qclient);
    }

    if (test_ctx->qserver != NULL) {
        picoquic_free(test_ctx->qserver);
    }

    for (size_t i = 0; i < test_ctx->nb_test_streams; i++) {
        test_api_delete_test_stream(&test_ctx->test_stream[i]);
    }

    if (test_ctx->c_to_s_link != NULL) {
        picoquictest_sim_link_delete(test_ctx->c_to_s_link);
    }

    if (test_ctx->c_to_s_link_2 != NULL) {
        picoquictest_sim_link_delete(test_ctx->c_to_s_link_2);
    }

    if (test_ctx->s_to_c_link != NULL) {
        picoquictest_sim_link_delete(test_ctx->s_to_c_link);
    }

    if (test_ctx->s_to_c_link_2 != NULL) {
        picoquictest_sim_link_delete(test_ctx->s_to_c_link_2);
    }

    if (test_ctx->send_buffer != NULL) {
        free(test_ctx->send_buffer);
    }

    if (test_ctx->bw_update != NULL) {
        (void)picoquic_file_close(test_ctx->bw_update);
    }

    if (test_ctx->path_events != NULL) {
        (void)picoquic_file_close(test_ctx->path_events);
    }

    if (test_ctx->default_path_update != NULL) {
        (void)picoquic_file_close(test_ctx->default_path_update);
    }

    tls_api_endpoint_release(&test_ctx->client_endpoint);
    tls_api_endpoint_release(&test_ctx->server_endpoint);

    free(test_ctx);
}

int tls_api_init_ctx_ex2(picoquic_test_tls_api_ctx_t** pctx, uint32_t proposed_version,
    char const* sni, char const* alpn, uint64_t* p_simulated_time, 
    char const* ticket_file_name, char const* token_file_name,
    int force_zero_share, int delayed_init, int use_bad_crypt, 
    picoquic_connection_id_t * icid, uint32_t nb_connections, int cid_zero,
    size_t send_buffer_size, int use_ecdsa)
{
    int ret = 0;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    char test_server_cert_file[512];
    char test_server_key_file[512];
    char test_server_cert_store_file[512];

    ret = picoquic_get_input_path(test_server_cert_file, sizeof(test_server_cert_file), picoquic_solution_dir,
        (use_ecdsa)?PICOQUIC_TEST_FILE_SERVER_CERT_ECDSA:PICOQUIC_TEST_FILE_SERVER_CERT);

    if (ret == 0) {
        ret = picoquic_get_input_path(test_server_key_file, sizeof(test_server_key_file), picoquic_solution_dir,
            (use_ecdsa)?PICOQUIC_TEST_FILE_SERVER_KEY_ECDSA:PICOQUIC_TEST_FILE_SERVER_KEY);
    }

    if (ret == 0) {
        ret = picoquic_get_input_path(test_server_cert_store_file, sizeof(test_server_cert_store_file), picoquic_solution_dir,
            PICOQUIC_TEST_FILE_CERT_STORE);
    }

    if (ret != 0) {
        DBG_PRINTF("%s", "Cannot set the cert, key or store file names.\n");
    } else {
        test_ctx = (picoquic_test_tls_api_ctx_t*)
            malloc(sizeof(picoquic_test_tls_api_ctx_t));

        if (test_ctx == NULL) {
            ret = -1;
        } else {
            /* Init to NULL */
            memset(test_ctx, 0, sizeof(picoquic_test_tls_api_ctx_t));
            test_ctx->client_callback.client_mode = 1;

            /* Init of the IP addresses */
            memset(&test_ctx->client_addr, 0, sizeof(struct sockaddr_in));
            test_ctx->client_addr.sin_family = AF_INET;
#ifdef _WINDOWS
            test_ctx->client_addr.sin_addr.S_un.S_addr = htonl(0x0A000002);
#else
            test_ctx->client_addr.sin_addr.s_addr = htonl(0x0A000002);
#endif
            test_ctx->client_addr.sin_port = htons(1234);

            memset(&test_ctx->server_addr, 0, sizeof(struct sockaddr_in));
            test_ctx->server_addr.sin_family = AF_INET;
#ifdef _WINDOWS
            test_ctx->server_addr.sin_addr.S_un.S_addr = htonl(0x0A000001);
#else
            test_ctx->server_addr.sin_addr.s_addr = htonl(0x0A000001);
#endif
            test_ctx->server_addr.sin_port = htons(4321);

            /* Test the creation of the client and server contexts */
            test_ctx->qclient = picoquic_create(8, NULL, NULL, test_server_cert_store_file, NULL, test_api_callback,
                (void*)&test_ctx->client_callback, NULL, NULL, NULL, *p_simulated_time,
                p_simulated_time, ticket_file_name, NULL, 0);

            if (token_file_name != NULL) {
                (void)picoquic_load_token_file(test_ctx->qclient, token_file_name);
            }

            test_ctx->qserver = picoquic_create(nb_connections,
                test_server_cert_file, test_server_key_file, test_server_cert_store_file,
                (alpn == NULL)?PICOQUIC_TEST_ALPN:alpn, test_api_callback, (void*)&test_ctx->server_callback, NULL, NULL, NULL,
                *p_simulated_time, p_simulated_time, NULL,
                (use_bad_crypt == 0) ? test_ticket_encrypt_key : test_ticket_badcrypt_key,
                (use_bad_crypt == 0) ? sizeof(test_ticket_encrypt_key) : sizeof(test_ticket_badcrypt_key));

            if (test_ctx->qclient == NULL || test_ctx->qserver == NULL) {
                ret = -1;
            }
            else if (cid_zero){
                test_ctx->qclient->local_cnxid_length = 0;
            }

            if (ret == 0) {
                /* Do not use randomization by default during tests */
                picoquic_set_random_initial(test_ctx->qclient, 0);
                picoquic_set_random_initial(test_ctx->qserver, 0);
            }

            /* register the links */
            if (ret == 0) {
                test_ctx->c_to_s_link = picoquictest_sim_link_create(0.01, 10000, NULL, 0, 0);
                test_ctx->s_to_c_link = picoquictest_sim_link_create(0.01, 10000, NULL, 0, 0);

                if (test_ctx->c_to_s_link == NULL || test_ctx->s_to_c_link == NULL) {
                    ret = -1;
                }
            }

            if (ret == 0) {
                /* Create the send buffer as requested */
                if (send_buffer_size == 0) {
                    test_ctx->send_buffer_size = PICOQUIC_MAX_PACKET_SIZE;
                }
                else {
                    test_ctx->send_buffer_size = send_buffer_size;
                    test_ctx->use_udp_gso = 1;
                }
                test_ctx->send_buffer = (uint8_t*)malloc(test_ctx->send_buffer_size);
                if (test_ctx->send_buffer == NULL) {
                    ret = -1;
                }
            }

            if (ret == 0) {
                /* Apply the zero share parameter if required */
                if (force_zero_share != 0)
                {
                    test_ctx->qclient->client_zero_share = 1;
                }
                /* Do not use hole insertion by default */
                picoquic_set_optimistic_ack_policy(test_ctx->qclient, 0);
                picoquic_set_optimistic_ack_policy(test_ctx->qserver, 0);

                /* Create a client connection */
                test_ctx->cnx_client = picoquic_create_cnx(test_ctx->qclient,
                    (icid == NULL)? picoquic_null_connection_id: *icid,
                    picoquic_null_connection_id,
                    (struct sockaddr*)&test_ctx->server_addr, *p_simulated_time,
                    proposed_version, sni, alpn, 1);

                if (test_ctx->cnx_client == NULL) {
                    ret = -1;
                }
                else if (delayed_init == 0) {
                    ret = picoquic_start_client_cnx(test_ctx->cnx_client);
                }
            }
        }
    }

    if (ret != 0 && test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }

    *pctx = test_ctx;

    return ret;
}

int tls_api_init_ctx_ex(picoquic_test_tls_api_ctx_t** pctx, uint32_t proposed_version,
    char const* sni, char const* alpn, uint64_t* p_simulated_time,
    char const* ticket_file_name, char const* token_file_name,
    int force_zero_share, int delayed_init, int use_bad_crypt, picoquic_connection_id_t* icid)
{
    return tls_api_init_ctx_ex2(pctx, proposed_version, sni, alpn, p_simulated_time, ticket_file_name, token_file_name,
        force_zero_share, delayed_init, use_bad_crypt, icid, 8, 0, 0, 0);
}

int tls_api_init_ctx(picoquic_test_tls_api_ctx_t** pctx, uint32_t proposed_version,
    char const* sni, char const* alpn, uint64_t* p_simulated_time,
    char const* ticket_file_name, char const* token_file_name,
    int force_zero_share, int delayed_init, int use_bad_crypt)
{
    return tls_api_init_ctx_ex(pctx, proposed_version, sni, alpn, p_simulated_time, ticket_file_name, token_file_name, force_zero_share, delayed_init, use_bad_crypt, NULL);
}

static picoquictest_sim_packet_t* tls_api_one_endpoint_packet_dequeue(
    picoquic_test_endpoint_t* endpoint)
{
    picoquictest_sim_packet_t* packet = endpoint->first_packet;

    if (packet != NULL) {
        if (packet->next_packet == NULL) {
            endpoint->last_packet = NULL;
        }
        endpoint->first_packet = packet->next_packet;
        if (endpoint->queue_size > 0) {
            endpoint->queue_size -= 1;
        }
    }
    return packet;
}

static int tls_api_one_endpoint_dequeue(picoquic_test_endpoint_t *endpoint,
    picoquic_quic_t * quic, uint64_t simulated_time, int * was_active, uint8_t recv_ecn)
{
    int ret = 0;

    /* If there is something to receive, do it now */
    picoquictest_sim_packet_t* packet = tls_api_one_endpoint_packet_dequeue(endpoint);

    if (packet != NULL) {
        if (recv_ecn == 0) {
            recv_ecn = packet->ecn_mark;
        }

        if (packet->length > 16) {
            ret = picoquic_incoming_packet(quic, packet->bytes, (uint32_t)packet->length,
                (struct sockaddr*)&packet->addr_from,
                (struct sockaddr*)&packet->addr_to, 0, recv_ecn, simulated_time);
            *was_active |= 1;

            endpoint->next_time_ready = simulated_time +
                endpoint->incoming_cpu_time;
        }

        if (ret != 0)
        {
            /* useless test, but makes it easier to add a breakpoint under debugger */
            ret = -1;
        }

        free(packet);
    }

    return ret;
}

static void tls_api_one_endpoint_arrival(picoquictest_sim_link_t* sim_link,
    picoquic_test_endpoint_t* endpoint, struct sockaddr * target_addr, int multiple_address, uint64_t simulated_time)
{
    /* Assume time is checked. Dequeue the next packet from the link */
    picoquictest_sim_packet_t* packet = picoquictest_sim_link_dequeue(sim_link, simulated_time);

    /* Check the destination address  before submitting the packet */
    if (packet != NULL && !
        (picoquic_compare_addr(target_addr, (struct sockaddr*) & packet->addr_to) == 0 ||
        (packet->addr_to.ss_family == target_addr->sa_family  && multiple_address))) {
        free(packet);
        packet = NULL;
    }

    if (packet != NULL) {
        /* If there is an incoming packet, queue it now */
        if (endpoint->first_packet == NULL) {
            /* arrival on an empty queue, update the time. */
            if (packet->arrival_time > endpoint->next_time_ready) {
                endpoint->next_time_ready = packet->arrival_time;
            }
            endpoint->queue_size = 1;
            endpoint->first_packet = packet;
            endpoint->last_packet = packet;
            packet->next_packet = NULL;
        }
        else if (endpoint->queue_size < endpoint->packet_queue_max ||
            endpoint->packet_queue_max == 0) {
            /* add this packet to the endpoint input queue */
            packet->next_packet = NULL;
            endpoint->last_packet->next_packet = packet;
            endpoint->last_packet = packet;
            endpoint->queue_size++;
        }
        else {
            free(packet);
        }
    }
}

static void tls_api_endpoint_arrival(picoquic_test_tls_api_ctx_t* test_ctx,
    tls_api_sim_action_enum next_action, uint64_t next_time)
{
    switch (next_action) {
    case sim_action_client_arrival:
        tls_api_one_endpoint_arrival(test_ctx->s_to_c_link,
            &test_ctx->client_endpoint, (struct sockaddr*) & test_ctx->client_addr,
            test_ctx->client_use_multiple_addresses, next_time);
        break;
    case sim_action_server_arrival:
        tls_api_one_endpoint_arrival(test_ctx->c_to_s_link,
            &test_ctx->server_endpoint, (struct sockaddr*) & test_ctx->server_addr,
            test_ctx->server_use_multiple_addresses, next_time);
        break;
    case sim_action_client_arrival2:
        tls_api_one_endpoint_arrival(test_ctx->s_to_c_link_2,
            &test_ctx->client_endpoint, (struct sockaddr*) & test_ctx->client_addr_2,
            0, next_time);
        break;
    case sim_action_server_arrival2:
        tls_api_one_endpoint_arrival(test_ctx->c_to_s_link_2,
            &test_ctx->server_endpoint, (struct sockaddr*) & test_ctx->server_addr,
            test_ctx->server_use_multiple_addresses,  next_time);
        break;
    default:
        /* Should never happen. */
        break;
    }
}

picoquictest_sim_link_t* tls_api_get_target_link(struct sockaddr_storage * addr_to,
    struct sockaddr * dest_addr2,
    picoquictest_sim_link_t* sim_link1, picoquictest_sim_link_t* sim_link2)
{
    picoquictest_sim_link_t* target_link = sim_link1;
    if (sim_link2 != NULL &&
        picoquic_compare_addr(dest_addr2, (struct sockaddr *)addr_to) == 0) {
        target_link = sim_link2;
    }
    return target_link;
}

static void tls_api_static_departure(picoquic_test_tls_api_ctx_t* test_ctx,
    struct sockaddr_storage * addr_from, struct sockaddr_storage * addr_to,
    int * was_active, size_t * send_length, size_t * p_segment_size,
    picoquictest_sim_link_t** target_link)
{
    picoquic_stateless_packet_t* sp = picoquic_dequeue_stateless_packet(test_ctx->qserver);

    if (sp != NULL) {
        if (sp->length > 0) {
            *was_active |= 1;
            picoquic_store_addr(addr_from, (struct sockaddr*) & sp->addr_local);
            picoquic_store_addr(addr_to, (struct sockaddr*) & sp->addr_to);
            memcpy(test_ctx->send_buffer, sp->bytes, sp->length);
            *send_length = sp->length;
            if (p_segment_size != NULL) {
                *p_segment_size = *send_length;
            }

            *target_link = tls_api_get_target_link(addr_to,
                (struct sockaddr*)&test_ctx->client_addr_2,
                test_ctx->s_to_c_link, test_ctx->s_to_c_link_2);
        }
        picoquic_delete_stateless_packet(sp);
    }
}

static int tls_api_server_departure(picoquic_test_tls_api_ctx_t* test_ctx,
    struct sockaddr_storage * addr_from, struct sockaddr_storage * addr_to,
    int * was_active, size_t * send_length, size_t * p_segment_size,
    picoquictest_sim_link_t** target_link, uint64_t simulated_time)
{
    int ret = 0;

    test_ctx->server_endpoint.last_send_time = simulated_time;

    ret = picoquic_prepare_packet_ex(test_ctx->cnx_server, -1, simulated_time,
        test_ctx->send_buffer, test_ctx->send_buffer_size, send_length,
        addr_to, addr_from, NULL, p_segment_size);
    test_ctx->server_endpoint.next_time_ready = simulated_time +
        test_ctx->server_endpoint.prepare_cpu_time;
    if (ret == PICOQUIC_ERROR_DISCONNECTED) {
        ret = 0;
    }
    else if (ret != 0) {
        /* useless test, but makes it easier to add a breakpoint under debugger */
        ret = -1;
    }
    else if (send_length > 0) {
        /* copy and queue in s to c */
        if (addr_from->ss_family == 0) {
            picoquic_store_addr(addr_from, (struct sockaddr*)&test_ctx->server_addr);
        }

        *target_link = tls_api_get_target_link(addr_to,
            (struct sockaddr*)&test_ctx->client_addr_2,
            test_ctx->s_to_c_link, test_ctx->s_to_c_link_2);
    }
    return ret;
}

static void tls_api_prepare_coalesce_test(picoquic_test_tls_api_ctx_t* test_ctx,
    size_t * coalesced_length, size_t send_buffer_size)
{
    uint32_t hl = 0;

    test_ctx->send_buffer[hl++] = 0xE0; /* handshake */
    picoformat_32(&test_ctx->send_buffer[hl],
        picoquic_supported_versions[test_ctx->cnx_client->version_index].version);
    hl += 4;
    test_ctx->send_buffer[hl++] = test_ctx->cnx_client->path[0]->p_remote_cnxid->cnx_id.id_len;
    hl += picoquic_format_connection_id(&test_ctx->send_buffer[hl],
        send_buffer_size - hl, test_ctx->cnx_client->path[0]->p_remote_cnxid->cnx_id);
    test_ctx->send_buffer[hl++] = test_ctx->cnx_client->path[0]->p_local_cnxid->cnx_id.id_len;
    hl += picoquic_format_connection_id(&test_ctx->send_buffer[hl],
        send_buffer_size - hl, test_ctx->cnx_client->path[0]->p_local_cnxid->cnx_id);
    test_ctx->send_buffer[hl++] = 21;
    picoquic_public_random(&test_ctx->send_buffer[hl], 21);
    *coalesced_length = hl + 21;
}

static int tls_api_client_departure(picoquic_test_tls_api_ctx_t* test_ctx,
    struct sockaddr_storage * addr_from, struct sockaddr_storage * addr_to,
    int * was_active, size_t * send_length, size_t * p_segment_size,
    picoquictest_sim_link_t** p_target_link, uint64_t simulated_time)
{
    int ret = 0;
    /* check whether the client has something to send */
    size_t coalesced_length = 0;
    size_t send_buffer_size = test_ctx->send_buffer_size;

    test_ctx->client_endpoint.last_send_time = simulated_time;

    if (test_ctx->do_bad_coalesce_test && test_ctx->cnx_client->cnx_state > picoquic_state_server_handshake) {
        send_buffer_size = PICOQUIC_MAX_PACKET_SIZE;
        p_segment_size = NULL;
        tls_api_prepare_coalesce_test(test_ctx, &coalesced_length, send_buffer_size);
    }

    ret = picoquic_prepare_packet_ex(test_ctx->cnx_client, -1, simulated_time,
        test_ctx->send_buffer + coalesced_length, send_buffer_size - coalesced_length, send_length,
        addr_to, addr_from, NULL, p_segment_size);

    test_ctx->client_endpoint.next_time_ready = simulated_time +
        test_ctx->client_endpoint.prepare_cpu_time;
    if (ret != 0)
    {
        /* useless test, but makes it easier to add a breakpoint under debugger */
        ret = -1;
    }
    else if (*send_length > 0) {
        *send_length += coalesced_length;
        /* queue in c_to_s */
        if (addr_from->ss_family == 0) {
            picoquic_store_addr(addr_from, (struct sockaddr*)& test_ctx->client_addr);
        }

        if (test_ctx->c_to_s_link_2 != NULL &&
            picoquic_compare_addr((struct sockaddr*) & test_ctx->client_addr_2,
                (struct sockaddr*) addr_from) == 0) {
            *p_target_link = test_ctx->c_to_s_link_2;
        }
        else {
            *p_target_link = test_ctx->c_to_s_link;
        }
    }
    return ret;
}

int tls_api_one_sim_round(picoquic_test_tls_api_ctx_t* test_ctx,
    uint64_t* simulated_time, uint64_t time_out, int* was_active)
{
    int ret = 0;
    picoquictest_sim_link_t* target_link = NULL;
    tls_api_sim_action_enum next_action = sim_action_none;
    uint64_t next_time = *simulated_time;

    if (test_ctx->qserver->pending_stateless_packet != NULL) {
        next_action = sim_action_stateless_packet;
    }
    else {
        uint64_t client_arrival, server_arrival;
        int continue_dequeue;
        
        next_time = *simulated_time + 120000000ull;
        do {
            continue_dequeue = 0;
            next_action = sim_action_none;
            if (test_ctx->cnx_client->cnx_state != picoquic_state_disconnected) {
                uint64_t client_departure = test_ctx->cnx_client->next_wake_time;
                if (client_departure < test_ctx->client_endpoint.next_time_ready) {
                    client_departure = test_ctx->client_endpoint.next_time_ready;
                }
                if (client_departure < next_time) {
                    next_time = client_departure;
                    next_action = sim_action_client_departure;
                }
            }

            if (test_ctx->cnx_server != NULL && test_ctx->cnx_server->cnx_state != picoquic_state_disconnected) {
                uint64_t server_departure = test_ctx->cnx_server->next_wake_time;
                if (server_departure < test_ctx->server_endpoint.next_time_ready) {
                    server_departure = test_ctx->server_endpoint.next_time_ready;
                }
                if (server_departure < next_time) {
                    next_time = server_departure;
                    next_action = sim_action_server_departure;
                }
            }

            client_arrival = picoquictest_sim_link_next_arrival(test_ctx->s_to_c_link, next_time);
            if (client_arrival < next_time) {
                next_time = client_arrival;
                next_action = sim_action_client_arrival;
            }

            server_arrival = picoquictest_sim_link_next_arrival(test_ctx->c_to_s_link, next_time);
            if (server_arrival < next_time) {
                next_time = server_arrival;
                next_action = sim_action_server_arrival;
            }

            if (test_ctx->s_to_c_link_2 != NULL) {
                uint64_t client_arrival_2 = picoquictest_sim_link_next_arrival(test_ctx->s_to_c_link_2, next_time);
                if (client_arrival_2 < next_time) {
                    next_time = client_arrival_2;
                    next_action = sim_action_client_arrival2;
                }
            }

            if (test_ctx->c_to_s_link_2 != NULL) {
                uint64_t server_arrival_2 = picoquictest_sim_link_next_arrival(test_ctx->c_to_s_link_2, next_time);
                if (server_arrival_2 < next_time) {
                    next_time = server_arrival_2;
                    next_action = sim_action_server_arrival2;
                }
            }

            if (test_ctx->client_endpoint.first_packet != NULL &&
                test_ctx->client_endpoint.next_time_ready <= next_time &&
                (next_action != sim_action_client_departure ||
                    test_ctx->client_endpoint.incoming_cpu_time == 0 ||
                    test_ctx->client_endpoint.last_send_time + PICOQUIC_ACK_DELAY_MAX > next_time )){
                next_time = test_ctx->client_endpoint.next_time_ready;
                next_action = sim_action_client_dequeue;
            }

            if (test_ctx->server_endpoint.first_packet != NULL &&
                test_ctx->server_endpoint.next_time_ready <= next_time &&
                (next_action != sim_action_server_departure ||
                    test_ctx->server_endpoint.incoming_cpu_time == 0 ||
                    test_ctx->server_endpoint.last_send_time + PICOQUIC_ACK_DELAY_MAX > next_time )){
                next_time = test_ctx->server_endpoint.next_time_ready;
                next_action = sim_action_server_dequeue;
            }
            
            if (next_action >= sim_action_client_arrival && next_action <= sim_action_server_arrival2) {
                /* packet arrival at one of the endpoints */
                tls_api_endpoint_arrival(test_ctx, next_action, next_time);
                continue_dequeue = 1;
            }
        } while (continue_dequeue);

        if (time_out > 0 && next_time > time_out) {
            next_action = sim_action_none;
            *simulated_time = time_out;
        } else if (next_time > *simulated_time) {
            *simulated_time = next_time;
        }
    }

    if (next_action >= sim_action_stateless_packet && next_action <= sim_action_server_departure) {
        if (test_ctx->cnx_client == NULL) {
            ret = -1;
        }
        else {
            struct sockaddr_storage addr_from;
            struct sockaddr_storage addr_to;
            size_t send_length = 0;
            size_t segment_size = 0;
            size_t * p_segment_size = (test_ctx->use_udp_gso) ? &segment_size : NULL;

            if (next_action == sim_action_stateless_packet) {
                tls_api_static_departure(test_ctx, &addr_from, &addr_to,
                    was_active, &send_length, p_segment_size,
                    &target_link);
            }
            else if (next_action == sim_action_client_departure) {
                /* check whether the client has something to send */
                ret = tls_api_client_departure(test_ctx, &addr_from, &addr_to,
                    was_active, &send_length, p_segment_size, &target_link,
                    *simulated_time);
            }
            else if (next_action == sim_action_server_departure) {
                ret = tls_api_server_departure(test_ctx, &addr_from, &addr_to,
                    was_active, &send_length, p_segment_size,
                    &target_link, *simulated_time);
            }

            if (send_length > 0) {
                int simulate_loss = 0;
                /* TODO: simulate "unreachable" error */
                /* If sending from client, callback client connection,
                 * else callback server connection. Use source and dest address from packet */

                if (target_link->is_unreachable) {
#ifdef _WINDOWS
                    static int unreachable_error = WSAENETUNREACH;
#else
                    static int unreachable_error = EHOSTUNREACH;
#endif
                    picoquic_cnx_t * cnx = test_ctx->cnx_client;
                    if (target_link == test_ctx->s_to_c_link || target_link == test_ctx->s_to_c_link_2) {
                        cnx = test_ctx->cnx_server;
                    }
                    if (cnx != NULL) {
                        picoquic_notify_destination_unreachable(cnx, *simulated_time, (struct sockaddr*)&addr_to,
                            (struct sockaddr*)&addr_from, 0, unreachable_error);
                    }
                    simulate_loss = 1;
                }
                else if (target_link == test_ctx->s_to_c_link) {
                    if (!test_ctx->client_use_multiple_addresses) {
                        if (test_ctx->client_use_nat) {
                            if (picoquic_compare_addr((struct sockaddr*) & test_ctx->client_addr_natted,
                                (struct sockaddr*) & addr_to) == 0) {
                                /* Rewrite the address */
                                picoquic_store_addr(&addr_to, (struct sockaddr*) & test_ctx->client_addr);
                            }
                            else {
                                /* Using wrong address: simulate loss */
                                simulate_loss = 1;
                            }
                        }
                        else if (picoquic_compare_addr((struct sockaddr*) & test_ctx->client_addr,
                            (struct sockaddr*) & addr_to) != 0) {
                            /* Using wrong address: simulate loss */
                            simulate_loss = 1;
                        }
                    }
                }
                else if (target_link == test_ctx->c_to_s_link && test_ctx->client_use_nat) {
                    picoquic_store_addr(&addr_from, (struct sockaddr*) & test_ctx->client_addr_natted);
                }

                if (*simulated_time < test_ctx->blackhole_end && *simulated_time >= test_ctx->blackhole_start) {
                    simulate_loss = 1;
                }

                if (simulate_loss == 0) {
                    size_t size_sent = 0;
                    uint8_t *  send_buffer = test_ctx->send_buffer;
                    if (p_segment_size == NULL) {
                        segment_size = PICOQUIC_MAX_PACKET_SIZE;
                    }
                    while (ret == 0 && size_sent < send_length) {
                        picoquictest_sim_packet_t* packet = picoquictest_sim_link_create_packet();

                        if (packet == NULL) {
                            ret = -1;
                        }
                        else {
                            picoquic_store_addr(&packet->addr_from, (struct sockaddr*) & addr_from);
                            picoquic_store_addr(&packet->addr_to, (struct sockaddr*) & addr_to);
                            packet->ecn_mark = test_ctx->packet_ecn_default;
                            packet->length = send_length - size_sent;
                            if (packet->length > segment_size) {
                                packet->length = segment_size;
                            }
                            memcpy(packet->bytes, send_buffer, packet->length);
                            picoquictest_sim_link_submit(target_link, packet, *simulated_time);
                            size_sent += segment_size;
                            send_buffer += segment_size;
                        }
                    }
                }

                *was_active |= 1;
            }
        }
    }
    else if (next_action == sim_action_client_dequeue) {
        ret = tls_api_one_endpoint_dequeue(&test_ctx->client_endpoint,
            test_ctx->qclient, *simulated_time, was_active, test_ctx->recv_ecn_client);
    }
    else if (next_action == sim_action_server_dequeue) {
        ret = tls_api_one_endpoint_dequeue(&test_ctx->server_endpoint,
            test_ctx->qserver, *simulated_time, was_active, test_ctx->recv_ecn_server);
    }
    else if (next_action != sim_action_none) {
        /* Unexpected action ! */
        ret = -1;
    }

    if (test_ctx->cnx_server == NULL && ret == 0 && *was_active) {
        picoquic_connection_id_t target_cnxid = test_ctx->cnx_client->initial_cnxid;
        picoquic_cnx_t* next = test_ctx->qserver->cnx_list;

        while (next != NULL && picoquic_compare_connection_id(&next->initial_cnxid, &target_cnxid) != 0) {
            next = next->next_in_table;
        }

        test_ctx->cnx_server = next;
    }
    return ret;
}

int tls_api_connection_loop(picoquic_test_tls_api_ctx_t* test_ctx,
    uint64_t* loss_mask, uint64_t queue_delay_max, uint64_t* simulated_time)
{
    int ret = 0;
    int nb_trials = 0;
    int nb_inactive = 0;

    test_ctx->c_to_s_link->loss_mask = loss_mask;
    test_ctx->s_to_c_link->loss_mask = loss_mask;

    test_ctx->c_to_s_link->queue_delay_max = queue_delay_max;
    test_ctx->s_to_c_link->queue_delay_max = queue_delay_max;

    while (ret == 0 && nb_trials < 1024 && nb_inactive < 512 && (!TEST_CLIENT_READY || (test_ctx->cnx_server == NULL || !TEST_SERVER_READY))) {
        int was_active = 0;
        nb_trials++;

        ret = tls_api_one_sim_round(test_ctx, simulated_time, 0, &was_active);

        if (test_ctx->cnx_client->cnx_state == picoquic_state_disconnected &&
            (test_ctx->cnx_server == NULL || test_ctx->cnx_server->cnx_state == picoquic_state_disconnected)) {
            break;
        }

        if (nb_trials == 512) {
            DBG_PRINTF("After %d trials, client state = %d, server state = %d",
                nb_trials, (int)test_ctx->cnx_client->cnx_state,
                (test_ctx->cnx_server == NULL) ? -1 : test_ctx->cnx_server->cnx_state);
        }

        if (was_active) {
            nb_inactive = 0;
        } else {
            nb_inactive++;
        }
    }

    return ret;
}

uint64_t test_vary_link(picoquic_test_tls_api_ctx_t* test_ctx, uint64_t transition_time, test_vary_link_spec_t* link_state)
{
    const uint64_t ten_twelve = 1000000000000ull;
    uint64_t picoseq_per_byte_up = (ten_twelve * 8) / link_state->bits_per_second_up;
    uint64_t picoseq_per_byte_down = (ten_twelve * 8) / link_state->bits_per_second_down;
    test_ctx->c_to_s_link->microsec_latency = link_state->microsec_latency;
    test_ctx->c_to_s_link->picosec_per_byte = picoseq_per_byte_up;
    test_ctx->s_to_c_link->microsec_latency = link_state->microsec_latency;
    test_ctx->s_to_c_link->picosec_per_byte = picoseq_per_byte_down;

    return transition_time + link_state->duration;
}

int tls_api_data_sending_loop_ex(picoquic_test_tls_api_ctx_t* test_ctx,
    uint64_t* loss_mask, uint64_t* simulated_time, int max_trials, size_t nb_link_states, test_vary_link_spec_t * link_state)
{
    int ret = 0;
    int nb_trials = 0;
    int nb_inactive = 0;
    uint64_t next_state_change = 0;
    size_t next_link_state = 0;

    test_ctx->c_to_s_link->loss_mask = loss_mask;
    test_ctx->s_to_c_link->loss_mask = loss_mask;

    if (max_trials <= 0) {
        max_trials = 4000000;
    }

    if (nb_link_states > 0) {
        next_state_change = test_vary_link(test_ctx, *simulated_time, link_state);
    }

    while (ret == 0 && nb_trials < max_trials && nb_inactive < 256 && TEST_CLIENT_READY && TEST_SERVER_READY) {
        int was_active = 0;
        nb_trials++;
        ret = tls_api_one_sim_round(test_ctx, simulated_time, next_state_change, &was_active);
        if (nb_link_states > 0 && *simulated_time >= next_state_change) {
            next_link_state++;
            if (next_link_state >= nb_link_states) {
                next_link_state = 0;
            }
            next_state_change = test_vary_link(test_ctx, *simulated_time, &link_state[next_link_state]);
        }

        if (ret < 0)
        {
            break;
        }

        if (was_active) {
            nb_inactive = 0;
        } else {
            nb_inactive++;
        }

        if (test_ctx->test_finished) {
            if (test_ctx->immediate_exit ||
                (picoquic_is_cnx_backlog_empty(test_ctx->cnx_client) && picoquic_is_cnx_backlog_empty(test_ctx->cnx_server))) {
                break;
            }
        }
    }

    return ret; /* end of sending loop */
}

int tls_api_data_sending_loop(picoquic_test_tls_api_ctx_t* test_ctx,
    uint64_t* loss_mask, uint64_t* simulated_time, int max_trials)
{
    return tls_api_data_sending_loop_ex(test_ctx, loss_mask, simulated_time, max_trials, 0, NULL);
}

int tls_api_synch_to_empty_loop(picoquic_test_tls_api_ctx_t* test_ctx,
    uint64_t* simulated_time, int max_trials,
    int path_target, int wait_for_ready)
{
    /* run a receive loop until no outstanding data */
    int ret = 0;
    uint64_t time_out = *simulated_time + 4000000;
    int nb_rounds = 0;
    int success = 0;

    while (ret == 0 && *simulated_time < time_out &&
        nb_rounds < max_trials && test_ctx->cnx_client->cnx_state != picoquic_state_disconnected) {
        int was_active = 0;

        ret = tls_api_one_sim_round(test_ctx, simulated_time, time_out, &was_active);
        nb_rounds++;

        if (test_ctx->cnx_server == NULL) {
            break;
        }

        if (test_ctx->cnx_client->nb_paths >= path_target &&
            test_ctx->cnx_server->nb_paths >= path_target &&
            picoquic_is_cnx_backlog_empty(test_ctx->cnx_client) &&
            picoquic_is_cnx_backlog_empty(test_ctx->cnx_server) &&
            (!wait_for_ready || (
                test_ctx->cnx_client->cnx_state == picoquic_state_ready &&
                test_ctx->cnx_server->cnx_state == picoquic_state_ready))) {
            success = 1;
            break;
        }
    }

    if (ret == 0 && success == 0) {
        DBG_PRINTF("Exit synch loop after %d rounds, backlog or not enough paths (%d & %d).\n",
            nb_rounds, test_ctx->cnx_client->nb_paths, (test_ctx->cnx_server == NULL)?0: test_ctx->cnx_server->nb_paths);
    }

    return ret;
}


static int wait_application_aead_ready(picoquic_test_tls_api_ctx_t* test_ctx,
    uint64_t * simulated_time)
{
    int ret = 0;
    uint64_t time_out = *simulated_time + 4000000;
    int nb_trials = 0;
    int nb_inactive = 0;

    while (*simulated_time < time_out &&
        TEST_CLIENT_READY &&
        TEST_SERVER_READY &&
        test_ctx->cnx_server->crypto_context[3].aead_decrypt == NULL &&
        nb_trials < 1024 &&
        nb_inactive < 64 &&
        ret == 0) {
        int was_active = 0;
        nb_trials++;

        ret = tls_api_one_sim_round(test_ctx, simulated_time, time_out, &was_active);

        if (was_active) {
            nb_inactive = 0;
        }
        else {
            nb_inactive++;
        }
    }

    if (ret == 0 && test_ctx->cnx_server != NULL && test_ctx->cnx_server->crypto_context[3].aead_decrypt == NULL) {
        DBG_PRINTF("Could not obtain the 1-RTT decryption key, state = %d\n",
            test_ctx->cnx_server->cnx_state);
        ret = -1;
    }

    return ret;
}

int tls_api_wait_for_timeout(picoquic_test_tls_api_ctx_t* test_ctx,
    uint64_t* simulated_time, uint64_t time_out_delay)
{
    int ret = 0;
    uint64_t time_out = *simulated_time + time_out_delay;
    int nb_inactive = 0;

    while (*simulated_time < time_out &&
        TEST_CLIENT_READY &&
        TEST_SERVER_READY &&
        nb_inactive < 64 &&
        ret == 0) {
        int was_active = 0;

        ret = tls_api_one_sim_round(test_ctx, simulated_time, time_out, &was_active);

        if (was_active) {
            nb_inactive = 0;
        }
        else {
            nb_inactive++;
        }
    }

    return ret;
}

int wait_client_connection_ready(picoquic_test_tls_api_ctx_t* test_ctx,
    uint64_t* simulated_time)
{
    int ret = 0;
    uint64_t time_out = *simulated_time + 4000000;
    int nb_trials = 0;
    int nb_inactive = 0;
    int was_active = 0;

    while (*simulated_time < time_out &&
        test_ctx->cnx_client->cnx_state < picoquic_state_ready &&
        nb_trials < 1024 &&
        nb_inactive < 64 &&
        ret == 0) {
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

    if (ret == 0 && test_ctx->cnx_client->cnx_state != picoquic_state_ready) {
        DBG_PRINTF("Could not get to ready state, client state = %d\n",
            test_ctx->cnx_client->cnx_state);
        ret = -1;
    }

    return ret;
}

int tls_api_close_with_losses(
    picoquic_test_tls_api_ctx_t* test_ctx, uint64_t* simulated_time, uint64_t loss_mask)
{
    int ret = 0;
    int nb_rounds = 0;
    
    ret = picoquic_close(test_ctx->cnx_client, 0);

    if (ret == 0) {
        /* packet from client to server */
        /* Do not simulate losses there, as there is no way to correct them */

        test_ctx->c_to_s_link->loss_mask = &loss_mask;
        test_ctx->s_to_c_link->loss_mask = &loss_mask;

        while (ret == 0 && (test_ctx->cnx_client->cnx_state != picoquic_state_disconnected || 
            (test_ctx->cnx_server != NULL && test_ctx->cnx_server->cnx_state != picoquic_state_disconnected)) && nb_rounds < 100000) {
            int was_active = 0;
            ret = tls_api_one_sim_round(test_ctx, simulated_time, 0, &was_active);
            if (ret != 0){
                if (test_ctx->cnx_client->cnx_state == picoquic_state_disconnected && test_ctx->cnx_server->cnx_state == picoquic_state_disconnected) {
                    ret = 0;
                    break;
                }
            }
            nb_rounds++;
        }
    }

    if (ret == 0 && (test_ctx->cnx_client->cnx_state != picoquic_state_disconnected || 
        (test_ctx->cnx_server != NULL && test_ctx->cnx_server->cnx_state != picoquic_state_disconnected))) {
        ret = -1;
    }

    return ret;
}

static int tls_api_attempt_to_close(
    picoquic_test_tls_api_ctx_t* test_ctx, uint64_t* simulated_time)
{
    return tls_api_close_with_losses(test_ctx, simulated_time, 0);
}

int tls_api_test_with_loss_final(picoquic_test_tls_api_ctx_t* test_ctx, uint32_t proposed_version,
    char const* sni, char const* alpn, uint64_t * simulated_time)
{
    int ret = 0;

    if (ret == 0 && test_ctx->cnx_server != NULL) {
        ret = verify_transport_extension(test_ctx->cnx_client, test_ctx->cnx_server);
        if (ret != 0)
        {
            DBG_PRINTF("%s", "Transport extensions do no match\n");
        }

        if (ret == 0) {
            ret = verify_sni(test_ctx->cnx_client, test_ctx->cnx_server, sni);

            if (ret != 0)
            {
                DBG_PRINTF("%s", "SNI do not match\n");
            }
        }

        if (ret == 0) {
            ret = verify_alpn(test_ctx->cnx_client, test_ctx->cnx_server, alpn);

            if (ret != 0)
            {
                DBG_PRINTF("%s", "ALPN do not match\n");
            }
        }

        if (ret == 0) {
            ret = verify_version(test_ctx->cnx_client, test_ctx->cnx_server);

            if (ret != 0)
            {
                DBG_PRINTF("%s", "Negotiated versions do not match\n");
            }
        }
    }

    if (ret == 0) {
        ret = tls_api_attempt_to_close(test_ctx, simulated_time);

        if (ret != 0)
        {
            DBG_PRINTF("Connection close returns %d\n", ret);
        }
    }

    return ret;
}

int tls_api_connect_test()
{
    uint64_t simulated_time = 0;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    int ret = tls_api_init_ctx(&test_ctx, PICOQUIC_INTERNAL_TEST_VERSION_1, PICOQUIC_TEST_SNI, PICOQUIC_TEST_ALPN, &simulated_time, NULL, NULL, 0, 0, 0);

    if (ret != 0)
    {
        DBG_PRINTF("Could not create the QUIC test contexts for V=%x\n", PICOQUIC_INTERNAL_TEST_VERSION_1);
    }

    if (ret == 0) {
        int nb_trials = 0;
        int nb_inactive = 0;

        test_ctx->c_to_s_link->loss_mask = NULL;
        test_ctx->s_to_c_link->loss_mask = NULL;

        test_ctx->c_to_s_link->queue_delay_max = 0;
        test_ctx->s_to_c_link->queue_delay_max = 0;

        while (ret == 0 && nb_trials < 1024 && nb_inactive < 512 && (
            !(test_ctx->cnx_client->cnx_state == picoquic_state_ready || test_ctx->cnx_client->cnx_state == picoquic_state_client_ready_start) ||
            (test_ctx->cnx_server == NULL || 
                !(test_ctx->cnx_server != NULL && (test_ctx->cnx_server->cnx_state >= picoquic_state_server_handshake))))) {
            int was_active = 0;
            nb_trials++;

            ret = tls_api_one_sim_round(test_ctx, &simulated_time, 0, &was_active);

            if (test_ctx->cnx_client->cnx_state == picoquic_state_disconnected &&
                (test_ctx->cnx_server == NULL || test_ctx->cnx_server->cnx_state == picoquic_state_disconnected)) {
                break;
            }

            if (nb_trials == 512) {
                DBG_PRINTF("After %d trials, client state = %d, server state = %d",
                    nb_trials, (int)test_ctx->cnx_client->cnx_state,
                    (test_ctx->cnx_server == NULL) ? -1 : test_ctx->cnx_server->cnx_state);
            }

            if (was_active) {
                nb_inactive = 0;
            }
            else {
                nb_inactive++;
            }
        }

        if (ret != 0)
        {
            DBG_PRINTF("Connection loop returns %d\n", ret);
        }
    }

    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }

    return ret;
}

static int tls_api_test_with_loss(uint64_t* loss_mask, uint32_t proposed_version,
    char const* sni, char const* alpn)
{
    uint64_t simulated_time = 0;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    int ret = tls_api_init_ctx(&test_ctx, proposed_version, sni, alpn, &simulated_time, NULL, NULL, 0, 0, 0);

    if (ret != 0)
    {
        DBG_PRINTF("Could not create the QUIC test contexts for V=%x\n", proposed_version);
    }

    if (ret == 0) {
        ret = tls_api_connection_loop(test_ctx, loss_mask, 0, &simulated_time);

        if (ret != 0)
        {
            DBG_PRINTF("Connection loop returns %d\n", ret);
        }
    }

    if (ret == 0) {
        ret = tls_api_test_with_loss_final(test_ctx, proposed_version, sni, alpn, &simulated_time);
    }

    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }

    return ret;
}

int tls_api_test()
{
    return tls_api_test_with_loss(NULL, PICOQUIC_INTERNAL_TEST_VERSION_1, PICOQUIC_TEST_SNI, PICOQUIC_TEST_ALPN);
}

int tls_api_inject_hs_ack_test()
{
    uint64_t simulated_time = 0;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    int ret = tls_api_init_ctx(&test_ctx, PICOQUIC_INTERNAL_TEST_VERSION_1, PICOQUIC_TEST_SNI, PICOQUIC_TEST_ALPN, &simulated_time, NULL, NULL, 0, 0, 0);

    if (ret != 0)
    {
        DBG_PRINTF("Could not create the QUIC test contexts for V=%x\n", PICOQUIC_INTERNAL_TEST_VERSION_1);
    }

    if (ret == 0) {
        int ret = 0;
        int nb_trials = 0;
        int nb_inactive = 0;
        int injected = 0;

        while (ret == 0 && nb_trials < 1024 && nb_inactive < 512 && (!TEST_CLIENT_READY || (test_ctx->cnx_server == NULL || !TEST_SERVER_READY))) {
            int was_active = 0;
            nb_trials++;

            ret = tls_api_one_sim_round(test_ctx, &simulated_time, 0, &was_active);

            if (test_ctx->cnx_client->cnx_state == picoquic_state_disconnected &&
                (test_ctx->cnx_server == NULL || test_ctx->cnx_server->cnx_state == picoquic_state_disconnected)) {
                break;
            }

            if (!injected && test_ctx->cnx_client->crypto_context[2].aead_encrypt != NULL) {
                const uint8_t ack_only[] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    picoquic_frame_type_ack, 0, 0, 0, 0 };

                ret = tls_api_inject_packet(test_ctx, 1, 2, ack_only, sizeof(ack_only), 0, simulated_time);

                injected = 1;
            }

            if (was_active) {
                nb_inactive = 0;
            }
            else {
                nb_inactive++;
            }
        }

        if (ret != 0)
        {
            DBG_PRINTF("Connection loop returns %d\n", ret);
        }
    }

    if (ret == 0) {
        ret = tls_api_test_with_loss_final(test_ctx, PICOQUIC_INTERNAL_TEST_VERSION_1, PICOQUIC_TEST_SNI, PICOQUIC_TEST_ALPN, &simulated_time);
    }

    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }

    return ret;
}

int tls_api_silence_test()
{
    uint64_t loss_mask = 0;
    uint64_t simulated_time = 0;
    uint64_t next_time = 0;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    int ret = tls_api_init_ctx(&test_ctx, 0, PICOQUIC_TEST_SNI, PICOQUIC_TEST_ALPN, &simulated_time, NULL, NULL, 0, 0, 0);

    if (ret == 0) {
        ret = tls_api_connection_loop(test_ctx, &loss_mask, 0, &simulated_time);
    }

    /* simulate 5 seconds of silence */
    next_time = simulated_time + 5000000;
    while (ret == 0 && simulated_time < next_time && TEST_CLIENT_READY && TEST_SERVER_READY) {
        int was_active = 0;

        ret = tls_api_one_sim_round(test_ctx, &simulated_time, next_time, &was_active);
    }

    if (ret == 0) {
        ret = tls_api_attempt_to_close(test_ctx, &simulated_time);
    }

    if (ret == 0) {
        /* verify the absence of any spurious retransmission */
        if (test_ctx->cnx_client->nb_retransmission_total != 0) {
            ret = -1;
        } else if (test_ctx->cnx_server != NULL && test_ctx->cnx_server->nb_retransmission_total != 0) {
            ret = -1;
        }
    }

    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }

    return ret;
}

int tls_api_loss_test(uint64_t mask)
{
    uint64_t loss_mask = mask;

    return tls_api_test_with_loss(&loss_mask, 0, PICOQUIC_TEST_SNI, PICOQUIC_TEST_ALPN);
}

/* Test that connection establishment succeeds in presence of many losses */
int tls_api_many_losses()
{
    uint64_t loss_mask = 0;
    int ret = 0;
    uint64_t random_context = 0x1055ca45c001babaull;

    /* We first test with a set of preprogrammed masks, checking consecutive drops */
    for (int i = 0; ret == 0 && i < 6; i++) {
        for (int j = 0; ret == 0 && j < 4; j++) {
            uint64_t j_mask = ~(UINT64_MAX << j);
            loss_mask = j_mask << i;
            ret = tls_api_loss_test(loss_mask);
            if (ret != 0) {
                DBG_PRINTF("Handshake fails for mask %d-%d = %llx", i, j, (unsigned long long)loss_mask);
            }
        }
        for (uint64_t j = 8; ret == 0 && j < 11; j++) {
            loss_mask = (j | (j << 4) | (j << 8))<<i;
            ret = tls_api_loss_test(loss_mask);
            if (ret != 0) {
                DBG_PRINTF("Handshake fails for mask %d, %" PRIu64" = %llx", i, j,  (unsigned long long)loss_mask);
            }
        }
    }

    /* Then we verify that we can establish 50 connections with packet drop rate=30% */
    for (int i = 0; ret == 0 &&  i < 50; i++)
    {
        uint64_t loss_mask = 0;
        for (int j = 0; j < 64; j++)
        {
            loss_mask <<= 1;

            if (picoquic_test_uniform_random(&random_context, 1000) < 300) {
                loss_mask |= 1;
            }
        }

        ret = tls_api_one_scenario_test(test_scenario_q_and_r, sizeof(test_scenario_q_and_r), 0, loss_mask, 128000, 0, 0, 0, NULL, NULL);
        if (ret != 0) {
            DBG_PRINTF("Handshake fails for random mask %d, mask = %llx", i, (unsigned long long)loss_mask);
        }
    }

    return ret;
}

/* Basic version negotiation.
 * Verifies that client properly handles a version negotiation packet.
 */

int tls_api_version_negotiation_test()
{
    const uint32_t version_grease = 0x0aca4a0a;
    uint64_t simulated_time = 0;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    int ret = tls_api_init_ctx(&test_ctx, version_grease, PICOQUIC_TEST_SNI, PICOQUIC_TEST_ALPN, &simulated_time, NULL, NULL, 0, 0, 0);

    if (ret != 0)
    {
        DBG_PRINTF("Could not create the QUIC test contexts for V=%x\n", version_grease);
    }

    if (ret == 0) {
        (void)tls_api_connection_loop(test_ctx, NULL, 0, &simulated_time);

        if (test_ctx->cnx_client->cnx_state == picoquic_state_disconnected) {
            ret = 0;
        }
        else {
            DBG_PRINTF("Unexpected state: %d\n", test_ctx->cnx_client->cnx_state);
            ret = -1;
        }
    }


    if (ret == 0) {
        if (!test_ctx->received_version_negotiation){
            DBG_PRINTF("%s", "No version negotiation notified\n");
            ret = -1;
        }
    }

    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }

    return ret;
}

/* Version negotiation invariant test.
 * Verifies that server generates a version negotiation packet, even if the
 * connection ID lengths are larger than the current version permits.
 */

static int check_vn_invariant(uint8_t* packet, size_t packet_length, uint8_t* response, size_t response_length)
{
    int ret = 0;
    size_t icid_len;
    uint8_t * icid;
    size_t scid_len;
    uint8_t* scid;
    size_t response_index = 5; /* Points to byte after VN */
    /* Invariant parsing -- compute minimum length */
    icid_len = packet[5];
    icid = &packet[6];
    scid_len = packet[5 + 1 + icid_len];
    scid = &packet[5 + 1 + icid_len + 1];
    /* Check that the response is long enough */
    if (response_length < 1 + 4 + 1 + icid_len + 1 + scid_len + 4) {
        DBG_PRINTF("Response too short, length = %zu", response_length);
        ret = -1;
    }
    /* Check that response is long header */
    if (ret == 0 && (response[0] & 0x80) != 0x80) {
        DBG_PRINTF("Not a long header, packet[0] = 0x%02x", response[0]);
        ret = -1;
    }
    /* Check that response version is 0 */
    for (size_t i = 1; ret == 0 && i < 5; i++) {
        if (response[i] != 0) {
            DBG_PRINTF("Version ID not zero, packet[%zu] = 0x%02x", i, response[i]);
            ret = -1;
        }
    }
    /* Verify that the DCID matches incoming SCID */
    if (ret == 0) {
        if (response[response_index] != scid_len) {
            DBG_PRINTF("Expected DCID length %zu, got 0x02x", scid_len, response[response_index]);
            ret = -1;
        }
        else {
            response_index++;
            if (scid_len > 0 && memcmp(scid, response + response_index, scid_len) != 0) {
                DBG_PRINTF("%s", "DCID does not match incoming SCID");
                ret = -1;
            }
            else {
                response_index += scid_len;
            }
        }
    }
    /* Verify that the SCID matches incoming DCID */
    if (ret == 0) {
        if (response[response_index] != icid_len) {
            DBG_PRINTF("Expected ICID length %zu, got 0x02x", icid_len, response[response_index]);
            ret = -1;
        }
        else {
            response_index++;
            if (scid_len > 0 && memcmp(icid, response + response_index, icid_len) != 0) {
                DBG_PRINTF("%s", "SCID does not match incoming ICID");
                ret = -1;
            }
        }
    }

    return ret;
}

int tls_api_version_invariant_test()
{
    uint64_t simulated_time = 0;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    int ret = tls_api_init_ctx(&test_ctx, 0, PICOQUIC_TEST_SNI, PICOQUIC_TEST_ALPN, &simulated_time, NULL, NULL, 0, 0, 0);

    if (ret != 0)
    {
        DBG_PRINTF("%s", "Could not create the QUIC test contexts");
    }
    else {
        /* Fabricate a packet that stresses the invariants */
        uint8_t packet[PICOQUIC_MAX_PACKET_SIZE];
        /* Initialize first byte to long header value*/
        packet[0] = 0xF5;
        /* Set version to unexpected value */
        memset(packet + 1, 0xaa, 4);
        /* Set destination CID to 255 times "dd" */
        packet[6] = 255;
        memset(packet + 7, 0xdd, 255);
        /* Set source CID to 127 times "cc" */
        packet[262] = 127;
        memset(packet + 263, 0xcc, 127);
        /* Set reminder of packet to 0x55*/
        memset(packet + 290, 0x55, PICOQUIC_MAX_PACKET_SIZE - 290);

        /* Submit the packet to the server */
        ret = picoquic_incoming_packet(test_ctx->qserver, packet, PICOQUIC_MAX_PACKET_SIZE,
            (struct sockaddr*) & test_ctx->client_addr, (struct sockaddr*) & test_ctx->server_addr,
            0, 0, simulated_time);
        if (ret != 0) {
            DBG_PRINTF("incoming invariant test returns %d (0x%x)", ret, ret);
        }
        else {
            uint8_t response[PICOQUIC_MAX_PACKET_SIZE];
            struct sockaddr_storage addr_to;
            struct sockaddr_storage addr_from;
            size_t send_length = 0;
            int if_index = 0;
            picoquic_connection_id_t log_cid;
            picoquic_cnx_t* last_cnx = NULL;

            ret = picoquic_prepare_next_packet(test_ctx->qserver, simulated_time, response, PICOQUIC_MAX_PACKET_SIZE,
                &send_length, &addr_to, &addr_from, &if_index, &log_cid, &last_cnx);
            if (ret != 0) {
                DBG_PRINTF("Invariant response test returns %d (0x%x)", ret, ret);
            }
            else if (send_length == 0) {
                DBG_PRINTF("%s", "Invariant response test does not return any data");
                ret = -1;
            }
            else {
                ret = check_vn_invariant(packet, PICOQUIC_MAX_PACKET_SIZE, response, send_length);
            }
        }
    }

    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }

    return ret;
}

/* Test that spoofed version negotiation does not delete the connection context
 * spoof mode:
 * 0- valid CID
 * 1- invalid DCID
 * 2- invalid SCID
 * 3- invalid VN, empty list
 * 4- invalid list, contains current version
 * 5- invalid list, contains null version
 * 6- invalid list, contains only non existing versions
 * 7- invalid VN, length not multiple of 4
 */
size_t test_version_negotiation_get_spoofed(picoquic_cnx_t* cnx, int spoof_mode, uint8_t * packet, size_t packet_length)
{
    size_t packet_index = 0;
    picoquic_connection_id_t bad_cid = { {0xba, 0xdc, 0x1d, 0, 0, 0, 0, 0}, 8 };
    uint32_t this_vn = picoquic_supported_versions[cnx->version_index].version;
    uint32_t random_vn = 0xa5a6a7a8 ^ (this_vn & 0x0f0f0f0f);
    /* First byte for long header packet */
    if (packet_index < packet_length) {
        packet[packet_index++] = (uint8_t)(spoof_mode | 0x80);
    }
    /* version value 0 */
    if (packet_index + 4 < packet_length) {
        picoformat_32(&packet[packet_index], 0);
        packet_index += 4;
    }
    /* DCID */
    if (packet_index + 1 < packet_length) {
        if (spoof_mode == 1) {
            packet[packet_index++] = bad_cid.id_len;
            packet_index += picoquic_format_connection_id(&packet[packet_index], packet_length - packet_index, bad_cid);
        }
        else {
            packet[packet_index++] = cnx->path[0]->p_local_cnxid->cnx_id.id_len;
            packet_index += picoquic_format_connection_id(&packet[packet_index], packet_length - packet_index, cnx->path[0]->p_local_cnxid->cnx_id);
        }
    }
    /* SCID */
    if (packet_index + 1 < packet_length) {
        if (spoof_mode == 2) {
            packet[packet_index++] = bad_cid.id_len;
            packet_index += picoquic_format_connection_id(&packet[packet_index], packet_length - packet_index, bad_cid);
        }
        else {
            packet[packet_index++] = cnx->initial_cnxid.id_len;
            packet_index += picoquic_format_connection_id(&packet[packet_index], packet_length - packet_index, cnx->initial_cnxid);
        }
    }
    /* Encode the proposed versions */
    if (spoof_mode != 3) {
        if (packet_index + 4 < packet_length) {
            picoformat_32(&packet[packet_index], random_vn);
            packet_index += 4;
        }
        if (packet_index + 4 < packet_length) {
            uint32_t plausible_vn = 0xffffffff;
            if (spoof_mode == 4) {
                plausible_vn = this_vn;
            }
            else if (spoof_mode == 5) {
                plausible_vn = this_vn;
            }
            else if (spoof_mode != 6 && picoquic_nb_supported_versions > 1) {
                size_t plausible_index = picoquic_nb_supported_versions - 1;
                if (cnx->version_index == plausible_index) {
                    plausible_index = 0;
                }
                plausible_vn = picoquic_supported_versions[plausible_index].version;
            }
            picoformat_32(&packet[packet_index], plausible_vn);
            packet_index += 4;
        }
        if (spoof_mode == 7 && packet_index < packet_length) {
            packet[packet_index++] = 0xaf;
        }
    }

    return packet_index;
}

int test_version_negotiation_spoof_one(int spoof_mode)
{
    uint64_t simulated_time = 0;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    int ret = tls_api_init_ctx(&test_ctx, 0, PICOQUIC_TEST_SNI, PICOQUIC_TEST_ALPN, &simulated_time, NULL, NULL, 0, 0, 0);
    uint8_t packet[256];
    size_t packet_length = 0;
    int nb_trials = 0;
    int nb_inactive = 0;

    /* Do one round of simulation so the client connection moves to initial state */
    while (ret == 0 && nb_trials < 1024 && nb_inactive < 512) {
        int was_active = 0;
        nb_trials++;

        ret = tls_api_one_sim_round(test_ctx, &simulated_time, 0, &was_active);

        if (test_ctx->cnx_client->cnx_state >= picoquic_state_client_init_sent) {
            break;
        }

        if (nb_trials == 512) {
            DBG_PRINTF("After %d trials, client state = %d, server state = %d",
                nb_trials, (int)test_ctx->cnx_client->cnx_state,
                (test_ctx->cnx_server == NULL) ? -1 : test_ctx->cnx_server->cnx_state);
        }

        if (was_active) {
            nb_inactive = 0;
        }
        else {
            nb_inactive++;
        }
    }
    /* Verify that the connection is in the right state */
    if (ret == 0 && test_ctx->cnx_client->cnx_state != picoquic_state_client_init_sent) {
        DBG_PRINTF("After %d trials, client state = %d",
            nb_trials, (int)test_ctx->cnx_client->cnx_state);
        ret = -1;
    }

    if (ret == 0) {
        /* Create the spoofed VN */
        packet_length = test_version_negotiation_get_spoofed(test_ctx->cnx_client, spoof_mode, packet, sizeof(packet));

        /* Inject the spoofed VN packet */
        ret = picoquic_incoming_packet(test_ctx->qclient, packet, packet_length,
            (struct sockaddr*)&test_ctx->server_addr, (struct sockaddr*)&test_ctx->client_addr,
            0, 0, simulated_time);
    }

    if (ret == 0) {
        /* Verify that the connection survived */
        if (test_ctx->cnx_client->cnx_state != picoquic_state_client_init_sent) {
            DBG_PRINTF("After VN injection, client state = %d",
                (int)test_ctx->cnx_client->cnx_state);
            ret = -1;
        }
    }

    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }

    return ret;
}

int test_version_negotiation_spoof()
{
    int ret = 0;

    if (test_version_negotiation_spoof_one(0) == 0) {
        DBG_PRINTF("%s", "VN spoof mode 0 has no effect");
        ret = -1;
    }

    for (int spoof_mode = 1; ret == 0 && spoof_mode < 8; spoof_mode++) {
        ret = test_version_negotiation_spoof_one(spoof_mode);
        if (ret != 0) {
            DBG_PRINTF("VN spoof mode %d caused failure", spoof_mode);
            ret = -1;
        }
    }

    return ret;
}

/* Test the compatible VN setup.
 * This will start a connection with version 1, and verify that it gets established with version 2,
 * or to version 2 draft.
 */
int vn_compat_test_one(uint32_t current, uint32_t target)
{
    uint64_t simulated_time = 0;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    int ret = tls_api_init_ctx(&test_ctx, current, PICOQUIC_TEST_SNI, PICOQUIC_TEST_ALPN, &simulated_time, NULL, NULL, 0, 1, 0);


    if (ret == 0) {
        /* Set the desired version */
        picoquic_set_desired_version(test_ctx->cnx_client, target);
        /* Start the client connection */
        ret = picoquic_start_client_cnx(test_ctx->cnx_client);
    }

    if (ret != 0)
    {
        DBG_PRINTF("Could not create the QUIC test contexts for V=%x\n", current);
    }

    if (ret == 0) {
        (void)tls_api_connection_loop(test_ctx, NULL, 0, &simulated_time);
    }


    if (ret == 0) {
        if (picoquic_supported_versions[test_ctx->cnx_client->version_index].version != target) {
            DBG_PRINTF("Client remained to version 0x%08x",
                picoquic_supported_versions[test_ctx->cnx_client->version_index].version);
            ret = -1;
        }
        else if (picoquic_supported_versions[test_ctx->cnx_server->version_index].version != target) {
            DBG_PRINTF("Server remained to version 0x%08x",
                picoquic_supported_versions[test_ctx->cnx_client->version_index].version);
            ret = -1;
        }
    }

    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }

    return ret;
}

int vn_compat_test()
{
    int ret = 0;

    if (vn_compat_test_one(PICOQUIC_V1_VERSION, PICOQUIC_V2_VERSION) != 0) {
        ret = -1;
    }
    else if (vn_compat_test_one(PICOQUIC_V1_VERSION, PICOQUIC_V2_VERSION_DRAFT) != 0) {
        ret = -1;
    }
    else if (vn_compat_test_one(PICOQUIC_V1_VERSION, PICOQUIC_INTERNAL_TEST_VERSION_1) == 0) {
        ret = -1;
    }

    return ret;
}

/* Test setting the SNI
 */

int tls_api_sni_test()
{
    return tls_api_test_with_loss(NULL, 0, PICOQUIC_TEST_SNI, PICOQUIC_TEST_ALPN);
}

/* The ALPN test checks that the connection fails if no ALPN is specified.
 */

int tls_api_alpn_test()
{
    int ret = tls_api_test_with_loss(NULL, 0, PICOQUIC_TEST_SNI, NULL);

    if (ret == PICOQUIC_ERROR_NO_ALPN_PROVIDED) {
        ret = 0;
    } else if (ret == 0) {
        DBG_PRINTF("ALPN test succeeds while no ALPN is specified, ret = 0x%x", ret);
        ret = -1;
    }
    else {
        DBG_PRINTF("ALPN test does not return expected error code, ret = 0x%x", ret);
        ret = -1;
    }
    return ret;
}

int tls_api_wrong_alpn_test()
{
    uint64_t simulated_time = 0;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    int ret = tls_api_init_ctx(&test_ctx, 0, PICOQUIC_TEST_SNI, PICOQUIC_TEST_WRONG_ALPN, &simulated_time, NULL, NULL, 0, 0, 0);

    if (ret == 0) {
        /* By default, client and servers are using the same ALPN. Correct that on the server side 
         * so we can test the wrong ALPN condition */
        free((void*)test_ctx->qserver->default_alpn);
        test_ctx->qserver->default_alpn = picoquic_string_duplicate(PICOQUIC_TEST_ALPN);
    }

    if (ret != 0)
    {
        DBG_PRINTF("Could not create the QUIC test contexts for V=%x\n", 0);
    }

    if (ret == 0) {
        ret = tls_api_connection_loop(test_ctx, 0, 0, &simulated_time);

        if (ret == 0)
        {
            if (test_ctx->cnx_client != NULL) {
                if (test_ctx->cnx_client->cnx_state == picoquic_state_disconnected &&
                    test_ctx->cnx_client->remote_error == PICOQUIC_TLS_ALERT_WRONG_ALPN) {
                    ret = 0;
                }
                else {
                    DBG_PRINTF("Connection loop returns 0x%" PRIx64, test_ctx->cnx_client->remote_error);
                    ret = -1;
                }
            }
            else {
                DBG_PRINTF("%s", "Could not establish a client connection");
                ret = -1;
            }
        }
    }

    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }

    return ret;
}

/*
 * Scenario based transmission tests.
 */

int tls_api_one_scenario_init_ex(
    picoquic_test_tls_api_ctx_t** p_test_ctx, uint64_t * simulated_time,
    uint32_t proposed_version,
    picoquic_tp_t * client_params, picoquic_tp_t * server_params,
    picoquic_connection_id_t * icid, int cid_zero)
{
    int ret = tls_api_init_ctx_ex(p_test_ctx,
        (proposed_version == 0) ? PICOQUIC_INTERNAL_TEST_VERSION_1 : proposed_version,
        PICOQUIC_TEST_SNI, PICOQUIC_TEST_ALPN, simulated_time, NULL, NULL, 0, 1, 0, icid);

    if (ret != 0) {
        DBG_PRINTF("Could not create the QUIC test contexts for V=%x\n", proposed_version);
    }
    else if (*p_test_ctx == NULL || (*p_test_ctx)->cnx_client == NULL || (*p_test_ctx)->qserver == NULL) {
        DBG_PRINTF("%s", "Connections where not properly created!\n");
        ret = -1;
    }

    if (ret == 0 && client_params != NULL) {
        picoquic_set_transport_parameters((*p_test_ctx)->cnx_client, client_params);
    }

    if (ret == 0 && server_params != NULL) {
        ret = picoquic_set_default_tp((*p_test_ctx)->qserver, server_params);
        if (server_params->prefered_address.ipv4Port != 0 ||
            server_params->prefered_address.ipv6Port != 0) {
            /* If testing server migration, disable address check */
            (*p_test_ctx)->server_use_multiple_addresses = 1;
        }
    }

    return ret;
}

int tls_api_one_scenario_init(
    picoquic_test_tls_api_ctx_t** p_test_ctx, uint64_t* simulated_time,
    uint32_t proposed_version,
    picoquic_tp_t* client_params, picoquic_tp_t* server_params)
{
    return tls_api_one_scenario_init_ex(p_test_ctx, simulated_time, proposed_version, client_params, server_params, NULL, 0);
}

int tls_api_one_scenario_verify(picoquic_test_tls_api_ctx_t* test_ctx)
{
    int ret = 0;

    if (test_ctx->server_callback.error_detected) {
        ret = -1;
    }
    else if (test_ctx->client_callback.error_detected) {
        ret = -1;
    }
    else {
        for (size_t i = 0; ret == 0 && i < test_ctx->nb_test_streams; i++) {
            if (test_ctx->test_stream[i].q_recv_nb != test_ctx->test_stream[i].q_len) {
                ret = -1;
            }
            else if (test_ctx->test_stream[i].r_recv_nb != test_ctx->test_stream[i].r_len) {
                ret = -1;
            }
            else if (test_ctx->test_stream[i].q_received == 0 || test_ctx->test_stream[i].r_received == 0) {
                ret = -1;
            }
        }

        if (test_ctx->stream0_sent != test_ctx->stream0_target ||
            test_ctx->stream0_sent != test_ctx->stream0_received) {
            ret = -1;
        }

        if (ret == 0 && test_ctx->qclient->nb_data_nodes_allocated > test_ctx->qclient->nb_data_nodes_in_pool) {
            ret = -1;
        } else 
        if (ret == 0 && test_ctx->qserver->nb_data_nodes_allocated > test_ctx->qserver->nb_data_nodes_in_pool) {
            ret = -1;
        }
    }
    if (ret != 0)
    {
        DBG_PRINTF("Test scenario verification returns %d\n", ret);
    }

    return ret;
}

int tls_api_one_scenario_body_connect(picoquic_test_tls_api_ctx_t* test_ctx,
    uint64_t * simulated_time, size_t stream0_target, uint64_t max_data, uint64_t queue_delay_max)
{
    int ret = picoquic_start_client_cnx(test_ctx->cnx_client);
    test_ctx->loss_mask_default = 0;

    if (ret != 0)
    {
        DBG_PRINTF("%s", "Could not initialize connection for the client\n");
    }
    else {
        ret = tls_api_connection_loop(test_ctx, &test_ctx->loss_mask_default, queue_delay_max, simulated_time);

        if (ret != 0)
        {
            DBG_PRINTF("Connection loop returns error %d\n", ret);
        }
    }

    if (ret == 0 && max_data != 0) {
        test_ctx->cnx_client->maxdata_local = max_data;
        test_ctx->cnx_client->maxdata_remote = max_data;
        test_ctx->cnx_server->maxdata_local = max_data;
        test_ctx->cnx_server->maxdata_remote = max_data;
    }

    return ret;
}

int tls_api_one_scenario_body_verify(picoquic_test_tls_api_ctx_t* test_ctx,
    uint64_t * simulated_time,
    uint64_t max_completion_microsec)
{

    uint64_t close_time = 0;
    int ret = tls_api_one_scenario_verify(test_ctx);

    if (ret == 0) {
        close_time = *simulated_time;
        tls_api_attempt_to_close(test_ctx, simulated_time);
        if (ret != 0)
        {
            DBG_PRINTF("Attempt to close returns %d\n", ret);
        }
    }

    if (ret == 0 && max_completion_microsec != 0) {
        uint64_t completion_time = close_time - test_ctx->cnx_client->start_time;
        if (completion_time > max_completion_microsec)
        {
            DBG_PRINTF("Scenario completes in %llu microsec, more than %llu, %llu losses, %llu spurious\n",
                (unsigned long long)completion_time, (unsigned long long)max_completion_microsec,
                test_ctx->cnx_server->nb_retransmission_total, test_ctx->cnx_server->nb_spurious);
             ret = -1;
        }
    }

    return ret;
}

int tls_api_one_scenario_body_ex(picoquic_test_tls_api_ctx_t* test_ctx,
    uint64_t * simulated_time,
    test_api_stream_desc_t* scenario, size_t sizeof_scenario, size_t stream0_target,
    uint64_t init_loss_mask, uint64_t max_data, uint64_t queue_delay_max,
    uint64_t max_completion_microsec, size_t nb_link_states, test_vary_link_spec_t* link_state)
{
    int ret = tls_api_one_scenario_body_connect(test_ctx, simulated_time, stream0_target,
        max_data, queue_delay_max);

    /* Prepare to send data */
    if (ret == 0) {
        test_ctx->stream0_target = stream0_target;
        test_ctx->loss_mask_default = init_loss_mask;
        ret = test_api_init_send_recv_scenario(test_ctx, scenario, sizeof_scenario);

        if (ret != 0)
        {
            DBG_PRINTF("Init send receive scenario returns %d\n", ret);
        }
    }

    /* Perform a data sending loop */
    if (ret == 0) {
        ret = tls_api_data_sending_loop_ex(test_ctx, &test_ctx->loss_mask_default, simulated_time, 0,
            nb_link_states, link_state);

        if (ret != 0)
        {
            DBG_PRINTF("Data sending loop returns %d\n", ret);
        }
    }

    if (ret == 0) {
        ret = tls_api_one_scenario_body_verify(test_ctx, simulated_time, max_completion_microsec);
    }

    return ret;
}

int tls_api_one_scenario_body(picoquic_test_tls_api_ctx_t* test_ctx,
    uint64_t* simulated_time,
    test_api_stream_desc_t* scenario, size_t sizeof_scenario, size_t stream0_target,
    uint64_t init_loss_mask, uint64_t max_data, uint64_t queue_delay_max,
    uint64_t max_completion_microsec)
{
    return tls_api_one_scenario_body_ex(test_ctx, simulated_time, scenario, sizeof_scenario,
        stream0_target, init_loss_mask, max_data, queue_delay_max, max_completion_microsec,
        0, NULL);
}


int tls_api_one_scenario_test(test_api_stream_desc_t* scenario,
    size_t sizeof_scenario, size_t stream0_target,
    uint64_t init_loss_mask, uint64_t max_data, uint64_t queue_delay_max,
    uint32_t proposed_version, uint64_t max_completion_microsec,
    picoquic_tp_t * client_params, picoquic_tp_t * server_params) 
{
    uint64_t simulated_time = 0;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;

    int ret = tls_api_one_scenario_init(&test_ctx, &simulated_time,
        proposed_version, client_params, server_params);

    if (ret == 0) {
        ret = tls_api_one_scenario_body(test_ctx, &simulated_time,
            scenario, sizeof_scenario, stream0_target, init_loss_mask, max_data, queue_delay_max,
            max_completion_microsec);
    }

    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }

    return ret;
}

int tls_api_oneway_stream_test()
{
    return tls_api_one_scenario_test(test_scenario_oneway, sizeof(test_scenario_oneway), 0, 0, 0, 0, 0, 75000, NULL, NULL);
}

int tls_api_q_and_r_stream_test()
{
    return tls_api_one_scenario_test(test_scenario_q_and_r, sizeof(test_scenario_q_and_r), 0, 0, 0, 0, 0, 75000, NULL, NULL);
}

int tls_api_q2_and_r2_stream_test()
{
    return tls_api_one_scenario_test(test_scenario_q2_and_r2, sizeof(test_scenario_q2_and_r2), 0, 0, 0, 0, 0, 86000, NULL, NULL);
}

int tls_api_very_long_stream_test()
{
    return tls_api_one_scenario_test(test_scenario_very_long, sizeof(test_scenario_very_long), 0, 0, 0, 0, 0, 1000000, NULL, NULL);
}

int tls_api_very_long_max_test()
{
    return tls_api_one_scenario_test(test_scenario_very_long, sizeof(test_scenario_very_long), 0, 0, 128000, 0, 0, 1000000, NULL, NULL);
}

int tls_api_very_long_with_err_test()
{
    return tls_api_one_scenario_test(test_scenario_very_long, sizeof(test_scenario_very_long), 0, 0x30000, 128000, 0, 0, 2210000, NULL, NULL);
}

int tls_api_very_long_congestion_test()
{
    return tls_api_one_scenario_test(test_scenario_very_long, sizeof(test_scenario_very_long), 0, 0, 128000, 20000, 0, 1000000, NULL, NULL);
}

int unidir_test()
{
    return tls_api_one_scenario_test(test_scenario_unidir, sizeof(test_scenario_unidir), 0, 0, 128000, 10000, 0, 100000, NULL, NULL);
}

int many_short_loss_test()
{
    return tls_api_one_scenario_test(test_scenario_more_streams, sizeof(test_scenario_more_streams), 0, 0x882818A881288848ull, 16000, 2000, 0, 0, NULL, NULL);
}

/* Implicit ACK test: verify that the queues of initial and
 * handshake packets are empty after reaching the ready state
 */

int implicit_ack_test()
{
    uint64_t simulated_time = 0;
    uint64_t loss_mask = 0;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    int ret = tls_api_init_ctx(&test_ctx, 0, PICOQUIC_TEST_SNI, PICOQUIC_TEST_ALPN, &simulated_time, NULL, NULL, 0, 0, 0);
    picoquic_packet_context_enum pc[2] = { picoquic_packet_context_initial, picoquic_packet_context_handshake };

    if (ret == 0) {
        ret = tls_api_connection_loop(test_ctx, &loss_mask, 0, &simulated_time);
    }

    if (ret == 0) {
        ret = wait_client_connection_ready(test_ctx, &simulated_time);
    }

    for (int i = 0; ret == 0 && i < 2; i++) {
        if (test_ctx->cnx_client->pkt_ctx[pc[i]].pending_first != NULL) {
            DBG_PRINTF("Retransmit queue type %d not empty on client", pc[i]);
            ret = -1;
        }
        else if (test_ctx->cnx_server->pkt_ctx[pc[i]].pending_first != NULL) {
            DBG_PRINTF("Retransmit queue type %d not empty on server", pc[i]);
            ret = -1;
        }
        else if (test_ctx->cnx_client->pkt_ctx[pc[i]].retransmitted_oldest != NULL) {
            DBG_PRINTF("Retransmitted queue type %d not empty on client", pc[i]);
            ret = -1;
        }
        else if (test_ctx->cnx_server->pkt_ctx[pc[i]].pending_first != NULL) {
            DBG_PRINTF("Retransmitted queue type %d not empty on server", pc[i]);
            ret = -1;
        }
    }

    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }

    return ret;
}

/*
 * Server reset test.
 * Establish a connection between server and client.
 * When the connection is established, delete the server connection, and prime the client
 * to send data.
 * Expected result: the client sends a packet with a stream frame, the server responds
 * with a stateless reset, the client closes its own connection.
 */

int stateless_reset_test()
{
    uint64_t simulated_time = 0;
    uint64_t loss_mask = 0;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    int ret = tls_api_init_ctx(&test_ctx, 0, PICOQUIC_TEST_SNI, PICOQUIC_TEST_ALPN, &simulated_time, NULL, NULL, 0, 0, 0);
    uint8_t buffer[128];
    int was_active = 0;

    if (ret == 0) {
        ret = tls_api_connection_loop(test_ctx, &loss_mask, 0, &simulated_time);
    }

    if (ret == 0) {
        ret = wait_client_connection_ready(test_ctx, &simulated_time);
    }

    /* verify that client and server have the same reset secret */
    if (ret == 0) {
        uint8_t ref_secret[PICOQUIC_RESET_SECRET_SIZE];

        (void)picoquic_create_cnxid_reset_secret(test_ctx->qserver,
            &test_ctx->cnx_client->path[0]->p_remote_cnxid->cnx_id, ref_secret);
        if (memcmp(test_ctx->cnx_client->path[0]->p_remote_cnxid->reset_secret, ref_secret,
            PICOQUIC_RESET_SECRET_SIZE) != 0) {
            ret = -1;
        }
    }

    /* Prepare to reset */
    if (ret == 0) {
        picoquic_delete_cnx(test_ctx->cnx_server);
        test_ctx->cnx_server = NULL;

        memset(buffer, 0xaa, sizeof(buffer));
        ret = picoquic_add_to_stream(test_ctx->cnx_client, 4,
            buffer, sizeof(buffer), 1);
    }

    /* Perform a couple rounds of sending data */
    for (int i = 0; ret == 0 && i < 64 && test_ctx->cnx_client->cnx_state != picoquic_state_disconnected; i++) {
        was_active = 0;

        ret = tls_api_one_sim_round(test_ctx, &simulated_time, 0, &was_active);
    }

    /* Client should now be in state disconnected */
    if (ret == 0 && test_ctx->cnx_client->cnx_state != picoquic_state_disconnected) {
        ret = -1;
    }

    if (ret == 0 && test_ctx->reset_received == 0) {
        ret = -1;
    }
    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }

    return ret;
}

/*
* Server reset negative test.
* Establish a connection between server and client.
* When the connection is established, fabricate a bogus server reset and
* send it to the client.
* Expected result: the client ignores the bogus reset.
*/
int stateless_reset_bad_test()
{
    uint64_t simulated_time = 0;
    uint64_t loss_mask = 0;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    int ret = tls_api_init_ctx(&test_ctx, 0, PICOQUIC_TEST_SNI, PICOQUIC_TEST_ALPN, &simulated_time, NULL, NULL, 0, 0, 0);
    uint8_t buffer[256];

    if (ret == 0) {
        ret = tls_api_connection_loop(test_ctx, &loss_mask, 0, &simulated_time);
    }

    /* Prepare the bogus reset */
    if (ret == 0) {
        size_t byte_index = 0;
        buffer[byte_index++] = 0x41;
        byte_index += picoquic_format_connection_id(&buffer[byte_index], sizeof(buffer) - byte_index, test_ctx->cnx_client->path[0]->p_local_cnxid->cnx_id);
        memset(buffer + byte_index, 0xcc, sizeof(buffer) - byte_index);
        
        /* Submit bogus request to client */
        ret = picoquic_incoming_packet(test_ctx->qclient, buffer, sizeof(buffer),
            (struct sockaddr*)(&test_ctx->server_addr),
            (struct sockaddr*)(&test_ctx->client_addr), 0, test_ctx->recv_ecn_client,
            simulated_time);
    }

    /* check that the client is still up */
    if (ret == 0 && !TEST_CLIENT_READY) {
        ret = -1;
    }

    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }

    return ret;
}

/*
* Server reset client test.
* Establish a connection between server and client.
* Get the connection almost established on server,
* fabricate a bogus stateless reset and
* send it from the client to the server.
* Expected result: the server connection ignores the bogus reset.
*/
int stateless_reset_client_test()
{
    uint64_t simulated_time = 0;
    uint64_t loss_mask = 0;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    int ret = tls_api_init_ctx(&test_ctx, 0, PICOQUIC_TEST_SNI, PICOQUIC_TEST_ALPN, &simulated_time, NULL, NULL, 0, 0, 0);
    uint8_t buffer[256];

    if (ret == 0) {
        ret = tls_api_connection_loop(test_ctx, &loss_mask, 0, &simulated_time);
    }

    /* Prepare the bogus reset */
    if (ret == 0) {
        size_t byte_index = 0;
        buffer[byte_index++] = 0x41;
        /* Copy the client ID */
        byte_index += picoquic_format_connection_id(&buffer[byte_index], sizeof(buffer) - byte_index, test_ctx->cnx_server->path[0]->p_local_cnxid->cnx_id);
        /* Change one byte of the client ID */
        if (byte_index > 5) {
            buffer[5] ^= 0xff;
        }
        else {
            buffer[1] ^= 0xff;
        }
        /* rest of packet is null */
        memset(buffer + byte_index, 0xcc, sizeof(buffer) - byte_index);

        /* Submit bogus request to server */
        ret = picoquic_incoming_packet(test_ctx->qserver, buffer, sizeof(buffer),
            (struct sockaddr*)(&test_ctx->client_addr),
            (struct sockaddr*)(&test_ctx->server_addr), 0, test_ctx->recv_ecn_server,
            simulated_time);
    }

    /* check that the server is still up */
    if (ret == 0 && test_ctx->cnx_server != NULL && test_ctx->cnx_server->cnx_state > picoquic_state_ready) {
        ret = -1;
    }

    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }

    return ret;
}


/*
* Server reset handshake test.
* Verify that the server does not send a reset in response to
* a bogus long header packet
*/
int stateless_reset_handshake_test()
{
    uint64_t simulated_time = 0;
    uint64_t loss_mask = 0;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    int ret = tls_api_init_ctx(&test_ctx, 0, PICOQUIC_TEST_SNI, PICOQUIC_TEST_ALPN, &simulated_time, NULL, NULL, 0, 0, 0);
    uint8_t buffer[256];

    if (ret == 0) {
        ret = tls_api_connection_loop(test_ctx, &loss_mask, 0, &simulated_time);
    }

    /* Prepare the bogus reset */
    if (ret == 0) {
        size_t byte_index = 0;
        buffer[byte_index++] = 0xff;
        buffer[byte_index++] = test_ctx->cnx_server->path[0]->p_local_cnxid->cnx_id.id_len;
        buffer[byte_index++] = test_ctx->cnx_server->path[0]->p_remote_cnxid->cnx_id.id_len;
        /* Copy the client ID */
        byte_index += picoquic_format_connection_id(&buffer[byte_index], sizeof(buffer) - byte_index, test_ctx->cnx_server->path[0]->p_local_cnxid->cnx_id);
        /* Change one byte of the client ID */
        if (byte_index > 5) {
            buffer[5] ^= 0xff;
        }
        else {
            buffer[1] ^= 0xff;
        }
        /* Copy the server ID */
        byte_index += picoquic_format_connection_id(&buffer[byte_index], sizeof(buffer) - byte_index, test_ctx->cnx_server->path[0]->p_remote_cnxid->cnx_id);
        /* rest of packet is null */
        memset(buffer + byte_index, 0xcc, sizeof(buffer) - byte_index);

        /* Submit bogus request to server */
        ret = picoquic_incoming_packet(test_ctx->qserver, buffer, sizeof(buffer),
            (struct sockaddr*)(&test_ctx->client_addr),
            (struct sockaddr*)(&test_ctx->server_addr), 0, test_ctx->recv_ecn_server,
            simulated_time);
    }

    /* check that the server is still up */
    if (ret == 0 && test_ctx->cnx_server != NULL && test_ctx->cnx_server->cnx_state > picoquic_state_ready) {
        ret = -1;
    }
    /* Check that no stateless packet is queued */
    if (ret == 0 && test_ctx->qserver->pending_stateless_packet != NULL) {
        ret = -1;
    }

    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }

    return ret;
}

/* Immediate close. Test that a server can issue an immediate close,
 * and that the client eventually closes the connection. 
 */

int immediate_close_test()
{
    uint64_t simulated_time = 0;
    uint64_t loss_mask = 0;
    uint64_t nb_packet_sent_before_close = 0;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    int ret = tls_api_init_ctx(&test_ctx, 0, PICOQUIC_TEST_SNI, PICOQUIC_TEST_ALPN, &simulated_time, NULL, NULL, 0, 0, 0);
    uint8_t buffer[128];
    int was_active = 0;

    if (ret == 0) {
        ret = tls_api_connection_loop(test_ctx, &loss_mask, 0, &simulated_time);
    }

    if (ret == 0) {
        ret = wait_client_connection_ready(test_ctx, &simulated_time);
    }

    /* Immediate close */
    if (ret == 0) {
        nb_packet_sent_before_close = test_ctx->cnx_server->nb_packets_sent;
        picoquic_close_immediate(test_ctx->cnx_server);
    }
    /* Client sends some data, in order to test the connection */
    if (ret == 0) {
        memset(buffer, 0xaa, sizeof(buffer));
        ret = picoquic_add_to_stream(test_ctx->cnx_client, 4,
            buffer, sizeof(buffer), 1);
    }

    /* Perform a couple rounds of sending data */
    for (int i = 0; ret == 0 && i < 256 ; i++) {
        was_active = 0;

        ret = tls_api_one_sim_round(test_ctx, &simulated_time, 0, &was_active);
        if (test_ctx->cnx_client->cnx_state >= picoquic_state_disconnected) {
            /* Client has noticed the disconnect */
            ret = 0;
            break;
        }
    }

    /* Client and server should now be in state disconnected */
    if (ret == 0 && test_ctx->cnx_client->cnx_state != picoquic_state_disconnected) {
        ret = -1;
    }

    if (ret == 0 && test_ctx->cnx_server != NULL){
        if (test_ctx->cnx_server->cnx_state != picoquic_state_disconnected) {
            ret = -1;
        }
        else if (nb_packet_sent_before_close != test_ctx->cnx_server->nb_packets_sent)
        {
            ret = -1;
        }
    }

    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }

    return ret;
}

/*
 * verify that a connection is correctly established after a stateless retry,
 * and then verify that retyr is not used if tickets are available.
 */

static char const* token_file_name = "retry_tests_tokens.bin";

int tls_retry_token_test_one(int token_mode, int dup_token)
{
    int ret = 0;
    uint64_t simulated_time = 0;
    uint64_t loss_mask = 0;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    /* ensure that the token file is empty */
    FILE* F = picoquic_file_open(token_file_name, "wb");
    if (F == NULL) {
        ret = -1;
    }
    else {
        F = picoquic_file_close(F);
    }
    
    if (ret == 0) {
        ret = tls_api_init_ctx(&test_ctx, 0, PICOQUIC_TEST_SNI, PICOQUIC_TEST_ALPN,
            &simulated_time, NULL, token_file_name, 0, 0, 0);
    }

    if (ret == 0) {
        /* Set the server in requested token mode -- either check or merely provide */
        picoquic_set_cookie_mode(test_ctx->qserver, token_mode);
        /* Try the connection */
        ret = tls_api_connection_loop(test_ctx, &loss_mask, 0, &simulated_time);
    }

    if (ret == 0) {
        /* Wait some time, so the connection can stabilize to ready state */
        ret = tls_api_synch_to_empty_loop(test_ctx, &simulated_time, 2048, PICOQUIC_NB_PATH_TARGET, 1);
    }

    if (ret == 0) {
        ret = tls_api_attempt_to_close(test_ctx, &simulated_time);
    }

    /* Now we remove the client connection and create a new one.
     * Force the retry token flag, in case it was not set before, to ensure token retry mode.
     */
    if (ret == 0) {
        picoquic_delete_cnx(test_ctx->cnx_client);
        if (test_ctx->cnx_server != NULL) {
            picoquic_delete_cnx(test_ctx->cnx_server);
            test_ctx->cnx_server = NULL;
        }
        /* If testing token duplication, simulate previous use of token */
        if (dup_token) {
            uint8_t * token = NULL;
            uint16_t token_length = 0;

            ret = picoquic_get_token(test_ctx->qclient,
                PICOQUIC_TEST_SNI, (uint16_t)strlen(PICOQUIC_TEST_SNI),
                NULL, 0,
                &token, &token_length, 0);
            if (ret != 0){
                DBG_PRINTF("picoquic_get_token returns %d\n", ret);
            }
            else {
                uint8_t text[256];
                size_t text_len = 256;
                int is_new_token = 0;

                ret = picoquic_server_decrypt_retry_token(test_ctx->qserver, (struct sockaddr*) & test_ctx->client_addr,
                    &is_new_token, token, token_length, text, &text_len);
                if (ret != 0) {
                    DBG_PRINTF("cannot decrypt the token, ret= %d\n", ret);
                }
                else if (text_len < 8 ) {
                    DBG_PRINTF("Token too short, len=%z\n", text_len);
                    ret = -1;
                }
                else {
                    uint64_t valid_until = PICOPARSE_64(text);
                    ret = picoquic_registered_token_check_reuse(test_ctx->qserver, token, token_length, valid_until);
                    if (ret != 0) {
                        DBG_PRINTF("Token already registered, ret= %d\n", ret);
                    }
                }
            }
            if (token != NULL) {
                free(token);
            }
        }

        if (ret == 0) {
            test_ctx->qserver->check_token = 1;

            test_ctx->cnx_client = picoquic_create_cnx(test_ctx->qclient,
                picoquic_null_connection_id, picoquic_null_connection_id,
                (struct sockaddr*) & test_ctx->server_addr, simulated_time,
                0, PICOQUIC_TEST_SNI, PICOQUIC_TEST_ALPN, 1);

            if (test_ctx->cnx_client == NULL) {
                ret = -1;
            }
            else {
                ret = picoquic_start_client_cnx(test_ctx->cnx_client);
            }
        }
    }

    if (ret == 0) {
        /* Try the new connection */
        ret = tls_api_connection_loop(test_ctx, &loss_mask, 0, &simulated_time);

        if (dup_token ) {
            if (ret == 0 && test_ctx->cnx_client->cnx_state != picoquic_state_disconnected){
                if (test_ctx->cnx_client->original_cnxid.id_len > 0) {
                    /* Correct behavior, required a new token */
                    ret = tls_api_attempt_to_close(test_ctx, &simulated_time);
                }
                else {
                    ret = -1;
                    DBG_PRINTF("Connection succeeds despite duplicate token, ret= %d\n", ret);
                }
            }
        }
        else {
            if (ret == 0) {
                ret = tls_api_attempt_to_close(test_ctx, &simulated_time);
            }

            if (ret == 0 && test_ctx->cnx_client->original_cnxid.id_len != 0) {
                DBG_PRINTF("Second retry did not use the stored token, odcil len=%d\n",
                    test_ctx->cnx_client->original_cnxid.id_len);
                ret = -1;
            }
        }
    }
    if (ret == 0) {
        /* Not strictly needed, but allows for inspection */
        ret = picoquic_save_tokens(test_ctx->qclient, token_file_name);
    }

    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }

    return ret;
}

int tls_retry_token_test()
{
    int ret = tls_retry_token_test_one(1,0);

    if (ret != 0) {
        DBG_PRINTF("Retry token test returns %d", ret);
    }
    else {
        ret = tls_retry_token_test_one(2,0);

        if (ret != 0) {
            DBG_PRINTF("Provide token test returns %d", ret);
        }
        else {
            ret = tls_retry_token_test_one(1, 1);
            if (ret != 0){
                DBG_PRINTF("Duplicate token test returns %d", ret);
            }
        }
    }

    return ret;
}

/* Unit test of token validation */
int tls_retry_token_valid_test()
{
    int ret = 0;
    int is_new_token = 0;
    struct sockaddr_in addr1, addr2, addr3;
    struct sockaddr* addr[3];
    picoquic_connection_id_t n_cid = picoquic_null_connection_id;
    picoquic_connection_id_t cid1 = { { 1,1,1,1,1,1,1,1}, 8 };
    picoquic_connection_id_t cid2 = { { 2,2,2,2,2,2,2,2,2}, 9 };
    picoquic_connection_id_t* cid[3];
    picoquic_connection_id_t cid_o = { { 3,3,3,3,3,3,3,3}, 8 };
    picoquic_connection_id_t* odcid[2];
    picoquic_connection_id_t odcid_found;
    uint64_t time_base = 10000;
    uint64_t time_delta[4] = { 0, PICOQUIC_TOKEN_DELAY_SHORT, PICOQUIC_TOKEN_DELAY_SHORT + 4000001,
     24ull * 3600ull * 1000000ull + PICOQUIC_TOKEN_DELAY_SHORT + 1000000 };
    uint32_t pn[3] = { 0, 1, 2 };
    uint8_t token_buffer[128];
    size_t token_size;
    int verified;
    picoquic_quic_t * quic = picoquic_create(8, NULL, NULL, NULL, PICOQUIC_TEST_ALPN, NULL, NULL, NULL, NULL, NULL,
        time_base*1000000, NULL, NULL, test_ticket_encrypt_key, sizeof(test_ticket_encrypt_key));

    if (quic == NULL) {
        return -1;
    }

    picoquic_set_test_address(&addr1, 0x01010101, 1234);
    picoquic_set_test_address(&addr2, 0x01010101, 3456);
    picoquic_set_test_address(&addr3, 0x03030303, 1234);
    addr[0] = (struct sockaddr*) & addr1;
    addr[1] = (struct sockaddr*) & addr2;
    addr[2] = (struct sockaddr*) & addr3;
    cid[0] = &cid1;
    cid[1] = &n_cid;
    cid[2] = &cid2;
    odcid[0] = &cid_o;
    odcid[1] = &n_cid;

    /* Test of a connection token
     * - Create a token with test address, time1, cid1, pn1.
     * - Check with time-0 (valid), time1(valid), time2(invalid)
     * - Check with addr1,port1 (valid), addr1,port2 (valid), addr2,port1(invalid)
     * - Check with pn2 (valid), pn1(invalid)
     * - check with cid1 (valid), cid2(invalid)
     */

     /* Test of a new token
      * - Create a token with test address, time1, n_cid, pn1.
      * - Check with time-0 (valid), time1(valid), time2(invalid)
      * - Check with addr1,port1 (valid), addr1,port2 (valid), addr2,port1(invalid)
      * - Check with pn2 (valid), pn1(valid)
      * - check with cid1 (valid), cid2(valid)
      */

    /* Test of an invalid token: valid token with changed bytes */

    for (int token_mode = 0; ret == 0 && token_mode < 2; token_mode++) {
        if (picoquic_prepare_retry_token(quic, addr[0], time_base * 1000000 + time_delta[1], odcid[token_mode],
            cid[token_mode], pn[1],
            token_buffer, sizeof(token_buffer), &token_size) != 0) {
            ret = PICOQUIC_ERROR_MEMORY;
        }

        if (ret == 0) {
            verified = picoquic_verify_retry_token(quic, addr[0], time_base * 1000000 + time_delta[0],
                &is_new_token, &odcid_found, cid[0], pn[2],
                token_buffer, token_size, 0);
            if (verified != 0) {
                DBG_PRINTF("%s", "Token validation fails for normal parameters\n");
                ret = -1;
            }
            else if (token_mode == 0 && picoquic_compare_connection_id(odcid[0], &odcid_found) != 0) {
                DBG_PRINTF("%s", "ODCID validation fails\n");
                ret = -1;
            }
            else if (token_mode == 1 && odcid_found.id_len > 0) {
                DBG_PRINTF("%s", "Spurious ODCID\n");
                ret = -1;
            }
            else if (!is_new_token && odcid[token_mode]->id_len == 0) {
                DBG_PRINTF("%s", "Wrongly recognized as new token\n");
                ret = -1;
            }
            else if (is_new_token && odcid[token_mode]->id_len > 0) {
                DBG_PRINTF("%s", "Wrongly recognized as retry token\n");
                ret = -1;
            }
        }

        if (ret == 0 && picoquic_verify_retry_token(quic, addr[0], time_base * 1000000 + time_delta[2 + token_mode],
            &is_new_token, &odcid_found, cid[0], pn[2],
            token_buffer, token_size, 0) == 0) {
            DBG_PRINTF("%s", "Token validation does not detect elapsed time.\n");
            ret = -1;
        }

        if (ret == 0) {
            verified = picoquic_verify_retry_token(quic, addr[0], time_base * 1000000 + time_delta[0],
                &is_new_token, &odcid_found, cid[2], pn[2],
                token_buffer, token_size, 0);
            if (token_mode == 0 && verified == 0) {
                DBG_PRINTF("%s", "RCID invalidation fails\n");
                ret = -1;
            }
            else if (token_mode == 1 && verified != 0) {
                DBG_PRINTF("%s", "Spurious RCID invalidation\n");
                ret = -1;
            }
        }

        for (int pn_id = 0; ret == 0 && pn_id < 2; pn_id++) {
            verified = picoquic_verify_retry_token(quic, addr[0], time_base * 1000000 + time_delta[0],
                &is_new_token, &odcid_found, cid[0], pn[pn_id],
                token_buffer, token_size, 0);
            if (token_mode == 0 && verified == 0) {
                DBG_PRINTF("%s", "PN invalidation fails\n");
                ret = -1;
            }
            else if (token_mode == 1 && verified != 0) {
                DBG_PRINTF("%s", "Spurious PN invalidation\n");
                ret = -1;
            }
        }

        /* test of an invalid token, overly long */
        if (ret == 0 && token_mode == 0) {
            uint8_t big_token[PICOQUIC_MAX_PACKET_SIZE];
            if (token_size < sizeof(big_token)) {
                memcpy(big_token, token_buffer, token_size);
                memset(big_token + token_size, 0xa5, sizeof(big_token) - token_size);
                verified = picoquic_verify_retry_token(quic, addr[0], time_base * 1000000 + time_delta[0],
                    &is_new_token, &odcid_found, cid[0], pn[2],
                    token_buffer, sizeof(big_token), 0);
                if (verified == 0) {
                    DBG_PRINTF("%s", "Bad length check fails\n");
                    ret = -1;
                }
            }
        }
    }

    picoquic_free(quic);
    return ret;
}

int tls_api_retry_test_one(int large_client_hello)
{
    uint64_t simulated_time = 0;
    const uint64_t target_time = 230000ull;
    uint64_t loss_mask = 0;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    int ret = tls_api_init_ctx(&test_ctx, 0, PICOQUIC_TEST_SNI, PICOQUIC_TEST_ALPN, &simulated_time, NULL, NULL, 0, 1, 0);

    if (ret == 0) {
        if (large_client_hello) {
            test_ctx->cnx_client->test_large_chello = 1;
        }
        ret = picoquic_start_client_cnx(test_ctx->cnx_client);
    }


    if (ret == 0) {
        /* Set the server in HRR/Cookies mode */
        picoquic_set_cookie_mode(test_ctx->qserver, 1);
        /* Try the connection */
        ret = tls_api_connection_loop(test_ctx, &loss_mask, 0, &simulated_time);
    }

    if (ret == 0) {
        ret = tls_api_attempt_to_close(test_ctx, &simulated_time);
    }

    if (ret == 0 && simulated_time > target_time) {
        DBG_PRINTF("Retry test completes in %llu microsec, more than %llu\n", simulated_time, target_time);
        ret = -1;
    }

    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }

    return ret;
}

int tls_api_retry_test()
{
    return tls_api_retry_test_one(0);
}

int tls_api_retry_large_test()
{
    return tls_api_retry_test_one(1);
}
/*
* verify that a connection is correctly established
* if the client does not initially provide a key share
*/

int tls_zero_share_test()
{
    uint64_t simulated_time = 0;
    uint64_t loss_mask = 0;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    int ret = tls_api_init_ctx(&test_ctx, 0, PICOQUIC_TEST_SNI, PICOQUIC_TEST_ALPN, &simulated_time, NULL, NULL, 1, 0, 0);

    if (ret == 0) {
        ret = tls_api_connection_loop(test_ctx, &loss_mask, 0, &simulated_time);
    }

    if (ret == 0) {
        ret = tls_api_attempt_to_close(test_ctx, &simulated_time);
    }

    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }

    return ret;
}


/*
 * Test two successive connections from the same client.
 */

int tls_api_two_connections_test()
{
    uint64_t simulated_time = 0;
    uint64_t loss_mask = 0;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    int ret = tls_api_init_ctx(&test_ctx, 0, PICOQUIC_TEST_SNI, PICOQUIC_TEST_ALPN, &simulated_time, NULL, NULL, 0, 0, 0);

    if (ret == 0) {
        ret = tls_api_connection_loop(test_ctx, &loss_mask, 0, &simulated_time);
    }

    if (ret == 0) {
        /* Verify that the connection is fully established */
        uint64_t target_time = simulated_time + 2000000;

        while (ret == 0 && TEST_CLIENT_READY && TEST_SERVER_READY && simulated_time < target_time) {
            int was_active = 0;
            ret = tls_api_one_sim_round(test_ctx, &simulated_time, target_time, &was_active);
        }

        /* Delete the client connection from the client context,
         * without sending notification to the server */
        while (test_ctx->qclient->cnx_list != NULL) {
            picoquic_delete_cnx(test_ctx->qclient->cnx_list);
        }

        /* Erase the server connection reference */
        test_ctx->cnx_server = NULL;

        /* Create a new connection in the client context */

        test_ctx->cnx_client = picoquic_create_cnx(test_ctx->qclient,
            picoquic_null_connection_id, picoquic_null_connection_id,
            (struct sockaddr*)&test_ctx->server_addr, simulated_time, 0, PICOQUIC_TEST_SNI, PICOQUIC_TEST_ALPN, 1);

        if (test_ctx->cnx_client == NULL) {
            ret = -1;
        }
        else {
            ret = picoquic_start_client_cnx(test_ctx->cnx_client);
        }
    }

    /* Now, restart a connection in the same context */
    if (ret == 0) {
        ret = tls_api_connection_loop(test_ctx, &loss_mask, 0, &simulated_time);
    }

    if (ret == 0) {
        ret = tls_api_attempt_to_close(test_ctx, &simulated_time);
    }

    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }

    return ret;
}

int tls_api_client_first_loss_test()
{
    return tls_api_loss_test(1ull);
}

int tls_api_client_second_loss_test()
{
    return tls_api_loss_test(2ull);
}

int tls_api_server_first_loss_test()
{
    return tls_api_loss_test(14ull);
}

int tls_api_client_losses_test()
{
    return tls_api_loss_test(3ull);
}

int tls_api_server_losses_test()
{
    return tls_api_loss_test(6ull);
}

/*
 * Do a simple test for all supported versions
 */
int tls_api_multiple_versions_test()
{
    int ret = 0;

    for (size_t i = 1; ret == 0 && i < picoquic_nb_supported_versions; i++) {
        ret = tls_api_one_scenario_test(test_scenario_q_and_r, sizeof(test_scenario_q_and_r), 0, 0, 0, 0,
            picoquic_supported_versions[i].version, 0, NULL, NULL);
    }

    return ret;
}

/*
 * Keep alive test.
 */

int keep_alive_test_impl(int keep_alive)
{
    uint64_t simulated_time = 0;
    const uint64_t keep_alive_interval = 0; /* Will use the default value */
    uint64_t loss_mask = 0;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    int ret = tls_api_init_ctx(&test_ctx, 0, PICOQUIC_TEST_SNI, PICOQUIC_TEST_ALPN, &simulated_time, NULL, NULL, 0, 0, 0);
    int was_active = 0;

    if (ret == 0 && test_ctx == NULL) {
        return PICOQUIC_ERROR_MEMORY;
    }

    /*
     * setup the connections.
     */

    if (ret == 0) {
        ret = tls_api_connection_loop(test_ctx, &loss_mask, 0, &simulated_time);
    }

    /*
     * Enable keep alive
     */
    if (ret == 0 && keep_alive) {
        picoquic_enable_keep_alive(test_ctx->cnx_client, keep_alive_interval);
    }

    /* Perform rounds of sending data until the requested time has been spent */
    for (int i = 0; ret == 0 && i < 0x10000 && test_ctx->cnx_client->cnx_state != picoquic_state_disconnected ; i++) {
        was_active = 0;

        ret = tls_api_one_sim_round(test_ctx, &simulated_time, 0, &was_active);
        if (simulated_time > 2 * PICOQUIC_MICROSEC_SILENCE_MAX) {
            break;
        }
    }

    /* Check that the status matched the expected value */
    if (test_ctx == NULL || test_ctx->cnx_client == NULL) {
        ret = -1;
    } else if (keep_alive != 0) {
        if (!TEST_CLIENT_READY) {
            ret = -1;
        } else if (simulated_time < 2 * PICOQUIC_MICROSEC_SILENCE_MAX) {
            DBG_PRINTF("Keep alive test concludes after %llu microsecs instead of %llu, ret = %d\n",
                (unsigned long long)simulated_time, (unsigned long long)2 * PICOQUIC_MICROSEC_SILENCE_MAX, ret);
            ret = -1;
        } 
    } else if (keep_alive == 0) {
        /* If keep alive was not activated, reset ret to `0`, as `tls_api_one_sim_round` returns -1
         * when the connection was disconnected.
         */
        ret = test_ctx->cnx_client->cnx_state != picoquic_state_disconnected;
    }

    /* Close the connection */
    if (ret == 0 && test_ctx->cnx_client->cnx_state != picoquic_state_disconnected) {
        ret = tls_api_attempt_to_close(test_ctx, &simulated_time);
    }

    /* Clean up */
    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }

    return ret;
}

int keep_alive_test()
{
    int ret = keep_alive_test_impl(1);

    if (ret == 0) {
        ret = keep_alive_test_impl(0);
    }

    return ret;
}

/*
 * Session resume test.
 */
static char const* ticket_file_name = "resume_tests_tickets.bin";

int session_resume_wait_for_ticket(picoquic_test_tls_api_ctx_t* test_ctx,
    uint64_t * simulated_time) 
{
    int ret = 0;
    uint64_t time_out = *simulated_time + 4000000;
    int nb_trials = 0;
    int nb_inactive = 0;

    while (*simulated_time <time_out &&
        TEST_CLIENT_READY &&
        TEST_SERVER_READY &&
        test_ctx->qclient->p_first_ticket == NULL &&
        nb_trials < 1024 &&
        nb_inactive < 64 &&
        ret == 0){
        int was_active = 0;
        nb_trials++;

        ret = tls_api_one_sim_round(test_ctx, simulated_time, time_out, &was_active);

        if (was_active) {
            nb_inactive = 0;
        }
        else {
            nb_inactive++;
        }
    }
    
    return ret;
}

int session_resume_test()
{
    uint64_t simulated_time = 0;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    char const* sni = PICOQUIC_TEST_SNI;
    char const* alpn = PICOQUIC_TEST_ALPN;
    uint64_t loss_mask = 0;
    int ret = 0;

    /* Initialize an empty ticket store */
    ret = picoquic_save_tickets(NULL, simulated_time, ticket_file_name);

    for (int i = 0; i < 2; i++) {
        /* Set up the context, while setting the ticket store parameter for the client */
        if (ret == 0) {
            ret = tls_api_init_ctx(&test_ctx, 0, sni, alpn, &simulated_time, ticket_file_name, NULL, 0, 0, 0);
        }

        if (ret == 0) {
            test_ctx->cnx_client->max_early_data_size = 0;

            ret = tls_api_connection_loop(test_ctx, &loss_mask, 0, &simulated_time);
        }

        if (ret == 0 && i == 1) {
            /* If resume succeeded, the second connection will have a type "PSK" */
            if (picoquic_tls_is_psk_handshake(test_ctx->cnx_server) == 0 || picoquic_tls_is_psk_handshake(test_ctx->cnx_client) == 0) {
                ret = -1;
            }
        }

        if (ret == 0 && i == 0) {
            /* Before closing, wait for the session ticket to arrive */
            ret = session_resume_wait_for_ticket(test_ctx, &simulated_time);
        }

        if (ret == 0) {
            ret = tls_api_attempt_to_close(test_ctx, &simulated_time);
        }

        /* Verify that the session ticket has been received correctly */
        if (ret == 0) {
            if (test_ctx->qclient->p_first_ticket == NULL) {
                ret = -1;
            } else {
                ret = picoquic_save_tickets(test_ctx->qclient->p_first_ticket, simulated_time, ticket_file_name);
            }
        }
        /* Tear down and free everything */

        if (test_ctx != NULL) {
            tls_api_delete_ctx(test_ctx);
            test_ctx = NULL;
        }
    }

    return ret;
}

/*
 * Zero RTT test. Like the session resume test, but with a twist...
 * Use multipath_init_params procedure to set up parameters for the multipath test.
 */
void multipath_init_params(picoquic_tp_t* test_parameters, int enable_time_stamp);

int zero_rtt_test_one(int use_badcrypt, int hardreset, uint64_t early_loss, 
    unsigned int no_coal, unsigned int long_data, uint64_t extra_delay, int do_multipath)
{
    uint64_t simulated_time = 0;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    char const* sni = PICOQUIC_TEST_SNI;
    char const* alpn = PICOQUIC_TEST_ALPN;
    uint64_t loss_mask = 0;
    uint32_t proposed_version = 0;

    picoquic_tp_t server_parameters = { 0 };
    int ret = 0;

    /* Initialize an empty ticket store */
    ret = picoquic_save_tickets(NULL, simulated_time, ticket_file_name);

    for (int i = 0; i < 2; i++) {
        /* Insert a delay before the second connection attempt */
        if (i == 1) {
            simulated_time += extra_delay;
        }
        /* Set up the context, while setting the ticket store parameter for the client */
        if (ret == 0) {
            ret = tls_api_init_ctx(&test_ctx, 
                (i==0)?0: proposed_version, sni, alpn, &simulated_time, ticket_file_name, NULL, 0, 1,
                (i == 0)?0:use_badcrypt);

            if (ret == 0 && no_coal) {
                test_ctx->qserver->dont_coalesce_init = 1;
            }

            if (ret == 0 && hardreset != 0 && i == 1) {
                picoquic_set_cookie_mode(test_ctx->qserver, 1);
            }

            if (ret == 0 && do_multipath) {
                /* Set the multipath option at both client and server */
                multipath_init_params(&server_parameters, 0);
                picoquic_set_default_tp(test_ctx->qserver, &server_parameters);
                test_ctx->cnx_client->local_parameters.is_multipath_enabled = 1;
                test_ctx->cnx_client->local_parameters.initial_max_path_id = 3;
                test_ctx->cnx_client->local_parameters.enable_time_stamp = 0;
            }

            if (ret == 0) {
                /* Initialize the client connection */
                picoquic_start_client_cnx(test_ctx->cnx_client);
            }
        }

        if (ret == 0 && i == 1) {
            /* set the link delays to 100 ms, for realistic testing */
            test_ctx->c_to_s_link->microsec_latency = 50000ull;
            test_ctx->s_to_c_link->microsec_latency = 50000ull;

            if (long_data) {
                for (uint64_t x = 0; x <= 16; x++) {
                    uint64_t stream_id = 4u * x + 4u;
                    test_ctx->nb_test_streams = (size_t)(x + 1);
                    if (test_api_init_test_stream(&test_ctx->test_stream[x], stream_id, UINT64_MAX, 256, 32) != 0){
                        DBG_PRINTF("Could not initialize data for stream %d", (int)stream_id);
                        ret = -1;
                    }
                    /* Queue an initial frame on each stream */
                    if (picoquic_add_to_stream(test_ctx->cnx_client, stream_id, 
                        test_ctx->test_stream[x].q_src, test_ctx->test_stream[x].q_len, 1) != 0) {
                        DBG_PRINTF("Could not write data for stream %d", (int)stream_id);
                        ret = -1;
                    }
                }
            }
            else {
                uint8_t test_data[8] = { 't', 'e', 's', 't', '0', 'r', 't', 't' };
                /* Queue an initial frame on the client connection */
                if (picoquic_add_to_stream(test_ctx->cnx_client, 0, test_data, sizeof(test_data), 1) != 0) {
                    DBG_PRINTF("Could not write data for stream %d", 0);
                    ret = -1;
                }
            }

            if (early_loss > 0) {
                loss_mask = early_loss;
            }
        }

        if (ret == 0) {
            ret = tls_api_connection_loop(test_ctx, &loss_mask, 0, &simulated_time);

            if (ret != 0) {
                DBG_PRINTF("Zero RTT test (badcrypt: %d, hard: %d), connection %d fails (0x%x)\n",
                    use_badcrypt, hardreset, i, ret);
            }
        }

        if (ret == 0 && use_badcrypt == 0 && hardreset == 0) {
            int rtt_is_available = picoquic_is_0rtt_available(test_ctx->cnx_client);

            if ((rtt_is_available && i == 0) ||
                (!rtt_is_available && i != 0)) {
                ret = -1;
            }
        }

        if (ret == 0 && i == 1) {
            /* If resume succeeded, the second connection will have a type "PSK" */
            if (use_badcrypt == 0 && hardreset == 0 && (
                picoquic_tls_is_psk_handshake(test_ctx->cnx_server) == 0 || 
                picoquic_tls_is_psk_handshake(test_ctx->cnx_client) == 0)) {
                DBG_PRINTF("Zero RTT test (badcrypt: %d, hard: %d), connection %d not PSK.\n",
                    use_badcrypt, hardreset, i);
                ret = -1;
            } else {
                /* run a receive loop until no outstanding data */
                ret = tls_api_synch_to_empty_loop(test_ctx, &simulated_time, 2048, 0, 0);
            }
        }

        if (ret == 0 && i == 1 && do_multipath) {
            /* verify that multipath was negotiated */
            if (!test_ctx->cnx_client->is_multipath_enabled ||
                !test_ctx->cnx_server->is_multipath_enabled) {
                DBG_PRINTF("Zero RTT test, multipath not negotiated (client: %d, server: %d).\n",
                    test_ctx->cnx_client->is_multipath_enabled,
                    test_ctx->cnx_server->is_multipath_enabled);
                ret = -1;
            }
        }

        if (ret == 0) {
            if (i == 0) {
                /* Before closing, wait for the session ticket to arrive */
                ret = session_resume_wait_for_ticket(test_ctx, &simulated_time);
            }
            else {
                /* Before closing, wait for all data to be acknowledged, etc. */
                ret = tls_api_synch_to_empty_loop(test_ctx, &simulated_time, 2048, 0, 1);
            }
        }

        if (ret == 0) {
            ret = tls_api_attempt_to_close(test_ctx, &simulated_time);

            if (ret != 0) {
                DBG_PRINTF("Zero RTT test (badcrypt: %d, hard: %d), connection %d close error (0x%x).\n",
                    use_badcrypt, hardreset, i, ret);
            }
        }

        /* Verify that the 0RTT data was sent and acknowledged */
        if (ret == 0 && i == 1) {
            if (use_badcrypt == 0 && hardreset == 0) {
                if (test_ctx->cnx_client->nb_zero_rtt_sent == 0) {
                    DBG_PRINTF("Zero RTT test (badcrypt: %d, hard: %d), no zero RTT sent.\n",
                        use_badcrypt, hardreset);
                    ret = -1;
                }
                else if (early_loss == 0 &&
                    test_ctx->cnx_client->nb_zero_rtt_acked != test_ctx->cnx_client->nb_zero_rtt_sent) {
                    DBG_PRINTF("Zero RTT test (badcrypt: %d, hard: %d), no zero RTT acked.\n",
                        use_badcrypt, hardreset);
                    ret = -1;
                }
                else if (early_loss == 0 && no_coal && test_ctx->cnx_server != NULL &&
                        test_ctx->cnx_client->nb_zero_rtt_sent != test_ctx->cnx_server->nb_zero_rtt_received) {
                    DBG_PRINTF("Zero RTT test sent %d 0RTT, received %d\n",
                        test_ctx->cnx_client->nb_zero_rtt_sent, test_ctx->cnx_server->nb_zero_rtt_received);
                    ret = -1;
                }
                else if (long_data && test_ctx->cnx_client->nb_zero_rtt_sent < 3) {
                    DBG_PRINTF("Zero RTT long test (badcrypt: %d, hard: %d), only %d zero RTT sent.\n",
                        use_badcrypt, hardreset, (int)test_ctx->cnx_client->nb_zero_rtt_sent);
                    ret = -1;
                }
            } else {
                if (test_ctx->cnx_client->nb_zero_rtt_sent == 0) {
                    DBG_PRINTF("Zero RTT test (badcrypt: %d, hard: %d), no zero RTT sent.\n",
                        use_badcrypt, hardreset);
                    ret = -1;
                }
                else if (early_loss == 0 && hardreset == 0 && test_ctx->cnx_client->nb_zero_rtt_acked != 0) {
                    DBG_PRINTF("Zero RTT test (badcrypt: %d, hard: %d), zero acked, not expected.\n",
                        use_badcrypt, hardreset);
                    ret = -1;
                }
                else if (test_ctx->sum_data_received_at_server == 0) {
                    DBG_PRINTF("Zero RTT test (badcrypt: %d, hard: %d, loss: %d), no data received.\n",
                        use_badcrypt, hardreset, early_loss);
                    ret = -1;
                }
                else if (test_ctx->cnx_client->did_receive_short_initial) {
                    DBG_PRINTF("Zero RTT test (badcrypt: %d, hard: %d), server sent unpadded initial.\n",
                        use_badcrypt, hardreset);
                    ret = -1;
                }
            }
        }

        /* Verify that the session ticket has been received correctly */
        if (ret == 0) {
            if (test_ctx->qclient->p_first_ticket == NULL) {
                DBG_PRINTF("Zero RTT test (badcrypt: %d, hard: %d), cnx %d, no ticket received.\n",
                    use_badcrypt, hardreset, i);
                ret = -1;
            } else {
                ret = picoquic_save_tickets(test_ctx->qclient->p_first_ticket, simulated_time, ticket_file_name);
                if (ret != 0) {
                    DBG_PRINTF("Zero RTT test (badcrypt: %d, hard: %d), cnx %d, ticket save error (0x%x).\n",
                        use_badcrypt, hardreset, i, ret);
                }
            }
        }

        /* Tear down and free everything */
        if (test_ctx != NULL) {
            tls_api_delete_ctx(test_ctx);
            test_ctx = NULL;
        }
    }

    return ret;
}

/* 
* Basic 0-RTT test. Verify that things work in the absence of loss 
*/

int zero_rtt_test()
{
    return zero_rtt_test_one(0, 0, 0, 0, 0, 0, 0);
}

/*
* zero rtt test with losses. Verify that the connection setup works even 
* if packets are lost. The "loss test" indicates which packet will be lost
* during the exchange. As the code stands for draft-13, the EOED is sent in
* a zero RTT packet, the 9th packet on the connection. This order is
* however very dependent on the details of the implementation. To be on the safe
* side, we should repeat the test while emulating the loss of any packet
* between 1 and 16.
*/

int zero_rtt_loss_test()
{
    int ret = 0;

    for (unsigned int i = 1; ret == 0 && i < 16; i++) {
        uint64_t early_loss = 1ull << i;
        ret = zero_rtt_test_one(0, 0, early_loss, 0, 0, 0, 0);
        if (ret != 0) {
            DBG_PRINTF("Zero RTT test fails when packet #%d is lost.\n", i);
        }
    }

    return ret;
}
/*
* Zero Spurious RTT test.
* Check what happens if the client attempts to resume a connection using a bogus ticket.
* This will cause a connection retry of some kind, the 0rtt packet will be lost.
* This is simulated by runnig the zero-rtt code, but using a different
* ticket key for the second server instance.
*/

int zero_rtt_spurious_test()
{
    return zero_rtt_test_one(1, 0, 0, 0, 0, 0, 0);
}

/*
* Zero RTT Retry test.
* Check what happens if the client attempts to resume a connection but the
* server responds with a retry. This is simulated by activating the retry
* mode on the server between the 2 client connections.
*/

int zero_rtt_retry_test()
{
    return zero_rtt_test_one(0, 1, 0, 0, 0, 0, 0);
}

/*
* Zero RTT No Coalesced Packets test
* Check what happens if the server does not coalesce packets.
* We expect the client to send an ACK of the Initial packet, and if
* zero RTT is enabled to add a padded 0-RTT packet
*/

int zero_rtt_no_coal_test()
{
    return zero_rtt_test_one(0, 0, 0, 1, 0, 0, 0);
}

/* Test the robustness of the connection in a zero RTT scenario,
 * which uses a slightly different path than the regular connections.
 * We test that 50 connections succeed in presence of 30% packet drops.
 */

int zero_rtt_many_losses_test()
{
    int ret = 0;
    uint64_t random_context = 0x1055ca45c001babaull;

    for (int i = 0; ret == 0 && i < 50; i++)
    {
        uint64_t loss_mask = 0;

        for (int j = 0; j < 64; j++)
        {
            loss_mask <<= 1;

            if (picoquic_test_uniform_random(&random_context, 1000) < 300) {
                loss_mask |= 1;
            }
        }

        ret = zero_rtt_test_one(0, 0, loss_mask, 0, 0, 0, 0);
        if (ret != 0) {
            DBG_PRINTF("Handshake fails for mask %d, mask = %llx", i, (unsigned long long)loss_mask);
        }
    }
    return ret;
}

/*
* 0-RTT long test. Verify that the client can send several 0-RTT packets
*/

int zero_rtt_long_test()
{
    return zero_rtt_test_one(0, 0, 0, 0, 1, 0, 0);
}

/*
* 0-RTT delay test. Verify that the tickets as old as the specified delay are still accepted.
*/

int zero_rtt_delay_test()
{
    int ret = 0;
    int bad_ret;
    const uint64_t nominal_delay_sec = 100000;
    const uint64_t nominal_delay = nominal_delay_sec * 1000000;

    bad_ret = zero_rtt_test_one(0, 0, 0, 0, 1, nominal_delay + 1000000, 0);
    if (bad_ret == 0) {
        DBG_PRINTF("Zero RTT succeed despite delay = %" PRIu64, " + 1 second.", nominal_delay_sec);
        ret = -1;
    }
    else {
        ret = zero_rtt_test_one(0, 0, 0, 0, 1, nominal_delay - 2000000, 0);
        if (ret != 0) {
            DBG_PRINTF("Zero RTT fails for delay = %" PRIu64, " - 2 seconds.", nominal_delay_sec);
        }
    }

    return ret;
}
/*
 * Stop sending test. Start a long transmission, but after receiving some bytes,
 * send a stop sending request. Then ask for another transmission. The
 * test succeeds if only few bytes of the first are received, and all bytes
 * of the second.
 * 
 * The same code is used to test the "stream discard" test, creates a reset
 * and a stop sending in a single call.
 */

int stop_sending_test_one(int discard, int reset_loss)
{
    uint64_t simulated_time = 0;
    const uint64_t stop_sending_latency = 100000;
    uint64_t loss_mask = 0x0F0F0F0F0F000000ull;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    int ret = tls_api_init_ctx(&test_ctx, PICOQUIC_INTERNAL_TEST_VERSION_1,
        PICOQUIC_TEST_SNI, PICOQUIC_TEST_ALPN, &simulated_time, NULL, NULL, 0, 0, 0);
    int nb_initial_loop = 0;

    if (ret == 0) {
        /* Set long delays, in order to test potential leaks of node structure */
        test_ctx->c_to_s_link->microsec_latency = stop_sending_latency;
        test_ctx->s_to_c_link->microsec_latency = stop_sending_latency;
    }

    if (ret == 0) {
        ret = tls_api_connection_loop(test_ctx, &loss_mask, 0, &simulated_time);
    }

    /* Prepare to send data */
    if (ret == 0) {
        ret = test_api_init_send_recv_scenario(test_ctx, test_scenario_stop_sending, sizeof(test_scenario_stop_sending));
    }

    /* Perform a data sending loop for a few rounds, until some bytes are received on the first stream */
    while (ret == 0 && nb_initial_loop < 64) {
        nb_initial_loop++;

        ret = tls_api_data_sending_loop(test_ctx, &loss_mask, &simulated_time, 16);

        if (test_ctx->test_stream[0].r_recv_nb != 0) {
            break;
        }
    }

    /* issue the stop sending command */
    if (ret == 0 && test_ctx->cnx_client != NULL) {
        if (discard) {
            ret = picoquic_discard_stream(test_ctx->cnx_client, test_scenario_stop_sending[0].stream_id, 1);
            /* discarding the stream causes end of notifications, so we
             * simulate a reset notification */
            if (test_api_callback(test_ctx->cnx_client, test_scenario_stop_sending[0].stream_id,
                NULL, 0, picoquic_callback_stream_reset, (void*)&test_ctx->client_callback, NULL) != 0) {
                ret = -1;
            }
        }
        else {
            ret = picoquic_stop_sending(test_ctx->cnx_client, test_scenario_stop_sending[0].stream_id, 1);
        }
    }

    /* resume the sending scenario */
    if (ret == 0) {
        if (reset_loss) {
            /* Mask is calibrated to cause loss of the reset packet.
             * This could be replaced by a specialized wait loop up to the
             * point when the stop sending packet has been received.
             */
            loss_mask = 0x00FC0000000ull;
        }
        ret = tls_api_data_sending_loop(test_ctx, &loss_mask, &simulated_time, 0);
    }

    if (ret == 0) {
        if (test_ctx->server_callback.error_detected) {
            ret = -1;
        } else if (test_ctx->client_callback.error_detected) {
            ret = -1;
        } else {
            for (size_t i = 0; ret == 0 && i < test_ctx->nb_test_streams; i++) {
                if (test_ctx->test_stream[i].q_recv_nb != test_ctx->test_stream[i].q_len) {
                    ret = -1;
                } else if (i == 0 && test_ctx->test_stream[i].r_recv_nb == test_ctx->test_stream[i].r_len) {
                    ret = -1;
                } else if (i != 0 && test_ctx->test_stream[i].r_recv_nb != test_ctx->test_stream[i].r_len) {
                    ret = -1;
                } else if (test_ctx->test_stream[i].q_received == 0 || test_ctx->test_stream[i].r_received == 0) {
                    ret = -1;
                }
            }
        }
    }

    if (ret == 0 && test_ctx->qclient->nb_data_nodes_allocated > test_ctx->qclient->nb_data_nodes_in_pool) {
        ret = -1;
    }
    else if (ret == 0 && test_ctx->qserver->nb_data_nodes_allocated > test_ctx->qserver->nb_data_nodes_in_pool) {
        ret = -1;
    }

    if (ret == 0) {
        ret = picoquic_close(test_ctx->cnx_client, 0);
    }

    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }

    return ret;
}

int stop_sending_test()
{
    int ret = stop_sending_test_one(0, 0);
    return ret;
}

int stop_sending_loss_test()
{
    int ret = stop_sending_test_one(0, 1);
    return ret;
}

int discard_stream_test()
{
    int ret = stop_sending_test_one(1, 0);
    return ret;
}

/*
* MTU discovery tests. Perform a moderate transmission.
* Verify that MTU was properly set to expected value,
* according to the specified option.
*/

int mtu_discovery_test_one(picoquic_pmtud_policy_enum pmtud_policy, 
    size_t mtu_expected_client, size_t mtu_expected_server,
    test_api_stream_desc_t * scenario, size_t scenario_size,
    uint32_t mtu_max)
{
    uint64_t simulated_time = 0;
    uint64_t loss_mask = 0;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    int ret = tls_api_init_ctx(&test_ctx, PICOQUIC_INTERNAL_TEST_VERSION_1,
        PICOQUIC_TEST_SNI, PICOQUIC_TEST_ALPN, &simulated_time, NULL, NULL, 0, 0, 0);

    if (ret == 0) {
        picoquic_set_default_pmtud_policy(test_ctx->qserver, pmtud_policy);
        picoquic_cnx_set_pmtud_policy(test_ctx->cnx_client, pmtud_policy);
        if (mtu_max > 0) {
            picoquic_set_mtu_max(test_ctx->qserver, mtu_max);
        }
    }

    if (ret == 0) {
        ret = tls_api_connection_loop(test_ctx, &loss_mask, 0, &simulated_time);
    }

    /* Prepare to send data */
    if (ret == 0) {
        ret = test_api_init_send_recv_scenario(test_ctx, scenario, scenario_size);
    }

    /* Perform a data sending loop */
    if (ret == 0) {
        ret = tls_api_data_sending_loop(test_ctx, &loss_mask, &simulated_time, 0);
    }

    if (ret == 0) {
        if (test_ctx->cnx_client->path[0]->send_mtu != mtu_expected_client) {
            ret = -1;
        } else if (test_ctx->cnx_server->path[0]->send_mtu != mtu_expected_server) {
            ret = -1;
        }
    }

    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }

    return ret;
}

int mtu_discovery_test()
{
    int ret = mtu_discovery_test_one(picoquic_pmtud_basic, 1440, 1440, 
        test_scenario_mtu_discovery, sizeof(test_scenario_mtu_discovery), 0);
    return ret;
}

int mtu_blocked_test()
{
    int ret = mtu_discovery_test_one(picoquic_pmtud_blocked, 1252, 1252, 
        test_scenario_mtu_discovery, sizeof(test_scenario_mtu_discovery), 0);
    return ret;
}

int mtu_delayed_test()
{
    int ret = mtu_discovery_test_one(picoquic_pmtud_delayed, 1252, 1440, 
        test_scenario_very_long, sizeof(test_scenario_very_long), 0);
    return ret;
}

int mtu_required_test()
{
    int ret = mtu_discovery_test_one(picoquic_pmtud_required, 1440, 1440, 
        test_scenario_q_and_r, sizeof(test_scenario_q_and_r), 0);
    return ret;
}

int mtu_max_test()
{
    int ret = mtu_discovery_test_one(picoquic_pmtud_basic, 1420, 1392,
        test_scenario_mtu_discovery, sizeof(test_scenario_mtu_discovery), 1420);
    return ret;
}

/*
* MTU drop test. Perform a long duration transmission.
* Verify that MTU was properly set to expected value, then
* simulate a routing event that causes the MTU to drop.
* Check that the MTU gets reduced, and the transmission
* completes.
*/

static int mtu_drop_cc_algotest(picoquic_congestion_algorithm_t* cc_algo, uint64_t target_time)
{
    uint64_t simulated_time = 0;
    uint64_t loss_mask = 0;
    const uint64_t mtu_drop_latency = 100000;
    const uint64_t picosec_1mbps = 8000000;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    picoquic_connection_id_t initial_cid = { {0xa1, 0x10, 0xcc, 0xa1, 0x90, 6, 7, 8}, 8 };
    int ret;

    initial_cid.id[4] = cc_algo->congestion_algorithm_number;
    
    ret = tls_api_init_ctx_ex(&test_ctx, PICOQUIC_INTERNAL_TEST_VERSION_1,
        PICOQUIC_TEST_SNI, PICOQUIC_TEST_ALPN, &simulated_time, NULL, NULL, 0, 0, 0, &initial_cid);

    if (ret == 0) {
        /* Set long delays, 1 Mbps each way */
        test_ctx->c_to_s_link->microsec_latency = mtu_drop_latency;
        test_ctx->c_to_s_link->picosec_per_byte = picosec_1mbps;
        test_ctx->s_to_c_link->microsec_latency = mtu_drop_latency;
        test_ctx->s_to_c_link->picosec_per_byte = picosec_1mbps;
        /* Set the CC algorithm to selected value */
        picoquic_set_default_congestion_algorithm(test_ctx->qserver, cc_algo);
        picoquic_set_binlog(test_ctx->qserver, ".");
        test_ctx->qserver->use_long_log = 1;
    }

    if (ret == 0) {
        ret = tls_api_connection_loop(test_ctx, &loss_mask, 2*mtu_drop_latency, &simulated_time);
    }

    /* Prepare to send data */
    if (ret == 0) {
        ret = test_api_init_send_recv_scenario(test_ctx, test_scenario_very_long, sizeof(test_scenario_very_long));
    }

    /* Send for 1 seconds, check that MTU is discovered, and then drop the MTU size in the s_to_c direction */
    if (ret == 0) {
        ret = tls_api_wait_for_timeout(test_ctx, &simulated_time, 1000000);
    }

    if (ret == 0) {
        if (test_ctx->cnx_client->path[0]->send_mtu != test_ctx->cnx_server->local_parameters.max_packet_size) {
            ret = -1;
        }
        else if (test_ctx->cnx_server->path[0]->send_mtu != test_ctx->cnx_client->local_parameters.max_packet_size) {
            ret = -1;
        }
    }

    if (ret == 0) {
        test_ctx->c_to_s_link->path_mtu = (PICOQUIC_INITIAL_MTU_IPV4 + test_ctx->c_to_s_link->path_mtu) / 2;
        test_ctx->s_to_c_link->path_mtu = (PICOQUIC_INITIAL_MTU_IPV4 + test_ctx->s_to_c_link->path_mtu) / 2;
    }

    /* Try to complete the data sending loop */
    if (ret == 0) {
        ret = tls_api_data_sending_loop(test_ctx, &loss_mask, &simulated_time, 0);
    }

    /* verify that the transmission was complete */
    if (ret == 0) {
        ret = tls_api_one_scenario_body_verify(test_ctx, &simulated_time, target_time);
    }

    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }

    return ret;
}

int mtu_drop_bbr_test()
{
    /* TODO: the time with BBR v1 was 10300000. The current value is
     * a slight regression. Investigate whether some performance
     * for BBR3 "recover from PTO" could be improved. */
    int ret = mtu_drop_cc_algotest(picoquic_bbr_algorithm, 10700000);
    return ret;
}

int mtu_drop_cubic_test()
{
    int ret = mtu_drop_cc_algotest(picoquic_cubic_algorithm, 10000000);
    return ret;
}

int mtu_drop_dcubic_test()
{
    int ret = mtu_drop_cc_algotest(picoquic_dcubic_algorithm, 9200000);
    return ret;
}

int mtu_drop_fast_test()
{
    int ret = mtu_drop_cc_algotest(picoquic_fastcc_algorithm, 11500000);
    return ret;
}

int mtu_drop_newreno_test()
{
    int ret = mtu_drop_cc_algotest(picoquic_newreno_algorithm, 11600000);
    return ret;
}

/*
 * Trying to reproduce the scenario that resulted in
 * spurious retransmissions,and checking that it is fixed.
 */

int spurious_retransmit_test()
{
    uint64_t loss_mask = 0;
    uint64_t simulated_time = 0;
    uint64_t next_time = 0;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    int ret = tls_api_init_ctx(&test_ctx, 0, PICOQUIC_TEST_SNI, PICOQUIC_TEST_ALPN, &simulated_time, NULL, NULL, 0, 0, 0);

    if (ret == 0) {
        test_ctx->c_to_s_link->microsec_latency = 50000ull;
        test_ctx->s_to_c_link->microsec_latency = 50000ull;

        ret = tls_api_connection_loop(test_ctx, &loss_mask, 0, &simulated_time);
    }

    /* simulate 1 second of silence */
    next_time = simulated_time + 1000000ull;
    while (ret == 0 && simulated_time < next_time && TEST_CLIENT_READY && TEST_SERVER_READY) {
        int was_active = 0;

        ret = tls_api_one_sim_round(test_ctx, &simulated_time, next_time, &was_active);
    }

    if (ret == 0) {
        ret = tls_api_attempt_to_close(test_ctx, &simulated_time);
    }

    if (ret == 0) {
        /* verify the absence of any spurious retransmission */
        if (test_ctx->cnx_client->nb_spurious != 0) {
            ret = -1;
        } else if (test_ctx->cnx_server != NULL && test_ctx->cnx_server->nb_spurious != 0) {
            ret = -1;
        }
    }

    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }

    return ret;
}

/*
* Set up a connection, and verify
* that the key generated for PN encryption on
* client and server produce the correct results.
*/

int pn_enc_1rtt_test()
{
    uint64_t loss_mask = 0;
    uint64_t simulated_time = 0;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    int ret = tls_api_init_ctx(&test_ctx, 0, PICOQUIC_TEST_SNI, PICOQUIC_TEST_ALPN, &simulated_time, NULL, NULL, 0, 0, 0);

    if (ret == 0) {
        ret = tls_api_connection_loop(test_ctx, &loss_mask, 0, &simulated_time);
    }

    if (ret == 0) {
        ret = wait_application_aead_ready(test_ctx, &simulated_time);
    }

    if (ret == 0)
    {
        /* Try to encrypt a sequence number */
        uint8_t seq_num_1[4] = { 0xde, 0xad, 0xbe, 0xef };
        uint8_t sample_1[16] = {
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
            0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a };
        uint8_t seq_num_2[4] = { 0xba, 0xba, 0xc0, 0x0l };
        uint8_t sample_2[16] = {
            0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96 };

        for (int i = 1; i < 4; i *= 2)
        {
            ret = test_one_pn_enc_pair(seq_num_1, 4, test_ctx->cnx_client->crypto_context[3].pn_enc, test_ctx->cnx_server->crypto_context[3].pn_dec, sample_1);

            if (ret == 0)
            {
                ret = test_one_pn_enc_pair(seq_num_2, 4, test_ctx->cnx_server->crypto_context[3].pn_enc, test_ctx->cnx_client->crypto_context[3].pn_dec, sample_2);
            }
        }
    }

    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }

    return ret;
}

int bad_certificate_test()
{
    uint64_t simulated_time = 0;
    uint64_t loss_mask = 0;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    char test_server_cert_file[512];
    char test_server_key_file[512];
    char test_server_cert_store_file[512];
    int ret = tls_api_init_ctx(&test_ctx, 0, PICOQUIC_TEST_SNI, PICOQUIC_TEST_ALPN, &simulated_time, NULL, NULL, 0, 0, 0);

    if (ret == 0) {
        ret = picoquic_get_input_path(test_server_cert_file, sizeof(test_server_cert_file), picoquic_solution_dir, PICOQUIC_TEST_FILE_SERVER_BAD_CERT);

        if (ret == 0) {
            ret = picoquic_get_input_path(test_server_key_file, sizeof(test_server_key_file), picoquic_solution_dir, PICOQUIC_TEST_FILE_SERVER_KEY);
        }

        if (ret == 0) {
            ret = picoquic_get_input_path(test_server_cert_store_file, sizeof(test_server_cert_store_file), picoquic_solution_dir, PICOQUIC_TEST_FILE_CERT_STORE);
        }

        if (ret != 0) {
            DBG_PRINTF("%s", "Cannot set the cert, key or store file names.\n");
        }
    }

    /* Delete the server context, and recreate it with the bad certificate */

    if (ret == 0)
    {
        if (test_ctx->qserver != NULL) {
            picoquic_free(test_ctx->qserver);
        }

        test_ctx->qserver = picoquic_create(8,
            test_server_cert_file, test_server_key_file, test_server_cert_store_file,
            PICOQUIC_TEST_ALPN, test_api_callback, (void*)&test_ctx->server_callback, NULL, NULL, NULL,
            simulated_time, &simulated_time, NULL,
            test_ticket_encrypt_key, sizeof(test_ticket_encrypt_key));

        if (test_ctx->qserver == NULL) {
            ret = -1;
        }
    }

    /* Proceed with the connection loop. It should fail, and thus we don't test the return code */
    if (ret == 0) {
        (void)tls_api_connection_loop(test_ctx, &loss_mask, 0, &simulated_time);

        if (test_ctx->cnx_client == NULL) {
            ret = -1;
        }
        else if (test_ctx->cnx_client->cnx_state != picoquic_state_disconnected) {
            ret = -1;
        }
        else if (!picoquic_is_handshake_error(picoquic_get_local_error(test_ctx->cnx_client))) {
            ret = -1;
        }
        else if (!picoquic_is_handshake_error(picoquic_get_remote_error(test_ctx->cnx_server))) {
            ret = -1;
        }
        else {
            ret = 0;
        }
    }

    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }

    return ret;
}

/*
* Test setting the verify certificate callback.
*/

typedef struct st_verify_certificate_test_cb_t {
    ptls_verify_certificate_t super;
    int callcount;
} verify_certificate_test_cb_t;

static int verify_sign_test(void* verify_ctx, uint16_t algo, ptls_iovec_t data, ptls_iovec_t sign)
{
    int* ptr = (int*)verify_ctx;
    *ptr += 1;

    return 0;
}
/*
    int (*cb)(struct st_ptls_verify_certificate_t *self, ptls_t *tls, const char *server_name,
              int (**verify_sign)(void *verify_ctx, uint16_t algo, ptls_iovec_t data, ptls_iovec_t sign), void **verify_data,
              ptls_iovec_t *certs, size_t num_certs);
*/
static int verify_certificate_test_cb(struct st_ptls_verify_certificate_t* self, ptls_t* tls, const char* server_name,
    int (**verify_sign)(void* verify_ctx, uint16_t algo, ptls_iovec_t data, ptls_iovec_t sign), void** verify_data,
    ptls_iovec_t* certs, size_t num_certs)
{

    int ret = 0;
    verify_certificate_test_cb_t* verify_cb_ctx = (verify_certificate_test_cb_t*)
        ((char*)self - offsetof(verify_certificate_test_cb_t, super.cb));

    *verify_sign = verify_sign_test;
    *verify_data = (void*)&verify_cb_ctx->callcount;

    return ret;
}

int set_verify_certificate_callback_test()
{
    uint64_t simulated_time = 0;
    uint64_t loss_mask = 0;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    char test_server_cert_file[512];
    char test_server_key_file[512];
    char test_server_cert_store_file[512];
    int ret = tls_api_init_ctx(&test_ctx, PICOQUIC_INTERNAL_TEST_VERSION_1,
        PICOQUIC_TEST_SNI, PICOQUIC_TEST_ALPN, &simulated_time, NULL, NULL, 0, 0, 0);
    static const uint16_t default_algos[] = {
        PTLS_SIGNATURE_ED25519, PTLS_SIGNATURE_RSA_PSS_RSAE_SHA256,
        PTLS_SIGNATURE_ECDSA_SECP256R1_SHA256, PTLS_SIGNATURE_RSA_PKCS1_SHA256, 
        PTLS_SIGNATURE_RSA_PKCS1_SHA1, UINT16_MAX };

    verify_certificate_test_cb_t verify_cb = { 0 };

    verify_cb.super.cb = verify_certificate_test_cb;
    verify_cb.super.algos = default_algos;

    if (ret == 0) {
        ret = picoquic_get_input_path(test_server_cert_file, sizeof(test_server_cert_file), picoquic_solution_dir, PICOQUIC_TEST_FILE_SERVER_CERT);
    }

    if (ret == 0) {
        ret = picoquic_get_input_path(test_server_key_file, sizeof(test_server_key_file), picoquic_solution_dir, PICOQUIC_TEST_FILE_SERVER_KEY);
    }

    if (ret == 0) {
        ret = picoquic_get_input_path(test_server_cert_store_file, sizeof(test_server_cert_store_file), picoquic_solution_dir, PICOQUIC_TEST_FILE_CERT_STORE);
    }

    if (ret != 0) {
        DBG_PRINTF("%s", "Cannot set the cert, key or store file names.\n");
    }

    /* Delete the client context, and recreate with a certificate */
    if (ret == 0) {
        if (test_ctx->qclient != NULL) {
            picoquic_free(test_ctx->qclient);
            test_ctx->cnx_client = NULL;
        }

        test_ctx->qclient = picoquic_create(8,
            test_server_cert_file, test_server_key_file, test_server_cert_store_file,
            NULL, test_api_callback, (void*)&test_ctx->client_callback, NULL, NULL, NULL,
            simulated_time, &simulated_time, NULL, NULL, 0);

        if (test_ctx->qclient == NULL) {
            ret = -1;
        }
    }
    /* recreate the client connection */
    if (ret == 0) {
        test_ctx->cnx_client = picoquic_create_cnx(test_ctx->qclient, picoquic_null_connection_id,
                                                   picoquic_null_connection_id,
                                                   (struct sockaddr*)&test_ctx->server_addr, 0,
                                                   0, PICOQUIC_TEST_SNI, PICOQUIC_TEST_ALPN, 1);

        if (test_ctx->cnx_client == NULL) {
            ret = -1;
        } else {
            ret = picoquic_start_client_cnx(test_ctx->cnx_client);
        }
    }
    /* Set the verify callback for the client */
    if (ret == 0) {
        picoquic_set_verify_certificate_callback(test_ctx->qclient, &verify_cb.super, NULL);
    }

    /* Set the verify callback for the server */
    if (ret == 0) {
        picoquic_set_verify_certificate_callback(test_ctx->qserver, &verify_cb.super, NULL);
    }
    /* Activate client authentication */
    if (ret == 0) {
        picoquic_set_client_authentication(test_ctx->qserver, 1);

        ret = tls_api_connection_loop(test_ctx, &loss_mask, 0, &simulated_time);
    }

    if (ret == 0 && verify_cb.callcount != 2) {
        ret = -1;
    }

    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }

    return ret;
}

/*
 * Verify that the simulated time works as expected
 */

int virtual_time_test()
{
    int ret = 0;
    uint64_t test_time = 0;
    uint64_t simulated_time = 0;
    uint64_t current_time = picoquic_current_time();
    uint64_t ptls_time = 0;
    uint8_t callback_ctx[256];
    char test_server_cert_store_file[512];
    picoquic_quic_t * qsimul = NULL;
    picoquic_quic_t * qdirect = NULL;

    ret = picoquic_get_input_path(test_server_cert_store_file, sizeof(test_server_cert_store_file), picoquic_solution_dir, PICOQUIC_TEST_FILE_CERT_STORE);

    if (ret != 0) {
        DBG_PRINTF("%s", "Cannot set the cert, key or store file names.\n");
    }
    else {
        qsimul = picoquic_create(8, NULL, NULL, test_server_cert_store_file,
            NULL, test_api_callback,
            (void*)callback_ctx, NULL, NULL, NULL, simulated_time,
            &simulated_time, ticket_file_name, NULL, 0);
        qdirect = picoquic_create(8, NULL, NULL, PICOQUIC_TEST_FILE_CERT_STORE,
            NULL, test_api_callback,
            (void*)callback_ctx, NULL, NULL, NULL, current_time,
            NULL, ticket_file_name, NULL, 0);

        if (qsimul == NULL || qdirect == NULL)
        {
            ret = -1;
        }
        else
        {
            /* Check that the simulated time follows the simulation */
            for (int i = 0; ret == 0 && i < 5; i++) {
                simulated_time += 12345678000;
                test_time = picoquic_get_quic_time(qsimul);
                ptls_time = picoquic_get_tls_time(qsimul);
                if (test_time != simulated_time) {
                    DBG_PRINTF("Test time: %llu != Simulated: %llu",
                        (unsigned long long)test_time,
                        (unsigned long long)simulated_time);
                    ret = -1;
                }
                else if (ptls_time < test_time || ptls_time > test_time + 1000) {
                    DBG_PRINTF("Test time: %llu does match ptls time: %llu",
                        (unsigned long long)test_time,
                        (unsigned long long)ptls_time);
                    ret = -1;
                }
            }
        }

        if (ret == 0) {
            int64_t delta, delta_low, delta_high;
            uint64_t current_previous = picoquic_current_time();
            uint64_t test_previous = picoquic_current_time();
            uint64_t ptls_previous = picoquic_get_tls_time(qdirect);

            /* Check that the non simulated time follows the current time */
            for (int i = 0; ret == 0 && i < 5; i++) {
#ifdef _WINDOWS
                Sleep(1);
#else
                usleep(1000);
#endif
                current_time = picoquic_current_time();
                test_time = picoquic_get_quic_time(qdirect);
                ptls_time = picoquic_get_tls_time(qdirect);

                delta = current_time - current_previous;
                delta_low = delta - 1000;
                delta_high = delta + 1000;
                if (test_time < test_previous + delta_low || test_time > test_previous + delta_high ) {
                    DBG_PRINTF("Test time: %" PRIu64 " does not match previous test time : %" PRIu64 " + delta : %" PRId64,
                        test_time, test_previous, delta);
                    ret = -1;
                }
                else if (ptls_time < ptls_previous + delta_low || ptls_time > ptls_previous + delta_high) {
                    DBG_PRINTF("Test time: %" PRIu64 " does not match previous test time : %" PRIu64 " + delta : %" PRId64,
                        ptls_time, ptls_previous, delta);
                    ret = -1;
                }
            }
        }
    }

    if (qsimul != NULL)
    {
        picoquic_free(qsimul);
        qsimul = NULL;
    }

    if (qdirect != NULL)
    {
        picoquic_free(qdirect);
        qdirect = NULL;
    }

    return ret;
}

/*
 * Testing with different initial connection parameters
 */

int tls_different_params_test()
{
    picoquic_tp_t test_parameters;

    memset(&test_parameters, 0, sizeof(picoquic_tp_t));

    picoquic_init_transport_parameters(&test_parameters, 1);

    test_parameters.initial_max_stream_id_bidir = 0;

    return tls_api_one_scenario_test(test_scenario_very_long, sizeof(test_scenario_very_long), 0, 0, 0, 0, 0, 3510000, &test_parameters, NULL);
}

int tls_quant_params_test()
{
    picoquic_tp_t test_parameters;

    memset(&test_parameters, 0, sizeof(picoquic_tp_t));

    picoquic_init_transport_parameters(&test_parameters, 1);

    test_parameters.initial_max_data = 0x4000;
    test_parameters.initial_max_stream_id_bidir = 0;
    test_parameters.initial_max_stream_id_unidir = 16384;
    test_parameters.initial_max_stream_data_bidi_local = 0x2000;
    test_parameters.initial_max_stream_data_bidi_remote = 0x2000;
    test_parameters.initial_max_stream_data_uni = 0x2000;

    return tls_api_one_scenario_test(test_scenario_quant, sizeof(test_scenario_quant), 0, 0, 0, 0, 0, 3510000, &test_parameters, NULL);
}

int set_certificate_and_key_test()
{
    uint64_t simulated_time = 0;
    uint64_t loss_mask = 0;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    char test_server_cert_file[512];
    char test_server_key_file[512];
    char test_server_cert_store_file[512];
    int ret = tls_api_init_ctx(&test_ctx, 0, PICOQUIC_TEST_SNI, PICOQUIC_TEST_ALPN, &simulated_time, NULL, NULL, 0, 0, 0);

    if (ret == 0) {
        ret = picoquic_get_input_path(test_server_cert_file, sizeof(test_server_cert_file), picoquic_solution_dir, PICOQUIC_TEST_FILE_SERVER_CERT);
    }

    if (ret == 0) {
        ret = picoquic_get_input_path(test_server_key_file, sizeof(test_server_key_file), picoquic_solution_dir, PICOQUIC_TEST_FILE_SERVER_KEY);
    }

    if (ret == 0) {
        ret = picoquic_get_input_path(test_server_cert_store_file, sizeof(test_server_cert_store_file), picoquic_solution_dir, PICOQUIC_TEST_FILE_CERT_STORE);
    }

    if (ret != 0) {
        DBG_PRINTF("%s", "Cannot set the cert, key or store file names.\n");
    }

    /* Delete the server context, and recreate it. */
    if (ret == 0)
    {
        if (test_ctx->qserver != NULL) {
            picoquic_free(test_ctx->qserver);
        }

        test_ctx->qserver = picoquic_create(8,
            NULL, NULL, NULL,
            PICOQUIC_TEST_ALPN, test_api_callback, (void*)&test_ctx->server_callback, NULL, NULL, NULL,
            simulated_time, &simulated_time, NULL,
            test_ticket_encrypt_key, sizeof(test_ticket_encrypt_key));

        if (test_ctx->qserver == NULL) {
            ret = -1;
        }

        if (ret == 0) {
            ret = picoquic_set_private_key_from_file(test_ctx->qserver, test_server_key_file);
        }

        if (ret == 0) {
            size_t count = 0;
            ptls_iovec_t* chain = picoquic_get_certs_from_file(test_server_cert_file, &count);
            if (chain == NULL) {
                ret = -1;
            } else {
                picoquic_set_tls_certificate_chain(test_ctx->qserver, chain, count);
            }
        }

        if (ret == 0) {
            size_t count = 0;
            ptls_iovec_t* chain = picoquic_get_certs_from_file(test_server_cert_store_file, &count);

            if (chain == NULL) {
                ret = -1;
            } else {
                picoquic_set_tls_root_certificates(test_ctx->qserver, chain, count);
                for (size_t i = 0; i < count; i++) {
                    free(chain[i].base);
                }
                free(chain);
            }
        }
    }

    /* Proceed with the connection loop. */
    if (ret == 0) {
        picoquic_enforce_client_only(test_ctx->qserver, 0);
        ret = tls_api_connection_loop(test_ctx, &loss_mask, 0, &simulated_time);
    }

    if (ret == 0 && (!TEST_CLIENT_READY || !TEST_SERVER_READY)) {
        ret = -1;
    }

    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }

    return ret;
}

int request_client_authentication_test()
{
    uint64_t simulated_time = 0;
    uint64_t loss_mask = 0;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    char test_server_cert_file[512];
    char test_server_key_file[512];
    char test_server_cert_store_file[512];
    int ret = picoquic_get_input_path(test_server_cert_file, sizeof(test_server_cert_file), picoquic_solution_dir, PICOQUIC_TEST_FILE_SERVER_CERT);

    if (ret == 0) {
        ret = picoquic_get_input_path(test_server_key_file, sizeof(test_server_key_file), picoquic_solution_dir, PICOQUIC_TEST_FILE_SERVER_KEY);
    }

    if (ret == 0) {
        ret = picoquic_get_input_path(test_server_cert_store_file, sizeof(test_server_cert_store_file), picoquic_solution_dir, PICOQUIC_TEST_FILE_CERT_STORE);
    }

    if (ret != 0) {
        DBG_PRINTF("%s", "Cannot set the cert, key or store file names.\n");
    }
    else {
        ret = tls_api_init_ctx(&test_ctx, 0, PICOQUIC_TEST_SNI, PICOQUIC_TEST_ALPN, &simulated_time, NULL, NULL, 0, 0, 0);
    }

    if (ret == 0 && test_ctx == NULL) {
        ret = -1;
    }

    /* Delete the client context, and recreate with a certificate */
    if (ret == 0)
    {
        if (test_ctx->qclient != NULL) {
            picoquic_free(test_ctx->qclient);
            test_ctx->cnx_client = NULL;
        }

        test_ctx->qclient = picoquic_create(8,
            test_server_cert_file, test_server_key_file, test_server_cert_store_file,
            NULL, test_api_callback, (void*)&test_ctx->client_callback, NULL, NULL, NULL,
            simulated_time, &simulated_time, NULL, NULL, 0);

        if (test_ctx->qclient == NULL) {
            ret = -1;
        }
        else {
            /* Enforce client only mode on the client side. */
            picoquic_enforce_client_only(test_ctx->qclient, 1);
        }
    }

    /* recreate the client connection */
    if (ret == 0) {
        test_ctx->cnx_client = picoquic_create_cnx(test_ctx->qclient, picoquic_null_connection_id,
                                                   picoquic_null_connection_id,
                                                   (struct sockaddr*)&test_ctx->server_addr, 0,
                                                   0, PICOQUIC_TEST_SNI, PICOQUIC_TEST_ALPN, 1);

        if (test_ctx->cnx_client == NULL) {
            ret = -1;
        } else {
            ret = picoquic_start_client_cnx(test_ctx->cnx_client);
        }
    }

    if (ret == 0) {
        picoquic_set_client_authentication(test_ctx->qserver, 1);
        
        /* Proceed with the connection loop. */
        ret = tls_api_connection_loop(test_ctx, &loss_mask, 0, &simulated_time);
    }
  
    /* Check that both the client and server are ready. */
    if (ret == 0) {
        if (test_ctx->cnx_client == NULL
            || test_ctx->cnx_server == NULL
            || !TEST_CLIENT_READY
            || !TEST_SERVER_READY) {
            ret = -1;
        }
    }

    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }

    return ret;
}

int bad_client_certificate_test()
{
    uint64_t simulated_time = 0;
    uint64_t loss_mask = 0;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    char test_server_cert_file[512];
    char test_server_key_file[512];
    char test_server_cert_store_file[512];
    int ret = picoquic_get_input_path(test_server_cert_file, sizeof(test_server_cert_file), picoquic_solution_dir, PICOQUIC_TEST_FILE_SERVER_BAD_CERT);

    if (ret == 0) {
        ret = picoquic_get_input_path(test_server_key_file, sizeof(test_server_key_file), picoquic_solution_dir, PICOQUIC_TEST_FILE_SERVER_KEY);
    }

    if (ret == 0) {
        ret = picoquic_get_input_path(test_server_cert_store_file, sizeof(test_server_cert_store_file), picoquic_solution_dir, PICOQUIC_TEST_FILE_CERT_STORE);
    }

    if (ret != 0) {
        DBG_PRINTF("%s", "Cannot set the cert, key or store file names.\n");
    }
    else {
        ret = tls_api_init_ctx(&test_ctx, 0, PICOQUIC_TEST_SNI, PICOQUIC_TEST_ALPN, &simulated_time, NULL, NULL, 0, 0, 0);
    }

    if (ret == 0 && test_ctx == NULL) {
        ret = -1;
    }

    /* Delete the client context, and recreate with a certificate */
    if (ret == 0)
    {
        if (test_ctx->qclient != NULL) {
            picoquic_free(test_ctx->qclient);
            test_ctx->cnx_client = NULL;
        }

        test_ctx->qclient = picoquic_create(8,
            test_server_cert_file, test_server_key_file, test_server_cert_store_file,
            NULL, test_api_callback, (void*)&test_ctx->client_callback, NULL, NULL, NULL,
            simulated_time, &simulated_time, NULL, NULL, 0);

        if (test_ctx->qclient == NULL) {
            ret = -1;
        }
    }

    /* recreate the client connection */
    if (ret == 0) {
        test_ctx->cnx_client = picoquic_create_cnx(test_ctx->qclient, picoquic_null_connection_id,
                                                   picoquic_null_connection_id,
                                                   (struct sockaddr*)&test_ctx->server_addr, 0,
                                                   0, PICOQUIC_TEST_SNI, PICOQUIC_TEST_ALPN, 1);

        if (test_ctx->cnx_client == NULL) {
            ret = -1;
        } else {
            ret = picoquic_start_client_cnx(test_ctx->cnx_client);
        }
    }

    if (ret == 0) {
        picoquic_set_client_authentication(test_ctx->qserver, 1);
        
        /* Proceed with the connection loop. It should fail */
        ret = tls_api_connection_loop(test_ctx, &loss_mask, 0, &simulated_time);
    }

    if (ret == 0) {
        if (test_ctx->cnx_client == NULL) {
            ret = -1;
        }
        else if (test_ctx->cnx_client->cnx_state != picoquic_state_disconnected) {
            ret = -1;
        }
        else if (!picoquic_is_handshake_error(picoquic_get_local_error(test_ctx->cnx_server))) {
            ret = -1;
        }
        else if (!picoquic_is_handshake_error(picoquic_get_remote_error(test_ctx->cnx_client))) {
            ret = -1;
        }
    }

    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }

    return ret;
}

/*
* NAT Rebinding test. The client is unaware of the migration.
* Start with one basic transmission, then switch the client
* to a different port number. Verify that the server issues 
* a path challenge, that the client responds with a path
* response, and that the connection completes.
*/

int nat_rebinding_count_r_cid(picoquic_cnx_t* cnx) {
    int nb_cid = 0;
    picoquic_remote_cnxid_t* r_cid = cnx->first_remote_cnxid_stash->cnxid_stash_first;

    while (r_cid) {
        nb_cid++;
        r_cid = r_cid->next;
    }

    return nb_cid;
}

int nat_rebinding_test_one(uint64_t loss_mask_data, int zero_cid, uint64_t latency)
{
    int ret;
    uint64_t simulated_time = 0;
    uint64_t next_time = 0;
    uint64_t loss_mask = 0;
    uint64_t initial_challenge = 0;
    int nb_inactive = 0;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    picoquic_connection_id_t initial_cid = { {0x19, 0x8a, 0, 0, 0, 0, 0, 0}, 8 };

    if (loss_mask_data != 0) {
        initial_cid.id[2] = 0x10;
    }

    if (zero_cid != 0) {
        initial_cid.id[3] = 0xc1;
    }

    ret = tls_api_init_ctx_ex2(&test_ctx, PICOQUIC_INTERNAL_TEST_VERSION_1,
        PICOQUIC_TEST_SNI, PICOQUIC_TEST_ALPN, &simulated_time, NULL, NULL, 0, 0, 0, &initial_cid, 8, zero_cid, 0, 0);

    if (ret == 0 && test_ctx == NULL) {
        ret = PICOQUIC_ERROR_MEMORY;
    }
    else {
        if (latency > 0) {
            test_ctx->c_to_s_link->microsec_latency = latency;
            test_ctx->s_to_c_link->microsec_latency = latency;
        }
        picoquic_set_log_level(test_ctx->qserver, 1);
        ret = picoquic_set_binlog(test_ctx->qserver, ".");
        picoquic_set_log_level(test_ctx->qclient, 1);
        if (ret == 0) {
            ret = picoquic_set_binlog(test_ctx->qclient, ".");
            binlog_new_connection(test_ctx->cnx_client);
        }
    }

    if (ret == 0) {
        ret = tls_api_connection_loop(test_ctx, &loss_mask, 0, &simulated_time);
    }

    /* run a receive loop until no outstanding data */
    if (ret == 0) {
        ret = tls_api_synch_to_empty_loop(test_ctx, &simulated_time, 2048, PICOQUIC_NB_PATH_TARGET, 1);
    }

    if (ret == 0) {
        initial_challenge = test_ctx->cnx_server->path[0]->challenge[0];
        loss_mask = loss_mask_data; 
        
        /* Change the client address */
        test_ctx->client_addr_natted = test_ctx->client_addr;
        test_ctx->client_addr_natted.sin_port += 17;
        test_ctx->client_use_nat = 1;

        /* Prepare to send data */
        ret = test_api_init_send_recv_scenario(test_ctx, test_scenario_q_and_r, sizeof(test_scenario_q_and_r));
    }

    /* Perform a data sending loop */
    if (ret == 0) {
        ret = tls_api_data_sending_loop(test_ctx, &loss_mask, &simulated_time, 0);
    }
    
    /* verify that the transmission was complete */
    if (ret == 0) {
        ret = tls_api_one_scenario_verify(test_ctx);
    }

    /* Add a time loop of 3 seconds to give some time for the challenge to be repeated */
    next_time = simulated_time + 3000000;
    loss_mask = 0;
    while (ret == 0 && simulated_time < next_time && TEST_CLIENT_READY 
        && TEST_SERVER_READY && !zero_cid
        && (test_ctx->cnx_server->path[0]->challenge_verified != 1 ||
            test_ctx->cnx_server->nb_paths > 1 ||
            test_ctx->cnx_server->first_remote_cnxid_stash->cnxid_stash_first->sequence == 0 ||
            nat_rebinding_count_r_cid(test_ctx->cnx_server) < 8 )) {
        int was_active = 0;

        ret = tls_api_one_sim_round(test_ctx, &simulated_time, next_time, &was_active);

        if (was_active) {
            nb_inactive = 0;
        }
        else {
            nb_inactive++;
            if (nb_inactive > 128) {
                ret = 0;
                if (nb_inactive > 256) {
                    break;
                }
            }
        }
    }

    /* Verify that the challenge was updated and done */
    if (ret == 0) {
        if (test_ctx->cnx_server == NULL) {
            DBG_PRINTF("%s", "Server connection disappeared");
            ret = -1;
        } else if (initial_challenge == test_ctx->cnx_server->path[0]->challenge[0]) {
            DBG_PRINTF("%s", "Challenge was not renewed after NAT rebinding");
            ret = -1;
        }
        else if (test_ctx->cnx_server->path[0]->challenge_verified != 1) {
            DBG_PRINTF("%s", "Challenge was not verified after NAT rebinding");
            ret = -1;
        }
    }

    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }

    return ret;
}

int nat_rebinding_test()
{
    uint64_t loss_mask = 0;

    return nat_rebinding_test_one(loss_mask, 0, 0);
}

int nat_rebinding_loss_test()
{
    uint64_t loss_mask = 0x2012;

    return nat_rebinding_test_one(loss_mask, 0, 0);
}

int nat_rebinding_zero_test()
{
    /* Test of NAT rebinding with zero-length client CID */
    uint64_t loss_mask = 0;

    return nat_rebinding_test_one(loss_mask, 1, 0);
}

int nat_rebinding_latency_test()
{
    /* Test of NAT rebinding with zero-length client CID */
    uint64_t loss_mask = 0;

    return nat_rebinding_test_one(loss_mask, 0, 100000);
}


/*
* Fast NAT Rebinding test. The client is unaware of the migration,
* and is programmed to not support migration. The NAT alternates
* between ports based on time, or packet counts. The test checks that
* the connection survives 6 NAT transitions at short intervals.
*/

int fast_nat_rebinding_test()
{
    uint64_t simulated_time = 0;
    uint64_t loss_mask = 0;
    const int nb_switches_required = 6;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    picoquic_connection_id_t initial_cid = { {0xfa, 0x57, 0x08, 0xa7, 0, 0, 0, 0}, 8 };

    int ret = tls_api_init_ctx_ex(&test_ctx, PICOQUIC_INTERNAL_TEST_VERSION_1,
        PICOQUIC_TEST_SNI, PICOQUIC_TEST_ALPN, &simulated_time, NULL, NULL, 0, 0, 0, &initial_cid);

    if (ret == 0 && test_ctx == NULL) {
        ret = PICOQUIC_ERROR_MEMORY;
    }

    if (ret == 0) {
        /* Set up logging */ 
        picoquic_set_binlog(test_ctx->qserver, ".");
        picoquic_set_binlog(test_ctx->qclient, ".");
        binlog_new_connection(test_ctx->cnx_client);
    }

    if (ret == 0) {
        ret = tls_api_connection_loop(test_ctx, &loss_mask, 0, &simulated_time);
    }

    if (ret == 0) {
        ret = test_api_init_send_recv_scenario(test_ctx, test_scenario_sustained, sizeof(test_scenario_sustained));
    }

    /* Perform a data sending loop */
    if (ret == 0) {
        uint64_t delta_t = 5 * (test_ctx->c_to_s_link->microsec_latency + test_ctx->s_to_c_link->microsec_latency);
        uint64_t next_time = simulated_time + 200000000;
        int nb_trials = 0;
        int nb_inactive = 0;
        int max_trials = 1000000;
        uint64_t switch_time = simulated_time;
        int switched = 0;
        int nb_switched = 0;

        test_ctx->client_use_nat = 1;
        test_ctx->client_addr_natted = test_ctx->client_addr;
        test_ctx->client_addr_natted.sin_port += 17;

        while (ret == 0 && nb_trials < max_trials && nb_inactive < 256 && simulated_time < next_time && TEST_CLIENT_READY && TEST_SERVER_READY) {
            int was_active = 0;

            nb_trials++;

            ret = tls_api_one_sim_round(test_ctx, &simulated_time, next_time, &was_active);

            if (ret < 0)
            {
                break;
            }

            if (ret == 0 && test_ctx->cnx_server != NULL && test_ctx->cnx_server->cnx_state == picoquic_state_ready) {
                if (((struct sockaddr_in*) & test_ctx->cnx_server->path[0]->peer_addr)->sin_port == 0) {
                    DBG_PRINTF("Client address out of sync, port: %d", ((struct sockaddr_in*) & test_ctx->cnx_server->path[0]->peer_addr)->sin_port);
                }
                else if (((struct sockaddr_in*) & test_ctx->cnx_server->path[0]->peer_addr)->sin_port == test_ctx->client_addr_natted.sin_port) {
                    if (switched) {
                        if (simulated_time > switch_time + delta_t &&
                            nb_switched < nb_switches_required) {
                            switched = 0;
                        }
                    }
                    else
                    {
                        /* Change the client address */
                        test_ctx->client_addr_natted.sin_port += 17;
                        switched = 1;
                        switch_time = simulated_time;
                        nb_switched++;
                    }
                }
            }

            if (was_active) {
                nb_inactive = 0;
            }
            else {
                nb_inactive++;

                if (nb_inactive == 254) {
                    DBG_PRINTF("Almost stalled after %d trials, %d inactive, %d switches", nb_trials, nb_inactive, nb_switched);
                }
            }

            if (test_ctx->test_finished) {
                if (picoquic_is_cnx_backlog_empty(test_ctx->cnx_client) && picoquic_is_cnx_backlog_empty(test_ctx->cnx_server)) {
                    break;
                }
            }
        }

        DBG_PRINTF("Exit after %d trials, %d inactive, %d switches", nb_trials, nb_inactive, nb_switched);

        /* Verify that the test was effective */
        if (ret == 0 && nb_switched < nb_switches_required) {
            ret = -1;
        }
    }

    /* verify that the transmission was complete */
    if (ret == 0) {
        ret = tls_api_one_scenario_verify(test_ctx);
    }

    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }

    return ret;
}

/*
 * Test whether the loss bit reporting can be enabled without breaking the connection
 */

int loss_bit_test()
{
    int ret = 0;
    picoquic_tp_t client_parameters;
    picoquic_tp_t server_parameters;

    for (int i = 0; ret == 0 && i <= 3; i++) {
        memset(&client_parameters, 0, sizeof(picoquic_tp_t));
        memset(&server_parameters, 0, sizeof(picoquic_tp_t));
        picoquic_init_transport_parameters(&client_parameters, 1);
        picoquic_init_transport_parameters(&server_parameters, 0);

        client_parameters.enable_loss_bit = (i & 1);
        server_parameters.enable_loss_bit = ((i > 1) & 1);

        ret = tls_api_one_scenario_test(test_scenario_many_streams, sizeof(test_scenario_many_streams), 0, 0, 0, 0, 0, 250000, &client_parameters, &server_parameters);
        if (ret != 0) {
            DBG_PRINTF("Loss bit test fails for client: %d, server: %d, ret = %d", i & 1, i >> 1, ret);
        }
    }

    return ret;
}


/*
* Closing on error test. We voluntarily inject an erroneous
* frame on the client connection. The expected result is that
* the server connection gets closed, but the server remains
* responsive.
*/

int client_error_test_modal(int mode)
{
    uint64_t simulated_time = 0;
    uint64_t next_time = 0;
    uint64_t loss_mask = 0;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    int ret = tls_api_init_ctx(&test_ctx, PICOQUIC_INTERNAL_TEST_VERSION_1,
        PICOQUIC_TEST_SNI, PICOQUIC_TEST_ALPN, &simulated_time, NULL, NULL, 0, 0, 0);

    if (ret == 0) {
        ret = tls_api_connection_loop(test_ctx, &loss_mask, 0, &simulated_time);
    }

    /* Prepare to send data */
    if (ret == 0) {
        ret = test_api_init_send_recv_scenario(test_ctx, test_scenario_q_and_r, sizeof(test_scenario_q_and_r));
    }

    /* Perform a data sending loop */
    if (ret == 0) {
        ret = tls_api_data_sending_loop(test_ctx, &loss_mask, &simulated_time, 0);
    }

    /* Inject an erroneous frame */
    if (ret == 0) {
        if (mode == 0) {
            /* Queue a data frame on stream 4, which was already closed */
            uint8_t stream_error_frame[] = { 0x17, 0x04, 0x41, 0x01, 0x08, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };
            picoquic_queue_misc_frame(test_ctx->cnx_client, stream_error_frame, sizeof(stream_error_frame), 0,
                picoquic_packet_context_application);
        }
        else if (mode == 1) {
            /* Test injection of a wrong NEW CONNECTION ID */
            uint8_t new_cnxid_error[1024];
            uint8_t* x = new_cnxid_error;

            *x++ = picoquic_frame_type_new_connection_id;
            *x++ = test_ctx->cnx_client->nb_paths + 3;
            *x++ = 0;
            *x++ = 8;
            for (int i = 0; i < 8; i++) {
                *x++ = 0x99; /* Hommage to Dilbert's random generator */
            }
            /* deliberate error: repeat the reset secret defined for path[0] */
            memcpy(x, test_ctx->cnx_server->path[0]->p_remote_cnxid->reset_secret, PICOQUIC_RESET_SECRET_SIZE);
            x += PICOQUIC_RESET_SECRET_SIZE;
            picoquic_queue_misc_frame(test_ctx->cnx_client, new_cnxid_error, x - new_cnxid_error, 0,
                picoquic_packet_context_application);
        }
        else if (mode == 2) {
            /* Queue a stop sending on stream 2, which is unidir */
            uint8_t stop_sending_error_frame[] = { (uint8_t)picoquic_frame_type_stop_sending, 2, 0 };
            picoquic_queue_misc_frame(test_ctx->cnx_client, stop_sending_error_frame, sizeof(stop_sending_error_frame), 0,
                picoquic_packet_context_application);
        }
        else {
            DBG_PRINTF("Error mode %d is not defined yet", mode);
        }
    }

    /* Add a time loop of 3 seconds to give some time for the error to be repeated */
    next_time = simulated_time + 3000000;
    loss_mask = 0;
    while (ret == 0 && simulated_time < next_time
        && (test_ctx->cnx_client->cnx_state < picoquic_state_disconnected ||
            test_ctx->cnx_server->cnx_state < picoquic_state_disconnected)) {
        int was_active = 0;

        ret = tls_api_one_sim_round(test_ctx, &simulated_time, next_time, &was_active);
    }

    if (ret == 0 && test_ctx->cnx_server->cnx_state != picoquic_state_disconnected) {
        ret = -1;
    }

    if (ret == 0) {
        /* Delete the client connection from the client context,
         * without sending notification to the server */
        while (test_ctx->qclient->cnx_list != NULL) {
            picoquic_delete_cnx(test_ctx->qclient->cnx_list);
        }

        /* Erase the server connection reference */
        test_ctx->cnx_server = NULL;

        /* Create a new connection in the client context */

        test_ctx->cnx_client = picoquic_create_cnx(test_ctx->qclient,
            picoquic_null_connection_id, picoquic_null_connection_id,
            (struct sockaddr*)&test_ctx->server_addr, simulated_time, 0, PICOQUIC_TEST_SNI, PICOQUIC_TEST_ALPN, 1);

        if (test_ctx->cnx_client == NULL) {
            ret = -1;
        }
        else if (ret == 0) {
            ret = picoquic_start_client_cnx(test_ctx->cnx_client);
        }
    }

    /* Now, restart a connection in the same context */
    if (ret == 0) {
        ret = tls_api_connection_loop(test_ctx, &loss_mask, 0, &simulated_time);
    }

    if (ret == 0){
        ret = wait_application_aead_ready(test_ctx, &simulated_time);
    }

    if (ret == 0) {
        ret = tls_api_attempt_to_close(test_ctx, &simulated_time);
    }

    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }

    return ret;
}

int client_error_test()
{
    int ret = 0;
    char const* mode_name[] = { "stream", "new_connection_id", "stop_sending" };
    int nb_modes = (int)(sizeof(mode_name) / sizeof(char const*));

    for (int mode = 0; mode < nb_modes; mode++) {
        if (client_error_test_modal(mode) != 0) {
            DBG_PRINTF("Client error test mode(%s) failed.\n", mode_name[mode]);
            ret = -1;
        }
    }

    return ret;
}

/*
* Client only test. Verify that if "client only" is set on the server context,
* then connections are refused.
*/

int client_only_test()
{
    uint64_t simulated_time = 0;
    uint64_t loss_mask = 0;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    picoquic_connection_id_t initial_cid = { {0xc1, 0x10, 0, 0, 0, 0, 0, 0}, 8 };
    int ret;

    ret = tls_api_init_ctx_ex(&test_ctx, PICOQUIC_INTERNAL_TEST_VERSION_1,
        PICOQUIC_TEST_SNI, PICOQUIC_TEST_ALPN, &simulated_time, NULL, NULL, 0, 0, 0, &initial_cid);

    if (ret == 0) {
        /* First, try enforcement. We do set log on the server side, but it is expected to be empty */
        int connection_ret = 0;
        picoquic_enforce_client_only(test_ctx->qserver, 1);
        picoquic_set_binlog(test_ctx->qserver, ".");
        picoquic_set_binlog(test_ctx->qclient, ".");
        binlog_new_connection(test_ctx->cnx_client);
        connection_ret = tls_api_connection_loop(test_ctx, &loss_mask, 0, &simulated_time);
        if (connection_ret == 0 && test_ctx->cnx_client->cnx_state < picoquic_state_disconnected) {
            DBG_PRINTF("Connection unexpectedly succeeds, state=%d, ret=%d (0x%x)",
                test_ctx->cnx_client->cnx_state, connection_ret, connection_ret);
            ret = -1;
        }
        else if (test_ctx->cnx_server != NULL) {
            DBG_PRINTF("Connection context created on client-only note, ret=%d (0x%x)",
                connection_ret, connection_ret);
            ret = -1;
        }
    }

    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }

    return ret;
}

/*
 * Set a connection, then verify that the "new connection id" frames have been exchanged properly.
 * Use the "check stash" function to verify that new connection ID were properly
 * stashed on each side.
 *
 * TODO: also test that no New Connection Id frames are sent if migration is disabled 
 */

int test_cnxid_count_stash(picoquic_cnx_t * cnx) {
    picoquic_remote_cnxid_t * stash = cnx->first_remote_cnxid_stash->cnxid_stash_first;
    int nb = 0;

    while (stash != NULL) {
        nb++;
        stash = stash->next;
    }

    return nb;
}

int transmit_cnxid_test_stash(picoquic_cnx_t * cnx1, picoquic_cnx_t * cnx2, char const * cnx_text)
{
    int ret = 0;
    picoquic_remote_cnxid_t * stash = cnx1->first_remote_cnxid_stash->cnxid_stash_first;
    picoquic_local_cnxid_t* cid_list = cnx2->first_local_cnxid_list->local_cnxid_first;
    int rank = 0;

    while (stash != NULL && cid_list != NULL) {
        if (picoquic_compare_connection_id(&stash->cnx_id, &cid_list->cnx_id) != 0) {
            DBG_PRINTF("On %s, cnx ID of stash #%d does not match cid[%d] of peer.\n",
                cnx_text, rank, (int)cid_list->sequence);
            ret = -1;
            break;
        }
        stash = stash->next;
        cid_list = cid_list->next;
        rank++;
    }

    if (ret == 0 && cid_list != NULL) {
        DBG_PRINTF("On %s, %d items in stash instead instead of %d.\n", cnx_text, rank, 
            cnx2->first_local_cnxid_list->nb_local_cnxid - 1);
        ret = -1;
    }

    if (ret == 0 && stash != NULL) {
        DBG_PRINTF("On %s, more than %d items in stash.\n", cnx_text, cnx2->first_local_cnxid_list->nb_local_cnxid - 1);
        ret = -1;
    }

    return ret;
}

int transmit_cnxid_test_one(int retire_before, int disable_migration, int retire_number_zero)
{
    uint64_t simulated_time = 0;
    uint64_t loss_mask = 0;
    /* We set the default ttl to 5 seconds, which is longer than the
     * delay set inside tls_api_synch_to_empty_loop */
    const uint64_t sync_empty_loop_timeout = 4000000;
    const uint64_t default_connection_id_ttl = 5000000;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    picoquic_tp_t test_parameters;
    int ret = tls_api_init_ctx(&test_ctx, PICOQUIC_INTERNAL_TEST_VERSION_1,
        PICOQUIC_TEST_SNI, PICOQUIC_TEST_ALPN, &simulated_time, NULL, NULL, 0, 0, 0);

    if (ret == 0 && disable_migration) {
        memset(&test_parameters, 0, sizeof(picoquic_tp_t));

        picoquic_init_transport_parameters(&test_parameters, 0);
        test_parameters.migration_disabled = 1;
        picoquic_set_default_tp(test_ctx->qserver, &test_parameters);
    }

    if (ret == 0 && retire_before) {
        picoquic_set_default_connection_id_ttl(test_ctx->qserver, default_connection_id_ttl);
    }

    if (retire_number_zero) {
        /* Do a short loop until the server connection is created */
        int nb_trials = 0;
        while (ret == 0 && nb_trials < 16 && test_ctx->cnx_server == NULL) {
            int was_active = 0;
            nb_trials++;

            ret = tls_api_one_sim_round(test_ctx, &simulated_time, 0, &was_active);
        }
        if (test_ctx->cnx_server == NULL) {
            DBG_PRINTF("Cannot create the server connection after %d trials", nb_trials);
            ret = -1;
        }
        else {
            /* force the retire prior to 1 so it be set in the first batch of CID. */
            test_ctx->cnx_server->first_local_cnxid_list->local_cnxid_retire_before = 1;
        }
    }

    if (ret == 0) {
        ret = tls_api_connection_loop(test_ctx, &loss_mask, 0, &simulated_time);
    }

    /* run a receive loop until no outstanding data */
    if (ret == 0) {
        ret = tls_api_synch_to_empty_loop(test_ctx, &simulated_time, 2048, PICOQUIC_NB_PATH_TARGET, 0);
    }

    if (ret == 0 && retire_number_zero) {
        /* verify that the path 0 on client uses CID number > 1 */
        if (test_ctx->cnx_client->path[0]->p_remote_cnxid->sequence == 0) {
            DBG_PRINTF("First path still has CNX_ID=%d", test_ctx->cnx_client->path[0]->p_remote_cnxid->sequence);
            ret = -1;
        }
    }

    if (ret == 0 && retire_before) {
        /* wait until the TTL of local CID expires */
        ret = tls_api_wait_for_timeout(test_ctx, &simulated_time, default_connection_id_ttl - sync_empty_loop_timeout);

        if (ret == 0 && test_ctx->cnx_server->first_local_cnxid_list->local_cnxid_retire_before == 0) {
            DBG_PRINTF("Retire before did not progress: %" PRIu64 ".\n",
                test_ctx->cnx_server->first_local_cnxid_list->local_cnxid_retire_before);
            ret = -1;
        }

        /* Now, wait until the next batch of connection ID is sent. */
        if (ret == 0) {
            ret = tls_api_synch_to_empty_loop(test_ctx, &simulated_time, 2048, PICOQUIC_NB_PATH_TARGET, 0);
        }
    }

    if (ret == 0) {
        if (test_ctx->cnx_client->first_local_cnxid_list->nb_local_cnxid < PICOQUIC_NB_PATH_TARGET) {
            DBG_PRINTF("Only %d CID created on client.\n", test_ctx->cnx_client->first_local_cnxid_list->nb_local_cnxid);
            ret = -1;
        } else if (test_ctx->cnx_server->first_local_cnxid_list->nb_local_cnxid < PICOQUIC_NB_PATH_TARGET) {
            DBG_PRINTF("Only %d CID created on server.\n", test_ctx->cnx_server->first_local_cnxid_list->nb_local_cnxid);
        }
    }

    if (ret == 0) {
        ret = transmit_cnxid_test_stash(test_ctx->cnx_client, test_ctx->cnx_server, "client");
    }

    if (ret == 0) {
        ret = transmit_cnxid_test_stash(test_ctx->cnx_server, test_ctx->cnx_client, "server");
    }

    if (ret == 0 && retire_before) {
        /* Verify that all CID in the client stash have valid sequence numbers. */
        picoquic_remote_cnxid_t* stashed = test_ctx->cnx_client->first_remote_cnxid_stash->cnxid_stash_first;

        while (stashed != NULL && ret == 0) {
            if (stashed->sequence < test_ctx->cnx_server->first_local_cnxid_list->local_cnxid_retire_before) {
                DBG_PRINTF("Old CID %" PRIu64 " still on client.\n", stashed->sequence);
                ret = -1;
                break;
            }
            stashed = stashed->next;
        }
    }

    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }

    return ret;
}

int transmit_cnxid_test()
{
    return transmit_cnxid_test_one(0, 0, 0);
}

int transmit_cnxid_disable_test()
{
    return transmit_cnxid_test_one(0, 1, 0);
}

int transmit_cnxid_retire_before_test()
{
    return transmit_cnxid_test_one(1, 0, 0);
}

int transmit_cnxid_retire_disable_test()
{
    return transmit_cnxid_test_one(1, 1, 0);
}

int transmit_cnxid_retire_early_test()
{
    return transmit_cnxid_test_one(0, 0, 1);
}

/*
 * Unit test for the probe management functions.
 *
 * Set up a connection, exchange new cnxid frames, then create a number of probes.
 * When the number exceeds the number of connections, the probing should fail.
 */

int probe_api_test()
{
    uint64_t simulated_time = 0;
    uint64_t loss_mask = 0;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    struct sockaddr_in t4[PICOQUIC_NB_PATH_TARGET];
    struct sockaddr_in6 t6[PICOQUIC_NB_PATH_TARGET];
    int nb_trials;

    /* Initialize the test addresses to synthetic values */
    for (int i = 0; i < PICOQUIC_NB_PATH_TARGET; i++) {
        memset(&t4[i], 0, sizeof(struct sockaddr_in));
        t4[i].sin_family = AF_INET;
        t4[i].sin_port = 1000+i;
        memset(&t4[i].sin_addr, i, 4);
        memset(&t6[i], 0, sizeof(struct sockaddr_in6));
        t6[i].sin6_family = AF_INET6;
        t6[i].sin6_port = 2000 + i;
        memset(&t6[i].sin6_addr, i, 16);
    }

    /* Set a test connection between client and server */
    int ret = tls_api_init_ctx(&test_ctx, PICOQUIC_INTERNAL_TEST_VERSION_1,
        PICOQUIC_TEST_SNI, PICOQUIC_TEST_ALPN, &simulated_time, NULL, NULL, 0, 0, 0);

    if (ret == 0) {
        ret = tls_api_connection_loop(test_ctx, &loss_mask, 0, &simulated_time);
    }

    /* run a receive loop until no outstanding data */
    if (ret == 0) {
        ret = tls_api_synch_to_empty_loop(test_ctx, &simulated_time, 2048, PICOQUIC_NB_PATH_TARGET, 0);
    }

    if (ret == 0) {
        if (test_ctx->cnx_client->first_local_cnxid_list->nb_local_cnxid < PICOQUIC_NB_PATH_TARGET) {
            DBG_PRINTF("Only %d CID created on client.\n", test_ctx->cnx_client->first_local_cnxid_list->nb_local_cnxid);
            ret = -1;
        }
        else if (test_ctx->cnx_server->first_local_cnxid_list->nb_local_cnxid < PICOQUIC_NB_PATH_TARGET) {
            DBG_PRINTF("Only %d CID created on server.\n", test_ctx->cnx_server->first_local_cnxid_list->nb_local_cnxid);
        }
    }

    /* Now, create a series of probes.
     * There are only PICOQUIC_NB_PATH_TARGET - 1 paths available. 
     * The last trial should fail.
     */
    nb_trials = 0;

    for (int i = 1; ret == 0 && test_ctx->cnx_client->nb_paths < PICOQUIC_NB_PATH_TARGET; i++) {
        for (int j = 0; ret == 0 && j < 2; j++) {
            int ret_probe;
            if (j == 0) {
                ret_probe = picoquic_probe_new_path(test_ctx->cnx_client, (struct sockaddr *) &t4[0], 
                    (struct sockaddr *) &t4[i], simulated_time);
            } else {
                ret_probe = picoquic_probe_new_path(test_ctx->cnx_client, (struct sockaddr *) &t6[0],
                    (struct sockaddr *) &t6[i], simulated_time);
            }

            nb_trials++;

            if (nb_trials < PICOQUIC_NB_PATH_TARGET) {
                if (ret_probe != 0) {
                    DBG_PRINTF("Trial %d (%d, %d) fails with ret = %x\n", nb_trials, i, j, ret_probe);
                    ret = -1;
                }
            }
            else if (ret_probe == 0) {
                DBG_PRINTF("Trial %d (%d, %d) succeeds (unexpected)\n", nb_trials, i, j);
                ret = -1;
            }

            if (ret == 0 && ret_probe == 0) {
                int path_id = test_ctx->cnx_client->nb_paths - 1;
                for (int ichal = 0; ichal < PICOQUIC_CHALLENGE_REPEAT_MAX; ichal++) {
                    test_ctx->cnx_client->path[path_id]->challenge[ichal] = (uint64_t)10000 + (uint64_t)10 * i + j + (uint64_t)1000*ichal;
                }
            }
        }
    }

    /* Releasing the context will test the delete functions. */
    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }

    return ret;
}

/*
 * Migration test. The client is aware of the migration, and
 * starts the migration by explicitly probing a new path.
 */

int migration_test_scenario(test_api_stream_desc_t * scenario, size_t size_of_scenario, uint64_t loss_target, int cid_zero)
{
    uint64_t simulated_time = 0;
    uint64_t next_time = 0;
    uint64_t loss_mask = 0;
    uint64_t initial_challenge = 0;
    picoquic_connection_id_t target_id = picoquic_null_connection_id;
    picoquic_connection_id_t previous_local_id = picoquic_null_connection_id;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    int ret = tls_api_init_ctx_ex2(&test_ctx, PICOQUIC_INTERNAL_TEST_VERSION_1,
        PICOQUIC_TEST_SNI, PICOQUIC_TEST_ALPN, &simulated_time, NULL, NULL, 0, 0, 0, NULL, 8, cid_zero, 0, 0);

    if (ret == 0 && test_ctx == NULL) {
        ret = PICOQUIC_ERROR_MEMORY;
    }

    if (ret == 0) {
        ret = tls_api_connection_loop(test_ctx, &loss_mask, 0, &simulated_time);
    }

    /* run a receive loop until no outstanding data */
    if (ret == 0) {
        ret = tls_api_synch_to_empty_loop(test_ctx, &simulated_time, 2048, PICOQUIC_NB_PATH_TARGET, 1);
    }

    if (ret == 0) {
        /* Change the client address */
        test_ctx->client_addr.sin_port += 17;

        /* Probe the new path */
        ret = picoquic_probe_new_path(test_ctx->cnx_client, (struct sockaddr *)&test_ctx->server_addr,
            (struct sockaddr *)&test_ctx->client_addr, simulated_time);

        if (ret == 0) {
            target_id = test_ctx->cnx_client->path[test_ctx->cnx_client->nb_paths-1]->p_remote_cnxid->cnx_id;
            if (!cid_zero) {
                previous_local_id = test_ctx->cnx_client->path[0]->p_local_cnxid->cnx_id;
            }
        }
    }

    /* Prepare to send data */
    if (ret == 0) {
        ret = test_api_init_send_recv_scenario(test_ctx, scenario, size_of_scenario);
    }

    /* Perform a data sending loop */
    loss_mask = loss_target;

    if (ret == 0) {
        ret = tls_api_data_sending_loop(test_ctx, &loss_mask, &simulated_time, 0);
    }

    /* Check that the data was sent and received */
    if (ret == 0) {
        ret = tls_api_one_scenario_verify(test_ctx);
    }

    /* Add a time loop of 3 seconds to give some time for the probes to be repeated */
    next_time = simulated_time + 4000000;
    loss_mask = 0;
    while (ret == 0 && simulated_time < next_time && TEST_CLIENT_READY
        && TEST_SERVER_READY
        && (test_ctx->cnx_server->path[0]->challenge_verified != 1 || test_ctx->cnx_client->path[0]->path_is_demoted == 1 ||
            initial_challenge == test_ctx->cnx_server->path[0]->challenge[0])) {
        int was_active = 0;

        ret = tls_api_one_sim_round(test_ctx, &simulated_time, next_time, &was_active);
    }

    /* Verify that the challenge was updated and done */
    /* TODO: verify that exactly one challenge was sent */
    if (ret == 0 && test_ctx->cnx_server != NULL) {
        if (initial_challenge == test_ctx->cnx_server->path[0]->challenge[0]) {
            DBG_PRINTF("%s", "Challenge was not renewed after migration");
            ret = -1;
        }
        else if (test_ctx->cnx_server->path[0]->challenge_verified != 1) {
            DBG_PRINTF("%s", "Challenge was not verified after migration");
            ret = -1;
        }
    }

    /* Verify that the connection ID are what we expect */
    if (ret == 0) {
        if (picoquic_compare_connection_id(&test_ctx->cnx_client->path[0]->p_remote_cnxid->cnx_id, &target_id) != 0) {
            DBG_PRINTF("%s", "The remote CNX ID did not change to selected value");
            ret = -1;
        }
        else if (!cid_zero && picoquic_compare_connection_id(&test_ctx->cnx_client->path[0]->p_local_cnxid->cnx_id, &previous_local_id) == 0) {
            DBG_PRINTF("%s", "The local CNX ID did not change to a new value");
            ret = -1;
        }
    }

    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }

    return ret;
}

int migration_test()
{
    return migration_test_scenario(test_scenario_q_and_r, sizeof(test_scenario_q_and_r), 0, 0);
}

int migration_test_long()
{
    return migration_test_scenario(test_scenario_very_long, sizeof(test_scenario_very_long), 0, 0);
}

int migration_test_loss()
{
    uint64_t loss_mask = 0x09;

    return migration_test_scenario(test_scenario_q_and_r, sizeof(test_scenario_q_and_r), loss_mask, 0);
}

int migration_zero_test()
{
    return migration_test_scenario(test_scenario_very_long, sizeof(test_scenario_q_and_r), 0, 1);
}

/* Failed migration test.
 * Start a transfer, start a migration to a non existant address,
 * verify that the transfer completes */

int migration_fail_test()
{
    uint64_t simulated_time = 0;
    uint64_t loss_mask = 0;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    int ret = tls_api_init_ctx(&test_ctx, PICOQUIC_INTERNAL_TEST_VERSION_1,
        PICOQUIC_TEST_SNI, PICOQUIC_TEST_ALPN, &simulated_time, NULL, NULL, 0, 0, 0);

    /* establish the connection*/
    if (ret == 0) {
        ret = tls_api_connection_loop(test_ctx, &loss_mask, 0, &simulated_time);
    }

    /* Prepare to send data */
    if (ret == 0) {
        ret = test_api_init_send_recv_scenario(test_ctx, test_scenario_very_long, sizeof(test_scenario_very_long));

        if (ret != 0)
        {
            DBG_PRINTF("Init send receive scenario returns %d\n", ret);
        }
    }

    /* Perform a loop until the connection is in ready state */
    if (ret == 0) {
        ret = wait_client_connection_ready(test_ctx, &simulated_time);
    }

    /* Start migration to bogus address */
    if (ret == 0) {
        struct sockaddr_in bogus_addr = test_ctx->client_addr;
        bogus_addr.sin_port += 1;

        ret = picoquic_probe_new_path(test_ctx->cnx_client,
            (struct sockaddr*) & test_ctx->server_addr, (struct sockaddr*) & bogus_addr, simulated_time);
        if (ret != 0) {
            DBG_PRINTF("Probe new path returns %d\n", ret);
        }
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
        ret = tls_api_one_scenario_body_verify(test_ctx, &simulated_time, 1000000);
    }

    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }

    return ret;
}


/* Migration stress test. 
 * This simulates an attack, during which a man on the side injects fake migration
 * packets from false addresses. One of the addresses is maintained so that packets sent
 * to it are natted back to the client.
 *
 * The goal of the attack is to verify that the connection resists.
 */

int rebinding_stress_test()
{
    int nb_trials = 0;
    const int max_trials = 10000;
    int nb_inactive = 0;
    int client_rebinding_done = 0;
    struct sockaddr_in hack_address;
    struct sockaddr_in hack_address_random;
    uint64_t simulated_time = 0;
    uint64_t loss_mask = 0;
    uint64_t last_inject_time = 0;
    uint64_t random_context = 0xBABAC001CAFEull;
    picoquictest_sim_packet_t* last_client_packet_processed = NULL;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    int ret = tls_api_init_ctx(&test_ctx, PICOQUIC_INTERNAL_TEST_VERSION_1,
        PICOQUIC_TEST_SNI, PICOQUIC_TEST_ALPN, &simulated_time, NULL, NULL, 0, 0, 0);

    if (ret == 0 && test_ctx == NULL) {
        ret = PICOQUIC_ERROR_MEMORY;
    }

    if (ret == 0) {
        memcpy(&hack_address, &test_ctx->client_addr, sizeof(struct sockaddr_in));
        memcpy(&hack_address_random, &test_ctx->client_addr, sizeof(struct sockaddr_in));

        hack_address.sin_port += 1023;

        ret = tls_api_connection_loop(test_ctx, &loss_mask, 0, &simulated_time);
    }

    /* Prepare to send data */
    if (ret == 0) {
        ret = test_api_init_send_recv_scenario(test_ctx, test_scenario_very_long, sizeof(test_scenario_very_long));
    }

    /* Rewrite the sending loop, so we can add injection of packet copies */
    if (ret == 0) {
        test_ctx->client_use_multiple_addresses = 1;
    }

    while (ret == 0 && nb_trials < max_trials && nb_inactive < 256 && TEST_CLIENT_READY && TEST_SERVER_READY) {
        int was_active = 0;

        nb_trials++;

        ret = tls_api_one_sim_round(test_ctx, &simulated_time, 0, &was_active);

        if (ret < 0)
        {
            break;
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

        /* Packet injection at the server */
        if (test_ctx->c_to_s_link->last_packet != NULL) {
            uint64_t server_arrival = test_ctx->c_to_s_link->last_packet->arrival_time;

            if (server_arrival > last_inject_time) {
                /* 9% chance of packet injection, 5% chances of reusing test address */
                uint64_t rand100 = picoquic_test_uniform_random(&random_context, 100);
                last_inject_time = server_arrival;
                if (rand100 < 9) {
                    struct sockaddr * bad_address;
                    if (rand100 < 5) {
                        bad_address = (struct sockaddr *)&hack_address;
                    }
                    else {
                        hack_address_random.sin_port = (uint16_t)picoquic_test_uniform_random(&random_context, 0x10000);
                        bad_address = (struct sockaddr *)&hack_address_random;
                    }
                    ret = picoquic_incoming_packet(test_ctx->qserver,
                        test_ctx->c_to_s_link->last_packet->bytes,
                        (uint32_t)test_ctx->c_to_s_link->last_packet->length,
                        bad_address,
                        (struct sockaddr*)&test_ctx->c_to_s_link->last_packet->addr_to, 0, test_ctx->recv_ecn_server,
                        simulated_time);
                }
            }
        }

        /* Initially, the attacker relays packets to the client. Then, it gives up */
        if (test_ctx->cnx_server->pkt_ctx[picoquic_packet_context_application].send_sequence > 256) {
            test_ctx->client_use_multiple_addresses = 0;
        }

        if (test_ctx->client_use_multiple_addresses && test_ctx->s_to_c_link->last_packet != NULL &&
            test_ctx->s_to_c_link->last_packet != last_client_packet_processed){
            last_client_packet_processed = test_ctx->s_to_c_link->last_packet;
            /* Packet reinjection at the client if using the special address */
            if (picoquic_compare_addr((struct sockaddr *)&hack_address, (struct sockaddr *)&test_ctx->s_to_c_link->last_packet->addr_to) == 0)
            {
                picoquic_store_addr(&test_ctx->s_to_c_link->last_packet->addr_to, (struct sockaddr *)&test_ctx->client_addr);
            }
            else if (test_ctx->client_use_nat) {
                if (picoquic_compare_addr((struct sockaddr*) & test_ctx->client_addr_natted, (struct sockaddr*) & test_ctx->s_to_c_link->last_packet->addr_to) == 0) {
                    picoquic_store_addr(&test_ctx->s_to_c_link->last_packet->addr_to, (struct sockaddr*) & test_ctx->client_addr);
                }
                else {
                    /* This packet should be dropped on arrival */
                    test_ctx->s_to_c_link->last_packet->length = 1;
                }
            }
            else if (picoquic_compare_addr((struct sockaddr*) & test_ctx->client_addr, (struct sockaddr*) & test_ctx->s_to_c_link->last_packet->addr_to) != 0) {
                /* This packet should be dropped on arrival */
                test_ctx->s_to_c_link->last_packet->length = 1;
            }
        }

        /* At some point, the client does migrate to a new address */
        if (!client_rebinding_done && test_ctx->cnx_server->pkt_ctx[picoquic_packet_context_application].send_sequence > 128) {
            test_ctx->client_addr_natted = test_ctx->client_addr;
            test_ctx->client_addr_natted.sin_port += 17;
            test_ctx->client_use_nat = 1;
            client_rebinding_done = 1;
        }
    }

    if (ret == 0) {
        ret = tls_api_attempt_to_close(test_ctx, &simulated_time);
    }

    if (ret == 0) {
        if (test_ctx->server_callback.error_detected) {
            ret = -1;
        }
        else if (test_ctx->client_callback.error_detected) {
            ret = -1;
        }
        else {
            for (size_t i = 0; ret == 0 && i < test_ctx->nb_test_streams; i++) {
                if (test_ctx->test_stream[i].q_recv_nb != test_ctx->test_stream[i].q_len) {
                    ret = -1;
                }
                else if (test_ctx->test_stream[i].r_recv_nb != test_ctx->test_stream[i].r_len) {
                    ret = -1;
                }
                else if (test_ctx->test_stream[i].q_received == 0 || test_ctx->test_stream[i].r_received == 0) {
                    ret = -1;
                }
            }
        }
        if (ret != 0)
        {
            DBG_PRINTF("Test scenario verification returns %d\n", ret);
        }
    }

    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }

    return ret;
}



/* Connection ID renewal test.
 * The client starts using a new server CID.
 * We expect the server to switch to using a new client CID
 */

int cnxid_renewal_test()
{
    uint64_t simulated_time = 0;
    uint64_t next_time = 0;
    uint64_t loss_mask = 0;
    picoquic_connection_id_t target_id = picoquic_null_connection_id;
    picoquic_connection_id_t previous_local_id = picoquic_null_connection_id;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    int ret = tls_api_init_ctx(&test_ctx, PICOQUIC_INTERNAL_TEST_VERSION_1,
        PICOQUIC_TEST_SNI, PICOQUIC_TEST_ALPN, &simulated_time, NULL, NULL, 0, 0, 0);

    if (ret == 0 && test_ctx == NULL) {
        ret = PICOQUIC_ERROR_MEMORY;
    }

    if (ret == 0) {
        ret = tls_api_connection_loop(test_ctx, &loss_mask, 0, &simulated_time);
    }

    /* run a receive loop until no outstanding data */
    if (ret == 0) {
        ret = tls_api_synch_to_empty_loop(test_ctx, &simulated_time, 2048, PICOQUIC_NB_PATH_TARGET, 1);
    }

    /* Renew the connection ID */
    if (ret == 0) {
        ret = picoquic_renew_connection_id(test_ctx->cnx_client, 0);
        if (ret == 0) {
            target_id = test_ctx->cnx_client->path[0]->p_remote_cnxid->cnx_id;
            previous_local_id = test_ctx->cnx_client->path[0]->p_local_cnxid->cnx_id;
        }
    }

    /* Prepare to send data */
    if (ret == 0) {
        ret = test_api_init_send_recv_scenario(test_ctx, test_scenario_q_and_r, sizeof(test_scenario_q_and_r));
    }

    /* Perform a data sending loop */
    if (ret == 0) {
        ret = tls_api_data_sending_loop(test_ctx, &loss_mask, &simulated_time, 0);
    }

    /* Add a time loop of 7 seconds to give some time for the probes to be repeated,
     * and to ensure that the demotion timers expire. */
    next_time = simulated_time + 7000000;
    loss_mask = 0;
    while (ret == 0 && simulated_time < next_time && TEST_CLIENT_READY
        && TEST_SERVER_READY) {
        int was_active = 0;

        ret = tls_api_one_sim_round(test_ctx, &simulated_time, next_time, &was_active);
    }

    /* verify that path[0] was not demoted */
    if (ret == 0) {
        if (test_ctx->cnx_client->path[0]->path_is_demoted) {
            DBG_PRINTF("%s", "The default client path is demoted");
            ret = -1;
        }
        if (test_ctx->cnx_server != NULL && test_ctx->cnx_server->path[0]->path_is_demoted) {
            DBG_PRINTF("%s", "The default server path is demoted");
            ret = -1;
        }
    }

    /* Verify that the connection ID are what we expect */
    if (ret == 0) {
        if (picoquic_compare_connection_id(&test_ctx->cnx_client->path[0]->p_remote_cnxid->cnx_id, &target_id) != 0) {
            DBG_PRINTF("%s", "The remote CNX ID migrated from the selected value");
            ret = -1;
        }
        else if (picoquic_compare_connection_id(&test_ctx->cnx_client->path[0]->p_local_cnxid->cnx_id, &previous_local_id) == 0) {
            DBG_PRINTF("%s", "The local CNX ID did not change to a new value");
            ret = -1;
        }
    }

    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }

    return ret;
}


/*
 * Perform a test of the "retire connection id" function.
 * The test will artificially retire connection ID on the client,
 * and verify that the server will refill the stash of 
 * connection ID.
 */
int retire_cnxid_test()
{
    uint64_t simulated_time = 0;
    uint64_t loss_mask = 0;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    int ret = tls_api_init_ctx(&test_ctx, PICOQUIC_INTERNAL_TEST_VERSION_1,
        PICOQUIC_TEST_SNI, PICOQUIC_TEST_ALPN, &simulated_time, NULL, NULL, 0, 0, 0);

    if (ret == 0) {
        ret = tls_api_connection_loop(test_ctx, &loss_mask, 0, &simulated_time);
    }

    /* run a receive loop until no outstanding data */
    if (ret == 0) {
        ret = tls_api_synch_to_empty_loop(test_ctx, &simulated_time, 2048, PICOQUIC_NB_PATH_TARGET, 0);
    }

    if (ret == 0) {
        if (test_ctx->cnx_client->first_local_cnxid_list->nb_local_cnxid < PICOQUIC_NB_PATH_TARGET) {
            DBG_PRINTF("Only %d cids created on client.\n", test_ctx->cnx_client->first_local_cnxid_list->nb_local_cnxid);
            ret = -1;
        }
        else if (test_ctx->cnx_server->first_local_cnxid_list->nb_local_cnxid < PICOQUIC_NB_PATH_TARGET) {
            DBG_PRINTF("Only %d cids created on server.\n", test_ctx->cnx_server->first_local_cnxid_list->nb_local_cnxid);
            ret = -1;
        }
    }

    /* Delete several connection ID */
    for (int i = 2; ret == 0 && i < PICOQUIC_NB_PATH_TARGET; i++) {
        picoquic_remote_cnxid_t * stashed = picoquic_obtain_stashed_cnxid(test_ctx->cnx_client, 0);

        if (stashed == NULL) {
            DBG_PRINTF("Could not retrieve cnx ID #%d.\n", i-1);
            ret = -1;
        } else {
            ret = picoquic_queue_retire_connection_id_frame(test_ctx->cnx_client, 0, stashed->sequence);
            (void)picoquic_remove_stashed_cnxid(test_ctx->cnx_client, 0, stashed, NULL);
        }
    }

    /* run the loop again until no outstanding data */
    if (ret == 0) {
        uint64_t time_out = simulated_time + 8000000;
        int nb_rounds = 0;
        int success = 0;

        while (ret == 0 && simulated_time < time_out &&
            nb_rounds < 2048 && test_ctx->cnx_client->cnx_state != picoquic_state_disconnected) {
            int was_active = 0; 

            ret = tls_api_one_sim_round(test_ctx, &simulated_time, time_out, &was_active);
            nb_rounds++;

            if (test_ctx->cnx_client->first_local_cnxid_list->nb_local_cnxid >= PICOQUIC_NB_PATH_TARGET &&
                test_ctx->cnx_server->first_local_cnxid_list->nb_local_cnxid >= PICOQUIC_NB_PATH_TARGET &&
                test_ctx->cnx_client->first_misc_frame == NULL &&
                test_cnxid_count_stash(test_ctx->cnx_client) >= (PICOQUIC_NB_PATH_TARGET - 1) &&
                picoquic_is_cnx_backlog_empty(test_ctx->cnx_client) &&
                picoquic_is_cnx_backlog_empty(test_ctx->cnx_server)) {
                success = 1;
                break;
            }
        }

        if (ret == 0 && success == 0) {
            DBG_PRINTF("Exit synch loop after %d rounds, backlog or not enough cids (%d & %d).\n",
                nb_rounds, test_ctx->cnx_client->first_local_cnxid_list->nb_local_cnxid, test_ctx->cnx_server->first_local_cnxid_list->nb_local_cnxid);
        }
    }

    /* Check */

    if (ret == 0) {
        if (test_ctx->cnx_server->first_local_cnxid_list->nb_local_cnxid != PICOQUIC_NB_PATH_TARGET) {
            DBG_PRINTF("Found %d cids active on server instead of %d.\n", test_ctx->cnx_server->first_local_cnxid_list->nb_local_cnxid, PICOQUIC_NB_PATH_TARGET);
            ret = -1;
        }
    }

    if (ret == 0) {
        ret = transmit_cnxid_test_stash(test_ctx->cnx_client, test_ctx->cnx_server, "client");
    }

    if (ret == 0) {
        ret = transmit_cnxid_test_stash(test_ctx->cnx_server, test_ctx->cnx_client, "server");
    }

    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }

    return ret;
}


/*
 * Perform a test of the "not before" CNXID function.
 * The test will artificially simulate receiving a "not before"
 * parameter in a new connection ID test, to check that the
 * old connection ID are removed and successfully replaced.
 */
int not_before_cnxid_test()
{
    uint64_t simulated_time = 0;
    uint64_t loss_mask = 0;
    uint64_t not_before;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    int ret = tls_api_init_ctx(&test_ctx, PICOQUIC_INTERNAL_TEST_VERSION_1,
        PICOQUIC_TEST_SNI, PICOQUIC_TEST_ALPN, &simulated_time, NULL, NULL, 0, 0, 0);

    if (ret == 0) {
        ret = tls_api_connection_loop(test_ctx, &loss_mask, 0, &simulated_time);
    }

    /* run a receive loop until no outstanding data */
    if (ret == 0) {
        ret = tls_api_synch_to_empty_loop(test_ctx, &simulated_time, 2048, PICOQUIC_NB_PATH_TARGET, 0);
    }

    /* find a plausible "not before" value, and apply it */
    if (ret == 0) {
        not_before = test_ctx->cnx_server->first_local_cnxid_list->local_cnxid_sequence_next - 1;
        uint64_t transport_error = picoquic_remove_not_before_cid(test_ctx->cnx_client, 0, not_before, simulated_time);
        if (transport_error != 0) {
            DBG_PRINTF("picoquic_remove_not_before_cid returns 0x%" PRIx64, transport_error);
            ret = -1;
        }
    }

    /* run the loop again until no outstanding data */
    if (ret == 0) {
        uint64_t time_out = simulated_time + 8000000;
        int nb_rounds = 0;
        int success = 0;

        while (ret == 0 && simulated_time < time_out &&
            nb_rounds < 2048 && test_ctx->cnx_client->cnx_state != picoquic_state_disconnected) {
            int was_active = 0;

            ret = tls_api_one_sim_round(test_ctx, &simulated_time, time_out, &was_active);
            nb_rounds++;

            if (nb_rounds == 30) {
                ret = 0;
            }

            if (test_ctx->cnx_client->first_local_cnxid_list->nb_local_cnxid >= PICOQUIC_NB_PATH_TARGET &&
                test_ctx->cnx_server->first_local_cnxid_list->nb_local_cnxid >= PICOQUIC_NB_PATH_TARGET &&
                test_ctx->cnx_client->first_misc_frame == NULL &&
                test_cnxid_count_stash(test_ctx->cnx_client) >= (PICOQUIC_NB_PATH_TARGET - 1) &&
                test_cnxid_count_stash(test_ctx->cnx_server) >= (PICOQUIC_NB_PATH_TARGET - 1) &&
                picoquic_is_cnx_backlog_empty(test_ctx->cnx_client) &&
                picoquic_is_cnx_backlog_empty(test_ctx->cnx_server)) {
                success = 1;
                break;
            }
        }

        if (ret == 0 && success == 0) {
            DBG_PRINTF("Exit synch loop after %d rounds, backlog or not enough cid (%d & %d).\n",
                nb_rounds, test_ctx->cnx_client->first_local_cnxid_list->nb_local_cnxid, test_ctx->cnx_server->first_local_cnxid_list->nb_local_cnxid);
        }
    }

    /* Check */

    if (ret == 0) {
        if (test_ctx->cnx_server->first_local_cnxid_list->nb_local_cnxid != PICOQUIC_NB_PATH_TARGET) {
            DBG_PRINTF("Found %d cid active on server instead of %d.\n", test_ctx->cnx_server->first_local_cnxid_list->nb_local_cnxid, PICOQUIC_NB_PATH_TARGET + 1);
            ret = -1;
        }
    }

    if (ret == 0) {
        ret = transmit_cnxid_test_stash(test_ctx->cnx_client, test_ctx->cnx_server, "client");
    }

    if (ret == 0) {
        ret = transmit_cnxid_test_stash(test_ctx->cnx_server, test_ctx->cnx_client, "server");
    }

    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }

    return ret;
}

/*
 * Server busy. Verify that the connection fails with the proper error code, and then that once the server is not busy the next connection succeeds.
 */

int server_busy_test()
{
    uint64_t loss_mask = 0;
    uint64_t simulated_time = 0;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    int ret = tls_api_init_ctx(&test_ctx, 0, PICOQUIC_TEST_SNI, PICOQUIC_TEST_ALPN, &simulated_time, NULL, NULL, 0, 0, 0);

    if (ret == 0) {
        test_ctx->qserver->server_busy = 1;
        (void) tls_api_connection_loop(test_ctx, &loss_mask, 0, &simulated_time);

        if (test_ctx->cnx_server != NULL &&
            test_ctx->cnx_server->cnx_state != picoquic_state_disconnected) {
            DBG_PRINTF("Server state: %d, local error: %" PRIx64, test_ctx->cnx_server->cnx_state, test_ctx->cnx_server->local_error);
            ret = -1;
        }
        else if (test_ctx->cnx_client->cnx_state != picoquic_state_disconnected ||
            test_ctx->cnx_client->remote_error != PICOQUIC_TRANSPORT_SERVER_BUSY) {
            DBG_PRINTF("Client state: %d, remote error: %" PRIx64, test_ctx->cnx_client->cnx_state, test_ctx->cnx_client->remote_error);
            ret = -1;
        }
        else if (simulated_time > 500000ull) {
            DBG_PRINTF("Simulated time: %" PRIu64, (unsigned long long)simulated_time);
            ret = -1;
        }
    }

    if (ret == 0) {
        test_ctx->qserver->server_busy = 0;

        if (test_ctx->cnx_server != NULL) {
            picoquic_delete_cnx(test_ctx->cnx_server);
            test_ctx->cnx_server = NULL;
        }
        if (test_ctx->cnx_client != NULL) {
            picoquic_delete_cnx(test_ctx->cnx_client);
            test_ctx->cnx_client = NULL;
        }

        /* Create a new client connection */
        test_ctx->cnx_client = picoquic_create_cnx(test_ctx->qclient,
            picoquic_null_connection_id, picoquic_null_connection_id,
            (struct sockaddr*)&test_ctx->server_addr, simulated_time,
            0, PICOQUIC_TEST_SNI, PICOQUIC_TEST_ALPN, 1);

        if (test_ctx->cnx_client == NULL) {
            ret = -1;
        } else {
            ret = picoquic_start_client_cnx(test_ctx->cnx_client);
        }
    }

    if (ret == 0) {
        ret = tls_api_connection_loop(test_ctx, &loss_mask, 0, &simulated_time);
    }

    if (ret == 0) {
        ret = tls_api_attempt_to_close(test_ctx, &simulated_time);
    }

    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }

    return ret;
}

/*
 * Initial close test. Check what happens when the client closes a connection without waiting for the full establishment
 */

int initial_close_test()
{
    uint64_t loss_mask = 0;
    uint64_t simulated_time = 0;
    int was_active = 0;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    int ret = tls_api_init_ctx(&test_ctx, 0, PICOQUIC_TEST_SNI, PICOQUIC_TEST_ALPN, &simulated_time, NULL, NULL, 0, 0, 0);

    if (ret == 0) {
        /* Send the initial packet, but no more than that */
        ret = tls_api_one_sim_round(test_ctx, &simulated_time, 0, &was_active);

        if (ret == 0) {
            test_ctx->cnx_client->cnx_state = picoquic_state_handshake_failure;
            test_ctx->cnx_client->local_error = 0xDEAD;
            picoquic_reinsert_by_wake_time(test_ctx->qclient, test_ctx->cnx_client, simulated_time);
        }
    }

    if (ret == 0) {
        for (int i = 0; i < 128; i++) {
            ret = tls_api_one_sim_round(test_ctx, &simulated_time, 0, &was_active);
            if (test_ctx->cnx_server != NULL) {
                break;
            }
        }
        if (ret == 0) {
            ret = tls_api_connection_loop(test_ctx, &loss_mask, 0, &simulated_time);
        }

        if (ret == 0) {
            if (test_ctx->cnx_server == NULL) {
                DBG_PRINTF("%s", "Server connection deleted, cannot verify error code.\n");
                ret = -1;
            }
            else if (test_ctx->cnx_server->cnx_state != picoquic_state_disconnected ||
                test_ctx->cnx_server->remote_error != 0xDEAD) {
                DBG_PRINTF("Server state: %d, remote error: %x\n", test_ctx->cnx_server->cnx_state, test_ctx->cnx_server->remote_error);
                ret = -1;
            }
            else if (test_ctx->cnx_client->cnx_state != picoquic_state_disconnected) {
                DBG_PRINTF("Client state: %d, local error: %x", test_ctx->cnx_client->cnx_state, test_ctx->cnx_client->local_error);
                ret = -1;
            }
            else if (simulated_time > 50000ull) {
                DBG_PRINTF("Simulated time: %llu", (unsigned long long)simulated_time);
                ret = -1;
            }
        }
    }

    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }

    return ret;
}

/*
 * Check what happens if the server detects an error in the client's initial
 * message. Verify that the client receives the error code.
 */

int initial_server_close_test()
{
    uint64_t loss_mask = 0;
    uint64_t simulated_time = 0;
    int was_active = 0;
    int nb_trials = 0;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    int ret = tls_api_init_ctx(&test_ctx, 0, PICOQUIC_TEST_SNI, PICOQUIC_TEST_ALPN, &simulated_time, NULL, NULL, 0, 0, 0);

    /* Set the connection on the server side, but not on the client side */
    while (ret == 0 && nb_trials < 32 ) {
        nb_trials++;

        ret = tls_api_one_sim_round(test_ctx, &simulated_time, 0, &was_active);

        if (test_ctx->cnx_server != NULL && test_ctx->cnx_server->cnx_state == picoquic_state_server_almost_ready) {
            break;
        }
    }

    if (test_ctx->cnx_server == NULL || test_ctx->cnx_server->cnx_state != picoquic_state_server_almost_ready) {
        DBG_PRINTF("Server state: %d\n", (test_ctx->cnx_server == NULL) ?
            -1 : test_ctx->cnx_server->cnx_state);
        ret = -1;
    }

    if (ret == 0) {
        test_ctx->cnx_server->cnx_state = picoquic_state_handshake_failure;
        test_ctx->cnx_server->local_error = 0xDEAD;
        picoquic_reinsert_by_wake_time(test_ctx->qserver, test_ctx->cnx_server, simulated_time);
    }


    if (ret == 0) {
        ret = tls_api_connection_loop(test_ctx, &loss_mask, 0, &simulated_time);
    }

    if (ret == 0) {
        if (test_ctx->cnx_server != NULL &&
            test_ctx->cnx_server->cnx_state != picoquic_state_disconnected) {
            DBG_PRINTF("Server state: %d, remote error: %x\n", test_ctx->cnx_server->cnx_state, test_ctx->cnx_server->remote_error);
            ret = -1;
        }
        else if (test_ctx->cnx_client->cnx_state != picoquic_state_disconnected ||
            test_ctx->cnx_client->remote_error != 0xDEAD) {
            DBG_PRINTF("Client state: %d, local error: %x", test_ctx->cnx_client->cnx_state, test_ctx->cnx_client->local_error);
            ret = -1;
        }
        else if (simulated_time > 50000ull) {
            DBG_PRINTF("Simulated time: %llu", (unsigned long long)simulated_time);
            ret = -1;
        }
    }

    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }

    return ret;
}


/*
 * Test that rotated keys are computed in a compatible way on client and server.
 */

static int aead_iv_check(void * aead1, void * aead2)
{
    int ret = 0;
#if 0
    ptls_aead_context_t *ctx1 = (ptls_aead_context_t *)aead1;
    ptls_aead_context_t *ctx2 = (ptls_aead_context_t *)aead2;

    if (memcmp(ctx1->static_iv, ctx2->static_iv, ctx1->algo->iv_size) != 0) {
        ret = -1;
    }
#else
    /* TODO: find a replacement for this test */
#ifdef _WINDOWS
    UNREFERENCED_PARAMETER(aead1);
    UNREFERENCED_PARAMETER(aead2);
#endif
#endif
    return ret;
}

#if 0
static int pn_enc_check(void * pn1, void * pn2)
{
    int ret = 0;
    uint8_t seed[16] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
    uint8_t pn[4] = { 0, 1, 2 ,3 };
    uint8_t pn_enc[4];
    uint8_t pn_dec[4];

    picoquic_pn_encrypt(pn1, seed, pn_enc, pn, 4);
    picoquic_pn_encrypt(pn2, seed, pn_dec, pn_enc, 4);

    if (memcmp(pn_dec, pn, 4) != 0) {
        ret = -1;
    }
    return ret;
}
#endif

int new_rotated_key_test()
{
    uint64_t loss_mask = 0;
    uint64_t simulated_time = 0;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    int ret = tls_api_init_ctx(&test_ctx, 0, PICOQUIC_TEST_SNI, PICOQUIC_TEST_ALPN, &simulated_time, NULL, NULL, 0, 0, 0);

    if (ret == 0) {
        ret = tls_api_connection_loop(test_ctx, &loss_mask, 0, &simulated_time);
    }

    if (ret == 0) {
        ret = wait_application_aead_ready(test_ctx, &simulated_time);
    }


    for (int i = 1; ret == 0 && i <= 3; i++) {
        
        /* Try to compute rotated keys on server */
        ret = picoquic_compute_new_rotated_keys(test_ctx->cnx_server);
        if (ret != 0) {
            DBG_PRINTF("Could not rotate server key, ret: %x\n", ret);
        } else {
            /* Try to compute rotated keys on client */
            ret = picoquic_compute_new_rotated_keys(test_ctx->cnx_client);
            if (ret != 0) {
                DBG_PRINTF("Could not rotate client key, round %d, ret: %x\n", i, ret);
            }
        }

        if (ret == 0)
        {
            /* Compare server encryption and client decryption */
            size_t key_size = picoquic_get_app_secret_size(test_ctx->cnx_client);

            if (key_size != picoquic_get_app_secret_size(test_ctx->cnx_server)) {
                DBG_PRINTF("Round %d. Key sizes dont match, client: %d, server: %d\n", i, key_size, picoquic_get_app_secret_size(test_ctx->cnx_server));
                ret = -1;
            }
            else if (memcmp(picoquic_get_app_secret(test_ctx->cnx_server, 1), picoquic_get_app_secret(test_ctx->cnx_client, 0), key_size) != 0) {
                DBG_PRINTF("Round %d. Server encryption secret does not match client decryption secret\n", i);
                ret = -1;
            }
            else if (memcmp(picoquic_get_app_secret(test_ctx->cnx_server, 0), picoquic_get_app_secret(test_ctx->cnx_client, 1), key_size) != 0) {
                DBG_PRINTF("Round %d. Server decryption secret does not match client encryption secret\n", i);
                ret = -1;
            }
            else if (aead_iv_check(test_ctx->cnx_server->crypto_context_new.aead_encrypt, test_ctx->cnx_client->crypto_context_new.aead_decrypt) != 0) {
                DBG_PRINTF("Round %d. Client AEAD decryption does not match server AEAD encryption.\n", i);
                ret = -1;
            }
            else if (aead_iv_check(test_ctx->cnx_client->crypto_context_new.aead_encrypt, test_ctx->cnx_server->crypto_context_new.aead_decrypt) != 0) {
                DBG_PRINTF("Round %d. Server AEAD decryption does not match cliens AEAD encryption.\n", i);
                ret = -1;
            }
#if 0
            else if (pn_enc_check(test_ctx->cnx_server->crypto_context_new.pn_enc, test_ctx->cnx_client->crypto_context_new.pn_dec) != 0) {
                DBG_PRINTF("Round %d. Client PN decryption does not match server PN encryption.\n", i);
                ret = -1;
            }
            else if (pn_enc_check(test_ctx->cnx_client->crypto_context_new.pn_enc, test_ctx->cnx_server->crypto_context_new.pn_dec) != 0) {
                DBG_PRINTF("Round %d. Server PN decryption does not match client PN encryption.\n", i);
                ret = -1;
            }
#endif
        }

        picoquic_crypto_context_free(&test_ctx->cnx_server->crypto_context_new);
        picoquic_crypto_context_free(&test_ctx->cnx_client->crypto_context_new);
    }

    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }

    return ret;
}


/*
 * Key rotation tests
 */

static int inject_false_rotation(picoquic_test_tls_api_ctx_t* test_ctx, int target_client, uint64_t simulated_time)
{
    /* In order to test robustness of key rotation against attacks, we inject a
     * random packet with properly set header indication transition */
    int ret = 0;
    picoquic_cnx_t * cnx = (target_client) ? test_ctx->cnx_client : test_ctx->cnx_server;
    picoquictest_sim_link_t* target_link = (target_client) ? test_ctx->s_to_c_link : test_ctx->c_to_s_link;
    picoquictest_sim_packet_t* packet = picoquictest_sim_link_create_packet();

    if (packet == NULL || cnx == NULL) {
        ret = -1;
    }
    else {
        uint64_t random_context = (0x123456789ABCDEF0ull)|cnx->pkt_ctx[picoquic_packet_context_application].send_sequence;
        size_t byte_index = 1;

        packet->bytes[0] = 0x3F | ((cnx->key_phase_dec) ? 0 : 0x40); /* Set phase to opposite of expected value */

        for (uint8_t i = 0; i < cnx->path[0]->p_local_cnxid->cnx_id.id_len; i++) {
            packet->bytes[byte_index++] = cnx->path[0]->p_local_cnxid->cnx_id.id[i];
        }
        picoquic_test_random_bytes(&random_context, packet->bytes + byte_index, 128u - byte_index);
        packet->length = 128;

        if (target_client) {
            picoquic_store_addr(&packet->addr_from, (struct sockaddr *)&test_ctx->server_addr);
            picoquic_store_addr(&packet->addr_to, (struct sockaddr *)&test_ctx->client_addr);
        }
        else {
            picoquic_store_addr(&packet->addr_from, (struct sockaddr *)&test_ctx->client_addr);
            picoquic_store_addr(&packet->addr_to, (struct sockaddr *)&test_ctx->server_addr);
        }

        picoquictest_sim_link_submit(target_link, packet, simulated_time);
    }

    return ret;
}

static int key_rotation_test_one(int inject_bad_packet)
{
    uint64_t simulated_time = 0;
    uint64_t loss_mask = 0;
    int nb_trials = 0;
    int nb_inactive = 0;
    int max_trials = 100000;
    int nb_rotation = 0;
    uint64_t rotation_sequence = 100;
    uint64_t injection_sequence = 50;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    int ret = tls_api_init_ctx(&test_ctx, PICOQUIC_INTERNAL_TEST_VERSION_1,
        PICOQUIC_TEST_SNI, PICOQUIC_TEST_ALPN, &simulated_time, NULL, NULL, 0, 0, 0);

    if (ret == 0 && test_ctx == NULL) {
        ret = PICOQUIC_ERROR_MEMORY;
    }

    if (ret == 0) {
        ret = tls_api_connection_loop(test_ctx, &loss_mask, 0, &simulated_time);
    }

    /* Prepare to send data */
    if (ret == 0) {
        ret = test_api_init_send_recv_scenario(test_ctx, test_scenario_sustained, sizeof(test_scenario_sustained));
    }

    /* Perform a data sending loop, during which various key rotations are tried
     * every 100 packets or so. To test robustness, inject bogus packets that
     * mimic a transition trigger */

    while (ret == 0 && nb_trials < max_trials && nb_inactive < 256 && TEST_CLIENT_READY && TEST_SERVER_READY) {
        int was_active = 0;

        nb_trials++;

        if (inject_bad_packet &&
            test_ctx->cnx_server->pkt_ctx[picoquic_packet_context_application].send_sequence > injection_sequence) {
            ret = inject_false_rotation(test_ctx, inject_bad_packet >> 1, simulated_time);
            if (ret != 0) {
                DBG_PRINTF("Could not inject bad packet, ret = %d\n", ret);
                break;
            }
            else {
                injection_sequence += 50;
            }
        }

        if (test_ctx->cnx_server->pkt_ctx[picoquic_packet_context_application].send_sequence > rotation_sequence &&
            picoquic_sack_list_last(&test_ctx->cnx_server->ack_ctx[picoquic_packet_context_application].sack_list) >
            test_ctx->cnx_server->crypto_epoch_sequence &&
            picoquic_sack_list_last(&test_ctx->cnx_client->ack_ctx[picoquic_packet_context_application].sack_list) >
            test_ctx->cnx_client->crypto_epoch_sequence &&
            test_ctx->cnx_server->key_phase_enc == test_ctx->cnx_server->key_phase_dec &&
            test_ctx->cnx_client->key_phase_enc == test_ctx->cnx_client->key_phase_dec) {
            rotation_sequence = test_ctx->cnx_server->pkt_ctx[picoquic_packet_context_application].send_sequence + 100;
            injection_sequence = test_ctx->cnx_server->pkt_ctx[picoquic_packet_context_application].send_sequence + 50;
            nb_rotation++;
            switch (nb_rotation) {
            case 1: /* Key rotation at the client */
                ret = picoquic_start_key_rotation(test_ctx->cnx_client);
                break;
            case 2: /* Key rotation at the server */
                ret = picoquic_start_key_rotation(test_ctx->cnx_server);
                break;
            case 3: /* Simultaneous key rotation at the client */
                rotation_sequence += 1000000000;
                ret = picoquic_start_key_rotation(test_ctx->cnx_client);
                if (ret == 0) {
                    ret = picoquic_start_key_rotation(test_ctx->cnx_server);
                }
                break;
            default:
                break;
            }

            if (ret != 0) {
                DBG_PRINTF("Could not start rotation #%d, ret = %x\n", nb_rotation, ret);
            }
        }

        if (ret == 0) {
            ret = tls_api_one_sim_round(test_ctx, &simulated_time, 0, &was_active);
        }

        if (ret < 0)
        {
            break;
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

    if (ret == 0 && nb_rotation < 3) {
        DBG_PRINTF("Only %d key rotations completed out of 3\n", nb_rotation);
        ret = -1;
    }

    if (ret == 0) {
        ret = tls_api_attempt_to_close(test_ctx, &simulated_time);

        if (ret != 0)
        {
            DBG_PRINTF("Connection close returns %d\n", ret);
        }
    }

    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }

    return ret;
}

int key_rotation_test()
{
    int ret = key_rotation_test_one(0);

    if (ret == 0) {
        /* test rotation with injection of bad packets on client */
        ret = key_rotation_test_one(2);
        if (ret != 0) {
            DBG_PRINTF("%s", "Packet injection on client defeats rotation.\n", ret);
        }
    }

    if (ret == 0) {
        /* test rotation with injection of bad packets on server */
        ret = key_rotation_test_one(1);
        if (ret != 0) {
            DBG_PRINTF("%s", "Packet injection on server defeats rotation.\n", ret);
        }
    }

    return ret;
}

static int key_rotation_auto_one(uint64_t epoch_length, int client_test)
{
    uint64_t simulated_time = 0;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    int ret = tls_api_init_ctx(&test_ctx, PICOQUIC_INTERNAL_TEST_VERSION_1,
        PICOQUIC_TEST_SNI, PICOQUIC_TEST_ALPN, &simulated_time, NULL, NULL, 0, 1, 0);

    if (ret == 0 && test_ctx == NULL) {
        ret = PICOQUIC_ERROR_MEMORY;
    }

    if (ret == 0) {
        if (client_test) {
            picoquic_set_crypto_epoch_length(test_ctx->cnx_client, epoch_length);
        }
        else {
            picoquic_set_default_crypto_epoch_length(test_ctx->qserver, epoch_length);
        }
        /* Run a basic test scenario */

        ret = tls_api_one_scenario_body(test_ctx, &simulated_time,
            test_scenario_key_rotation, sizeof(test_scenario_key_rotation), 0, 0, 0, 0, 2000000);
    }

    if (ret == 0) {
        uint64_t nb_rotation_expected;
        uint64_t nb_rotation_max;
        uint64_t nb_packets;
        picoquic_cnx_t* cnx = (client_test) ? test_ctx->cnx_server : test_ctx->cnx_client;

        nb_packets = cnx->pkt_ctx[picoquic_packet_context_application].send_sequence;
        nb_rotation_expected = nb_packets / (epoch_length + 10);
        nb_rotation_max = nb_packets / (epoch_length - 10);

        if (nb_rotation_expected > cnx->nb_crypto_key_rotations) {
            DBG_PRINTF("Only %" PRIu64 " key rotations completed instead of at least %" PRIu64 "\n",
                cnx->nb_crypto_key_rotations, nb_rotation_expected);
            ret = -1;
        }
        else if (nb_rotation_max < cnx->nb_crypto_key_rotations) {
            DBG_PRINTF("Over %" PRIu64 " key rotations completed instead of at most %" PRIu64 "\n",
                cnx->nb_crypto_key_rotations, nb_rotation_expected);
            ret = -1;
        }
    }

    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }

    return ret;
}

int key_rotation_auto_server()
{
    return key_rotation_auto_one(300, 0);
}

int key_rotation_auto_client()
{
    return key_rotation_auto_one(400, 1);
}

/*
 * Key rotation stress: mimic a client that rotates its keys very rapidly.
 * Expected results: the server should survive. The server connection should be
 * deleted or closed.
 */

static int key_rotation_stress_test_one(int nb_packets)
{
    uint64_t simulated_time = 0;
    uint64_t closing_time = 0;
    uint64_t loss_mask = 0;
    int nb_trials = 0;
    int nb_inactive = 0;
    int max_trials = 100000;
    int max_rotations = 100;
    int nb_rotation = 0;
    uint64_t rotation_sequence = 100;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    int ret = tls_api_init_ctx(&test_ctx, PICOQUIC_INTERNAL_TEST_VERSION_1,
        PICOQUIC_TEST_SNI, PICOQUIC_TEST_ALPN, &simulated_time, NULL, NULL, 0, 0, 0);

    if (ret == 0 && test_ctx == NULL) {
        ret = PICOQUIC_ERROR_MEMORY;
    }

    if (ret == 0) {
        ret = tls_api_connection_loop(test_ctx, &loss_mask, 0, &simulated_time);
    }

    /* Prepare to send data */
    if (ret == 0) {
        ret = test_api_init_send_recv_scenario(test_ctx, test_scenario_sustained, sizeof(test_scenario_sustained));
    }

    /* Perform a data sending loop, during which various key rotations are tried
     * every "nb_packets". */

    while (ret == 0 && nb_trials < max_trials && nb_inactive < 256 && TEST_CLIENT_READY && TEST_SERVER_READY) {
        int was_active = 0;

        nb_trials++;

        if (test_ctx->cnx_client->pkt_ctx[picoquic_packet_context_application].send_sequence > rotation_sequence &&
            test_ctx->cnx_client->key_phase_enc == test_ctx->cnx_client->key_phase_dec) {
            rotation_sequence = test_ctx->cnx_client->pkt_ctx[picoquic_packet_context_application].send_sequence + nb_packets;
            nb_rotation++;
            if (nb_rotation > max_rotations) {
                break;
            }
            else {
                ret = picoquic_start_key_rotation(test_ctx->cnx_client);
                if (ret != 0) {
                    DBG_PRINTF("Start key rotation returns %d\n", ret);
                }
            }
        }

        if (ret == 0) {
            ret = tls_api_one_sim_round(test_ctx, &simulated_time, 0, &was_active);
        }

        if (ret != 0)
        {
            break;
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

    if (ret == 0 && TEST_CLIENT_READY) {
        ret = tls_api_attempt_to_close(test_ctx, &simulated_time);

        if (ret != 0) {
            DBG_PRINTF("Connection close returns %d\n", ret);
        }
    }

    /*
     * Allow for some time for the server connection to close.
     */
    closing_time = simulated_time + 4000000;
    while (ret == 0 && simulated_time < closing_time) {
        int was_active = 0; 
        if (test_ctx->cnx_server == NULL) {
            ret = -1;
            break;
        }
        if (test_ctx->qserver->cnx_list == NULL || test_ctx->cnx_server->cnx_state == picoquic_state_disconnected) {
            break;
        }

        ret = tls_api_one_sim_round(test_ctx, &simulated_time, 0, &was_active);
    }

    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }

    return ret;
}

int key_rotation_stress_test()
{
    return key_rotation_stress_test_one(10);
}


/*
 * False migration. Test that the client server connection resists injection of
 * some packets sent from a wrong address. The "false migration inject" acts as
 * a misbehaving NAT. The expectation is that the server will ignore handshake
 * packets from a wrong origin, and that the connection will recover from
 * false packet injection during the data phase.
 */

int false_migration_inject(picoquic_test_tls_api_ctx_t* test_ctx, int target_client, picoquic_packet_context_enum false_pc, uint64_t simulated_time)
{

    /* In order to test robustness of key rotation against attacks, we inject a
     * random packet with properly set header indication transition */
    int ret = 0;
    picoquic_cnx_t * cnx = (target_client) ? test_ctx->cnx_client : test_ctx->cnx_server;
    picoquictest_sim_link_t* target_link = (target_client) ? test_ctx->c_to_s_link : test_ctx->s_to_c_link;
    picoquictest_sim_packet_t* sim_packet = picoquictest_sim_link_create_packet();
    picoquic_packet_t* packet = NULL;

    if (cnx == NULL) {
        return -1;
    }

    packet = picoquic_create_packet(cnx->quic);

    if (sim_packet == NULL || packet == NULL || cnx == NULL) {
        if (sim_packet != NULL) {
            free(sim_packet);
        }
        if (packet != NULL) {
            picoquic_recycle_packet(cnx->quic, packet);
        }
        ret = -1;
    }
    else {
        struct sockaddr_in false_address;
        size_t checksum_overhead = 8;
        uint32_t header_length = 0;
        size_t length = 0;
        picoquic_epoch_enum epoch;
        picoquic_path_t * path_x = cnx->path[0];

        switch (false_pc) {
        case picoquic_packet_context_application:
            packet->ptype = picoquic_packet_1rtt_protected;
            epoch = picoquic_epoch_1rtt;
            break;
        case picoquic_packet_context_handshake:
            packet->ptype = picoquic_packet_handshake;
            epoch = picoquic_epoch_handshake;
            break;
        case picoquic_packet_context_initial:
        default:
            packet->ptype = picoquic_packet_initial;
            epoch = picoquic_epoch_initial;
            break;
        }

        if (target_client) {
            memcpy(&false_address, &test_ctx->client_addr, sizeof(false_address));
        }
        else {
            memcpy(&false_address, &test_ctx->server_addr, sizeof(false_address));
        }
        false_address.sin_port += 1234;


        checksum_overhead = picoquic_get_checksum_length(cnx, epoch);
        packet->checksum_overhead = checksum_overhead;
        packet->pc = false_pc;
        length = checksum_overhead + 32;
        memset(packet->bytes, 0, length);

        picoquic_finalize_and_protect_packet(cnx, packet,
            ret, length, header_length, checksum_overhead,
            &sim_packet->length, sim_packet->bytes, PICOQUIC_MAX_PACKET_SIZE,
            path_x, simulated_time);

        picoquic_store_addr(&sim_packet->addr_from, (struct sockaddr *)&false_address);

        if (target_client) {
            picoquic_store_addr(&sim_packet->addr_to, (struct sockaddr *)&test_ctx->server_addr);
        }
        else {
            picoquic_store_addr(&sim_packet->addr_to, (struct sockaddr *)&test_ctx->client_addr);
        }

        picoquictest_sim_link_submit(target_link, sim_packet, simulated_time);
    }

    return ret;
}

int false_migration_test_scenario(test_api_stream_desc_t * scenario, size_t size_of_scenario, uint64_t loss_target, int target_client, picoquic_packet_context_enum false_pc, uint64_t false_rank)
{
    uint64_t simulated_time = 0;
    int nb_injected = 0;
    int nb_trials = 0;
    int nb_inactive = 0;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    int ret = tls_api_init_ctx(&test_ctx, PICOQUIC_INTERNAL_TEST_VERSION_1,
        PICOQUIC_TEST_SNI, PICOQUIC_TEST_ALPN, &simulated_time, NULL, NULL, 0, 0, 0);

    if (ret == 0 && test_ctx == NULL) {
        ret = PICOQUIC_ERROR_MEMORY;
    }

    /* Run a connection loop with injection test */
    if (ret == 0) {

        while (ret == 0 && nb_trials < 1024 && nb_inactive < 512 && (!TEST_CLIENT_READY || (test_ctx->cnx_server == NULL || !TEST_SERVER_READY))) {
            int was_active = 0;
            nb_trials++;

            if (nb_injected == 0) {
                if ((target_client && test_ctx->cnx_client->pkt_ctx[false_pc].send_sequence > false_rank && test_ctx->cnx_client->path[0]->p_remote_cnxid->cnx_id.id_len != 0) ||
                    (!target_client && test_ctx->cnx_server != NULL && test_ctx->cnx_server->pkt_ctx[false_pc].send_sequence > false_rank)) {
                    /* Inject a spoofed packet in the context */
                    ret = false_migration_inject(test_ctx, target_client, false_pc, simulated_time);
                    if (ret == 0) {
                        nb_injected++;
                    }
                    else
                    {
                        DBG_PRINTF("Could not inject false packet, ret = %x\n", ret);
                    }
                }
            }

            ret = tls_api_one_sim_round(test_ctx, &simulated_time, 0, &was_active);

            if (test_ctx->cnx_client->cnx_state == picoquic_state_disconnected &&
                (test_ctx->cnx_server == NULL || test_ctx->cnx_server->cnx_state == picoquic_state_disconnected)) {
                break;
            }

            if (was_active) {
                nb_inactive = 0;
            }
            else {
                nb_inactive++;
            }
        }
    }

    /* Prepare to send data */
    if (ret == 0) {
        ret = test_api_init_send_recv_scenario(test_ctx, scenario, size_of_scenario);
    }

    /* Perform a data sending loop */
    nb_trials = 0;
    nb_inactive = 0;

    /* Perform a data sending loop, during which various key rotations are tried
     * every 100 packets or so. To test robustness, inject bogus packets that
     * mimic a transition trigger */

    while (ret == 0 && nb_trials < 1024 && nb_inactive < 256 && TEST_CLIENT_READY && TEST_SERVER_READY) {
        int was_active = 0;

        nb_trials++;

        if (nb_injected == 0) {
            if ((target_client && test_ctx->cnx_client->pkt_ctx[false_pc].send_sequence > false_rank) ||
                (!target_client && test_ctx->cnx_server != NULL && test_ctx->cnx_server->pkt_ctx[false_pc].send_sequence > false_rank)) {
                /* Inject a spoofed packet in the context */
                ret = false_migration_inject(test_ctx, target_client, false_pc, simulated_time);
                if (ret == 0) {
                    nb_injected++;
                }
                else
                {
                    DBG_PRINTF("Could not inject false packet, ret = %x\n", ret);
                }
            }
        }

        if (ret == 0) {
            ret = tls_api_one_sim_round(test_ctx, &simulated_time, 0, &was_active);
        }

        if (ret < 0)
        {
            break;
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
    if (ret == 0 && nb_injected == 0) {
        DBG_PRINTF("Could not inject after packet #%d in context %d\n", (int)false_rank, (int)false_pc);
        ret = -1;
    }

    if (ret == 0) {
        ret = tls_api_attempt_to_close(test_ctx, &simulated_time);

        if (ret != 0)
        {
            DBG_PRINTF("Connection close returns %d\n", ret);
        }
    }

    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }

    return ret;
}

int false_migration_test()
{
    int ret = 0;
    int target_client;

    for (target_client = 1; ret == 0 && target_client >= 0; target_client--) {
        ret = false_migration_test_scenario(test_scenario_q2_and_r2, sizeof(test_scenario_q2_and_r2), 0, target_client, picoquic_packet_context_initial, 0);
        
        if (ret == 0) {
            ret = false_migration_test_scenario(test_scenario_q2_and_r2, sizeof(test_scenario_q2_and_r2), 0, target_client, picoquic_packet_context_handshake, 0);
        }

        for (uint64_t seq = 0; ret == 0 && seq < 4; seq++) {
            ret = false_migration_test_scenario(test_scenario_q2_and_r2, sizeof(test_scenario_q2_and_r2), 0, target_client, picoquic_packet_context_application, seq);
        }
    }

    return ret;
}

/*
* Testing what happens in case of NAT rebinding during handshake.
* In theory, it may cause the handshake to fail, but in practice it does
* not...
*/

int nat_handshake_test_one(int test_rank)
{
    uint64_t simulated_time = 0;
    uint64_t loss_mask = 0;
    int nb_inactive = 0;
    int nb_trials = 0;
    int natted = 0;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    int ret = tls_api_init_ctx(&test_ctx, PICOQUIC_INTERNAL_TEST_VERSION_1,
        PICOQUIC_TEST_SNI, PICOQUIC_TEST_ALPN, &simulated_time, NULL, NULL, 0, 0, 0);

    if (ret == 0 && test_ctx == NULL) {
        ret = PICOQUIC_ERROR_MEMORY;
    }

    /* Run a connection loop with rebinding test */
    if (ret == 0) {

        while (ret == 0 && nb_trials < 1024 && nb_inactive < 512 && (!TEST_CLIENT_READY || (test_ctx->cnx_server == NULL || !TEST_SERVER_READY))) {
            int was_active = 0;
            nb_trials++;

            if (natted == 0) {
                int should_nat = 0;

                switch (test_rank) {
                case 0: /* check that at least one packet was received from the server, setting the CNX_ID */
                    should_nat = (test_ctx->cnx_client->path[0]->p_remote_cnxid->cnx_id.id_len > 0);
                    break;
                case 1: /* Check that the connection is almost complete, but finished has not been sent */
                    should_nat = (test_ctx->cnx_client->crypto_context[3].aead_decrypt != NULL);
                    break;
                default:
                    break;
                }
                if (should_nat) {
                    /* Simulate a NAT rebinding */
                    test_ctx->client_addr_natted = test_ctx->client_addr;
                    test_ctx->client_addr_natted.sin_port += 17;
                    test_ctx->client_use_nat = 1;
                    natted++;
                }
            }

            ret = tls_api_one_sim_round(test_ctx, &simulated_time, 0, &was_active);

            if (test_ctx->cnx_client->cnx_state == picoquic_state_disconnected ||
                (test_ctx->cnx_server != NULL && test_ctx->cnx_server->cnx_state == picoquic_state_disconnected)) {
                break;
            }

            if (was_active) {
                nb_inactive = 0;
            }
            else {
                nb_inactive++;
            }
        }
    }

    /* Prepare to send data */
    if (ret == 0) {
        ret = test_api_init_send_recv_scenario(test_ctx, test_scenario_q2_and_r2, sizeof(test_scenario_q2_and_r2));
    }

    /* Try send data */
    if (ret == 0) {
        ret = tls_api_data_sending_loop(test_ctx, &loss_mask, &simulated_time, 0);
    }

    if (ret == 0) {
        ret = tls_api_attempt_to_close(test_ctx, &simulated_time);

        if (ret != 0)
        {
            DBG_PRINTF("Connection close returns %d\n", ret);
        }
    }

    /* verify that the connection did change address */
    if (ret == 0 && !natted) {
        DBG_PRINTF("Connection succeeded after %d natting in handshake, rank %d\n", natted, test_rank);
        ret = -1;
    }

    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }


    return ret;
}

int nat_handshake_test()
{
    int ret = 0;

    for (int test_rank = 0; ret == 0 && test_rank < 2; test_rank++) {
        ret = nat_handshake_test_one(test_rank);
    }

    return ret;
}

/*
 * Verify that connection attempts with a too-short CID are rejected.
 */
static int short_initial_cid_test_one(uint8_t cid_length)
{
    uint64_t simulated_time = 0;
    uint64_t loss_mask = 0;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    int ret = tls_api_init_ctx(&test_ctx, 0, PICOQUIC_TEST_SNI, PICOQUIC_TEST_ALPN, &simulated_time, NULL, NULL, 0, 0, 0);

    if (ret == 0 && test_ctx == NULL) {
        ret = -1;
    }

    /* Delete the client context, and recreate with a short CID */
    if (ret == 0)
    {
        picoquic_connection_id_t init_cid;

        for (unsigned int i = 0; i < cid_length; i++) {
            init_cid.id[i] = (uint8_t)(i + 1);
        }
        init_cid.id_len = cid_length;

        if (test_ctx->cnx_client != NULL) {
            picoquic_delete_cnx(test_ctx->cnx_client);
            test_ctx->cnx_client = NULL;
        }

        test_ctx->cnx_client = picoquic_create_cnx(test_ctx->qclient, init_cid,
            picoquic_null_connection_id,
            (struct sockaddr*)&test_ctx->server_addr, 0,
            0, PICOQUIC_TEST_SNI, PICOQUIC_TEST_ALPN, 1);

        if (test_ctx->cnx_client == NULL) {
            ret = -1;
        }
        else {
            ret = picoquic_start_client_cnx(test_ctx->cnx_client);
        }
    }

    /* Proceed with the connection loop. */
    if (ret == 0) {
        ret = tls_api_connection_loop(test_ctx, &loss_mask, 0, &simulated_time);
    }

    /* Check that both the client and server are ready. */
    if (ret == 0 && TEST_CLIENT_READY) {
        if (cid_length < PICOQUIC_ENFORCED_INITIAL_CID_LENGTH) {
            DBG_PRINTF("Connection succeeds despites cid_length %d < %d\n",
                cid_length, PICOQUIC_ENFORCED_INITIAL_CID_LENGTH);
            ret = -1;
        }
    }
    else if (cid_length > PICOQUIC_ENFORCED_INITIAL_CID_LENGTH) {
        DBG_PRINTF("Connection fails despites cid_length %d >= %d\n",
            cid_length, PICOQUIC_ENFORCED_INITIAL_CID_LENGTH);
        if (ret == 0) {
            ret = -1;
        }
    }
    else if (cid_length < PICOQUIC_ENFORCED_INITIAL_CID_LENGTH) {
        ret = 0;
    }

    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }

    return ret;
}

int short_initial_cid_test()
{
    int ret = 0;
    for (uint8_t i = 4; ret == 0 && i < 18; i++) {
        ret = short_initial_cid_test_one(i);
    }

    return ret;
}

/*
 * Test whether the number of open streams is properly enforced
 */

int stream_id_max_test()
{
    picoquic_tp_t test_parameters;

    memset(&test_parameters, 0, sizeof(picoquic_tp_t));

    picoquic_init_transport_parameters(&test_parameters, 0);
    test_parameters.initial_max_stream_id_bidir = 4;

    return tls_api_one_scenario_test(test_scenario_many_streams, sizeof(test_scenario_many_streams), 0, 0, 0, 0, 0, 250000, NULL, &test_parameters);
}

/*
 * Test whether padding policy is correctly applied, and whether the corresponding
 * connection succeeds.
 */

int padding_test()
{
    uint64_t simulated_time = 0;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    int ret = tls_api_init_ctx(&test_ctx, PICOQUIC_INTERNAL_TEST_VERSION_1, PICOQUIC_TEST_SNI, PICOQUIC_TEST_ALPN, &simulated_time, NULL, NULL, 0, 1, 0);

    if (ret == 0 && test_ctx == NULL) {
        ret = -1;
    }

    /* Set the padding policy in the server context and in the client connection
     */
    if (ret == 0) {
        picoquic_set_default_padding(test_ctx->qserver, 128, 64);
        picoquic_cnx_set_padding_policy(test_ctx->cnx_client, 128, 64);

        /* Run a basic test scenario
         */

        ret = tls_api_one_scenario_body(test_ctx, &simulated_time,
            test_scenario_many_streams, sizeof(test_scenario_many_streams), 0, 0, 0, 0, 250000);
    }

    /* And then free the resource
     */

    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }

    return ret;
}

/*
 * Test whether the server correctly processes coalesced packets when one of the segments does not decrypt correctly 
 */

int bad_coalesce_test()
{
    uint64_t simulated_time = 0;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    int ret = tls_api_init_ctx(&test_ctx, PICOQUIC_INTERNAL_TEST_VERSION_1, PICOQUIC_TEST_SNI, PICOQUIC_TEST_ALPN, &simulated_time, NULL, NULL, 0, 1, 0);

    if (ret == 0 && test_ctx == NULL) {
        ret = -1;
    }

    /* Set the coalescing policy in the test context
     */
    if (ret == 0) {
        test_ctx->do_bad_coalesce_test = 1;

        /* Run a basic test scenario
         */

        ret = tls_api_one_scenario_body(test_ctx, &simulated_time,
            test_scenario_q_and_r, sizeof(test_scenario_q_and_r), 0, 0, 0, 0, 250000);
    }

    /* And then free the resource
     */

    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }

    return ret;
}

/*
 * Bad packet test. The client opens a connection, requests a page, and then only
 * sends bad 1RTT packets. The test succeeds if the server closes its connection
 * in a reasonable time. */
typedef struct st_header_fuzzer_ctx_t {
    uint64_t random_context;
    uint32_t nb_packets;
    uint32_t nb_fuzzed;
} header_fuzzer_ctx_t;

static uint32_t header_fuzzer(void* fuzz_ctx, picoquic_cnx_t* cnx,
    uint8_t* bytes, size_t bytes_max, size_t length, size_t header_length)
{
    header_fuzzer_ctx_t* ctx = (header_fuzzer_ctx_t*)fuzz_ctx;

    ctx->nb_packets++;

    if (cnx->cnx_state >= picoquic_state_client_almost_ready &&
        cnx->pkt_ctx[picoquic_packet_context_application].send_sequence > 2) {
        uint64_t fuzz_pilot = picoquic_test_random(&ctx->random_context);
        
        for (size_t i =1; i <= 8 && i < length ; i++) {
            bytes[i] ^= (uint8_t)fuzz_pilot;
            fuzz_pilot >>= 8;
        }

        ctx->nb_fuzzed++;
    }

    return (uint32_t)length;
}

int bad_cnxid_test()
{
    uint64_t simulated_time = 0;
    header_fuzzer_ctx_t fuzz_ctx;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    int ret = tls_api_init_ctx(&test_ctx, PICOQUIC_INTERNAL_TEST_VERSION_1, PICOQUIC_TEST_SNI, PICOQUIC_TEST_ALPN, &simulated_time, NULL, NULL, 0, 1, 0);

    memset(&fuzz_ctx, 0, sizeof(fuzz_ctx));
    fuzz_ctx.random_context = 0x123456789ABCDEF0ull;

    if (ret == 0) {
        /* Prepare to send data */
        ret = test_api_init_send_recv_scenario(test_ctx, test_scenario_very_long, sizeof(test_scenario_very_long));
    }

    if (ret == 0) {
        /* establish the connection */
        ret = tls_api_one_scenario_body_connect(test_ctx, &simulated_time, 0, 0, 0);
    }

    /* Set fuzzer, then perform a data sending loop */
    if (ret == 0) {
        picoquic_set_fuzz(test_ctx->qclient, header_fuzzer, &fuzz_ctx);

        (void) tls_api_data_sending_loop(test_ctx, NULL, &simulated_time, 0);


        /* verify that the server connection has disappeared */
        if (fuzz_ctx.nb_fuzzed > 0 && (test_ctx->cnx_server == NULL || test_ctx->cnx_server->cnx_state == picoquic_state_disconnected)) {
            ret = 0;
        }
        else {
            DBG_PRINTF("Unexpected server state: %d, packet: %d, fuzzed: %d\n", test_ctx->cnx_server->cnx_state, 
                fuzz_ctx.nb_packets, fuzz_ctx.nb_fuzzed);
            ret = -1;
        }
    }

    if (ret == 0) {
        /* Remove the reference to the old server connection */
        test_ctx->cnx_server = NULL;
        /* Delete the old client connection */
        picoquic_delete_cnx(test_ctx->cnx_client);
        test_ctx->cnx_client = NULL;
        /* Remove the fuzzer */
        picoquic_set_fuzz(test_ctx->qclient, NULL, NULL);
        /* re-create a client connection */
        test_ctx->cnx_client = picoquic_create_cnx(test_ctx->qclient,
            picoquic_null_connection_id, picoquic_null_connection_id,
            (struct sockaddr*) & test_ctx->server_addr, simulated_time,
            PICOQUIC_INTERNAL_TEST_VERSION_1, PICOQUIC_TEST_SNI, PICOQUIC_TEST_ALPN, 1);
        if (test_ctx->cnx_client == NULL) {
            DBG_PRINTF("%s", "Could not create second client connection\n");    
            ret = -1;
        }
        else {
            for (size_t i = 0; i < test_ctx->nb_test_streams; i++) {
                test_api_delete_test_stream(&test_ctx->test_stream[i]);
            }
            ret = tls_api_one_scenario_body(test_ctx, &simulated_time,
                test_scenario_q_and_r, sizeof(test_scenario_q_and_r), 0, 0, 0, 20000, 100000);
            if (ret != 0) {
                DBG_PRINTF("Second connection fails, ret=%d (x%x)\n", ret, ret);
            }
        }
    }

    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }

    return ret;
}


/*
 * Test whether packet tracing works correctly by setting up a basic connection
 * and verifying that the log file is what we expect.
 */
#ifdef _WINDOWS
#define PACKET_TRACE_TEST_REF "picoquictest\\packet_trace_ref.txt"
#else
#define PACKET_TRACE_TEST_REF "picoquictest/packet_trace_ref.txt"
#endif
#define PACKET_TRACE_CSV "packet_trace.csv"
#define PACKET_TRACE_BIN "ace1020304050607.server.log"

int packet_trace_test()
{
    uint64_t simulated_time = 0;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    picoquic_connection_id_t initial_cid = { {0xac, 0xe1, 2, 3, 4, 5, 6, 7}, 8 };
    int ret = tls_api_init_ctx_ex(&test_ctx, PICOQUIC_INTERNAL_TEST_VERSION_1, PICOQUIC_TEST_SNI, PICOQUIC_TEST_ALPN, &simulated_time, NULL, NULL, 0, 1, 0, &initial_cid);

    if (ret == 0 && test_ctx == NULL) {
        ret = -1;
    }

    /* Set the logging policy on the server side, to store data in the
     * current working directory, and run a basic test scenario */
    if (ret == 0) {
        picoquic_set_binlog(test_ctx->qserver, ".");
        picoquic_set_default_lossbit_policy(test_ctx->qserver, picoquic_lossbit_send_receive);
        picoquic_set_default_lossbit_policy(test_ctx->qclient, picoquic_lossbit_send_receive);
        test_ctx->qserver->use_long_log = 1;
        ret = tls_api_one_scenario_body(test_ctx, &simulated_time,
            test_scenario_very_long, sizeof(test_scenario_very_long), 0, 0, 0, 20000, 1000000);
    }

    /* Free the resource, which will close the log file.
     */

    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }

    /* Create a CSV file from the .bin log file */
    if (ret == 0) {
        ret = picoquic_cc_log_file_to_csv(PACKET_TRACE_BIN, PACKET_TRACE_CSV);
    }

    /* compare the log file to the expected value */
    if (ret == 0)
    {
        char packet_trace_test_ref[512];

        ret = picoquic_get_input_path(packet_trace_test_ref, sizeof(packet_trace_test_ref), picoquic_solution_dir, PACKET_TRACE_TEST_REF);

        if (ret != 0) {
            DBG_PRINTF("%s", "Cannot set the packet trace test ref file name.\n");
        }
        else {
            ret = picoquic_test_compare_text_files(PACKET_TRACE_CSV, packet_trace_test_ref);
        }
    }

    return ret;
}


/*
 * Test whether packet tracing works correctly by setting up a basic connection
 * and verifying that the log file is what we expect.
 */
#ifdef _WINDOWS
#define QLOG_TRACE_TEST_REF "picoquictest\\qlog_trace_ref.txt"
#define QLOG_TRACE_ECN_TEST_REF "picoquictest\\qlog_trace_ecn_ref.txt"
#else
#define QLOG_TRACE_TEST_REF "picoquictest/qlog_trace_ref.txt"
#define QLOG_TRACE_ECN_TEST_REF "picoquictest/qlog_trace_ecn_ref.txt"
#endif
#define QLOG_TRACE_BIN "0102030405060708.server.log"
#define QLOG_TRACE_QLOG "qlog_trace.qlog"
#define QLOG_TRACE_ECN_QLOG "qlog_trace_ecn.qlog"
#define QLOG_TRACE_AUTO_QLOG "0102030405060708.server.qlog"

void qlog_trace_cid_fn(picoquic_quic_t* quic, picoquic_connection_id_t cnx_id_local,
    picoquic_connection_id_t cnx_id_remote, void* cnx_id_cb_data, picoquic_connection_id_t* cnx_id_returned)
{
    picoquic_connection_id_t* cnxfn_data = (picoquic_connection_id_t*)cnx_id_cb_data;
    cnx_id_returned->id_len = cnx_id_local.id_len;
    for (uint8_t i = 0; i < cnx_id_local.id_len; i++) {
        cnx_id_returned->id[i] = cnx_id_remote.id[i] + cnxfn_data->id[i];
    }

    for (uint8_t i = 0; i < cnx_id_local.id_len; i++) {
        cnxfn_data->id[i] += 1;
        if (cnxfn_data->id[i] != 0) {
            break;
        }
    }
}

int qlog_trace_test_one(int auto_qlog, int keep_binlog, uint8_t recv_ecn)
{
    uint64_t simulated_time = 0;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    int ret = tls_api_init_ctx(&test_ctx, PICOQUIC_INTERNAL_TEST_VERSION_1, PICOQUIC_TEST_SNI, PICOQUIC_TEST_ALPN, &simulated_time, NULL, NULL, 0, 1, 0);
    picoquic_connection_id_t initial_cid = { {1, 2, 3, 4, 5, 6, 7, 8}, 8 };
    picoquic_connection_id_t cnxfn_data_client = { {1, 1, 1, 1, 1, 1, 1, 1}, 8 };
    picoquic_connection_id_t cnxfn_data_server = { {2, 2, 2, 2, 2, 2, 2, 2}, 8 };
    uint8_t reset_seed_client[PICOQUIC_RESET_SECRET_SIZE] = { 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25 };
    uint8_t reset_seed_server[PICOQUIC_RESET_SECRET_SIZE] = { 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35 };
    char const* qlog_target = (auto_qlog) ? QLOG_TRACE_AUTO_QLOG : ((recv_ecn != 0) ? QLOG_TRACE_ECN_QLOG : QLOG_TRACE_QLOG);

    if (ret == 0 && test_ctx == NULL) {
        ret = -1;
    }

    if (!auto_qlog && !keep_binlog) {
        ret = -1;
    }

    (void)picoquic_file_delete(QLOG_TRACE_BIN, NULL);
    (void)picoquic_file_delete(qlog_target, NULL);

    /* Set the logging policy on the server side, to store data in the
     * current working directory, and run a basic test scenario */
    if (ret == 0) {
        test_ctx->recv_ecn_client = recv_ecn;
        test_ctx->recv_ecn_server = recv_ecn;
        if (auto_qlog) {
            picoquic_set_qlog(test_ctx->qserver, ".");
        }
        if (keep_binlog) {
            picoquic_set_binlog(test_ctx->qserver, ".");
        }
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

        /* Force ciphersuite to AES128, so Client Hello has a constant format */
        if (picoquic_set_cipher_suite(test_ctx->qclient, PICOQUIC_AES_128_GCM_SHA256) != 0) {
            DBG_PRINTF("Could not set ciphersuite to 0x%04x", PICOQUIC_AES_128_GCM_SHA256);
        }
        if (picoquic_set_key_exchange(test_ctx->qclient, PICOQUIC_GROUP_SECP256R1) != 0) {
            DBG_PRINTF("Could not set key exchange to %d", PICOQUIC_GROUP_SECP256R1);
        }
        /* Delete the old connection */
        picoquic_delete_cnx(test_ctx->cnx_client);

        /* re-create a client connection, this time picking up the required connection ID */
        test_ctx->cnx_client = picoquic_create_cnx(test_ctx->qclient,
            initial_cid, picoquic_null_connection_id,
            (struct sockaddr*) & test_ctx->server_addr, 0,
            PICOQUIC_INTERNAL_TEST_VERSION_1, PICOQUIC_TEST_SNI, PICOQUIC_TEST_ALPN, 1);

        ret = tls_api_one_scenario_body(test_ctx, &simulated_time,
            test_scenario_q2_and_r2, sizeof(test_scenario_q2_and_r2), 0, 0x00010a04, 0, 20000, 2000000);
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

    /* Free the resource, which will close the log file.
     */

    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }

    /* Create a QLOG file from the .bin log file */
    if (ret == 0 && !auto_qlog) {
        uint64_t log_time = 0;
        uint16_t flags;
        FILE* f_binlog = picoquic_open_cc_log_file_for_read(QLOG_TRACE_BIN, &flags, &log_time);
        if (f_binlog == NULL) {
            ret = -1;
        }
        else {
            ret = qlog_convert(&initial_cid, f_binlog, QLOG_TRACE_BIN, qlog_target, NULL, flags);
            picoquic_file_close(f_binlog);
        }
    }

    /* compare the log file to the expected value */
    if (ret == 0)
    {
        char qlog_trace_test_ref[512];

        ret = picoquic_get_input_path(qlog_trace_test_ref, sizeof(qlog_trace_test_ref), picoquic_solution_dir,
            (recv_ecn== 0)?QLOG_TRACE_TEST_REF: QLOG_TRACE_ECN_TEST_REF);

        if (ret != 0) {
            DBG_PRINTF("%s", "Cannot set the qlog trace test ref file name.\n");
        }
        else {
            ret = picoquic_test_compare_text_files(qlog_target, qlog_trace_test_ref);
        }
    }

    return ret;
}

int qlog_trace_test()
{
    return qlog_trace_test_one(0, 1, 0);
}

int qlog_trace_only_test()
{
    return qlog_trace_test_one(1, 0, 0);
}

int qlog_trace_auto_test()
{
    return qlog_trace_test_one(1, 1, 0);
}

int qlog_trace_ecn_test()
{
    return qlog_trace_test_one(0, 1, 0x02);
}

/*
 * Test of the performance log production
 */

#ifdef _WINDOWS
#define PERF_TRACE_CLIENT_TEST_REF "picoquictest\\perf_trace_client_ref.txt"
#define PERF_TRACE_SERVER_TEST_REF "picoquictest\\perf_trace_server_ref.txt"
#else
#define PERF_TRACE_CLIENT_TEST_REF "picoquictest/perf_trace_client_ref.txt"
#define PERF_TRACE_SERVER_TEST_REF "picoquictest/perf_trace_server_ref.txt"
#endif
#define PERF_TRACE_CLIENT "perf_trace_client.csv"
#define PERF_TRACE_SERVER "perf_trace_server.csv"

static int perflog_set_version(char const * buffer2, char * buffer3, size_t buffer3_len)
{
    size_t i2 = 0;
    size_t i3 = 0;
    int ret = 0;

    while (ret == 0 && buffer2[i2] != 0) {
        if (buffer2[i2] == '$' && buffer2[i2 + 1] == 'V') {
            char const* v = PICOQUIC_VERSION;
            size_t v_len = strlen(v);
            i2 += 2;
            if (i3 + v_len < buffer3_len) {
                memcpy(buffer3 + i3, v, v_len);
                i3 += v_len;
            }
            else {
                ret = -1;
            }
        }
        else {
            if (i3 < buffer3_len) {
                buffer3[i3] = buffer2[i2];
                i3++;
                i2++;
            }
            else {
                ret = -1;
            }
        }
    }
    if (ret == 0) {
        if (i3 < buffer3_len) {
            buffer3[i3] = 0;
        }
        else {
            buffer3[buffer3_len - 1] = 0;
            ret = -1;
        }
    }
    return(ret);
}

static int perflog_compare(const char* fname1, const char* fname2)
{
    int ret = 0;
    int nb_line = 0;
    FILE* F1 = picoquic_file_open(fname1, "r");
    FILE* F2 = picoquic_file_open(fname2, "r");

    if (F1 == NULL || F2 == NULL) {
        ret = -1;
    }
    else {
        char buffer1[512];
        char buffer2[512];
        char buffer3[512];

        while (ret == 0 && fgets(buffer1, sizeof(buffer1), F1) != NULL) {
            nb_line++;
            if (fgets(buffer2, sizeof(buffer2), F2) == NULL) {
                /* F2 is too short */
                DBG_PRINTF("File %s is shorter than %s\n", fname2, fname1);
                DBG_PRINTF("    Missing line %d: %s", nb_line, buffer1);
                ret = -1;
            }
            else {
                /* Replace $V in buffer2 by actual version */
                ret = perflog_set_version(buffer2, buffer3, sizeof(buffer3));

                if (ret == 0) {
                    ret = picoquic_compare_lines(buffer1, buffer3);
                }
                if (ret != 0)
                {
                    DBG_PRINTF("File %s differs %s at line %d\n", fname2, fname1, nb_line);
                    DBG_PRINTF("    Got: %s", buffer1);
                    DBG_PRINTF("    Vs:  %s", buffer3);
                }
            }
        }

        if (ret == 0 && fgets(buffer2, sizeof(buffer2), F2) != NULL) {
            /* F2 is too long */
            DBG_PRINTF("File %s is longer than %s\n", fname2, fname1);
            DBG_PRINTF("    Extra line %d: %s", nb_line + 1, buffer2);
            ret = -1;
        }
    }

    if (F1 != NULL) {
        (void)picoquic_file_close(F1);
    }

    if (F2 != NULL) {
        (void)picoquic_file_close(F2);
    }

    return ret;
}

#if defined(_WINDOWS) && !defined(_WINDOWS64)
int perflog_test()
{
    /* we do not run this test on Win32 builds */
    return 0;
}
#else
int perflog_test()
{
    uint64_t simulated_time = 0;
    uint64_t loss_mask = 0;
    uint64_t target_time = 4000000;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    picoquic_connection_id_t initial_cid = { {0x9e, 0x8f, 0x08, 0x8a, 0x8c, 0xe0, 0, 0}, 8 };
    size_t send_buffer_size = 0xFFFF;
    const uint64_t latency_target = 35000;
    const uint64_t picosec_per_byte = (1000000ull * 8) / 100;
    int ret;

    (void)picoquic_file_delete(PERF_TRACE_CLIENT, NULL);
    (void)picoquic_file_delete(PERF_TRACE_SERVER, NULL);

    ret = tls_api_init_ctx_ex2(&test_ctx, PICOQUIC_INTERNAL_TEST_VERSION_1,
        PICOQUIC_TEST_SNI, PICOQUIC_TEST_ALPN, &simulated_time, NULL, NULL, 0, 0, 0, &initial_cid, 8, 0, send_buffer_size, 0);

    if (ret == 0 && test_ctx == NULL) {
        ret = -1;
    }

    /* Require a performance trace of thee server side */
    if (ret == 0) {
        picoquic_perflog_setup(test_ctx->qclient, PERF_TRACE_CLIENT);
        picoquic_perflog_setup(test_ctx->qserver, PERF_TRACE_SERVER);
        /* Set parameters to simulate random early drop */
        test_ctx->c_to_s_link->microsec_latency = latency_target;
        test_ctx->c_to_s_link->picosec_per_byte = picosec_per_byte;
        test_ctx->s_to_c_link->microsec_latency = latency_target;
        test_ctx->s_to_c_link->picosec_per_byte = picosec_per_byte;
        /* Set the CC algorithm to selected value */
        picoquic_set_default_congestion_algorithm(test_ctx->qserver, picoquic_bbr_algorithm);
    }

    if (ret == 0) {
        ret = tls_api_connection_loop(test_ctx, &loss_mask, latency_target, &simulated_time);
    }

    /* Prepare to send data */
    if (ret == 0) {
        ret = test_api_init_send_recv_scenario(test_ctx, test_scenario_sustained2, sizeof(test_scenario_sustained2));
    }

    /* Try to complete the data sending loop */
    if (ret == 0) {
        ret = tls_api_data_sending_loop(test_ctx, &loss_mask, &simulated_time, 0);
    }

    /* verify that the transmission was complete */
    if (ret == 0) {
        ret = tls_api_one_scenario_body_verify(test_ctx, &simulated_time, target_time);
    }

    /* Free the resource, which will force writing the performance log files. */

    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }

    /* Verify that the performance logs are as expected. */
    for (int i = 0; ret == 0 && i < 2; i++) {
        char perf_trace_test_ref[512];

        ret = picoquic_get_input_path(perf_trace_test_ref, sizeof(perf_trace_test_ref), picoquic_solution_dir,
            (i)?PERF_TRACE_CLIENT_TEST_REF: PERF_TRACE_SERVER_TEST_REF);

        if (ret != 0) {
            DBG_PRINTF("Cannot set the perf trace test ref file name for the %s.\n",
                (i)?"client":"server");
        }
        else {
            ret = perflog_compare((i)?PERF_TRACE_CLIENT: PERF_TRACE_SERVER, perf_trace_test_ref);
        }
    }

    return ret;
}
#endif

/*
 * Testing the flow controlled sending scenario, or "direct sending".
 * Data is sent through the "prepare to send" callback.
 * The "ready to send" test checks the normal operation.
 * The "ready to skip" test checks what happens if at some point the application
 * does not provide any data.
 */

int ready_to_send_test_one(int test_option)
{
    int ret = 0;

    for (int i = 0; ret == 0 && i < 3; i++) {
        uint64_t simulated_time = 0;
        picoquic_test_tls_api_ctx_t* test_ctx = NULL;

        ret = tls_api_one_scenario_init(&test_ctx, &simulated_time,
            0, NULL, NULL);

        if (ret == 0) {
            test_ctx->stream0_test_option = i;
            ret = tls_api_one_scenario_body(test_ctx, &simulated_time,
                test_scenario_q_and_r, sizeof(test_scenario_q_and_r), 1000000, 0, 0, 20000,
                1200000);
        }

        if (test_ctx != NULL) {
            tls_api_delete_ctx(test_ctx);
            test_ctx = NULL;
        }

        if (ret != 0) {
            DBG_PRINTF("Ready to send variant %d fails\n", i);
        }
    }

    return ret;
}

int ready_to_send_test()
{
    int ret = ready_to_send_test_one(1);
    return ret;
}

int ready_to_skip_test()
{
    int ret = ready_to_send_test_one(3);
    return ret;
}

int ready_to_zero_test()
{
    int ret = ready_to_send_test_one(4);
    return ret;
}

int ready_to_zfin_test()
{
    int ret = ready_to_send_test_one(2);
    return ret;
}

/* Set the CID length to specified value */
int set_cid_length_in_context(picoquic_test_tls_api_ctx_t* test_ctx, uint8_t length, int delayed_init)
{
    int ret = 0;

    /* Delete the old connection */
    picoquic_delete_cnx(test_ctx->cnx_client);
    test_ctx->cnx_client = NULL;
    /* Change the default cnx_id length*/
    test_ctx->qclient->local_cnxid_length = length;
    /* re-create a client connection */
    test_ctx->cnx_client = picoquic_create_cnx(test_ctx->qclient,
        picoquic_null_connection_id, picoquic_null_connection_id,
        (struct sockaddr*) & test_ctx->server_addr, 0,
        PICOQUIC_INTERNAL_TEST_VERSION_1, PICOQUIC_TEST_SNI, PICOQUIC_TEST_ALPN, 1);
    if (test_ctx->cnx_client == NULL) {
        ret = -1;
    }
    else if (delayed_init == 0) {
        ret = picoquic_start_client_cnx(test_ctx->cnx_client);
    }

    return ret;
}

/* Test that different CID length are properly supported */
int cid_length_test_one(uint8_t length)
{
    uint64_t simulated_time = 0;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    int ret = tls_api_init_ctx(&test_ctx, PICOQUIC_INTERNAL_TEST_VERSION_1, PICOQUIC_TEST_SNI, PICOQUIC_TEST_ALPN, &simulated_time, NULL, NULL, 0, 1, 0);

    if (ret == 0 && test_ctx == NULL) {
        ret = -1;
    }

    /* Set the CID length in the client context, then recreate the connection */
    if (ret == 0) {
        ret = set_cid_length_in_context(test_ctx, length, 1);
    }

    /* Do a connection */
    if (ret == 0)
    {
        ret = tls_api_one_scenario_body(test_ctx, &simulated_time,
            test_scenario_q_and_r, sizeof(test_scenario_q_and_r), 0, 0, 0, 20000, 100000);

        if (ret == 0 &&
            test_ctx->cnx_client->path[0]->p_local_cnxid->cnx_id.id_len != length) {
            ret = -1;
        }

        if (ret == 0 &&
            test_ctx->cnx_server->path[0]->p_remote_cnxid->cnx_id.id_len != length) {
            ret = -1;
        }
    }

    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }

    return ret;
}

int cid_length_test()
{
    int ret = 0;
    const uint8_t tested_length[] = { 0, 1, 2, 3, 4, 5, 6, 7, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20};

    for (size_t i = 0; i < sizeof(tested_length); i++) {
        ret = cid_length_test_one(tested_length[i]);
        if (ret != 0) {
            DBG_PRINTF("Test fails for cid_length = %d\n", tested_length[i]);
            break;
        }
    }

    return ret;
}

/* Testing transmission behavior over large RTT links
 */

int long_rtt_test()
{
    int ret = 0;
    uint64_t simulated_time = 0;
    uint64_t latency = 300000ull; /* assume that each direction is 300 ms, e.g. satellite link */
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    picoquic_connection_id_t initial_cid = { {0x10, 0x10, 30, 0, 0, 0, 0, 0}, 8 };

    ret = tls_api_one_scenario_init_ex(&test_ctx, &simulated_time,
        0, NULL, NULL, &initial_cid, 0);

    if (ret == 0) {
        /* set the delay estimate, then launch the test */
        test_ctx->c_to_s_link->microsec_latency = latency;
        test_ctx->s_to_c_link->microsec_latency = latency;

        picoquic_set_binlog(test_ctx->qserver, ".");

        /* The transmission delay cannot be less than 2.6 sec:
         * 3 handshakes at 1 RTT each = 1.8 sec, plus
         * 1MB over a 10Mbps link = 0.8 sec. We observe
         * 3.31 seconds instead, i.e. 1.51 sec for the
         * data transmission. This is due to the slow start
         * phase of the congestion control, which we accelerated
         * but could not completely fix. */
        ret = tls_api_one_scenario_body(test_ctx, &simulated_time,
            test_scenario_very_long, sizeof(test_scenario_very_long), 0, 0, 0, 2*latency,
            3600000);
    }

    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }

    return ret;
}

/*
 * Test the insertion of holes in the ACK sequence. We start a large
 * download, while setting the policy to insert a hole approximately
 * every 16 packets. We verify that the transfer completes. Then,
 * we repeat that test but inject optimistic acks, which should
 * break the connection.
 */
int optimistic_ack_test_one(int shall_spoof_ack)
{
    int ret = 0;
    uint64_t simulated_time = 0;
    int nb_holes = 0;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    picoquic_connection_id_t initial_cid = { {0x0a, 0x0a, 0x0a, 0x0a, 0, 0, 0, 0}, 8 };

    if (shall_spoof_ack) {
        initial_cid.id[7] = 0xff;
    }

    ret = tls_api_one_scenario_init_ex(&test_ctx, &simulated_time,
        0, NULL, NULL, &initial_cid, 0);

    if (ret == 0) {
        /* set the optimistic ack policy to the default value */
        picoquic_set_optimistic_ack_policy(test_ctx->qserver, PICOQUIC_DEFAULT_HOLE_PERIOD);
        /* add a log request for debugging */
        picoquic_set_binlog(test_ctx->qserver, ".");

        /* Reset the uniform random test */
        picoquic_public_random_seed_64(RANDOM_PUBLIC_TEST_SEED, 1);

        ret = tls_api_one_scenario_body_connect(test_ctx, &simulated_time, 0,
            0, 0);

        if (ret != 0)
        {
            DBG_PRINTF("Connect scenario returns %d\n", ret);
        }
    }

    /* Prepare to send data */
    if (ret == 0) {
        test_ctx->stream0_target = 0;
        ret = test_api_init_send_recv_scenario(test_ctx, test_scenario_very_long, sizeof(test_scenario_very_long));

        if (ret != 0)
        {
            DBG_PRINTF("Init send receive scenario returns %d\n", ret);
        }
    }

    /* Perform a data sending loop */
    if (ret == 0) {
        int nb_trials = 0;
        int nb_inactive = 0;
        uint64_t hole_number = 0;

        test_ctx->c_to_s_link->loss_mask = NULL;
        test_ctx->s_to_c_link->loss_mask = NULL;

        while (ret == 0 && nb_trials < 64000 && nb_inactive < 1024 && TEST_CLIENT_READY && TEST_SERVER_READY) {
            int was_active = 0;

            nb_trials++;

            ret = tls_api_one_sim_round(test_ctx, &simulated_time, 0, &was_active);

            if (ret < 0) {
                DBG_PRINTF("Sim round number %d returns %d\n", nb_trials, ret);
                break;
            }
            else if (test_ctx->cnx_server->nb_retransmission_total > 0) {
                DBG_PRINTF("Unexpected retransmission at T=%d", (int)simulated_time);
                ret = -1;
                break;
            }

            if (was_active) {
                nb_inactive = 0;
            }
            else {
                nb_inactive++;
            }

            /* find whether there was a new hole inserted */
            if (test_ctx->cnx_server != NULL) {
                picoquic_packet_t * packet = test_ctx->cnx_server->pkt_ctx[picoquic_packet_context_application].pending_first;

                while (packet != NULL && packet->sequence_number > hole_number) {
                    if (packet->is_ack_trap) {
                        hole_number = packet->sequence_number;
                        if (shall_spoof_ack) {
                            ret = picoquic_record_pn_received(test_ctx->cnx_client, picoquic_packet_context_application,
                                test_ctx->cnx_client->first_local_cnxid_list->local_cnxid_first, hole_number, simulated_time);
                            if (ret != 0) {
                                DBG_PRINTF("Record pn hole %d number returns %d\n", (int)hole_number, ret);
                                break;
                            }
                        }
                        nb_holes++;
                        break;
                    }
                    packet = packet->packet_next;
                }
            }

            if (test_ctx->test_finished) {
                if (picoquic_is_cnx_backlog_empty(test_ctx->cnx_client) && picoquic_is_cnx_backlog_empty(test_ctx->cnx_server)) {
                    break;
                }
            }
        }

        if (!test_ctx->test_finished) {
            DBG_PRINTF("Data loop exit after %d rounds, %d inactive\n", nb_trials, nb_inactive);
        }

        if (ret != 0)
        {
            DBG_PRINTF("Data sending loop returns %d\n", ret);
        }
        else if (test_ctx->cnx_server != NULL) {
            DBG_PRINTF("Complete after %d packets sent, %d r. by client, %d retransmits, %d spurious.\n",
                (int)(test_ctx->cnx_server->nb_packets_sent),
                (int)test_ctx->cnx_client->nb_packets_received,
                test_ctx->cnx_server->nb_retransmission_total,
                test_ctx->cnx_server->nb_spurious);
        }
    }

    if (ret == 0){
        if (nb_holes <= 0) {
            DBG_PRINTF("%s", "No holes inserted\n");
            ret = -1;
        }
        else if (test_ctx->cnx_server->nb_packet_holes_inserted == 0) {
            DBG_PRINTF("Reporting %" PRIu64 " holes inserted\n",
                test_ctx->cnx_server->nb_packet_holes_inserted);
            ret = -1;
        }
    }

    if (shall_spoof_ack) {
        if (ret == 0 && test_ctx->test_finished) {
            DBG_PRINTF("Despite %d holes and spoofs, the transfer completed\n", nb_holes);
            ret = -1;
        }
        else {
            ret = 0;
        }
    }
    else {
        if (ret == 0) {
            ret = tls_api_one_scenario_body_verify(test_ctx, &simulated_time, 0);
            if (ret != 0) {
                DBG_PRINTF("Scenario verification returns %d", ret);
            }
        }
    }

    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }

    return ret;
}

int optimistic_ack_test()
{
    int ret = optimistic_ack_test_one(1);

    return ret;
}

int optimistic_hole_test()
{
    int ret = optimistic_ack_test_one(0);

    return ret;
}

/*
 * test that local and remote addresses are properly documented during the
 * call setup process.
 */

typedef struct st_tls_api_address_are_documented_t {
    /* addresses returned by almost ready callback */
    int nb_almost_ready;
    struct sockaddr_storage local_addr_almost_ready;
    struct sockaddr_storage remote_addr_almost_ready;
    /* addresses returned by ready callback */
    int nb_ready;
    struct sockaddr_storage local_addr_ready;
    struct sockaddr_storage remote_addr_ready;
    /* Pointer to the underlying callback */
    picoquic_stream_data_cb_fn callback_fn;
    void * callback_ctx;
} tls_api_address_are_documented_t;

static int test_local_address_callback(picoquic_cnx_t* cnx,
    uint64_t stream_id, uint8_t* bytes, size_t length,
    picoquic_call_back_event_t fin_or_event, void* callback_ctx, void* v_stream_ctx)
{
    int ret = 0;
    struct sockaddr * local_addr;
    struct sockaddr * remote_addr;

    tls_api_address_are_documented_t* cb_ctx = (tls_api_address_are_documented_t*)callback_ctx;

    if (fin_or_event == picoquic_callback_almost_ready) {
        picoquic_get_peer_addr(cnx, &remote_addr);
        picoquic_get_local_addr(cnx, &local_addr);
        cb_ctx->nb_almost_ready++;
        if (cb_ctx->nb_almost_ready == 1) {
            if (local_addr != NULL && local_addr->sa_family != 0) {
                picoquic_store_addr(&cb_ctx->local_addr_almost_ready, local_addr);
            }
            if (remote_addr != NULL && remote_addr->sa_family != 0) {
                picoquic_store_addr(&cb_ctx->remote_addr_almost_ready, remote_addr);
            }
        }
    }
    else if (fin_or_event == picoquic_callback_ready) {
        picoquic_get_peer_addr(cnx, &remote_addr);
        picoquic_get_local_addr(cnx, &local_addr);
        cb_ctx->nb_ready++;
        if (cb_ctx->nb_ready == 1) {
            if (local_addr != NULL && local_addr->sa_family != 0) {
                picoquic_store_addr(&cb_ctx->local_addr_ready, local_addr);
            }
            if (remote_addr != NULL && remote_addr->sa_family != 0) {
                picoquic_store_addr(&cb_ctx->remote_addr_ready, remote_addr);
            }
        }
    };

    if (cb_ctx->callback_fn != NULL) {
        picoquic_stream_data_cb_fn new_fn;
        void * new_ctx;

        ret = (cb_ctx->callback_fn)(cnx, stream_id, bytes, length, fin_or_event, cb_ctx->callback_ctx, NULL);

        /* Check that the callbacks were not reset during the last call */
        new_fn = picoquic_get_callback_function(cnx);
        new_ctx = picoquic_get_callback_context(cnx);

        if (new_fn != test_local_address_callback || new_ctx != callback_ctx) {
            cb_ctx->callback_fn = new_fn;
            cb_ctx->callback_ctx = new_ctx;
            picoquic_set_callback(cnx, test_local_address_callback, callback_ctx);
        }
    }

    return ret;
}

int document_addresses_check(tls_api_address_are_documented_t * test_cb_ctx,
    struct sockaddr * local_addr_ref, struct sockaddr * remote_addr_ref)
{
    int ret = 0;

    if (ret == 0 && test_cb_ctx->nb_almost_ready != 1) {
        DBG_PRINTF("Expected 1 almost ready callback, got %d\n", test_cb_ctx->nb_ready);
        ret = -1;
    }

    if (ret == 0 && test_cb_ctx->local_addr_almost_ready.ss_family == 0) {
        DBG_PRINTF("%s", "Expected almost ready local address, got AF = 0\n");
        ret = -1;
    }

    if (ret == 0 && picoquic_compare_addr(local_addr_ref,
        (struct sockaddr*)&test_cb_ctx->local_addr_almost_ready) != 0) {
        DBG_PRINTF("%s", "Local address from almost ready callback does not match\n");
        ret = -1;
    }

    if (ret == 0 && test_cb_ctx->remote_addr_almost_ready.ss_family == 0) {
        DBG_PRINTF("%s", "Expected almost ready remote address, got AF = 0\n");
        ret = -1;
    }

    if (ret == 0 && picoquic_compare_addr(remote_addr_ref,
        (struct sockaddr*)&test_cb_ctx->remote_addr_almost_ready) != 0) {
        DBG_PRINTF("%s", "Local address from almost ready callback does not match\n");
        ret = -1;
    }

    if (ret == 0 && test_cb_ctx->nb_ready != 1) {
        DBG_PRINTF("Expected 1 ready callback, got %d\n", test_cb_ctx->nb_ready);
        ret = -1;
    }

    if (ret == 0 && test_cb_ctx->local_addr_ready.ss_family == 0) {
        DBG_PRINTF("%s", "Expected ready local address, got AF = 0\n");
        ret = -1;
    }

    if (ret == 0 && picoquic_compare_addr(local_addr_ref,
        (struct sockaddr*)&test_cb_ctx->local_addr_ready) != 0) {
        DBG_PRINTF("%s", "Local address from ready callback does not match\n");
        ret = -1;
    }

    if (ret == 0 && test_cb_ctx->remote_addr_ready.ss_family == 0) {
        DBG_PRINTF("%s", "Expected ready remote address, got AF = 0\n");
        ret = -1;
    }

    if (ret == 0 && picoquic_compare_addr(remote_addr_ref,
        (struct sockaddr*)&test_cb_ctx->remote_addr_ready) != 0) {
        DBG_PRINTF("%s", "Local address from almost ready callback does not match\n");
        ret = -1;
    }

    return ret;
}

int document_addresses_test()
{
    uint64_t simulated_time = 0; 
    tls_api_address_are_documented_t client_address_callback_ctx, server_address_callback_ctx;

    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    int ret = tls_api_init_ctx(&test_ctx, PICOQUIC_INTERNAL_TEST_VERSION_1, PICOQUIC_TEST_SNI, PICOQUIC_TEST_ALPN, &simulated_time, NULL, NULL, 0, 1, 0);

    if (ret == 0 && test_ctx == NULL) {
        ret = -1;
    }
    if (ret == 0) {
        /* Set the call backs to intercept the almost ready and ready transitions */
        memset(&client_address_callback_ctx, 0, sizeof(tls_api_address_are_documented_t));
        client_address_callback_ctx.callback_fn = picoquic_get_callback_function(test_ctx->cnx_client);
        client_address_callback_ctx.callback_ctx = picoquic_get_callback_context(test_ctx->cnx_client);
        picoquic_set_callback(test_ctx->cnx_client, test_local_address_callback, &client_address_callback_ctx);

        memset(&server_address_callback_ctx, 0, sizeof(tls_api_address_are_documented_t));
        server_address_callback_ctx.callback_fn = picoquic_get_default_callback_function(test_ctx->qserver);
        server_address_callback_ctx.callback_ctx = picoquic_get_default_callback_context(test_ctx->qserver);
        picoquic_set_default_callback(test_ctx->qserver, test_local_address_callback, &server_address_callback_ctx);

        ret = tls_api_one_scenario_body(test_ctx, &simulated_time,
            test_scenario_q_and_r, sizeof(test_scenario_q_and_r), 0, 0, 0, 20000, 3600000);
    }

    /* Verify that the addresses and calls are what we expect */
    if (ret == 0) {
        ret = document_addresses_check(&client_address_callback_ctx,
            (struct sockaddr*)&test_ctx->client_addr, (struct sockaddr*)&test_ctx->server_addr);
        if (ret != 0) {
            DBG_PRINTF("%s", "Client addresses were not properly documented\n");
        }
    }

    if (ret == 0) {
        ret = document_addresses_check(&server_address_callback_ctx,
            (struct sockaddr*)&test_ctx->server_addr, (struct sockaddr*)&test_ctx->client_addr);
        if (ret != 0) {
            DBG_PRINTF("%s", "Server addresses were not properly documented\n");
        }
    }

    /* Free the resource */

    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }

    return ret;
}

/*
 * Test whether a connection succeed when SNI is not specified.
 */

int null_sni_test()
{
    return tls_api_test_with_loss(NULL, PICOQUIC_INTERNAL_TEST_VERSION_1, NULL, PICOQUIC_TEST_ALPN);
}

/*
 * Test whether server redirection is applied properly
 */

int preferred_address_test_one(int migration_disabled, int cid_zero)
{
    int ret;
    uint64_t simulated_time = 0;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    struct sockaddr_in server_preferred;
    picoquic_tp_t server_parameters;


    server_preferred.sin_family = AF_INET;
#ifdef _WINDOWS
    server_preferred.sin_addr.S_un.S_addr = 0x0A00000B;
#else
    server_preferred.sin_addr.s_addr = 0x0A00000B;
#endif
    server_preferred.sin_port = 5678;

    memset(&server_parameters, 0, sizeof(picoquic_tp_t));

    picoquic_init_transport_parameters(&server_parameters, 1);

    /* Create an alternate IP address, and use it as preferred address */
    server_parameters.prefered_address.is_defined = 1;
    memcpy(server_parameters.prefered_address.ipv4Address, &server_preferred.sin_addr, 4);
    server_parameters.prefered_address.ipv4Port = ntohs(server_preferred.sin_port);
    server_parameters.migration_disabled = migration_disabled;

    ret = tls_api_one_scenario_init_ex(&test_ctx, &simulated_time, PICOQUIC_INTERNAL_TEST_VERSION_1,
        NULL, &server_parameters, NULL, cid_zero);


    if (ret == 0) {
        /* Run a basic test scenario */

        ret = tls_api_one_scenario_body(test_ctx, &simulated_time,
            test_scenario_very_long, sizeof(test_scenario_very_long), 0, 0, 0, 0, 1500000);
    }

    /* Verify that the client and server have both migrated to using the preferred address */
    if (ret == 0 && picoquic_compare_addr((struct sockaddr*)&server_preferred,
        (struct sockaddr*)&test_ctx->cnx_client->path[0]->peer_addr) != 0) {
        DBG_PRINTF("%s", "Server address at client not updated\n");
        ret = -1;
    }

    if (ret == 0 && test_ctx->cnx_server != NULL &&
        picoquic_compare_addr((struct sockaddr*)&server_preferred,
        (struct sockaddr*)&test_ctx->cnx_server->path[0]->local_addr) != 0) {
        DBG_PRINTF("%s", "Server address not promoted\n");
        ret = -1;
    }

    /* verify that both have migrated to a new CID */
    if (ret == 0 && !cid_zero && 
        (test_ctx->cnx_client->path[0]->p_local_cnxid == NULL || 
            test_ctx->cnx_client->path[0]->p_local_cnxid->sequence == 0)){
        DBG_PRINTF("%s", "Client CID not updated\n");
        ret = -1;
    }

    if (ret == 0 && test_ctx->cnx_server != NULL &&
        (test_ctx->cnx_server->path[0]->p_local_cnxid == NULL ||
            test_ctx->cnx_server->path[0]->p_local_cnxid->sequence == 0)) {
        DBG_PRINTF("%s", "Server CID not updated\n");
        ret = -1;
    }

    /* verify that migrations are now authorized */
    if (ret == 0 && test_ctx->cnx_server != NULL && test_ctx->cnx_client->remote_parameters.migration_disabled) {
        DBG_PRINTF("%s", "Migration blocked on client\n");
        ret = -1;
    }

    if (ret == 0 && test_ctx->cnx_server != NULL && test_ctx->cnx_server->local_parameters.migration_disabled) {
        DBG_PRINTF("%s", "Migration blocked on server\n");
        ret = -1;
    }

    /* And then free the resource
     */

    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }

    return ret;
}

int preferred_address_test()
{
    return preferred_address_test_one(0, 0);
}

int preferred_address_dis_mig_test()
{
    return preferred_address_test_one(1, 0);
}

int preferred_address_zero_test()
{
    /* test with zero length client cid */
    return preferred_address_test_one(0, 1);
}

/* Test that the random public generation behaves in expected ways */
int random_public_tester_test()
{
#define RANDOM_PUBLIC_TEST_CONST 11
#define RANDOM_PUBLIC_TEST_ROUNDS 100
#define RANDOM_PUBLIC_CHI_SQUARE 18.31 /* Fail if significance of bias < P = 0.05 */
    int ret = 0;
    int r_count[RANDOM_PUBLIC_TEST_CONST];

    picoquic_public_random_seed_64(RANDOM_PUBLIC_TEST_SEED, 1);

    memset(r_count, 0, sizeof(r_count));

    for (int i = 0; i < RANDOM_PUBLIC_TEST_CONST*RANDOM_PUBLIC_TEST_ROUNDS; i++) {
        uint64_t x = picoquic_public_uniform_random(RANDOM_PUBLIC_TEST_CONST);

        if (x >= RANDOM_PUBLIC_TEST_CONST) {
            DBG_PRINTF("Value %d >= %d\n", x, RANDOM_PUBLIC_TEST_CONST);
            ret = -1;
            break;
        }
        else {
            r_count[x] += 1;
        }
    }

    if (ret == 0) {
        double chi_squared = 0;

        for (int i = 0; i < RANDOM_PUBLIC_TEST_CONST; i++) {
            double delta = ((double)RANDOM_PUBLIC_TEST_ROUNDS - r_count[i]);
            double d2 = delta * delta;
            d2 /= ((double)RANDOM_PUBLIC_TEST_ROUNDS);
            chi_squared += d2;
        }

        if (chi_squared > RANDOM_PUBLIC_CHI_SQUARE) {
            DBG_PRINTF("Chi2 = %f, larger than %f\n", chi_squared, RANDOM_PUBLIC_CHI_SQUARE);
            ret = -1;
        }
    }

    return ret;
}

/*
 * Test whether connections can be established when the client hello is larger than a 
 * single packet. This is done by adding a "padding" transport parameter.
 */

int large_client_hello_test()
{
    uint64_t simulated_time = 0;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    int ret = tls_api_init_ctx(&test_ctx, PICOQUIC_INTERNAL_TEST_VERSION_1, PICOQUIC_TEST_SNI, PICOQUIC_TEST_ALPN, &simulated_time, NULL, NULL, 0, 1, 0);

    if (ret == 0 && test_ctx == NULL) {
        ret = -1;
    }

    /* Set the test large hello flag in the client connection
     */
    if (ret == 0) {
        test_ctx->cnx_client->test_large_chello = 1;

        /* Run a basic test scenario
         */

        ret = tls_api_one_scenario_body(test_ctx, &simulated_time,
            test_scenario_q_and_r, sizeof(test_scenario_q_and_r), 0, 0, 0, 0, 250000);
    }

    /* Verify that there is no spurious retransmission */
    if (ret == 0) {
        if (test_ctx->cnx_server == NULL || test_ctx->cnx_server->nb_retransmission_total > 0) {
            DBG_PRINTF("Unexpected, server retransmitted %" PRIu64 " packets", 
                (test_ctx->cnx_server == NULL)? UINT64_MAX:test_ctx->cnx_server->nb_retransmission_total);
            ret = -1;
        }
        else if (test_ctx->cnx_client->nb_retransmission_total > 0) {
            DBG_PRINTF("Unexpected, client retransmitted %" PRIu64 " packets", test_ctx->cnx_client->nb_retransmission_total);
            ret = -1;
        }
    }

    /* And then free the resource
     */

    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }

    return ret;
}

/* DDOS Amplification Mitigation test
 *
 * In this test, the client sends a first packet (client hello) and then disappears.
 * This simulates an attempts to use the Quic server as an amplifier in a DDOS attack.
 * We want to verify that the server does not send out more than 3 times the amount
 * of data sent by the client.
 */

int ddos_amplification_test_one(int use_0rtt, int do_8k)
{
    uint64_t simulated_time = 0;
    uint64_t loss_mask = 0;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    uint32_t proposed_version = PICOQUIC_INTEROP_VERSION_LATEST;
    int ret; 
    picoquictest_sim_packet_t* packet = picoquictest_sim_link_create_packet();
    size_t data_sent_by_client = 0;
    size_t data_sent_by_server = 0;
    int nb_server_packets = 0;
    int nb_loops = 0;
    int nb_inactive = 0;

    ret = picoquic_save_tickets(NULL, simulated_time, ticket_file_name);

    if (ret == 0) {
        ret = tls_api_init_ctx(&test_ctx, proposed_version, PICOQUIC_TEST_SNI, PICOQUIC_TEST_ALPN, &simulated_time,
            ticket_file_name, NULL, 0, 0, 0);
    }

    if (ret != 0 || packet == NULL)
    {
        DBG_PRINTF("Could not create the QUIC test contexts for V=%x\n", proposed_version);
        ret = -1;
    }

    if (ret == 0 && do_8k) {
        test_ctx->qserver->test_large_server_flight = 1;
    }

    if (ret == 0 && use_0rtt) {
        /* Complete a first connection in order to obtain ticket and token for the client. */
        if (ret == 0) {
            ret = test_api_init_send_recv_scenario(test_ctx, test_scenario_q_and_r5000, sizeof(test_scenario_q_and_r5000));
        }

        if (ret == 0) {
            ret = tls_api_connection_loop(test_ctx, &loss_mask, 0, &simulated_time);

            if (ret != 0) {
                DBG_PRINTF("%", "Ticket grabbing connection failed\n");
            }
        }

        if (ret == 0) {
            /* Before closing, wait for the session ticket to arrive */
            ret = session_resume_wait_for_ticket(test_ctx, &simulated_time);

            /* Verify that the client has obtained a ticket */
            if (ret != 0 || test_ctx->qclient->p_first_ticket == NULL) {
                DBG_PRINTF("%s", "No resumption ticket obtained.\n");
                ret = -1;
            }
        }

        /* Delete this client connection and create a new one. */
        if (ret == 0) {
            /* Delete the old server connection */
            picoquic_delete_cnx(test_ctx->cnx_server);
            /* Delete the old client connection */
            picoquic_delete_cnx(test_ctx->cnx_client);
            for (size_t i = 0; i < test_ctx->nb_test_streams; i++) {
                 test_api_delete_test_stream(&test_ctx->test_stream[i]);
            }
            /* re-create a client connection, this time picking up the required connection ID */
            test_ctx->cnx_client = picoquic_create_cnx(test_ctx->qclient,
                picoquic_null_connection_id, picoquic_null_connection_id,
                (struct sockaddr*) & test_ctx->server_addr, 0,
                PICOQUIC_INTEROP_VERSION_LATEST, PICOQUIC_TEST_SNI, PICOQUIC_TEST_ALPN, 1);
            if (test_ctx->cnx_client == NULL) {
                DBG_PRINTF("Could not create the second connection for version =  %08x\n", proposed_version);
                ret = -1;
            }
            else {
                ret = picoquic_start_client_cnx(test_ctx->cnx_client);
            }
        }

        /* Set a scenario for sending packets from the server  */
        if (ret == 0) {
            ret = test_api_init_send_recv_scenario(test_ctx, test_scenario_q_and_r5000, sizeof(test_scenario_q_and_r5000));
        }
    }

    if (ret == 0) {
        /* Prepare a first packet from the client to the server */
        {
            ret = picoquic_prepare_packet(test_ctx->cnx_client, simulated_time,
                packet->bytes, PICOQUIC_MAX_PACKET_SIZE, &packet->length,
                &packet->addr_to, &packet->addr_from, NULL);
        }

        if (packet->length == 0) {
            ret = PICOQUIC_ERROR_UNEXPECTED_ERROR;
        }
        if (ret != 0 )
        {
            DBG_PRINTF("Could not create first client packet, ret=%x\n", ret);
        }
        else {
            data_sent_by_client += packet->length;
            picoquic_store_addr(&packet->addr_from, (struct sockaddr*)&test_ctx->client_addr);

            ret = picoquic_incoming_packet(test_ctx->qserver, packet->bytes, (uint32_t)packet->length,
                (struct sockaddr*) & packet->addr_from,
                (struct sockaddr*) & packet->addr_to, 0, test_ctx->recv_ecn_server,
                simulated_time);

            if (ret == 0) {
                picoquic_cnx_t* next = test_ctx->qserver->cnx_list;

                while (next != NULL && picoquic_compare_connection_id(&next->initial_cnxid, &test_ctx->cnx_client->initial_cnxid) != 0) {
                    next = next->next_in_table;
                }

                if (next != NULL) {
                    test_ctx->cnx_server = next;
                } else {
                    ret = -1;
                    DBG_PRINTF("Could not create server side connection, ret = %d\n", ret);
                }
            }
        }
    }

    while (ret == 0 && test_ctx->cnx_server != NULL && test_ctx->cnx_server->cnx_state != picoquic_state_disconnected && nb_loops < 1024 && nb_inactive < 256) {
        /* Update the time to the next server time */
        simulated_time = test_ctx->cnx_server->next_wake_time;
        packet->length = 0;
        nb_loops++;

        ret = picoquic_prepare_packet(test_ctx->cnx_server, simulated_time,
            packet->bytes, PICOQUIC_MAX_PACKET_SIZE, &packet->length,
            &packet->addr_to, &packet->addr_from, NULL);

        if (ret == PICOQUIC_ERROR_DISCONNECTED) {
            ret = 0;
        }

        if (ret != 0)
        {
            DBG_PRINTF("Could not create server packet, ret=%x\n", ret);
        }
        else if (packet->length > 0) {
            data_sent_by_server += packet->length;
            nb_server_packets++;
            nb_inactive = 0;
        }
        else {
            nb_inactive++;
        }
    }

    if (ret == 0 && test_ctx->cnx_server != NULL && test_ctx->cnx_server->cnx_state != picoquic_state_disconnected) {
        DBG_PRINTF("Simulation was looping, closed before termination, loops: %d, inactive: %d\n", nb_loops, nb_inactive);
        ret = -1;
    }

    if (ret == 0 && data_sent_by_server > 3*data_sent_by_client) {
        DBG_PRINTF("Client sent %d bytes, server sent >3x more, %d bytes, %d packets\n", (int)data_sent_by_client, (int)data_sent_by_server, nb_server_packets);
        ret = -1;
    }

    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }

    if (packet != NULL) {
        free(packet);
    }

    return ret;
}

int ddos_amplification_test()
{
    return ddos_amplification_test_one(0, 0);
}

int ddos_amplification_0rtt_test()
{
    return ddos_amplification_test_one(1, 0);
}

int ddos_amplification_8k_test()
{
    return ddos_amplification_test_one(0, 1);
}

/* Verify that the code operates correctly when the ack frequency extension is not used
 */

int no_ack_frequency_test()
{
    int ret = 0;
    picoquic_tp_t client_parameters;
    picoquic_tp_t server_parameters;

    for (int i = 1; ret == 0 && i <= 3; i++) {
        memset(&client_parameters, 0, sizeof(picoquic_tp_t));
        memset(&server_parameters, 0, sizeof(picoquic_tp_t));
        picoquic_init_transport_parameters(&client_parameters, 1);
        picoquic_init_transport_parameters(&server_parameters, 0);

        client_parameters.min_ack_delay = (i & 1) ? 0 : 1000;
        server_parameters.enable_loss_bit = (1 - ((i > 1) & 1));

        ret = tls_api_one_scenario_test(test_scenario_very_long, sizeof(test_scenario_very_long), 0, 128, 0, 0, 0, 2000000, &client_parameters, &server_parameters);
        if (ret != 0) {
            DBG_PRINTF("No min ack delay test fails for client: %d, server: %d, ret = %d", i & 1, i >> 1, ret);
        }
    }

    return ret;
}

/* Check that a connection does fail in a reasonable time after a transmission
 * drops.
 */

static int connection_drop_test_one(picoquic_state_enum target_client_state, picoquic_state_enum target_server_state, int target_is_client)
{
    uint64_t simulated_time = 0;
    uint64_t target_time = PICOQUIC_MICROSEC_HANDSHAKE_MAX;
    const char* target_name = (target_is_client) ? "client" : "server";
    picoquic_cnx_t* target_cnx = NULL;

    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    int ret = tls_api_init_ctx(&test_ctx, 0, PICOQUIC_TEST_SNI, PICOQUIC_TEST_ALPN, &simulated_time, NULL, NULL, 0, 0, 0);

    if (ret == 0) {
        int nb_trials = 0;
        int nb_inactive = 0;

        while (ret == 0 && nb_trials < 1024 && nb_inactive < 512 && (!TEST_CLIENT_READY || (test_ctx->cnx_server == NULL || !TEST_SERVER_READY))) {
            int was_active = 0;
            nb_trials++;

            ret = tls_api_one_sim_round(test_ctx, &simulated_time, 0, &was_active);

            if (test_ctx->cnx_client->cnx_state == picoquic_state_disconnected &&
                (test_ctx->cnx_server == NULL || test_ctx->cnx_server->cnx_state == picoquic_state_disconnected)) {
                break;
            }

            if (test_ctx->cnx_client->cnx_state >= target_client_state ||
                (test_ctx->cnx_server != NULL && test_ctx->cnx_server->cnx_state >= target_server_state)) {
                break;
            }
        }
    }

    if (ret == 0) {
        target_cnx = (target_is_client) ? test_ctx->cnx_client : test_ctx->cnx_server;

        if (target_cnx == NULL) {
            DBG_PRINTF("Target connection (%s) already dropped", target_name);
            ret = -1;
        }
        else if (target_cnx->cnx_state >= picoquic_state_ready) {
            DBG_PRINTF("Target connection (%s) already ready", target_name);
            ret = -1;
        }
    }

    if (ret == 0) {
        int nb_trials = 0;
        int nb_inactive = 0;
        int disconnected_in_time = 0;

        while (ret == 0 && nb_trials < 1024 && nb_inactive < 512) {
            struct sockaddr_storage a_from;
            struct sockaddr_storage a_to;
            uint8_t packet[PICOQUIC_MAX_PACKET_SIZE];
            size_t length = 0;

            if (target_cnx->next_wake_time > simulated_time) {
                simulated_time = target_cnx->next_wake_time;
            }

            if (simulated_time > target_time + target_cnx->start_time) {
                break;
            }

            ret = picoquic_prepare_packet(target_cnx, simulated_time, packet, PICOQUIC_MAX_PACKET_SIZE,
                &length, &a_to, &a_from, NULL);

            if (ret == PICOQUIC_ERROR_DISCONNECTED) {
                ret = 0;
            }

            if (target_cnx->cnx_state == picoquic_state_disconnected) {
                disconnected_in_time = 1;
                break;
            }
        }

        if (ret == 0 && !disconnected_in_time) {
            DBG_PRINTF("Connection not disconnected after %lld microsec", simulated_time);
            ret = -1;
        }
    }

    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }

    return ret;
}

int connection_drop_test()
{
    int ret = 0;
    picoquic_state_enum target_state[9] = {
        picoquic_state_client_init_sent,
        picoquic_state_client_renegotiate,
        picoquic_state_client_init_resent,
        picoquic_state_server_init,
        picoquic_state_server_handshake,
        picoquic_state_client_handshake_start,
        picoquic_state_server_false_start,
        picoquic_state_server_almost_ready,
        picoquic_state_client_almost_ready
    };
    int target_is_client[9] = {
        1, 1, 1, 0, 0, 1, 0, 0, 1 };

    for (int i = 0; ret == 0 && i < 9; i++) {
        picoquic_state_enum c_state = (target_is_client[i]) ? target_state[i] : picoquic_state_ready;
        picoquic_state_enum s_state = (target_is_client[i]) ? picoquic_state_ready : target_state[i];

        ret = connection_drop_test_one(c_state, s_state, target_is_client[i]);
        if (ret == -1) {
            DBG_PRINTF("connection drop test %d fails", i);
        }
    }

    return ret;
}

/* testing the pacing rate update function and the congestion
 * control parameter assessors.
 */

#ifdef _WINDOWS
#define PACING_RATE_TEST_REF "picoquictest\\pacing_rate_ref.txt"
#else
#define PACING_RATE_TEST_REF "picoquictest/pacing_rate_ref.txt"
#endif
#define PACING_RATE_CSV "pacing_rate.csv"


int pacing_update_test()
{
    uint64_t simulated_time = 0;

    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    int ret = tls_api_init_ctx(&test_ctx, PICOQUIC_INTERNAL_TEST_VERSION_1, PICOQUIC_TEST_SNI, PICOQUIC_TEST_ALPN, &simulated_time, NULL, NULL, 0, 1, 0);

    if (ret == 0 && test_ctx == NULL) {
        ret = -1;
    }
    if (ret == 0) {
        /* Open a file to log bandwidth updates and document it in context */
        test_ctx->bw_update = picoquic_file_open(PACING_RATE_CSV, "w");
        if (test_ctx->bw_update == NULL) {
            DBG_PRINTF("Could not write file <%s>", PACING_RATE_CSV);
            ret = -1;
        }
        else {
            fprintf(test_ctx->bw_update, "Time, Pacing_rate_CB, Pacing_rate, CWIN, RTT\n");
            /* Request bandwidth updates */
            picoquic_subscribe_pacing_rate_updates(test_ctx->cnx_client, 0x8000, 0x10000);

            /* Start a standard scenario, pushing 1MB from the client*/
            ret = tls_api_one_scenario_body(test_ctx, &simulated_time,
                test_scenario_q_and_r, sizeof(test_scenario_q_and_r), 1000000, 0, 0, 20000, 3600000);
        }
    }

    /* Free the test contex, which closes the trace file  */
    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }

    /* compare the trace to the expected value */
    if (ret == 0)
    {
        char pacing_rate_ref[512];

        ret = picoquic_get_input_path(pacing_rate_ref, sizeof(pacing_rate_ref), picoquic_solution_dir, PACING_RATE_TEST_REF);

        if (ret != 0) {
            DBG_PRINTF("%s", "Cannot set the pacing rate test ref file name.\n");
        }
        else {
            ret = picoquic_test_compare_text_files(PACING_RATE_CSV, pacing_rate_ref);
        }
    }

    return ret;
}

/* testing the quality update functionality when using the default path
* quality API.
*/

#ifdef _WINDOWS
#define QUALITY_UPDATE_REF "picoquictest\\quality_update_ref.txt"
#else
#define QUALITY_UPDATE_REF "picoquictest/quality_update_ref.txt"
#endif
#define QUALITY_UPDATE_CSV "quality_update.csv"

int quality_update_test()
{
    uint64_t simulated_time = 0;

    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    int ret = tls_api_init_ctx(&test_ctx, PICOQUIC_INTERNAL_TEST_VERSION_1, PICOQUIC_TEST_SNI, PICOQUIC_TEST_ALPN, &simulated_time, NULL, NULL, 0, 1, 0);

    if (ret == 0 && test_ctx == NULL) {
        ret = -1;
    }
    if (ret == 0) {
        /* Open a file to log bandwidth updates and document it in context */
        test_ctx->default_path_update = picoquic_file_open(QUALITY_UPDATE_CSV, "w");
        if (test_ctx->default_path_update == NULL) {
            DBG_PRINTF("Could not write file <%s>", QUALITY_UPDATE_CSV);
            ret = -1;
        }
        else {
            fprintf(test_ctx->default_path_update, "Time, Path_id, Sending_rate_CB, Pacing_rate, Receive_Rate, CWIN, RTT\n");
            /* Request bandwidth updates */
            picoquic_subscribe_to_quality_update(test_ctx->cnx_client, 0x10000, 0x1000);

            /* Start a standard scenario, pushing 1MB from the client*/
            ret = tls_api_one_scenario_body(test_ctx, &simulated_time,
                test_scenario_q_and_r, sizeof(test_scenario_q_and_r), 1000000, 0, 0, 20000, 3600000);
        }
    }

    /* Free the test contex, which closes the trace file  */
    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }

    /* compare the trace to the expected value */
    if (ret == 0)
    {
        char quality_update_ref[512];

        ret = picoquic_get_input_path(quality_update_ref, sizeof(quality_update_ref), picoquic_solution_dir, QUALITY_UPDATE_REF);

        if (ret != 0) {
            DBG_PRINTF("%s", "Cannot set the quality update ref file name.\n");
        }
        else {
            ret = picoquic_test_compare_text_files(QUALITY_UPDATE_CSV, quality_update_ref);
        }
    }

    return ret;
}


/* Test the direct receive API
 */

int direct_receive_test()
{
    int ret = 0;
    uint64_t simulated_time = 0;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    uint64_t loss_mask = 8;
    uint64_t max_completion_microsec = 3500000;

    ret = tls_api_one_scenario_init(&test_ctx, &simulated_time,
        0, NULL, NULL);

    if (ret == 0) {
        ret = tls_api_one_scenario_body_connect(test_ctx, &simulated_time, 0, 0, 0);

        /* Prepare to send data */
        if (ret == 0) {
            test_ctx->stream0_target = 0;
            ret = test_api_init_send_recv_scenario(test_ctx, test_scenario_very_long, sizeof(test_scenario_very_long));

            if (ret != 0)
            {
                DBG_PRINTF("Init send receive scenario returns %d\n", ret);
            }
        }

        /* Set the direct receive API for the stream number 4. */
        if (ret == 0) {
            ret = picoquic_mark_direct_receive_stream(test_ctx->cnx_client, 4, test_api_direct_receive_callback, 
                (void*)&test_ctx->client_callback);

            if (ret != 0)
            {
                DBG_PRINTF("Mark direct receive stream returns %d\n", ret);
            }
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
            ret = tls_api_one_scenario_body_verify(test_ctx, &simulated_time, max_completion_microsec);
        }
    }

    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }

    return ret;
}

/* Initial race condition.
* What happens if the client immediately repeats the Initial packet?
*/

int initial_race_test()
{
    uint64_t simulated_time = 0;
    uint64_t loss_mask = 0;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    int ret = tls_api_init_ctx(&test_ctx, PICOQUIC_INTERNAL_TEST_VERSION_1,
        PICOQUIC_TEST_SNI, PICOQUIC_TEST_ALPN, &simulated_time, NULL, NULL, 0, 0, 0);

    if (ret == 0 && test_ctx == NULL) {
        ret = PICOQUIC_ERROR_MEMORY;
    }

    /* Run an initial loop to make to send the client's first packet, and then replicate it. */
    if (ret == 0) {
        int was_active = 0;
        ret = tls_api_one_sim_round(test_ctx, &simulated_time, 0, &was_active);

        if (ret == 0) {
            /* Force a repeat of the first packet */
            simulated_time += 100;
            test_ctx->cnx_client->initial_repeat_needed = 1;
            ret = tls_api_one_sim_round(test_ctx, &simulated_time, 0, &was_active);
            test_ctx->cnx_client->initial_repeat_needed = 0;
            /* Verify that there are two packets in the initial queue */
            if (ret == 0) {
                if (test_ctx->c_to_s_link->first_packet == NULL) {
                    DBG_PRINTF("%s", "No packet queued");
                    ret = -1;
                }
                else if (test_ctx->c_to_s_link->last_packet == test_ctx->c_to_s_link->first_packet) {
                    DBG_PRINTF("%s", "Only one packet queued");
                    ret = -1;
                }
            }
        }

        while (ret == 0 && test_ctx->s_to_c_link->first_packet == NULL){
            /* run a couple of simulation round to process the first server packets,
             * but make sure the server sends only one packet */
            ret = tls_api_one_sim_round(test_ctx, &simulated_time, 0, &was_active);
        }

        if (ret == 0) {
            if (test_ctx->cnx_server == NULL) {
                DBG_PRINTF("%s", "No server connection");
                ret = -1;

            }
            else {
                /* Make sure that the server waits before sending the next packet. */
                test_ctx->cnx_server->next_wake_time += 2000;
            }
        }
    }

    /* Run a connection loop */
    if (ret == 0) {
        ret = tls_api_connection_loop(test_ctx, &loss_mask, 0, &simulated_time);
    }

    /* Prepare to send data */
    if (ret == 0) {
        ret = test_api_init_send_recv_scenario(test_ctx, test_scenario_q2_and_r2, sizeof(test_scenario_q2_and_r2));
    }

    /* Try send data */
    if (ret == 0) {
        ret = tls_api_data_sending_loop(test_ctx, &loss_mask, &simulated_time, 0);
    }

    /* Check that the data was sent and received */
    if (ret == 0) {
        ret = tls_api_one_scenario_verify(test_ctx);
    }

    if (ret == 0) {
        ret = tls_api_attempt_to_close(test_ctx, &simulated_time);

        if (ret != 0)
        {
            DBG_PRINTF("Connection close returns %d\n", ret);
        }
    }

    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }

    return ret;
}

/*
 * Test connection establishment with ChaCha20
 */

int chacha20_test()
{
    uint64_t simulated_time = 0;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    int has_chacha_poly = 0;
    int ret = tls_api_init_ctx(&test_ctx, PICOQUIC_INTERNAL_TEST_VERSION_1, PICOQUIC_TEST_SNI, PICOQUIC_TEST_ALPN, &simulated_time, NULL, NULL, 0, 1, 0);

    if (ret == 0 && test_ctx == NULL) {
        ret = -1;
    }

    /* Set the cipher suite to chacha20
     */
    if (ret == 0) {
        has_chacha_poly = (picoquic_set_cipher_suite(test_ctx->qclient, PICOQUIC_CHACHA20_POLY1305_SHA256) == 0);

        if (has_chacha_poly) {

            /* Run a basic test scenario */
            ret = tls_api_one_scenario_body(test_ctx, &simulated_time,
                test_scenario_q_and_r, sizeof(test_scenario_q_and_r), 0, 0, 0, 0, 250000);
        }
        else {
            DBG_PRINTF("%s", "Could not test CHACHA20, not supported on this platform.");
        }
    }

    /* And then free the resource
     */

    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }

    return ret;
}

/*
 * Test CID renewal on quiescence larger than PICOQUIC_CID_REFRESH_DELAY
 */
int cid_quiescence_test()
{
    uint64_t simulated_time = 0;
    uint64_t loss_mask = 0;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    picoquic_connection_id_t previous_remote_id = picoquic_null_connection_id;
    int ret = tls_api_init_ctx(&test_ctx, PICOQUIC_INTERNAL_TEST_VERSION_1, PICOQUIC_TEST_SNI, PICOQUIC_TEST_ALPN, &simulated_time, NULL, NULL, 0, 0, 0);

    /* Set up the connection */
    if (ret == 0) {
        /* establish the connection */
        ret = tls_api_connection_loop(test_ctx, &loss_mask, 0, &simulated_time);
    }

    if (ret == 0) {
        previous_remote_id = test_ctx->cnx_client->path[0]->p_remote_cnxid->cnx_id;
        /* Prepare to send data */
        ret = test_api_init_send_recv_scenario(test_ctx, test_scenario_very_long, sizeof(test_scenario_very_long));
    }

    if (ret == 0) {
        ret = wait_client_connection_ready(test_ctx, &simulated_time);
    }

    if (ret == 0) {
        previous_remote_id = test_ctx->cnx_client->path[0]->p_remote_cnxid->cnx_id;
        simulated_time += PICOQUIC_CID_REFRESH_DELAY;
    }

    /* Perform a data sending loop */
    if (ret == 0) {
        ret = tls_api_data_sending_loop(test_ctx, &loss_mask, &simulated_time, 0);
    }

    /* verify that the transmission was complete */
    if (ret == 0) {
        ret = tls_api_one_scenario_body_verify(test_ctx, &simulated_time, 0);
    }
    
    /* Verify that the CID has rotated */
    if (ret == 0 &&
        picoquic_compare_connection_id(&previous_remote_id, &test_ctx->cnx_client->path[0]->p_remote_cnxid->cnx_id) == 0) {
        ret = -1;
    }
    
    /* And then free the resource  */
    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }

    return ret;
}

/*
 * Test that the Quic Bit is properly greased.
 * Negotiate the Quic Bit parameter, transfer packets,
 * verify at the end that the quic bit was greased.
 */

int grease_quic_bit_test_one(unsigned int one_way_grease_quic_bit)
{
    int ret;
    picoquic_tp_t client_parameters;
    uint64_t simulated_time = 0;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;

    memset(&client_parameters, 0, sizeof(picoquic_tp_t));
    picoquic_init_transport_parameters(&client_parameters, 1);

    client_parameters.do_grease_quic_bit = 1;

    ret = tls_api_one_scenario_init(&test_ctx, &simulated_time, 0, &client_parameters, NULL);

    if (ret == 0 && one_way_grease_quic_bit) {
        test_ctx->qserver->one_way_grease_quic_bit = 1;
    }

    if (ret == 0) {
        ret = tls_api_one_scenario_body(test_ctx, &simulated_time,
            test_scenario_very_long, sizeof(test_scenario_very_long), 0, 0, 0, 0, 0);
    }

    if (ret == 0) {
        if (one_way_grease_quic_bit) {
            if (test_ctx->cnx_client->quic_bit_greased) {
                DBG_PRINTF("%s", "Quic bit was greased on client");
                ret = -1;
            }
        }
        else {
            if (!test_ctx->cnx_client->quic_bit_greased) {
                DBG_PRINTF("%s", "Quic bit was not greased on client");
                ret = -1;
            } else if (test_ctx->cnx_server == NULL || !test_ctx->cnx_server->quic_bit_received_0) {
                DBG_PRINTF("%s", "Quic bit was not received greased on server");
                ret = -1;
            }
        }

        if (test_ctx->cnx_server == NULL || !test_ctx->cnx_server->quic_bit_greased) {
            DBG_PRINTF("%s", "Quic bit was not greased on server");
            ret = -1;
        }
        else if (!test_ctx->cnx_client->quic_bit_received_0) {
            DBG_PRINTF("%s", "Quic bit not received greased on client");
            ret = -1;
        }
    }

    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }

    return ret;
}

int grease_quic_bit_test()
{
    return  grease_quic_bit_test_one(0);
}

int grease_quic_bit_one_way_test()
{
    return  grease_quic_bit_test_one(1);
}

/* Test effects of random early drop active queue management
 */

static int red_cc_algotest(picoquic_congestion_algorithm_t* cc_algo, uint64_t target_time, uint64_t loss_target)
{
    uint64_t simulated_time = 0;
    uint64_t loss_mask = 0;
    const uint64_t latency_target = 7500;
    const uint64_t red_drop_mask = 0x5555555555555555ull;
    const uint64_t queue_max_red = 40000;
    const uint64_t picosec_per_byte = (1000000ull * 8) /100;
    uint64_t observed_loss = 0;

    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    picoquic_connection_id_t initial_cid = { {0x8e, 0xd0, 0xcc, 0xa1, 0x90, 6, 7, 8}, 8 };
    int ret;

    initial_cid.id[4] = cc_algo->congestion_algorithm_number;

    ret = tls_api_init_ctx_ex(&test_ctx, PICOQUIC_INTERNAL_TEST_VERSION_1,
        PICOQUIC_TEST_SNI, PICOQUIC_TEST_ALPN, &simulated_time, NULL, NULL, 0, 0, 0, &initial_cid);

    if (ret == 0) {
        /* Set parameters to simulate random early drop */
        test_ctx->c_to_s_link->microsec_latency = latency_target;
        test_ctx->c_to_s_link->red_drop_mask = red_drop_mask;
        test_ctx->c_to_s_link->red_queue_max = queue_max_red;
        test_ctx->c_to_s_link->picosec_per_byte = picosec_per_byte;
        test_ctx->s_to_c_link->microsec_latency = latency_target;
        test_ctx->s_to_c_link->red_drop_mask = red_drop_mask;
        test_ctx->s_to_c_link->red_queue_max = queue_max_red;
        test_ctx->s_to_c_link->picosec_per_byte = picosec_per_byte;
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
        ret = test_api_init_send_recv_scenario(test_ctx, test_scenario_sustained, sizeof(test_scenario_sustained));
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
        DBG_PRINTF("RED, for cc=%s, expected %" PRIu64 " losses, got %" PRIu64 "\n",
            cc_algo->congestion_algorithm_id, loss_target, observed_loss);
        ret = -1;
    }

    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }

    return ret;
}

int red_newreno_test()
{
    int ret = red_cc_algotest(picoquic_newreno_algorithm, 500000, 150);
    return ret;
}

int red_cubic_test()
{
    int ret = red_cc_algotest(picoquic_cubic_algorithm, 500000, 225);
    return ret;
}

int red_dcubic_test()
{
    int ret = red_cc_algotest(picoquic_dcubic_algorithm, 500000, 275);
    return ret;
}

int red_fast_test()
{
    int ret = red_cc_algotest(picoquic_fastcc_algorithm, 500000, 250);
    return ret;
}

int red_bbr_test()
{
    int ret = red_cc_algotest(picoquic_bbr_algorithm, 500000, 170);
    return ret;
}

/* Sending multiple segments.
 * This tests whether the simulation correctly supports the equivalent of UDP GSO. It
 * also tests whether the congestion control works well with these multiple segments
 */


static int multi_segment_test_one(picoquic_congestion_algorithm_t* cc_algo, uint64_t target_time, size_t send_buffer_size)
{
    uint64_t simulated_time = 0;
    uint64_t loss_mask = 0;
    const uint64_t latency_target = 35000;
    const uint64_t picosec_per_byte = (1000000ull * 8) / 100;

    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    picoquic_connection_id_t initial_cid = { {0x5e, 0x90, 0xe0, 0x40, 0, 6, 7, 8}, 8 };
    int ret;

    initial_cid.id[4] = cc_algo->congestion_algorithm_number;

    ret = tls_api_init_ctx_ex2(&test_ctx, PICOQUIC_INTERNAL_TEST_VERSION_1,
        PICOQUIC_TEST_SNI, PICOQUIC_TEST_ALPN, &simulated_time, NULL, NULL, 0, 0, 0, &initial_cid, 8, 0, send_buffer_size, 0);

    if (ret == 0) {
        /* Set parameters to simulate random early drop */
        test_ctx->c_to_s_link->microsec_latency = latency_target;
        test_ctx->c_to_s_link->picosec_per_byte = picosec_per_byte;
        test_ctx->s_to_c_link->microsec_latency = latency_target;
        test_ctx->s_to_c_link->picosec_per_byte = picosec_per_byte;
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
        ret = test_api_init_send_recv_scenario(test_ctx, test_scenario_sustained2, sizeof(test_scenario_sustained2));
    }

    /* Try to complete the data sending loop */
    if (ret == 0) {
        ret = tls_api_data_sending_loop(test_ctx, &loss_mask, &simulated_time, 0);
    }

    /* verify that the transmission was complete */
    if (ret == 0) {
        ret = tls_api_one_scenario_body_verify(test_ctx, &simulated_time, target_time);
    }

    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }

    return ret;
}

int multi_segment_test()
{
    picoquic_congestion_algorithm_t* algo_list[5] = {
        picoquic_newreno_algorithm,
        picoquic_cubic_algorithm,
        picoquic_dcubic_algorithm,
        picoquic_fastcc_algorithm,
        picoquic_bbr_algorithm
    };
    uint64_t algo_time[5] = {
        1220000,
        1050000,
        1250000,
        1350000,
        1280000
    };
    int ret = 0;

    for (int i = 0; i < 5 && ret == 0; i++) {
        ret = multi_segment_test_one(algo_list[i], algo_time[i], 65536);
        if (ret != 0) {
            DBG_PRINTF("Multi segment test fails for CC=%s", algo_list[i]->congestion_algorithm_id);
        }
    }

    return ret;
}

/* heavy loss test:
* Simulate a connection experiencing heavy packet
* loss, such as 50% packet loss, for a duration of
* 5 seconds. The test succeeds if the connection stays
* up and the transfer completes.
* 
* The "interactive" scenario repeats the same test, but
* instead of just retrieving 4 files of 1MB each, it
* tries to conduct 100 transactions, each with a 255 bytes
* "query" and a 1KB "response".
* 
* The "total loass" test is similar to the first test, but
* instead of simulating 5 seconds with 50% losses,
* it simulates 5 seconds with 100% loss.
 */

test_api_stream_desc_t* heavy_loss_inter_scenario(size_t* scenario_size)
{
    size_t nb_rounds = 100;
    size_t sc_z = sizeof(test_api_stream_desc_t) * nb_rounds;
    test_api_stream_desc_t* sc;
    uint64_t previous_stream_id = 0;
    uint64_t next_stream_id = 4;

    sc = (test_api_stream_desc_t*)malloc(sc_z);
    if (sc != NULL) {
        memset(sc, 0, sc_z);

        for (size_t i = 0; i < nb_rounds; i++) {
            sc[i].previous_stream_id = previous_stream_id;
            sc[i].stream_id = next_stream_id;
            sc[i].q_len = 255;
            sc[i].r_len = 1000;
            previous_stream_id = next_stream_id;
            next_stream_id += 4;
        }
        *scenario_size = sc_z;
    }
    return sc;
}

int heavy_loss_test_one(int scenario_id, uint64_t completion_target)
{
    uint64_t simulated_time = 0;
    uint64_t loss_mask = 0;
    test_api_stream_desc_t* scenario = test_scenario_sustained;
    size_t scenario_size = sizeof(test_scenario_sustained);
    test_api_stream_desc_t* allocated_scenario = NULL;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    picoquic_connection_id_t initial_cid = { {0x8e, 0xfe, 0x10, 0x55, 0, 0, 0, 0}, 8 };
    int ret;

    ret = tls_api_init_ctx_ex(&test_ctx, PICOQUIC_INTERNAL_TEST_VERSION_1,
        PICOQUIC_TEST_SNI, PICOQUIC_TEST_ALPN, &simulated_time, NULL, NULL, 0, 1, 0, &initial_cid);

    if (ret == 0) {
        /* Set the CC algorithm to selected value */
        picoquic_set_default_congestion_algorithm(test_ctx->qserver, picoquic_bbr_algorithm);
        picoquic_set_binlog(test_ctx->qserver, ".");
        test_ctx->qserver->use_long_log = 1;
    }

    if (ret == 0 && scenario_id == 1) {
        allocated_scenario = heavy_loss_inter_scenario(&scenario_size);
        if (allocated_scenario == NULL) {
            DBG_PRINTF("%s", "Could not allocate interactive scenario");
            ret = -1;
        }
        else {
            scenario = allocated_scenario;
        }
    }

    if (ret == 0) {
        ret = picoquic_start_client_cnx(test_ctx->cnx_client);
    }

    if (ret == 0) {
        ret = tls_api_connection_loop(test_ctx, &loss_mask, 0, &simulated_time);
    }

    /* Prepare to send data */
    if (ret == 0) {
        ret = test_api_init_send_recv_scenario(test_ctx, scenario, scenario_size);
    }

    /* Send for 0.1 second, in order to ramp up transfer speed */
    if (ret == 0) {
        ret = tls_api_wait_for_timeout(test_ctx, &simulated_time, 100000);
    }

    /* Send for up to 30 seconds, with 50% packet loss rate.
     * Stop earlier if something breaks, or if all the required
     * data is sent.
     * In scenario 2, simulate "total loss".
     */
    if (ret == 0) {
        loss_mask = (scenario_id == 2)?UINT64_MAX:0x13596ac77ca69531ull;
        for (int i = 0; ret == 0 && !test_ctx->test_finished && i < 20; i++) {
            ret = tls_api_wait_for_timeout(test_ctx, &simulated_time, 1000000);
        }
    }

    /* Stop losing packets, try to complete the data sending loop */
    if (ret == 0) {
        loss_mask = 0;
        ret = tls_api_data_sending_loop(test_ctx, &loss_mask, &simulated_time, 0);
    }

    /* verify that the transmission was complete */
    if (ret == 0) {
        ret = tls_api_one_scenario_body_verify(test_ctx, &simulated_time, completion_target);
    }

    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }

    if (allocated_scenario != NULL) {
        free(allocated_scenario);
    }

    return ret;
}

int heavy_loss_test()
{
    return heavy_loss_test_one(0, 23500000);
}

int heavy_loss_inter_test()
{
    return heavy_loss_test_one(1, 22000000);
}

int heavy_loss_total_test()
{
    return heavy_loss_test_one(2, 25000000);
}



int integrity_limit_test()
{
    uint64_t simulated_time = 0;
    uint64_t loss_mask = 0;
    int nb_initial_loop = 0;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    picoquic_connection_id_t initial_cid = { {0x15, 0x4E, 0x98, 0x14, 0, 0, 0, 1}, 8 };
    int ret = tls_api_init_ctx_ex(&test_ctx, PICOQUIC_INTERNAL_TEST_VERSION_1,
        PICOQUIC_TEST_SNI, PICOQUIC_TEST_ALPN, &simulated_time, NULL, NULL, 0, 0, 0, &initial_cid);

    if (ret == 0 && test_ctx == NULL) {
        ret = -1;
    }

    if (ret == 0) {
        picoquic_set_qlog(test_ctx->qserver, ".");
        ret = tls_api_connection_loop(test_ctx, &loss_mask, 0, &simulated_time);
    }

    /* Prepare to send data */
    if (ret == 0) {
        ret = test_api_init_send_recv_scenario(test_ctx, test_scenario_very_long, sizeof(test_scenario_very_long));
    }

    /* Perform a data sending loop for a few rounds after the ready state */
    while (ret == 0 && nb_initial_loop < 64) {
        if (test_ctx->cnx_server != NULL && 
            test_ctx->cnx_server->crypto_context[picoquic_epoch_1rtt].aead_decrypt != NULL) {
            nb_initial_loop++;
        }

        ret = tls_api_data_sending_loop(test_ctx, &loss_mask, &simulated_time, 16);
    }

    /* Check the max length of an epoch is the expected value */
    if (ret == 0) {
        uint64_t limit = picoquic_aead_confidentiality_limit(test_ctx->cnx_server->crypto_context[picoquic_epoch_1rtt].aead_decrypt);

        if (test_ctx->cnx_server->crypto_epoch_length_max != limit) {
            DBG_PRINTF("Server confidentiality limit set to 0x%" PRIx64 ", insted of %" PRIx64,
                test_ctx->cnx_server->crypto_epoch_length_max, limit);
            ret = -1;
        } else if (test_ctx->cnx_client->crypto_epoch_length_max != limit) {
            DBG_PRINTF("Client confidentiality limit set to 0x%" PRIx64 ", insted of %" PRIx64,
                test_ctx->cnx_client->crypto_epoch_length_max, limit);
            ret = -1;
        }
    }


    /* Set the number of failed decryptions just below the limit and then send a bad packet  */
    if (ret == 0 && test_ctx->cnx_server != NULL) {
        uint8_t p[256];

        test_ctx->cnx_server->crypto_failure_count = picoquic_aead_integrity_limit(
            test_ctx->cnx_server->crypto_context[picoquic_epoch_1rtt].aead_decrypt);

        memset(p, 0, sizeof(p));
        memcpy(p + 1, test_ctx->cnx_server->path[0]->p_local_cnxid->cnx_id.id, test_ctx->cnx_server->path[0]->p_local_cnxid->cnx_id.id_len);
        p[0] |= 64;
        (void)picoquic_incoming_packet(test_ctx->qserver, p, sizeof(p), (struct sockaddr*) & test_ctx->cnx_server->path[0]->peer_addr,
            (struct sockaddr*) & test_ctx->cnx_server->path[0]->local_addr, 0, test_ctx->recv_ecn_server, simulated_time);

        if (test_ctx->cnx_server->cnx_state != picoquic_state_disconnecting) {
            DBG_PRINTF("Connection not disconnecting, limit 0x%" PRIx64 ", reached %" PRIx64,
                test_ctx->cnx_server->crypto_context[picoquic_epoch_1rtt].aead_decrypt,
                test_ctx->cnx_server->crypto_failure_count);
            ret = -1;
        }
        else if (test_ctx->cnx_server->local_error != PICOQUIC_TRANSPORT_AEAD_LIMIT_REACHED) {
            DBG_PRINTF("Wrong error code, 0x%x instead of 0x%x",
                test_ctx->cnx_server->local_error,
                PICOQUIC_TRANSPORT_AEAD_LIMIT_REACHED);
            ret = -1;
        }
    }

    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }

    return ret;
}

/* Excess repeat test.
 * start a big transfer, then kill the client. Check how many packets the server sends
 * before giving up. Fail if too many.
 * Repeat for all supported congestion control algorithms */

int excess_repeat_test_one(picoquic_congestion_algorithm_t* cc_algo, int repeat_target)
{
    const uint64_t test_latency = 30000;
    const uint64_t picosec_100mbps = 80000;
    const int nb_loops_max = 3000;
    uint64_t simulated_time = 0;
    uint64_t loss_mask = 0;
    int nb_initial_loop = 0;
    int nb_repeated = 0;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    picoquic_connection_id_t initial_cid = { {0xe8, 0xce, 0x55, 0, 0, 0, 0, 0}, 8 };
    int ret;
    
    initial_cid.id[7] = cc_algo->congestion_algorithm_number;
    ret = tls_api_init_ctx_ex(&test_ctx, PICOQUIC_INTERNAL_TEST_VERSION_1,
        PICOQUIC_TEST_SNI, PICOQUIC_TEST_ALPN, &simulated_time, NULL, NULL, 0, 0, 0, &initial_cid);

    if (ret == 0 && test_ctx == NULL) {
        ret = -1;
    }

    if (ret == 0) {
        /* Set long delays, 1 Mbps each way */
        test_ctx->c_to_s_link->microsec_latency = test_latency;
        test_ctx->c_to_s_link->picosec_per_byte = picosec_100mbps;
        test_ctx->s_to_c_link->microsec_latency = test_latency;
        test_ctx->s_to_c_link->picosec_per_byte = picosec_100mbps;
        /* Set the CC algorithm to selected value */
        picoquic_set_default_congestion_algorithm(test_ctx->qserver, cc_algo);
        /* set qlog */
        picoquic_set_qlog(test_ctx->qserver, ".");
        /* initial connection */
        ret = tls_api_connection_loop(test_ctx, &loss_mask, 0, &simulated_time);
    }

    /* Prepare to send data */
    if (ret == 0) {
        ret = test_api_init_send_recv_scenario(test_ctx, test_scenario_very_long, sizeof(test_scenario_very_long));
    }

    /* Perform a data sending loop for a few rounds after the ready state */
    while (ret == 0 && nb_initial_loop < 64) {
        if (test_ctx->cnx_server != NULL && test_ctx->cnx_client->cnx_state >= picoquic_state_ready){
            nb_initial_loop++;
        }

        ret = tls_api_data_sending_loop(test_ctx, &loss_mask, &simulated_time, 16);
    }

    /* Now, simulate that the client has gone away, and count the packets */
    if (ret == 0) {
        picoquictest_sim_packet_t* packet = picoquictest_sim_link_create_packet();
        int if_index = 0;
        picoquic_connection_id_t log_cid;
        picoquic_cnx_t* last_cnx;
        uint64_t max_disconnected_time = simulated_time + 30000000;
        int nb_loops = 0;

        if (cc_algo->congestion_algorithm_number == PICOQUIC_CC_ALGO_NUMBER_DCUBIC ||
            cc_algo->congestion_algorithm_number == PICOQUIC_CC_ALGO_NUMBER_FAST) {
            repeat_target = 200;
        }

        if (packet == NULL) {
            ret = -1;
        }
        else {
            while (ret == 0 &&
                test_ctx->qserver->current_number_connections > 0 &&
                test_ctx->cnx_server != NULL &&
                test_ctx->cnx_server->cnx_state != picoquic_state_disconnected) {
                uint64_t old_time = simulated_time;
                uint64_t delta_t;

                simulated_time = picoquic_get_next_wake_time(test_ctx->qserver, simulated_time);
                delta_t = simulated_time - old_time;
                if (delta_t > 3000000) {
                    DBG_PRINTF("Large delta t=%" PRIu64, delta_t);
                    ret = -1;
                    break;
                }
                if (simulated_time > max_disconnected_time) {
                    DBG_PRINTF("Timeout too at t=%" PRIu64 ", Delta_t=%" PRIu64,
                        simulated_time, delta_t);
                    ret = -1;
                    break;
                }
                else {
                    ret = picoquic_prepare_next_packet(test_ctx->qserver, simulated_time,
                        packet->bytes, sizeof(packet->bytes), &packet->length,
                        &packet->addr_to, &packet->addr_from, &if_index, &log_cid, &last_cnx);
                    if (ret == 0 && packet->length > 0) {
                        nb_repeated++;
                        if (nb_repeated > repeat_target) {
                            DBG_PRINTF("Stop test for cc=%s stopped after %d repeats, t=%" PRIu64,
                                cc_algo->congestion_algorithm_id, nb_repeated, simulated_time);
                            ret = -1;
                            break;
                        }
                    }
                }
                nb_loops += 1;
                if (nb_loops > nb_loops_max) {
                    DBG_PRINTF("Stop test for cc=%s stopped after %d loops, %d repeats, t=%" PRIu64,
                        cc_algo->congestion_algorithm_id, nb_loops, nb_repeated, simulated_time);
                    ret = -1;
                    break;
                }

            }
            if (ret == 0) {
                DBG_PRINTF("Test for cc=%s passes after %d loops, %d repeats, t=%" PRIu64,
                    cc_algo->congestion_algorithm_id, nb_loops, nb_repeated, simulated_time);
            }

            free(packet);
        }
    }

    /* Delete the context */
    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
    }

    return ret;
}

int excess_repeat_test()
{
    const int nb_repeat_max = 128;

    picoquic_congestion_algorithm_t* algo_list[6] = {
        picoquic_newreno_algorithm,
        picoquic_cubic_algorithm,
        picoquic_dcubic_algorithm,
        picoquic_fastcc_algorithm,
        picoquic_bbr_algorithm,
        picoquic_prague_algorithm
    };
    int ret = 0;

    for (int i = 0; i < 6 && ret == 0; i++) {
        ret = excess_repeat_test_one(algo_list[i], nb_repeat_max);
        if (ret != 0) {
            DBG_PRINTF("Excess repeat test fails for CC=%s", algo_list[i]->congestion_algorithm_id);
        }
    }

    return ret;
}

/* Connection DDOS
* Simulate attack on server by sending tons of connection requests. See
* what happens.
*/

int cnx_ddos_test_loop(int nb_connections, uint64_t ddos_interval, const char* qlogdir)
{
    uint64_t simulated_time = 0;
    uint64_t ddos_time = 0;
    int nb_ddos_done = 0;
    int nb_sent = 0;
    int if_index = 0;
    int still_sending = 0;
    picoquic_connection_id_t log_cid;
    picoquic_cnx_t* last_cnx;
    picoquic_quic_t* qddos = picoquic_create(100, NULL, NULL, NULL, PICOQUIC_TEST_ALPN, NULL, NULL,
        NULL, NULL, NULL, 0, &simulated_time, NULL, NULL, 0);
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    uint64_t start_wall_time;
    uint64_t elapsed_wall_time;
    picoquictest_sim_packet_t* packet = picoquictest_sim_link_create_packet();
    picoquictest_sim_packet_t* ddos_packet_first = NULL;
    int ret = tls_api_init_ctx_ex2(&test_ctx, PICOQUIC_INTERNAL_TEST_VERSION_1,
        PICOQUIC_TEST_SNI, PICOQUIC_TEST_ALPN, &simulated_time, NULL, NULL, 0, 0, 0, NULL, 10000, 0, 0, 0);
    uint32_t max_number_cnx_ctx = 0;

    if (ret == 0 && (test_ctx == NULL || packet == NULL || qddos == NULL)) {
        ret = -1;
    }

    if (ret == 0 && qlogdir != NULL && strcmp("-", qlogdir) != 0) {
        picoquic_set_qlog(test_ctx->qserver, qlogdir);
    }

    /* Create a list of nb_connections initial packets. We do this before running the
     * DDOS, so the time to create the attack is not counted in the "wall time" of
     * the server under attacks. */
    for (int i = 0; ret == 0 && i < nb_connections; i++) {
        picoquictest_sim_packet_t* ddos_packet = picoquictest_sim_link_create_packet();
        if (ddos_packet == NULL) {
            DBG_PRINTF("Could not create dos packet #%d", i + 1);
            ret = -1;
        }
        else {
            picoquic_cnx_t* ddos_cnx = NULL;

            ddos_packet->next_packet = ddos_packet_first;
            ddos_packet_first = ddos_packet;

            ddos_cnx = picoquic_create_cnx(qddos, picoquic_null_connection_id, picoquic_null_connection_id,
                (struct sockaddr*)&test_ctx->server_addr, simulated_time, 0, PICOQUIC_TEST_SNI,
                PICOQUIC_TEST_ALPN, 1);
            if (ddos_cnx == NULL) {
                DBG_PRINTF("Cannot create ddos cnx #%d", nb_ddos_done);
                ret = -1;
            }
            else if ((ret = picoquic_start_client_cnx(ddos_cnx)) != 0) {
                DBG_PRINTF("Cannot create ddos cnx #%d", nb_ddos_done);
                ret = -1;
            }
            else if ((ret = picoquic_prepare_next_packet(qddos, simulated_time,
                ddos_packet->bytes, sizeof(ddos_packet->bytes), &ddos_packet->length,
                &ddos_packet->addr_to, &ddos_packet->addr_from, &if_index, &log_cid, &last_cnx)) != 0 ||
                ddos_packet->length == 0) {
                DBG_PRINTF("Cannot create ddos initial #%d, ret = 0x%x", nb_ddos_done, ret);
                ret = -1;
            }
            else {
                picoquic_set_test_address((struct sockaddr_in*)&packet->addr_from,
                    0x0a010000 + nb_ddos_done, 0x8421);
            }

            if (ddos_cnx != NULL) {
                picoquic_delete_cnx(ddos_cnx);
            }
        }
    }
    if (ret == 0) {
        DBG_PRINTF("Created %d ddos initial packets", nb_connections);
    }

    start_wall_time = picoquic_current_time();
    while (ret == 0 && (ddos_packet_first != NULL || still_sending)) {
        uint64_t next_time = picoquic_get_next_wake_time(test_ctx->qserver, simulated_time);

        still_sending = 0;

        if (test_ctx->qserver->current_number_connections > max_number_cnx_ctx) {
            max_number_cnx_ctx = test_ctx->qserver->current_number_connections;
        }

        if (next_time < ddos_time) {
            simulated_time = next_time;

            ret = picoquic_prepare_next_packet(test_ctx->qserver, simulated_time,
                packet->bytes, sizeof(packet->bytes), &packet->length,
                &packet->addr_to, &packet->addr_from, &if_index, &log_cid, &last_cnx);
            if (ret != 0) {
                DBG_PRINTF("Server error after #%d ddos, ret = 0x%x", nb_ddos_done, ret);
                ret = -1;
            }
            else if (packet->length > 0) {
                nb_sent++;
                still_sending = 1;
            }
        }
        else if (ddos_packet_first != NULL) {
            picoquictest_sim_packet_t* ddos_packet = ddos_packet_first;
            ddos_packet_first = ddos_packet->next_packet;

            simulated_time = ddos_time;
            nb_ddos_done++;

            if (nb_ddos_done >= nb_connections) {
                ddos_time = UINT64_MAX;
            }
            else {
                ddos_time += ddos_interval;
            }

            ret = picoquic_incoming_packet(test_ctx->qserver, ddos_packet->bytes, ddos_packet->length,
                (struct sockaddr*)&ddos_packet->addr_from, (struct sockaddr*)&ddos_packet->addr_to,
                if_index, 0, simulated_time);
            still_sending = 1;
            if (ret != 0) {
                DBG_PRINTF("Server chokes on initial #%d, ret = 0x%x", nb_ddos_done, ret);
            }

            free(ddos_packet);
        }
    }

    elapsed_wall_time = picoquic_current_time() - start_wall_time;

    if (ret == 0) {
        if (max_number_cnx_ctx > test_ctx->qserver->max_half_open_before_retry) {
            DBG_PRINTF("Too many connection context, up to %d instead of at most %d",
                max_number_cnx_ctx, test_ctx->qserver->max_half_open_before_retry);
            ret = -1;
        }

        DBG_PRINTF("Simulation succeeds at t=%" PRIu64 ", spent: %" PRIu64 ", sent: %d",
            simulated_time, elapsed_wall_time, nb_sent);
    }

    /* TODO: run a simulated connection to verify that the context is operational */
    if (ret == 0) {
        /* Get rid of the connection if one was created in the context */
        if (test_ctx->cnx_client != NULL) {
            (void)picoquic_delete_cnx(test_ctx->cnx_client);
            test_ctx->cnx_client = NULL;
        }
        /* re-create a client connection, this time picking up the correct start time */
        test_ctx->cnx_client = picoquic_create_cnx(test_ctx->qclient,
            picoquic_null_connection_id, picoquic_null_connection_id,
            (struct sockaddr*)&test_ctx->server_addr, simulated_time,
            PICOQUIC_INTERNAL_TEST_VERSION_1, PICOQUIC_TEST_SNI, PICOQUIC_TEST_ALPN, 1);

        ret = tls_api_one_scenario_body(test_ctx, &simulated_time,
            test_scenario_q2_and_r2, sizeof(test_scenario_q2_and_r2), 0, 0x00004281, 0, 20000, 2000000);

        if (ret == 0) {
            DBG_PRINTF("Post DDOS connection succeeds at t=%" PRIu64 ", spent: %" PRIu64 ", sent: %d",
                simulated_time, elapsed_wall_time, nb_sent);
        }
    }

    /* Delete the context and other fields. */
    if (packet != NULL) {
        free(packet);
    }

    if (qddos != NULL) {
        picoquic_free(qddos);
    }

    while (ddos_packet_first != NULL) {
        picoquictest_sim_packet_t* ddos_packet = ddos_packet_first;
        ddos_packet_first = ddos_packet->next_packet;
        free(ddos_packet);
    }

    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
    }

    return ret;
}

int cnx_ddos_unit_test()
{
    return cnx_ddos_test_loop(1000, 1000, NULL);
}


/*
 * Test randomization of initial packet number
 */

int pn_random_check_sequence(picoquic_cnx_t* cnx, char const* cnx_name, int randomize_all)
{
    int ret = 0;
    for (picoquic_packet_context_enum pc = picoquic_packet_context_application;
        pc < picoquic_nb_packet_context; pc++) {
        if (randomize_all || pc == picoquic_packet_context_initial) {
            if (cnx->pkt_ctx[pc].send_sequence < PICOQUIC_PN_RANDOM_MIN) {
                DBG_PRINTF("For connection %s, context number %d, sequencee number is only %" PRIu64,
                    cnx_name, (int)pc, cnx->pkt_ctx[pc].send_sequence);
                ret = -1;
                break;
            }
        } else if (cnx->pkt_ctx[pc].send_sequence >= PICOQUIC_PN_RANDOM_MIN) {
            DBG_PRINTF("For connection %s, context number %d, sequencee number is %" PRIu64,
                cnx_name, (int)pc, cnx->pkt_ctx[pc].send_sequence);
            ret = -1;
            break;
        }
    }

    return ret;
}

int pn_random_test_one(int randomize_all)
{
    uint64_t simulated_time = 0;
    uint64_t loss_mask = 0;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;

    picoquic_connection_id_t initial_cid = { {0xff, 0x12, 0x34, 0, 0, 0, 0, 0}, 8 };
    int ret = tls_api_init_ctx_ex(&test_ctx, PICOQUIC_INTERNAL_TEST_VERSION_1, PICOQUIC_TEST_SNI, PICOQUIC_TEST_ALPN,
        &simulated_time, NULL, NULL, 0, 1, 0, &initial_cid);

    if (ret == 0 && test_ctx == NULL) {
        ret = -1;
    }

    /* Set the initial packet number randomization */
    if (ret == 0) {
        picoquic_set_random_initial(test_ctx->qclient, (randomize_all) ? 2 : 1);
        picoquic_set_random_initial(test_ctx->qserver, (randomize_all) ? 2 : 1);
        picoquic_set_qlog(test_ctx->qserver, ".");
        /* The client connection is already created, so we force randomization of sequence numbers here */
        for (picoquic_packet_context_enum pc = 
            (randomize_all)?picoquic_packet_context_application: picoquic_packet_context_initial;
            pc < picoquic_nb_packet_context; pc++) {
            test_ctx->cnx_client->pkt_ctx[pc].send_sequence = ((uint64_t)PICOQUIC_PN_RANDOM_MIN) + 17 + (uint64_t)pc;
        }
        /* Now, start the client connection */
        ret = picoquic_start_client_cnx(test_ctx->cnx_client);
    }

    if (ret == 0){
        ret = tls_api_connection_loop(test_ctx, 0, 0, &simulated_time);

        if (ret != 0)
        {
            DBG_PRINTF("Connection loop returns error %d\n", ret);
        }
        else {
            /* Check that the sequence numbers for all number spaces are larger than random minimum */
            ret = pn_random_check_sequence(test_ctx->cnx_client, "client", randomize_all);
            if (ret == 0) {
                ret = pn_random_check_sequence(test_ctx->cnx_server, "server", randomize_all);
            }
        }
    }
    /* Complete the connection */
    if (ret == 0) {
        /* Prepare to send data */
        ret = test_api_init_send_recv_scenario(test_ctx, test_scenario_q_and_r, sizeof(test_scenario_q_and_r));

        /* Try to complete the data sending loop */
        if (ret == 0) {
            ret = tls_api_data_sending_loop(test_ctx, &loss_mask, &simulated_time, 0);
        }

        /* verify that the transmission was complete */
        if (ret == 0) {
            ret = tls_api_one_scenario_body_verify(test_ctx, &simulated_time, 1000000);
        }
    }

    /* And then free the resource
     */

    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }

    return ret;
}

int pn_random_test()
{

    int ret = pn_random_test_one(0);

    if (ret != 0) {
        DBG_PRINTF("Randomize initials fails, ret = %d", ret);
    } else{
        ret = pn_random_test_one(1);
        if (ret != 0) {
            DBG_PRINTF("Randomize all fails, ret = %d", ret);
        }
    }

    return ret;
}

int pn_random_init_test()
{
    int ret = pn_random_test_one(0);

    return ret;
}



/* Test the stateless reset blowback control mechanism
 */
int test_stateless_blowback_one(picoquic_quic_t* quic, uint64_t * simulated_time, int * was_sent)
{
    int ret = 0;
    uint8_t bytes[PICOQUIC_MAX_PACKET_SIZE];
    size_t length = PICOQUIC_MAX_PACKET_SIZE;
    uint8_t filler;
    struct sockaddr_in addr_peer, addr_srv;

    *was_sent = 0;

    /* Format random 1 RTT packet */
    filler = 0xff ^ (((uint8_t)*simulated_time) & 0xff);
    memset(bytes, filler, sizeof(bytes));
    bytes[0] &= 0x7f;
    picoquic_set_test_address(&addr_peer, 0x01010101, 1234);
    picoquic_set_test_address(&addr_srv, 0x02020202, 4567);

    /* Submit as incoming */
    ret = picoquic_incoming_packet(quic, bytes, length, (struct sockaddr*) & addr_peer,
        (struct sockaddr*) & addr_srv, 0, 0, *simulated_time);

    /* Try read stateless packet */
    if (ret == 0) {
        picoquic_cnx_t* cnx;
        picoquic_connection_id_t cid_log;
        struct sockaddr_storage s_addr_to, s_addr_from;
        int if_index;
        ret = picoquic_prepare_next_packet(quic, *simulated_time, bytes, sizeof(bytes), &length,
            &s_addr_to, &s_addr_from, &if_index, &cid_log, &cnx);
        if (ret == 0 && length > 0) {
            *was_sent = 1;
        }
    }

    return ret;
}

int test_stateless_blowback()
{
    int was_sent = 0;
    uint64_t new_interval = 2 * PICOQUIC_MICROSEC_STATELESS_RESET_INTERVAL_DEFAULT;

    /* Create a context with the default timer. */
    uint64_t simulated_time = 0;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;

    picoquic_connection_id_t initial_cid = { {0xb1, 0x08, 0xba, 0xcc, 0, 0, 0, 0}, 8 };
    int ret = tls_api_init_ctx_ex(&test_ctx, PICOQUIC_INTERNAL_TEST_VERSION_1, PICOQUIC_TEST_SNI, PICOQUIC_TEST_ALPN,
        &simulated_time, NULL, NULL, 0, 1, 0, &initial_cid);

    if (test_ctx->qserver->stateless_reset_min_interval != PICOQUIC_MICROSEC_STATELESS_RESET_INTERVAL_DEFAULT) {
        DBG_PRINTF("Stateless reset interval set to T=%" PRIu64, test_ctx->qserver->stateless_reset_min_interval);
        ret = -1;

    }

    /* Format a random packet and submit it, verify that the stateless reset is queued */
    if (ret == 0) {
        ret = test_stateless_blowback_one(test_ctx->qserver, &simulated_time, &was_sent);
        if (ret == 0 && !was_sent) {
            DBG_PRINTF("First stateless reset was not sent at T=%" PRIu64, simulated_time);
            ret = -1;
        }
    }

    /* Progress by 1/2 specified interval, retry, it should not work  */
    if (ret == 0) {
        simulated_time += test_ctx->qserver->stateless_reset_min_interval;
        ret = test_stateless_blowback_one(test_ctx->qserver, &simulated_time, &was_sent);
        if (ret == 0 && !was_sent) {
            DBG_PRINTF("Second stateless reset was not sent at T=%" PRIu64, simulated_time);
            ret = -1;
        }
    }
    
    /* Progress by 1x specified interval, retry, it should work  */
    if (ret == 0) {
        simulated_time += test_ctx->qserver->stateless_reset_min_interval / 2;
        ret = test_stateless_blowback_one(test_ctx->qserver, &simulated_time, &was_sent);
        if (ret == 0 && was_sent) {
            DBG_PRINTF("Third stateless reset was sent at T=%" PRIu64, simulated_time);
            ret = -1;
        }
    }

    /* Reset the interval to twice the previous value */
    if (ret == 0) {
        picoquic_set_default_stateless_reset_min_interval(test_ctx->qserver, new_interval);
        if (test_ctx->qserver->stateless_reset_min_interval != new_interval) {
            DBG_PRINTF("Stateless reset interval set to T=%" PRIu64, test_ctx->qserver->stateless_reset_min_interval);
            ret = -1;
        }
    }
    
    /* Progress by 0.75x new interval, retry, it should work  */
    if (ret == 0) {
        simulated_time += (new_interval - new_interval / 4);
        ret = test_stateless_blowback_one(test_ctx->qserver, &simulated_time, &was_sent);
        if (ret == 0 && !was_sent) {
            DBG_PRINTF("After new interval,  stateless reset was not sent at T=%" PRIu64, simulated_time);
            ret = -1;
        }
    }

    /* Reset the interval to zero */
    if (ret == 0) {
        picoquic_set_default_stateless_reset_min_interval(test_ctx->qserver, 0);
        if (test_ctx->qserver->stateless_reset_min_interval != 0) {
            DBG_PRINTF("Stateless reset interval set to T=%" PRIu64, test_ctx->qserver->stateless_reset_min_interval);
            ret = -1;
        }
    }

    /* Try immediately, it should not work  */
    if (ret == 0) {
        ret = test_stateless_blowback_one(test_ctx->qserver, &simulated_time, &was_sent);
        if (ret == 0 && !was_sent) {
            DBG_PRINTF("After zero interval,  stateless reset was not sent at T=%" PRIu64, simulated_time);
            ret = -1;
        }
    }

    /* Add 1 microsec, it should work  */
    if (ret == 0) {
        simulated_time += 1;
        ret = test_stateless_blowback_one(test_ctx->qserver, &simulated_time, &was_sent);
        if (ret == 0 && !was_sent) {
            DBG_PRINTF("After zero +1 interval,  stateless reset was not sent at T=%" PRIu64, simulated_time);
            ret = -1;
        }
    }

    /* Free the resurce and return */
    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }

    return ret;
}

/* Test that random padding of coalesced packets has no unexpected side effects.
 */
char const* random_padding_text_log = "random_padding_log.txt";

int random_padding_test_one(size_t pad_length, uint64_t* random_context, uint8_t test_id)
{
    int ret;
    uint64_t simulated_time = 0;
    uint64_t loss_mask = 0;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    uint32_t proposed_version = PICOQUIC_INTEROP_VERSION_LATEST;
    picoquictest_sim_packet_t* packet = picoquictest_sim_link_create_packet();
    picoquic_connection_id_t initial_cid = { {0x8a, 0x8d, 0x08, 0x9a, 0xdd, 0, 0, 0}, 8 };

    ret = picoquic_save_tickets(NULL, simulated_time, ticket_file_name);
    initial_cid.id[5] = test_id;
    
    ret = tls_api_init_ctx_ex(&test_ctx, proposed_version, PICOQUIC_TEST_SNI, PICOQUIC_TEST_ALPN, &simulated_time,
            ticket_file_name, NULL, 0, 0, 0, &initial_cid);

    if (ret != 0 || packet == NULL)
    {
        DBG_PRINTF("Could not create the QUIC test contexts for V=%x\n", proposed_version);
        ret = -1;
    }

    if (ret == 0) {
        /* Start logging on the server */
        picoquic_set_textlog(test_ctx->qserver, random_padding_text_log);
        picoquic_set_binlog(test_ctx->qserver, ".");
        test_ctx->qserver->use_long_log = 1;
    }

    if (ret == 0) {
        /* Prepare a first packet from the client to the server */
        ret = picoquic_prepare_packet(test_ctx->cnx_client, simulated_time,
            packet->bytes, PICOQUIC_MAX_PACKET_SIZE, &packet->length,
            &packet->addr_to, &packet->addr_from, NULL);
        picoquic_store_addr(&packet->addr_from, (struct sockaddr*) & test_ctx->client_addr);

        if (packet->length == 0) {
            ret = PICOQUIC_ERROR_UNEXPECTED_ERROR;
        }
        if (ret != 0)
        {
            DBG_PRINTF("Could not create first client packet, ret=%x\n", ret);
        }
        else if (packet->length + pad_length > PICOQUIC_MAX_PACKET_SIZE) {
            DBG_PRINTF("Cannot insert %uz bytes after length %uz\n", pad_length, packet->length);
            ret = -1;
        }
        else {
            /* Insert random padding */
            picoquic_test_random_bytes(random_context, packet->bytes + packet->length, pad_length);
            packet->bytes[packet->length] |= 0x80;
            packet->length += pad_length;
            simulated_time += test_ctx->c_to_s_link->microsec_latency;

            ret = picoquic_incoming_packet(test_ctx->qserver, packet->bytes, (uint32_t)packet->length,
                (struct sockaddr*) & packet->addr_from,
                (struct sockaddr*) & packet->addr_to, 0, test_ctx->recv_ecn_server,
                simulated_time);

            if (ret == 0) {
                picoquic_cnx_t* next = test_ctx->qserver->cnx_list;

                while (next != NULL && picoquic_compare_connection_id(&next->initial_cnxid, &test_ctx->cnx_client->initial_cnxid) != 0) {
                    next = next->next_in_table;
                }

                if (next != NULL) {
                    test_ctx->cnx_server = next;
                }
                else {
                    ret = -1;
                    DBG_PRINTF("Could not create server side connection, ret = %d\n", ret);
                }
            }
        }
    }

    if (ret == 0) {
        /* Perform a connection loop to verify it goes OK */
        ret = tls_api_connection_loop(test_ctx, &loss_mask,
            2*test_ctx->c_to_s_link->microsec_latency, &simulated_time);

        if (ret != 0)
        {
            DBG_PRINTF("Connection loop returns %d\n", ret);
        }
    }

    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }

    if (packet != NULL) {
        free(packet);
    }

    return ret;
}

int random_padding_test()
{
    uint64_t random_context = 0x1234567890abcdef;

    int ret = random_padding_test_one(128, &random_context, 0);

    if (ret == 0) {
        ret = random_padding_test_one(16, &random_context, 1);
    }

    return ret;
}
#if 0
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
                    (i==0)?0:max_completion_time);
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
                        bdp_test_option == bdp_test_option_cubic) {
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
#endif
/* Test closing a connection with a specific error message.
 */

char const* error_reason_text_log = "error_reason_log.txt";

int error_reason_test()
{
    uint64_t simulated_time = 0;
    uint64_t loss_mask = 0;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    picoquic_connection_id_t initial_cid = { {0xe8, 0x80, 0x88, 0xea, 0x50, 0, 0, 0}, 8 };
    int ret = tls_api_init_ctx_ex(&test_ctx, PICOQUIC_INTERNAL_TEST_VERSION_1, PICOQUIC_TEST_SNI, PICOQUIC_TEST_ALPN,
        &simulated_time, NULL, NULL, 0, 1, 0, &initial_cid);

    if (ret == 0 && test_ctx == NULL) {
        ret = -1;
    }

    if (ret == 0) {
        /* Request the logs on the server side, so manual inspection can verify that
         * the error reason is properly displayed. */
        picoquic_set_textlog(test_ctx->qserver, error_reason_text_log);
        test_ctx->qserver->use_long_log = 1;
        picoquic_set_qlog(test_ctx->qserver, ".");
        /* Now, start the client connection */
        ret = picoquic_start_client_cnx(test_ctx->cnx_client);
    }

    if (ret == 0) {
        /* Perform a connection loop to verify it goes OK */
        ret = tls_api_connection_loop(test_ctx, &loss_mask,
            2 * test_ctx->c_to_s_link->microsec_latency, &simulated_time);

        if (ret != 0)
        {
            DBG_PRINTF("Connection loop returns %d\n", ret);
        }
    }

    if (ret == 0) {
        /* force closure of the client connection with an internal error */
        int local_error_ret = picoquic_connection_error_ex(test_ctx->cnx_client, PICOQUIC_TRANSPORT_INTERNAL_ERROR,
            0, "error reason test");
        if (local_error_ret != PICOQUIC_ERROR_DETECTED) {
            DBG_PRINTF("picoquic_connection_error_ex returns %d\n", ret);
            ret = -1;
        }
    }

    if (ret == 0) {
        /* verify that the connection will be closed */
        int nb_trials = 0;
        int nb_inactive = 0;
        while (ret == 0 && nb_trials < 1024 && nb_inactive < 512 ) {
            int was_active = 0;
            nb_trials++;

            ret = tls_api_one_sim_round(test_ctx, &simulated_time, 0, &was_active);

            if (test_ctx->cnx_client->cnx_state == picoquic_state_disconnected &&
                (test_ctx->cnx_server == NULL || test_ctx->cnx_server->cnx_state == picoquic_state_disconnected)) {
                break;
            }

            if (nb_trials == 512) {
                DBG_PRINTF("After %d trials, client state = %d, server state = %d",
                    nb_trials, (int)test_ctx->cnx_client->cnx_state,
                    (test_ctx->cnx_server == NULL) ? -1 : test_ctx->cnx_server->cnx_state);
            }

            if (was_active) {
                nb_inactive = 0;
            }
            else {
                nb_inactive++;
            }
        }
    }
    /* Close the contexts, which will close the logs.
     */

    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }

    return ret;
}
 /* Test of the blocked ports functionality
  */

int port_blocked_test_one(picoquic_quic_t * quic,
    uint8_t* packet, size_t packet_length, 
    struct sockaddr* addr_from, struct sockaddr* addr_to,
    int expect_blocked, int retry_accepted, uint64_t current_time)
{
    uint8_t send_buffer[PICOQUIC_MAX_PACKET_SIZE];
    struct sockaddr_storage s_to;
    struct sockaddr_storage s_from;
    int if_index = 0;
    picoquic_cnx_t* first_cnx = NULL;
    int path_id = -1;
    picoquic_cnx_t* last_cnx = NULL;
    size_t send_length = 0;
    picoquic_connection_id_t log_cid = { 0 };


    int ret = picoquic_incoming_packet_ex(quic, packet, packet_length, addr_from, addr_to, 0, 0, &first_cnx, &path_id, current_time);

    if (ret == 0) {
        ret = picoquic_prepare_next_packet_ex(quic, current_time, send_buffer, PICOQUIC_MAX_PACKET_SIZE, &send_length, &s_to, &s_from, &if_index, &log_cid, &last_cnx, NULL);
    }

    if (ret == 0) {
        if (send_length > 0 && expect_blocked) {
            /* TODO: check whether the "blocked" packet is a stateless retry */
            uint8_t flags;
            uint32_t vn;
            const uint8_t* bytes;
            int version_index;

            ret = -1;

            if (retry_accepted) {
                if ((bytes = picoquic_frames_uint8_decode(send_buffer, &send_buffer[send_length], &flags)) != NULL &&
                    (bytes = picoquic_frames_uint32_decode(bytes, &send_buffer[send_length], &vn)) != NULL &&
                    (version_index = picoquic_get_version_index(vn)) >= 0) {
                    picoquic_packet_type_enum p_type = picoquic_parse_long_packet_type(flags, version_index);
                    if (p_type == picoquic_packet_retry) {
                        ret = 0;
                    }
                }
            }
        }
        else if (send_length == 0 && !expect_blocked) {
            ret = -1;
        }
    }

    return ret;
}

int port_blocked_test_address(
    struct sockaddr* addr_from, struct sockaddr* addr_to,
    int expect_blocked, int do_disable)
{
    /* Create a series of connection contexts for the list of port */
    uint8_t send_buffer[PICOQUIC_MAX_PACKET_SIZE];
    struct sockaddr_storage s_to;
    struct sockaddr_storage s_from;
    size_t send_length;
    int if_index;
    picoquic_connection_id_t log_cid;
    picoquic_cnx_t* last_cnx;
    uint64_t simulated_time = 0;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    int ret = tls_api_init_ctx(&test_ctx, PICOQUIC_V1_VERSION, PICOQUIC_TEST_SNI, PICOQUIC_TEST_ALPN, &simulated_time, NULL, NULL, 0, 1, 0);
    if (ret == 0) {
        /* Delete the default connection */
        picoquic_delete_cnx(test_ctx->cnx_client);
        /* Set prot blocking to expected value */
        picoquic_disable_port_blocking(test_ctx->qserver, do_disable);
    }
    /* Perform the VN test */
    if (ret == 0) {
        memset(send_buffer, 0xaa, PICOQUIC_ENFORCED_INITIAL_MTU);
        send_buffer[1] = 0xa1;
        send_buffer[2] = 0xa2;
        send_buffer[3] = 0xa3;
        send_buffer[4] = 0xa4;
        send_buffer[5] = 8;
        send_buffer[14] = 8;
        send_length = PICOQUIC_ENFORCED_INITIAL_MTU;
        simulated_time += 1000;
        ret = port_blocked_test_one(test_ctx->qserver, send_buffer, send_length, addr_from, addr_to, expect_blocked, 0, simulated_time);
        if (ret != 0) {
            DBG_PRINTF("VN blocked test fails, ret = %d", ret);
        }
    }
    /* test the 1RTT function */
    if (ret == 0) {
        memset(send_buffer, 0xbb, PICOQUIC_ENFORCED_INITIAL_MTU);
        send_buffer[0] = 0x7f;
        send_length = PICOQUIC_ENFORCED_INITIAL_MTU;
        simulated_time += 1000;
        ret = port_blocked_test_one(test_ctx->qserver, send_buffer, send_length, addr_from, addr_to, expect_blocked, 0, simulated_time);
        if (ret != 0) {
            DBG_PRINTF("Stateless blocked test fails, ret = %d", ret);
        }
    }
    if (ret == 0) {
        /* Create the client connection with correct address */
        simulated_time += 1000;
        test_ctx->cnx_client = picoquic_create_cnx(test_ctx->qclient,
            picoquic_null_connection_id,
            picoquic_null_connection_id,
            addr_to, simulated_time,
            PICOQUIC_V1_VERSION, PICOQUIC_TEST_SNI, PICOQUIC_TEST_ALPN, 1);
        if (test_ctx->cnx_client == NULL) {
            ret = -1;
        }
        else {
            ret = picoquic_start_client_cnx(test_ctx->cnx_client);
            if (ret != 0) {
                DBG_PRINTF("Cannot start client connection, ret = %d", ret);
            }
            else {
                ret = picoquic_prepare_next_packet_ex(test_ctx->qclient, simulated_time, send_buffer, PICOQUIC_ENFORCED_INITIAL_MTU, &send_length, &s_to, &s_from, &if_index, &log_cid, &last_cnx, NULL);
                if (ret == 0 && send_length == 0) {
                    ret = -1;
                }
                if (ret == 0) {
                    ret = port_blocked_test_one(test_ctx->qserver, send_buffer, send_length, addr_from, addr_to, expect_blocked, 1, simulated_time);
                    if (ret != 0) {
                        DBG_PRINTF("Initial blocked test fails, ret = %d", ret);
                    }
                }
            }
        }
    }
    /* Delete the context */
    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }

    return ret;
}

int port_blocked_test_port(uint16_t port, int expect_blocked)
{
    int ret = 0;
    struct sockaddr_storage a_from = { 0 };
    struct sockaddr_storage a_to = { 0 };
    char const* a_from_t[2] = { "1.1.1.1", "2001:2:3::4" };
    char const* a_to_t[2] = { "10.0.0.1", "2002:3::4" };

    for (int a_x = 0; ret == 0 && a_x < 2; a_x++) {
        /* set the addresses */
        if (ret == 0) {
            int is_name = 0;
            ret = picoquic_get_server_address(a_from_t[a_x], port, &a_from, &is_name);
            if (ret == 0 && is_name) {
                ret = -1;
            }
        }
        if (ret == 0) {
            int is_name = 0;
            ret = picoquic_get_server_address(a_to_t[a_x], 961, &a_to, &is_name);
            if (ret == 0 && is_name) {
                ret = -1;
            }
        }
        /* Iterate for blocked or not */
        for (int do_disable = 0; ret == 0 && do_disable < 2; do_disable++) {
            int actually_blocked = expect_blocked && (do_disable == 0);

            ret = port_blocked_test_address((struct sockaddr*)&a_from,
                (struct sockaddr*)&a_to, actually_blocked, do_disable);
            if (ret != 0) {
                DBG_PRINTF("For [%s]:%u, test (%d (%d), %d) fails.",
                    a_from_t[a_x], port, expect_blocked, actually_blocked, do_disable);
            }
        }
    } 
    return ret;
}

int port_blocked_test()
{
    int ret = 0;
    const uint16_t blocked_port_to_test[] = { 0, 53, 138, 1900, 5353, 11211 };
    const uint16_t unblocked_port_to_test[] = { 443, 4433, 33721 };
    size_t nb_blocked = sizeof(blocked_port_to_test) / sizeof(uint16_t);
    size_t nb_unblocked = sizeof(unblocked_port_to_test) / sizeof(uint16_t);

    for (size_t i = 0; ret == 0 && i < nb_blocked; i++) {
        ret = port_blocked_test_port(blocked_port_to_test[i], 1);
    }

    for (size_t i = 0; ret == 0 && i < nb_unblocked; i++) {
        ret = port_blocked_test_port(unblocked_port_to_test[i], 0);
    }

    return ret;
}

/* Test the immediate ACK function.
 */
int immediate_ack_test()
{
    uint64_t simulated_time = 0;
    uint64_t loss_mask = 0;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    picoquic_connection_id_t initial_cid = { {0x1a, 0x1a, 0x1a, 0x1a, 0x1a, 0x1a, 0x1a, 0x1a}, 8 };
    int ret;

    ret = tls_api_init_ctx_ex(&test_ctx, PICOQUIC_INTERNAL_TEST_VERSION_1,
        PICOQUIC_TEST_SNI, PICOQUIC_TEST_ALPN, &simulated_time, NULL, NULL, 0, 0, 0, &initial_cid);

    if (ret == 0) {
        picoquic_set_binlog(test_ctx->qserver, ".");
    }

    if (ret == 0) {
        ret = tls_api_connection_loop(test_ctx, &loss_mask, 0, &simulated_time);
    }

    if (ret == 0) {
        ret = wait_client_connection_ready(test_ctx, &simulated_time);
    }

    if (ret == 0) {
        int nb_trials = 0;
        int was_active;
        uint64_t immediate_received_at_server = 0;
        uint64_t immediate_cleared_at_server = 0;
        int all_acked = 0;
        uint8_t immediate_ack_frame[2] = { picoquic_frame_type_immediate_ack };
        /* Queue misc frame with "Immediate ACK" set */
        picoquic_queue_misc_frame(test_ctx->cnx_client, immediate_ack_frame, 2, 0,
            picoquic_packet_context_application);
        /* Do couple of rounds until the frame is received;
         * Check that it is received my verifying that the "immediate ACK" 
         * is set in the ACK context at the server. Check the time.
         */
        while (ret == 0 && nb_trials < 16) {
            nb_trials++;
            ret = tls_api_one_sim_round(test_ctx, &simulated_time, 0, &was_active);
            if (test_ctx->cnx_server != NULL &&
                test_ctx->cnx_server->ack_ctx[picoquic_packet_context_application].act[0].is_immediate_ack_required) {
                immediate_received_at_server = simulated_time;
                break;
            }
        }
        if (ret == 0 && immediate_received_at_server == 0) {
            DBG_PRINTF("Immediate ACK not received after %d rounds", nb_trials);
            ret = -1;
        }
        /* Do a couple rounds until the "immediate ACK" flag is not
         * set at the server anymore. Verify that no time is elapsed since
         * the end of the previous round */
        nb_trials = 0;
        while (ret == 0 && nb_trials < 16) {
            nb_trials++;
            ret = tls_api_one_sim_round(test_ctx, &simulated_time, 0, &was_active);
            if (test_ctx->cnx_server != NULL &&
                !test_ctx->cnx_server->ack_ctx[picoquic_packet_context_application].act[0].is_immediate_ack_required) {
                immediate_cleared_at_server = simulated_time;
                break;
            }
        }
        if (ret != 0){
            if (immediate_cleared_at_server == 0) {
                DBG_PRINTF("Immediate ACK not cleared after %d rounds", nb_trials);
                ret = -1;
            }
            else if (immediate_cleared_at_server != immediate_received_at_server) {
                DBG_PRINTF("ACK not quite immediate, set at: %" PRIu64 ", cleared at %" PRIu64,
                    immediate_received_at_server, immediate_cleared_at_server);
                ret = -1;
            }
        }
        /* Do couple rounds until the ACK is received at the client. 
         * This is verified by checking that the client ACK queue is
         * empty.
         */
        nb_trials = 0;
        while (ret == 0 && nb_trials < 32) {
            nb_trials++;
            ret = tls_api_one_sim_round(test_ctx, &simulated_time, 0, &was_active);
            if (test_ctx->cnx_client != NULL && 
                picoquic_is_cnx_backlog_empty(test_ctx->cnx_client)) {
                all_acked = 1;
                break;
            }
        }
        if (ret == 0 && !all_acked) {
            DBG_PRINTF("ACK was not received at: %" PRIu64, simulated_time);
            ret = -1;
        }
    }

    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }

    return ret;
}