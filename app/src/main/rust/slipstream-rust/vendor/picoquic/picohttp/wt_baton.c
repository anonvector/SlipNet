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

/* The "baton" protocol was defined as a test application protocol for 
 * web transport. We use it here to test design ideas for implementing
 * web transport as a "filter". In that "filter" architecture, the
 * call back from the H3 stack arrive directly to the application
 * processor. If needed, the application uses the web transport
 * library to implement the web transport functions.
 */


/**
* The relay game:
*
* A client opens a WT session to the server
*
* The server:
*   1. picks a random number [0-255] (called the baton)
*   2. opens a UNI stream
*   3. sends the baton + FIN.
*
* If either peer receives a UNI stream, it:
*   1. decodes the baton
*   2. adds 1
*   3. opens a BIDI stream
*   4. sends the new baton + FIN
*
* If either peer receives a BIDI stream, it:
*   1. decodes the baton
*   2. adds 1
*   3. replies with the new baton + FIN on the BIDI stream
*
* If either peer receives a BIDI reply, it:
*   1. decodes the baton
*   2. adds 1
*   3. opens a UNI stream
*   4. sends the new baton + FIN
*
* If either peer receives a baton == 0 at any point, ignore the above and close
* the session.
*
* Example:
*
* C->S: open
* S->C: U(250)
* C->S: Breq(251)
* S->C: Bresp(252)
* C->S: U(253)
* S->C: Breq(254)
* C->S: Bresp(255)
* S->C: U(0)
* C->S: FIN 
*/

#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <picoquic.h>
#include <tls_api.h>
#include "h3zero.h"
#include "h3zero_common.h"
#include "h3zero_uri.h"
#include "pico_webtransport.h"
#include "demoserver.h"
#include "wt_baton.h"


/* Close the session. */
int wt_baton_close_session(picoquic_cnx_t* cnx, wt_baton_ctx_t* baton_ctx, uint32_t err, char const * err_msg)
{
    int ret = 0;

    h3zero_stream_ctx_t* stream_ctx = wt_baton_find_stream(baton_ctx, baton_ctx->control_stream_id);

    picoquic_log_app_message(cnx, "Closing session control stream %" PRIu64, baton_ctx->control_stream_id);

    if (stream_ctx != NULL && !stream_ctx->ps.stream_state.is_fin_sent) {
        if (err_msg == NULL) {
            switch (err) {
            case 0:
                err_msg = "Have a nice day";
                break;
            case WT_BATON_SESSION_ERR_DA_YAMN:
                err_msg = "There is insufficient stream credit to continue the protocol";
                break;
            case  WT_BATON_SESSION_ERR_BRUH:
                err_msg = "Received a malformed Baton message";
                break;
            case WT_BATON_SESSION_ERR_GAME_OVER:
                err_msg = "All baton streams have been reset";
                break;
            case WT_BATON_SESSION_ERR_BORED:
                err_msg = "Got tired of waiting for the next message";
                break;
            default:
                break;
            }
        }
        ret = picowt_send_close_session_message(cnx, stream_ctx, err, err_msg);
        baton_ctx->baton_state = wt_baton_state_closed;
    }

    return(ret);
}

/* Update context when sending a connect request */
int wt_baton_connecting(picoquic_cnx_t* cnx,
    h3zero_stream_ctx_t* stream_ctx, void * v_baton_ctx)
{
    wt_baton_ctx_t* baton_ctx = (wt_baton_ctx_t*)v_baton_ctx;

    picoquic_log_app_message(cnx, "Outgoing connect baton on stream: %"PRIu64, stream_ctx->stream_id);
    baton_ctx->baton_state = wt_baton_state_ready;
    baton_ctx->control_stream_id = stream_ctx->stream_id;

    return 0;
}

/* Ready to receive */
void wt_baton_set_receive_ready(wt_baton_ctx_t* baton_ctx)
{
    for (size_t i = 0; i < baton_ctx->nb_lanes; i++) {
        baton_ctx->incoming[i].is_receiving = 0;
        baton_ctx->incoming[i].receiving_stream_id = UINT64_MAX;
        baton_ctx->incoming[i].padding_expected = UINT64_MAX;
    }
}

/* Process incoming stream data. */
int wt_baton_relay(picoquic_cnx_t* cnx, 
    h3zero_stream_ctx_t* stream_ctx, wt_baton_ctx_t* baton_ctx, size_t lane_id)
{
    int ret = 0;

    /* Find the next stream context */
    if (stream_ctx == NULL ||
        (IS_BIDIR_STREAM_ID(stream_ctx->stream_id) && IS_LOCAL_STREAM_ID(stream_ctx->stream_id, baton_ctx->is_client))) {
        /* need to relay the baton on a new local unidir stream */
        if ((stream_ctx = picowt_create_local_stream(cnx, 0, baton_ctx->h3_ctx, baton_ctx->control_stream_id)) == NULL) {
            ret = -1;
        }
    }
    else if (!IS_BIDIR_STREAM_ID(stream_ctx->stream_id)) {
        /* need to relay the baton on a new local bidir stream */
        if ((stream_ctx = picowt_create_local_stream(cnx, 1, baton_ctx->h3_ctx, baton_ctx->control_stream_id)) == NULL) {
            ret = -1;
        }
    }
    else {
        /* NO OP: baton was received on remote bidir stream, will send on the reverse stream. */
    }

    if (ret == 0 && stream_ctx != NULL) {
        baton_ctx->nb_turns += 1;
        baton_ctx->lanes[lane_id].nb_turns += 1;
        baton_ctx->lanes[lane_id].baton_state = wt_baton_state_sending;
        baton_ctx->lanes[lane_id].sending_stream_id = stream_ctx->stream_id;
        baton_ctx->lanes[lane_id].padding_required = UINT64_MAX;
        baton_ctx->lanes[lane_id].padding_sent = 0;

        stream_ctx->path_callback = wt_baton_callback;
        stream_ctx->path_callback_ctx = baton_ctx;

        ret = picoquic_mark_active_stream(cnx, stream_ctx->stream_id, 1, stream_ctx);
    }

    return ret;
}

int wt_baton_check(picoquic_cnx_t* cnx, h3zero_stream_ctx_t* stream_ctx,
    wt_baton_ctx_t* baton_ctx, uint8_t baton_received)
{
    int ret = 0;
    size_t lane_id = SIZE_MAX;
    size_t available_lane = SIZE_MAX;

    for (size_t i = 0; i < baton_ctx->nb_lanes; i++) {
        /* TODO: maybe store expected value if known */
        /* Looking first for direct match */
        if (baton_ctx->lanes[i].baton_state == wt_baton_state_sent) {
            if ((uint8_t)(baton_ctx->lanes[i].baton + 1) == baton_received) {
                /* matches expected echo of last sent baton */
                baton_ctx->lanes[i].baton_state = wt_baton_state_sending;
                lane_id = i;
                break;
            }
        }
        else if (available_lane == SIZE_MAX &&
            ( baton_ctx->lanes[i].baton_state == wt_baton_state_ready ||
                baton_ctx->lanes[i].baton_state == wt_baton_state_none)) {
            baton_ctx->lanes[i].first_baton = baton_received;
            available_lane = i;
        }
    }
    if (lane_id == SIZE_MAX) {
        if (available_lane < SIZE_MAX) {
            lane_id = available_lane;
            baton_ctx->lanes[lane_id].baton_state = wt_baton_state_sending;
        } else {
            /* baton does not match anything here */
            baton_ctx->baton_state = wt_baton_state_error;
            picoquic_log_app_message(cnx, "Wrong baton on stream: %" PRIu64 " after %d turns", stream_ctx->stream_id, baton_ctx->nb_turns);
            ret = wt_baton_close_session(cnx, baton_ctx, WT_BATON_SESSION_ERR_BRUH, "What the heck, Bruh?");
        }
    }
    if (lane_id != SIZE_MAX) {
        /* if the baton is all zeroes, then the exchange is done */
        if (baton_received == 0) {
            picoquic_log_app_message(cnx, "All ZERO baton on stream: %"PRIu64 " after %d turns", stream_ctx->stream_id, baton_ctx->nb_turns);
            baton_ctx->lanes[lane_id].baton_state = wt_baton_state_done;
            baton_ctx->lanes_completed += 1;
            /* Close the control stream, which will close the session */
            if (IS_BIDIR_STREAM_ID(stream_ctx->stream_id) && !IS_LOCAL_STREAM_ID(stream_ctx->stream_id, baton_ctx->is_client)) {
                /* Close this stream, because there is no response expected on return path */
                ret = picoquic_add_to_stream_with_ctx(cnx, stream_ctx->stream_id, NULL, 0, 1, NULL);
                stream_ctx->ps.stream_state.is_fin_sent = 1;
            }
            if (baton_ctx->lanes_completed >= baton_ctx->nb_lanes) {
                /* Close the session, because we are done. */
                ret = wt_baton_close_session(cnx, baton_ctx, 0, NULL);
            }
        } else {
            int baton_7 = baton_received % 7;

            if (baton_7 == picoquic_is_client(cnx) && baton_received != 0) {
                baton_ctx->is_datagram_ready = 1;
                baton_ctx->baton_datagram_send_next = baton_received;
                h3zero_set_datagram_ready(cnx, baton_ctx->control_stream_id);
            }
            if (lane_id == 0 && !baton_ctx->is_client && baton_ctx->inject_error &&
                baton_ctx->lanes[lane_id].nb_turns >= 4) {
                picoquic_log_app_message(cnx, "Error injection after %d turns", baton_ctx->lanes[lane_id].nb_turns);
                baton_ctx->lanes[lane_id].baton += 31;
                if (baton_ctx->lanes[lane_id].baton == 0) {
                    baton_ctx->lanes[lane_id].baton = 1;
                }
            } else {
                baton_ctx->lanes[lane_id].baton = baton_received + 1;
            }
            baton_ctx->baton_state = wt_baton_state_sent;
            if (baton_ctx->lanes[lane_id].baton == 0) {
                baton_ctx->lanes_completed += 1;
            }
            ret = wt_baton_relay(cnx, stream_ctx, baton_ctx, lane_id);
        }
    }
    return ret;
}

int wt_baton_incoming_data(picoquic_cnx_t * cnx, wt_baton_ctx_t* baton_ctx,
    wt_baton_incoming_t* incoming_ctx, const uint8_t * bytes, size_t length)
{
    int ret = 0;
    size_t processed = 0;

    baton_ctx->nb_baton_bytes_received += length;
    /* Padding length has not been received yet */
    while (processed < length && incoming_ctx->padding_expected == UINT64_MAX) {
        if (incoming_ctx->nb_receive_buffer_bytes > 0) {
            size_t expected_length_of_length = VARINT_LEN_T(incoming_ctx->receive_buffer, size_t);

            if (incoming_ctx->nb_receive_buffer_bytes >= expected_length_of_length) {
                /* decode the expected length */
                (void)picoquic_frames_varint_decode(
                    incoming_ctx->receive_buffer, incoming_ctx->receive_buffer + expected_length_of_length, 
                    &incoming_ctx->padding_expected);
                break;
            }
        }
        incoming_ctx->receive_buffer[incoming_ctx->nb_receive_buffer_bytes] = bytes[processed];
        incoming_ctx->nb_receive_buffer_bytes++;
        processed++;
    }

    if (incoming_ctx->padding_expected != UINT64_MAX && processed < length) {
        if (incoming_ctx->padding_expected > incoming_ctx->padding_received) {
            size_t available = length - processed;
            if (available + incoming_ctx->padding_received > incoming_ctx->padding_expected) {
                available = (size_t)(incoming_ctx->padding_expected - incoming_ctx->padding_received);
            }
            incoming_ctx->padding_received += available;
            processed += available;
        }
    }

    if (incoming_ctx->padding_expected != UINT64_MAX &&
        incoming_ctx->padding_expected == incoming_ctx->padding_received && processed < length)
    {
        if (!incoming_ctx->is_receiving || processed + 1 < length) {
            /* Protocol error */
            picoquic_log_app_message(cnx, "Received %zu baton bytes on stream %" PRIu64 ", %zu expected",
                length, length - processed, 1);
            ret = wt_baton_close_session(cnx, baton_ctx, WT_BATON_SESSION_ERR_BRUH, "Too much data on stream!");
        }
        else if (incoming_ctx->is_receiving) {
            /* Done receiving, will pass the baton to the checker. But first, null
            * the current data. */
            incoming_ctx->baton_received = bytes[processed];
            processed++;
            incoming_ctx->is_receiving = 0;
            incoming_ctx->padding_expected = UINT64_MAX;
            incoming_ctx->padding_received = 0;
            incoming_ctx->nb_receive_buffer_bytes = 0;
        }
    }

    return ret;
}

int wt_baton_stream_data(picoquic_cnx_t* cnx,
    uint8_t* bytes, size_t length, int is_fin,
    struct st_h3zero_stream_ctx_t* stream_ctx,
    void* path_app_ctx)
{
    int ret = 0;

    wt_baton_ctx_t* baton_ctx = (wt_baton_ctx_t*)path_app_ctx;
    size_t receive_id = SIZE_MAX;
    size_t receive_available = SIZE_MAX;

    /* Special case of data or fin received on the control stream.
     * The control stream should only carry capsule data, and these are
     * processed directly at the web transport layer.
     */
    if (stream_ctx->stream_id == baton_ctx->control_stream_id) {
        ret = picowt_receive_capsule(cnx, stream_ctx, bytes, bytes + length, &baton_ctx->capsule, baton_ctx->h3_ctx);
        if (ret == 0 && is_fin) {
            stream_ctx->ps.stream_state.is_fin_received = 1;
            baton_ctx->baton_state = wt_baton_state_closed;
            if (baton_ctx->is_client) {
                ret = picoquic_close(cnx, 0);
            }
            else {
                h3zero_delete_stream_prefix(cnx, baton_ctx->h3_ctx, stream_ctx->stream_id);
            }
        }
    }
    else if (stream_ctx->ps.stream_state.control_stream_id == UINT64_MAX) {
        picoquic_log_app_message(cnx, "Received FIN after baton close on stream %" PRIu64, stream_ctx->stream_id);
    }
    else if (baton_ctx->baton_state != wt_baton_state_ready &&
        baton_ctx->baton_state != wt_baton_state_none &&
        baton_ctx->baton_state != wt_baton_state_sent && length > 0) {
        /* Unexpected data at this stage */
        picoquic_log_app_message(cnx, "Received baton data on stream %" PRIu64 ", when not ready",
            stream_ctx->stream_id);
        ret = wt_baton_close_session(cnx, baton_ctx, WT_BATON_SESSION_ERR_BRUH, "Too much data on stream!");
    }
    else {
        /* Associate the stream with one of the incoming contexts */
        for (size_t i = 0; i < baton_ctx->nb_lanes; i++) {
            if (baton_ctx->incoming[i].receiving_stream_id == stream_ctx->stream_id) {
                receive_id = i;
                break;
            }
            else if (!baton_ctx->incoming[i].is_receiving) {
                receive_available = i;
            }
        }

        if (receive_id == SIZE_MAX) {
            if (receive_available == SIZE_MAX) {
                /* unexpected incoming stream */
                picoquic_log_app_message(cnx, "Received baton data on wrong stream %" PRIu64 ", expected %" PRIu64,
                    stream_ctx->stream_id);
                ret = wt_baton_close_session(cnx, baton_ctx, WT_BATON_SESSION_ERR_BRUH, "Data on wrong stream!");
            }
            else {
                receive_id = receive_available;
                baton_ctx->incoming[receive_available].receiving_stream_id = stream_ctx->stream_id;
                baton_ctx->incoming[receive_available].is_receiving = 1;
                baton_ctx->incoming[receive_available].padding_expected = UINT64_MAX;
                baton_ctx->incoming[receive_available].padding_received = 0;
                baton_ctx->incoming[receive_available].nb_receive_buffer_bytes = 0;
            }
        }

        /* Process to receive the stream */
        if (ret == 0){
            wt_baton_incoming_t* incoming_ctx = &baton_ctx->incoming[receive_id];

            if (length > 0) {
                ret = wt_baton_incoming_data(cnx, baton_ctx, incoming_ctx, bytes, length);
            }
            /* process FIN, including doing the baton check */
            if (is_fin) {
                if (baton_ctx->baton_state != wt_baton_state_closed) {

                    if (incoming_ctx->is_receiving) {
                        if (IS_BIDIR_STREAM_ID(stream_ctx->stream_id) &&
                            IS_LOCAL_STREAM_ID(stream_ctx->stream_id, baton_ctx->is_client) &&
                            length == 0 &&
                            baton_ctx->count_fin_wait > 0){
                            baton_ctx->count_fin_wait--;
                        }
                        else {
                            picoquic_log_app_message(cnx, "Error: FIN before baton on data stream %" PRIu64 "\n",
                                stream_ctx->stream_id);
                            ret = wt_baton_close_session(cnx, baton_ctx, WT_BATON_SESSION_ERR_BRUH, "Fin stream before baton");
                        }
                    }
                    else if (ret == 0) {
                        ret = wt_baton_check(cnx, stream_ctx, baton_ctx, incoming_ctx->baton_received);
                    }
                }
                if (stream_ctx->ps.stream_state.is_fin_sent == 1 &&
                    (stream_ctx->ps.stream_state.is_fin_received || stream_ctx->stream_id != baton_ctx->control_stream_id)) {
                    h3zero_callback_ctx_t* h3_ctx = (h3zero_callback_ctx_t*)picoquic_get_callback_context(cnx);
                    picoquic_set_app_stream_ctx(cnx, stream_ctx->stream_id, NULL);
                    if (h3_ctx != NULL) {
                        h3zero_delete_stream(cnx, baton_ctx->h3_ctx, stream_ctx);
                    }
                }
            }
        }
    }
    
    return ret;
}

/* The provide data function assumes that the wt header has been sent already.
 */
 /* Process the FIN of a stream.
 */
int wt_baton_provide_data(picoquic_cnx_t* cnx,
    uint8_t* context, size_t space,
    struct st_h3zero_stream_ctx_t* stream_ctx,
    void* path_app_ctx)
{
    int ret = 0;
    size_t lane_id = SIZE_MAX;
    size_t empty_lane = SIZE_MAX;
    wt_baton_ctx_t* baton_ctx = (wt_baton_ctx_t*)path_app_ctx;

    /* Check whether there is already a lane assigned to that stream */
    for (size_t i = 0; i < baton_ctx->nb_lanes; i++) {
        if (baton_ctx->lanes[i].sending_stream_id == stream_ctx->stream_id) {
            lane_id = i;
            break;
        }
        if (baton_ctx->lanes[i].sending_stream_id == UINT64_MAX &&
            empty_lane == SIZE_MAX) {
            empty_lane = i;
            baton_ctx->lanes[i].baton_state = wt_baton_state_sending;
        }
    }

    if (lane_id == SIZE_MAX){
        if (empty_lane != SIZE_MAX) {
            lane_id = empty_lane;
            baton_ctx->lanes[lane_id].sending_stream_id = stream_ctx->stream_id;
        }
        else {
            picoquic_log_app_message(cnx, "Providing baton data on wrong stream %" PRIu64,
                stream_ctx->stream_id);
            ret = wt_baton_close_session(cnx, baton_ctx, WT_BATON_SESSION_ERR_BRUH, "Sending on wrong stream!");
        }
    }

    if (ret == 0 && baton_ctx->lanes[lane_id].baton_state == wt_baton_state_sending) {
        size_t useful = 0;
        size_t padding_length_length = 0;
        size_t pad_length;
        uint8_t* buffer;
        size_t consumed = 0;
        int more_to_send = 0;

        if (baton_ctx->lanes[lane_id].padding_required == UINT64_MAX) {
            if (baton_ctx->baton_state == wt_baton_state_done ||
                baton_ctx->nb_baton_bytes_sent > 0x10000) {
                baton_ctx->lanes[lane_id].padding_required = 0;
                padding_length_length = 1;
            }
            else if (space == 1) {
                baton_ctx->lanes[lane_id].padding_required = 0x3F;
                padding_length_length = 1;
            }
            else {
                baton_ctx->lanes[lane_id].padding_required = 0x3FFF;
                padding_length_length = 2;
            }
        }
        useful = padding_length_length + (size_t)(baton_ctx->lanes[lane_id].padding_required - 
            baton_ctx->lanes[lane_id].padding_sent) + 1;
        if (useful > space) {
            more_to_send = 1;
            useful = space;
            pad_length = space - padding_length_length;
        }
        else {
            pad_length = (size_t)(baton_ctx->lanes[lane_id].padding_required - baton_ctx->lanes[lane_id].padding_sent);
        }
        buffer = picoquic_provide_stream_data_buffer(context, useful, !more_to_send, more_to_send);
        if (padding_length_length > 0) {
            (void)picoquic_frames_varint_encode(buffer, buffer + padding_length_length,
                baton_ctx->lanes[lane_id].padding_required);
            consumed = padding_length_length;
        }
        if (pad_length > 0) {
            memset(buffer + consumed, 0, pad_length);
            consumed += pad_length;
            baton_ctx->lanes[lane_id].padding_sent += pad_length;
        }
        baton_ctx->nb_baton_bytes_sent += useful;

        if (baton_ctx->lanes[lane_id].baton_state == wt_baton_state_sending &&
            !more_to_send) {
            /* Everything was sent! */
            buffer[consumed] = baton_ctx->lanes[lane_id].baton;
            if (IS_BIDIR_STREAM_ID(stream_ctx->stream_id) &&
                IS_LOCAL_STREAM_ID(stream_ctx->stream_id, baton_ctx->is_client) &&
                baton_ctx->lanes[lane_id].baton == 0) {
                baton_ctx->count_fin_wait++;
            }
            baton_ctx->lanes[lane_id].baton_state = wt_baton_state_sent;
            stream_ctx->ps.stream_state.is_fin_sent = 1;
            if (stream_ctx->ps.stream_state.is_fin_received == 1) {
                h3zero_delete_stream(cnx, baton_ctx->h3_ctx, stream_ctx);
            }
        }
    }
    else {
        /* Not sending here! */
        (void)picoquic_provide_stream_data_buffer(context, 0, 0, 0);
    }

    return ret;
}

int wt_baton_ctx_path_params(wt_baton_ctx_t* baton_ctx, const uint8_t* path, size_t path_length)
{
    int ret = 0;
    size_t query_offset = h3zero_query_offset(path, path_length);
    if (query_offset < path_length) {
        const uint8_t* queries = path + query_offset;
        size_t queries_length = path_length - query_offset;

        if (h3zero_query_parameter_number(queries, queries_length, "version", 5, &baton_ctx->version, 0) != 0 ||
            h3zero_query_parameter_number(queries, queries_length, "baton", 5, &baton_ctx->initial_baton, 0) != 0 ||
            h3zero_query_parameter_number(queries, queries_length, "count", 5, &baton_ctx->nb_lanes, 1) != 0 ||
            h3zero_query_parameter_number(queries, queries_length, "inject", 6, &baton_ctx->inject_error, 0) != 0) {
            ret = -1;
        }
        else if ( baton_ctx->version != WT_BATON_VERSION ||
            baton_ctx->initial_baton > 255 ||
            baton_ctx->nb_lanes > WT_BATON_MAX_LANES||
            baton_ctx->nb_lanes < 1 ) {
            ret = -1;
        }
    }
    else {
        /* Set parameters to default values */
        baton_ctx->initial_baton = 240;
        baton_ctx->nb_lanes = 1;
    }

    return ret;
}

/* Accept an incoming connection */
int wt_baton_accept(picoquic_cnx_t* cnx,
    uint8_t* path, size_t path_length,
    struct st_h3zero_stream_ctx_t* stream_ctx,
    void* path_app_ctx)
{
    int ret = 0;
    wt_baton_app_ctx_t* app_ctx = (wt_baton_app_ctx_t*)path_app_ctx;
    h3zero_callback_ctx_t* h3_ctx = (h3zero_callback_ctx_t*)picoquic_get_callback_context(cnx);
    wt_baton_ctx_t* baton_ctx = (wt_baton_ctx_t*)malloc(sizeof(wt_baton_ctx_t));
    if (baton_ctx == NULL) {
        ret = -1;
    }
    else {
        /* register the incoming stream ID */
        ret = wt_baton_ctx_init(baton_ctx, h3_ctx, app_ctx, stream_ctx);

        /* init the global parameters */
        if (path != NULL && path_length > 0) {
            ret = wt_baton_ctx_path_params(baton_ctx, path, path_length);
        }

        if (ret == 0) {
            stream_ctx->ps.stream_state.is_web_transport = 1;
            stream_ctx->path_callback = wt_baton_callback;
            stream_ctx->path_callback_ctx = baton_ctx;
            baton_ctx->connection_ready = 1;
            if (baton_ctx->initial_baton == 0) {
                baton_ctx->initial_baton = (uint8_t)picoquic_public_uniform_random(32) + 128;
            }

            for (size_t lane_id = 0; ret == 0 && lane_id < baton_ctx->nb_lanes; lane_id++) {
                baton_ctx->lanes[lane_id].baton = (uint8_t)baton_ctx->initial_baton;
                baton_ctx->lanes[lane_id].first_baton = (uint8_t)baton_ctx->initial_baton;
                /* Get the relaying started */
                ret = wt_baton_relay(cnx, NULL, baton_ctx, lane_id);
            }
        }
    }
    return ret;
}

int wt_baton_stream_reset(picoquic_cnx_t* cnx, h3zero_stream_ctx_t* stream_ctx,
    void* path_app_ctx)
{
    int ret = 0;
    wt_baton_ctx_t* baton_ctx = (wt_baton_ctx_t*)path_app_ctx;

    picoquic_log_app_message(cnx, "Received reset on stream %" PRIu64 ", closing the session", stream_ctx->stream_id);

    if (baton_ctx != NULL) {
        ret = wt_baton_close_session(cnx, baton_ctx, WT_BATON_SESSION_ERR_GAME_OVER, NULL);

        /* Any reset results in the abandon of the context */
        baton_ctx->baton_state = wt_baton_state_closed;
        if (baton_ctx->is_client) {
            ret = picoquic_close(cnx, 0);
        }
        h3zero_delete_stream_prefix(cnx, baton_ctx->h3_ctx, baton_ctx->control_stream_id);
    }

    return ret;
}

void wt_baton_unlink_context(picoquic_cnx_t* cnx,
    h3zero_stream_ctx_t* control_stream_ctx,
    void* v_ctx)
{
    h3zero_callback_ctx_t* h3_ctx = (h3zero_callback_ctx_t*)picoquic_get_callback_context(cnx);
    wt_baton_ctx_t* baton_ctx = (wt_baton_ctx_t*)v_ctx;

    picowt_deregister(cnx, h3_ctx, control_stream_ctx);

    picowt_release_capsule(&baton_ctx->capsule);
    if (!cnx->client_mode) {
        free(baton_ctx);
    }
    else {
        baton_ctx->connection_closed = 1;
    }
}

/* Management of datagrams
 */
int wt_baton_receive_datagram(picoquic_cnx_t* cnx,
    const uint8_t* bytes, size_t length,
    struct st_h3zero_stream_ctx_t* stream_ctx,
    void* path_app_ctx)
{
    int ret = 0;
    wt_baton_ctx_t* baton_ctx = (wt_baton_ctx_t*)path_app_ctx;
    const uint8_t* bytes_max = bytes + length;
    uint64_t padding_length;
    uint8_t next_baton = 0;

    /* Parse the padding length  */
    if (stream_ctx != NULL && stream_ctx->stream_id != baton_ctx->control_stream_id) {
        /* error, unexpected datagram on this stream */
    }
    else if ((bytes = picoquic_frames_varint_decode(bytes, bytes_max, &padding_length)) != NULL &&
            (bytes = picoquic_frames_fixed_skip(bytes, bytes_max, padding_length)) != NULL &&
            (bytes = picoquic_frames_uint8_decode(bytes, bytes_max, &next_baton)) != NULL &&
            bytes == bytes_max){
        baton_ctx->baton_datagram_received = next_baton;
        baton_ctx->nb_datagrams_received += 1;
        baton_ctx->nb_datagram_bytes_received += length;
    }
    else {
        /* error, badly coded datagram */
    }
    return ret;
}

int wt_baton_provide_datagram(picoquic_cnx_t* cnx,
    void* context, size_t space,
    struct st_h3zero_stream_ctx_t* stream_ctx,
    void* path_app_ctx)
{
    int ret = 0;
    wt_baton_ctx_t* baton_ctx = (wt_baton_ctx_t*)path_app_ctx;

    if (baton_ctx->is_datagram_ready) {
        if (space > 1536) {
            space = 1536;
        }
        if (space < 3) {
            /* Not enough space to send anything */
        }
        else {
            uint8_t* buffer = h3zero_provide_datagram_buffer(context, space, 0);
            if (buffer == NULL) {
                ret = -1;
            }
            else {
                size_t padding_length = space - 3;
                uint8_t* bytes = buffer;
                *bytes++ = 0x40 | (uint8_t)((padding_length >> 8) & 0x3F);
                *bytes++ = (uint8_t)(padding_length & 0xFF);
                memset(bytes, 0, padding_length);
                bytes += padding_length;
                *bytes = baton_ctx->baton_datagram_send_next;
                baton_ctx->is_datagram_ready = 0;
                baton_ctx->baton_datagram_send_next = 0;
                baton_ctx->nb_datagrams_sent += 1;
                baton_ctx->nb_datagram_bytes_sent += space;
            }
        }
    }

    return ret;
}

/* Web transport/baton callback. This will be called from the web server
* when the path points to a web transport callback.
* Discuss: is the stream context needed? Should it be a wt_stream_context?
*/

int wt_baton_callback(picoquic_cnx_t* cnx,
    uint8_t* bytes, size_t length,
    picohttp_call_back_event_t wt_event,
    struct st_h3zero_stream_ctx_t* stream_ctx,
    void* path_app_ctx)
{
    int ret = 0;
    DBG_PRINTF("wt_baton_callback: %d, %" PRIi64 "\n", (int)wt_event, (stream_ctx == NULL)?(int64_t)-1:(int64_t)stream_ctx->stream_id);
    switch (wt_event) {
    case picohttp_callback_connecting:
        ret = wt_baton_connecting(cnx, stream_ctx, path_app_ctx);
        break;
    case picohttp_callback_connect:
        /* A connect has been received on this stream, and could be accepted.
        */
        /* The web transport should create a web transport connection context,
        * and also register the stream ID as identifying this context.
        * Then, callback the application. That means the WT app context
        * should be obtained from the path app context, etc.
        */
        ret = wt_baton_accept(cnx, bytes, length, stream_ctx, path_app_ctx);
        break;
    case picohttp_callback_connect_refused:
        /* The response from the server has arrived and it is negative. The 
        * application needs to close that stream.
        * Do we need an error code? Maybe pass as bytes + length.
        * Application should clean up the app context.
        */
        break;
    case picohttp_callback_connect_accepted: /* Connection request was accepted by peer */
        /* The response from the server has arrived and it is positive.
         * The application can start sending data.
         */
        if (stream_ctx != NULL) {
            stream_ctx->is_upgraded = 1;
        }
        break;

    case picohttp_callback_post_fin:
    case picohttp_callback_post_data:
        /* Data received on a stream for which the per-app stream context is known.
        * the app just has to process the data, and process the fin bit if present.
        */
        ret = wt_baton_stream_data(cnx, bytes, length, (wt_event == picohttp_callback_post_fin), stream_ctx, path_app_ctx);
        break; 
    case picohttp_callback_provide_data: /* Stack is ready to send chunk of response */
        /* We assume that the required stream headers have already been pushed,
        * and that the stream context is already set. Just send the data.
        */
        ret = wt_baton_provide_data(cnx, bytes, length, stream_ctx, path_app_ctx);
        break;
    case picohttp_callback_post_datagram:
        /* Data received on a stream for which the per-app stream context is known.
        * the app just has to process the data.
        */
        ret = wt_baton_receive_datagram(cnx, bytes, length, stream_ctx, path_app_ctx);
        break;
    case picohttp_callback_provide_datagram: /* Stack is ready to send a datagram */
        ret = wt_baton_provide_datagram(cnx, bytes, length, stream_ctx, path_app_ctx);
        break;
    case picohttp_callback_reset: /* Stream has been abandoned. */
        /* If control stream: abandon the whole connection. */
        ret = wt_baton_stream_reset(cnx, stream_ctx, path_app_ctx);
        break;
    case picohttp_callback_free: /* Used during clean up the stream. Only cause the freeing of memory. */
        /* Free the memory attached to the stream */
        break;
    case picohttp_callback_deregister:
        /* The app context has been removed from the registry.
         * Its references should be removed from streams belonging to this session.
         * On the client, the memory should be freed.
         */
        wt_baton_unlink_context(cnx, stream_ctx, path_app_ctx);
        break;
    default:
        /* protocol error */
        ret = -1;
        break;
    }
    return ret;
}

h3zero_stream_ctx_t* wt_baton_find_stream(wt_baton_ctx_t* baton_ctx, uint64_t stream_id)
{
    h3zero_stream_ctx_t* stream_ctx = h3zero_find_stream(baton_ctx->h3_ctx, stream_id);
    return stream_ctx;
}

/* Initialize the content of a wt_baton context.
* TODO: replace internal pointers by pointer to h3zero context
*/
int wt_baton_ctx_init(wt_baton_ctx_t* baton_ctx, h3zero_callback_ctx_t* h3_ctx, wt_baton_app_ctx_t * app_ctx, h3zero_stream_ctx_t* stream_ctx)
{
    int ret = 0;

    memset(baton_ctx, 0, sizeof(wt_baton_ctx_t));
    /* Init the stream tree */
    /* Do we use the path table for the client? or the web folder? */
    /* connection wide tracking of stream prefixes */
    if (h3_ctx == NULL) {
        ret = -1;
    }
    else {
        baton_ctx->h3_ctx = h3_ctx;

        /* Connection flags connection_ready and connection_closed are left
        * to zero by default. */
        /* init the baton protocol will be done in the "accept" call for server */

        if (stream_ctx != NULL) {
            /* Register the control stream and the stream id */
            baton_ctx->control_stream_id = stream_ctx->stream_id;
            stream_ctx->ps.stream_state.control_stream_id = stream_ctx->stream_id;
            ret = h3zero_declare_stream_prefix(baton_ctx->h3_ctx, stream_ctx->stream_id, wt_baton_callback, baton_ctx);
        }
        else {
            /* Poison the control stream ID field so errors can be detected. */
            baton_ctx->control_stream_id = UINT64_MAX;
        }
    }

    if (ret != 0) {
        /* Todo: undo init. */
    }
    return ret;
}

int wt_baton_process_remote_stream(picoquic_cnx_t* cnx,
    uint64_t stream_id, uint8_t* bytes, size_t length,
    picoquic_call_back_event_t fin_or_event,
    h3zero_stream_ctx_t* stream_ctx,
    wt_baton_ctx_t* baton_ctx)
{
    int ret = 0;

    if (stream_ctx == NULL) {
        stream_ctx = h3zero_find_or_create_stream(cnx, stream_id, baton_ctx->h3_ctx, 1, 1);
        picoquic_set_app_stream_ctx(cnx, stream_id, stream_ctx);
    }
    if (stream_ctx == NULL) {
        ret = -1;
    }
    else {
        uint8_t* bytes_max = bytes + length;

        bytes = h3zero_parse_incoming_remote_stream(bytes, bytes_max, stream_ctx, baton_ctx->h3_ctx);

        if (bytes == NULL) {
            picoquic_log_app_message(cnx, "Cannot parse incoming stream: %"PRIu64, stream_id);
            ret = -1;
        }
        else if (bytes < bytes_max) {
            ret = h3zero_post_data_or_fin(cnx, bytes, bytes_max - bytes, fin_or_event, stream_ctx);
        }
    }
    return ret;
}

/*
* wt_baton_prepare_context:
* Prepare the application context (baton_ctx), documenting the h3 context,
* and initializing the application. Should be called before calling
* picowt_connect.
*/

int wt_baton_prepare_context(picoquic_cnx_t* cnx, wt_baton_ctx_t* baton_ctx,
    h3zero_callback_ctx_t* h3_ctx, h3zero_stream_ctx_t* control_stream_ctx,
    const char* server_name, const char* path)
{
    int ret = 0;

    wt_baton_ctx_init(baton_ctx, h3_ctx, NULL, NULL);
    baton_ctx->cnx = cnx;
    baton_ctx->is_client = 1;
    baton_ctx->authority = server_name;
    baton_ctx->server_path = path;

    baton_ctx->connection_ready = 1;
    baton_ctx->is_client = 1;

    if (baton_ctx->server_path != NULL) {
        ret = wt_baton_ctx_path_params(baton_ctx, (const uint8_t*)baton_ctx->server_path,
            strlen(baton_ctx->server_path));
    }

    if (ret == 0) {
        wt_baton_set_receive_ready(baton_ctx);
    }

    return ret;
}
