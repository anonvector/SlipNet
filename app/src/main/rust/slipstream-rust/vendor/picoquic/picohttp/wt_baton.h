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

#ifndef WT_BATON_H
#define WT_BATON_H

#include "h3zero.h"
#include "h3zero_common.h"
#include "pico_webtransport.h"

#ifdef __cplusplus
extern "C" {
#endif
    /* error codes */
#define WT_BATON_STREAM_ERR_IDC 0x01 /* I don't care about this stream */
#define WT_BATON_STREAM_ERR_WHATEVER 0x02 /* The peer asked for this */
#define WT_BATON_STREAM_ERR_I_LIED 0x03 /* Spontaneous reset */

#define WT_BATON_SESSION_ERR_DA_YAMN 0x01 /* There is insufficient stream credit to continue the protocol */
#define WT_BATON_SESSION_ERR_BRUH 0x02 /* Received a malformed Baton message */
#define WT_BATON_SESSION_ERR_GAME_OVER 0x03 /* All baton streams have been reset */
#define WT_BATON_SESSION_ERR_BORED 0x04 /* Got tired of waiting for the next message */

#define WT_BATON_VERSION 0
#define WT_BATON_MAX_COUNT 256
#define WT_BATON_MAX_LANES 256

    /* Wt_baton context:
     *
     */
    typedef enum {
        wt_baton_state_none = 0,
        wt_baton_state_ready,
        wt_baton_state_sent,
        wt_baton_state_sending,
        wt_baton_state_done,
        wt_baton_state_error,
        wt_baton_state_closed,
        wt_baton_state_reset
    } wt_baton_state_enum;

    typedef struct st_wt_baton_lane_t {
        uint8_t baton;
        uint8_t first_baton;
        uint8_t baton_received;
        wt_baton_state_enum baton_state;
        int nb_turns;
        /* Stream management */
        uint64_t sending_stream_id; /* UINT64_MAX if unknown */
        uint64_t padding_required;  /* UINT64_MAX if unknown */
        uint64_t padding_sent;
    } wt_baton_lane_t;

    typedef struct st_wt_baton_incoming_t {
        int is_receiving;
        uint64_t receiving_stream_id; /* UINT64_MAX if unknown */
        uint64_t padding_expected;  /* UINT64_MAX if unknown */
        uint64_t padding_received; 
        uint8_t receive_buffer[8];
        uint8_t nb_receive_buffer_bytes;
        uint8_t baton_received;
    } wt_baton_incoming_t;

    typedef struct st_wt_baton_ctx_t {
        picoquic_cnx_t* cnx;
        h3zero_callback_ctx_t* h3_ctx;
        char const* authority;
        char const* server_path;
        uint64_t control_stream_id;
        /* Capsule state */
        picowt_capsule_t capsule;
        /* Connection state */
        int is_client;
        int connection_ready;
        int connection_closed;
        /* Baton protocol data */
        uint64_t version;
        uint64_t initial_baton;
        // uint64_t count;
        uint64_t nb_lanes;
        uint64_t lanes_completed;
        uint64_t count_fin_wait;
        uint64_t inject_error;
        int nb_turns;
        wt_baton_state_enum baton_state;
        wt_baton_lane_t lanes[256];
        wt_baton_incoming_t incoming[256];
        /* Datagram management */
        int nb_datagrams_received;
        size_t nb_datagram_bytes_received;
        uint8_t baton_datagram_received;
        int nb_datagrams_sent;
        size_t nb_datagram_bytes_sent;
        int is_datagram_ready;
        uint8_t baton_datagram_send_next;
        uint64_t nb_baton_bytes_received;
        uint64_t nb_baton_bytes_sent;
    } wt_baton_ctx_t;

    typedef struct st_wt_baton_app_ctx_t {
        int nb_turns_required;
    } wt_baton_app_ctx_t;

    int wt_baton_prepare_context(picoquic_cnx_t* cnx, wt_baton_ctx_t* baton_ctx,
        h3zero_callback_ctx_t* h3_ctx, h3zero_stream_ctx_t* control_stream_ctx,
        const char* server_name, const char* path);

    int wt_baton_ctx_path_params(wt_baton_ctx_t* baton_ctx, const uint8_t* path, size_t path_length);

    int wt_baton_accept(picoquic_cnx_t* cnx,
        uint8_t* bytes, size_t length,
        struct st_h3zero_stream_ctx_t* stream_ctx,
        void* path_app_ctx);

    h3zero_stream_ctx_t* wt_baton_create_stream(picoquic_cnx_t* cnx, int is_bidir, wt_baton_ctx_t* baton_ctx);
    h3zero_stream_ctx_t* wt_baton_find_stream(wt_baton_ctx_t* ctx, uint64_t stream_id);

    int wt_baton_ctx_init(wt_baton_ctx_t* baton_ctx, h3zero_callback_ctx_t* h3_ctx, wt_baton_app_ctx_t* app_ctx, h3zero_stream_ctx_t* stream_ctx);
    
    /* Web transport callback. This will be called from the web server
    * when the path points to a web transport callback
    */

    int wt_baton_callback(picoquic_cnx_t* cnx,
        uint8_t* bytes, size_t length,
        picohttp_call_back_event_t fin_or_event,
        struct st_h3zero_stream_ctx_t* stream_ctx,
        void* path_app_ctx);

#ifdef __cplusplus
}
#endif
#endif /* WT_BATON_H */