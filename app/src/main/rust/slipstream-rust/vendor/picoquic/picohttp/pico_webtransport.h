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

#ifndef pico_webtransport_H
#define pico_webtransport_H

#include "h3zero_common.h"

#ifdef __cplusplus
extern "C" {
#endif
    /* Capsule types defined for web transport */
#define picowt_capsule_close_webtransport_session 0x2843
#define picowt_capsule_drain_webtransport_session 0x78ae 

    /* Set required transport parameters for web transport  */
    void picowt_set_transport_parameters(picoquic_cnx_t* cnx);

    /* Create the control stream for the Web Transport session on the client. */
    h3zero_stream_ctx_t* picowt_set_control_stream(picoquic_cnx_t* cnx, h3zero_callback_ctx_t* h3_ctx);


    /*
    * picowt_prepare_client_cnx:
    * Prepare a QUIC connection and allocate the parameters required for
    * the web transport setup:
    * - p_cnx points to a quic connection context. If *p_cnx is null, a connection context
    *   will be created.
    * - p_h3_ctx points to an HTTP3 connection context. If *p_h3_ctx is null,
    *   an HTTP3 context will be created.
    * - p_control_stream_ctx should be NULL. On successfull return, it will
    *   point to the stream context for the "control stream" of
    *   the web transport connection.
     */
    int picowt_prepare_client_cnx(picoquic_quic_t* quic, struct sockaddr* server_address,
        picoquic_cnx_t** p_cnx, h3zero_callback_ctx_t** p_h3_ctx,
        h3zero_stream_ctx_t** p_stream_ctx,
        uint64_t current_time, const char* sni);

    /* Web transport initiate, client side
     * cnx: an established QUIC connection, set to ALPN=H3.
     * stream_ctx: the stream context returned by picowt_set_control_stream
     * wt_callback: callback function to use in the web transport connection.
     *              this is defined in h3zero_common.h
     * wt_ctx: application level context for that connection.
     */
    int picowt_connect(picoquic_cnx_t* cnx, h3zero_callback_ctx_t* ctx, h3zero_stream_ctx_t* stream_ctx, const char* authority, const char* path, picohttp_post_data_cb_fn wt_callback, void* wt_ctx);
    /* Send capsule to close web transport session,
     * and close web transport control stream.
     */
    int picowt_send_close_session_message(picoquic_cnx_t* cnx, h3zero_stream_ctx_t* control_stream_ctx, uint32_t picowt_err, const char* err_msg);
    /* Send drain capsule to tell the peer to finish and then close the session.
     */
    int picowt_send_drain_session_message(picoquic_cnx_t* cnx,
        h3zero_stream_ctx_t* control_stream_ctx);
    /* accumulate data for the web transport capsule in
     * specified context.
     */
    typedef struct st_picowt_capsule_t {
        h3zero_capsule_t h3_capsule;
        uint32_t error_code;
        const uint8_t* error_msg;
        size_t error_msg_len;
    } picowt_capsule_t;

    int picowt_receive_capsule(picoquic_cnx_t* cnx, h3zero_stream_ctx_t* stream_ctx, const uint8_t* bytes, const uint8_t* bytes_max, picowt_capsule_t* capsule, h3zero_callback_ctx_t* h3_ctx);
    void picowt_release_capsule(picowt_capsule_t* capsule);

    void picowt_deregister(picoquic_cnx_t* cnx, h3zero_callback_ctx_t* h3_ctx, h3zero_stream_ctx_t* control_stream_ctx);

    /**
    * Create local stream: when a stream is created locally. 
    * Send the stream header. Associate the stream with a per_stream
    * app context.
    */
    h3zero_stream_ctx_t* picowt_create_local_stream(picoquic_cnx_t* cnx, int is_bidir, h3zero_callback_ctx_t* h3_ctx,
        uint64_t control_stream_id);

#ifdef __cplusplus
}
#endif
#endif /* PICO_WEBTRANSPORT_H */