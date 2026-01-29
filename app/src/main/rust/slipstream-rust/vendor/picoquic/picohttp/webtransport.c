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

/*
 * Web Transport API implementation for Picoquic.
 * 
 * Expected usage:
 *  - quic server is multipurpose, serves H3 pages, posts, etc., in addition to web socket.
 *  - WT acting as client learns of a connection to the intended server. TBD: generic
 *    connection also used for something else, or specialized connection?
 *  - WT client issues CONNECT on connection, which creates a WT context.
 *  - Server side, WT responder is notified of connect, which creates a WT context.
 *  - Both client and server could open streams
 * 
 * Architecture:
 * 
 *    -- quic events generate picoquic callbacks.
 *    -- web transport state established when processing CONNECT
 *    -- web transport intercepts related callbacks:
 *        -- incoming unidir streams starting with specified frame
 *        -- incoming bidir streams starting with specified frame
 *        -- datagrams starting with specified ID
 *    -- mapping of picoquic callbacks to WT callbacks
 * 
 * 
 */

#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <picoquic.h>
#include "picoquic_utils.h"
#include "h3zero_common.h"
#include "pico_webtransport.h"

/* web transport set parameters
* Set the parameters adequate for web transport, including:
* - initial number of bidir and unidir streams to 63
* - initial max data per stream to 0x3FFF (16K -1)
* - datagram length to PICOQUIC_MAX_PACKET_SIZE
*/
static void picowt_set_transport_parameters_values(const picoquic_tp_t* tp_current, picoquic_tp_t* tp_new)
{
    if (tp_current != NULL) {
        memcpy(tp_new, tp_current, sizeof(picoquic_tp_t));
    }
    else {
        memset(tp_new, 0, sizeof(picoquic_tp_t));
    }
    if (tp_new->initial_max_data < 0x3FFF) {
        tp_new->initial_max_data = 0x3FFF;
    }
    if (tp_new->initial_max_stream_data_bidi_local < 0x3FFF) {
        tp_new->initial_max_stream_data_bidi_local = 0x3FFF;
    }
    if (tp_new->initial_max_stream_data_bidi_remote < 0x3FFF) {
        tp_new->initial_max_stream_data_bidi_remote = 0x3FFF;
    }
    if (tp_new->initial_max_stream_data_uni < 0x3FFF) {
        tp_new->initial_max_stream_data_uni = 0x3FFF;
    }
    if (tp_new->initial_max_stream_id_bidir < 0x3F) {
        tp_new->initial_max_stream_id_bidir = 0x3F;
    }
    if (tp_new->initial_max_stream_id_unidir < 0x3F) {
        tp_new->initial_max_stream_id_unidir = 0x3F;
    }
    if (tp_new->max_datagram_frame_size == 0) {
        tp_new->max_datagram_frame_size = PICOQUIC_MAX_PACKET_SIZE;
    }
}

void picowt_set_transport_parameters(picoquic_cnx_t* cnx)
{
    const picoquic_tp_t* tp_current = picoquic_get_transport_parameters(cnx, 1);
    picoquic_tp_t tp_new;
    picowt_set_transport_parameters_values(tp_current, &tp_new);
    picoquic_set_transport_parameters(cnx, &tp_new);
}

/* Web transport commands */


/**
* Create stream: when a stream is created locally. 
* Send the stream header. Associate the stream with a per_stream
* app context. mark the stream as active, per batn protocol.
*/
static h3zero_stream_ctx_t* picowt_create_stream_ctx(picoquic_cnx_t* cnx, int is_bidir, h3zero_callback_ctx_t* h3_ctx, 
    uint64_t control_stream_id)
{
    uint64_t stream_id = picoquic_get_next_local_stream_id(cnx, !is_bidir);
    h3zero_stream_ctx_t* stream_ctx = h3zero_find_or_create_stream(
        cnx, stream_id, h3_ctx, 1, 1);
    if (stream_ctx != NULL) {
        /* Associate the stream with a per_stream context */
        stream_ctx->ps.stream_state.stream_type = (is_bidir) ? h3zero_frame_webtransport_stream : h3zero_stream_type_webtransport;
        stream_ctx->ps.stream_state.control_stream_id = control_stream_id;
        if (picoquic_set_app_stream_ctx(cnx, stream_id, stream_ctx) != 0) {
            DBG_PRINTF("Could not set context for stream %"PRIu64, stream_id);
        }
    }
    return stream_ctx;
}

h3zero_stream_ctx_t* picowt_create_local_stream(picoquic_cnx_t* cnx, int is_bidir, h3zero_callback_ctx_t* h3_ctx,
    uint64_t control_stream_id)
{
    h3zero_stream_ctx_t* stream_ctx = picowt_create_stream_ctx(cnx, is_bidir, h3_ctx, control_stream_id);
    if (stream_ctx != NULL) {
        /* Write the first required bytes for sending the context ID */
        uint8_t stream_header[16];
        int ret;

        uint8_t* bytes = stream_header;
        bytes = picoquic_frames_varint_encode(bytes, stream_header + 16, 
            (is_bidir)?h3zero_frame_webtransport_stream:h3zero_stream_type_webtransport);
        bytes = picoquic_frames_varint_encode(bytes, stream_header + 16, control_stream_id);
        if ((ret = picoquic_add_to_stream_with_ctx(cnx, stream_ctx->stream_id, stream_header, bytes - stream_header, 0, stream_ctx)) != 0) {
            /* something went wrong */
            DBG_PRINTF("Could not add data for stream %"PRIu64 ", ret = %d", stream_ctx->stream_id, ret);
            h3zero_delete_stream(cnx, h3_ctx, stream_ctx);
            stream_ctx = NULL;
        }
    }
    return(stream_ctx);
}


/* Web transport initiate, client side. Start with two parameters:
* cnx: an established QUIC connection, set to ALPN=H3.
* h3_ctx: the http3 connection context.
* 
* The web transport connection is set in four phases:
* 
* 1- Create an h3zero stream context for the control stream, using
*    the API picowt_set_control_stream.
* 
* 2- Prepare the application state before the connection. This may
*    include documenting the control stream context.
* 
* 3- Call the picowt_connect API to prepare and queue the web transport
*    connect message. The API takes the following parameters:
* 
*      - cnx: QUIC connection context
*      - stream_ctx: the stream context returned by `picowt_set_control_stream`
*      - path: the path parameter for the connect request
*      - wt_callback: the path callback used for the application
*      - wt_ctx: the web transport application context associated with the path callback
* 
* 4- Make sure that the application is ready to process incoming streams.
*/

h3zero_stream_ctx_t* picowt_set_control_stream(picoquic_cnx_t* cnx, h3zero_callback_ctx_t* h3_ctx)
{
    uint64_t stream_id = picoquic_get_next_local_stream_id(cnx, 0);
    h3zero_stream_ctx_t* stream_ctx = h3zero_find_or_create_stream(
        cnx, stream_id, h3_ctx, 1, 1);
    if (stream_ctx != NULL) {
        /* Associate the stream with a per_stream context */
        if (picoquic_set_app_stream_ctx(cnx, stream_id, stream_ctx) != 0) {
            DBG_PRINTF("Could not set context for stream %"PRIu64, stream_id);
            h3zero_delete_stream(cnx, h3_ctx, stream_ctx);
            stream_ctx = NULL;
        }
    }
    return stream_ctx;
}

int picowt_prepare_client_cnx(picoquic_quic_t* quic, struct sockaddr* server_address,
    picoquic_cnx_t** p_cnx, h3zero_callback_ctx_t** p_h3_ctx,
    h3zero_stream_ctx_t** p_stream_ctx,
    uint64_t current_time, const char* sni)
{
    int ret = 0;


    /* use the generic H3 callback */
    /* Set the client callback context */
    if (*p_h3_ctx == NULL) {
        *p_h3_ctx = h3zero_callback_create_context(NULL);
    }
    if (*p_h3_ctx == NULL) {
        ret = 1;
    }
    else
    {
        /* Create a client connection */
        if (*p_cnx == NULL) {
            *p_cnx = picoquic_create_cnx(quic, picoquic_null_connection_id, picoquic_null_connection_id,
                (struct sockaddr*)server_address, current_time, 0, sni, "h3", 1);
        }
        if (*p_cnx == NULL) {
            fprintf(stderr, "Could not create connection context\n");
            ret = -1;
        }
        else {
            picowt_set_transport_parameters(*p_cnx);
            picoquic_set_callback(*p_cnx, h3zero_callback, *p_h3_ctx);
            *p_stream_ctx = picowt_set_control_stream(*p_cnx, *p_h3_ctx);

            if (*p_stream_ctx == NULL) {
                ret = -1;
            }
            else {
                /* Perform the initialization, settings and QPACK streams
                 */
                ret = h3zero_protocol_init(*p_cnx);
            }
        }
    }
    return ret;
}


/*
* Connect
*/

int picowt_connect(picoquic_cnx_t* cnx, h3zero_callback_ctx_t* ctx,  h3zero_stream_ctx_t* stream_ctx, 
    const char * authority, const char* path, picohttp_post_data_cb_fn wt_callback, void* wt_ctx)
{
    /* register the stream ID as session ID */
    int ret = h3zero_declare_stream_prefix(ctx, stream_ctx->stream_id, wt_callback, wt_ctx);
    if (cnx != NULL) {
        picoquic_log_app_message(cnx, "Allocated prefix for control stream %" PRIu64, stream_ctx->stream_id);
    }
    /* set the required stream parameters for the state of the stream. */
    stream_ctx->is_open = 1;
    stream_ctx->path_callback = wt_callback;
    stream_ctx->path_callback_ctx = wt_ctx;

    /* Declare the outgoing connection through the callback, so it can update its own state */
    ret = wt_callback(cnx, NULL, 0, picohttp_callback_connecting, stream_ctx, wt_ctx);

    if (ret == 0) {
        /* Format and send the connect frame. */
        uint8_t buffer[1024];
        uint8_t* bytes = buffer;
        uint8_t* bytes_max = bytes + 1024;

        *bytes++ = h3zero_frame_header;
        bytes += 2; /* reserve two bytes for frame length */

        bytes = h3zero_create_connect_header_frame(bytes, bytes_max, authority, (const uint8_t*)path, strlen(path), "webtransport", NULL,
            H3ZERO_USER_AGENT_STRING);

        if (bytes == NULL) {
            ret = -1;
        }
        else {
            /* Encode the header length */
            size_t header_length = bytes - &buffer[3];
            if (header_length < 64) {
                buffer[1] = (uint8_t)(header_length);
                memmove(&buffer[2], &buffer[3], header_length);
                bytes--;
            }
            else {
                buffer[1] = (uint8_t)((header_length >> 8) | 0x40);
                buffer[2] = (uint8_t)(header_length & 0xFF);
            }
            size_t connect_length = bytes - buffer;
            stream_ctx->ps.stream_state.is_upgrade_requested = 1;
            ret = picoquic_add_to_stream_with_ctx(cnx, stream_ctx->stream_id, buffer, connect_length,
                    0, stream_ctx);
        }

        if (ret != 0) {
            /* remove the stream prefix */
            h3zero_delete_stream_prefix(cnx, ctx, stream_ctx->stream_id);
        }
    }
    return ret;
}

/*
CLOSE_WEBTRANSPORT_SESSION Capsule {
    Type (i) = CLOSE_WEBTRANSPORT_SESSION,
    Length (i),
    Application Error Code (32),
    Application Error Message (..8192),
}
*/

int picowt_send_close_session_message(picoquic_cnx_t* cnx, 
    h3zero_stream_ctx_t* control_stream_ctx, 
    uint32_t picowt_err, const char* err_msg)
{
    uint8_t buffer[512];
    int ret = 0;
    /* Compute the length */
    size_t length = 4;
    size_t err_msg_len = 0;
    uint8_t* bytes;
    uint8_t* bytes_max = buffer + sizeof(buffer);

    if (control_stream_ctx->ps.stream_state.is_fin_sent) {
        /* cannot send! */
        ret = -1;
    }
    else {
        /* Compute the length */
        if (err_msg != NULL) {
            err_msg_len = strlen(err_msg);
        }
        length += err_msg_len;
        /* Encode the capsule */
        if ((bytes = picoquic_frames_varint_encode(buffer, bytes_max,
            picowt_capsule_close_webtransport_session)) != NULL &&
            (bytes = picoquic_frames_varint_encode(bytes, bytes_max, length)) != NULL &&
            (bytes = picoquic_frames_uint32_encode(bytes, bytes_max, picowt_err)) != NULL)
        {
            if (bytes + err_msg_len > bytes_max) {
                bytes = NULL;
            }
            else if (err_msg_len > 0) {
                memcpy(bytes, err_msg, err_msg_len);
                bytes += err_msg_len;
            }
        }
        if (bytes == NULL) {
            /* This might happen if the error message is too long */
            ret = -1;
        }
        else {
            /* Write the capsule*/
            ret = picoquic_add_to_stream(cnx, control_stream_ctx->stream_id, buffer, bytes - buffer, 1);
            control_stream_ctx->ps.stream_state.is_fin_sent = 1;
        }
    }
    return ret;
}

/*
DRAIN_WEBTRANSPORT_SESSION Capsule {
    Type (i) = DRAIN_WEBTRANSPORT_SESSION,
    Length (i) = 0
}
*/

int picowt_send_drain_session_message(picoquic_cnx_t* cnx, 
    h3zero_stream_ctx_t* control_stream_ctx)
{
    const uint8_t drain_capsule[] = {
        0x80, 0,
        (uint8_t)((picowt_capsule_drain_webtransport_session >> 8) & 0xff),
        (uint8_t)(picowt_capsule_drain_webtransport_session & 0xff),
        0
    };
    int ret = 0;
    if (control_stream_ctx->ps.stream_state.is_fin_sent) {
        /* cannot send! */
        ret = -1;
    }
    else {
        ret = picoquic_add_to_stream(cnx, control_stream_ctx->stream_id, drain_capsule, sizeof(drain_capsule), 0);
    }
    return ret;
}


/* Receive a WT capsule.
* With web transport, we expect three types of capsule:
* - Datagram, if datagram was not negotiated at the QUIC level,
* - Drain session,
* - Close session.
* 
*/
int picowt_receive_capsule(picoquic_cnx_t* cnx, h3zero_stream_ctx_t* stream_ctx, const uint8_t* bytes, const uint8_t* bytes_max, picowt_capsule_t * capsule, h3zero_callback_ctx_t* h3_ctx)
{
    int ret = 0; 
    
    while (ret == 0 && bytes < bytes_max) {
        const uint8_t* bytes_first = bytes;
        bytes = h3zero_accumulate_capsule(bytes, bytes_max, &capsule->h3_capsule);

        if (bytes == NULL) {
            picoquic_log_app_message(cnx, "Cannot parse %zu capsule bytes", bytes_max - bytes_first);
            ret = -1;
            break;
        }
        else{
            if (capsule->h3_capsule.is_stored) {
                switch (capsule->h3_capsule.capsule_type) {
                case h3zero_capsule_type_datagram:
                    h3zero_receive_datagram_capsule(cnx, stream_ctx, &capsule->h3_capsule, h3_ctx);
                    break;
                case picowt_capsule_drain_webtransport_session:
                case picowt_capsule_close_webtransport_session:
                    picoquic_log_app_message(cnx, "Received web transport session capsule, type: 0x%" PRIx64 " (%s)",
                        capsule->h3_capsule.capsule_type,
                        (capsule->h3_capsule.capsule_type == picowt_capsule_close_webtransport_session)?"close session":"drain session");
                    if (capsule->h3_capsule.capsule_length < 4) {
                        picoquic_log_app_message(cnx, "Web transport capsule too short, %zu bytes", capsule->h3_capsule.capsule_length);
                        ret = -1;
                    }
                    else {
                        capsule->error_msg = picoquic_frames_uint32_decode(
                            capsule->h3_capsule.capsule_buffer, capsule->h3_capsule.capsule_buffer + capsule->h3_capsule.capsule_length,
                            &capsule->error_code);
                        capsule->error_msg_len = capsule->h3_capsule.capsule_length - 4;
                    }
                    break;
                default:
                    picoquic_log_app_message(cnx, "Unexpected web transport capsule type: 0x%" PRIx64, capsule->h3_capsule.capsule_type);
                    ret = -1;
                    break;
                }
            }
        }
    }

    return ret;
}

void picowt_release_capsule(picowt_capsule_t* capsule)
{
    h3zero_release_capsule(&capsule->h3_capsule);
}

void picowt_deregister(picoquic_cnx_t* cnx,
    h3zero_callback_ctx_t* h3_ctx,
    h3zero_stream_ctx_t* control_stream_ctx)
{
    picosplay_node_t* previous = NULL;
    uint64_t control_stream_id = control_stream_ctx->stream_id;
    /* Free the streams created for this session */
    while (1) {
        picosplay_node_t* next = (previous == NULL) ? picosplay_first(&h3_ctx->h3_stream_tree) : picosplay_next(previous);
        if (next == NULL) {
            break;
        }
        else {
            h3zero_stream_ctx_t* stream_ctx =
                (h3zero_stream_ctx_t*)picohttp_stream_node_value(next);

            if (control_stream_id == stream_ctx->ps.stream_state.control_stream_id &&
                control_stream_id != stream_ctx->stream_id) {
                stream_ctx->ps.stream_state.control_stream_id = UINT64_MAX;
                stream_ctx->path_callback = NULL;
                stream_ctx->path_callback_ctx = NULL;
                h3zero_forget_stream(cnx, stream_ctx);
                picosplay_delete_hint(&h3_ctx->h3_stream_tree, next);
            }
            else {
                previous = next;
            }
        }
    }
    /* Then deregister the control stream */
    if (!control_stream_ctx->ps.stream_state.is_fin_sent) {
        picoquic_add_to_stream(cnx, control_stream_ctx->stream_id, NULL, 0, 1);
        control_stream_ctx->ps.stream_state.is_fin_sent = 1;
    }
    picoquic_unlink_app_stream_ctx(cnx, control_stream_ctx->stream_id);
    picoquic_log_app_message(cnx, "Prefix for control stream %"PRIu64 " was unregistered", control_stream_id);
}
