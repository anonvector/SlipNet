/*
* Author: Christian Huitema
* Copyright (c) 2019, Private Octopus, Inc.
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

#ifndef DEMO_SERVER_H
#define DEMO_SERVER_H

#include "h3zero_common.h"

#ifdef __cplusplus
extern "C" {
#endif

/* This server code is provided for demonstration purposes.
 * The demo server serves a canned index page, or generate
 * variable length content in response to requests of the
 * form "GET /123456" (123456 bytes of data in that case.) 
 */

 /* Defining first the Http 3.0 variant of the server 
  */

#define PICOHTTP_FIRST_COMMAND_MAX 256
#define PICOHTTP_RESPONSE_MAX (1 << 20)

#define PICOHTTP_ALPN_H3_LATEST "h3-32"
#define PICOHTTP_ALPN_HQ_LATEST "hq-32"

/* Identify the path item based on the incoming path in GET or POST */

int picohttp_find_path_item(const uint8_t* path, size_t path_length, const picohttp_server_path_item_t* path_table, size_t path_table_nb);

/* Define value for default pages */

extern char const* h3zero_server_default_page;
extern char const* h3zero_server_post_response_page;

void h3zero_init_stream_tree(picosplay_tree_t* h3_stream_tree);
int h3zero_server_parse_path(const uint8_t* path, size_t path_length, uint64_t* echo_size,
    char** file_path, char const* web_folder, int* file_error);
int h3zero_server_prepare_to_send(void* context, size_t space, h3zero_stream_ctx_t* stream_ctx);

/* Defining then the Http 0.9 variant of the server
 */
#define picoquic_h09_server_callback_ctx_t h3zero_callback_ctx_t

int picoquic_h09_server_process_data_header(const uint8_t* bytes, size_t length, picoquic_call_back_event_t fin_or_event, h3zero_stream_ctx_t* stream_ctx, size_t* r_processed);

int picoquic_h09_server_callback(picoquic_cnx_t* cnx,
    uint64_t stream_id, uint8_t* bytes, size_t length,
    picoquic_call_back_event_t fin_or_event, void* callback_ctx, void* v_stream_ctx);


/* The generic server callback will call either http3 or http0.9,
 * according to the ALPN selected by the client
 */

int picoquic_demo_server_callback(picoquic_cnx_t* cnx,
    uint64_t stream_id, uint8_t* bytes, size_t length,
    picoquic_call_back_event_t fin_or_event, void* callback_ctx, void* v_stream_ctx);

size_t picoquic_demo_server_callback_select_alpn(picoquic_quic_t* quic, ptls_iovec_t* list, size_t count);

int demo_server_is_path_sane(const uint8_t* path, size_t path_length);

int demo_server_try_file_path(const uint8_t* path, size_t path_length, uint64_t* echo_size, 
    char ** file_path,char const* web_folder, int* file_error);

#ifdef __cplusplus
}
#endif

#endif /* DEMO_SERVER_H */