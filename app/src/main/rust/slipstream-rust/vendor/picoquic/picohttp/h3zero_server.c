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

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <picotls.h>
#include "picosplay.h"
#include "picoquic_internal.h"
#include "tls_api.h"
#include "h3zero.h"
#include "h3zero_common.h"
#include "democlient.h"

/*
 * Incoming data call back.
 * Create context if not yet present.
 * Create stream context if not yet present.
 * Different behavior for unidir and bidir.
 */
extern char const* h3zero_server_default_page;
extern char const* h3zero_server_post_response_page;

/* Sanity check of path name to prevent directory traversal.
 * We use a simple command that check for file names mae of alpha,
 * num, hyphens and underlines, plus non repeated dots */
int demo_server_is_path_sane(const uint8_t* path, size_t path_length)
{
    int ret = 0;
    size_t i = 0;
    int past_is_dot = 0;
    int nb_good = 0;

    if (path[0] == '/') {
        i++;
    }
    else {
        ret = -1;
    }

    for (; ret == 0 && i < path_length; i++) {
        int c = path[i];
        if ((c >= 'a' && c <= 'z') ||
            (c >= 'A' && c <= 'Z') ||
            (c >= '0' && c <= '9') ||
            c == '-' || c == '_') {
            nb_good++;
            past_is_dot = 0;
        }
        else if (c == '/' && i < path_length - 1 && nb_good > 0) {
            nb_good++;
        }
        else if (c == '.' && !past_is_dot && nb_good > 0){
            past_is_dot = 1;
        }
        else {
            ret = -1;
        }
    }

    if (ret == 0 && nb_good == 0) {
        ret = -1;
    }

    return ret;
}

int demo_server_try_file_path(const uint8_t* path, size_t path_length, uint64_t* echo_size,
    char** file_path, char const* web_folder, int * file_error)
{
    int ret = -1;
    size_t len = strlen(web_folder);
    size_t file_name_len = len + path_length + 1;
    char* file_name = malloc(file_name_len);
    FILE* F;

    if (file_name != NULL && demo_server_is_path_sane(path, path_length) == 0) {
        memcpy(file_name, web_folder, len);
#ifdef _WINDOWS
        if (len == 0 || file_name[len - 1] != '\\') {
            file_name[len] = '\\';
            len++;
        }
#else
        if (len == 0 || file_name[len - 1] != '/') {
            file_name[len] = '/';
            len++;
        }
#endif
        memcpy(file_name + len, path+1, path_length-1);
        len += path_length - 1;
        file_name[len] = 0;

        F = picoquic_file_open_ex(file_name, "rb", file_error);

        if (F != NULL) {
            long sz;
            fseek(F, 0, SEEK_END);
            sz = ftell(F);

            if (sz > 0) {
                *echo_size = (size_t)sz;
                fseek(F, 0, SEEK_SET);
                ret = 0;
                *file_path = file_name;
            }
            picoquic_file_close(F);
        }
    }

    if (ret != 0 && file_name != NULL){
        free(file_name);
    }

    return ret;
}

int h3zero_server_parse_path(const uint8_t * path, size_t path_length, uint64_t * echo_size, 
    char ** file_path, char const * web_folder, int * file_error)
{
    int ret = 0;

    *file_error = 0;

    if (path != NULL && path_length == 1 && path[0] == '/') {
        /* Redirect the root requests to the default index so it can be read from file if file is present */
        path = (const uint8_t *)"/index.html";
        path_length = 11;
    }

    *echo_size = 0;
    if (path == NULL || path_length == 0 || path[0] != '/') {
        ret = -1;
    }
    else if (web_folder != NULL && demo_server_try_file_path(path, path_length, echo_size,
        file_path, web_folder, file_error) == 0) {
        ret = 0;
    }
    else if (path_length > 1 && (path_length != 11 || memcmp(path, "/index.html", 11) != 0)) {
        uint64_t x = 0;
        for (size_t i = 1; i < path_length; i++) {
            if (path[i] < '0' || path[i] > '9') {
                ret = -1;
                break;
            }
            x *= 10;
            x += path[i] - '0';
            if (x > (UINT64_MAX >> 2)) {
                /* required length is more than 62 bits */
                ret = -1;
                break;
            }
        }

        if (ret == 0) {
            *echo_size = x;
        }
    }

    return ret;
}

/* Prepare to send. This is the same code as on the client side, except for the
 * delayed opening of the data file */
int h3zero_server_prepare_to_send(void* context, size_t space, h3zero_stream_ctx_t* stream_ctx)
{
    int ret = 0;

    if (stream_ctx->F == NULL && stream_ctx->file_path != NULL) {
        stream_ctx->F = picoquic_file_open(stream_ctx->file_path, "rb");
        if (stream_ctx->F == NULL) {
            ret = -1;
        }
    }

    if (ret == 0) {
        ret = h3zero_prepare_and_send_data(context, space, stream_ctx->echo_length, &stream_ctx->echo_sent,
            stream_ctx->F);
    }

    return ret;
}

/* TODO:
 * - Establish processing of CONNECT
 * 
 * Server side logic:
 * - State = h3_receive_header: accumulate bytes until header is fully received.
 *         when header is received, process it.
 *         if CONNECT, may receive a connect data frame instead.
 * - State = h3_receive_data:
 *         receive incoming data after the header.
 *         expect data frames. pass content of data frames to application.
 *         generate an error if data is not expected (GET, CONNECT-control, server side).
 * - State = h3_received_fin:
 *         end of receiving data.
 *         for POST: finalize the response
 *         for CONNECT: close the context.
 */

int picohttp_find_path_item(const uint8_t * path, size_t path_length, const picohttp_server_path_item_t * path_table, size_t path_table_nb)
{
    size_t i = 0;

    while (i < path_table_nb) {
        if (path_length >= path_table[i].path_length && memcmp(path, path_table[i].path, path_table[i].path_length) == 0){
            return (int)i;
        }
        i++;
    }
    return -1;
}

