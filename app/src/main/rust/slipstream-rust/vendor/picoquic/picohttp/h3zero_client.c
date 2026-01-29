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
#include "picoquic_internal.h"
#include "h3zero.h"
#include "h3zero_common.h"

/*
 * H3Zero client. This is a simple client that conforms to HTTP 3.0,
 * but the client implementation is barebone.
 */

int h3zero_client_create_stream_request_ex(
    uint8_t * buffer, size_t max_bytes, uint8_t const * path, size_t path_len, const char * range, size_t range_len, uint64_t post_size, const char * host, size_t * consumed)
{
    int ret = 0;
    uint8_t * o_bytes = buffer;
    uint8_t * o_bytes_max = o_bytes + max_bytes;

    *consumed = 0;

    if (max_bytes < 3) {
        o_bytes = NULL;
    }
    else if (host == NULL) {
        o_bytes = NULL;
    }
    else {
        /* Create the request frame for the specified document */
        *o_bytes++ = h3zero_frame_header;
        o_bytes += 2; /* reserve two bytes for frame length */
        if (post_size == 0) {
            o_bytes = h3zero_create_request_header_frame_ex(o_bytes, o_bytes_max,
                (const uint8_t *)path, path_len, (const uint8_t *)range, range_len, host, H3ZERO_USER_AGENT_STRING);
        }
        else {
            o_bytes = h3zero_create_post_header_frame(o_bytes, o_bytes_max,
                (const uint8_t *)path, path_len, host, h3zero_content_type_text_plain);
        }
    }

    if (o_bytes == NULL) {
        ret = -1;
    }
    else {
        size_t header_length = o_bytes - &buffer[3];
        if (header_length < 64) {
            buffer[1] = (uint8_t)(header_length);
            memmove(&buffer[2], &buffer[3], header_length);
            o_bytes--;
        }
        else {
            buffer[1] = (uint8_t)((header_length >> 8) | 0x40);
            buffer[2] = (uint8_t)(header_length & 0xFF);
        }

        if (post_size > 0) {
            /* Add initial DATA frame for POST */
            size_t ll = 0;

            if (o_bytes < o_bytes_max) {
                *o_bytes++ = h3zero_frame_data;
                ll = picoquic_varint_encode(o_bytes, o_bytes_max - o_bytes, post_size);
                o_bytes += ll;
            }
            if (ll == 0) {
                ret = -1;
            }
            else {
                *consumed = o_bytes - buffer;
            }
        }
        else {
            *consumed = o_bytes - buffer;
        }
    }

    return ret;
}

int h3zero_client_create_stream_request(
    uint8_t* buffer, size_t max_bytes, uint8_t const* path, size_t path_len, uint64_t post_size, const char* host, size_t* consumed)
{
    return h3zero_client_create_stream_request_ex(buffer, max_bytes, path, path_len, NULL, 0, post_size, host, consumed);
}


