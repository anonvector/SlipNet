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
#include "tls_api.h"
#include "h3zero.h"
#include "h3zero_common.h"
#include "democlient.h"
#include "demoserver.h"
#ifdef _WINDOWS
#include "wincompat.h"
#include <direct.h>
#else
#include <sys/stat.h>
#include <sys/types.h>
#endif
#if 0
/* Include picotls.h in order to support tests of ESNI */
#include "picotls.h"
#include "tls_api.h"
#endif
#include "autoqlog.h"
#include "picoquic_binlog.h"
#include "pico_webtransport.h"

/* testing:
 * uint8_t * h3zero_varint_from_stream(uint8_t* bytes, uint8_t* bytes_max, uint64_t * result, uint8_t * buffer, size_t* buffer_length)
 *
 * start with a stream encoding, made of a set of bytes, encoding a number of varint puls some extra bytes.
 * the state is captured in a decoded varint vector of size N.
 * the vector is initialized to UINT64_MAX.
 * the logic:
 *   get the encoded buffer that contains the encoded value of the varints, as a string of bytes
 *   feed that buffer to the decoder in multiple ways:
 *    - all bytes at once,
 *    - one byte at a time,
 *    - two bytes at a time.
 *   The decoder itself will try to decode the next varint in the record, and consume bytes.
 *   if the varint value is not UINT64_MAX, go to the next one, etc.
 */

typedef struct st_h3zero_varint_stream_test_t {
    uint64_t v_int[4];
    uint64_t targets[4];
    size_t nb_targets;
    uint8_t buffer[16];
    size_t buffer_length;
    uint8_t bytes[64];
    size_t nb_bytes;
    size_t nb_processed;
} h3zero_varint_stream_test_t;

static int h3zero_varint_stream_test_init(h3zero_varint_stream_test_t * hvst, uint64_t * targets, size_t nb_targets)
{
    int ret = 0;
    uint8_t * bytes = hvst->bytes;
    uint8_t * bytes_max = bytes + sizeof(hvst->bytes);

    memset(hvst, 0, sizeof(h3zero_varint_stream_test_t));
    if (nb_targets > 4) {
        ret = -1;
    }
    else {
        hvst->nb_targets = nb_targets;
        for (size_t i = 0; i < nb_targets && i < 4; i++) {
            hvst->targets[i] = targets[i];
            hvst->v_int[i] = UINT64_MAX;
            bytes = picoquic_frames_varint_encode(bytes, bytes_max, targets[i]);
            if (bytes == NULL) {
                ret = -1;
                break;
            }
        }
        if (ret == 0) {
            hvst->nb_bytes = bytes - hvst->bytes;
        }
    }
    return ret;
}

int h3zero_varint_stream_chunk_test(uint64_t * targets, size_t nb_targets, size_t chunk_bytes)
{
    h3zero_varint_stream_test_t hvst;
    int ret = h3zero_varint_stream_test_init(&hvst, targets, nb_targets);
    size_t nb_not_64max = 0;
    size_t nb_chunks = 0;
    uint8_t* bytes = hvst.bytes;
    uint8_t* bytes_max = hvst.bytes + hvst.nb_bytes;
    uint8_t* chunk_start;
    uint8_t* chunk_end;

    while (ret == 0) {
        chunk_start = hvst.bytes + chunk_bytes * nb_chunks;
        chunk_end = chunk_start + chunk_bytes;
        if (chunk_start >= bytes_max) {
            /* nothing more to feed */
            break;
        }
        else if (chunk_end >= bytes_max) {
            chunk_end = bytes_max;
        }
        nb_chunks++;
        bytes = chunk_start;
        while (bytes != NULL && bytes < chunk_end) {
            bytes = h3zero_varint_from_stream(bytes, chunk_end, &hvst.v_int[nb_not_64max], hvst.buffer, &hvst.buffer_length);
            if (hvst.v_int[nb_not_64max] != UINT64_MAX) {
                nb_not_64max++;
                if (nb_not_64max >= nb_targets) {
                    break;
                }
                continue;
            }
        }
        if (nb_not_64max >= nb_targets) {
            break;
        }
    }
    if (nb_not_64max < nb_targets) {
        ret = -1;
    }
    else {
        for (size_t i = 0; ret == 0 && i < nb_targets; i++) {
            if (hvst.v_int[i] != targets[i]) {
                ret = -1;
                break;
            }
        }
    }
    return ret;
}

int h3zero_varint_stream_test()
{
    int ret = 0;
    uint64_t targets[4] = { 132, 4, 0x10001, 0x10000001 };

    for (size_t nb_targets = 1; ret == 0 && nb_targets <= 4; nb_targets++) {
        for (size_t j = 0; ret == 0 && j < 4; j++) {
            size_t chunk_bytes = (size_t)(1 << j);
            ret = h3zero_varint_stream_chunk_test(targets, nb_targets, chunk_bytes);
            if (ret == -1) {
                DBG_PRINTF("varint_stream test fails for chunks size= %zu, nb_target=%zu", chunk_bytes, nb_targets);
            }
        }
    }
    return ret;
}

/*
 * Test of
 *  uint8_t* h3zero_parse_remote_unidir_stream(
 *     uint8_t* bytes, uint8_t* bytes_max,
 *     h3zero_stream_ctx_t* stream_ctx,
 *     h3zero_callback_ctx_t* ctx,
 *     uint64_t * error_found)
 * 
 * uint8_t* h3zero_parse_incoming_remote_stream(
 *    uint8_t* bytes, uint8_t* bytes_max,
 *    h3zero_stream_ctx_t* stream_ctx,
 *    h3zero_callback_ctx_t* ctx)
 * 
 * The test requires that a valid context is defined:
 * 
 * h3zero_stream_ctx_t: incoming stream context.
 * 
 */

int incoming_unidir_test_fn(picoquic_cnx_t* cnx,
    uint8_t* bytes, size_t length,
    picohttp_call_back_event_t fin_or_event,
    struct st_h3zero_stream_ctx_t* stream_ctx,
    void* path_app_ctx)
{
    return 0;
}

int h3zero_incoming_unidir_test()
{
    picoquic_quic_t* quic = NULL;
    picoquic_cnx_t* cnx = NULL;
    int ret = picoquic_test_set_minimal_cnx(&quic, &cnx);
    uint64_t stream_id = 3;
    h3zero_stream_ctx_t* control_stream_ctx;
    h3zero_stream_ctx_t* stream_ctx = NULL;
    h3zero_callback_ctx_t* h3_ctx = NULL;
    uint8_t unidir_input[] = { 0x40, 0x54, 0x04, 0xf0 };

    if (ret == 0) {
        h3_ctx = h3zero_callback_create_context(NULL);
        if (h3_ctx == NULL) {
            ret = -1;
        }
        else {
            picoquic_set_callback(cnx, h3zero_callback, h3_ctx);
        }
    }

    if (ret == 0) {
        control_stream_ctx  = picowt_set_control_stream(cnx, h3_ctx);
        if (control_stream_ctx == NULL) {
            ret = -1;
        }
        else {
            unidir_input[2] = (uint8_t)control_stream_ctx->stream_id;
            /* Need to program a stream prefix that matches the connection */
            ret = h3zero_declare_stream_prefix(h3_ctx, control_stream_ctx->stream_id, incoming_unidir_test_fn, NULL);
        }
    }

    if (ret == 0) {
        stream_ctx = h3zero_find_or_create_stream(cnx, stream_id, h3_ctx, 1, 1);
        if (stream_ctx == NULL) {
            ret = -1;
        }
    }
    
    picoquic_set_app_stream_ctx(cnx, stream_id, stream_ctx);

    if (ret == 0) {
        int success = 0;

        for (size_t i = 0; ret == 0 && i < 4; i++) {
            uint8_t * bytes = &unidir_input[i];
            uint8_t * bytes_max = bytes + 1;
            bytes = h3zero_parse_incoming_remote_stream(bytes, bytes_max, stream_ctx, h3_ctx);
            if (bytes == bytes_max) {
                continue;
            }
            else if (bytes == NULL) {
                ret = -1;
            }
            else if (bytes != &unidir_input[3]) {
                ret = -1;
            }
            else {
                success = 1;
            }
        }
        if (!success) {
            ret = -1;
        }
    }
    picoquic_set_callback(cnx, NULL, NULL);
    h3zero_callback_delete_context(cnx, h3_ctx);
    picoquic_test_delete_minimal_cnx(&quic, &cnx);

    return ret;
}