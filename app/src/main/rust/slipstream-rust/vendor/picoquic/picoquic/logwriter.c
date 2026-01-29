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

/*
* Packet logging.
*/

#include <stdarg.h>
#include "picoquic_binlog.h"
#include "bytestream.h"
#include "tls_api.h"
#include "picotls.h"
#include "picoquic_unified_log.h"
#include "picoquic_binlog.h"

static const uint8_t* picoquic_log_fixed_skip(const uint8_t* bytes, const uint8_t* bytes_max, size_t size)
{
    return bytes == NULL ? NULL : ((bytes += size) <= bytes_max ? bytes : NULL);
}

static const uint8_t* picoquic_log_varint_skip(const uint8_t* bytes, const uint8_t* bytes_max)
{
    return bytes == NULL ? NULL : (bytes < bytes_max ? picoquic_log_fixed_skip(bytes, bytes_max, VARINT_LEN_T(bytes, size_t)) : NULL);
}

static const uint8_t* picoquic_log_varint(const uint8_t* bytes, const uint8_t* bytes_max, uint64_t* n64)
{
    size_t len = (bytes == NULL) ? 0 : picoquic_varint_decode(bytes, bytes_max - bytes, n64);
    return len == 0 ? NULL : bytes + len;
}

static const uint8_t* picoquic_log_length(const uint8_t* bytes, const uint8_t* bytes_max, size_t* nsz)
{
    uint64_t n64 = 0;
    size_t len = 0;
    if (bytes != NULL) {
        len = picoquic_varint_decode(bytes, bytes_max - bytes, &n64);
    }
    *nsz = (size_t)n64;
    return (len == 0 || *nsz != n64) ? NULL : bytes + len;
}

static void picoquic_binlog_frame(FILE* f, const uint8_t* bytes, const uint8_t* bytes_max)
{
    if (bytes != NULL && bytes_max != NULL) {
        size_t len = bytes_max - bytes;
        uint8_t varlen[8];
        size_t l_varlen = picoquic_varint_encode(varlen, 8, len);
        fwrite(varlen, 1, l_varlen, f);
        fwrite(bytes, 1, len, f);
    }
}

static const uint8_t* picoquic_log_stream_frame(FILE* f, const uint8_t* bytes, const uint8_t* bytes_max)
{
    const uint8_t* bytes_begin = bytes;
    uint8_t ftype = bytes[0];
    size_t length = 0;
    uint8_t log_buffer[256];
    int has_length = 0;
    size_t extra_bytes = 8;

    bytes = picoquic_log_fixed_skip(bytes, bytes_max, 1); /* type */
    bytes = picoquic_log_varint_skip(bytes, bytes_max); /* stream */

    if ((ftype & 4) != 0) {
        bytes = picoquic_log_varint_skip(bytes, bytes_max); /* offset */
    }

    if (bytes != NULL) {
        if ((ftype & 2) != 0) {
            bytes = picoquic_log_length(bytes, bytes_max, &length); /* length */
            has_length = 1;
        }
        else {
            length = bytes_max - bytes;
        }
    }

    if (bytes != NULL) {
        if (length < extra_bytes) {
            /* Add up to 8 bytes of content that can be documented in the qlog */
            extra_bytes = length;
        }
        if (has_length) {
            picoquic_binlog_frame(f, bytes_begin, bytes + extra_bytes);
        }
        else {
            uint8_t* log_next = log_buffer;
            size_t l_head = bytes - bytes_begin;

            memcpy(log_buffer, bytes_begin, l_head);
            log_next += l_head;
            if ((log_next = picoquic_frames_varint_encode(log_next, log_buffer + 256, length)) != NULL) {
                memcpy(log_next, bytes, extra_bytes);
                log_next += extra_bytes;
                picoquic_binlog_frame(f, log_buffer, log_next);
            }
            else {
                picoquic_binlog_frame(f, log_buffer, log_buffer + l_head);
            }
        }

        bytes = picoquic_log_fixed_skip(bytes, bytes_max, length);
    }
    else {
        /* Cautiously log the beginning of the erroneous frame */
        length = bytes_max - bytes_begin;
        if (length > 26) {
            length = 26;
        }
        picoquic_binlog_frame(f, bytes_begin, bytes_begin + length);
    }
    return bytes;
}

static const uint8_t* picoquic_log_ack_frame(FILE* f, const uint8_t* bytes, const uint8_t* bytes_max)
{
    const uint8_t* bytes_begin = bytes;
    uint64_t ftype = 0;
    uint64_t nb_blocks;

    (void) picoquic_varint_decode(bytes, bytes_max - bytes, &ftype);

    bytes = picoquic_log_varint_skip(bytes, bytes_max); /* Logging the frame type, maybe multiple bytes */

    if (ftype == picoquic_frame_type_path_ack || ftype == picoquic_frame_type_path_ack_ecn) {
        bytes = picoquic_log_varint_skip(bytes, bytes_max); /* Log the path_id */
    }

    bytes = picoquic_log_varint_skip(bytes, bytes_max);
    bytes = picoquic_log_varint_skip(bytes, bytes_max);
    bytes = picoquic_log_varint(bytes, bytes_max, &nb_blocks);

    for (uint64_t i = 0; bytes != NULL && i <= nb_blocks; i++) {
        if (i != 0) {
            bytes = picoquic_log_varint_skip(bytes, bytes_max);
        }
        bytes = picoquic_log_varint_skip(bytes, bytes_max);
    }
    
    if (ftype == picoquic_frame_type_ack_ecn || ftype == picoquic_frame_type_path_ack_ecn) {
        bytes = picoquic_log_varint_skip(bytes, bytes_max);
        bytes = picoquic_log_varint_skip(bytes, bytes_max);
        bytes = picoquic_log_varint_skip(bytes, bytes_max);
    }

    picoquic_binlog_frame(f, bytes_begin, bytes);
    return bytes;
}

static const uint8_t* picoquic_log_reset_stream_frame(FILE* f, const uint8_t* bytes, const uint8_t* bytes_max)
{
    const uint8_t * bytes_begin = bytes;

    bytes = picoquic_log_fixed_skip(bytes, bytes_max, 1);
    bytes = picoquic_log_varint_skip(bytes, bytes_max);
    bytes = picoquic_log_varint_skip(bytes, bytes_max);
    bytes = picoquic_log_varint_skip(bytes, bytes_max);

    picoquic_binlog_frame(f, bytes_begin, bytes);
    return bytes;
}

static const uint8_t* picoquic_log_stop_sending_frame(FILE* f, const uint8_t* bytes, const uint8_t* bytes_max)
{
    const uint8_t* bytes_begin = bytes;

    bytes = picoquic_log_fixed_skip(bytes, bytes_max, 1);
    bytes = picoquic_log_varint_skip(bytes, bytes_max);
    bytes = picoquic_log_varint_skip(bytes, bytes_max);

    picoquic_binlog_frame(f, bytes_begin, bytes);
    return bytes;
}

static const uint8_t* picoquic_log_close_frame(FILE* f, const uint8_t* bytes, const uint8_t* bytes_max)
{
    const uint8_t* bytes_begin = bytes;
    size_t length = 0;

    bytes = picoquic_log_fixed_skip(bytes, bytes_max, 1);
    bytes = picoquic_log_varint_skip(bytes, bytes_max);
    bytes = picoquic_log_varint_skip(bytes, bytes_max);
    bytes = picoquic_log_length(bytes, bytes_max, &length);
    bytes = picoquic_log_fixed_skip(bytes, bytes_max, length);

    picoquic_binlog_frame(f, bytes_begin, bytes);
    return bytes;
}

static const uint8_t* picoquic_log_app_close_frame(FILE* f, const uint8_t* bytes, const uint8_t* bytes_max)
{
    const uint8_t* bytes_begin = bytes;
    size_t length = 0;

    bytes = picoquic_log_fixed_skip(bytes, bytes_max, 1);
    bytes = picoquic_log_varint_skip(bytes, bytes_max);
    bytes = picoquic_log_length(bytes, bytes_max, &length);
    bytes = picoquic_log_fixed_skip(bytes, bytes_max, length);

    picoquic_binlog_frame(f, bytes_begin, bytes);
    return bytes;
}

static const uint8_t* picoquic_log_max_data_frame(FILE* f, const uint8_t* bytes, const uint8_t* bytes_max)
{
    const uint8_t* bytes_begin = bytes;

    bytes = picoquic_log_fixed_skip(bytes, bytes_max, 1);
    bytes = picoquic_log_varint_skip(bytes, bytes_max);

    picoquic_binlog_frame(f, bytes_begin, bytes);
    return bytes;
}

static const uint8_t* picoquic_log_max_stream_data_frame(FILE* f, const uint8_t* bytes, const uint8_t* bytes_max)
{
    const uint8_t* bytes_begin = bytes;

    bytes = picoquic_log_fixed_skip(bytes, bytes_max, 1);
    bytes = picoquic_log_varint_skip(bytes, bytes_max);
    bytes = picoquic_log_varint_skip(bytes, bytes_max);

    picoquic_binlog_frame(f, bytes_begin, bytes);
    return bytes;
}

static const uint8_t* picoquic_log_max_stream_id_frame(FILE* f, const uint8_t* bytes, const uint8_t* bytes_max)
{
    const uint8_t* bytes_begin = bytes;

    bytes = picoquic_log_fixed_skip(bytes, bytes_max, 1);
    bytes = picoquic_log_varint_skip(bytes, bytes_max);

    picoquic_binlog_frame(f, bytes_begin, bytes);
    return bytes;
}

static const uint8_t* picoquic_log_blocked_frame(FILE* f, const uint8_t* bytes, const uint8_t* bytes_max)
{
    const uint8_t* bytes_begin = bytes;

    bytes = picoquic_log_fixed_skip(bytes, bytes_max, 1);
    bytes = picoquic_log_varint_skip(bytes, bytes_max);

    picoquic_binlog_frame(f, bytes_begin, bytes);
    return bytes;
}

static const uint8_t* picoquic_log_stream_blocked_frame(FILE* f, const uint8_t* bytes, const uint8_t* bytes_max)
{
    const uint8_t* bytes_begin = bytes;

    bytes = picoquic_log_fixed_skip(bytes, bytes_max, 1);
    bytes = picoquic_log_varint_skip(bytes, bytes_max);
    bytes = picoquic_log_varint_skip(bytes, bytes_max);

    picoquic_binlog_frame(f, bytes_begin, bytes);
    return bytes;
}

static const uint8_t* picoquic_log_streams_blocked_frame(FILE* f, const uint8_t* bytes, const uint8_t* bytes_max)
{
    const uint8_t* bytes_begin = bytes;

    bytes = picoquic_log_fixed_skip(bytes, bytes_max, 1);
    bytes = picoquic_log_varint_skip(bytes, bytes_max);

    picoquic_binlog_frame(f, bytes_begin, bytes);
    return bytes;
}

static const uint8_t* picoquic_log_new_connection_id_frame(FILE* f, const uint8_t* bytes, const uint8_t* bytes_max)
{
    const uint8_t* bytes_begin = bytes;

    bytes = picoquic_log_fixed_skip(bytes, bytes_max, 1);
    bytes = picoquic_log_varint_skip(bytes, bytes_max);
    bytes = picoquic_log_varint_skip(bytes, bytes_max);
    if (bytes != NULL) {
        bytes = picoquic_log_fixed_skip(bytes, bytes_max, ((size_t)1) + bytes[0]);
    }

    bytes = picoquic_log_fixed_skip(bytes, bytes_max, PICOQUIC_RESET_SECRET_SIZE);

    picoquic_binlog_frame(f, bytes_begin, bytes);
    return bytes;
}

static const uint8_t* picoquic_log_path_new_connection_id_frame(FILE* f, const uint8_t* bytes, const uint8_t* bytes_max)
{
    const uint8_t* bytes_begin = bytes;

    bytes = picoquic_log_varint_skip(bytes, bytes_max);
    bytes = picoquic_log_varint_skip(bytes, bytes_max);
    bytes = picoquic_log_varint_skip(bytes, bytes_max);
    bytes = picoquic_log_varint_skip(bytes, bytes_max);
    if (bytes != NULL) {
        bytes = picoquic_log_fixed_skip(bytes, bytes_max, ((size_t)1) + bytes[0]);
    }

    bytes = picoquic_log_fixed_skip(bytes, bytes_max, PICOQUIC_RESET_SECRET_SIZE);

    picoquic_binlog_frame(f, bytes_begin, bytes);
    return bytes;
}

static const uint8_t* picoquic_log_retire_connection_id_frame(FILE* f, const uint8_t* bytes, const uint8_t* bytes_max)
{
    const uint8_t* bytes_begin = bytes;

    bytes = picoquic_log_fixed_skip(bytes, bytes_max, 1);
    bytes = picoquic_log_varint_skip(bytes, bytes_max);

    picoquic_binlog_frame(f, bytes_begin, bytes);
    return bytes;
}

static const uint8_t* picoquic_log_path_retire_connection_id_frame(FILE* f, const uint8_t* bytes, const uint8_t* bytes_max)
{
    const uint8_t* bytes_begin = bytes;

    bytes = picoquic_log_varint_skip(bytes, bytes_max);
    bytes = picoquic_log_varint_skip(bytes, bytes_max);
    bytes = picoquic_log_varint_skip(bytes, bytes_max);

    picoquic_binlog_frame(f, bytes_begin, bytes);
    return bytes;
}

static const uint8_t* picoquic_log_new_token_frame(FILE* f, const uint8_t* bytes, const uint8_t* bytes_max)
{
    const uint8_t* bytes_begin = bytes;
    size_t length = 0;

    bytes = picoquic_log_fixed_skip(bytes, bytes_max, 1);
    bytes = picoquic_log_length(bytes, bytes_max, &length);

    bytes = picoquic_log_fixed_skip(bytes, bytes_max, length);

    picoquic_binlog_frame(f, bytes_begin, bytes);
    return bytes;
}

static const uint8_t* picoquic_log_path_frame(FILE* f, const uint8_t* bytes, const uint8_t* bytes_max)
{
    const uint8_t* bytes_begin = bytes;

    bytes = picoquic_log_fixed_skip(bytes, bytes_max, 1 + 8);

    picoquic_binlog_frame(f, bytes_begin, bytes);
    return bytes;
}

static const uint8_t* picoquic_log_crypto_hs_frame(FILE* f, const uint8_t* bytes, const uint8_t* bytes_max)
{
    const uint8_t* bytes_begin = bytes;
    size_t length = 0;

    bytes = picoquic_log_fixed_skip(bytes, bytes_max, 1);
    bytes = picoquic_log_varint_skip(bytes, bytes_max);
    bytes = picoquic_log_length(bytes, bytes_max, &length);

    picoquic_binlog_frame(f, bytes_begin, bytes);

    bytes = picoquic_log_fixed_skip(bytes, bytes_max, length);
    return bytes;
}


static const uint8_t* picoquic_log_handshake_done_frame(FILE* f, const uint8_t* bytes, const uint8_t* bytes_max)
{
    const uint8_t* bytes_begin = bytes;

    bytes = picoquic_log_fixed_skip(bytes, bytes_max, 1);

    picoquic_binlog_frame(f, bytes_begin, bytes);
    return bytes;
}

static const uint8_t* picoquic_log_datagram_frame(FILE* f, const uint8_t* bytes, const uint8_t* bytes_max)
{
    const uint8_t* bytes_begin = bytes;
    uint8_t ftype = bytes[0];
    size_t length = 0;

    bytes = picoquic_log_fixed_skip(bytes, bytes_max, 1);

    if (ftype & 1) {
        bytes = picoquic_log_length(bytes, bytes_max, &length);
    } else {
        length = bytes_max - bytes;
    }

    picoquic_binlog_frame(f, bytes_begin, bytes);

    bytes = picoquic_log_fixed_skip(bytes, bytes_max, length);
    return bytes;
}

static const uint8_t* picoquic_log_time_stamp_frame(FILE* f, const uint8_t* bytes, const uint8_t* bytes_max)
{
    const uint8_t* bytes_begin = bytes;

    bytes = picoquic_log_varint_skip(bytes, bytes_max); /* frame type as varint */
    bytes = picoquic_log_varint_skip(bytes, bytes_max); /* time stamp as varint */

    picoquic_binlog_frame(f, bytes_begin, bytes);

    return bytes;
}

static const uint8_t* picoquic_log_path_abandon_frame(FILE* f, const uint8_t* bytes, const uint8_t* bytes_max)
{
    const uint8_t* bytes_begin = bytes;
    bytes = picoquic_log_varint_skip(bytes, bytes_max); /* frame type as varint */
    bytes = picoquic_skip_path_abandon_frame(bytes, bytes_max); /* skip abandon frame */
    picoquic_binlog_frame(f, bytes_begin, bytes);

    return bytes;
}

static const uint8_t* picoquic_log_path_available_or_backup_frame(FILE* f, const uint8_t* bytes, const uint8_t* bytes_max)
{
    const uint8_t* bytes_begin = bytes;
    bytes = picoquic_log_varint_skip(bytes, bytes_max); /* frame type as varint */
    bytes = picoquic_skip_path_available_or_standby_frame(bytes, bytes_max); /* skip available or standby frame */
    picoquic_binlog_frame(f, bytes_begin, bytes);

    return bytes;
}


static const uint8_t* picoquic_log_ack_frequency_frame(FILE* f, const uint8_t* bytes, const uint8_t* bytes_max)
{
    const uint8_t* bytes_begin = bytes;

    bytes = picoquic_log_varint_skip(bytes, bytes_max); /* frame type as varint */
    bytes = picoquic_log_varint_skip(bytes, bytes_max); /* Seq num */
    bytes = picoquic_log_varint_skip(bytes, bytes_max); /* Packet tolerance */
    bytes = picoquic_log_varint_skip(bytes, bytes_max); /* Max ACK delay */
    bytes = picoquic_log_varint_skip(bytes, bytes_max); /* Reordering threshold */

    picoquic_binlog_frame(f, bytes_begin, bytes);

    return bytes;
}

static const uint8_t* picoquic_log_immediate_ack_frame(FILE* f, const uint8_t* bytes, const uint8_t* bytes_max)
{
    const uint8_t* bytes_begin = bytes;

    bytes = picoquic_log_varint_skip(bytes, bytes_max); /* frame type as varint */
    picoquic_binlog_frame(f, bytes_begin, bytes);

    return bytes;
}

static const uint8_t* picoquic_log_erroring_frame(FILE* f, const uint8_t* bytes, const uint8_t* bytes_max)
{
    size_t frame_size = bytes_max - bytes;
    size_t copied = (frame_size > 8) ? 8 : frame_size;

    picoquic_binlog_frame(f, bytes, bytes + copied);

    return NULL;
}

static const uint8_t* picoquic_log_padding(FILE* f, const uint8_t* bytes, const uint8_t* bytes_max)
{
    picoquic_binlog_frame(f, bytes, bytes + 1);

    uint8_t ftype = bytes[0];
    while (bytes < bytes_max && bytes[0] == ftype) {
        bytes++;
    }

    return bytes;
}

static const uint8_t* picoquic_log_bdp_frame(FILE* f, const uint8_t* bytes, const uint8_t* bytes_max)
{
    const uint8_t* bytes_begin = bytes;
    size_t ip_len = 0;

    bytes = picoquic_log_varint_skip(bytes, bytes_max); /* Frame type */
    bytes = picoquic_log_varint_skip(bytes, bytes_max); /* Life time */
    bytes = picoquic_log_varint_skip(bytes, bytes_max); /* Bytes in flight */
    bytes = picoquic_log_varint_skip(bytes, bytes_max); /* min rtt */
    bytes = picoquic_log_length(bytes, bytes_max, &ip_len); /*  IP Address length */
    bytes = picoquic_log_fixed_skip(bytes, bytes_max, ip_len); /* IP address value */

    picoquic_binlog_frame(f, bytes_begin, bytes);

    return bytes;
}

static const uint8_t* picoquic_log_observed_address_frame(FILE* f, const uint8_t* bytes, const uint8_t* bytes_max, uint64_t ftype)
{
    const uint8_t* bytes_begin = bytes;
    size_t ip_len = ((ftype & 1) == 0) ? 4 : 16;
    size_t data_len = ip_len + 2;


    bytes = picoquic_log_varint_skip(bytes, bytes_max); /* Frame type */
    bytes = picoquic_log_varint_skip(bytes, bytes_max); /* Sequence number */
    bytes = picoquic_log_fixed_skip(bytes, bytes_max, data_len); /* IP address and port */

    picoquic_binlog_frame(f, bytes_begin, bytes);

    return bytes;
}

void picoquic_binlog_frames(FILE * f, const uint8_t* bytes, size_t length)
{
    const uint8_t* bytes_max = bytes + length;

    while (bytes != NULL && bytes < bytes_max) {
        uint64_t ftype= 0;
        size_t ftype_ll = picoquic_varint_decode(bytes, length, &ftype);

        if (ftype_ll == 0) {
            /* Error, incorrect frame type encoding */
            bytes = NULL;
            break;
        }
        else if (ftype < 64 && ftype_ll != 1) {
            /* Error, incorrect frame type encoding */
            bytes = NULL;
            break;
        }

        if (PICOQUIC_IN_RANGE(ftype, picoquic_frame_type_stream_range_min, picoquic_frame_type_stream_range_max)) {
            bytes = picoquic_log_stream_frame(f, bytes, bytes_max);
            continue;
        }

        switch (ftype) {
        case picoquic_frame_type_ack:
        case picoquic_frame_type_ack_ecn:
        case picoquic_frame_type_path_ack:
        case picoquic_frame_type_path_ack_ecn:
            bytes = picoquic_log_ack_frame(f, bytes, bytes_max);
            break;
        case picoquic_frame_type_retire_connection_id:
            bytes = picoquic_log_retire_connection_id_frame(f, bytes, bytes_max);
            break;
        case picoquic_frame_type_path_retire_connection_id:
            bytes = picoquic_log_path_retire_connection_id_frame(f, bytes, bytes_max);
            break;
        case picoquic_frame_type_padding:
        case picoquic_frame_type_ping:
        case picoquic_frame_type_poll:
            bytes = picoquic_log_padding(f, bytes, bytes_max);
            break;
        case picoquic_frame_type_reset_stream:
            bytes = picoquic_log_reset_stream_frame(f, bytes, bytes_max);
            break;
        case picoquic_frame_type_connection_close:
            bytes = picoquic_log_close_frame(f, bytes, bytes_max);
            break;
        case picoquic_frame_type_application_close:
            bytes = picoquic_log_app_close_frame(f, bytes, bytes_max);
            break;
        case picoquic_frame_type_max_data:
            bytes = picoquic_log_max_data_frame(f, bytes, bytes_max);
            break;
        case picoquic_frame_type_max_stream_data:
            bytes = picoquic_log_max_stream_data_frame(f, bytes, bytes_max);
            break;
        case picoquic_frame_type_max_streams_bidir:
        case picoquic_frame_type_max_streams_unidir:
            bytes = picoquic_log_max_stream_id_frame(f, bytes, bytes_max);
            break;
        case picoquic_frame_type_data_blocked:
            bytes = picoquic_log_blocked_frame(f, bytes, bytes_max);
            break;
        case picoquic_frame_type_stream_data_blocked:
            bytes = picoquic_log_stream_blocked_frame(f, bytes, bytes_max);
            break;
        case picoquic_frame_type_streams_blocked_bidir:
        case picoquic_frame_type_streams_blocked_unidir:
            bytes = picoquic_log_streams_blocked_frame(f, bytes, bytes_max);
            break;
        case picoquic_frame_type_new_connection_id:
            bytes = picoquic_log_new_connection_id_frame(f, bytes, bytes_max);
            break;
        case picoquic_frame_type_path_new_connection_id:
            bytes = picoquic_log_path_new_connection_id_frame(f, bytes, bytes_max);
            break;
        case picoquic_frame_type_stop_sending:
            bytes = picoquic_log_stop_sending_frame(f, bytes, bytes_max);
            break;
        case picoquic_frame_type_path_challenge:
        case picoquic_frame_type_path_response:
            bytes = picoquic_log_path_frame(f, bytes, bytes_max);
            break;
        case picoquic_frame_type_crypto_hs:
            bytes = picoquic_log_crypto_hs_frame(f, bytes, bytes_max);
            break;
        case picoquic_frame_type_new_token:
            bytes = picoquic_log_new_token_frame(f, bytes, bytes_max);
            break;
        case picoquic_frame_type_handshake_done:
            bytes = picoquic_log_handshake_done_frame(f, bytes, bytes_max);
            break;
        case picoquic_frame_type_datagram:
        case picoquic_frame_type_datagram_l:
            bytes = picoquic_log_datagram_frame(f, bytes, bytes_max);
            break;
        case picoquic_frame_type_ack_frequency:
            bytes = picoquic_log_ack_frequency_frame(f, bytes, bytes_max);
            break;
        case picoquic_frame_type_immediate_ack:
            bytes = picoquic_log_immediate_ack_frame(f, bytes, bytes_max);
            break;
        case picoquic_frame_type_time_stamp:
            bytes = picoquic_log_time_stamp_frame(f, bytes, bytes_max);
            break;
        case picoquic_frame_type_path_abandon:
            bytes = picoquic_log_path_abandon_frame(f, bytes, bytes_max);
            break;
        case picoquic_frame_type_path_backup:
        case picoquic_frame_type_path_available:
            bytes = picoquic_log_path_available_or_backup_frame(f, bytes, bytes_max);
            break;
        case picoquic_frame_type_bdp:
            bytes = picoquic_log_bdp_frame(f, bytes, bytes_max);
            break;
        case picoquic_frame_type_observed_address_v4:
        case picoquic_frame_type_observed_address_v6:
            bytes = picoquic_log_observed_address_frame(f, bytes, bytes_max, ftype);
            break;
        default:
            bytes = picoquic_log_erroring_frame(f, bytes, bytes_max);
            break;
        }
    }
}

static void binlog_compose_event_header(bytestream* msg, const picoquic_connection_id_t* cid, uint64_t current_time,
    uint64_t path_id, picoquic_log_event_type event_type)
{
    /* Common chunk header */
    bytewrite_cid(msg, cid);
    bytewrite_vint(msg, current_time);
    bytewrite_vint(msg, path_id);
    bytewrite_vint(msg, (uint64_t)event_type);
}

static uint64_t binlog_get_path_id(picoquic_cnx_t* cnx, picoquic_path_t* path_x)
{
    uint64_t path_id = 0;

    if (cnx->is_multipath_enabled && path_x != NULL) {
        path_id = path_x->unique_path_id;
    }

    return path_id;
}

void binlog_pdu(FILE* f, const picoquic_connection_id_t* cid, int receiving, uint64_t current_time,
    const struct sockaddr* addr_peer, const struct sockaddr* addr_local, size_t packet_length)
{
    bytestream_buf stream_msg;
    bytestream* msg = bytestream_buf_init(&stream_msg, BYTESTREAM_MAX_BUFFER_SIZE);

    /* Common chunk header */
    binlog_compose_event_header(msg, cid, current_time, 0, picoquic_log_event_pdu_sent + receiving);

    /* PDU information */
    bytewrite_addr(msg, addr_peer);
    bytewrite_vint(msg, packet_length);
    bytewrite_addr(msg, addr_local);

    uint8_t head[4] = { 0 };
    picoformat_32(head, (uint32_t)bytestream_length(msg));

    (void)fwrite(head, sizeof(head), 1, f);
    (void)fwrite(bytestream_data(msg), bytestream_length(msg), 1, f);
}

static void binlog_pdu_ex(picoquic_cnx_t* cnx, int receiving, uint64_t current_time,
    const struct sockaddr* addr_peer, const struct sockaddr* addr_local, size_t packet_length)
{
    if (cnx != NULL && cnx->f_binlog != NULL && picoquic_cnx_is_still_logging(cnx)) {
        binlog_pdu(cnx->f_binlog, &cnx->initial_cnxid, receiving, current_time, addr_peer, addr_local, packet_length);
    }
}

void binlog_packet(FILE* f, const picoquic_connection_id_t* cid, uint64_t path_id, int receiving, uint64_t current_time,
    const picoquic_packet_header* ph, const uint8_t* bytes, size_t bytes_max)
{
    long fpos0 = ftell(f);

    uint8_t head[4] = { 0 };
    (void)fwrite(head, 4, 1, f);

    bytestream_buf stream_msg;
    bytestream* msg = bytestream_buf_init(&stream_msg, BYTESTREAM_MAX_BUFFER_SIZE);

    /* Common chunk header */
    binlog_compose_event_header(msg, cid, current_time, path_id, picoquic_log_event_packet_sent + receiving);

    /* packet information */
    bytewrite_vint(msg, bytes_max);

    /* packet header */
    bytewrite_int8(msg, (uint8_t)(64*ph->quic_bit_is_zero + 2 * ph->spin + ph->key_phase));
    bytewrite_vint(msg, ph->payload_length);
    bytewrite_vint(msg, ph->ptype);
    bytewrite_vint(msg, ph->pn64);

    bytewrite_cid(msg, &ph->dest_cnx_id);
    bytewrite_cid(msg, &ph->srce_cnx_id);

    if (ph->ptype != picoquic_packet_1rtt_protected &&
        ph->ptype != picoquic_packet_version_negotiation) {
        bytewrite_int32(msg, ph->vn);
    }

    if (ph->ptype == picoquic_packet_initial) {
        bytewrite_vint(msg, ph->token_length);
        bytewrite_buffer(msg, ph->token_bytes, ph->token_length);
    }

    (void)fwrite(bytestream_data(msg), bytestream_length(msg), 1, f);

    /* frame information */
    if (ph->ptype == picoquic_packet_version_negotiation || ph->ptype == picoquic_packet_retry) {
        picoquic_binlog_frame(f, bytes + ph->offset, bytes + bytes_max);
    }
    else if (ph->ptype != picoquic_packet_error) {
        picoquic_binlog_frames(f, bytes + ph->offset, ph->payload_length);
    }

    /* re-write chunk size field */
    long fpos1 = ftell(f);

    picoformat_32(head, (uint32_t)(fpos1 - fpos0 - 4));

    (void)fseek(f, fpos0, SEEK_SET);
    (void)fwrite(head, 4, 1, f);
    (void)fseek(f, 0, SEEK_END);
}

static void binlog_packet_ex(picoquic_cnx_t* cnx, picoquic_path_t * path_x, int receiving, uint64_t current_time,
    picoquic_packet_header* ph, const uint8_t* bytes, size_t bytes_max)
{
    if (cnx != NULL && cnx->f_binlog != NULL && picoquic_cnx_is_still_logging(cnx)) {
        binlog_packet(cnx->f_binlog, &cnx->initial_cnxid, binlog_get_path_id(cnx, path_x),
            receiving, current_time, ph, bytes, bytes_max);
    }
}

void binlog_dropped_packet(picoquic_cnx_t* cnx, picoquic_path_t* path_x,
    picoquic_packet_header* ph,  size_t packet_size, int err,
    uint8_t * raw_data, uint64_t current_time)
{
    FILE* f = cnx->f_binlog;
    size_t raw_size = packet_size;
    bytestream_buf stream_msg;
    bytestream* msg = bytestream_buf_init(&stream_msg, BYTESTREAM_MAX_BUFFER_SIZE);

    if (err == PICOQUIC_ERROR_AEAD_CHECK) {
        /* Do not log on decryption error, because the buffer was randomized by decryption */
        raw_size = 0;
    } else if (raw_size > 32) {
        raw_size = 32;
    }

    bytewrite_int32(msg, 0);
    /* Common chunk header */
    binlog_compose_event_header(msg, &cnx->initial_cnxid, current_time, binlog_get_path_id(cnx, path_x),
        picoquic_log_event_packet_dropped);
    /* Event header */
    bytewrite_vint(msg, ph->ptype);
    bytewrite_vint(msg, packet_size);
    bytewrite_vint(msg, err);
    bytewrite_vint(msg, raw_size);
    (void)bytewrite_buffer(msg, raw_data, raw_size);

    /* write the frame length at the reserved spot, and save to log file*/
    picoformat_32(msg->data, (uint32_t)(msg->ptr - 4));
    (void)fwrite(bytestream_data(msg), bytestream_length(msg), 1, f);
}

void binlog_buffered_packet(picoquic_cnx_t* cnx, picoquic_path_t* path_x, 
    picoquic_packet_type_enum ptype, uint64_t current_time)
{
    FILE* f = cnx->f_binlog;
    bytestream_buf stream_msg;
    bytestream* msg = bytestream_buf_init(&stream_msg, BYTESTREAM_MAX_BUFFER_SIZE);

    bytewrite_int32(msg, 0);
    /* Common chunk header */
    binlog_compose_event_header(msg, &cnx->initial_cnxid, current_time, binlog_get_path_id(cnx, path_x),
        picoquic_log_event_packet_buffered);
    /* Event header */
    bytewrite_vint(msg, ptype);
    (void)bytewrite_cstr(msg, "keys_unavailable");

    /* write the frame length at the reserved spot, and save to log file*/
    picoformat_32(msg->data, (uint32_t)(msg->ptr - 4));
    (void)fwrite(bytestream_data(msg), bytestream_length(msg), 1, f);
}


void binlog_outgoing_packet(picoquic_cnx_t* cnx, picoquic_path_t * path_x,
    uint8_t * bytes, uint64_t sequence_number, size_t pn_length, size_t length,
    uint8_t* send_buffer, size_t send_length, uint64_t current_time)
{
    FILE* f = cnx->f_binlog;

    picoquic_cnx_t* pcnx = cnx;
    picoquic_packet_header ph;
    size_t checksum_length = 16;
    struct sockaddr_in default_addr;

    const picoquic_connection_id_t * cnxid = (cnx != NULL) ? &cnx->initial_cnxid : &picoquic_null_connection_id;

    memset(&default_addr, 0, sizeof(struct sockaddr_in));
    default_addr.sin_family = AF_INET;

    picoquic_parse_packet_header((cnx == NULL) ? NULL : cnx->quic, send_buffer, send_length,
        ((cnx == NULL || cnx->path[0] == NULL) ? (struct sockaddr *)&default_addr :
        (struct sockaddr *)&cnx->path[0]->local_addr), &ph, &pcnx, 0);

    if (cnx != NULL) {
        picoquic_epoch_enum epoch = (ph.ptype == picoquic_packet_1rtt_protected) ? picoquic_epoch_1rtt :
            ((ph.ptype == picoquic_packet_0rtt_protected) ? picoquic_epoch_0rtt :
            ((ph.ptype == picoquic_packet_handshake) ? picoquic_epoch_handshake : picoquic_epoch_initial));
        if (cnx->crypto_context[epoch].aead_encrypt != NULL) {
            checksum_length = picoquic_get_checksum_length(cnx, epoch);
        }
    }

    ph.pn64 = sequence_number;
    ph.pn = (uint32_t)ph.pn64;
    if (ph.ptype != picoquic_packet_retry) {
        if (ph.pn_offset != 0) {
            ph.offset = ph.pn_offset + pn_length;
            ph.payload_length -= pn_length;
        }
    }
    if (ph.ptype != picoquic_packet_version_negotiation) {
        if (ph.payload_length > checksum_length) {
            ph.payload_length -= (uint16_t)checksum_length;
        }
        else {
            ph.payload_length = 0;
        }
    }

    binlog_packet(f, cnxid, binlog_get_path_id(cnx, path_x),  0, current_time, &ph, bytes, length);
}

void binlog_packet_lost(picoquic_cnx_t* cnx, picoquic_path_t* path_x,
    picoquic_packet_type_enum ptype,  uint64_t sequence_number, char const * trigger,
    picoquic_connection_id_t * dcid, size_t packet_size,
    uint64_t current_time)
{
    FILE* f = cnx->f_binlog;

    bytestream_buf stream_msg;
    bytestream* msg = bytestream_buf_init(&stream_msg, BYTESTREAM_MAX_BUFFER_SIZE);

    bytewrite_int32(msg, 0);
    /* Common chunk header */
    binlog_compose_event_header(msg, &cnx->initial_cnxid, current_time, binlog_get_path_id(cnx, path_x), picoquic_log_event_packet_lost);
    /* Event header */
    bytewrite_vint(msg, ptype);
    bytewrite_vint(msg, sequence_number);
    bytewrite_cstr(msg, trigger);
    if (dcid != NULL) {
        bytewrite_cid(msg, dcid);
    }
    else {
        bytewrite_int8(msg, 0);
    }
    bytewrite_vint(msg, packet_size);

    /* write the frame length at the reserved spot, and save to log file*/
    picoformat_32(msg->data, (uint32_t)(msg->ptr - 4));
    (void)fwrite(bytestream_data(msg), bytestream_length(msg), 1, f);
}


void binlog_negotiated_alpn(picoquic_cnx_t* cnx, int is_local,
    uint8_t const * sni, size_t sni_len, uint8_t const* alpn, size_t alpn_len,
    const ptls_iovec_t* alpn_list, size_t alpn_count)
{
    FILE* f = cnx->f_binlog;

    bytestream_buf stream_msg;
    bytestream* msg = bytestream_buf_init(&stream_msg, BYTESTREAM_MAX_BUFFER_SIZE);
    /* Common chunk header */
    binlog_compose_event_header(msg, &cnx->initial_cnxid, picoquic_get_quic_time(cnx->quic), 0, picoquic_log_event_alpn_update);
    /* Event header */
    bytewrite_vint(msg, is_local);
    bytewrite_vint(msg, sni_len);
    if (sni_len > 0) {
        bytewrite_buffer(msg, sni, sni_len);
    }

    bytewrite_vint(msg, alpn_count);
    if (alpn_count > 0) {
        for (size_t i = 0; i < alpn_count; i++) {
            bytewrite_vint(msg, alpn_list[i].len);
            bytewrite_buffer(msg, alpn_list[i].base, alpn_list[i].len);
        }
    }

    bytewrite_vint(msg, alpn_len);
    if (alpn_len > 0) {
        bytewrite_buffer(msg, alpn, alpn_len);
    }

    bytestream_buf stream_head;
    bytestream* head = bytestream_buf_init(&stream_head, 4);
    bytewrite_int32(head, (uint32_t)bytestream_length(msg));

    (void)fwrite(bytestream_data(head), bytestream_length(head), 1, f);
    (void)fwrite(bytestream_data(msg), bytestream_length(msg), 1, f);
}

void binlog_transport_extension(picoquic_cnx_t* cnx, int is_local,
    size_t param_length, uint8_t* params)
{
    FILE* f = cnx->f_binlog;

    bytestream_buf stream_msg;
    bytestream* msg = bytestream_buf_init(&stream_msg, BYTESTREAM_MAX_BUFFER_SIZE);
    /* Common chunk header */
    binlog_compose_event_header(msg, &cnx->initial_cnxid, picoquic_get_quic_time(cnx->quic), 0, picoquic_log_event_param_update);
    /* Event header */
    bytewrite_vint(msg, is_local);
    bytewrite_vint(msg, param_length);

    if (param_length > 0) {
        bytewrite_buffer(msg, params, param_length);
    }

    bytestream_buf stream_head;
    bytestream* head = bytestream_buf_init(&stream_head, 4);
    bytewrite_int32(head, (uint32_t)bytestream_length(msg));

    (void)fwrite(bytestream_data(head), bytestream_length(head), 1, f);
    (void)fwrite(bytestream_data(msg), bytestream_length(msg), 1, f);
}

void binlog_picotls_ticket(FILE* f, picoquic_connection_id_t cnx_id,
    uint8_t* ticket, uint16_t ticket_length)
{
    bytestream_buf stream_msg;
    bytestream * msg = bytestream_buf_init(&stream_msg, BYTESTREAM_MAX_BUFFER_SIZE);
    /* Common chunk header */
    binlog_compose_event_header(msg, &cnx_id, 0, 0, picoquic_log_event_tls_key_update);

    bytewrite_vint(msg, ticket_length);
    bytewrite_buffer(msg, ticket, ticket_length);

    bytestream_buf stream_head;
    bytestream * head = bytestream_buf_init(&stream_head, 8);
    bytewrite_int32(head, (uint32_t)bytestream_length(msg));

    (void)fwrite(bytestream_data(head), bytestream_length(head), 1, f);
    (void)fwrite(bytestream_data(msg), bytestream_length(msg), 1, f);
}

static void binlog_picotls_ticket_ex(picoquic_cnx_t* cnx,
    uint8_t* ticket, uint16_t ticket_length)
{
    if (cnx != NULL && cnx->f_binlog != NULL && picoquic_cnx_is_still_logging(cnx)) {
        binlog_picotls_ticket(cnx->f_binlog, cnx->initial_cnxid, ticket, ticket_length);
    }
}

FILE* create_binlog(char const* binlog_file, uint64_t creation_time, unsigned int multipath_enabled);

void binlog_new_connection(picoquic_cnx_t * cnx)
{
    char const* bin_dir = (cnx->quic->binlog_dir == NULL) ? cnx->quic->qlog_dir : cnx->quic->binlog_dir;

    if (bin_dir == NULL) {
        return;
    }

    if (cnx->quic->current_number_of_open_logs >= cnx->quic->max_simultaneous_logs) {
        return;
    }

    int ret = 0;

    cnx->f_binlog = picoquic_file_close(cnx->f_binlog);
    
    char cid_name[2 * PICOQUIC_CONNECTION_ID_MAX_SIZE + 1];
    if (picoquic_print_connection_id_hexa(cid_name, sizeof(cid_name), &cnx->initial_cnxid) != 0) {
        ret = -1;
    }

    char log_filename[512];
    if (ret == 0) {
        int sprintf_ret = -1;
        if (cnx->quic->use_unique_log_names) {
            sprintf_ret = picoquic_sprintf(log_filename, sizeof(log_filename), NULL, "%s%s%s.%x.%s.log",
                bin_dir, PICOQUIC_FILE_SEPARATOR, cid_name, cnx->log_unique,
                (cnx->client_mode) ? "client" : "server");
        }
        else {
            sprintf_ret = picoquic_sprintf(log_filename, sizeof(log_filename), NULL, "%s%s%s.%s.log",
                bin_dir, PICOQUIC_FILE_SEPARATOR, cid_name,
                (cnx->client_mode) ? "client" : "server");
        }
        if (sprintf_ret != 0) {
            ret = -1;
        }
        else {
            picoquic_string_free(cnx->binlog_file_name);
            cnx->binlog_file_name = picoquic_string_duplicate(log_filename);
        }
    }

    if (ret == 0) {
        cnx->f_binlog = create_binlog(log_filename, picoquic_get_quic_time(cnx->quic),
           cnx->local_parameters.is_multipath_enabled);
        if (cnx->f_binlog == NULL) {
            cnx->binlog_file_name = picoquic_string_free(cnx->binlog_file_name);
            ret = -1;
        }
        else {
            cnx->quic->current_number_of_open_logs++;
        }
    }

    if (ret == 0) {
        bytestream_buf stream_msg;
        bytestream * msg = bytestream_buf_init(&stream_msg, BYTESTREAM_MAX_BUFFER_SIZE);
        /* Common chunk header */
        binlog_compose_event_header(msg, &cnx->initial_cnxid, cnx->start_time, 0, picoquic_log_event_new_connection);

        bytewrite_int8(msg, cnx->client_mode != 0);
        bytewrite_int32(msg, cnx->proposed_version);
        bytewrite_cid(msg, &cnx->path[0]->p_remote_cnxid->cnx_id);

        /* Algorithms used */
        bytewrite_cstr(msg, cnx->congestion_alg->congestion_algorithm_id);
        bytewrite_vint(msg, cnx->spin_policy);

        bytestream_buf stream_head;
        bytestream * head = bytestream_buf_init(&stream_head, 8);
        bytewrite_int32(head, (uint32_t)bytestream_length(msg));

        (void)fwrite(bytestream_data(head), bytestream_length(head), 1, cnx->f_binlog);
        (void)fwrite(bytestream_data(msg), bytestream_length(msg), 1, cnx->f_binlog);
    }
}

void binlog_close_connection(picoquic_cnx_t * cnx)
{
    FILE * f = cnx->f_binlog;
    if (f == NULL) {
        return;
    }

    bytestream_buf stream_msg;
    bytestream * msg = bytestream_buf_init(&stream_msg, BYTESTREAM_MAX_BUFFER_SIZE);
    /* Common chunk header */
    binlog_compose_event_header(msg, &cnx->initial_cnxid, picoquic_get_quic_time(cnx->quic), 0, picoquic_log_event_connection_close);

    bytestream_buf stream_head;
    bytestream * head = bytestream_buf_init(&stream_head, 8);
    bytewrite_int32(head, (uint32_t)bytestream_length(msg));

    (void)fwrite(bytestream_data(head), bytestream_length(head), 1, f);
    (void)fwrite(bytestream_data(msg), bytestream_length(msg), 1, f);

    fflush(f);

    cnx->f_binlog = picoquic_file_close(cnx->f_binlog);

    if (cnx->quic->qlog_dir != NULL && cnx->quic->autoqlog_fn != NULL) {
        (void)cnx->quic->autoqlog_fn(cnx);
    }
    cnx->binlog_file_name = picoquic_string_free(cnx->binlog_file_name);
    if (cnx->quic->current_number_of_open_logs > 0) {
        cnx->quic->current_number_of_open_logs--;
    }
}

FILE* create_binlog(char const* binlog_file, uint64_t creation_time, unsigned int is_multipath_supported)
{
    FILE* f_binlog = picoquic_file_open(binlog_file, "wb");
    if (f_binlog == NULL) {
        DBG_PRINTF("Cannot open file %s for write.\n", binlog_file);
    }
    else {
        /* Write a header text with version identifier and current date  */
        bytestream_buf stream;
        bytestream* ps = bytestream_buf_init(&stream, 16);
        bytewrite_int32(ps, FOURCC('q', 'l', 'o', 'g'));
        bytewrite_int16(ps, (is_multipath_supported) ? 0x01 : 0); /* flags */
        bytewrite_int16(ps, 0x01); /* version */
        bytewrite_int64(ps, creation_time);

        if (fwrite(bytestream_data(ps), bytestream_length(ps), 1, f_binlog) <= 0) {
            DBG_PRINTF("Cannot write header for file %s.\n", binlog_file);
            f_binlog = picoquic_file_close(f_binlog);
        }
    }

    return f_binlog;
}

/*
 * Log the state of the congestion management, retransmission, etc.
 * Call either just after processing a received packet, or just after
 * sending a packet.
 */

void binlog_cc_dump(picoquic_cnx_t* cnx, uint64_t current_time)
{
    if (cnx->f_binlog == NULL) {
        return;
    }

    bytestream_buf stream_msg;
    bytestream* ps_msg = bytestream_buf_init(&stream_msg, BYTESTREAM_MAX_BUFFER_SIZE);
    int path_max = (cnx->is_multipath_enabled) ? cnx->nb_paths : 1;

    for (int path_id = 0; path_id < path_max; path_id++)
    {
        picoquic_path_t* path = cnx->path[path_id];
        picoquic_packet_context_t* pkt_ctx = &cnx->pkt_ctx[picoquic_packet_context_application];
        
        if (cnx->is_multipath_enabled) {
            pkt_ctx = &cnx->path[path_id]->pkt_ctx;
        }

        if (!path->is_cc_data_updated) {
            continue;
        }
        path->is_cc_data_updated = 0;

        /* Common chunk header */
        /* TODO: understand how to provide per path data -- most probably do a loop on
         * all available paths, and write the data for each path if multipath is enabled.
         * verify that it works for CSV and QLOG formats.
         */
        binlog_compose_event_header(ps_msg, &cnx->initial_cnxid, current_time, 
            binlog_get_path_id(cnx, path), picoquic_log_event_cc_update);

        bytewrite_vint(ps_msg, pkt_ctx->send_sequence);

        if (pkt_ctx->highest_acknowledged != UINT64_MAX) {
            bytewrite_vint(ps_msg, 1);
            bytewrite_vint(ps_msg, pkt_ctx->highest_acknowledged);
            bytewrite_vint(ps_msg, pkt_ctx->highest_acknowledged_time - cnx->start_time);
            bytewrite_vint(ps_msg, pkt_ctx->latest_time_acknowledged - cnx->start_time);
        }
        else {
            bytewrite_vint(ps_msg, 0);
        }

        bytewrite_vint(ps_msg, path->cwin);
        bytewrite_vint(ps_msg, path->one_way_delay_sample);
        bytewrite_vint(ps_msg, path->rtt_sample);
        bytewrite_vint(ps_msg, path->smoothed_rtt);
        bytewrite_vint(ps_msg, path->rtt_min);
        bytewrite_vint(ps_msg, path->bandwidth_estimate);
        bytewrite_vint(ps_msg, path->receive_rate_estimate);
        bytewrite_vint(ps_msg, path->send_mtu);
        bytewrite_vint(ps_msg, path->pacing.packet_time_microsec);
        if (cnx->is_multipath_enabled) {
            bytewrite_vint(ps_msg, path->nb_losses_found);
            bytewrite_vint(ps_msg, path->nb_spurious);
        }
        else {
            bytewrite_vint(ps_msg, cnx->nb_retransmission_total);
            bytewrite_vint(ps_msg, cnx->nb_spurious);
        }
        bytewrite_vint(ps_msg, cnx->cwin_blocked);
        bytewrite_vint(ps_msg, cnx->flow_blocked);
        bytewrite_vint(ps_msg, cnx->stream_blocked);

        if (cnx->congestion_alg == NULL) {
            bytewrite_vint(ps_msg, 0);
            bytewrite_vint(ps_msg, 0);
        }
        else {
            uint64_t cc_state = 0;
            uint64_t cc_param = 0;

            if (cnx->path[0]->congestion_alg_state != NULL) {
                cnx->congestion_alg->alg_observe(cnx->path[0], &cc_state, &cc_param);
            }
            bytewrite_vint(ps_msg, cc_state);
            bytewrite_vint(ps_msg, cc_param);
        }

        bytewrite_vint(ps_msg, path->peak_bandwidth_estimate);
        bytewrite_vint(ps_msg, path->bytes_in_transit);
        bytewrite_vint(ps_msg, path->last_bw_estimate_path_limited);

        bytestream_buf stream_head;
        bytestream* ps_head = bytestream_buf_init(&stream_head, BYTESTREAM_MAX_BUFFER_SIZE);

        bytewrite_int32(ps_head, (uint32_t)bytestream_length(ps_msg));

        (void)fwrite(bytestream_data(ps_head), bytestream_length(ps_head), 1, cnx->f_binlog);
        (void)fwrite(bytestream_data(ps_msg), bytestream_length(ps_msg), 1, cnx->f_binlog);
    }
}

/*
 * Write an information message frame, for free form debugging.
 */

void picoquic_binlog_message_v(picoquic_cnx_t* cnx, const char* fmt, va_list vargs)
{
    if (cnx->f_binlog == NULL) {
        return;
    }
    bytestream_buf stream_msg;
    bytestream* ps_msg = bytestream_buf_init(&stream_msg, BYTESTREAM_MAX_BUFFER_SIZE);
    size_t message_len;
    char* message_text;
    int written = -1;
    /* Common chunk header */
    binlog_compose_event_header(ps_msg, &cnx->initial_cnxid, picoquic_get_quic_time(cnx->quic), 0, picoquic_log_event_info_message);

    message_text = (char*)(ps_msg->data + ps_msg->ptr);
#ifdef _WINDOWS
    written = vsnprintf_s(message_text,
        ps_msg->size - ps_msg->ptr, _TRUNCATE, fmt, vargs);
    message_len = (written < 0) ? ps_msg->size - ps_msg->ptr - 1 : written;
#else
    written = vsnprintf(message_text, ps_msg->size - ps_msg->ptr, fmt, vargs);
    if (written < 0 || written >= ps_msg->size - ps_msg->ptr){
        message_len = ps_msg->size - ps_msg->ptr - 1;
    } else {
        message_len = written;
    }
#endif
    ps_msg->ptr += message_len;

    bytestream_buf stream_head;
    bytestream* ps_head = bytestream_buf_init(&stream_head, BYTESTREAM_MAX_BUFFER_SIZE);

    bytewrite_int32(ps_head, (uint32_t)bytestream_length(ps_msg));

    (void)fwrite(bytestream_data(ps_head), bytestream_length(ps_head), 1, cnx->f_binlog);
    (void)fwrite(bytestream_data(ps_msg), bytestream_length(ps_msg), 1, cnx->f_binlog);
}

/* Log an event that cannot be attached to a specific connection */
void binlog_ignore_quic_app_message(picoquic_quic_t* quic, const picoquic_connection_id_t* cid, const char* fmt, va_list vargs)
{
#ifdef _WINDOWS
    UNREFERENCED_PARAMETER(quic);
    UNREFERENCED_PARAMETER(cid);
    UNREFERENCED_PARAMETER(fmt);
#endif
}

/* Log arrival or departure of an UDP datagram for an unknown connection */
void binlog_ignore_quic_pdu(picoquic_quic_t* quic, int receiving, uint64_t current_time, uint64_t cid64,
    const struct sockaddr* addr_peer, const struct sockaddr* addr_local, size_t packet_length)
{
#ifdef _WINDOWS
    UNREFERENCED_PARAMETER(quic);
    UNREFERENCED_PARAMETER(receiving);
    UNREFERENCED_PARAMETER(current_time);
    UNREFERENCED_PARAMETER(addr_peer);
    UNREFERENCED_PARAMETER(addr_local);
    UNREFERENCED_PARAMETER(packet_length);
#endif
}

/* Log an event relating to a specific connection */
static void binlog_app_message(picoquic_cnx_t* cnx, const char* fmt, va_list vargs)
{
    if (cnx->f_binlog != NULL) {
        picoquic_binlog_message_v(cnx, fmt, vargs);
    }
}

/* Return from close with nothing, as this is per connection only */
void binlog_close(picoquic_quic_t* quic)
{
#ifdef _WINDOWS
    UNREFERENCED_PARAMETER(quic);
#endif
}

struct st_picoquic_unified_logging_t binlog_functions = {
    /* Per context log function */
    binlog_ignore_quic_app_message,
    binlog_ignore_quic_pdu,
    binlog_close,
    /* Per connection functions */
    binlog_app_message,
    binlog_pdu_ex,
    binlog_packet_ex,
    binlog_dropped_packet,
    binlog_buffered_packet,
    binlog_outgoing_packet,
    binlog_packet_lost,
    binlog_negotiated_alpn,
    binlog_transport_extension,
    binlog_picotls_ticket_ex,
    binlog_new_connection,
    binlog_close_connection,
    binlog_cc_dump
};

int picoquic_set_binlog(picoquic_quic_t* quic, char const* binlog_dir)
{
    quic->binlog_dir = picoquic_string_free(quic->binlog_dir);
    quic->binlog_dir = picoquic_string_duplicate(binlog_dir);
    quic->bin_log_fns = &binlog_functions;
    return 0;
}

void picoquic_enable_binlog(picoquic_quic_t* quic)
{
    quic->bin_log_fns = &binlog_functions;
}
