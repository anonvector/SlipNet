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

#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <errno.h>

#include "picoquic_internal.h"
#include "bytestream.h"
#include "logreader.h"
#include "picoquic_binlog.h"
#include "cidset.h"

static int byteread_packet_header(bytestream * s, picoquic_packet_header * ph);

int fileread_binlog(FILE* bin_log, int(*cb)(bytestream*, void*), void* cbptr)
{
    int ret = 0;
    uint8_t head[4];
    bytestream_buf stream_msg;

    fseek(bin_log, 16, SEEK_SET);

    while (ret == 0 && fread(head, sizeof(head), 1, bin_log) > 0) {

        uint32_t len = (head[0] << 24) | (head[1] << 16) | (head[2] << 8) | head[3];
        if (len > sizeof(stream_msg.buf)) {
            ret = -1;
        }

        if (ret == 0 && fread(stream_msg.buf, len, 1, bin_log) <= 0) {
            ret = -1;
        }

        if (ret == 0) {
            bytestream* s = bytestream_buf_init(&stream_msg, len);
            ret |= cb(s, cbptr);
        }
    }

    return ret;
}

typedef struct convert_log_file_event_st {

    const picoquic_connection_id_t * cid;
    binlog_convert_cb_t * callbacks;

} convert_log_file_event_t;

static int binlog_convert_event(bytestream * s, void * ptr)
{
    int ret = 0;
    convert_log_file_event_t* ctx = (convert_log_file_event_t*)ptr;
    void * cbptr = ctx->callbacks->ptr;

    picoquic_connection_id_t cid;
    ret |= byteread_cid(s, &cid);

    /* filter for connection id */
    if (ret != 0 || picoquic_compare_connection_id(&cid, ctx->cid) != 0) {
        return ret;
    }

    uint64_t time = 0;
    ret |= byteread_vint(s, &time);

    uint64_t path_id = 0;
    ret |= byteread_vint(s, &path_id);

    uint64_t id = 0;
    ret |= byteread_vint(s, &id);

    switch (id) {
    case picoquic_log_event_new_connection: {

        uint8_t client_mode = 0;
        ret |= byteread_int8(s, &client_mode);

        uint32_t proposed_version = 0;
        ret |= byteread_int32(s, &proposed_version);

        picoquic_connection_id_t remote_cnxid;
        ret |= byteread_cid(s, &remote_cnxid);

        if (ret == 0) {
            ret |= ctx->callbacks->connection_start(time, &cid, client_mode, proposed_version, &remote_cnxid, cbptr);
        }
        break;
    }
    case picoquic_log_event_connection_close: {
        if (ret == 0) {
            ret |= ctx->callbacks->connection_end(time, cbptr);
        }
        break;
    } 
    case picoquic_log_event_pdu_recv:
    case picoquic_log_event_pdu_sent:
    {
        int rxtx = id == picoquic_log_event_pdu_recv;
        ret |= ctx->callbacks->pdu(time, rxtx, s, cbptr);
        break;
    }
    case picoquic_log_event_packet_recv:
    case picoquic_log_event_packet_sent:
    {
        int rxtx = id == picoquic_log_event_packet_recv;

        uint64_t packet_length = 0;
        ret |= byteread_vint(s, &packet_length);

        picoquic_packet_header ph;
        ret |= byteread_packet_header(s, &ph);

        if (ret == 0) {
            ret = ctx->callbacks->packet_start(time, path_id, packet_length, &ph, rxtx, cbptr);
        }

        while (ret == 0 && bytestream_remain(s) > 0) {

            size_t len = 0;
            ret = byteread_vlen(s, &len);

            if (ret == 0) {
                bytestream stream;
                bytestream* frame = bytestream_ref_init(&stream, bytestream_ptr(s), len);

                ret = bytestream_skip(s, len);
                if (ret == 0) {
                    ret = ctx->callbacks->packet_frame(frame, cbptr);
                }
            }
        }

        if (ret == 0) {
            ret = ctx->callbacks->packet_end(cbptr);
        }

        break;
    }
    case picoquic_log_event_packet_dropped:
        if (ret == 0) {
            ret = ctx->callbacks->packet_dropped(time, path_id, s, cbptr);
        }
        break;
    case picoquic_log_event_packet_buffered:
        if (ret == 0) {
            ret = ctx->callbacks->packet_buffered(time, path_id, s, cbptr);
        }
        break;
    case picoquic_log_event_packet_lost:
        if (ret == 0) {
            ret = ctx->callbacks->packet_lost(time, path_id, s, cbptr);
        }
        break;
    case picoquic_log_event_alpn_update:
        if (ret == 0) {
            ret = ctx->callbacks->alpn_update(time, s, cbptr);
        }
        break;
    case picoquic_log_event_param_update:
        if (ret == 0) {
            ret = ctx->callbacks->param_update(time, s, cbptr);
        }
        break;
    case picoquic_log_event_cc_update:
        if (ret == 0) {
            ret = ctx->callbacks->cc_update(time, path_id, s, cbptr);
        }
        break;
    case picoquic_log_event_info_message:
        if (ret == 0) {
            ret = ctx->callbacks->info_message(time, s, cbptr);
        }
        break;
    default:
        /* This event is ignored for now */
        break;
    }

    return ret;
}

int binlog_convert(FILE * f_binlog, const picoquic_connection_id_t * cid, binlog_convert_cb_t * callbacks)
{
    convert_log_file_event_t ctx;
    ctx.cid = cid;
    ctx.callbacks = callbacks;

    return fileread_binlog(f_binlog, binlog_convert_event, &ctx);
}

static int binlog_list_cids_cb(bytestream * s, void * cbptr)
{
    picoquic_connection_id_t cid;
    int ret = byteread_cid(s, &cid);

    if (ret == 0) {
        ret = cidset_insert((picohash_table*)cbptr, &cid);
    }

    return ret;
}

int binlog_list_cids(FILE * binlog, picohash_table * cids)
{
    return fileread_binlog(binlog, binlog_list_cids_cb, cids);
}

static int byteread_packet_header(bytestream * s, picoquic_packet_header * ph)
{
    int ret = 0;

    /* packet information */
    uint8_t header_flags = 0;
    byteread_int8(s, &header_flags);
    ph->quic_bit_is_zero = ((header_flags & 64) != 0);
    ph->spin = ((header_flags & 2) != 0);
    ph->key_phase = ((header_flags & 1) != 0);

    size_t payload_length = 0;
    byteread_vlen(s, &payload_length);
    ph->payload_length = payload_length;

    uint64_t ptype;
    byteread_vint(s, &ptype);
    ph->ptype = (picoquic_packet_type_enum)ptype;

    byteread_vint(s, &ph->pn64);

    byteread_cid(s, &ph->dest_cnx_id);
    byteread_cid(s, &ph->srce_cnx_id);

    if (ptype != picoquic_packet_1rtt_protected &&
        ptype != picoquic_packet_version_negotiation) {
        byteread_int32(s, &ph->vn);
    }
    else {
        ph->vn = 0;
    }

    ph->token_length = 0;
    ph->token_bytes = NULL;

    if (ptype == picoquic_packet_initial) {
        byteread_vlen(s, &ph->token_length);
        ph->token_bytes = s->data + s->ptr;
        bytestream_skip(s, ph->token_length);
    }

    return ret;
}

FILE * open_outfile(const char * cid_name, const char * binlog_name, const char * out_dir, const char * out_ext)
{
    if (out_dir == NULL) {
        return stdout;
    }

    char filename[512];
    int ret = picoquic_sprintf(filename, sizeof(filename), NULL, "%s%s%s.%s",
        out_dir, PICOQUIC_FILE_SEPARATOR, cid_name, out_ext);

    if (ret != 0) {
        DBG_PRINTF("Cannot format file name for connection %s in file %s", cid_name, binlog_name);
        return NULL;
    }
    
    FILE * f = picoquic_file_open(filename, "w");
    if (f == NULL) {
        fprintf(stderr, "Could not open '%s' for writing (err=%d)", filename, errno);
    }
    return f;
}

/* Open the bin file for reading */
FILE * picoquic_open_cc_log_file_for_read(char const * bin_cc_log_name, uint16_t * flags, uint64_t * log_time)
{
    int ret = 0;
    FILE * bin_log = picoquic_file_open(bin_cc_log_name, "rb");
    if (bin_log == NULL) {
        DBG_PRINTF("Cannot open CC file %s.\n", bin_cc_log_name);
        ret = -1;
    }

    if (ret == 0) {
        bytestream_buf stream;
        bytestream * ps = bytestream_buf_init(&stream, 16);

        uint32_t fcc = 0;
        uint16_t version = 0;

        if (fread(stream.buf, bytestream_size(ps), 1, bin_log) <= 0) {
            ret = -1;
            DBG_PRINTF("Cannot read header for file %s.\n", bin_cc_log_name);
        }
        else if (byteread_int32(ps, &fcc) != 0 || fcc != FOURCC('q', 'l', 'o', 'g')) {
            ret = -1;
            DBG_PRINTF("Header for file %s does not start with magic number.\n", bin_cc_log_name);
        }
        else if (byteread_int16(ps, flags) != 0) {
            ret = -1;
            DBG_PRINTF("Header for file %s does include flags.\n", bin_cc_log_name);
        }
        else if (byteread_int16(ps, &version) != 0 || version != 0x01) {
            ret = -1;
            DBG_PRINTF("Header for file %s requires unsupported version.\n", bin_cc_log_name);
        }
        else {
            ret = byteread_int64(ps, log_time);
        }
    }

    if (ret != 0) {
        bin_log = picoquic_file_close(bin_log);
    }

    return bin_log;
}
