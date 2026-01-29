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
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

#include "logconvert.h"
#include "logreader.h"

typedef struct svg_context_st {

    FILE * f_txtlog;      /*!< The file handle of the opened output file. */
    FILE * f_template;    /*!< The file handle of the opened template file. */

    const char * cid_name; /*!< Name of the connection, default = initial connection id */

    uint64_t start_time;  /*!< Timestamp is very first log event reported. */
    int packet_count;
    int frame_count;

    int state;
} svg_context_t;

int svg_pdu(uint64_t time, int rxtx, bytestream* s, void * ptr)
{
    (void)time;
    (void)rxtx;
    (void)s;
    (void)ptr;
    return 0;
}

int svg_alpn_update(uint64_t time, bytestream* s, void* ptr)
{
    (void)time;
    (void)s;
    (void)ptr;
    return 0;
}


int svg_param_update(uint64_t time, bytestream* s, void* ptr)
{
    (void)time;
    (void)s;
    (void)ptr;
    return 0;
}

int svg_packet_lost(uint64_t time, uint64_t path_id, bytestream* s, void* ptr)
{
    (void)time;
    (void)path_id;
    (void)s;
    (void)ptr;
    return 0;
}

int svg_packet_dropped(uint64_t time, uint64_t path_id, bytestream* s, void* ptr)
{
    (void)time;
    (void)path_id;
    (void)s;
    (void)ptr;
    return 0;
}

int svg_packet_buffered(uint64_t time, uint64_t path_id, bytestream* s, void* ptr)
{
    (void)time;
    (void)path_id;
    (void)s;
    (void)ptr;
    return 0;
}

int svg_connection_start(uint64_t time, const picoquic_connection_id_t * cid, int client_mode,
    uint32_t proposed_version, const picoquic_connection_id_t * remote_cnxid, void * ptr)
{
    (void)time;
    (void)cid;
    (void)client_mode;
    (void)proposed_version;
    (void)remote_cnxid;
    (void)ptr;
    return 0;
}

int svg_connection_end(uint64_t time, void* ptr)
{
    (void)time;
    (void)ptr;
    return 0;
}


int svg_packet_start(uint64_t time, uint64_t path_id, uint64_t size, const picoquic_packet_header * ph, int rxtx, void * ptr)
{
    const int event_height = 32;
    svg_context_t * svg = (svg_context_t*)ptr;
    FILE * f = svg->f_txtlog;

    (void)path_id;

    time -= svg->start_time;

    int x_pos = 50;
    int y_pos = 32 + svg->packet_count * event_height;

    const char * dir = rxtx == 0 ? "out" : "in";

    uint64_t time1 = time / 1000;
    uint64_t time01 = (time % 1000) / 100;

    fprintf(f, "  <use x=\"%d\" y=\"%d\" xlink:href=\"#packet-%s\" />\n", x_pos, y_pos, dir);
    fprintf(f, "  <text x=\"%d\" y=\"%d\" text-anchor=\"end\" class=\"time\">%"PRIu64".%"PRIu64" ms</text>\n", x_pos - 4, y_pos + 8, time1, time01);

    if (rxtx == 0) {
        fprintf(f, "  <text x=\"%d\" y=\"%d\" text-anchor=\"end\" class=\"seq_%s\">%"PRIu64"</text>\n", x_pos - 4, y_pos - 4, dir, ph->pn64);
        fprintf(f, "  <text x=\"%d\" y=\"%d\" text-anchor=\"end\" class=\"arw\">%"PRIu64" b</text>\n", 80, y_pos - 2, size);
        fprintf(f, "  <text x=\"%d\" y=\"%d\" text-anchor=\"start\" class=\"frm\" xml:space=\"preserve\"> %s</text>\n", 80, y_pos - 2, ptype2str(ph->ptype));
        fprintf(f, "  <text x=\"%d\" y=\"%d\" text-anchor=\"start\" class=\"frm\" xml:space=\"preserve\">", x_pos + 30, y_pos + 10);
    }
    else {
        fprintf(f, "  <text x=\"%d\" y=\"%d\" text-anchor=\"start\" class=\"seq_%s\">%"PRIu64"</text>\n", 600 - x_pos + 4, y_pos - 4, dir, ph->pn64);
        fprintf(f, "  <text x=\"%d\" y=\"%d\" text-anchor=\"start\" class=\"arw\">%"PRIu64" b</text>\n", 600 - 80, y_pos - 2, size);
        fprintf(f, "  <text x=\"%d\" y=\"%d\" text-anchor=\"end\" class=\"frm\" xml:space=\"preserve\">%s </text>\n", 600-80, y_pos - 2, ptype2str(ph->ptype));
        fprintf(f, "  <text x=\"%d\" y=\"%d\" text-anchor=\"end\" class=\"frm\" xml:space=\"preserve\">", 600 - x_pos - 30, y_pos + 10);
    }

    svg->packet_count++;
    return 0;
}

int svg_packet_frame(bytestream * s, void * ptr)
{
    svg_context_t * svg = (svg_context_t*)ptr;

    uint64_t ftype = 0;
    byteread_vint(s, &ftype);

    if (ftype >= picoquic_frame_type_stream_range_min &&
        ftype <= picoquic_frame_type_stream_range_max) {
        uint64_t stream_id = 0;
        byteread_vint(s, &stream_id);
        fprintf(svg->f_txtlog, " stream[%"PRIu64"] ", stream_id);
    } else {
        fprintf(svg->f_txtlog, " %s ", ftype2str((picoquic_frame_type_enum_t)ftype));
    }
    return 0;
}

int svg_packet_end(void * ptr)
{
    svg_context_t * svg = (svg_context_t*)ptr;
    FILE * f = svg->f_txtlog;
    fprintf(f, "</text>\n");
    return 0;
}

int svg_cc_update(uint64_t time, uint64_t path_id, bytestream* s, void* ptr)
{
#ifdef _WINDOWS
    UNREFERENCED_PARAMETER(time);
    UNREFERENCED_PARAMETER(path_id);
    UNREFERENCED_PARAMETER(s);
    UNREFERENCED_PARAMETER(ptr);
#endif
    return 0;
}

int svg_info_message(uint64_t time, bytestream* s, void* ptr)
{
#ifdef _WINDOWS
    UNREFERENCED_PARAMETER(time);
    UNREFERENCED_PARAMETER(s);
    UNREFERENCED_PARAMETER(ptr);
#endif
    return 0;
}

int svg_convert(const picoquic_connection_id_t * cid, FILE * f_binlog, FILE * f_template, const char * binlog_name, const char * out_dir)
{
    int ret = 0;

    char cid_name[2 * PICOQUIC_CONNECTION_ID_MAX_SIZE + 1];
    if (picoquic_print_connection_id_hexa(cid_name, sizeof(cid_name), cid) != 0) {
        DBG_PRINTF("Cannot convert connection id for %s", binlog_name);
        ret = -1;
    }

    svg_context_t svg;
    svg.f_txtlog = open_outfile(cid_name, binlog_name, out_dir, "svg");
    svg.f_template = f_template;
    svg.cid_name = cid_name;
    svg.start_time = 0;
    svg.packet_count = 0;

    binlog_convert_cb_t ctx;
    ctx.connection_start = svg_connection_start;
    ctx.connection_end = svg_connection_end;
    ctx.param_update = svg_alpn_update;
    ctx.param_update = svg_param_update;
    ctx.pdu = svg_pdu;
    ctx.packet_start = svg_packet_start;
    ctx.packet_frame = svg_packet_frame;
    ctx.packet_end = svg_packet_end;
    ctx.packet_lost = svg_packet_lost;
    ctx.packet_dropped = svg_packet_dropped;
    ctx.packet_buffered = svg_packet_buffered;
    ctx.cc_update = svg_cc_update;
    ctx.info_message = svg_info_message;
    ctx.ptr = &svg;

    char line[256];
    while (fgets(line, sizeof(line), f_template) != NULL) /* read a line */ {
        if (strcmp(line, "#\n") != 0) {
            /* Copy the template to the SVG file */
            fprintf(svg.f_txtlog, "%s", line);
        } else {
            ret = binlog_convert(f_binlog, cid, &ctx);
        }
    }

    return ret;
}
