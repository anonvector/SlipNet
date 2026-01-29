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
#include <errno.h>

#include "picoquic_internal.h"
#include "bytestream.h"
#include "csv.h"
#include "svg.h"
#include "qlog.h"
#include "cidset.h"
#include "logreader.h"
#ifdef _WINDOWS
#include "../picoquicfirst/getopt.h"
#endif

typedef struct app_conversion_context_st
{
    const char * out_format;
    const char * out_dir;

    const char * binlog_name;
    FILE * f_binlog;

    const char * template_name;
    FILE * f_template;

    uint64_t log_time;
    uint16_t flags;
} app_conversion_context_t;

int convert_csv(const picoquic_connection_id_t * cid, void * ptr);
int convert_svg(const picoquic_connection_id_t * cid, void * ptr);
int convert_qlog(const picoquic_connection_id_t * cid, void * ptr);
int filedump_binlog(FILE* bin_log, FILE* bin_dump);

int usage();
void usage_formats();

/* - Open binary log file and find all connection ids it contains by:
 *   - read each event
 *   - read connection id of the event
 *   - store connection id in the hashtable if it doesn't contain it already
 * - Print all connection ids found.
 * - Check if user provided a connection id on the command line and verify it is
 *   contained in the hashtable. If so, replace the hashtable of connection ids
 *   with a new hashtable only containing the user provided connection id.
 * - Iterate over all connection ids in the hashtable and for each connection id
 *   convert all events for that connection id into the specified format.
 */

int main(int argc, char ** argv)
{
    int ret = 0;

    picohash_table * cids = cidset_create();

    const char * cid_name = NULL;
    picoquic_connection_id_t cid = picoquic_null_connection_id;

    app_conversion_context_t appctx = { 0 };
    appctx.out_format = "csv";

    int opt;
    while ((opt = getopt(argc, argv, "o:f:t:c:h")) != -1) {
        switch (opt) {
        case 'o':
            appctx.out_dir = optarg;
            break;
        case 'f':
            appctx.out_format = optarg;
            break;
        case 't':
            appctx.template_name = optarg;
            break;
        case 'c':
            cid_name = optarg;
            break;
        case 'h':
        default:
            return usage();
            break;
        }
    }

    if (optind < argc) {
        appctx.binlog_name = argv[optind++];
    } else {
        return usage();
    }

    if (cids == NULL) {
        fprintf(stderr, "Fatal: failed to create resources.\n");
        return 1;
    }

    if (cid_name != NULL && picoquic_parse_connection_id_hexa(cid_name, strlen(cid_name), &cid) == 0) {
        fprintf(stderr, "Could not parse connection id: %s\n", cid_name);
        ret = -1;
    }

    debug_printf_push_stream(stderr);

    appctx.f_binlog = picoquic_open_cc_log_file_for_read(appctx.binlog_name, &appctx.flags, &appctx.log_time);
    if (appctx.f_binlog == NULL) {
        fprintf(stderr, "Could not open log file %s\n", appctx.binlog_name);
        ret = -1;
    }

    if (ret == 0) {
        if (strcmp(appctx.out_format, "dump") == 0) {
            char dump_file_name[512];
            FILE* bin_dump = NULL;
            size_t name_len = 0;

            ret = picoquic_sprintf(dump_file_name, sizeof(dump_file_name), &name_len, "%s.dump", appctx.binlog_name);
            if (ret == 0) {
                bin_dump = picoquic_file_open(dump_file_name, "w");
                if (bin_dump == NULL) {
                    fprintf(stderr, "Could not open dump file %s\n", dump_file_name);
                    ret = -1;
                }
                else {
                    ret = filedump_binlog(appctx.f_binlog, bin_dump);
                    (void)picoquic_file_close(bin_dump);
                }
            }
        }
        else {
            if (appctx.template_name != NULL) {
                appctx.f_template = picoquic_file_open(appctx.template_name, "r");
                if (appctx.f_template == NULL) {
                    fprintf(stderr, "Could not open template file %s\n", appctx.binlog_name);
                    ret = -1;
                }
            }

            if (ret == 0) {
                binlog_list_cids(appctx.f_binlog, cids);

                fprintf(stderr, "%s contains %"PRIst" connection(s):\n\n", appctx.binlog_name, cids->count);
                cidset_print(stderr, cids);
                fprintf(stderr, "\n");

                if (!picoquic_is_connection_id_null(&cid)) {
                    if (!cidset_has_cid(cids, &cid)) {
                        fprintf(stderr, "%s does not contain connection %s\n", appctx.binlog_name, cid_name);
                        ret = -1;
                    }
                    else {
                        (void)cidset_delete(cids);
                        cids = cidset_create();
                        if (cids != NULL) {
                            cidset_insert(cids, &cid);
                        }
                        else {
                            ret = -1;
                        }
                    }
                }
            }

            if (ret == 0) {
                if (strcmp(appctx.out_format, "csv") == 0) {
                    ret = cidset_iterate(cids, convert_csv, &appctx);
                }
                else if (strcmp(appctx.out_format, "svg") == 0) {
                    if (appctx.f_template == NULL) {
                        fprintf(stderr, "The svg format conversion requires a template file specified by parameter -t\n");
                        ret = -1;
                    }
                    else {
                        ret = cidset_iterate(cids, convert_svg, &appctx);
                    }
                }
                else if (strcmp(appctx.out_format, "qlog") == 0) {
                    ret = cidset_iterate(cids, convert_qlog, &appctx);
                }
                else {
                    fprintf(stderr, "Invalid output format '%s'. Valid formats are\n\n", appctx.out_format);
                    usage_formats();
                    ret = 1;
                }
            }
        }
    }

    (void)picoquic_file_close(appctx.f_binlog);
    (void)picoquic_file_close(appctx.f_template);
    (void)cidset_delete(cids);
    return ret;
}

int usage()
{
    fprintf(stderr, "PicoQUIC log file converter\n");
    fprintf(stderr, "Usage: picolog <options> input \n");
    fprintf(stderr, "\n");
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  -o directory          output directory name\n");
    fprintf(stderr, "                        default is current working directory\n");
    fprintf(stderr, "  -f format             output format:\n");
    usage_formats();
    fprintf(stderr, "  -t template-file      template file for svg format conversion\n");
    fprintf(stderr, "  -c connection-id      only convert logs of specified connection id\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "picolog converts binary log files into the format specified. Output files are\n");
    fprintf(stderr, "placed in the specified directory with their connection-id as file name.\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "If no connection id is specified all connections contained in the binary file\n");
    fprintf(stderr, "are converted producing as many output files as connections are found in the\n");
    fprintf(stderr, "binary file.\n");
    return 1;
}

void usage_formats()
{
    fprintf(stderr, "                        -f csv  : generate CC csv file\n");
    fprintf(stderr, "                        -f svg  : generate svg packet flow diagram.\n");
    fprintf(stderr, "                                  requires a template specified by -t\n");
    fprintf(stderr, "                        -f qlog : generate IETF QLOG file\n");
}

int convert_csv(const picoquic_connection_id_t * cid, void * ptr)
{
    const app_conversion_context_t* appctx = (const app_conversion_context_t*)ptr;
    int ret = 0;

    char cid_name[2 * PICOQUIC_CONNECTION_ID_MAX_SIZE + 1];
    if (picoquic_print_connection_id_hexa(cid_name, sizeof(cid_name), cid) != 0) {
        DBG_PRINTF("Cannot convert connection id for %s", appctx->binlog_name);
        ret = -1;
    }

    if (ret == 0) {
        ret = picoquic_cc_bin_to_csv(appctx->f_binlog,
            open_outfile(cid_name, appctx->binlog_name, appctx->out_dir, "csv"));
    }

    return ret;
}

int convert_svg(const picoquic_connection_id_t * cid, void * ptr)
{
    const app_conversion_context_t* appctx = (const app_conversion_context_t*)ptr;
    return svg_convert(cid, appctx->f_binlog, appctx->f_template, appctx->binlog_name, appctx->out_dir);
}

int convert_qlog(const picoquic_connection_id_t * cid, void * ptr)
{
    const app_conversion_context_t* appctx = (const app_conversion_context_t*)ptr;
    return qlog_convert(cid, appctx->f_binlog, appctx->binlog_name, NULL, appctx->out_dir, appctx->flags);
}

int filedump_binlog(FILE* bin_log, FILE* bin_dump)
{
    int ret = 0;
    uint8_t head[4];
    bytestream_buf stream_msg;

    fseek(bin_log, 16, SEEK_SET);

    fprintf(bin_dump, "MSG-len, I-CID, Time, ID, Comment\n");

    while (ret == 0 && fread(head, sizeof(head), 1, bin_log) > 0) {

        uint32_t len = (head[0] << 24) | (head[1] << 16) | (head[2] << 8) | head[3];
        if (len > sizeof(stream_msg.buf)) {
            fprintf(bin_dump, "%d, x, 0, 0, \"Message larger than buffer[%d]\"\n", len, (int)sizeof(stream_msg.buf));
            ret = -1;
        }

        if (ret == 0 && fread(stream_msg.buf, len, 1, bin_log) <= 0) {
            fprintf(bin_dump, "%d, x, 0, 0, \"Message cannot be read from file\n", len);
            ret = -1;
        }

        if (ret == 0) {
            bytestream* s = bytestream_buf_init(&stream_msg, len);

            picoquic_connection_id_t cid;
            ret |= byteread_cid(s, &cid);

            uint64_t time = 0;
            ret |= byteread_vint(s, &time);

            uint64_t id = 0;
            ret |= byteread_vint(s, &id);

            if (ret != 0) {
                fprintf(bin_dump, "%d, x, 0, 0, \"cannot read CID, Time and ID\n", len);
            }
            else {
                fprintf(bin_dump, "%d, x", len);
                for (uint8_t x = 0; x < cid.id_len; x++) {
                    fprintf(bin_dump, "%02x", cid.id[x]);
                }
                fprintf(bin_dump, ", %" PRIu64 ", %" PRIu64 ",\n", time, id);
            }
        }
    }

    return ret;
}