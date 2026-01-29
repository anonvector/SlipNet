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

/*
* Memory log: keep trace in memory for the specified connection. The program
* operates by:
* 
* 1) Allocating memory at the beginning of the connection. The request
*    specified how many lines shall be logged.
* 2) Log a line each time "pdu log" is called, until the table is full.
* 3) Writes the lines to the specified CSV file when the table is full,
*    or when the connecton is being closed.
* 
* The creation creates two entries in the connection context:
* - log memory callback function.
* - log memory address.
* There are two callbacks: log PDU, and close.
*/
#include <stdint.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include "picoquic.h"
#include "picoquic_internal.h"
#include "picoquic_utils.h"

typedef struct st_picoquic_memory_line_t {
    uint64_t current_time;
    uint64_t send_sequence;
    uint64_t highest_acknowledged;
    uint64_t highest_acknowledged_time;
    uint64_t latest_time_acknowledged;
    uint64_t cwin;
    uint64_t one_way_delay_sample;
    uint64_t rtt_sample;
    uint64_t smoothed_rtt;
    uint64_t rtt_min;
    uint64_t bandwidth_estimate;
    uint64_t receive_rate_estimate;
    uint64_t send_mtu;
    uint64_t packet_time_microsec;
    uint64_t nb_retransmission_total;
    uint64_t nb_spurious;
    unsigned int cwin_blocked : 1;
    unsigned int flow_blocked : 1;
    unsigned int stream_blocked : 1;
    unsigned int last_bw_estimate_path_limited : 1;
    uint64_t cc_state;
    uint64_t cc_param;
    uint64_t peak_bandwidth_estimate;
    uint64_t bytes_in_transit;
} picoquic_memory_line_t;

typedef struct st_picoquic_memory_log_t {
    FILE* F;
    size_t nb_lines;
    size_t nb_alloc;

    picoquic_memory_line_t* lines;
} picoquic_memory_log_t;

int memlog_fill_line(picoquic_cnx_t* cnx, picoquic_path_t* path, picoquic_memory_line_t* memline, picoquic_memory_line_t* previous_line, uint64_t current_time)
{
    int ret = 0;
    picoquic_packet_context_t* pkt_ctx = &cnx->pkt_ctx[picoquic_packet_context_application];

    if (cnx->is_multipath_enabled) {
        pkt_ctx = &path->pkt_ctx;
    }

    memline->current_time = current_time - cnx->start_time;
    memline->send_sequence = pkt_ctx->send_sequence;

    if (pkt_ctx->highest_acknowledged != UINT64_MAX) {
        memline->highest_acknowledged = pkt_ctx->highest_acknowledged;
        memline->highest_acknowledged_time = pkt_ctx->highest_acknowledged_time - cnx->start_time;
        memline->latest_time_acknowledged = pkt_ctx->latest_time_acknowledged - cnx->start_time;
    }
    else {
        memline->highest_acknowledged = UINT64_MAX;
        memline->highest_acknowledged_time = 0;
        memline->latest_time_acknowledged = 0;
    }

    if (previous_line != NULL &&
        previous_line->send_sequence == memline->send_sequence &&
        previous_line->highest_acknowledged == memline->highest_acknowledged) {
        /* Would be a duplicate line. */
        ret = -1;
    }
    else {
        memline->cwin = path->cwin;
        memline->one_way_delay_sample = path->one_way_delay_sample;
        memline->rtt_sample = path->rtt_sample;
        memline->smoothed_rtt = path->smoothed_rtt;
        memline->rtt_min = path->rtt_min;
        memline->bandwidth_estimate = path->bandwidth_estimate;
        memline->receive_rate_estimate = path->receive_rate_estimate;
        memline->send_mtu = path->send_mtu;
        memline->packet_time_microsec = path->pacing.packet_time_microsec;
        if (cnx->is_multipath_enabled) {
            memline->nb_retransmission_total = path->nb_losses_found;
            memline->nb_spurious = path->nb_spurious;
        }
        else {
            memline->nb_retransmission_total = cnx->nb_retransmission_total;
            memline->nb_spurious = cnx->nb_spurious;
        }
        memline->cwin_blocked = cnx->cwin_blocked;
        memline->flow_blocked = cnx->flow_blocked;
        memline->stream_blocked = cnx->stream_blocked;

        if (cnx->congestion_alg == NULL ||
            cnx->path[0]->congestion_alg_state == NULL) {
            memline->cc_state = 0;
            memline->cc_param = 0;
        }
        else {
            cnx->congestion_alg->alg_observe(cnx->path[0], &memline->cc_state, &memline->cc_param);
        }

        memline->peak_bandwidth_estimate = path->peak_bandwidth_estimate;
        memline->bytes_in_transit = path->bytes_in_transit;
        memline->last_bw_estimate_path_limited = path->last_bw_estimate_path_limited;
    }
    return ret;
}

void memlog_print_header(FILE* F)
{
    fprintf(F, "current_time, ");
    fprintf(F, "send_sequence, ");

    fprintf(F, "highest_ack, ");
    fprintf(F, "high_ack_time, ");
    fprintf(F, "latest_time_ack, ");

    fprintf(F, "cwin, ");
    fprintf(F, "one_way_delay, ");
    fprintf(F, "rtt_sample, ");
    fprintf(F, "smoothed_rtt, ");
    fprintf(F, "rtt_min, ");
    fprintf(F, "bw_e, ");
    fprintf(F, "recv_rate, ");
    fprintf(F, "send_mtu, ");
    fprintf(F, "packet_time, ");

    fprintf(F, "nb_retrans, ");
    fprintf(F, "nb_spurious, ");

    fprintf(F, "cwin_blocked, ");
    fprintf(F, "flow_blocked, ");
    fprintf(F, "stream_blocked, ");

    fprintf(F, "cc_state, ");
    fprintf(F, "cc_param, ");

    fprintf(F, "peak_bandwidth_estimate, ");
    fprintf(F, "bytes_in_transit, ");
    fprintf(F, "bwe_path_limited");
    fprintf(F, "\n");
}


void memlog_print_line(FILE* F, picoquic_memory_line_t* memline)
{
    fprintf(F, "%" PRIu64 ",", memline->current_time);
    fprintf(F, "%" PRIu64 ",", memline->send_sequence);

    fprintf(F, "%" PRIi64 ",", (int64_t)memline->highest_acknowledged);
    fprintf(F, "%" PRIu64 ",", memline->highest_acknowledged_time);
    fprintf(F, "%" PRIu64 ",", memline->latest_time_acknowledged);

    fprintf(F, "%" PRIu64 ",", memline->cwin);
    fprintf(F, "%" PRIu64 ",", memline->one_way_delay_sample);
    fprintf(F, "%" PRIu64 ",", memline->rtt_sample);
    fprintf(F, "%" PRIu64 ",", memline->smoothed_rtt);
    fprintf(F, "%" PRIu64 ",", memline->rtt_min);
    fprintf(F, "%" PRIu64 ",", memline->bandwidth_estimate);
    fprintf(F, "%" PRIu64 ",", memline->receive_rate_estimate);
    fprintf(F, "%" PRIu64 ",", memline->send_mtu);
    fprintf(F, "%" PRIu64 ",", memline->packet_time_microsec);

    fprintf(F, "%" PRIu64 ",", memline->nb_retransmission_total);
    fprintf(F, "%" PRIu64 ",", memline->nb_spurious);

    fprintf(F, "%u,", memline->cwin_blocked);
    fprintf(F, "%u,", memline->flow_blocked);
    fprintf(F, "%u,", memline->stream_blocked);

    fprintf(F, "%" PRIu64 ",", memline->cc_state);
    fprintf(F, "%" PRIu64 ",", memline->cc_param);

    fprintf(F, "%" PRIu64 ",", memline->peak_bandwidth_estimate);
    fprintf(F, "%" PRIu64 ",", memline->bytes_in_transit);
    fprintf(F, "%u,", memline->last_bw_estimate_path_limited);
    fprintf(F, "\n");
}

void memlog_call_back(picoquic_cnx_t* cnx, picoquic_path_t* path, void* v_memlog, int op_code, uint64_t current_time)
{
    picoquic_memory_log_t* memlog = (picoquic_memory_log_t*)v_memlog;
    if (memlog != NULL) {
        if (op_code == 0) {
            if (memlog->nb_lines < memlog->nb_alloc){
                if (memlog_fill_line(cnx, path, &memlog->lines[memlog->nb_lines],
                    (memlog->nb_lines == 0)?NULL: &memlog->lines[memlog->nb_lines - 1],
                    current_time) == 0) {
                    memlog->nb_lines++;
                }
            }
        }
        else
        {
#ifdef PICOQUIC_MEMORY_LOG
            cnx->memlog_call_back = NULL;
            cnx->memlog_ctx = NULL;
#endif
            /* This is the close callback */
            if (memlog->F != NULL) {
                memlog_print_header(memlog->F);
                for (size_t i = 0; i < memlog->nb_lines; i++)
                {
                    memlog_print_line(memlog->F, &memlog->lines[i]);
                }
                memlog->F = picoquic_file_close(memlog->F);
            }
            free(memlog->lines);
            free(memlog);
        }
    }
}

int memlog_init(picoquic_cnx_t* cnx, size_t nb_lines, const char * memlog_file)
{
    int ret = -1;
    picoquic_memory_log_t* memlog = (picoquic_memory_log_t*)malloc(sizeof(picoquic_memory_log_t));
    if (memlog != NULL) {
        memset(memlog, 0, sizeof(picoquic_memory_log_t));

        memlog->lines = (picoquic_memory_line_t*)malloc(nb_lines * sizeof(picoquic_memory_line_t));
        if (memlog->lines != NULL) {
            memlog->nb_alloc = nb_lines;

            memlog->F = picoquic_file_open(memlog_file, "wt");

            if (memlog->F == NULL) {
                free(memlog->lines);
                ret = -1;
            }
            else {
                ret = 0;
            }
        }
        else {
            ret = -1;
        }

        if (ret != 0) {
            free(memlog);
        }
        else {
#ifdef PICOQUIC_MEMORY_LOG
            cnx->memlog_call_back = memlog_call_back;
            cnx->memlog_ctx = memlog;
#endif
        }
    }
    return(ret);
}