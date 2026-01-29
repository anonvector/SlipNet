/*
* Author: Christian Huitema
* Copyright (c) 2020, Private Octopus, Inc.
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

/* For performance tests, it is useful to collect parameters about the configuration
 * of the connection (ALPN, client or server, key transport parameters), the
 * resulting performance (time, data sent, data received, number of transactions)
 * and execution parameters (number of packets sent, lost, min/smooth RTT,
 * number of packet trains, cuase of short trains).
 * We don't want the data collection to interfere with the measured performance,
 * including in tests of "number of connections per second". The data collection
 * is performed in three phases:
 * - parameter values are collected when the connection is running.
 * - a measurement vector is stored at the end of the connection in the
 *   "performance log" context, i.e., in memory.
 * - when there are no more active connections on the server, the collected
 *   data is appended to the log.
 */

#include <stdlib.h>
#include <string.h>
#include "picoquic.h"
#include "picoquic_utils.h"
#include "picoquic_internal.h"
#include "performance_log.h"

typedef struct st_picoquic_performance_log_item_t {
    struct st_picoquic_performance_log_item_t* next;
    /* TODO: store ALPN and QUIC version here, update list of names. Add download and upload speed. 
     * Treat perflog version as constant */
    /* First store here the data that is not represented well as an integer */
    double duration_sec;
    double send_mbps;
    double recv_mbps;
    uint64_t data_sent;
    uint64_t data_received;
    uint32_t quic_version;
    char* alpn;
    picoquic_connection_id_t cnxid;
    uint64_t cnx_time_64;
    /* Then add a list of values for interesting parameters */
    size_t nb_values;
    uint64_t v[PICOQUIC_PERF_LOG_MAX_ITEMS];
} picoquic_performance_log_item_t;

typedef struct st_picoquic_performance_log_ctx_t {
    struct st_picoquic_performance_log_item_t* first;
    struct st_picoquic_performance_log_item_t* last;
    char const* perflog_file_name;
} picoquic_performance_log_ctx_t;

void picoquic_perflog_item_free(picoquic_performance_log_item_t* perflog_item)
{
    if (perflog_item->alpn != NULL) {
        free((char*)perflog_item->alpn);
    }
    free(perflog_item);
}

int picoquic_perflog_save(picoquic_performance_log_ctx_t* perflog_ctx)
{
    int ret = 0;
    FILE* F = picoquic_file_open(perflog_ctx->perflog_file_name, "a");

    if (F == NULL) {
        ret = -1;
    }
    else {
        while (perflog_ctx->first != NULL) {
            char cnxid_str[513];
            picoquic_performance_log_item_t* perflog_item = perflog_ctx->first;
            perflog_ctx->first = perflog_item->next;
            if (perflog_ctx->first == NULL) {
                perflog_ctx->last = NULL;
            }
            /* Print version identifiers */
            fprintf(F, "%d, %s, ", PICOQUIC_PER_LOG_VERSION, PICOQUIC_VERSION);
            /* Print the key performance data */
            fprintf(F, "%f, %" PRIu64 ", %" PRIu64 ", %f, %f",
                perflog_item->duration_sec,
                perflog_item->data_sent,
                perflog_item->data_received,
                perflog_item->send_mbps,
                perflog_item->recv_mbps);
            /* TODO: nb streams.
            printf("Nb_transactions: %" PRIu64"\n", quicperf_ctx->nb_streams);
            printf("TPS: %f\n", ((double)quicperf_ctx->nb_streams) / duration_sec);
            */
            /* Print identification data */
            if (picoquic_print_connection_id_hexa(cnxid_str, sizeof(cnxid_str), &perflog_item->cnxid) != 0) {
                cnxid_str[0] = 0;
            }
            fprintf(F, ", 0x%x, %s, 0x%s, %" PRIu64,
                perflog_item->quic_version,
                (perflog_item->alpn == NULL) ? "" : perflog_item->alpn,
                cnxid_str, perflog_item->cnx_time_64);

            /* Print the additional values */
            for (size_t i = 0; i < perflog_item->nb_values; i++) {
                fprintf(F, ", %"PRIu64, perflog_item->v[i]);
            }
            fprintf(F, "\n");
            picoquic_perflog_item_free(perflog_item);
        }
        (void)picoquic_file_close(F);
    }
    return ret;
}

int picoquic_perflog_record(picoquic_cnx_t* cnx, picoquic_performance_log_ctx_t* perflog_ctx)
{
    int ret = 0;
    picoquic_performance_log_item_t* perflog_item = (picoquic_performance_log_item_t*)
        malloc(sizeof(picoquic_performance_log_item_t));

    if (perflog_item == NULL) {
        ret = -1;
    }
    else {
        uint64_t start_time = picoquic_get_cnx_start_time(cnx);
        uint64_t close_time = picoquic_get_quic_time(cnx->quic);
        uint64_t duration_usec = close_time - start_time;
        memset(perflog_item, 0, sizeof(picoquic_performance_log_item_t));
        /* Compute the key performance metrics */
        perflog_item->duration_sec = ((double)duration_usec) / 1000000.0;
        if (perflog_item->duration_sec > 0) {
            perflog_item->data_sent = picoquic_get_data_sent(cnx);
            perflog_item->data_received = picoquic_get_data_received(cnx);
            perflog_item->send_mbps = ((double)perflog_item->data_sent) * 8.0 / ((double)duration_usec);
            perflog_item->recv_mbps = ((double)perflog_item->data_received) * 8.0 / ((double)duration_usec);
            /* TODO: nb streams.
            printf("Nb_transactions: %" PRIu64"\n", quicperf_ctx->nb_streams);
            printf("TPS: %f\n", ((double)quicperf_ctx->nb_streams) / duration_sec);
            */
        }
        /* Store identification data */
        perflog_item->alpn = picoquic_string_duplicate(cnx->alpn);
        perflog_item->quic_version = (cnx->version_index >= 0) ?
            picoquic_supported_versions[cnx->version_index].version : 0;
        perflog_item->cnxid = picoquic_get_logging_cnxid(cnx);
        perflog_item->cnx_time_64 = start_time;
        /* Store additional parameters */
        perflog_item->nb_values = PICOQUIC_PERF_LOG_MAX_ITEMS;
        perflog_item->v[picoquic_perflog_is_client] = cnx->client_mode;
        perflog_item->v[picoquic_perflog_nb_packets_received] = cnx->nb_packets_received;
        perflog_item->v[picoquic_perflog_nb_trains_sent] = cnx->nb_trains_sent;
        perflog_item->v[picoquic_perflog_nb_trains_short] = cnx->nb_trains_short;
        perflog_item->v[picoquic_perflog_nb_trains_blocked_cwin] = cnx->nb_trains_blocked_cwin;
        perflog_item->v[picoquic_perflog_nb_trains_blocked_pacing] = cnx->nb_trains_blocked_pacing;
        perflog_item->v[picoquic_perflog_nb_trains_blocked_others] = cnx->nb_trains_blocked_others;
        perflog_item->v[picoquic_perflog_nb_packets_sent] = cnx->nb_packets_sent;
        perflog_item->v[picoquic_perflog_nb_retransmission_total] = cnx->nb_retransmission_total;
        perflog_item->v[picoquic_perflog_nb_spurious] = cnx->nb_spurious;
        perflog_item->v[picoquic_perflog_delayed_ack_option] = cnx->is_ack_frequency_negotiated;
        perflog_item->v[picoquic_perflog_min_ack_delay_remote] = cnx->min_ack_delay_remote;
        perflog_item->v[picoquic_perflog_max_ack_delay_remote] = cnx->max_ack_delay_remote;
        perflog_item->v[picoquic_perflog_max_ack_gap_remote] = cnx->max_ack_gap_remote;
        perflog_item->v[picoquic_perflog_min_ack_delay_local] = cnx->min_ack_delay_local;
        perflog_item->v[picoquic_perflog_max_ack_delay_local] = cnx->max_ack_delay_local;
        perflog_item->v[picoquic_perflog_max_ack_gap_local] = cnx->max_ack_gap_local;
        perflog_item->v[picoquic_perflog_max_mtu_sent] = cnx->max_mtu_sent;
        perflog_item->v[picoquic_perflog_max_mtu_received] = cnx->max_mtu_received;
        perflog_item->v[picoquic_perflog_zero_rtt] = (cnx->nb_zero_rtt_received > 0) || (cnx->nb_zero_rtt_acked > 0);
        if (cnx->path != NULL && cnx->path[0] != NULL) {
            perflog_item->v[picoquic_perflog_srtt] = cnx->path[0]->smoothed_rtt;
            perflog_item->v[picoquic_perflog_minrtt] = cnx->path[0]->rtt_min;
            perflog_item->v[picoquic_perflog_cwin] = cnx->path[0]->cwin;
            perflog_item->v[picoquic_perflog_bwe_max] = cnx->path[0]->bandwidth_estimate_max;
            perflog_item->v[picoquic_perflog_pacing_quantum_max] = cnx->path[0]->pacing.quantum_max;
            perflog_item->v[picoquic_perflog_pacing_rate] = cnx->path[0]->pacing.rate_max;
        }
        if (cnx->congestion_alg != NULL) {
            perflog_item->v[picoquic_perflog_ccalgo] = cnx->congestion_alg->congestion_algorithm_number;
        }
        
        if (perflog_ctx->first == NULL) {
            perflog_ctx->first = perflog_item;
        }

        if (perflog_ctx->last == NULL) {
            perflog_ctx->last = perflog_item;
        }
        else {
            perflog_ctx->last->next = perflog_item;
        }

        if (cnx->quic->cnx_list == cnx && cnx->quic->cnx_last == cnx) {
            ret = picoquic_perflog_save(perflog_ctx);
        }
    }

    return ret;
}

void picoquic_perflog_free(picoquic_performance_log_ctx_t* perflog_ctx)
{
    if (perflog_ctx->perflog_file_name != NULL) {
        free((char *)perflog_ctx->perflog_file_name);
    }
    while (perflog_ctx->first != NULL) {
        picoquic_performance_log_item_t* perflog_item = perflog_ctx->first;
        perflog_ctx->first = perflog_item->next;
        picoquic_perflog_item_free(perflog_item);
    }
    free(perflog_ctx);
}

int picoquic_perflog(picoquic_quic_t* quic, picoquic_cnx_t* cnx, int should_delete)
{
    int ret = 0;
    picoquic_performance_log_ctx_t* perflog_ctx = (picoquic_performance_log_ctx_t*)quic->v_perflog_ctx;

    if (cnx != NULL) {
        ret = picoquic_perflog_record(cnx, perflog_ctx);
    }

    if (should_delete) {
        picoquic_perflog_free(perflog_ctx);
        quic->v_perflog_ctx = NULL;
        quic->perflog_fn = NULL;
    }

    return ret;
}

const char* picoquic_perflog_param_name(picoquic_perflog_column_enum rank)
{
    switch (rank) {
    case picoquic_perflog_is_client: return("is_client");
    case picoquic_perflog_nb_packets_received: return("pkt_recv");
    case picoquic_perflog_nb_trains_sent: return("trains_s");
    case picoquic_perflog_nb_trains_short: return("t_short");
    case picoquic_perflog_nb_trains_blocked_cwin: return("tb_cwin");
    case picoquic_perflog_nb_trains_blocked_pacing: return("tb_pacing");
    case picoquic_perflog_nb_trains_blocked_others: return("tb_others");
    case picoquic_perflog_nb_packets_sent: return("pkt_sent");
    case picoquic_perflog_nb_retransmission_total: return("retrans.");
    case picoquic_perflog_nb_spurious: return("spurious");
    case picoquic_perflog_delayed_ack_option: return("delayed_ack_option");
    case picoquic_perflog_min_ack_delay_remote: return("min_ack_delay_remote");
    case picoquic_perflog_max_ack_delay_remote: return("max_ack_delay_remote");
    case picoquic_perflog_max_ack_gap_remote: return("max_ack_gap_remote");
    case picoquic_perflog_min_ack_delay_local: return("min_ack_delay_local");
    case picoquic_perflog_max_ack_delay_local: return("max_ack_delay_local");
    case picoquic_perflog_max_ack_gap_local: return("max_ack_gap_local");
    case picoquic_perflog_max_mtu_sent: return("max_mtu_sent");
    case picoquic_perflog_max_mtu_received: return("max_mtu_received");
    case picoquic_perflog_zero_rtt: return("zero_rtt");
    case picoquic_perflog_srtt: return("srtt");
    case picoquic_perflog_minrtt: return("minrtt");
    case picoquic_perflog_cwin: return("cwin");
    case picoquic_perflog_ccalgo: return("ccalgo");
    case picoquic_perflog_bwe_max: return("bwe_max");
    case picoquic_perflog_pacing_quantum_max: return("p_quantum");
    case picoquic_perflog_pacing_rate: return("p_rate");
    default:
        break;
    }
    return NULL;
}

int picoquic_perflog_file_is_empty(char const* perflog_file_name)
{
    int is_empty = 0;
    FILE* F = picoquic_file_open(perflog_file_name, "rb");
    if (F == NULL) {
        is_empty = 1;
    }
    else {
        long sz;
        fseek(F, 0, SEEK_END);
        sz = ftell(F);
        if (sz == 0) {
            is_empty = 1;
        }
        (void)picoquic_file_close(F);
    }
    return (is_empty);
}

void picoquic_perflog_file_set_header(char const* perflog_file_name)
{
    FILE* F = picoquic_file_open(perflog_file_name, "w");

    if (F != NULL) {
        fprintf(F, "Log_v, PQ_v, Duration, Sent, Received, Mpbs_S, Mbps_R");
        fprintf(F, ", QUIC_v, ALPN, CNX_ID, T64");
        /* Print the additional values */
        for (size_t i = 0; i < PICOQUIC_PERF_LOG_MAX_ITEMS; i++) {
            char buf[16];
            char const* s = picoquic_perflog_param_name((picoquic_perflog_column_enum)i);
            if (s == NULL) {
                (void)picoquic_sprintf(buf, sizeof(buf), NULL, "v%zu", i);
                s = buf;
            }
            fprintf(F, ", %s", s);
        }
        fprintf(F, "\n");
        fclose(F);
    }
}

int picoquic_perflog_setup(picoquic_quic_t* quic, char const * perflog_file_name)
{
    int ret = 0;
    picoquic_performance_log_ctx_t* perflog_ctx = (picoquic_performance_log_ctx_t*)
        malloc(sizeof(picoquic_performance_log_ctx_t));
    if (perflog_ctx == NULL) {
        ret = -1;
    }
    else {
        memset(perflog_ctx, 0, sizeof(picoquic_performance_log_ctx_t));
        perflog_ctx->perflog_file_name = picoquic_string_duplicate(perflog_file_name);
        if (perflog_ctx->perflog_file_name == NULL) {
            free(perflog_ctx);
            ret = -1;
        } else {
            /* If the file is empty, add a description string, so CSV looks good */
            if (picoquic_perflog_file_is_empty(perflog_file_name)) {
                picoquic_perflog_file_set_header(perflog_file_name);
            }
            /* Program the QUIC context to produce performance logs */
            quic->perflog_fn = picoquic_perflog;
            quic->v_perflog_ctx = (void*)perflog_ctx;
        }
    }
    return ret;
}