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
#include "picoquic_internal.h"
#include "logreader.h"
#include "picoquic_binlog.h"
#include "bytestream.h"
#include "csv.h"

typedef struct csv_cb_data_st
{
    FILE * f;
    uint64_t starttime;
    int idx;
} csv_cb_data;

int csv_cb(bytestream* s, void* ptr);

int picoquic_cc_log_file_to_csv(char const* bin_cc_log_name, char const* csv_cc_log_name)
{
    /* Open the bin file for reading, the csv file for writing */
    int ret = 0;
    uint64_t log_time = 0;
    uint16_t flags;
    FILE* f_binlog = picoquic_open_cc_log_file_for_read(bin_cc_log_name, &flags, &log_time);
    FILE* f_csvlog = picoquic_file_open(csv_cc_log_name, "w");

    if (f_binlog == NULL || f_csvlog == NULL) {
        ret = -1;
    } else {
        ret = picoquic_cc_bin_to_csv(f_binlog, f_csvlog);
    }
    (void)picoquic_file_close(f_csvlog);
    (void)picoquic_file_close(f_binlog);

    return ret;
}

/* Extract all picoquic_log_event_cc_update events from the binary log file and write them into an csv file. */
int picoquic_cc_bin_to_csv(FILE * f_binlog, FILE * f_csvlog)
{
    int ret = 0;

    ret |= fprintf(f_csvlog, "time, ") <= 0;
    ret |= fprintf(f_csvlog, "path, ") <= 0;
    ret |= fprintf(f_csvlog, "sequence, ") <= 0;
    ret |= fprintf(f_csvlog, "highest ack, ") <= 0;
    ret |= fprintf(f_csvlog, "high ack time, ") <= 0;
    ret |= fprintf(f_csvlog, "last time ack, ") <= 0;
    ret |= fprintf(f_csvlog, "cwin, ") <= 0;
    ret |= fprintf(f_csvlog, "one-way-delay, ") <= 0;
    ret |= fprintf(f_csvlog, "rtt-sample, ") <= 0;
    ret |= fprintf(f_csvlog, "SRTT, ") <= 0;
    ret |= fprintf(f_csvlog, "RTT min, ") <= 0;
    ret |= fprintf(f_csvlog, "Bandwidth (B/s), ") <= 0;
    ret |= fprintf(f_csvlog, "Receive rate (B/s), ") <= 0;
    ret |= fprintf(f_csvlog, "Send MTU, ") <= 0;
    ret |= fprintf(f_csvlog, "pacing packet time(us), ") <= 0;
    ret |= fprintf(f_csvlog, "nb retrans, ") <= 0;
    ret |= fprintf(f_csvlog, "nb spurious, ") <= 0;
    ret |= fprintf(f_csvlog, "cwin blkd, ") <= 0;
    ret |= fprintf(f_csvlog, "flow blkd, ") <= 0;
    ret |= fprintf(f_csvlog, "stream blkd, ") <= 0;
    ret |= fprintf(f_csvlog, "app limited, ") <= 0;
    ret |= fprintf(f_csvlog, "cc_state, ") <= 0;
    ret |= fprintf(f_csvlog, "cc_param, ") <= 0;
    ret |= fprintf(f_csvlog, "bw_max, ") <= 0;
    ret |= fprintf(f_csvlog, "transit, ") <= 0;
    ret |= fprintf(f_csvlog, "\n") <= 0;

    if (ret == 0) {

        csv_cb_data data;
        data.f = f_csvlog;
        data.starttime = 0;
        data.idx = 0;

        ret = fileread_binlog(f_binlog, csv_cb, &data);
    }

    return ret;
}

int csv_cb(bytestream * s, void * ptr)
{
    csv_cb_data * data = (csv_cb_data*)ptr;
    FILE * f_csvlog = data->f;
    int ret = 0;

    picoquic_connection_id_t cid;
    ret |= byteread_cid(s, &cid);

    uint64_t time = 0;
    ret |= byteread_vint(s, &time);

    uint64_t path_id = 0;
    ret |= byteread_vint(s, &path_id);

    uint64_t id = 0;
    ret |= byteread_vint(s, &id);

    if (data->idx == 0) {
        data->starttime = time;
    }

    data->idx++;
    time -= data->starttime;

    if (ret == 0 && id == picoquic_log_event_cc_update) {
        uint64_t sequence = 0;
        uint64_t packet_rcvd = 0;
        uint64_t highest_ack = UINT64_MAX;
        uint64_t high_ack_time = 0;
        uint64_t last_time_ack = 0;
        uint64_t cwin = 0;
        uint64_t one_way_delay = 0;
        uint64_t rtt_sample = 0;
        uint64_t SRTT = 0;
        uint64_t RTT_min = 0;
        uint64_t bandwidth_estimate = 0;
        uint64_t receive_rate_estimate = 0;
        uint64_t Send_MTU = 0;
        uint64_t pacing_packet_time = 0;
        uint64_t nb_retrans = 0;
        uint64_t nb_spurious = 0;
        uint64_t cwin_blkd = 0;
        uint64_t flow_blkd = 0;
        uint64_t stream_blkd = 0;
        uint64_t cc_state = 0;
        uint64_t cc_param = 0;
        uint64_t bw_max = 0;
        uint64_t bytes_in_transit = 0;
        uint64_t app_limited = 0;

        ret |= byteread_vint(s, &sequence);
        ret |= byteread_vint(s, &packet_rcvd);
        if (packet_rcvd != 0) {
            ret |= byteread_vint(s, &highest_ack);
            ret |= byteread_vint(s, &high_ack_time);
            ret |= byteread_vint(s, &last_time_ack);
        }
        ret |= byteread_vint(s, &cwin);
        ret |= byteread_vint(s, &one_way_delay);
        ret |= byteread_vint(s, &rtt_sample);
        ret |= byteread_vint(s, &SRTT);
        ret |= byteread_vint(s, &RTT_min);
        ret |= byteread_vint(s, &bandwidth_estimate);
        ret |= byteread_vint(s, &receive_rate_estimate);
        ret |= byteread_vint(s, &Send_MTU);
        ret |= byteread_vint(s, &pacing_packet_time);
        ret |= byteread_vint(s, &nb_retrans);
        ret |= byteread_vint(s, &nb_spurious);
        ret |= byteread_vint(s, &cwin_blkd);
        ret |= byteread_vint(s, &flow_blkd);
        ret |= byteread_vint(s, &stream_blkd);

        (void)byteread_vint(s, &cc_state);
        (void)byteread_vint(s, &cc_param);
        (void)byteread_vint(s, &bw_max);
        (void)byteread_vint(s, &bytes_in_transit);
        (void)byteread_vint(s, &app_limited);

        if (ret != 0 || fprintf(f_csvlog, "%" PRIu64 ", %" PRIu64 ", %" PRIu64 ", %" PRId64 ", %" PRIu64 ", %" PRIu64 ", %" PRIu64 ", %" PRIu64 ", %" PRIu64 ", %" PRIu64 ", %" PRIu64 ", %" PRIu64 ", %" PRIu64 ", %" PRIu64 ", %" PRIu64 ", %" PRIu64 ", %" PRIu64 ", %" PRIu64 ", %" PRIu64 ", %" PRIu64 ", %" PRIu64 ", %" PRIu64 ", %" PRIu64 ", %" PRIu64 ", %" PRIu64 ",", 
            time, path_id, sequence, (int64_t)highest_ack, high_ack_time, last_time_ack,
            cwin, one_way_delay, rtt_sample, SRTT, RTT_min, bandwidth_estimate, receive_rate_estimate, Send_MTU, pacing_packet_time,
            nb_retrans, nb_spurious, cwin_blkd, flow_blkd, stream_blkd, app_limited, cc_state, cc_param, bw_max, bytes_in_transit) <= 0) {
            ret = -1;
        }
        if (ret != 0 || fprintf(f_csvlog, "\n") <= 0) {
            ret = -1;
        }
    }

    return ret;
}
