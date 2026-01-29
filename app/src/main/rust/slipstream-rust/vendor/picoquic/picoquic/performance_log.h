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
#ifndef PICOQUIC_PERFORMANCE_LOG_H
#define PICOQUIC_PERFORMANCE_LOG_H

#ifdef __cplusplus
extern "C" {
#endif

#define PICOQUIC_PER_LOG_VERSION 1
#define PICOQUIC_PERF_LOG_MAX_ITEMS 27

typedef enum {
    picoquic_perflog_is_client = 0,
    picoquic_perflog_nb_packets_received = 1,
    picoquic_perflog_nb_trains_sent = 2,
    picoquic_perflog_nb_trains_short = 3,
    picoquic_perflog_nb_trains_blocked_cwin = 4,
    picoquic_perflog_nb_trains_blocked_pacing = 5,
    picoquic_perflog_nb_trains_blocked_others = 6,
    picoquic_perflog_nb_packets_sent = 7,
    picoquic_perflog_nb_retransmission_total = 8,
    picoquic_perflog_nb_spurious = 9,
    picoquic_perflog_delayed_ack_option = 10,
    picoquic_perflog_min_ack_delay_remote = 11,
    picoquic_perflog_max_ack_delay_remote = 12,
    picoquic_perflog_max_ack_gap_remote = 13,
    picoquic_perflog_min_ack_delay_local = 14,
    picoquic_perflog_max_ack_delay_local = 15,
    picoquic_perflog_max_ack_gap_local = 16,
    picoquic_perflog_max_mtu_sent = 17,
    picoquic_perflog_max_mtu_received = 18,
    picoquic_perflog_zero_rtt = 19,
    picoquic_perflog_srtt = 20,
    picoquic_perflog_minrtt = 21,
    picoquic_perflog_cwin = 22,
    picoquic_perflog_ccalgo = 23,
    picoquic_perflog_bwe_max = 24,
    picoquic_perflog_pacing_quantum_max = 25,
    picoquic_perflog_pacing_rate = 26
} picoquic_perflog_column_enum;

const char* picoquic_perflog_param_name(picoquic_perflog_column_enum rank);

int picoquic_perflog_setup(picoquic_quic_t* quic, char const* perflog_file_name);

#ifdef __cplusplus
}
#endif
#endif /* PICOQUIC_PERFORMANCE_LOG_H */

