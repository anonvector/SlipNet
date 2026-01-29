/*
* Author: Christian Huitema
* Copyright (c) 2017, Private Octopus, Inc.
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

#include "picoquic_internal.h"
#include <stdlib.h>
#include <string.h>


/* Initialize pacing state to high speed default */
void picoquic_pacing_init(picoquic_pacing_t* pacing, uint64_t current_time)
{
    pacing->evaluation_time = current_time;
    pacing->bucket_nanosec = 16;
    pacing->bucket_max = 16;
    pacing->packet_time_nanosec = 1;
    pacing->packet_time_microsec = 1;
}

/* Update the leaky bucket used for pacing.
*/
static void picoquic_update_pacing_bucket(picoquic_pacing_t* pacing, uint64_t current_time)
{
    if (pacing->bucket_nanosec < -pacing->packet_time_nanosec) {
        pacing->bucket_nanosec = -pacing->packet_time_nanosec;
    }

    if (current_time > pacing->evaluation_time) {
        pacing->bucket_nanosec += (current_time - pacing->evaluation_time) * 1000;
        pacing->evaluation_time = current_time;
        if (pacing->bucket_nanosec > pacing->bucket_max) {
            pacing->bucket_nanosec = pacing->bucket_max;
        }
    }
}

/* Check whether pacing authorizes immediate transmission, 
* no not send any state
 */
int picoquic_is_pacing_blocked(picoquic_pacing_t* pacing)
{
    return (pacing->bucket_nanosec < pacing->packet_time_nanosec);
}

/*
* Check pacing to see whether the next transmission is authorized.
* If if is not, update the next wait time to reflect pacing.
* 
* In packet train mode, the wait will last until the bucket is completely full, or
* if at least N packets are received.
*/
int picoquic_is_authorized_by_pacing(picoquic_pacing_t * pacing, uint64_t current_time, uint64_t * next_time,
    unsigned int packet_train_mode, picoquic_quic_t * quic)
{
    int ret = 1;

    picoquic_update_pacing_bucket(pacing, current_time);

    if (pacing->bucket_nanosec < pacing->packet_time_nanosec) {
        uint64_t next_pacing_time;
        int64_t bucket_required;

        if (packet_train_mode || pacing->bandwidth_pause) {
            bucket_required = pacing->bucket_max;

            if (bucket_required > 10 * pacing->packet_time_nanosec) {
                bucket_required = 10 * pacing->packet_time_nanosec;
            }

            bucket_required -= pacing->bucket_nanosec;
        }
        else {
            bucket_required = pacing->packet_time_nanosec - pacing->bucket_nanosec;
        }

        next_pacing_time = current_time + 1 + bucket_required / 1000;
        if (next_pacing_time < *next_time) {
            pacing->bandwidth_pause = 0;
            *next_time = next_pacing_time;
            if (quic != NULL) {
                SET_LAST_WAKE(quic, PICOQUIC_SENDER);
            }
        }
        ret = 0;
    }

    return ret;
}

/* Report pacing updates if required
 */
static void picoquic_report_pacing_update(picoquic_pacing_t* pacing, picoquic_path_t* path_x)
{
    picoquic_cnx_t* cnx = path_x->cnx;

    if (cnx->is_pacing_update_requested && path_x == cnx->path[0] &&
        cnx->callback_fn != NULL) {
        if ((pacing->rate > cnx->pacing_rate_signalled &&
            (pacing->rate - cnx->pacing_rate_signalled >= cnx->pacing_increase_threshold)) ||
            (pacing->rate < cnx->pacing_rate_signalled &&
                (cnx->pacing_rate_signalled - pacing->rate > cnx->pacing_decrease_threshold))){
            (void)cnx->callback_fn(cnx, pacing->rate, NULL, 0, picoquic_callback_pacing_changed, cnx->callback_ctx, NULL);
            cnx->pacing_rate_signalled = pacing->rate;
        }
    }
    if (cnx->is_path_quality_update_requested &&
        cnx->callback_fn != NULL) {
        /* TODO: add a function "export path quality" */
        /* TODO: remember previous signalled value for change tests */
        if (path_x->smoothed_rtt < path_x->rtt_threshold_low ||
            path_x->smoothed_rtt > path_x->rtt_threshold_high ||
            pacing->rate < path_x->pacing_rate_threshold_low ||
            pacing->rate > path_x->pacing_rate_threshold_high) {
            (void)cnx->callback_fn(cnx, path_x->unique_path_id, NULL, 0, picoquic_callback_path_quality_changed, cnx->callback_ctx, path_x->app_path_ctx);
            picoquic_refresh_path_quality_thresholds(path_x);
        }
    }
}

/* Reset the pacing data after recomputing the pacing rate
*/
void picoquic_update_pacing_parameters(picoquic_pacing_t * pacing, double pacing_rate, uint64_t quantum, size_t send_mtu, uint64_t smoothed_rtt,
    picoquic_path_t * signalled_path)
{
    double packet_time = (double)send_mtu / pacing_rate;
    double quantum_time = (double)quantum / pacing_rate;
    uint64_t rtt_nanosec = smoothed_rtt * 1000;

    pacing->rate = (uint64_t)pacing_rate;

    if (quantum > pacing->quantum_max) {
        pacing->quantum_max = quantum;
    }
    if (pacing->rate > pacing->rate_max) {
        pacing->rate_max = pacing->rate;
    }

    pacing->packet_time_nanosec = (uint64_t)(packet_time * 1000000000.0);

    if (pacing->packet_time_nanosec <= 0) {
        pacing->packet_time_nanosec = 1;
        pacing->packet_time_microsec = 1;
    }
    else {
        if ((uint64_t)pacing->packet_time_nanosec > rtt_nanosec) {
            pacing->packet_time_nanosec = rtt_nanosec;
        }
        pacing->packet_time_microsec = (pacing->packet_time_nanosec + 999ull) / 1000;
    }

    pacing->bucket_max = (uint64_t)(quantum_time * 1000000000.0);
    if (pacing->bucket_max <= 0) {
        pacing->bucket_max = 16 * pacing->packet_time_nanosec;
    }

    if (pacing->bucket_nanosec > pacing->bucket_max) {
        pacing->bucket_nanosec = pacing->bucket_max;
    }

    if (signalled_path != NULL) {
        picoquic_report_pacing_update(pacing, signalled_path);
    }
}

/*
* Reset the pacing data after CWIN is updated.
* The max bucket is set to contain at least 2 packets more than 1/8th of the congestion window.
*/

void picoquic_update_pacing_window(picoquic_pacing_t * pacing, int slow_start, uint64_t cwin, size_t send_mtu, uint64_t smoothed_rtt,
    picoquic_path_t * signalled_path)
{
    uint64_t rtt_nanosec = smoothed_rtt * 1000;

    if ((cwin < ((uint64_t)send_mtu) * 8) || rtt_nanosec <= 1000) {
        /* Small windows, should only relie on ACK clocking */
        pacing->bucket_max = rtt_nanosec;
        pacing->packet_time_nanosec = 1;
        pacing->packet_time_microsec = 1;

        if (pacing->bucket_nanosec > pacing->bucket_max) {
            pacing->bucket_nanosec = pacing->bucket_max;
        }
    }
    else {
        double pacing_rate = ((double)cwin / (double)rtt_nanosec) * 1000000000.0;
        uint64_t quantum = cwin / 4;

        if (quantum < 2ull * send_mtu) {
            quantum = 2ull * send_mtu;
        }
        else {
            if (slow_start && smoothed_rtt > 4*PICOQUIC_MAX_BANDWIDTH_TIME_INTERVAL_MAX) {
                const uint64_t quantum_min = 0x8000;
                if (quantum  < quantum_min){
                    quantum = quantum_min;
                }
                else {
                    uint64_t quantum2 = (uint64_t)((pacing_rate * PICOQUIC_MAX_BANDWIDTH_TIME_INTERVAL_MAX) / 1000000.0);
                    if (quantum2 > quantum) {
                        quantum = quantum2;
                    }
                }
            }
            else if (quantum > 16ull * send_mtu) {
                quantum = 16ull * send_mtu;
            }

        }

        if (slow_start) {
            pacing_rate *= 1.25;
        }
        picoquic_update_pacing_parameters(pacing, pacing_rate, quantum, send_mtu, smoothed_rtt, signalled_path);
    }
}

/* 
* Update the pacing data after sending a packet.
*/
void picoquic_update_pacing_data_after_send(picoquic_pacing_t * pacing, size_t length, size_t send_mtu, uint64_t current_time)
{
    uint64_t packet_time_nanosec;

    picoquic_update_pacing_bucket(pacing, current_time);
    packet_time_nanosec = ((pacing->packet_time_nanosec * (uint64_t)length) + (send_mtu - 1)) / send_mtu;
    pacing->bucket_nanosec -= packet_time_nanosec;
}

/* Interface functions for compatibility with old implementation */
void picoquic_update_pacing_after_send(picoquic_path_t* path_x, size_t length, uint64_t current_time)
{
    picoquic_update_pacing_data_after_send(&path_x->pacing, length, path_x->send_mtu, current_time);
}

int picoquic_is_sending_authorized_by_pacing(picoquic_cnx_t* cnx, picoquic_path_t* path_x, uint64_t current_time, uint64_t* next_time)
{
    return picoquic_is_authorized_by_pacing(&path_x->pacing, current_time, next_time, cnx->quic->packet_train_mode,
        cnx->quic);
}

/* Reset pacing data if congestion algorithm computes it directly */
void picoquic_update_pacing_rate(picoquic_cnx_t* cnx, picoquic_path_t* path_x, double pacing_rate, uint64_t quantum)
{
    picoquic_update_pacing_parameters(&path_x->pacing, pacing_rate,
        quantum, path_x->send_mtu, path_x->smoothed_rtt, path_x);
}
/* Reset pacing if expressed as CWIN and RTT */
void picoquic_update_pacing_data(picoquic_cnx_t* cnx, picoquic_path_t* path_x, int slow_start)
{
    picoquic_update_pacing_window(&path_x->pacing, slow_start, path_x->cwin, path_x->send_mtu, path_x->smoothed_rtt,
        path_x);
}
