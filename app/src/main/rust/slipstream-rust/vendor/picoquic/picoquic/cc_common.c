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

#include "picoquic_internal.h"
#include <stdlib.h>
#include <string.h>
#include "cc_common.h"

uint64_t picoquic_cc_get_sequence_number(picoquic_cnx_t* cnx, picoquic_path_t* path_x)
{
    uint64_t sequence_number;

    if (cnx->is_multipath_enabled) {
            sequence_number = path_x->pkt_ctx.send_sequence;
        }
    else {
       sequence_number = cnx->pkt_ctx[picoquic_packet_context_application].send_sequence;
    }
    return sequence_number;
}

uint64_t picoquic_cc_get_ack_number(picoquic_cnx_t* cnx, picoquic_path_t* path_x)
{
    uint64_t highest_acknowledged;

    if (cnx->is_multipath_enabled) {
        highest_acknowledged = path_x->pkt_ctx.highest_acknowledged;
    }
    else {
        highest_acknowledged = cnx->pkt_ctx[picoquic_packet_context_application].highest_acknowledged;
    }
    return highest_acknowledged;
}

uint64_t picoquic_cc_get_ack_sent_time(picoquic_cnx_t* cnx, picoquic_path_t* path_x)
{
    uint64_t latest_time_acknowledged;

    if (cnx->is_multipath_enabled) {
        latest_time_acknowledged = path_x->pkt_ctx.latest_time_acknowledged;
    }
    else {
        latest_time_acknowledged = cnx->pkt_ctx[picoquic_packet_context_application].latest_time_acknowledged;
    }
    return latest_time_acknowledged;
}


void picoquic_filter_rtt_min_max(picoquic_min_max_rtt_t * rtt_track, uint64_t rtt)
{
    int x = rtt_track->sample_current;
    int x_max;


    rtt_track->samples[x] = rtt;

    rtt_track->sample_current = x + 1;
    if (rtt_track->sample_current >= PICOQUIC_MIN_MAX_RTT_SCOPE) {
        rtt_track->is_init = 1;
        rtt_track->sample_current = 0;
    }
    
    x_max = (rtt_track->is_init) ? PICOQUIC_MIN_MAX_RTT_SCOPE : x + 1;

    rtt_track->sample_min = rtt_track->samples[0];
    rtt_track->sample_max = rtt_track->samples[0];

    for (int i = 1; i < x_max; i++) {
        if (rtt_track->samples[i] < rtt_track->sample_min) {
            rtt_track->sample_min = rtt_track->samples[i];
        } else if (rtt_track->samples[i] > rtt_track->sample_max) {
            rtt_track->sample_max = rtt_track->samples[i];
        }
    }
}

int picoquic_hystart_loss_test(picoquic_min_max_rtt_t* rtt_track, picoquic_congestion_notification_t event,
    uint64_t lost_packet_number, double error_rate_max)
{
    int ret = 0;
    uint64_t next_number = rtt_track->last_lost_packet_number;

    if (lost_packet_number > next_number) {
        if (next_number + PICOQUIC_SMOOTHED_LOSS_SCOPE < lost_packet_number) {
            next_number = lost_packet_number - PICOQUIC_SMOOTHED_LOSS_SCOPE;
        }

        while (next_number < lost_packet_number) {
            rtt_track->smoothed_drop_rate *= (1.0 - PICOQUIC_SMOOTHED_LOSS_FACTOR);
            next_number++;
        }

        rtt_track->smoothed_drop_rate += (1.0 - rtt_track->smoothed_drop_rate) * PICOQUIC_SMOOTHED_LOSS_FACTOR;
        rtt_track->last_lost_packet_number = lost_packet_number;

        switch (event) {
        case picoquic_congestion_notification_repeat:
            ret = rtt_track->smoothed_drop_rate > error_rate_max;
            break;
        case picoquic_congestion_notification_timeout:
            ret = 1;
        default:
            break;
        }
    }

    return ret;
}

int picoquic_hystart_loss_volume_test(picoquic_min_max_rtt_t* rtt_track, picoquic_congestion_notification_t event,  uint64_t nb_bytes_newly_acked, uint64_t nb_bytes_newly_lost)
{
    int ret = 0;

    rtt_track->smoothed_bytes_lost_16 -= rtt_track->smoothed_bytes_lost_16 / 16;
    rtt_track->smoothed_bytes_lost_16 += nb_bytes_newly_lost;
    rtt_track->smoothed_bytes_sent_16 -= rtt_track->smoothed_bytes_sent_16 / 16;
    rtt_track->smoothed_bytes_sent_16 += nb_bytes_newly_acked + nb_bytes_newly_lost;

    if (rtt_track->smoothed_bytes_sent_16 > 0) {
        rtt_track->smoothed_drop_rate = ((double)rtt_track->smoothed_bytes_lost_16) / ((double)rtt_track->smoothed_bytes_sent_16);
    }
    else {
        rtt_track->smoothed_drop_rate = 0;
    }

    switch (event) {
    case picoquic_congestion_notification_acknowledgement:
        ret = rtt_track->smoothed_drop_rate > PICOQUIC_SMOOTHED_LOSS_THRESHOLD;
        break;
    case picoquic_congestion_notification_timeout:
        ret = 1;
    default:
        break;
    }

    return ret;
}

int picoquic_hystart_test(picoquic_min_max_rtt_t* rtt_track, uint64_t rtt_measurement, uint64_t packet_time, uint64_t current_time, int is_one_way_delay_enabled)
{
    int ret = 0;

    if(current_time > rtt_track->last_rtt_sample_time + 1000) {
        picoquic_filter_rtt_min_max(rtt_track, rtt_measurement);
        rtt_track->last_rtt_sample_time = current_time;

        if (rtt_track->is_init) {
            uint64_t delta_max;

            if (rtt_track->rtt_filtered_min == 0 ||
                rtt_track->rtt_filtered_min > rtt_track->sample_max) {
                rtt_track->rtt_filtered_min = rtt_track->sample_max;
            }
            delta_max = rtt_track->rtt_filtered_min / 4;

            if (rtt_track->sample_min > rtt_track->rtt_filtered_min) {
                if (rtt_track->sample_min > rtt_track->rtt_filtered_min + delta_max) {
                    rtt_track->nb_rtt_excess++;
                    if (rtt_track->nb_rtt_excess >= PICOQUIC_MIN_MAX_RTT_SCOPE) {
                        /* RTT increased too much, get out of slow start! */
                        ret = 1;
                    }
                }
            }
            else {
                rtt_track->nb_rtt_excess = 0;
            }
        }
    }

    return ret;
}

void picoquic_hystart_increase(picoquic_path_t * path_x, picoquic_min_max_rtt_t* rtt_filter, uint64_t nb_delivered)
{
    path_x->cwin += nb_delivered;
}

uint64_t picoquic_cc_increased_window(picoquic_cnx_t* cnx, uint64_t previous_window)
{
    uint64_t new_window;
    if (cnx->path[0]->rtt_min <= PICOQUIC_TARGET_RENO_RTT) {
        new_window = previous_window * 2;
    }
    else {
        double w = (double)previous_window;
        w /= (double)PICOQUIC_TARGET_RENO_RTT;
        w *= (cnx->path[0]->rtt_min > PICOQUIC_TARGET_SATELLITE_RTT)? PICOQUIC_TARGET_SATELLITE_RTT: cnx->path[0]->rtt_min;
        new_window = (uint64_t)w;
    }
    return new_window;
}