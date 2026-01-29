/*
* Author: Christian Huitema
* Copyright (c) 2023, Private Octopus, Inc.
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
#include "picoquic_unified_log.h"
#include "tls_api.h"
#include <stdlib.h>
#include <string.h>

/* Management of time: estimate of round trip time, variations, etc.
 * Computation of PTO, RTO.
 */


 /*
 * If a retransmit is needed, fill the packet with the required
 * retransmission. Also, prune the retransmit queue as needed.
 *
 * TODO: consider that the retransmit timer is per path, from the path on
 * which the packet was first sent, but the retransmission may be on 
 * a different path, with different MTU.
 */

uint64_t picoquic_current_retransmit_timer(picoquic_cnx_t* cnx, picoquic_path_t * path_x)
{
    uint64_t rto = path_x->retransmit_timer;

    if (path_x->nb_retransmit > 0) {
        if (path_x->nb_retransmit < 3) {
            rto <<= path_x->nb_retransmit;
        }
        else {
            uint64_t n1 = path_x->nb_retransmit - 2;
            if (n1 > 18) {
                n1 = 18;
            }
            rto <<= (2 + (n1 / 4));
            n1 &= 3;
            rto += (n1*rto) >> 2;
        }
        if (cnx->idle_timeout > 15) {
            if (rto > (cnx->idle_timeout >> 4)) {
                rto = cnx->idle_timeout >> 4;
            }
        }
    }

    if (cnx->cnx_state < picoquic_state_client_ready_start) {
        if (PICOQUIC_MICROSEC_HANDSHAKE_MAX / 1000 < cnx->local_parameters.max_idle_timeout) {
            /* Special case of very long delays */
            rto = path_x->retransmit_timer << path_x->nb_retransmit;
            if (rto > cnx->local_parameters.max_idle_timeout * 100) {
                rto = cnx->local_parameters.max_idle_timeout * 100;
            }
        } else if (rto > PICOQUIC_INITIAL_MAX_RETRANSMIT_TIMER) {
            rto = PICOQUIC_INITIAL_MAX_RETRANSMIT_TIMER;
        }
    }
    else if (rto > PICOQUIC_LARGE_RETRANSMIT_TIMER){
        uint64_t alt_rto = PICOQUIC_LARGE_RETRANSMIT_TIMER;
        if (path_x->rtt_min > PICOQUIC_TARGET_SATELLITE_RTT) {
            alt_rto = (path_x->smoothed_rtt * 3) >> 1;
        }
        if (alt_rto < rto) {
            rto = alt_rto;
        }
    }

    return rto;
}

/* The BDP seed is validated upon receiving the first RTT measurement */
static void picoquic_validate_bdp_seed(picoquic_cnx_t* cnx, picoquic_path_t* path_x, uint64_t rtt_sample, uint64_t current_time)
{
    if (path_x == cnx->path[0] && cnx->seed_cwin != 0 &&
        !cnx->cwin_notified_from_seed){
        uint64_t rtt_margin = rtt_sample / 4;
        if (cnx->seed_rtt_min >= rtt_sample - rtt_margin &&
            cnx->seed_rtt_min <= rtt_sample + rtt_margin) {
            uint8_t* ip_addr;
            uint8_t ip_addr_length;
            picoquic_get_ip_addr((struct sockaddr*)&path_x->peer_addr, &ip_addr, &ip_addr_length);

            if (ip_addr_length == cnx->seed_ip_addr_length &&
                memcmp(ip_addr, cnx->seed_ip_addr, ip_addr_length) == 0) {
                picoquic_per_ack_state_t ack_state = { 0 };
                ack_state.nb_bytes_acknowledged = (uint64_t)cnx->seed_cwin;
                cnx->cwin_notified_from_seed = 1;
                cnx->congestion_alg->alg_notify(cnx, path_x,
                    picoquic_congestion_notification_seed_cwin,
                    &ack_state, current_time);
            }
        }
    }
}


/* Update one way delays, which can be used for example to properly exit
* slow start in high-start mode. The code assume that path and samples are set properly,
* and that the ack delay has been validated
*/

void picoquic_update_path_rtt_one_way(picoquic_cnx_t* cnx, picoquic_path_t* old_path, picoquic_path_t* path_x,
    uint64_t send_time, uint64_t current_time, uint64_t ack_delay, uint64_t time_stamp)
{
    if (time_stamp != 0) {
        /* If the phase is not yet known, it should be set. */
        if (cnx->phase_delay == INT64_MAX) {
            cnx->phase_delay = old_path->rtt_sample / 2;

            if (!cnx->client_mode) {
                cnx->phase_delay = -cnx->phase_delay;
            }
        }
        /* TODO: some check on the validity of the one way delay */
        int64_t time_stamp_local = time_stamp - ack_delay + cnx->start_time + cnx->phase_delay;
        int is_time_stamp_valid = 1;

        /* The computation may indicate that the "local" value of the ack-stamping time
        * was earlier than the send time of the packet, or later than the current time.
        * This cannot happen, of course, which means that either the ack delay or
        * the phase estimate is wrong.
        */
        if (time_stamp_local < 0 || (uint64_t)time_stamp_local < send_time) {
            int64_t min_phase = send_time - time_stamp + ack_delay - cnx->start_time;
            time_stamp_local = time_stamp - ack_delay + cnx->start_time + min_phase;
            if (time_stamp_local > 0 && (uint64_t)time_stamp_local <= current_time) {
                /* looks plausible -- the computed stamp is earlier than now. */
                cnx->phase_delay = min_phase;
            }
            else {
                is_time_stamp_valid = 0;
            }
        }
        else if ((uint64_t)time_stamp_local > current_time) {
            int64_t max_phase = current_time - time_stamp + ack_delay - cnx->start_time;
            time_stamp_local = time_stamp - ack_delay + cnx->start_time + max_phase;
            if (time_stamp_local > 0 && (uint64_t)time_stamp_local >= send_time) {
                /* looks plausible -- the computed stamp is earlier than now. */
                cnx->phase_delay = max_phase;
            }
            else {
                is_time_stamp_valid = 0;
            }
        }
        if (is_time_stamp_valid) {
            old_path->one_way_delay_sample = time_stamp_local - send_time;
        }
        else {
            old_path->nb_delay_outliers++;
        }
    }
}


/* The RTT computation algorithm separates RTT computation from one way delay computations,
* using a straightforward averaging method even in multipath scenarios. It also tries to
* pace computation of averages and variants, so that average delays and variations are
* computed just a few times per round trip.
*/
void picoquic_update_path_rtt(picoquic_cnx_t* cnx, picoquic_path_t* old_path, picoquic_path_t* path_x, int epoch,
    uint64_t send_time, uint64_t current_time, uint64_t ack_delay, uint64_t time_stamp)
{
    if (old_path != NULL && (!old_path->rtt_is_initialized || epoch >= 0)) {
        uint64_t rtt_estimate = 0;
        int is_first = !old_path->rtt_is_initialized;
        picoquic_packet_context_t* pkt_ctx = NULL;
        if (cnx->is_multipath_enabled) {
            pkt_ctx = &old_path->pkt_ctx;
        }
        else if (epoch == picoquic_epoch_1rtt || epoch == picoquic_epoch_0rtt) {
            pkt_ctx = &cnx->pkt_ctx[picoquic_packet_context_application];
        }

        if (current_time > send_time) {
            rtt_estimate = current_time - send_time;
            /* We cannot blindly trust the ack delay,
             * and especially not for the first sample */
            if (!is_first && ack_delay > 0 && cnx->cnx_state >= picoquic_state_ready) {
                if (ack_delay > cnx->local_parameters.max_ack_delay) {
                    ack_delay = cnx->local_parameters.max_ack_delay;
                }
                if (old_path->rtt_min + ack_delay < rtt_estimate) {
                    rtt_estimate -= ack_delay;
                }
            }
        }
        old_path->rtt_sample = rtt_estimate;
        /* During a measurement period, accumulate data:
        * - number of estimates since update
        * - sum of all estimates since update
        * - min estimate
        * - max estimate
        * If the PTO is lower than the max estimate, increase it.
        * If the min RTT is lower than the current low, lower it.
        */
        old_path->nb_rtt_estimate_in_period += 1;
        old_path->sum_rtt_estimate_in_period += rtt_estimate;
        if (old_path->nb_rtt_estimate_in_period == 1) {
            old_path->min_rtt_estimate_in_period = rtt_estimate;
            old_path->max_rtt_estimate_in_period = rtt_estimate;
        }
        else {
            if (rtt_estimate > old_path->max_rtt_estimate_in_period) {
                old_path->max_rtt_estimate_in_period = rtt_estimate;
            }
            if (rtt_estimate < old_path->min_rtt_estimate_in_period) {
                old_path->min_rtt_estimate_in_period = rtt_estimate;
            }
        }
        if (old_path->retransmit_timer < rtt_estimate) {
            old_path->retransmit_timer = rtt_estimate;
        }
        if (old_path->rtt_min > rtt_estimate) {
            old_path->rtt_min = rtt_estimate;
        }
        if (old_path->rtt_max < rtt_estimate) {
            old_path->rtt_max = rtt_estimate;
        }

        /* if one way delay measured, use it */
        if (time_stamp > 0) {
            picoquic_update_path_rtt_one_way(cnx, old_path, path_x, send_time, current_time, ack_delay, time_stamp);
        }
        /* At the end of the period, update the smoothed and variants statistics.
        */
        if (pkt_ctx == NULL || pkt_ctx->highest_acknowledged > old_path->rtt_packet_previous_period ||
            old_path->rtt_time_previous_period + (rtt_estimate / 4) > current_time) {
            old_path->rtt_time_previous_period = current_time;

            if (old_path->nb_rtt_estimate_in_period > 1) {
                rtt_estimate = old_path->sum_rtt_estimate_in_period / old_path->nb_rtt_estimate_in_period;
            }

            if (is_first) {
                old_path->smoothed_rtt = rtt_estimate;
                old_path->rtt_variant = rtt_estimate / 2;
                old_path->rtt_min = old_path->min_rtt_estimate_in_period;
                old_path->rtt_is_initialized = 1;
            }
            else {
                /* use the average of all samples to adjust the average */
                /* use the lowest and highest samples in the period to adjust the variant */
                uint64_t rtt_var_sample = 0;
                if (old_path->smoothed_rtt > old_path->max_rtt_estimate_in_period) {
                    rtt_var_sample = old_path->smoothed_rtt - old_path->min_rtt_estimate_in_period;
                }
                else if (old_path->smoothed_rtt < old_path->min_rtt_estimate_in_period) {
                    rtt_var_sample = old_path->max_rtt_estimate_in_period - old_path->smoothed_rtt;
                }
                else {
                    uint64_t rtt_var_sample_min = old_path->smoothed_rtt - old_path->min_rtt_estimate_in_period;

                    rtt_var_sample = old_path->max_rtt_estimate_in_period - old_path->smoothed_rtt;
                    if (rtt_var_sample_min > rtt_var_sample) {
                        rtt_var_sample = rtt_var_sample_min;
                    }
                }
                old_path->rtt_variant = (3 * old_path->rtt_variant + rtt_var_sample) / 4;
                old_path->smoothed_rtt = (7 * old_path->smoothed_rtt + rtt_estimate) / 8;
            }
            old_path->retransmit_timer = old_path->smoothed_rtt + 3 * old_path->rtt_variant +
                cnx->remote_parameters.max_ack_delay;

            /* if RTT updated, reset delayed ACK parameters */
            if (old_path == cnx->path[0] && cnx->cnx_state >= picoquic_state_ready) {
                cnx->is_ack_frequency_updated = cnx->is_ack_frequency_negotiated;
                if (!cnx->is_ack_frequency_negotiated || cnx->cnx_state != picoquic_state_ready) {
                    picoquic_compute_ack_gap_and_delay(cnx, cnx->path[0]->rtt_min, PICOQUIC_ACK_DELAY_MIN,
                        cnx->path[0]->receive_rate_max, &cnx->ack_gap_remote, &cnx->ack_delay_remote);
                }
            }

            /* reset the period counters */
            if (pkt_ctx != NULL) {
                old_path->rtt_packet_previous_period = pkt_ctx->highest_acknowledged;
            }
            old_path->nb_rtt_estimate_in_period = 0;
            old_path->sum_rtt_estimate_in_period = 0;
            old_path->max_rtt_estimate_in_period = 0;
            old_path->min_rtt_estimate_in_period = UINT64_MAX;
        }

        /* Pass the new values to the congestion algorithm */
        if (cnx->congestion_alg != NULL) {
            picoquic_per_ack_state_t ack_state = { 0 };
            ack_state.rtt_measurement = rtt_estimate;
            ack_state.one_way_delay = (cnx->is_time_stamp_enabled) ? old_path->one_way_delay_sample : 0;
            cnx->congestion_alg->alg_notify(cnx, old_path,
                picoquic_congestion_notification_rtt_measurement,
                &ack_state, current_time);
        }

        /* On very first sample, apply the saved BDP */
        if (is_first) {
            picoquic_validate_bdp_seed(cnx, old_path, rtt_estimate, current_time);
        }
        /* Perform a quality changed callback if needed */
        (void)picoquic_issue_path_quality_update(cnx, old_path);
    }
}