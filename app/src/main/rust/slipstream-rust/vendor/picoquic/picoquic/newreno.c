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
#include "cc_common.h"

#define NB_RTT_RENO 4

/* Many congestion control algorithms run a parallel version of new reno in order
 * to provide a lower bound estimate of either the congestion window or the
 * the minimal bandwidth. This implementation of new reno does not directly
 * refer to the connection and path variables (e.g. cwin) but instead sets
 * its entire state in memory.
 */

void picoquic_newreno_sim_reset(picoquic_newreno_sim_state_t * nrss)
{
    /* Initialize the state of the congestion control algorithm */
    memset(nrss, 0, sizeof(picoquic_newreno_sim_state_t));
    nrss->alg_state = picoquic_newreno_alg_slow_start;
    nrss->ssthresh = UINT64_MAX;
    nrss->cwin = PICOQUIC_CWIN_INITIAL;
}

/* The recovery state last 1 RTT, during which parameters will be frozen
 */
static void picoquic_newreno_sim_enter_recovery(
    picoquic_newreno_sim_state_t* nr_state,
    picoquic_cnx_t* cnx,
    picoquic_path_t * path_x,
    picoquic_congestion_notification_t notification,
    uint64_t current_time)
{
    nr_state->ssthresh = nr_state->cwin / 2;
    if (nr_state->ssthresh < PICOQUIC_CWIN_MINIMUM) {
        nr_state->ssthresh = PICOQUIC_CWIN_MINIMUM;
    }

    if (notification == picoquic_congestion_notification_timeout) {
        nr_state->cwin = PICOQUIC_CWIN_MINIMUM;
        nr_state->alg_state = picoquic_newreno_alg_slow_start;
    }
    else {
        nr_state->cwin = nr_state->ssthresh;
        nr_state->alg_state = picoquic_newreno_alg_congestion_avoidance;
    }

    nr_state->recovery_start = current_time;
    nr_state->recovery_sequence = picoquic_cc_get_sequence_number(cnx, path_x);
    nr_state->residual_ack = 0;
}

/* Update cwin per signaled bandwidth
 */
static void picoquic_newreno_sim_seed_cwin(picoquic_newreno_sim_state_t* nr_state,
    picoquic_path_t* path_x, uint64_t bytes_in_flight)
{
    if (nr_state->alg_state == picoquic_newreno_alg_slow_start &&
        nr_state->ssthresh == UINT64_MAX) {
        if (bytes_in_flight > nr_state->cwin) {
            nr_state->cwin = bytes_in_flight;
            nr_state->ssthresh = bytes_in_flight;
            nr_state->alg_state = picoquic_newreno_alg_congestion_avoidance;
        }
    }
}


/* Notification API for new Reno simulations.
 */
void picoquic_newreno_sim_notify(
    picoquic_newreno_sim_state_t* nr_state,
    picoquic_cnx_t* cnx,
    picoquic_path_t* path_x,
    picoquic_congestion_notification_t notification,
    picoquic_per_ack_state_t * ack_state,
    uint64_t current_time)
{
    switch (notification) {
    case picoquic_congestion_notification_acknowledgement: {
        switch (nr_state->alg_state) {
        case picoquic_newreno_alg_slow_start:
            nr_state->cwin += ack_state->nb_bytes_acknowledged;
            /* if cnx->cwin exceeds SSTHRESH, exit and go to CA */
            if (nr_state->cwin >= nr_state->ssthresh) {
                nr_state->alg_state = picoquic_newreno_alg_congestion_avoidance;
            }
            break;
        case picoquic_newreno_alg_congestion_avoidance:
        default: {
            uint64_t complete_delta = ack_state->nb_bytes_acknowledged * path_x->send_mtu + nr_state->residual_ack;
            nr_state->residual_ack = complete_delta % nr_state->cwin;
            nr_state->cwin += complete_delta / nr_state->cwin;
            break;
        }
        }
        break;
    }
    case picoquic_congestion_notification_ecn_ec:
    case picoquic_congestion_notification_repeat:
    case picoquic_congestion_notification_timeout:
        /* if the loss happened in this period, enter recovery */
        if (nr_state->recovery_sequence <= ack_state->lost_packet_number) {
            picoquic_newreno_sim_enter_recovery(nr_state, cnx, path_x, notification, current_time);
        }
        break;
    case picoquic_congestion_notification_spurious_repeat:
        if (!cnx->is_multipath_enabled) {
            if (current_time - nr_state->recovery_start < path_x->smoothed_rtt &&
                nr_state->recovery_sequence > picoquic_cc_get_ack_number(cnx, path_x)) {
                /* If spurious repeat of initial loss detected,
                 * exit recovery and reset threshold to pre-entry cwin.
                 */
                if (nr_state->ssthresh != UINT64_MAX &&
                    nr_state->cwin < 2 * nr_state->ssthresh) {
                    nr_state->cwin = 2 * nr_state->ssthresh;
                    nr_state->alg_state = picoquic_newreno_alg_congestion_avoidance;
                }
            }
        }
        else {
            if (current_time - nr_state->recovery_start < path_x->smoothed_rtt &&
                nr_state->recovery_start > picoquic_cc_get_ack_sent_time(cnx, path_x)) {
                /* If spurious repeat of initial loss detected,
                 * exit recovery and reset threshold to pre-entry cwin.
                 */
                if (nr_state->ssthresh != UINT64_MAX &&
                    nr_state->cwin < 2 * nr_state->ssthresh) {
                    nr_state->cwin = 2 * nr_state->ssthresh;
                    nr_state->alg_state = picoquic_newreno_alg_congestion_avoidance;
                }
            }
        }
        break;
    case picoquic_congestion_notification_reset:
        picoquic_newreno_sim_reset(nr_state);
        break;
    case picoquic_congestion_notification_seed_cwin:
        picoquic_newreno_sim_seed_cwin(nr_state, path_x, ack_state->nb_bytes_acknowledged);
        break;
    default:
        /* ignore */
        break;
    }
}


/* Actual implementation of New Reno, when used as a stand alone algorithm
 */

typedef struct st_picoquic_newreno_state_t {
    picoquic_newreno_sim_state_t nrss;
    picoquic_min_max_rtt_t rtt_filter;
} picoquic_newreno_state_t;

static void picoquic_newreno_reset(picoquic_newreno_state_t* nr_state, picoquic_path_t* path_x)
{
    memset(nr_state, 0, sizeof(picoquic_newreno_state_t));
    picoquic_newreno_sim_reset(&nr_state->nrss);
    path_x->cwin = nr_state->nrss.cwin;
}

static void picoquic_newreno_init(picoquic_cnx_t * cnx, picoquic_path_t* path_x, uint64_t current_time)
{
    /* Initialize the state of the congestion control algorithm */
    picoquic_newreno_state_t* nr_state = (picoquic_newreno_state_t*)malloc(sizeof(picoquic_newreno_state_t));
#ifdef _WINDOWS
    UNREFERENCED_PARAMETER(current_time);
    UNREFERENCED_PARAMETER(cnx);
#endif

    if (nr_state != NULL) {
        picoquic_newreno_reset(nr_state, path_x);
        path_x->congestion_alg_state = nr_state;
    }
    else {
        path_x->congestion_alg_state = NULL;
    }
}

/*
 * Properly implementing New Reno requires managing a number of
 * signals, such as packet losses or acknowledgements. We attempt
 * to condensate all that in a single API, which could be shared
 * by many different congestion control algorithms.
 */
static void picoquic_newreno_notify(
    picoquic_cnx_t * cnx,
    picoquic_path_t* path_x,
    picoquic_congestion_notification_t notification,
    picoquic_per_ack_state_t * ack_state,
    uint64_t current_time)
{
    picoquic_newreno_state_t* nr_state = (picoquic_newreno_state_t*)path_x->congestion_alg_state;

    path_x->is_cc_data_updated = 1;

    if (nr_state != NULL) {
        switch (notification) {
        case picoquic_congestion_notification_acknowledgement:
            if (nr_state->nrss.alg_state == picoquic_newreno_alg_slow_start &&
                nr_state->nrss.ssthresh == UINT64_MAX) {
                /* RTT measurements will happen before acknowledgement is signalled */
                uint64_t max_win = path_x->peak_bandwidth_estimate * path_x->smoothed_rtt / 1000000;
                uint64_t min_win = max_win /= 2;
                if (nr_state->nrss.cwin < min_win) {
                    nr_state->nrss.cwin = min_win;
                    path_x->cwin = min_win;
                }
            }

            if (path_x->last_time_acked_data_frame_sent > path_x->last_sender_limited_time) {
                picoquic_newreno_sim_notify(&nr_state->nrss, cnx, path_x, notification, ack_state, current_time);
                path_x->cwin = nr_state->nrss.cwin;
            }
            break;
        case picoquic_congestion_notification_seed_cwin:
        case picoquic_congestion_notification_ecn_ec:
        case picoquic_congestion_notification_repeat:
        case picoquic_congestion_notification_timeout:
            picoquic_newreno_sim_notify(&nr_state->nrss, cnx, path_x, notification, ack_state, current_time);
            path_x->cwin = nr_state->nrss.cwin;
            break;
        case picoquic_congestion_notification_spurious_repeat:
            picoquic_newreno_sim_notify(&nr_state->nrss, cnx, path_x, notification, ack_state, current_time);
            path_x->cwin = nr_state->nrss.cwin;
            path_x->is_ssthresh_initialized = 1;
            break;
        case picoquic_congestion_notification_rtt_measurement:
            /* Using RTT increases as signal to get out of initial slow start */
            if (nr_state->nrss.alg_state == picoquic_newreno_alg_slow_start &&
                nr_state->nrss.ssthresh == UINT64_MAX){

                if (path_x->rtt_min > PICOQUIC_TARGET_RENO_RTT) {
                    uint64_t min_win;

                    if (path_x->rtt_min > PICOQUIC_TARGET_SATELLITE_RTT) {
                        min_win = (uint64_t)((double)PICOQUIC_CWIN_INITIAL * (double)PICOQUIC_TARGET_SATELLITE_RTT / (double)PICOQUIC_TARGET_RENO_RTT);
                    }
                    else {
                        /* Increase initial CWIN for long delay links. */
                        min_win = (uint64_t)((double)PICOQUIC_CWIN_INITIAL * (double)path_x->rtt_min / (double)PICOQUIC_TARGET_RENO_RTT);
                    }
                    if (min_win > nr_state->nrss.cwin) {
                        nr_state->nrss.cwin = min_win;
                        path_x->cwin = min_win;
                    }
                }

                if (picoquic_hystart_test(&nr_state->rtt_filter, (cnx->is_time_stamp_enabled) ? ack_state->one_way_delay : ack_state->rtt_measurement,
                    cnx->path[0]->pacing.packet_time_microsec, current_time,
                    cnx->is_time_stamp_enabled)) {
                    /* RTT increased too much, get out of slow start! */
                    nr_state->nrss.ssthresh = nr_state->nrss.cwin;
                    nr_state->nrss.alg_state = picoquic_newreno_alg_congestion_avoidance;
                    path_x->cwin = nr_state->nrss.cwin;
                    path_x->is_ssthresh_initialized = 1;
                }
            }
            break;
        case picoquic_congestion_notification_cwin_blocked:
            break;
        case picoquic_congestion_notification_reset:
            picoquic_newreno_reset(nr_state, path_x);
            break;
        default:
            /* ignore */
            break;
        }

        /* Compute pacing data */
        picoquic_update_pacing_data(cnx, path_x, nr_state->nrss.alg_state == picoquic_newreno_alg_slow_start &&
            nr_state->nrss.ssthresh == UINT64_MAX);
    }
}

/* Release the state of the congestion control algorithm */
static void picoquic_newreno_delete(picoquic_path_t* path_x)
{
    if (path_x->congestion_alg_state != NULL) {
        free(path_x->congestion_alg_state);
        path_x->congestion_alg_state = NULL;
    }
}

/* Observe the state of congestion control */

void picoquic_newreno_observe(picoquic_path_t* path_x, uint64_t* cc_state, uint64_t* cc_param)
{
    picoquic_newreno_state_t* nr_state = (picoquic_newreno_state_t*)path_x->congestion_alg_state;
    *cc_state = (uint64_t)nr_state->nrss.alg_state;
    *cc_param = (nr_state->nrss.ssthresh == UINT64_MAX) ? 0 : nr_state->nrss.ssthresh;
}

/* Definition record for the New Reno algorithm */

#define PICOQUIC_NEWRENO_ID "newreno" /* NR88 */

picoquic_congestion_algorithm_t picoquic_newreno_algorithm_struct = {
    PICOQUIC_NEWRENO_ID, PICOQUIC_CC_ALGO_NUMBER_NEW_RENO,
    picoquic_newreno_init,
    picoquic_newreno_notify,
    picoquic_newreno_delete,
    picoquic_newreno_observe
};

picoquic_congestion_algorithm_t* picoquic_newreno_algorithm = &picoquic_newreno_algorithm_struct;
