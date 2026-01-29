/*
* Author: Christian Huitema
* Copyright (c) 2022, Private Octopus, Inc.
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
* 
* This code is derived in part from the initial implementation of the prague
* algorithm in picoquic, written in 2019 by by Quentin De Coninck.
*/

#include "picoquic_internal.h"
#include <stdlib.h>
#include <string.h>
#include "cc_common.h"

/*
 * We implement here the Prague algorithm as a simple modification of New Reno,
 * with the following changes:
 * 
 * - maintain a coefficient "alpha", exponentially smoothed value of "frac", the
 *   fraction of EC/(ECT+ECT1) notifications in previous RTT.
 *       As a slight deviation from the base prague specification, we set
 *       alpha to frac if frac is more than alpha + 0.5. This addresses the
 *       issue of sudden onset of congestion.
 * - modify HyStart to not exit immediately on ECN notification
 * - use alpha in New Reno: control amount of window increase or decrease, as
 *   in Prague spec.
 * - reset the L3S computation on "enter_recovery". This is a useful but
 *   imperfect attempt at avoiding "double dipping".
 * 
 */

/* Observations and issues:
 *
 * Exit hystart one RTT too late. Hystart ends when the first EC markings appear.
 * These are the marks cause by traffic of epoch N-1. The traffic of epoch N
 * is already in flight, will cause congestion and losses. Increasing 
 * the pacing rate or the quantum value does cause an earlier exit from
 * slow start, but the window ends up too small -- maybe due to the
 * redundant loss signal mentioned above.
 * 
 * Window shrinking after idle. There are no data in flight at the beginning
 * of the epoch. The leaky-bucket based pacing allows a quick initial flight
 * to come in. The queue increases, many packets are marked. As a consequence,
 * the window shrinks, even in the absence of losses.
 * 
 * This variant overrides the smoothing if there are sudden onset of marks.
 * Not doing that improves performance, but also causes a sharp increase in
 * the number of losses.
 * 
 * Redundant loss signals. Marks are detected at epoch[N]. Very likely, this 
 * correlates with losses one RTO timer later. The window shrunk once because
 * of the marks, shrinks again when the loss happens -- value is then too low.
 * Something similar happens in the other direction as well. Slow start exits
 * due to increased delays, observed before the end of the epoch. Shortly
 * after that, congestion marks are reported at end of epoch, causing window
 * to shrink further. Same could happen if losses are observed, followed
 * by CE marks. This is mitigated by restarting the L4S computation after
 * slow start, but the mitigation is not sufficient. It would be better
 * to wait for the a full RTT, so packets sent with excessive rate are
 * purged from the queue.
 * 
 * Correlated CE marks. If CE marks happen at epoch N, the traffic in flight
 * correpond to the old window, before the window is reduced. CE marks will
 * very likely be detected in next window, causing too much reduction. This
 * effect is much reduced if dirctly using "frac" instead of computing "alpha".
 * 
 * L4S threshold is hard to set for the AQM. Too low, and the throughput
 * drops. Too high, and the amount of losses increases too much. In the
 * tests, the threshold is set approximately BDP/4. This may be dues to
 * inefficient solutions of the issues mentioned above.
 */

#include "picoquic_internal.h"
#include <stdlib.h>
#include <string.h>

typedef enum {
    picoquic_prague_alg_slow_start = 0,
    picoquic_prague_alg_congestion_avoidance
} picoquic_prague_alg_state_t;

#define NB_RTT_RENO 4
#define PRAGUE_SHIFT_G 4 /* g = 1/2^4, gain parameter for alpha EWMA */
#define PRAGUE_G_INV (1<<PRAGUE_SHIFT_G)

typedef struct st_picoquic_prague_state_t {
    picoquic_prague_alg_state_t alg_state;
    // double alpha;
    uint64_t alpha_shifted;
    uint64_t alpha;
    uint64_t residual_ack;
    uint64_t ssthresh;
    uint64_t recovery_start;
    uint64_t l4s_update_sent;
    uint64_t l4s_epoch_send;
    uint64_t l4s_epoch_ect1;
    uint64_t l4s_epoch_ce;
    picoquic_min_max_rtt_t rtt_filter;
} picoquic_prague_state_t;

static void picoquic_prague_init_reno(picoquic_prague_state_t* pr_state, picoquic_path_t* path_x)
{
    pr_state->alg_state = picoquic_prague_alg_slow_start;
    pr_state->ssthresh = UINT64_MAX;
    pr_state->alpha = 0;
    path_x->cwin = PICOQUIC_CWIN_INITIAL;
}

void picoquic_prague_init(picoquic_cnx_t * cnx, picoquic_path_t* path_x, uint64_t current_time)
{
    /* Initialize the state of the congestion control algorithm */
    picoquic_prague_state_t* pr_state = (picoquic_prague_state_t*)malloc(sizeof(picoquic_prague_state_t));
#ifdef _WINDOWS
    UNREFERENCED_PARAMETER(cnx);
#endif

    if (pr_state != NULL) {
        memset(pr_state, 0, sizeof(picoquic_prague_state_t));
        path_x->congestion_alg_state = (void*)pr_state;
        picoquic_prague_init_reno(pr_state, path_x);
    }
    else {
        path_x->congestion_alg_state = NULL;
    }
}

static picoquic_packet_context_t* picoquic_prague_get_pkt_ctx(picoquic_cnx_t* cnx,  picoquic_path_t* path_x)
{
    picoquic_packet_context_t* pkt_ctx = &cnx->pkt_ctx[picoquic_packet_context_application];

    /* Reset the L3S measurement context to the current value */
    if (cnx->is_multipath_enabled) {
        pkt_ctx = &path_x->pkt_ctx;
    }

    return pkt_ctx;
}


static void picoquic_prague_reset_l3s(picoquic_cnx_t* cnx, picoquic_prague_state_t* pr_state, picoquic_path_t* path_x)
{
    picoquic_packet_context_t* pkt_ctx = picoquic_prague_get_pkt_ctx(cnx, path_x);
    pr_state->l4s_epoch_send = pkt_ctx->send_sequence;
    pr_state->l4s_epoch_ect1 = pkt_ctx->ecn_ect1_total_remote;
    pr_state->l4s_epoch_ce = pkt_ctx->ecn_ce_total_remote;
    pr_state->alpha = 0;
    pr_state->alpha_shifted = 0;

}


static void picoquic_prague_reset(picoquic_cnx_t * cnx, picoquic_prague_state_t* pr_state, picoquic_path_t* path_x)
{
    
    picoquic_prague_init_reno(pr_state, path_x);
    picoquic_prague_reset_l3s(cnx, pr_state, path_x);
}


/* The recovery state last 1 RTT, during which parameters will be frozen
 */
static void picoquic_prague_enter_recovery(
    picoquic_cnx_t* cnx,
    picoquic_path_t* path_x,
    picoquic_congestion_notification_t notification,
    picoquic_prague_state_t* pr_state,
    uint64_t current_time)
{
    pr_state->ssthresh = path_x->cwin / 2;
    if (pr_state->ssthresh < PICOQUIC_CWIN_MINIMUM) {
        pr_state->ssthresh = PICOQUIC_CWIN_MINIMUM;
    }

    if (notification == picoquic_congestion_notification_timeout) {
        path_x->cwin = PICOQUIC_CWIN_MINIMUM;
        pr_state->alg_state = picoquic_prague_alg_slow_start;
    }
    else {
        path_x->cwin = pr_state->ssthresh;
        pr_state->alg_state = picoquic_prague_alg_congestion_avoidance;
    }

    pr_state->recovery_start = current_time;

    pr_state->residual_ack = 0;
    
    picoquic_prague_reset_l3s(cnx, pr_state, path_x);
}

static void picoquic_prague_update_alpha(picoquic_cnx_t* cnx,
    picoquic_path_t* path_x, picoquic_prague_state_t* pr_state, uint64_t nb_bytes_acknowledged, uint64_t current_time)
{
    /* Check the L4S epoch, based on first number sent in previous epoch */
    picoquic_packet_context_t* pkt_ctx = picoquic_prague_get_pkt_ctx(cnx, path_x);
    uint64_t update_sent = pkt_ctx->latest_time_acknowledged;

    if (pkt_ctx->highest_acknowledged != UINT64_MAX &&
        pkt_ctx->highest_acknowledged > pr_state->l4s_epoch_send) {
        /* The epoch packet has been acked. Time to update alpha. */
        uint64_t frac = 0;
        int is_suspect = 0;
        pr_state->l4s_epoch_send = pkt_ctx->send_sequence;
        uint64_t delta_ect1 = pkt_ctx->ecn_ect1_total_remote - pr_state->l4s_epoch_ect1;
        uint64_t delta_ce = pkt_ctx->ecn_ce_total_remote - pr_state->l4s_epoch_ce;

        if (delta_ce > 0) {
            frac = (delta_ce * 1024) / (delta_ce + delta_ect1);
        }
        else {
            frac = 0;
        }

        if (pr_state->l4s_update_sent != 0 && frac > 512 && pr_state->alpha < 128 &&
            update_sent - pr_state->l4s_update_sent > path_x->smoothed_rtt) {
            /* 
             * the epoch lasted more than the RTT. This is most
             * probably due to period of inactivity, then effects of imprecise
             * tuning of pacing's leaky bucket algorithm. Limiting the
             * fraction frac to about 1/8th to avoid too much bad effects. */
            is_suspect = 1;
            frac = 128;
        }
        pr_state->l4s_update_sent = update_sent;

        if (delta_ce > 0 || delta_ect1 > 0) {
            if (frac > pr_state->alpha && (frac > 512 || is_suspect)) {
                pr_state->alpha = frac;
                pr_state->alpha_shifted = frac << PRAGUE_SHIFT_G;
            }
            else {
                int64_t delta_frac = frac - pr_state->alpha;

                pr_state->alpha_shifted += delta_frac;
                pr_state->alpha = pr_state->alpha_shifted >> PRAGUE_SHIFT_G;
            }
        }
        pr_state->l4s_epoch_send = pkt_ctx->send_sequence;
        pr_state->l4s_epoch_ect1 = pkt_ctx->ecn_ect1_total_remote;
        pr_state->l4s_epoch_ce = pkt_ctx->ecn_ce_total_remote;

        if (delta_ce > 0) {
            if (pr_state->alpha > 512) {
                /* If we got many ECN marks in the last RTT, treat as full on congestion */
                picoquic_prague_enter_recovery(cnx, path_x, picoquic_congestion_notification_ecn_ec, pr_state, current_time);
            }
            else {
                /* If we got ECN marks in the last RTT, update the ssthresh and the CWIN */
                uint64_t reduction = (path_x->cwin * pr_state->alpha) / 2048;
                pr_state->ssthresh = path_x->cwin - reduction;
                if (pr_state->ssthresh < PICOQUIC_CWIN_MINIMUM) {
                    pr_state->ssthresh = PICOQUIC_CWIN_MINIMUM;
                }
                uint64_t old_cwin = path_x->cwin;
                path_x->cwin = pr_state->ssthresh;
                pr_state->alg_state = picoquic_prague_alg_congestion_avoidance;

                picoquic_log_app_message(cnx, "Prague alpha: %" PRIu64 ", cwin, was % " PRIu64 " is now % " PRIu64 "\n",
                    pr_state->alpha, old_cwin, path_x->cwin);
            }
        }
    }
}

/* Callback management for Prague
 */
void picoquic_prague_notify(
    picoquic_cnx_t* cnx,
    picoquic_path_t* path_x,
    picoquic_congestion_notification_t notification,
    picoquic_per_ack_state_t * ack_state,
    uint64_t current_time)
{
    picoquic_prague_state_t* pr_state = (picoquic_prague_state_t*)path_x->congestion_alg_state;

    if (pr_state != NULL) {
        switch (notification) {
        case picoquic_congestion_notification_acknowledgement: {
            if (pr_state->alg_state == picoquic_prague_alg_slow_start &&
                pr_state->ssthresh == UINT64_MAX) {
                /* RTT measurements will happen after the back is signalled */
                uint64_t max_win = path_x->peak_bandwidth_estimate * path_x->smoothed_rtt / 1000000;
                uint64_t min_win = max_win /= 2;
                if (path_x->cwin < min_win) {
                    path_x->cwin = min_win;
                }
            }

            /* Regardless of the alg state, update alpha */
            picoquic_prague_update_alpha(cnx, path_x, pr_state, ack_state->nb_bytes_acknowledged, current_time);
            /* Increae or reduce the congestion window based on alpha */
            switch (pr_state->alg_state) {
            case picoquic_prague_alg_slow_start:
                if (path_x->smoothed_rtt <= PICOQUIC_TARGET_RENO_RTT) {
                    path_x->cwin += (ack_state->nb_bytes_acknowledged * (1024 - pr_state->alpha)) / 1024;
                }
                else {
                    uint64_t delta = ack_state->nb_bytes_acknowledged;
                    delta *= path_x->smoothed_rtt;
                    delta *= (1024 - pr_state->alpha);
                    delta /= PICOQUIC_TARGET_RENO_RTT;
                    delta /= 1024;
                    path_x->cwin += delta;
                }
                /* if cnx->cwin exceeds SSTHRESH, exit and go to CA */
                if (path_x->cwin >= pr_state->ssthresh) {
                    pr_state->alg_state = picoquic_prague_alg_congestion_avoidance;
                }
                break;
            case picoquic_prague_alg_congestion_avoidance:
            default: {
                uint64_t complete_delta = ack_state->nb_bytes_acknowledged * path_x->send_mtu + pr_state->residual_ack;
                pr_state->residual_ack = complete_delta % path_x->cwin;
                uint64_t delta = complete_delta / path_x->cwin;
                delta = (delta * (1024 - pr_state->alpha)) / 1024;
                path_x->cwin += delta;
                break;
            }
            }
            break;
        }
        case picoquic_congestion_notification_ecn_ec:
            // picoquic_prague_update_alpha(cnx, path_x, pr_state, nb_bytes_acknowledged, current_time);
            if (pr_state->alg_state == picoquic_prague_alg_slow_start &&
                pr_state->ssthresh == UINT64_MAX) {
                if (path_x->cwin > path_x->send_mtu) {
                    path_x->cwin -= path_x->send_mtu;
                }
                pr_state->ssthresh = path_x->cwin;
                pr_state->alg_state = picoquic_prague_alg_congestion_avoidance;
                path_x->is_ssthresh_initialized = 1;
            }
            break;
        case picoquic_congestion_notification_repeat:
        case picoquic_congestion_notification_timeout:
            /* enter recovery */
            if (current_time - pr_state->recovery_start > path_x->smoothed_rtt) {
                picoquic_prague_enter_recovery(cnx, path_x, notification, pr_state, current_time);
            }
            break;
        case picoquic_congestion_notification_spurious_repeat:
            if (current_time - pr_state->recovery_start < path_x->smoothed_rtt) {
                /* If spurious repeat of initial loss detected,
                 * exit recovery and reset threshold to pre-entry cwin.
                 */
                if (path_x->cwin < 2 * pr_state->ssthresh) {
                    path_x->cwin = 2 * pr_state->ssthresh;
                    pr_state->alg_state = picoquic_prague_alg_congestion_avoidance;
                }
            }
            break;
        case picoquic_congestion_notification_rtt_measurement:
            /* Using RTT increases as signal to get out of initial slow start */
            if (pr_state->alg_state == picoquic_prague_alg_slow_start &&
                pr_state->ssthresh == UINT64_MAX) {

                if (path_x->rtt_min > PICOQUIC_TARGET_RENO_RTT) {
                    uint64_t min_win;

                    if (path_x->rtt_min > PICOQUIC_TARGET_SATELLITE_RTT) {
                        min_win = (uint64_t)((double)PICOQUIC_CWIN_INITIAL * (double)PICOQUIC_TARGET_SATELLITE_RTT / (double)PICOQUIC_TARGET_RENO_RTT);
                    }
                    else {
                        /* Increase initial CWIN for long delay links. */
                        min_win = (uint64_t)((double)PICOQUIC_CWIN_INITIAL * (double)path_x->rtt_min / (double)PICOQUIC_TARGET_RENO_RTT);
                    }
                    if (min_win > path_x->cwin) {
                        path_x->cwin = min_win;
                    }
                }

                if (picoquic_hystart_test(&pr_state->rtt_filter, (cnx->is_time_stamp_enabled) ? ack_state->one_way_delay : ack_state->rtt_measurement,
                    cnx->path[0]->pacing.packet_time_microsec, current_time,
                    cnx->is_time_stamp_enabled)) {
                    /* RTT increased too much, get out of slow start! */
                    pr_state->ssthresh = path_x->cwin;
                    pr_state->alg_state = picoquic_prague_alg_congestion_avoidance;
                    path_x->is_ssthresh_initialized = 1;
                }
            }
            break;
        case picoquic_congestion_notification_reset:
            picoquic_prague_reset(cnx, pr_state, path_x);
            break;
        case picoquic_congestion_notification_cwin_blocked:
        default:
            /* ignore */
            break;
        }
    }

    /* Compute pacing data */
    picoquic_update_pacing_data(cnx, path_x, pr_state->alg_state == picoquic_prague_alg_slow_start &&
        pr_state->ssthresh == UINT64_MAX);
}

/* Release the state of the congestion control algorithm */
void picoquic_prague_delete(picoquic_path_t* path_x)
{
    if (path_x->congestion_alg_state != NULL) {
        free(path_x->congestion_alg_state);
        path_x->congestion_alg_state = NULL;
    }
}

/* Observe the state of congestion control */

void picoquic_prague_observe(picoquic_path_t* path_x, uint64_t* cc_state, uint64_t* cc_param)
{
    picoquic_prague_state_t* pr_state = (picoquic_prague_state_t*)path_x->congestion_alg_state;
    *cc_state = (uint64_t)pr_state->alg_state;
    *cc_param = (pr_state->ssthresh == UINT64_MAX) ? 0 : pr_state->ssthresh;
}

/* Definition record for the Prague algorithm */

#define PICOQUIC_PRAGUE_ID "prague" 

picoquic_congestion_algorithm_t picoquic_prague_algorithm_struct = {
    PICOQUIC_PRAGUE_ID, PICOQUIC_CC_ALGO_NUMBER_PRAGUE,
    picoquic_prague_init,
    picoquic_prague_notify,
    picoquic_prague_delete,
    picoquic_prague_observe
};

picoquic_congestion_algorithm_t* picoquic_prague_algorithm = &picoquic_prague_algorithm_struct;
