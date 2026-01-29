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
#include "picoquic_unified_log.h"
#include "tls_api.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* Packet loss recovery logic. This is an implementation of the RACK
 * algorithm, with two key functions:
 * 
 * - picoquic_retransmit_needed: perform the packet number based loss
 *   detection.
 * - picoquic_pto_needed: perform the timer based loss detection.
 * 
 * The first action in the sender loop is normally to retransmit lost packets.
 * This is done by a call to "picoquic_retransmit_needed", which will look
 * at packets that should be considered lost. This can happen for two
 * reasons, and want to treat those two reasons differently:
 * 
 * - doing packet number based loss detection starting from the oldest
 *   packet in the queue. If number-based loss detection occurs, there is
 *   a very high chance that the packet is actually lost, and the frames
 *   in such packets shall be resent asap.
 * - doing timeout based loss detection. This should only trigger if
 *   the last "ack eliciting" packet in the queue was not acknowledged
 *   yet. There is a much higher risk of getting these timers wrong
 *   than getting number-based loss detection wrong, so we want to
 *   proceed conservatively.
 * 
 * The solution recommeded in RACK is to just push a new packet on
 * the link in case of timeout based loss detection. If that packet
 * is acknowledged, then number based loss detection will kick in,
 * thus resolving packet losses with minimal risk of spurious
 * loss detection. But there are two border cases: path suspension
 * and path breakage.
 * 
 * If the path is broken, restransmitting data on the path will
 * will mostly cause queues to build up between the sender and
 * the point of breakage. That does not seem very useful. But if
 * the path is just suspended, it makes sense to send a trial
 * packet at regular intervals. When the path is restored, the
 * peer will receive one of the trial packets and will acknowledge
 * it, enabling number based loss detection.
 * 
 * Loss detection is often used for path breakage detection. Many
 * implementations of TCP would count the number of times the last
 * packet needed to be retransmitted, and after some threshold
 * give up and abandon the connection. The problem is that breaking
 * the connection does not accumplish much, apart from providing
 * a signal to the application. Different applications might have
 * different preferences. There are two plausible compromises:
 * 
 * - Use the "idle timeout" as an indication of the application's
 *   intent, and only break the connection if the path cannot
 *   be restored within the idle timeout.
 * - Provide a "timeout" callback to the application when
 *   repeated losses occur, so the application can for example
 *   try a migration to a new path.
 * 
 * The same kind of compromise could be used in multipath
 * configuration: inform the multipath scheduler that connectivity
 * on the path is dubious, and try repeating the packets
 * presumed lost on a different path. In the current code,
 * this would mean declaring the queued packets as lost, so
 * that the individual frames in tehse packets can be sent on
 * the better path. But that should only happen if another
 * path is available.
 * 
 * The loss detection logic should be organized per path, as
 * follow:
 * 
 * - Use `picoquic_retransmit_needed` as the main call from
 *   the sending logic.
 * 
 * - For single path, call `picoquic_retransmit_needed_loop`
 *   which in turn will call `picoquic_retransmit_needed_packet`
 *   for the oldest packets in the loop, until no more
 *   packets can be processed. After that, check whether the
 *   flag `is_pto_needed` should be set for the path.
 * 
 * - For multipath, this is a bit more complex, see below.
 * 
 * At the very beginning of the handshake, the server only
 * performs regular loss recovery if the client's IP is
 * validated. After that, the path logic applies, complemented
 * by implicit acknowledgements.
 * 
 * 0RTT packets are a special case. They are sent during the
 * handshake, but acknowledgement can only be processed if the
 * client has obtained the "application" keys. Before that,
 * the "path" logic does not apply. After that, it is possible
 * that some initial or handshake packets sent before the
 * handshake complete but after the 0RTT packets will be
 * acknowledged before the 0RTT, which could confuse the
 * number based logic. In practice, this means the number
 * based logic will only apply if the later acknowledgement
 * are for 0RTT or 1RTT packets.
 * 
 * Multipath is also a special case, because of the interaction
 * between loss recovery and path scheduling. By default,
 * multipath scheduling selects among the paths with the lowest
 * "nb_retransmit". Otherwise, path are only selected when it
 * is time to send a "multipath probe" to check whether the
 * path is back up. This contradicts the "PTO" logic, which
 * expects retransmission on the same path. The other
 * difference is that when tetsing for retransmission we
 * need to tests all paths. The changes are:
 * 
 * - Visit all paths, with two options:
 *
 *   - if the packet is empty, just call the function
 *     `picoquic_retransmit_needed_loop` for the path,
 *     or a variant for "simple multipath".
 *   - if the packet is full, check whether the wake up
 *     timer shall be set, and possibly also check whether
 *     the flag `is_pto_needed` should be set.
 * 
 * - Inside the `picoquic_retransmit_needed_packet`,
 *   consider some differences:
 * 
 *     - for "probably lost" packets, just retransmit them.
 *     - in case of timeout, manage a difference between
 *       retransmission on the same path, in which case
 *       the PTO logic will work, and retransmission on
 *       a different path, for which it does not.
 */

static size_t picoquic_retransmit_needed_loop(picoquic_cnx_t* cnx, picoquic_packet_context_t* pkt_ctx,
    picoquic_packet_context_enum pc,
    picoquic_path_t* path_x, uint64_t current_time, uint64_t* next_wake_time,
    picoquic_packet_t* packet, size_t send_buffer_max, size_t* header_length);

static size_t picoquic_retransmit_needed_packet(picoquic_cnx_t* cnx, picoquic_packet_context_t* pkt_ctx,
    picoquic_packet_t* old_p,
    picoquic_packet_context_enum pc,
    picoquic_path_t* path_x, uint64_t current_time, uint64_t* next_wake_time,
    picoquic_packet_t* packet, size_t send_buffer_max, size_t* header_length,
    int* continue_next);

static picoquic_packet_t* picoquic_process_lost_packet(picoquic_cnx_t* cnx, picoquic_packet_context_t* pkt_ctx,
    picoquic_packet_t* old_p,
    int is_timer_expired,
    picoquic_packet_context_enum pc,
    picoquic_path_t* path_x, uint64_t current_time,
    picoquic_packet_t* packet, size_t send_buffer_max,
    size_t* length, int* packet_is_pure_ack, size_t * header_length);

static int picoquic_is_packet_ack_eliciting(picoquic_packet_t* packet);

static void picoquic_set_wake_up_from_packet_retransmit(
    picoquic_cnx_t* cnx, picoquic_packet_t* old_p, uint64_t current_time, uint64_t* next_wake_time);

int picoquic_retransmit_needed(picoquic_cnx_t* cnx,
    picoquic_packet_context_enum pc,
    picoquic_path_t* path_x, uint64_t current_time, uint64_t* next_wake_time,
    picoquic_packet_t* packet, size_t send_buffer_max, size_t* header_length)
{
    size_t length = 0;

    if (pc == picoquic_packet_context_application && cnx->is_multipath_enabled) {
        /* If unique multipath is enabled, should check for retransmission on all paths */
        for (int i=0; i<cnx->nb_paths; i++) {
            if (length == 0) {
                length = picoquic_retransmit_needed_loop(cnx, &cnx->path[i]->pkt_ctx, pc, path_x, current_time,
                    next_wake_time, packet, send_buffer_max, header_length);
            }
            else {
                /* If more retransmission are queued, set the timer appropriately */
                if (cnx->path[i]->pkt_ctx.pending_first != NULL) {
                    picoquic_set_wake_up_from_packet_retransmit(cnx, cnx->path[i]->pkt_ctx.pending_first, current_time, next_wake_time);
                }
            }
        }
    }
    else {
        length = picoquic_retransmit_needed_loop(cnx, &cnx->pkt_ctx[pc], pc, path_x, current_time, next_wake_time,
            packet, send_buffer_max, header_length);
    }

    return (int)length;
}

static size_t picoquic_retransmit_needed_loop(picoquic_cnx_t* cnx, picoquic_packet_context_t* pkt_ctx,
    picoquic_packet_context_enum pc,
    picoquic_path_t* path_x, uint64_t current_time, uint64_t* next_wake_time,
    picoquic_packet_t* packet, size_t send_buffer_max, size_t* header_length)
{
    int continue_next = 1;
    size_t length = 0;
    picoquic_packet_t* old_p = pkt_ctx->pending_first;

    /* Call the per packet routine in a loop */
    while (old_p != 0 && continue_next) {
        picoquic_packet_t* p_next = old_p->packet_next;

        length = picoquic_retransmit_needed_packet(cnx, pkt_ctx, old_p, pc, path_x, current_time,
            next_wake_time, packet, send_buffer_max, header_length, &continue_next);
        old_p = p_next;
    }
    /* TODO: manage the pto flag for the path. */

    return length;
}

/*
* Per packet processing. The code makes a series of determinations:
* 
* - Is the packet considered lost? (should really test just numbers)
* - Should the content of this packet be resent?
* - Should a copy of this packet be kept in the reransmitted queue?
* - Should the PTO needed flag be set for the path?
* - Should the MTU be reset?
* - Should the path be abandoned?
* - Should the code continue processing other packets queued in the path?
* - Should the wakeup timer be reset?
* 
* The decisions are based on a series of tests:
* 
* - RACK test: are there enough acknowledged packets after this one?
* - 0RTT test: is this a 0RTT packet, are we expecting ACKs for those?
* - ACK Trap: not real packets but PNs that were skipped to catch bad receiver behavior.
* - Initial retransmit: the server should repeat Initial packets because the client did
* - Pure ACK: if a packet only contains frames that do not need repeating.
* 
* TODO:
* Current decision mixe "is lost" and "needs repeating", with "on timer"
* indication. This is bad, because "needs repeating" is a decision, which
* should be in one place.
* 
* Need PTO indication is a property of the path, not a property of a packet.
* 
* Continue the loop is an artefact of the software code: simple multipath
* uses a loop per path, the other modes use a loop per number space. Leave it
* in the per packet code for now. The loop should be:
* 
* - while a packet is deemed lost (by number):
*      - maybe skip if packet is 0RTT.
*      - just delete the packet if ACK Trap. 
*      - track MTU issues
*      - try "copy for retransmit".
*          - unchain, but only delete if pure ACK.
*      - do statistics and notifications.
*      - if copied packet is empty, continue, else stop there.
* 
* - After all pure losses have been worked on, check whether the last "ACK
*   eliciting" packet is too old.
*      - if yes, set PTO needed.
*      - exit the loop.
* 
* There are a couple of issues in the PTO case. We want to repeat exactly
* one packet per PTO or Timer iteration, but we also want to repeat data
* as soon as possible. If we set the PTO flag, we will repeat the oldest
* packet in the queue, but just that one. In practice, that means
* leaving the queue alone if the PTO flag has not been reset by the
* sender.
* 
* TODO:
* Path closing logic should probably not use a hard max repeat number.
* maybe tie that to idle timeout?
* 
* Detect a path suspension.
* 
 */
static int picoquic_is_packet_probably_lost(picoquic_cnx_t* cnx,
    picoquic_packet_t* p, uint64_t current_time, uint64_t* next_retransmit_time,
    int* is_timer_expired);

static void picoquic_check_path_mtu_on_losses(
    picoquic_cnx_t* cnx, picoquic_packet_t* old_p, int timer_based_retransmit);

static void picoquic_count_and_notify_loss(
    picoquic_cnx_t* cnx, picoquic_packet_t* old_p, int timer_based_retransmit, uint64_t current_time);

static void picoquic_retransmit_path_packet_queue(picoquic_cnx_t* cnx, picoquic_path_t* path_x,
    picoquic_packet_context_t* pkt_ctx, uint64_t current_time);

static size_t picoquic_retransmit_needed_packet(picoquic_cnx_t* cnx, picoquic_packet_context_t* pkt_ctx,
    picoquic_packet_t* old_p,
    picoquic_packet_context_enum pc,
    picoquic_path_t* path_x, uint64_t current_time, uint64_t* next_wake_time,
    picoquic_packet_t* packet, size_t send_buffer_max, size_t* header_length,
    int* continue_next)
{
    size_t length = 0;
    *continue_next = 0;

    /* TODO: while packets are pure ACK, drop them from retransmit queue */
    picoquic_path_t* old_path = old_p->send_path; /* should be the path on which the packet was transmitted */

    int is_probably_lost = 0;
    int is_timer_expired = 0;
    uint64_t next_retransmit_time = *next_wake_time;

    length = 0;

    if (old_p->ptype == picoquic_packet_0rtt_protected && cnx->cnx_state < picoquic_state_client_ready_start) {
        /* Special case: 0RTT cannot be acked before handshake is complete */
        *continue_next = 1;
        return 0;
    }
    is_probably_lost = cnx->initial_repeat_needed || old_p->send_path == NULL ||
        picoquic_is_packet_probably_lost(cnx, old_p, current_time, &next_retransmit_time, &is_timer_expired);

    if (is_probably_lost && (old_p->ptype == picoquic_packet_initial || old_p->ptype == picoquic_packet_handshake)) {
        /* Need to verify that there is no coalescing issue! */
        if (old_p->length > send_buffer_max) {
            picoquic_log_app_message(cnx, "Delay retransmission in type %d, seq %" PRIu64 ", buffer too small",
                old_p->ptype, old_p->sequence_number);
            return 0;
        }
    }

    if (is_probably_lost) {
        if (old_p->is_ack_trap) {
            picoquic_dequeue_retransmit_packet(cnx, pkt_ctx, old_p, 1, 0);
            *continue_next = 1;
        }
        else {
            /* check if this is an ACK only packet */
            int packet_is_pure_ack = 1;

            /* Parse the old packet, queue frames for retransmit, perhaps copy some
             * frames into the new packet, dequeue from packet queue and if needed
             * copy to "retransmitted", return old_p = 0 if freed.
             */
            old_p = picoquic_process_lost_packet(cnx, pkt_ctx, old_p, 0, pc, path_x, current_time,
                packet, send_buffer_max, &length, &packet_is_pure_ack, header_length);

            /* If there was no frame copied in the packet, tell the caller to continue the loop. */
            if (old_p == NULL || packet_is_pure_ack) {
                length = 0;
                *continue_next = 1;
            }
            /* Also continue the loop if the packet is zero length. This is a tradeoff, because
             * in some circumstances it may cause an increase in memory consumption.
             * Consider limiting this to cases when "bytes in transit" is larger than "CWIN".
             */
            if (length == 0) {
                *continue_next = 1;
            }
        }
    }
    else if (!is_timer_expired) {
        /*
        * Always retransmit in order. If not this one, then nothing.
        * But make an exception for 0-RTT packets.
        */
        if (old_p->ptype == picoquic_packet_0rtt_protected) {
            *continue_next = 1;
        }
        else {
            if (next_retransmit_time < *next_wake_time) {
                *next_wake_time = next_retransmit_time;
                SET_LAST_WAKE(cnx->quic, PICOQUIC_LOSS_RECOVERY);
            }
            /* Will not continue */
            *continue_next = 0;
        }
    }
    else if (cnx->cnx_state <= picoquic_state_client_ready_start) {
        /* We do not follow the PTO logic before the connection is complete */
        int packet_is_pure_ack;
        if (old_path != NULL &&
            (((old_p->sequence_number > pkt_ctx->highest_acknowledged || pkt_ctx->highest_acknowledged == UINT64_MAX) &&
            old_p->send_time > old_path->last_loss_event_detected) ||
            old_path->last_loss_event_detected == 0)){
            old_path->nb_retransmit++;
            old_path->last_loss_event_detected = current_time;
        }
        old_p = picoquic_process_lost_packet(cnx, pkt_ctx, old_p, 1, pc, path_x, current_time,
            packet, send_buffer_max, &length, &packet_is_pure_ack, header_length);
        if (old_p == NULL || packet_is_pure_ack) {
            length = 0;
            *continue_next = 1;
        }
    }
    else {
        /* The timer is expired */

        /* Evaluate whether this packet did in fact require an acknowledgement */
        if (!picoquic_is_packet_ack_eliciting(old_p)) {
            /* if the packet did not require an acknowledgement, it can be safely
             * removed from the queue, and processing will move to the next packet.
             */

            /* If ack only packets are lost, bundle a ping next time an ACK is sent on that path */
            if (old_p->send_path != NULL && cnx->is_multipath_enabled) {
                old_p->send_path->is_ack_lost = 1;
            }
            // TODO: we don't consider it lost when it's not ack eliciting
            // picoquic_count_and_notify_loss(cnx, old_p, 2, current_time);
            picoquic_dequeue_retransmit_packet(cnx, pkt_ctx, old_p, 1, 0);
            length = 0;
            *continue_next = 1;
        }
        else if (old_path->is_pto_required && path_x == old_path) {
            /* A previous iteration of this loop requested a PTO repeat, and
             * the repeat has not happened yet. Just wait.
             */
            length = 0;
            *continue_next = 0;
        }
        else {
            /* We need to send a PTO. */
            int packet_is_pure_ack = 1;

            /* Parse the old packet, queue frames for retransmit, perhaps copy some
            * frames into the new packet, dequeue from packet queue and if needed
            * copy to "retransmitted", return old_p = 0 if freed.
            */
            /* TODO: there may be a special case for multipath, in which the
            * management of repeats is different */
            old_p = picoquic_process_lost_packet(cnx, pkt_ctx, old_p, 1, pc, path_x, current_time,
                packet, send_buffer_max, &length,
                &packet_is_pure_ack, header_length);

            if (packet_is_pure_ack) {
                /* this could happen if there is nothing to copy. */
                length = 0;
                *continue_next = 1;
            }
            else {
                /* we did perform a repetition */
                /* First, keep track of retransmissions per path, in order to
                * manage scheduling in multipath setup */

                if (old_path != NULL) {
                    if (path_x == old_path) {
                        old_path->is_pto_required = 1;
                    }
                    old_path->nb_retransmit++;
                    old_path->last_loss_event_detected = current_time;
                    if (cnx->is_multipath_enabled && cnx->nb_paths > 1) {
                        picoquic_retransmit_path_packet_queue(cnx, old_path, pkt_ctx, current_time);
                    }
                    if (old_path->nb_retransmit > 9 &&
                        cnx->cnx_state >= picoquic_state_ready) {
                        /* Max retransmission reached for this path */
                        DBG_PRINTF("%s\n", "Too many data retransmits, abandon path");
                        picoquic_log_app_message(cnx, "%s", "Too many data retransmits, abandon path");

                        if (cnx->is_multipath_enabled) {
                            int all_paths_dubious = 1;
                            for (int path_id = 0; path_id < cnx->nb_paths; path_id++) {
                                if (cnx->path[path_id]->nb_retransmit == 0) {
                                    all_paths_dubious = 0;
                                    break;
                                }
                            }
                            if (!all_paths_dubious) {
                                old_path->challenge_failed = 1;
                                cnx->path_demotion_needed = 1;
                            }
                        }
                        else {
                            old_path->challenge_failed = 1;
                            cnx->path_demotion_needed = 1;
                        }
                    }
                }
                /* Then, manage the total number of retransmissions across all paths. */
                if ((old_path == NULL || old_path->nb_retransmit > 9) &&
                    cnx->cnx_state >= picoquic_state_ready) {
                    /* TODO: only disconnect if there is no other available path */
                    int all_paths_bad = 1;
                    if (cnx->is_multipath_enabled) {
                        for (int path_id = 0; path_id < cnx->nb_paths; path_id++) {
                            if (cnx->path[path_id]->nb_retransmit <= 9) {
                                all_paths_bad = 0;
                                break;
                            }
                        }
                    }
                    if (all_paths_bad) {
                        /*
                        * Max retransmission count was exceeded. Log.
                        */
                        DBG_PRINTF("Too many retransmits of packet number %d, disconnect", (int)old_p->sequence_number);

                        *continue_next = 0;
                    }
                }
            }
#ifdef TODO_CHECK_IF_PACING_ALSO_NEEDED_IN_ALL_CASES
            if (length <= packet->offset) {
                length = 0;
                packet->length = 0;
                packet->offset = 0;
                if (!packet_is_pure_ack) {
                    /* Pace down the next retransmission so as to not pile up error upon error.
                    * We only do that if theree are enough tokens in the bucket to allow at least
                    * one packet out. Otherwise, there is a risk of creating a waiting loop that
                    * only stops when all queued packets have been processed.
                    */
                    if (path_x->pacing_bucket_nanosec > path_x->pacing_packet_time_nanosec) {
                        path_x->pacing_bucket_nanosec -= path_x->pacing_packet_time_nanosec;
                    }
                }
                /*
                * If the loop is continuing, this means that we need to look
                * at the next candidate packet.
                */
                *continue_next = (timer_based_retransmit == 0);
            }
            else {
                *continue_next = 0;
            }
#endif
        }
    }

    return length;
}

static int picoquic_is_packet_probably_lost(picoquic_cnx_t* cnx,
    picoquic_packet_t* old_p, uint64_t current_time, uint64_t* next_retransmit_time,
    int* is_timer_expired)
{
    uint64_t retransmit_time = UINT64_MAX;
    int64_t delta_seq = 0;
    int64_t delta_sent = 0;
    uint64_t rack_timer_min;
    int is_probably_lost = 0;

    *is_timer_expired = 0;

    if (old_p->ptype == picoquic_packet_0rtt_protected && !cnx->zero_rtt_data_accepted) {
        /* Zero RTT data was not accepted by the peer, the packets are considered lost */
        retransmit_time = current_time;
        is_probably_lost = 1;
    }
    else if (old_p->ptype == picoquic_packet_0rtt_protected && cnx->cnx_state != picoquic_state_ready &&
        cnx->cnx_state != picoquic_state_client_ready_start) {
        /* Set the retransmit time ahead of current time since the connection is not ready */
        retransmit_time = current_time + old_p->send_path->smoothed_rtt + PICOQUIC_RACK_DELAY;
    }
    else {
        picoquic_packet_context_t* pkt_ctx = (cnx->is_multipath_enabled && old_p->pc == picoquic_packet_context_application) ?
            &old_p->send_path->pkt_ctx : &cnx->pkt_ctx[old_p->pc];
        delta_seq = pkt_ctx->highest_acknowledged - old_p->sequence_number;

        if (delta_seq > 0) {
            /* Set a timer relative to that last packet */
            int64_t rack_delay = (old_p->send_path->smoothed_rtt >> 2);
            delta_sent = pkt_ctx->latest_time_acknowledged - old_p->send_time;
            if (rack_delay > PICOQUIC_RACK_DELAY / 2) {
                rack_delay = PICOQUIC_RACK_DELAY / 2;
            }
            retransmit_time = old_p->send_time + old_p->send_path->retransmit_timer;
            rack_timer_min = pkt_ctx->highest_acknowledged_time + rack_delay
                - delta_sent + cnx->remote_parameters.max_ack_delay;
            if (retransmit_time > rack_timer_min) {
                retransmit_time = rack_timer_min;
            }
            if (retransmit_time <= current_time || old_p->is_ack_trap) {
                is_probably_lost = 1;
            }
        }
    }
    if (!is_probably_lost) {
        /* Find the last packet in the queue, which may be this one.
        * Compute a timer from the time this last packet was sent.
        * If the timer has elapsed, this packet should be resent,
        * in a timer based manner. If not, set the timer to
        * the specified value. */
        uint64_t retransmit_time_timer;
        picoquic_packet_t* last_packet = picoquic_get_last_packet(cnx, old_p->send_path, old_p->pc);

        if (last_packet == NULL) {
            last_packet = old_p;
        }
        retransmit_time_timer = last_packet->send_time + picoquic_current_retransmit_timer(cnx, old_p->send_path);

        if (current_time >= retransmit_time_timer) {
            if (old_p->send_path->path_is_demoted) {
                /* if the path is demoted, treat this as a simple loss */
                is_probably_lost = 1;
            }
            else {
                /* Do not set the "probably lost" condition, because timers are unreliable */
                *is_timer_expired = 1;
            }
        }
        else if (old_p->send_path->nb_retransmit == 0) {
            /* RACK has failure modes if the sender keeps adding small packets to the
             * retransmit queue. This may push the send time of the "last" packet
             * beyond a reasonable value.
             * In that case, we pick a safe timer based retransmit.
             * The "timer" condition will have consequences on congestion control;
             * we only set it if the packet is ack eliciting.
             */
            uint64_t alt_retransmit_timer = old_p->send_time + 2*picoquic_current_retransmit_timer(cnx, old_p->send_path);

            if (alt_retransmit_timer < last_packet->send_time) {
                retransmit_time_timer = alt_retransmit_timer;
                if (current_time >= retransmit_time_timer) {
                    if (picoquic_is_packet_ack_eliciting(old_p))
                    {
                        *is_timer_expired = 1;
                    }
                    else {
                        is_probably_lost = 1;
                    }
                }
            }
        }

        if (retransmit_time_timer < retransmit_time) {
            retransmit_time = retransmit_time_timer;
        }
    }
    if (*next_retransmit_time > retransmit_time) {
        *next_retransmit_time = retransmit_time;
    }

    return is_probably_lost;
}

static void picoquic_set_wake_up_from_packet_retransmit(
    picoquic_cnx_t * cnx, picoquic_packet_t * old_p, uint64_t current_time, uint64_t * next_wake_time)
{
    uint64_t next_retransmit_time = *next_wake_time;
    int is_timer_expired = 0;
    int is_probably_lost = picoquic_is_packet_probably_lost(cnx, old_p, current_time, &next_retransmit_time,
        &is_timer_expired);

    if (is_probably_lost || is_timer_expired) {
        *next_wake_time = current_time;
        SET_LAST_WAKE(cnx->quic, PICOQUIC_LOSS_RECOVERY);
    }
    else if (next_retransmit_time < *next_wake_time) {
        *next_wake_time = next_retransmit_time;
        SET_LAST_WAKE(cnx->quic, PICOQUIC_LOSS_RECOVERY);
    }
}

/* When a packet is deemed lost, the frames that it contained may have to
 * be resent. For a given frame time, there are several possible outcomes:
 * 
 * - Frame is pure ACK, and does not need to be repeated.
 * - Frame is datagram, will not be repeated but loss should be signalled
 * - Frame is stream data, will be queued for repeat.
 *    the stream data queue management will deal with acknowledgement
 *    of stream data, and thus avoid duplicates.
 * - Frame is not pure ACK, may need to be repeated:
 *    if "force queue" is set, the frame is queued in "misc" file
 *    else, the frame is copied in the repeated packet.
 */
int picoquic_copy_before_retransmit(picoquic_packet_t * old_p,
    picoquic_cnx_t * cnx,
    uint8_t * new_bytes,
    size_t send_buffer_max_minus_checksum,
    int * packet_is_pure_ack,
    int * do_not_detect_spurious,
    int force_queue,
    size_t * length,
    int * add_to_data_repeat_queue)
{
    /* check if this is an ACK only packet */
    int ret = 0;
    int frame_is_pure_ack = 0;
    size_t frame_length = 0;
    size_t byte_index = 0; /* Used when parsing the old packet */

    if (old_p->is_mtu_probe) {
        if (old_p->send_path != NULL) {
            /* MTU probe was lost, presumably because of packet too big */
            old_p->send_path->mtu_probe_sent = 0;
            if (!force_queue || force_queue == 2) {
                old_p->send_path->send_mtu_max_tried = old_p->length + old_p->checksum_overhead;
            }
        }
        /* MTU probes should not be retransmitted */
        *packet_is_pure_ack = 1;
        *do_not_detect_spurious = 0;
    }
    else if (old_p->is_ack_trap) {
        *packet_is_pure_ack = 1;
        *do_not_detect_spurious = 1;
    }
    else if (old_p->is_multipath_probe) {
        *packet_is_pure_ack = 0;
        *do_not_detect_spurious = 1;
    }
    else if (old_p->was_preemptively_repeated) {
        *packet_is_pure_ack = 1;
        *do_not_detect_spurious = 1;
    }
    else {
        /* Copy the relevant bytes from one packet to the next */
        byte_index = old_p->offset;

        while (ret == 0 && byte_index < old_p->length) {
            ret = picoquic_skip_frame(&old_p->bytes[byte_index],
                old_p->length - byte_index, &frame_length, &frame_is_pure_ack);

            /* Check whether the data was already acked, which may happen in
            * case of spurious retransmissions */
            if (ret == 0 && frame_is_pure_ack == 0) {
                ret = picoquic_check_frame_needs_repeat(cnx, &old_p->bytes[byte_index],
                    frame_length, old_p->ptype, &frame_is_pure_ack, do_not_detect_spurious, NULL);
            }

            /* Keep track of datagram frames that are possibly lost */
            if (ret == 0 &&
                PICOQUIC_IN_RANGE(old_p->bytes[byte_index], picoquic_frame_type_datagram, picoquic_frame_type_datagram_l) &&
                cnx->callback_fn != NULL) {
                uint8_t frame_id;
                uint64_t content_length;
                uint8_t* content_bytes = &old_p->bytes[byte_index];

                /* Parse and skip type and length */
                content_bytes = picoquic_decode_datagram_frame_header(content_bytes, content_bytes + frame_length,
                    &frame_id, &content_length);
                if (content_bytes != NULL) {
                    ret = (cnx->callback_fn)(cnx, old_p->send_time, content_bytes, (size_t)content_length,
                        picoquic_callback_datagram_lost, cnx->callback_ctx, NULL);
                }
                picoquic_log_app_message(cnx, "Datagram lost, PN=%" PRIu64 ", Sent: %" PRIu64,
                    old_p->sequence_number, old_p->send_time);
            }

            /* Prepare retransmission if needed */
            if (ret == 0) {
                if (!frame_is_pure_ack) {
                    if (PICOQUIC_IN_RANGE(old_p->bytes[byte_index], picoquic_frame_type_stream_range_min, picoquic_frame_type_stream_range_max)) {
                        * add_to_data_repeat_queue = 1;
                    }
                    else {
                        if ((force_queue || frame_length > send_buffer_max_minus_checksum - *length)) {
                            ret = picoquic_queue_misc_frame(cnx, &old_p->bytes[byte_index], frame_length, 0,
                                old_p->pc);
                        }
                        else if (frame_length <= send_buffer_max_minus_checksum - *length) {
                            memcpy(&new_bytes[*length], &old_p->bytes[byte_index], frame_length);
                            *length += frame_length;
                        }
                        else {
                            uint64_t error_frame_type = 0;
                            (void)picoquic_varint_decode(&old_p->bytes[byte_index], frame_length, &error_frame_type);
                            picoquic_log_app_message(cnx, "Cannot copy frame 0x%" PRIu64 ", packet type = %d, force queue = %d, repeat buffer : %zu, previous length : %zu.",
                                error_frame_type, old_p->ptype, force_queue);
                            ret = picoquic_connection_error_ex(cnx, PICOQUIC_TRANSPORT_INTERNAL_ERROR,
                                error_frame_type, "Cannot copy frame for retransmit");
                        }
                    }
                    *packet_is_pure_ack = 0;
                }
                byte_index += frame_length;
            }
        }
    }

    return ret;
}

static picoquic_packet_t* picoquic_process_lost_packet(picoquic_cnx_t* cnx, picoquic_packet_context_t* pkt_ctx,
    picoquic_packet_t* old_p,
    int is_timer_expired,
    picoquic_packet_context_enum pc,
    picoquic_path_t* path_x, uint64_t current_time,
    picoquic_packet_t* packet, size_t send_buffer_max,
    size_t* length, int * packet_is_pure_ack, size_t * header_length)
{
    int do_not_detect_spurious = 1;
    int add_to_data_repeat_queue = 0;
    uint8_t* new_bytes = NULL;
    size_t checksum_length = 0;
    size_t available_buffer = 0;
    int ret = 0;
    int force_queue = 0;

    /* Manage the path MTU issues */
    picoquic_check_path_mtu_on_losses(cnx, old_p, is_timer_expired);
    /* Report loss to application, update counts */
    picoquic_count_and_notify_loss(cnx, old_p, is_timer_expired, current_time);

    /* Prepare the packet copy */
    *packet_is_pure_ack = 1;

    if (packet == NULL) {
        force_queue = 2;
    } else {
        new_bytes = packet->bytes;
        packet->sequence_number = pkt_ctx->send_sequence;
        packet->send_path = path_x;
        packet->pc = pc;
        packet->ptype = (old_p->ptype == picoquic_packet_0rtt_protected) ? picoquic_packet_1rtt_protected : old_p->ptype;

        *length = picoquic_predict_packet_header_length(cnx, packet->ptype, pkt_ctx);
        packet->offset = *length;
        *header_length = *length;

        switch (packet->ptype) {
        case picoquic_packet_1rtt_protected:
            checksum_length = picoquic_get_checksum_length(cnx, picoquic_epoch_1rtt);
            break;
        case picoquic_packet_initial:
            checksum_length = picoquic_get_checksum_length(cnx, picoquic_epoch_initial);
            break;
        case picoquic_packet_handshake:
            checksum_length = picoquic_get_checksum_length(cnx, picoquic_epoch_handshake);
            break;
        case picoquic_packet_0rtt_protected:
            checksum_length = picoquic_get_checksum_length(cnx, picoquic_epoch_0rtt);
            break;
        default:
            DBG_PRINTF("Trying to retransmit packet type %d", old_p->ptype);
            checksum_length = 0;
            break;
        }
        available_buffer = send_buffer_max - checksum_length;
    }

    ret = picoquic_copy_before_retransmit(old_p, cnx,
        new_bytes,
        available_buffer,
        packet_is_pure_ack,
        &do_not_detect_spurious, force_queue,
        length,
        &add_to_data_repeat_queue);

    if (*length <= *header_length) {
        *length = 0;
    }

    /* If ack only packets are lost, bundle a ping next time an ACK is sent on that path */
    if (old_p->send_path != NULL && cnx->is_multipath_enabled) {
        old_p->send_path->is_ack_lost = 1;
    }

    if (ret != 0) {
        DBG_PRINTF("Copy before retransmit returns %d\n", ret);
    }

    /* Update the number of bytes in transit and remove old packet from queue */
    /* If not pure ack, the packet will be placed in the "retransmitted" queue,
    * in order to enable detection of spurious restransmissions */
    /* Keep track of the path, as "old_p->send_path" will be zeroed when dequeued */
    old_p = picoquic_dequeue_retransmit_packet(cnx, pkt_ctx, old_p, *packet_is_pure_ack & do_not_detect_spurious,
        add_to_data_repeat_queue);

    return old_p;
}

static void picoquic_check_path_mtu_on_losses(
    picoquic_cnx_t* cnx, picoquic_packet_t* old_p, int timer_based_retransmit)
{
    if (old_p->send_path != NULL &&
        ((old_p->length + old_p->checksum_overhead) == old_p->send_path->send_mtu || timer_based_retransmit) &&
        cnx->cnx_state >= picoquic_state_ready) {
        old_p->send_path->nb_mtu_losses++;
        if (old_p->send_path->nb_mtu_losses > PICOQUIC_MTU_LOSS_THRESHOLD || timer_based_retransmit) {
            size_t old_mtu = old_p->send_path->send_mtu;
            picoquic_reset_path_mtu(old_p->send_path);
            if (old_mtu != old_p->send_path->send_mtu) {
                picoquic_log_app_message(cnx,
                    "Reset path %" PRIu64 " MTU after %" PRIu64 " retransmissions, %" PRIu64 "MTU losses, Timer mode : %d",
                    old_p->send_path->unique_path_id,
                    old_p->send_path->nb_retransmit,
                    old_p->send_path->nb_mtu_losses,
                    timer_based_retransmit);
            }
        }
    }
}

static void picoquic_count_and_notify_loss(
    picoquic_cnx_t* cnx, picoquic_packet_t * old_p, int timer_based_retransmit, uint64_t current_time)
{
    if (timer_based_retransmit < 2) {
        picoquic_log_packet_lost(cnx, old_p->send_path, old_p->ptype, old_p->sequence_number,
            (timer_based_retransmit) ? "timer" : "repeat",
            (old_p->send_path == NULL || old_p->send_path->p_remote_cnxid == NULL) ? NULL : &old_p->send_path->p_remote_cnxid->cnx_id,
            old_p->length, current_time);

        if (!old_p->is_preemptive_repeat) {
            cnx->nb_retransmission_total++;
        }
    }

    if (old_p->send_path != NULL) {
        old_p->send_path->nb_losses_found++;
        if (timer_based_retransmit) {
            old_p->send_path->nb_timer_losses++;
        }
        if ((old_p->send_path->smoothed_rtt != PICOQUIC_INITIAL_RTT ||
            old_p->send_path->rtt_variant != 0) &&
            old_p->send_time > cnx->start_time + old_p->send_path->smoothed_rtt) {
            /* we do not count losses occruring before ready state, because the 
             * timers are not reliable yet */
            old_p->send_path->total_bytes_lost += old_p->length;
        }

        if (cnx->congestion_alg != NULL && cnx->cnx_state >= picoquic_state_ready && old_p->send_path != NULL) {
            picoquic_per_ack_state_t ack_state = { 0 };
            ack_state.lost_packet_number = old_p->sequence_number;
            ack_state.nb_bytes_newly_lost = old_p->length;
            cnx->congestion_alg->alg_notify(cnx, old_p->send_path,
                (timer_based_retransmit == 0) ? picoquic_congestion_notification_repeat : picoquic_congestion_notification_timeout,
                &ack_state, current_time);
        }
    }
}

static int picoquic_is_packet_ack_eliciting(picoquic_packet_t * packet)
{
    /* check if this is an ACK eliciting packet */
    int is_ack_eliciting = 0;

    if (packet->is_evaluated) {
        is_ack_eliciting = packet->is_ack_eliciting;
    } else {
        /* Trap packets are never supposed to elicit an ACK. */
        /* For other packets, we need to look at the frames inside. */
        if (!packet->is_ack_trap) {
            size_t frame_length = 0;
            size_t byte_index = packet->offset;

            while (byte_index < packet->length) {
                int frame_is_pure_ack = 0;
                if (picoquic_skip_frame(&packet->bytes[byte_index],
                    packet->length - byte_index, &frame_length, &frame_is_pure_ack) != 0) {
                    /* Malformed packet. Ignore it. Do not expect an ack */
                    break;
                }
                if (!frame_is_pure_ack) {
                    is_ack_eliciting = 1;
                    break;
                }
                byte_index += frame_length;
            }
        }
        packet->is_ack_eliciting = is_ack_eliciting;
        packet->is_evaluated = 1;
    }

    return is_ack_eliciting;
}

/* In multipath operation, schedule all packets queued on a path for retransmission
 */
static void picoquic_retransmit_path_packet_queue(picoquic_cnx_t* cnx, picoquic_path_t* path_x,
    picoquic_packet_context_t* pkt_ctx, uint64_t current_time)
{
    picoquic_packet_t* old_p = pkt_ctx->pending_first;
    int ret;

    while (old_p != NULL) {
        picoquic_packet_t* next_packet = old_p->packet_next;
        int packet_is_pure_ack = 1;
        int do_not_detect_spurious = 0;
        int add_to_data_repeat_queue = 0;
        size_t length = 0;

        /* Report loss to application, update counts */
        picoquic_count_and_notify_loss(cnx, old_p, 0, current_time);
        /* Call the copy routine but force it to not put anything in the copy */
        if ((ret = picoquic_copy_before_retransmit(old_p, cnx,
            NULL, 0, &packet_is_pure_ack, &do_not_detect_spurious, 1, &length,
            &add_to_data_repeat_queue)) != 0) {
            DBG_PRINTF("Copy before retransmit returns %d\n", ret);
        }

        /* If ack only packets are lost, bundle a ping next time an ACK is sent on that path */
        if (old_p->send_path != NULL && cnx->is_multipath_enabled) {
            old_p->send_path->is_ack_lost = 1;
        }

        /* Update the number of bytes in transit and remove old packet from queue */
        /* If not pure ack, the packet will be placed in the "retransmitted" queue,
        * in order to enable detection of spurious restransmissions */
        (void)picoquic_dequeue_retransmit_packet(cnx, pkt_ctx, old_p, packet_is_pure_ack & do_not_detect_spurious,
            add_to_data_repeat_queue);

        /* move to next packet */
        old_p = next_packet;
    }

}

void picoquic_retransmit_demoted_path(picoquic_cnx_t* cnx, picoquic_path_t* path_x,
    uint64_t current_time)
{
    picoquic_packet_context_t* pkt_ctx = NULL;

    if (cnx->cnx_state == picoquic_state_ready && cnx->nb_paths > 1) {
        if (cnx->is_multipath_enabled) {
            pkt_ctx = &path_x->pkt_ctx;
        }
        else {
            pkt_ctx = &cnx->pkt_ctx[picoquic_packet_context_application];
        }
        if (pkt_ctx != NULL) {
            picoquic_retransmit_path_packet_queue(cnx, path_x, pkt_ctx, current_time);
        }
    }
}


void picoquic_queue_retransmit_on_ack(picoquic_cnx_t* cnx, picoquic_path_t* path_x,
    uint64_t current_time)
{
    picoquic_packet_context_t* pkt_ctx = NULL;
    picoquic_packet_t* old_p;
    uint64_t next_retransmit_time = UINT64_MAX;

    /* If multipath, pick the packet context associated with the current path,
     * else, pick the default 1RTT context */
    if (cnx->is_multipath_enabled) {
        pkt_ctx = &path_x->pkt_ctx;
    }
    else {
        pkt_ctx = &cnx->pkt_ctx[picoquic_packet_context_application];
    }
    /* For all packets in this context:
    * Check whether it needs retransmit.
    * if yes, call "picoquic_process_lost_packet".
    * else, stop. */
    old_p = pkt_ctx->pending_first;

    /* Call the per packet routine in a loop */
    while (old_p != NULL) {
        picoquic_packet_t* p_next = old_p->packet_next;
        int packet_is_pure_ack = 0;
        size_t header_length = 0;
        int is_timer_expired = 0;
        int is_probably_lost = cnx->initial_repeat_needed || old_p->send_path == NULL ||
            picoquic_is_packet_probably_lost(cnx, old_p, current_time, &next_retransmit_time, &is_timer_expired);
        size_t length = 0;

        if (is_probably_lost) {
            if (old_p->is_ack_trap) {
                picoquic_dequeue_retransmit_packet(cnx, pkt_ctx, old_p, 1, 0);
            }
            else {
                (void)picoquic_process_lost_packet(cnx, pkt_ctx, old_p, is_timer_expired, old_p->pc,
                    path_x, current_time, NULL, 0, &length, &packet_is_pure_ack, &header_length);
            }
            old_p = p_next;
        }
        else {
            break;
        }   
    }
}