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

/*
 * Really basic network simulator, only simulates a simple link using a
 * packet structure. 
 * Init: link creation. Returns a link structure with defined bandwidth,
 * latency, loss pattern and initial time. The link is empty. The loss
 * pattern is a 64 bit bit mask.
 * Submit packet of length L at time t. The packet is queued to the link.
 * Get packet out of link at time T + L + Queue.
 */

#include "picoquic_internal.h"
#include "picoquic_utils.h"
#include "picosocks.h"
#include <stdlib.h>
#include <string.h>

picoquictest_sim_link_t* picoquictest_sim_link_create(double data_rate_in_gps,
    uint64_t microsec_latency, uint64_t* loss_mask, uint64_t queue_delay_max, uint64_t current_time)
{
    picoquictest_sim_link_t* link = (picoquictest_sim_link_t*)malloc(sizeof(picoquictest_sim_link_t));
    if (link != 0) {
        double pico_d = (data_rate_in_gps <= 0) ? 0 : (8000.0 / data_rate_in_gps);
        memset(link, 0, sizeof(picoquictest_sim_link_t));
        pico_d *= (1.024 * 1.024); /* account for binary units */
        link->next_send_time = current_time;
        link->queue_time = current_time;
        link->queue_delay_max = queue_delay_max;
        link->picosec_per_byte = (uint64_t)pico_d; 
        link->microsec_latency = microsec_latency;
        link->packets_dropped = 0;
        link->packets_sent = 0;
        link->first_packet = NULL;
        link->last_packet = NULL;
        link->loss_mask = loss_mask;
        link->jitter_seed = 0xDEADBEEFBABAC001ull;
        link->jitter = 0;
        link->path_mtu = PICOQUIC_MAX_PACKET_SIZE;
        link->red_drop_mask = 0;
        link->red_queue_max = 0;
        link->bucket_increase_per_microsec = 0;
        link->bucket_max = 0;
        link->bucket_current = 0;
        link->bucket_arrival_last = current_time;
    }

    return link;
}

void picoquictest_sim_link_delete(picoquictest_sim_link_t* link)
{
    picoquictest_sim_packet_t* packet;

    while ((packet = link->first_packet) != NULL) {
        link->first_packet = packet->next_packet;
        free(packet);
    }

    free(link);
}

picoquictest_sim_packet_t* picoquictest_sim_link_create_packet()
{
    picoquictest_sim_packet_t* packet = (picoquictest_sim_packet_t*)malloc(sizeof(picoquictest_sim_packet_t));
    if (packet != NULL) {
        packet->next_packet = NULL;
        packet->arrival_time = 0;
        packet->length = 0;
        packet->ecn_mark = 0;
    }

    return packet;
}

uint64_t picoquictest_sim_link_next_arrival(picoquictest_sim_link_t* link, uint64_t current_time)
{
    picoquictest_sim_packet_t* packet = link->first_packet;

    if (packet != NULL && packet->arrival_time < current_time) {
        current_time = packet->arrival_time;
    }

    return current_time;
}

picoquictest_sim_packet_t* picoquictest_sim_link_dequeue(picoquictest_sim_link_t* link,
    uint64_t current_time)
{
    picoquictest_sim_packet_t* packet = link->first_packet;

    if (packet != NULL && packet->arrival_time <= current_time) {
        link->first_packet = packet->next_packet;
        if (link->first_packet == NULL) {
            link->last_packet = NULL;
        }
    } else {
        packet = NULL;
    }

    return packet;
}

static int picoquictest_sim_link_testloss(uint64_t* loss_mask)
{
    uint64_t loss_bit = 0;

    if (loss_mask != NULL) {
        /* Last bit indicates loss or not */
        loss_bit = (uint64_t)((*loss_mask) & 1ull);

        /* Rotate loss mask by 1 to prepare next round */
        *loss_mask >>= 1;
        *loss_mask |= (loss_bit << 63);
    }

    return (int)loss_bit;
}

static uint64_t picoquictest_sim_link_jitter(picoquictest_sim_link_t* link)
{
    uint64_t jitter = link->jitter;
    double x = picoquic_test_gauss_random(&link->jitter_seed);
    if (x < -3.0) {
        x = -3.0;
    }
    x /= 3.0;
    jitter += (int64_t)(x * (double)jitter);

    return jitter;
}

void picoquictest_sim_link_submit(picoquictest_sim_link_t* link, picoquictest_sim_packet_t* packet,
    uint64_t current_time)
{
    uint64_t queue_delay = (current_time > link->queue_time) ? 0 : link->queue_time - current_time;
    uint64_t transmit_time = ((link->picosec_per_byte * ((uint64_t)packet->length)) >> 20);
    uint64_t should_drop = 0;

    if (transmit_time <= 0)
        transmit_time = 1;

    if (link->bucket_increase_per_microsec > 0) {
        /* Simulate a rate limiter based on classic leaky bucket algorithm */
        uint64_t delta_microsec = current_time - link->bucket_arrival_last;
        link->bucket_arrival_last = current_time;
        link->bucket_current += ((double)delta_microsec) * link->bucket_increase_per_microsec;
        if (link->bucket_current > (double)link->bucket_max) {
            link->bucket_current = (double)link->bucket_max;
        }
        if (link->bucket_current > (double)packet->length) {
            link->bucket_current -= (double)packet->length;
        }
        else {
            should_drop = 1;
        }
    } else if (link->queue_delay_max > 0 && queue_delay >= link->queue_delay_max) {
        if (link->red_drop_mask == 0 || queue_delay >= link->red_queue_max) {
            should_drop = 1;
        }
        else {
            should_drop = link->red_drop_mask & 1;
            link->red_drop_mask >>= 1;
            link->red_drop_mask |= (should_drop << 63);
        }
    }

    if (!should_drop) {
        link->queue_time = current_time + queue_delay + transmit_time;
        /* TODO: proper simulation of marking policy */
        if (link->l4s_max > 0 && queue_delay >= link->l4s_max) {
            packet->ecn_mark = PICOQUIC_ECN_CE;
        }
        if (packet->length > link->path_mtu || picoquictest_sim_link_testloss(link->loss_mask) != 0 ||
            link->is_switched_off) {
            link->packets_dropped++;
            free(packet);
        } else {
            link->packets_sent++;
            if (link->last_packet == NULL) {
                link->first_packet = packet;
            } else {
                link->last_packet->next_packet = packet;
            }
            link->last_packet = packet;
            packet->next_packet = NULL;
            packet->arrival_time = link->queue_time + link->microsec_latency;
            if (link->jitter != 0) {
                packet->arrival_time += picoquictest_sim_link_jitter(link);
            }
            if (packet->arrival_time < link->resume_time) {
                packet->arrival_time = link->resume_time;
            }

        }
    } else {
        /* simulate congestion loss or random drop on queue full */
        link->packets_dropped++;
        free(packet);
    }
}

/*
* Simulate a brief suspension of transmission on a link, similar to what
* happens when a Wi-Fi transmission gets suspended while scanning other
* radio channels. The existing packets are queued for delivery at the end of the interval.
*/

void picoquic_test_simlink_suspend(picoquictest_sim_link_t* link, uint64_t time_end_of_interval, int simulate_receive)
{
    picoquictest_sim_packet_t* packet;
    picoquictest_sim_packet_t* first_old;

    if (simulate_receive) {
        /* specify the resume time */
        link->resume_time = time_end_of_interval;
        /* packets scheduled to arrive before the end of the interval are rescheduled to
         * that end of interval time.
         */
        packet = link->first_packet;
        while (packet != NULL && packet->arrival_time < time_end_of_interval) {
            packet->arrival_time = time_end_of_interval;
            packet = packet->next_packet;
        }
    }
    else {
        /* Reset the queue delay to the end of interval */
        link->queue_time = time_end_of_interval;
        /* stash the old queue, and reset the queue pointers */
        first_old = link->first_packet;
        link->first_packet = NULL;
        link->last_packet = NULL;
        /* resubmit all packets at the end of interval time */
        packet = first_old;
        while (packet != NULL) {
            picoquictest_sim_packet_t* next_packet = packet->next_packet;
            packet->next_packet = NULL;
            picoquictest_sim_link_submit(link, packet, time_end_of_interval);
            packet = next_packet;
        }
    }
}

int sim_link_one_test(uint64_t* loss_mask, uint64_t queue_delay_max, uint64_t nb_losses)
{
    int ret = 0;
    uint64_t current_time = 0;
    uint64_t departure_time = 0;
    picoquictest_sim_link_t* link = picoquictest_sim_link_create(0.01, 10000, loss_mask, queue_delay_max, current_time);
    uint64_t dequeued = 0;
    uint64_t queued = 0;
    const uint64_t nb_packets = 16;

    if (link == NULL) {
        ret = -1;
    }
    else {

        while (ret == 0) {
            if (queued >= nb_packets) {
                departure_time = UINT64_MAX;
            }

            current_time = picoquictest_sim_link_next_arrival(link, departure_time);

            picoquictest_sim_packet_t* packet = picoquictest_sim_link_dequeue(link, current_time);

            if (packet != NULL) {
                dequeued++;
                free(packet);
            }
            else if (queued < nb_packets) {
                packet = picoquictest_sim_link_create_packet();

                if (packet == NULL) {
                    ret = -1;
                }
                else {
                    packet->length = sizeof(packet->bytes);
                    picoquictest_sim_link_submit(link, packet, departure_time);
                    departure_time += 250;
                    queued++;
                }
            }
            else {
                break;
            }
        }

        if ((dequeued + nb_losses) != nb_packets) {
            ret = -1;
        }
        
        picoquictest_sim_link_delete(link);
    }

    return ret;
}

int sim_link_test()
{
    int ret = 0;
    uint64_t loss_mask = 0;
    
    ret = sim_link_one_test(&loss_mask, 0, 0);

    if (ret == 0) {
        loss_mask = 8;
        ret = sim_link_one_test(&loss_mask, 0, 1);
    }

    if (ret == 0) {
        loss_mask = 0x18;
        ret = sim_link_one_test(&loss_mask, 0, 2);
    }

    return ret;
}

void picoquic_set_test_address(struct sockaddr_in * addr, uint32_t addr_val, uint16_t port)
{
    /* Init of the IP addresses */
    memset(addr, 0, sizeof(struct sockaddr_in));
    addr->sin_family = AF_INET;
#ifdef _WINDOWS
    addr->sin_addr.S_un.S_addr = addr_val;
#else
    addr->sin_addr.s_addr = addr_val;
#endif
    addr->sin_port = port;
}