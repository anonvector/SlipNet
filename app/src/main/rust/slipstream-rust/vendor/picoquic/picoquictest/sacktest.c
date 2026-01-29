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

/* Utility function to set minimal quic and cnx contexts
 */
int picoquic_test_set_minimal_cnx(picoquic_quic_t** quic, picoquic_cnx_t** cnx)
{
    *cnx = NULL;
    *quic = picoquic_create(8, NULL, NULL, NULL, NULL, NULL,
        NULL, NULL, NULL, NULL, 0, NULL, NULL, NULL, 0);
    if (*quic != NULL) {
        *cnx = picoquic_create_cnx(*quic,
            picoquic_null_connection_id,
            picoquic_null_connection_id,
            NULL, 0,
            0, PICOQUIC_TEST_SNI, "minimal", 1);
        if (*cnx == NULL) {
            picoquic_free(*quic);
            *quic = NULL;
        }
    }
    return (*quic == NULL || *cnx == NULL);
}

int picoquic_test_reset_minimal_cnx(picoquic_quic_t* quic, picoquic_cnx_t** cnx)
{
    if (*cnx != NULL) {
        picoquic_delete_cnx(*cnx);
    }
    *cnx = picoquic_create_cnx(quic,
        picoquic_null_connection_id,
        picoquic_null_connection_id,
        NULL, 0,
        0, PICOQUIC_TEST_SNI, "minimal", 1);
    return (*cnx == NULL) ? -1 : 0;
}

void picoquic_test_delete_minimal_cnx(picoquic_quic_t** quic, picoquic_cnx_t** cnx)
{
    if (*cnx != NULL) {
        picoquic_delete_cnx(*cnx);
        *cnx = NULL;
    }
    if (*quic != NULL) {
        picoquic_free(*quic);
        *quic = NULL;
    }
}
/*
 * Test of the SACK functionality
 */

static const uint64_t test_pn64[] = {
    3, 4, 0, 2, 7, 8, 11, 12, 13, 17, 19, 21, 18, 16, 20, 10, 5, 6, 9, 1, 14, 15
};

static const size_t nb_test_pn64 = sizeof(test_pn64) / sizeof(uint64_t);

struct expected_ack_t {
    uint64_t highest_received;
    uint64_t last_range;
    uint8_t num_blocks;
};

static struct expected_ack_t expected_ack[] = {
    { 3, 0, 0 },
    { 4, 1, 0 },
    { 4, 1, 1 },
    { 4, 2, 1 },
    { 7, 0, 2 },
    { 8, 1, 2 },
    { 11, 0, 3 },
    { 12, 1, 2 },
    { 13, 2, 1 },
    { 17, 0, 2 },
    { 19, 0, 2 },
    { 21, 0, 3 },
    { 21, 0, 2 },
    { 21, 0, 1 },
    { 21, 5, 0 },
    { 21, 5, 1 },
    { 21, 5, 2 },
    { 21, 5, 2 },
    { 21, 5, 1 },
    { 21, 5, 1 },
    { 21, 5, 1 },
    { 21, 21, 0 }
};


int check_ack_ranges(picoquic_sack_list_t* sack_list)
{
    int ret = 0;

    for (int r = 0; r < 2; r++) {
        int range_sum[PICOQUIC_MAX_ACK_RANGE_REPEAT] = { 0 };
        picoquic_sack_item_t* sack = picoquic_sack_first_item(sack_list);

        while (sack != NULL) {
            if (sack->nb_times_sent[r] < 0) {
                ret = -1;
                break;
            }
            else if (sack->nb_times_sent[r] < PICOQUIC_MAX_ACK_RANGE_REPEAT) {
                range_sum[sack->nb_times_sent[r]] += 1;
            }
            sack = picoquic_sack_next_item(sack);
        }

        for (int i = 0; ret == 0 && i < PICOQUIC_MAX_ACK_RANGE_REPEAT; i++) {
            if (sack_list->rc[r].range_counts[i] != range_sum[i]) {
                ret = -1;
            }
        }
    }
    return ret;
}


int sacktest()
{
    int ret = 0;
    picoquic_cnx_t *cnx;
    picoquic_quic_t* quic;
    uint64_t current_time = 0;
    uint64_t highest_seen = 0;
    uint64_t highest_seen_time = 0;
    picoquic_packet_context_enum pc = 0;

    if (picoquic_test_set_minimal_cnx(&quic, &cnx) != 0) {
        return -1;
    }

    if (picoquic_create_local_cnxid(cnx, 0, NULL, 0) == NULL) {
        return -1;
    }

    /* Do a basic test with packet zero */
    if (picoquic_is_pn_already_received(cnx, pc,
        cnx->first_local_cnxid_list->local_cnxid_first, 0) != 0) {
        ret = -1;
    }
    else if (picoquic_record_pn_received(cnx, pc, cnx->first_local_cnxid_list->local_cnxid_first,
        0, current_time) != 0) {
        ret = -1;
    }
    else if (picoquic_is_pn_already_received(cnx, pc,
        cnx->first_local_cnxid_list->local_cnxid_first, 0) == 0) {
        ret = -1;
    }
    else if (picoquic_sack_list_first(&cnx->ack_ctx[pc].sack_list) != 0 ||
        picoquic_sack_list_last(&cnx->ack_ctx[pc].sack_list) != 0 ||
        picoquic_sack_list_first_range(&cnx->ack_ctx[pc].sack_list) != NULL) {
        ret = -1;
    }
    else {
        /* reset for the next test */
        picoquic_test_reset_minimal_cnx(quic, &cnx);
    }

    if (ret == 0) {
        ret = check_ack_ranges(&cnx->ack_ctx[pc].sack_list);
    }

    for (size_t i = 0; ret == 0 && i < nb_test_pn64; i++) {
        current_time = ((uint64_t)i) * 100 + 1;

        if (test_pn64[i] > highest_seen) {
            highest_seen = test_pn64[i];
            highest_seen_time = current_time;
        }

        if (picoquic_record_pn_received(cnx, pc, cnx->first_local_cnxid_list->local_cnxid_first, test_pn64[i], current_time) != 0) {
            ret = -1;
        }

        if (ret == 0) {
            ret = check_ack_ranges(&cnx->ack_ctx[pc].sack_list);
        }

        for (size_t j = 0; ret == 0 && j <= i; j++) {
            if (picoquic_is_pn_already_received(cnx, pc,
                cnx->first_local_cnxid_list->local_cnxid_first, test_pn64[j]) == 0) {
                ret = -1;
            }

            if (picoquic_record_pn_received(cnx, pc, cnx->first_local_cnxid_list->local_cnxid_first, test_pn64[j], current_time) != 1) {
                ret = -1;
            }
        }

        for (size_t j = i + 1; ret == 0 && j < nb_test_pn64; j++) {
            if (picoquic_is_pn_already_received(cnx, pc,
                cnx->first_local_cnxid_list->local_cnxid_first, test_pn64[j]) != 0) {
                ret = -1;
            }
        }
    }

    if (ret == 0) {
        if (picoquic_sack_list_last(&cnx->ack_ctx[pc].sack_list) != 21 ||
            picoquic_sack_list_first(&cnx->ack_ctx[pc].sack_list) != 0 ||
            cnx->ack_ctx[pc].time_stamp_largest_received != highest_seen_time ||
            picoquic_sack_list_first_range(&cnx->ack_ctx[pc].sack_list) != NULL) {
            ret = -1;
        }
    }

    /* Free the sack lists*/
    picoquic_test_delete_minimal_cnx(&quic, &cnx);

    return ret;
}

static void ack_range_mask(uint64_t* mask, uint64_t highest, uint64_t range)
{
    for (uint64_t i = 0; i < range; i++) {
        *mask |= 1ull << (highest & 63);
        highest--;
    }
}

static int basic_ack_parse(uint8_t* bytes, size_t bytes_max,
    struct expected_ack_t* expected_ack, uint64_t * previous_mask, uint64_t expected_mask)
{
    int ret = 0;
    size_t byte_index = 1;
    uint8_t first_byte = bytes[0];
    uint64_t num_block = 0;
    uint64_t largest = 0;
    uint64_t last_range = 0;
    uint64_t ack_range = 0;
    uint64_t acked_mask = 0;
    uint64_t gap_begin = 0;
    size_t l_largest = 0;
    size_t l_delay = 0;
    size_t l_num_block = 0;
    size_t l_last_range = 0;

    if (first_byte != picoquic_frame_type_ack) {
        ret = -1;
    } else {
        /* Largest */
        if (byte_index < bytes_max) {
            l_largest = picoquic_varint_decode(bytes + byte_index, bytes_max - byte_index, &largest);
            byte_index += l_largest;
        }

        /* ACK delay */
        if (byte_index < bytes_max) {
            l_delay = picoquic_varint_skip(bytes + byte_index);
            byte_index += l_delay;
        }

        /* Num blocks */
        if (byte_index < bytes_max) {
            l_num_block = picoquic_varint_decode(bytes + byte_index, bytes_max - byte_index, &num_block);
            byte_index += l_num_block;
        }

        /* last range */
        if (byte_index < bytes_max) {
            l_last_range = picoquic_varint_decode(bytes + byte_index, bytes_max - byte_index, &last_range);
            byte_index += l_last_range;
        }

        if (l_largest == 0 || l_delay == 0 || l_num_block == 0 || l_last_range == 0 || byte_index > bytes_max) {
            ret = -1;
        } else {
            if (last_range <= largest) {
                ack_range_mask(&acked_mask, largest, last_range + 1);
                gap_begin = largest - last_range - 1;
            } else {
                ret = -1;
            }

            for (int i = 0; ret == 0 && i < num_block; i++) {
                size_t l_gap = 0;
                size_t l_range = 0;
                uint64_t gap = 0;

                /* Decode the gap */
                if (byte_index < bytes_max) {
                    l_gap = picoquic_varint_decode(bytes + byte_index, bytes_max - byte_index, &gap);
                    byte_index += l_gap;
                    gap += 1;
                }
                /* decode the range */
                if (byte_index < bytes_max) {
                    l_range = picoquic_varint_decode(bytes + byte_index, bytes_max - byte_index, &ack_range);
                    byte_index += l_range;
                }
                if (l_gap == 0 || l_range == 0) {
                    ret = -1;
                } else if (gap > gap_begin) {
                    ret = -1;
                } else {
                    gap_begin -= gap;

                    if (gap_begin >= ack_range) {
                        /* mark the range as received */
                        ack_range_mask(&acked_mask, gap_begin, ++ack_range);

                        /* start of next gap */
                        gap_begin -= ack_range;
                    } else {
                        ret = -1;
                    }
                }
            }
        }

        if (ret == 0) {
            if (byte_index != bytes_max) {
                ret = -1;
            }
        }

        if (ret == 0) {
            if (largest != expected_ack->highest_received || last_range != expected_ack->last_range || num_block != expected_ack->num_blocks) {
                ret = -1;
            }
        }

        if (ret == 0) {
            acked_mask |= *previous_mask;
            if (acked_mask != expected_mask) {
                ret = -1;
            }
            *previous_mask = acked_mask;
        }
    }

    return ret;
}


int sendacktest()
{
    int ret = 0;
    picoquic_quic_t* quic;
    picoquic_cnx_t * cnx;
    uint64_t current_time;
    uint64_t received_mask = 0;
    uint64_t previous_mask = 0;
    uint8_t bytes[256];
    picoquic_packet_context_enum pc = 0;

    if (picoquic_test_set_minimal_cnx(&quic, &cnx) != 0) {
        return -1;
    }
    cnx->sending_ecn_ack = 0; /* don't write an ack_ecn frame */
    
    if (check_ack_ranges(&cnx->ack_ctx[pc].sack_list) != 0) {
        ret = -1;
    }

    for (size_t i = 0; ret == 0 && i < nb_test_pn64; i++) {
        current_time = ((uint64_t)i) * 100;

        if (picoquic_record_pn_received(cnx, pc, cnx->first_local_cnxid_list->local_cnxid_first, test_pn64[i], current_time) != 0) {
            ret = -1;
        }

        if (check_ack_ranges(&cnx->ack_ctx[pc].sack_list) != 0) {
            ret = -1;
        }

        if (ret == 0) {
            int more_data = 0;
            uint8_t* bytes_next = picoquic_format_ack_frame(cnx, bytes, bytes + sizeof(bytes), &more_data, 0, pc, 0);

            received_mask |= 1ull << (test_pn64[i] & 63);

            if (check_ack_ranges(&cnx->ack_ctx[pc].sack_list) != 0) {
                ret = -1;
            }

            if (ret == 0) {
                ret = basic_ack_parse(bytes, bytes_next - bytes, &expected_ack[i], &previous_mask, received_mask);
            }

            if (ret != 0) {
                ret = -1; /* useless code, but helps with checkpointing */
            }
        }
    }

    picoquic_test_delete_minimal_cnx(&quic, &cnx);

    return ret;
}

int sendack_loop_test_one(uint64_t ack_gap, uint64_t ack_delay)
{
    int ret = 0;
    picoquic_cnx_t * cnx;
    picoquic_quic_t * quic;
    uint64_t current_time;
    uint64_t next_ack_time = UINT64_MAX;
    uint64_t largest_received_number = 0;
    uint64_t largest_ack_number = 0;
    uint64_t largest_time_sent = 0;
    uint8_t bytes[256];
    picoquic_packet_context_enum pc = 0;

    if (picoquic_test_set_minimal_cnx(&quic, &cnx) != 0) {
        return -1;
    }

    if (picoquic_create_local_cnxid(cnx, 0, NULL, 0) == NULL) {
        return -1;
    }

    //picoquic_sack_list_init(&cnx->ack_ctx[pc].sack_list);
    cnx->sending_ecn_ack = 0; /* don't write an ack_ecn frame */
    cnx->ack_delay_remote = ack_delay;
    cnx->ack_gap_remote = ack_gap;

    if (check_ack_ranges(&cnx->ack_ctx[pc].sack_list) != 0) {
        ret = -1;
    }

    for (size_t i = 0; ret == 0 && i < nb_test_pn64; i++) {
        int ack_sent = 0;
        int out_of_order = 0;
        current_time = ((uint64_t)i) * 1000;

        if (picoquic_record_pn_received(cnx, pc, cnx->first_local_cnxid_list->local_cnxid_first, test_pn64[i], current_time) != 0) {
            ret = -1;
        }
        else {
            if (largest_received_number + 1 != test_pn64[i]) {
                out_of_order = 1;
            }
            picoquic_set_ack_needed(cnx, current_time, pc, cnx->path[0], out_of_order);
            if (next_ack_time > current_time + ack_delay) {
                next_ack_time = current_time + ack_delay;
            }
            if (largest_received_number < test_pn64[i]) {
                largest_received_number = test_pn64[i];
            }

            if (check_ack_ranges(&cnx->ack_ctx[pc].sack_list) != 0) {
                ret = -1;
            }
        }

        for (int k=0; ret == 0 && k < 5; k++){
            int more_data = 0;
            uint8_t* bytes_next = bytes;
            uint64_t next_wake_time = UINT64_MAX;
            size_t ack_length = 0;

            current_time = ((uint64_t)i) * 1000 + ((uint64_t)k)*10;
            
            if (picoquic_is_ack_needed(cnx, current_time, &next_wake_time, pc, 0)) {
                bytes_next = picoquic_format_ack_frame(cnx, bytes_next, bytes + sizeof(bytes), &more_data,
                    current_time, pc, 0);

                if (bytes_next == NULL) {
                    /* unexpected! */
                    ret = -1;
                }
                else if (more_data) {
                    /* unexpected */
                    ret = -1;
                }
                else {
                    ack_length = bytes_next - bytes;
                }
            }
            
            if (ret == 0) {
                if (ack_length == 0) {
                    if (!ack_sent) {
                        if (largest_ack_number + ack_gap < largest_received_number) {
                            DBG_PRINTF("Ack loop (%d,%d), missing ack by number", i, k);
                            ret = -1;
                        }
                        else if (largest_time_sent + ack_delay < largest_time_sent) {
                            DBG_PRINTF("Ack loop (%d,%d), missing ack by time", i, k);
                            ret = -1;
                        }
                    }
                }
                else {
                    if (ack_sent) {
                        DBG_PRINTF("Ack loop (%d,%d), duplicate ack", i, k);
                        ret = -1;
                    }
                    else if (largest_ack_number + ack_gap > largest_received_number &&
                        largest_time_sent + ack_delay > current_time &&
                        !out_of_order) {
                        DBG_PRINTF("Ack loop (%d,%d), sent before time or number", i, k);
                        ret = -1;
                    } else {
                        ack_sent = 1;
                        largest_ack_number = largest_received_number;
                        largest_time_sent = current_time;
                    }
                }
            }
        }
    }

    picoquic_test_delete_minimal_cnx(&quic, &cnx);

    return ret;
}

int sendack_loop_test()
{
    int ret;
    uint64_t ack_gap[3] = { 0, 2, 10000 };
    uint64_t ack_delay[3] = { 0, 1000, 25 };

    for (int i = 0; i < 3; i++) {
        if ((ret = sendack_loop_test_one(ack_gap[i], ack_delay[i])) != 0) {
            DBG_PRINTF("ack loop test (%" PRIu64", %" PRIu64") fails", ack_gap[i], ack_delay[i]);
        }
    }
    return ret;
}

typedef struct st_test_ack_range_t {
    uint64_t range_min;
    uint64_t range_max;
} test_ack_range_t;

static const test_ack_range_t ack_range[] = {
    { 1, 1000 },
    { 0, 0 },
    { 3001, 4000 },
    { 4001, 5000 },
    { 6001, 7000 },
    { 5001, 6000 },
    { 1501, 2500 },
    { 501, 1500 },
    { 501, 7500 }
};

static const size_t nb_ack_range = sizeof(ack_range) / sizeof(test_ack_range_t);

int ackrange_test()
{
    int ret = 0;
    picoquic_sack_list_t sack0;

    picoquic_sack_list_init(&sack0);

    for (size_t i = 0; ret == 0 && i < nb_ack_range; i++) {
        ret = picoquic_check_sack_list(&sack0,
            ack_range[i].range_min, ack_range[i].range_max);

        if (ret == 0) {
            ret = picoquic_update_sack_list(&sack0,
                ack_range[i].range_min, ack_range[i].range_max, 0);
        }

        if (ret == 0) {
            ret = check_ack_ranges(&sack0);
        }

        for (size_t j = 0; j < i; j++) {
            if (picoquic_check_sack_list(&sack0,
                    ack_range[j].range_min, ack_range[j].range_max)
                == 0) {
                ret = -1;
                break;
            }
        }

        if (ret != 0) {
            break;
        }
    }

    if (ret == 0 && picoquic_sack_list_first(&sack0) != 0) {
        ret = -1;
    }

    if (ret == 0 && picoquic_sack_list_last(&sack0)!= 7500) {
        ret = -1;
    }

    if (ret == 0 && picoquic_sack_list_first_range(&sack0) != NULL) {
        ret = -1;
    }

    picoquic_sack_list_free(&sack0);

    return ret;
}


/* Examine what happens when the packets are received in disorder. In this test, even packets (0, 2..)
 * are received through a high latency path, odd packets (1..3) through a low latency path, and the
 * ack-of-ack is sent after 32 packets are received. The goal is to verify that ack ranges are
 * retained long enough to allow for coalescing. We measure the maximum nimber of ack ranges in the mix.
 * 
 * The "horizon" variant studies what happens when setting an "horizon" under which ack ranges shall
 * be kept, in order to allow merging of ranges.
 */

#define ACK_DISORDER_LOG "ack_disorder_test.csv"
#define ACK_HORIZON_LOG "ack_horizon_test.csv"

typedef struct st_ack_disorder_ackk_t {
    uint64_t pn;
    uint64_t arrive_time;
    uint64_t ackk_time;
    size_t nb_ranges_arrive;
    size_t nb_ranges_ack;
    size_t nb_acked;
} ack_disorder_ackk_t;

int ack_disorder_receive_pn(picoquic_sack_list_t * sack0,
    uint64_t pn, uint64_t next_time, uint64_t ack_interval,
    size_t * nb_ackk, size_t nb_ranges, ack_disorder_ackk_t* ackk_list)
{
    int ret = 0;

    if (picoquic_update_sack_list(sack0, pn, pn, next_time) != 0) {
        ret = -1;
    }
    else if (*nb_ackk >= nb_ranges){
        ret = -1;
    }
    else {
        ackk_list[*nb_ackk].pn = pn;
        ackk_list[*nb_ackk].arrive_time = next_time;
        ackk_list[*nb_ackk].ackk_time = next_time + ack_interval;
        ackk_list[*nb_ackk].nb_ranges_arrive = picoquic_sack_list_size(sack0);
        ackk_list[*nb_ackk].nb_ranges_ack = 0;
        *nb_ackk += 1;
    }
    return ret;
}

int ack_disorder_test_one(char const * log_name, int64_t horizon_delay, double range_average_max)
{
    size_t const nb_ranges = 1000;
    size_t const nb_even_ranges = nb_ranges / 2;
    size_t const nb_odd_ranges = nb_ranges - nb_even_ranges;
    uint64_t const low_latency = 11111;
    uint64_t const high_latency = 300000;
    uint64_t const ack_interval = 100000;
    uint64_t const packet_interval = 1000;
    ack_disorder_ackk_t* ackk_list = (ack_disorder_ackk_t*)malloc(nb_ranges * sizeof(ack_disorder_ackk_t));
    size_t nb_ackk = 0;
    size_t i_ackk = 0;
    size_t i_even_arrive = 0;
    size_t i_odd_arrive = 0;
    uint64_t t_even_arrive = low_latency;
    uint64_t t_odd_arrive = packet_interval + high_latency;
    uint64_t pn;
    int ret = 0;
    picoquic_sack_list_t sack0;

    /* Initialize the test sack list */
    if (ackk_list == NULL) {
        ret = -1;
    } 
    else {
        picoquic_sack_list_init(&sack0);
    }

    sack0.horizon_delay = horizon_delay;

    /* Run a loop to simulate arrival of packets and ack of ack */
    while (ret == 0 && (i_even_arrive < nb_even_ranges || i_odd_arrive < nb_odd_ranges || i_ackk < nb_ackk)) {
        uint64_t next_time = UINT64_MAX;
        int i_action = -1; /* by default do odd arrival */

        if (i_odd_arrive < nb_odd_ranges) {
            i_action = 0;
            next_time = t_odd_arrive;
        }

        if (i_even_arrive < nb_even_ranges && t_even_arrive < next_time) {
            i_action = 1;
            next_time = t_even_arrive;
        }

        if (i_ackk < nb_ackk && ackk_list[i_ackk].ackk_time < next_time) {
            i_action = 2;
            next_time = ackk_list[i_ackk].ackk_time;
        }

        switch (i_action) {
        case 0: /* arrival on odd path */
            pn = 2 * i_odd_arrive + 1;
            i_odd_arrive++;
            t_odd_arrive += packet_interval;
            if (ack_disorder_receive_pn(&sack0, pn, next_time, ack_interval, &nb_ackk, nb_ranges, ackk_list) != 0) {
                ret = -1;
            }
            break;
        case 1: /* arrival on even path */
            pn = 2 * i_even_arrive;
            i_even_arrive++;
            t_even_arrive += packet_interval;
            if (ack_disorder_receive_pn(&sack0, pn, next_time, ack_interval, &nb_ackk, nb_ranges, ackk_list) != 0) {
                ret = -1;
            }
            break;
        case 2: /* ack of ack */
            (void)picoquic_process_ack_of_ack_range(&sack0, NULL, ackk_list[i_ackk].pn, ackk_list[i_ackk].pn);
            ackk_list[i_ackk].nb_ranges_ack = picoquic_sack_list_size(&sack0);
            i_ackk++;
            break;
        }
    }


    if (ret == 0) {
        FILE* F = picoquic_file_open(log_name, "w");

        if (F == NULL) {
            ret = -1;
        }
        else {
            fprintf(F, "pn,arrive_time,ackk_time,nb_ranges_arrive,nb_ranges_ack\n");
            for (size_t i = 0; i < nb_ackk; i++) {
                (void)fprintf(F, "%"PRIu64 ", %"PRIu64 ", %"PRIu64 ", %zu, %zu\n",
                    ackk_list[i].pn, ackk_list[i].arrive_time, ackk_list[i].ackk_time,
                    ackk_list[i].nb_ranges_arrive, ackk_list[i].nb_ranges_ack);
            }
            (void) picoquic_file_close(F);
        }
    }

    if (ret == 0) {
        /* Compute average number of ACK frames at ACK time */
        uint64_t sum_ranges_ack = 0;
        double range_average;
        for (size_t i = 0; i < nb_ackk; i++) {
            sum_ranges_ack += ackk_list[i].nb_ranges_ack;
        }
        range_average = (double)sum_ranges_ack / (double)nb_ackk;
        if (range_average > range_average_max) {
            DBG_PRINTF("Got %f ranges, larger than expected %f", range_average, range_average_max);
            ret = -1;
        }
    }

    if (ackk_list != NULL) {
        free(ackk_list);
    }

    picoquic_sack_list_free(&sack0);

    return ret;
}

int ack_disorder_test()
{
    int ret = ack_disorder_test_one(ACK_DISORDER_LOG, 0, 133.0);
    return ret;
}

int ack_horizon_test()
{
    int ret = ack_disorder_test_one(ACK_HORIZON_LOG, 1000000, 196.0);
    return ret;
}
