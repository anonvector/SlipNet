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

/*
 * The purpose of the ACK of ACK logic is to prune the sack list from blocks that
 * have already been notified to the peer, in an ACK that the peer has acknowledged.
 *
 * Suppose the simplest case: ACK list says "1-9", previous ACK was saying "1-8", 
 * ACK list will now be saying "9-9".
 *
 * More complex case: ACK list says "1-3","5-6", "8-9". ACK says "1-3", "5-6", new list
 * should say "0-9".
 *
 * Special case: ACK list says "1-6","8-9", ACK says "1-3", "5-6", new list should say?
 * (Probably "1-6","8-9").
 *
 * Note that there is little concern about leaving holes -- they are unlikely to
 * be filled later. But we don't want to create extra fragmentation. Sack ranges 
 * should only be pruned if there is an exact match, or if the ack range matched the
 * tail of the "largest" range.
 */

typedef struct st_test_ack_range_t {
    uint64_t start_of_sack_range;
    uint64_t end_of_sack_range;
    uint64_t ack_time;
} test_ack_range_t;

static const test_ack_range_t test_range_in_1[] = {
    { 1, 9 }
};

static const test_ack_range_t test_range_ack_1[] = {
    { 1, 8 }
};

static const test_ack_range_t test_range_res_1[] = {
    { 9, 9 }
};

static const test_ack_range_t test_range_in_2[] = {
    { 8, 9 }, { 5, 6 }, { 1, 3 },
};

static const test_ack_range_t test_range_ack_2[] = {
    { 5, 6 }, { 1, 3 },
};

static const test_ack_range_t test_range_res_2[] = {
    { 8, 9 }
};

static const test_ack_range_t test_range_in_3[] = {
    { 8, 9 }, { 1, 6 }
};

static const test_ack_range_t test_range_ack_3[] = {
    { 5, 6 }, { 1, 3 }
};

static const test_ack_range_t test_range_res_3[] = {
    { 8, 9 }, { 1, 6 }
};

typedef struct st_test_ack_of_ack_t {
    char const* test_name;
    test_ack_range_t const* initial;
    size_t nb_initial;
    test_ack_range_t const* ack;
    size_t nb_ack;
    test_ack_range_t const* result;
    size_t nb_result;
    uint32_t version_flags;
} test_ack_of_ack_t;

static const test_ack_of_ack_t test_ack_of_ack_list[] = {
    { "simple",
        test_range_in_1, sizeof(test_range_in_1) / sizeof(test_ack_range_t),
        test_range_ack_1, sizeof(test_range_ack_1) / sizeof(test_ack_range_t),
        test_range_res_1, sizeof(test_range_res_1) / sizeof(test_ack_range_t),
        0 },
    { "two ranges",
        test_range_in_2, sizeof(test_range_in_2) / sizeof(test_ack_range_t),
        test_range_ack_2, sizeof(test_range_ack_2) / sizeof(test_ack_range_t),
        test_range_res_2, sizeof(test_range_res_2) / sizeof(test_ack_range_t),
        0 },
    { "no op",
        test_range_in_3, sizeof(test_range_in_3) / sizeof(test_ack_range_t),
        test_range_ack_3, sizeof(test_range_ack_3) / sizeof(test_ack_range_t),
        test_range_res_3, sizeof(test_range_res_3) / sizeof(test_ack_range_t),
        0 }
};

/*
 * Fill a structured SACK list from a test range 
 */

static int fill_test_sack_list(picoquic_sack_list_t* sack_list,
    test_ack_range_t const* ranges, size_t nb_ranges)
{
    int ret = 0;
    for (size_t i = 0; ret == 0 &&  i < nb_ranges; i++) {
        ret = picoquic_sack_insert_item(sack_list, ranges[i].start_of_sack_range, ranges[i].end_of_sack_range, 0);
    }
    return ret;
}

/*
 * Compare a structured list to a test range
 */

static int cmp_test_sack_list(picoquic_sack_list_t* sack_list,
    test_ack_range_t const* ranges, size_t nb_ranges)
{
    size_t nb_compared = 0;
    picoquic_sack_item_t* sack_head = picoquic_sack_last_item(sack_list);
    picoquic_sack_item_t* next = sack_head;

    for (size_t i = 0; i < nb_ranges; i++) {
        if (next->start_of_sack_range != ranges[i].start_of_sack_range || next->end_of_sack_range != ranges[i].end_of_sack_range) {
            break;
        }

        nb_compared++;

        next = picoquic_sack_previous_item(next);

        if (next == NULL) {
            break;
        }
    }

    return (next == NULL && nb_compared == nb_ranges) ? 0 : -1;
}

static size_t build_test_ack(test_ack_range_t const* ranges, size_t nb_ranges,
    uint8_t* bytes, size_t bytes_max, uint32_t version_flags)
{
    size_t byte_index = 0;
    uint64_t ack_range = 0;

    /* Encode the first byte */
    bytes[byte_index++] = picoquic_frame_type_ack;
    /* Encode the largest seen */
    byte_index += picoquic_varint_encode(bytes + byte_index, bytes_max - byte_index, ranges[0].end_of_sack_range);
    /* Set the ACK delay to zero for these tests */
    byte_index += picoquic_varint_encode(bytes + byte_index, bytes_max - byte_index, 0);
    /* Encode the number of blocks -- assume nb_ranges always lower than 64 */
    bytes[byte_index++] = (uint8_t)(nb_ranges - 1);
    /* Encode the size of the first ack range */
    ack_range = ranges[0].end_of_sack_range - ranges[0].start_of_sack_range;
    byte_index += picoquic_varint_encode(bytes + byte_index, bytes_max - byte_index, ack_range);
    /* Encode each of the ack block items */
    for (size_t i = 1; i < nb_ranges && byte_index + 5 < bytes_max; i++) {
        uint64_t gap = ranges[i - 1].start_of_sack_range - ranges[i].end_of_sack_range - 2;
        byte_index += picoquic_varint_encode(bytes + byte_index, bytes_max - byte_index, gap);
        ack_range = ranges[i].end_of_sack_range - ranges[i].start_of_sack_range;
        byte_index += picoquic_varint_encode(bytes + byte_index, bytes_max - byte_index, ack_range);
    }
    return byte_index;
}

/*
 * Single sample test.
 */
static int ack_of_ack_do_one_test(test_ack_of_ack_t const* sample)
{
    int ret = 0;
    picoquic_sack_list_t sack_list;
    uint8_t ack[1024];
    size_t consumed;

    picoquic_sack_list_init(&sack_list);

    if (ret == 0) {
        ret = fill_test_sack_list(&sack_list, sample->initial, sample->nb_initial);
    }

    if (ret == 0) {
        size_t ack_length = build_test_ack(sample->ack, sample->nb_ack, ack, sizeof(ack),
            sample->version_flags);
        ret = picoquic_process_ack_of_ack_frame(&sack_list, ack, ack_length, &consumed, 0);
    }

    if (ret == 0) {
        ret = cmp_test_sack_list(&sack_list, sample->result, sample->nb_result);
    }
    else {
        DBG_PRINTF("ack of ack, ret=%d", ret);
    }

    picoquic_sack_list_free(&sack_list);

    return ret;
}

/*
 * Perform the whole set of range tests 
 */

int ack_of_ack_test()
{
    int ret = 0;

    for (size_t i = 0; i < sizeof(test_ack_of_ack_list) / sizeof(test_ack_of_ack_t); i++) {
        ret = ack_of_ack_do_one_test(&test_ack_of_ack_list[i]);

        if (ret != 0) {
            break;
        }
    }

    return ret;
}