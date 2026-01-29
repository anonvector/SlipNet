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

#include "tls_api.h"
#include "picoquic_internal.h"
#include "picoquictest_internal.h"
#include <stdlib.h>
#include <string.h>

#include "logreader.h"
#include "picoquic_binlog.h"
#include "picoquic_logger.h"
#include "qlog.h"

/*
 * Test of the skip frame API.
 * This test is only defined for the varint encodings -- the older fixed int
 * versions are obsolete by now.
 */

static uint8_t test_frame_type_padding[] = { 0, 0, 0 };

static uint8_t test_frame_type_reset_stream[] = {
    picoquic_frame_type_reset_stream,
    17,
    1,
    1
};

static uint8_t test_type_connection_close[] = {
    picoquic_frame_type_connection_close,
    0x80, 0x00, 0xCF, 0xFF, 0,
    9,
    '1', '2', '3', '4', '5', '6', '7', '8', '9'
};

static uint8_t test_type_application_close[] = {
    picoquic_frame_type_application_close,
    0,
    0
};

static uint8_t test_type_application_close_reason[] = {
    picoquic_frame_type_application_close,
    0x44, 4,
    4,
    't', 'e', 's', 't'
};

static uint8_t test_frame_type_max_data[] = {
    picoquic_frame_type_max_data,
    0xC0, 0, 0x01, 0, 0, 0, 0, 0
};

static uint8_t test_frame_type_max_stream_data[] = {
    picoquic_frame_type_max_stream_data,
    1,
    0x80, 0x01, 0, 0
};

static uint8_t test_frame_type_max_streams_bidir[] = {
    picoquic_frame_type_max_streams_bidir,
    0x41, 0
};

static uint8_t test_frame_type_max_streams_unidir[] = {
    picoquic_frame_type_max_streams_unidir,
    0x41, 7
};

static uint8_t test_frame_type_ping[] = {
    picoquic_frame_type_ping
};

static uint8_t test_frame_type_blocked[] = {
    picoquic_frame_type_data_blocked,
    0x80, 0x01, 0, 0
};

static uint8_t test_frame_type_stream_blocked[] = {
    picoquic_frame_type_stream_data_blocked,
    0x80, 1, 0, 0,
    0x80, 0x02, 0, 0
};

static uint8_t test_frame_type_streams_blocked_bidir[] = {
    picoquic_frame_type_streams_blocked_bidir,
    0x41, 0x00
};

static uint8_t test_frame_type_streams_blocked_unidir[] = {
    picoquic_frame_type_streams_blocked_unidir,
    0x42, 0x00
};

static uint8_t test_frame_type_new_connection_id[] = {
    picoquic_frame_type_new_connection_id,
    7,
    0,
    8,
    1, 2, 3, 4, 5, 6, 7, 8,
    0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7,
    0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF
};

static uint8_t test_frame_type_stop_sending[] = {
    picoquic_frame_type_stop_sending,
    17,
    0x17
};

static uint8_t test_frame_type_path_challenge[] = {
    picoquic_frame_type_path_challenge,
    1, 2, 3, 4, 5, 6, 7, 8
};

static uint8_t test_frame_type_path_response[] = {
    picoquic_frame_type_path_response,
    1, 2, 3, 4, 5, 6, 7, 8
};

static uint8_t test_frame_type_new_token[] = {
    picoquic_frame_type_new_token,
    17, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17
};

static uint8_t test_frame_type_ack[] = {
    picoquic_frame_type_ack,
    0xC0, 0, 0, 1, 2, 3, 4, 5,
    0x44, 0,
    2,
    5,
    0, 0,
    5, 12
};

static uint8_t test_frame_type_ack_ecn[] = {
    picoquic_frame_type_ack_ecn,
    0xC0, 0, 0, 1, 2, 3, 4, 5,
    0x44, 0,
    2,
    5,
    0, 0,
    5, 12,
    3, 0, 1
};

static uint8_t test_frame_type_stream_range_min[] = {
    picoquic_frame_type_stream_range_min,
    1,
    0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7,
    0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF
};

static uint8_t test_frame_type_stream_range_max[] = {
    picoquic_frame_type_stream_range_min + 2 + 4,
    1,
    0x44, 0,
    0x10,
    0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7,
    0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF
};

static uint8_t test_frame_type_crypto_hs[] = {
    picoquic_frame_type_crypto_hs,
    0,
    0x10,
    0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7,
    0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF
};


static uint8_t test_frame_type_retire_connection_id[] = {
    picoquic_frame_type_retire_connection_id,
    1
};

static uint8_t test_frame_type_datagram[] = {
    picoquic_frame_type_datagram,
    0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7,
    0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF
};

static uint8_t test_frame_type_datagram_l[] = {
    picoquic_frame_type_datagram_l,
    0x10,
    0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7,
    0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF
};

static uint8_t test_frame_type_handshake_done[] = {
    picoquic_frame_type_handshake_done
};

static uint8_t test_frame_type_ack_frequency[] = {
    0x40, picoquic_frame_type_ack_frequency,
    17, 0x0A, 0x44, 0x20, 0x00
};

static uint8_t test_frame_type_ack_frequency_t5[] = {
    0x40, picoquic_frame_type_ack_frequency,
    17, 0x0A, 0x44, 0x20, 0x40, 0x05
};

static uint8_t test_frame_type_immediate_ack[] = {
    picoquic_frame_type_immediate_ack
};

static uint8_t test_frame_type_time_stamp[] = {
    (uint8_t)(0x40 | (picoquic_frame_type_time_stamp >> 8)), (uint8_t)(picoquic_frame_type_time_stamp & 0xFF),
    0x44, 0
};

static uint8_t test_frame_type_path_abandon_0[] = {
    (uint8_t)(0x80 | (picoquic_frame_type_path_abandon >> 24)), (uint8_t)(picoquic_frame_type_path_abandon >> 16),
    (uint8_t)(picoquic_frame_type_path_abandon >> 8), (uint8_t)(picoquic_frame_type_path_abandon & 0xFF),
    0x01, /* Path 0 */
    0x00 /* No error */
};

static uint8_t test_frame_type_path_abandon_1[] = {
    (uint8_t)(0x80 | (picoquic_frame_type_path_abandon >> 24)), (uint8_t)(picoquic_frame_type_path_abandon >> 16),
    (uint8_t)(picoquic_frame_type_path_abandon >> 8), (uint8_t)(picoquic_frame_type_path_abandon & 0xFF),
    0x01,
    0x11 /* Some new error */
};

static uint8_t test_frame_type_path_backup[] = {
    (uint8_t)(0x80 | (picoquic_frame_type_path_backup >> 24)), (uint8_t)(picoquic_frame_type_path_backup >> 16),
    (uint8_t)(picoquic_frame_type_path_backup >> 8), (uint8_t)(picoquic_frame_type_path_backup & 0xFF),
    0x00, /* Path 0 */
    0x0F, /* Sequence = 0x0F */
};

static uint8_t test_frame_type_path_available[] = {
    (uint8_t)(0x80 | (picoquic_frame_type_path_available>> 24)), (uint8_t)(picoquic_frame_type_path_available >> 16),
    (uint8_t)(picoquic_frame_type_path_available >> 8), (uint8_t)(picoquic_frame_type_path_available & 0xFF),
    0x00, /* Path 0 */
    0x0F, /* Sequence = 0x0F */
};


static uint8_t test_frame_type_bdp[] = {
    (uint8_t)(0x80 | (picoquic_frame_type_bdp >> 24)), (uint8_t)(picoquic_frame_type_bdp >> 16),
    (uint8_t)(picoquic_frame_type_bdp >> 8), (uint8_t)(picoquic_frame_type_bdp & 0xFF),
    0x01, 0x02, 0x03, 
    0x04, 0x0A, 0x0, 0x0, 0x01
};

static uint8_t test_frame_type_path_ack[] = {
    (uint8_t)(0x80|(picoquic_frame_type_path_ack>>24)),
    (uint8_t)(picoquic_frame_type_path_ack>>16),
    (uint8_t)(picoquic_frame_type_path_ack>>8),
    (uint8_t)(picoquic_frame_type_path_ack),
    0,
    0xC0, 0, 0, 1, 2, 3, 4, 5,
    0x44, 0,
    2,
    5,
    0, 0,
    5, 12
};

static uint8_t test_frame_type_path_ack_ecn[] = {
    (uint8_t)(0x80|(picoquic_frame_type_path_ack_ecn>>24)),
    (uint8_t)(picoquic_frame_type_path_ack_ecn>>16),
    (uint8_t)(picoquic_frame_type_path_ack_ecn>>8),
    (uint8_t)(picoquic_frame_type_path_ack_ecn),
    0,
    0xC0, 0, 0, 1, 2, 3, 4, 5,
    0x44, 0,
    2,
    5,
    0, 0,
    5, 12,
    3, 0, 1
};

static uint8_t test_frame_type_max_path_id[] = {
    (uint8_t)(0x80 | (picoquic_frame_type_max_path_id >> 24)), (uint8_t)(picoquic_frame_type_max_path_id >> 16),
    (uint8_t)(picoquic_frame_type_max_path_id >> 8), (uint8_t)(picoquic_frame_type_max_path_id & 0xFF),
    0x11, /* max paths = 17 */
};

static uint8_t test_frame_type_path_new_connection_id[] = {
    (uint8_t)(0x80 | (picoquic_frame_type_path_new_connection_id >> 24)), (uint8_t)(picoquic_frame_type_path_new_connection_id >> 16),
    (uint8_t)(picoquic_frame_type_path_new_connection_id >> 8), (uint8_t)(picoquic_frame_type_path_new_connection_id & 0xFF),
    1,
    7,
    0,
    8,
    1, 2, 3, 4, 5, 6, 7, 8,
    0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8,
    0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF, 0xB0
};

static uint8_t test_frame_type_path_retire_connection_id[] = {
    (uint8_t)(0x80 | (picoquic_frame_type_path_retire_connection_id >> 24)), (uint8_t)(picoquic_frame_type_path_retire_connection_id >> 16),
    (uint8_t)(picoquic_frame_type_path_retire_connection_id >> 8), (uint8_t)(picoquic_frame_type_path_retire_connection_id & 0xFF),
    0,
    2
};

static uint8_t test_frame_type_path_blocked[] = {
    (uint8_t)(0x80 | (picoquic_frame_type_path_blocked >> 24)), (uint8_t)(picoquic_frame_type_path_blocked >> 16),
    (uint8_t)(picoquic_frame_type_path_blocked >> 8), (uint8_t)(picoquic_frame_type_path_blocked & 0xFF),
    0x11, /* max paths = 17 */
};

static uint8_t test_frame_observed_address_v4[] = {
    (uint8_t)(0x80 | (picoquic_frame_type_observed_address_v4 >> 24)), (uint8_t)(picoquic_frame_type_observed_address_v4 >> 16),
    (uint8_t)(picoquic_frame_type_observed_address_v4 >> 8), (uint8_t)(picoquic_frame_type_observed_address_v4 & 0xFF),
    1,
    0x1, 0x2, 0x3, 0x4,
    0x12, 0x34,
};

static uint8_t test_frame_observed_address_v6[] = {
    (uint8_t)(0x80 | (picoquic_frame_type_observed_address_v6 >> 24)), (uint8_t)(picoquic_frame_type_observed_address_v6 >> 16),
    (uint8_t)(picoquic_frame_type_observed_address_v6 >> 8), (uint8_t)(picoquic_frame_type_observed_address_v6 & 0xFF),
    2,
    0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf, 0x0,
    0x45, 0x67,
};

#define TEST_SKIP_ITEM_OLD(n, x, a, l, e, err, skip_err)    \
    {                                                       \
        n, x, sizeof(x), a, l, e, err, skip_err, 0, 0       \
    }

#define TEST_SKIP_ITEM_OLD_MPATH(n, x, a, l, e, err, skip_err, mpath) \
    {                                                             \
        n, x, sizeof(x), a, l, e, err, skip_err, mpath, 0         \
    }


#define TEST_SKIP_ITEM(n, x, a, l, e, err, skip_err, varints) \
    {                                                         \
        n, x, sizeof(x), a, l, e, err, skip_err, 0, varints   \
    }

#define TEST_SKIP_ITEM_MPATH(n, x, a, l, e, err, skip_err, mpath, varints) \
    {                                                                      \
        n, x, sizeof(x), a, l, e, err, skip_err, mpath, varints         \
    }

test_skip_frames_t test_skip_list[] = {
    TEST_SKIP_ITEM("padding", test_frame_type_padding, 1, 0, 0, 0, 0, 0),
    TEST_SKIP_ITEM("reset_stream", test_frame_type_reset_stream, 0, 0, 3, 0, 0, 3),
    TEST_SKIP_ITEM("connection_close", test_type_connection_close, 0, 0, 3, 0, 0, 3),
    TEST_SKIP_ITEM("application_close", test_type_application_close, 0, 0, 3, 0, 0, 2),
    TEST_SKIP_ITEM("application_close", test_type_application_close_reason, 0, 0, 3, 0, 0, 2),

    TEST_SKIP_ITEM("max_data", test_frame_type_max_data, 0, 0, 3, 0, 0, 1),
    TEST_SKIP_ITEM("max_stream_data", test_frame_type_max_stream_data, 0, 0, 3, 0, 0, 2),
    TEST_SKIP_ITEM("max_streams_bidir", test_frame_type_max_streams_bidir, 0, 0, 3, 0, 0, 1),
    TEST_SKIP_ITEM("max_streams_unidir", test_frame_type_max_streams_unidir, 0, 0, 3, 0, 0, 1),
    TEST_SKIP_ITEM_OLD("ping", test_frame_type_ping, 0, 0, 3, 0, 0),

    TEST_SKIP_ITEM("blocked", test_frame_type_blocked, 0, 0, 3, 0, 0, 1),
    TEST_SKIP_ITEM("stream_data_blocked", test_frame_type_stream_blocked, 0, 0, 3, 0, 0, 1),
    TEST_SKIP_ITEM("streams_blocked_bidir", test_frame_type_streams_blocked_bidir, 0, 0, 3, 0, 0, 1),
    TEST_SKIP_ITEM("streams_blocked_unidir", test_frame_type_streams_blocked_unidir, 0, 0, 3, 0, 0, 1),
    TEST_SKIP_ITEM("new_connection_id", test_frame_type_new_connection_id, 0, 0, 3, 0, 0, 4),

    TEST_SKIP_ITEM("stop_sending", test_frame_type_stop_sending, 0, 0, 3, 0, 0, 2),
    TEST_SKIP_ITEM("challenge", test_frame_type_path_challenge, 1, 0, 3, 0, 0, 0),
    TEST_SKIP_ITEM("response", test_frame_type_path_response, 1, 0, 3, 0, 0, 0),
    TEST_SKIP_ITEM("new_token", test_frame_type_new_token, 0, 0, 3, 0, 0, 1),
    TEST_SKIP_ITEM("ack", test_frame_type_ack, 1, 0, 3, 0, 0, 8),

    TEST_SKIP_ITEM("ack_ecn", test_frame_type_ack_ecn, 1, 0, 3, 0, 0, 11),
    TEST_SKIP_ITEM("stream_min", test_frame_type_stream_range_min, 0, 1, 3, 0, 0, 1),
    TEST_SKIP_ITEM("stream_max", test_frame_type_stream_range_max, 0, 0, 3, 0, 0, 4),
    TEST_SKIP_ITEM("crypto_hs", test_frame_type_crypto_hs, 0, 0, 2, 0, 0, 2),
    TEST_SKIP_ITEM("retire_connection_id", test_frame_type_retire_connection_id, 0, 0, 3, 0, 0, 1),

    TEST_SKIP_ITEM("datagram", test_frame_type_datagram, 0, 1, 3, 0, 0, 0),
    TEST_SKIP_ITEM("datagram_l", test_frame_type_datagram_l, 0, 0, 3, 0, 0, 1),
    TEST_SKIP_ITEM("handshake_done", test_frame_type_handshake_done, 0, 0, 3, 0, 0, 0),
    TEST_SKIP_ITEM("ack_frequency", test_frame_type_ack_frequency, 0, 0, 3, 0, 0, 4),
    TEST_SKIP_ITEM("ack_frequency_t5", test_frame_type_ack_frequency_t5, 0, 0, 3, 0, 0, 4),

    TEST_SKIP_ITEM("immediate_ack", test_frame_type_immediate_ack, 0, 0, 3, 0, 0, 0),
    TEST_SKIP_ITEM("time_stamp", test_frame_type_time_stamp, 1, 0, 3, 0, 0, 1),
    TEST_SKIP_ITEM_MPATH("path_abandon_0", test_frame_type_path_abandon_0, 0, 0, 3, 0, 0, 1, 2),
    TEST_SKIP_ITEM_MPATH("path_abandon_1", test_frame_type_path_abandon_1, 0, 0, 3, 0, 0, 1, 2),
    TEST_SKIP_ITEM_MPATH("path_backup", test_frame_type_path_backup, 0, 0, 3, 0, 0, 1, 2),

    TEST_SKIP_ITEM_MPATH("path_available", test_frame_type_path_available, 0, 0, 3, 0, 0, 1, 2),
    TEST_SKIP_ITEM_MPATH("max paths", test_frame_type_max_path_id, 0, 0, 3, 0, 0, 1, 1),
    TEST_SKIP_ITEM_MPATH("path_new_connection_id", test_frame_type_path_new_connection_id, 0, 0, 3, 0, 0, 1, 5),
    TEST_SKIP_ITEM_MPATH("path_retire_connection_id", test_frame_type_path_retire_connection_id, 0, 0, 3, 0, 0, 1, 2),
    TEST_SKIP_ITEM_MPATH("paths blocked", test_frame_type_path_blocked, 0, 0, 3, 0, 0, 1, 1),

    TEST_SKIP_ITEM("bdp", test_frame_type_bdp, 0, 0, 3, 0, 0, 4),
    TEST_SKIP_ITEM_MPATH("observed_address_v4", test_frame_observed_address_v4, 0, 0, 3, 0, 0, 2, 1),
    TEST_SKIP_ITEM_MPATH("observed_address_v6", test_frame_observed_address_v6, 0, 0, 3, 0, 0, 2, 1),
    TEST_SKIP_ITEM_MPATH("path_ack", test_frame_type_path_ack, 1, 0, 3, 0, 0, 1, 9),
    TEST_SKIP_ITEM_MPATH("path_ack_ecn", test_frame_type_path_ack_ecn, 1, 0, 3, 0, 0, 1, 12),
};

size_t nb_test_skip_list = sizeof(test_skip_list) / sizeof(test_skip_frames_t);

static uint8_t test_frame_type_bad_reset_stream_offset[] = {
    picoquic_frame_type_reset_stream,
    17,
    1,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
};

static uint8_t test_frame_type_bad_reset_stream[] = {
    picoquic_frame_type_reset_stream,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    1,
    1
};

static uint8_t test_frame_type_bad_reset_stream2[] = {
    picoquic_frame_type_reset_stream,
    0xFF, 0xFF, 0xFF, 0xFF,
    1,
    1
};

static uint8_t test_type_bad_connection_close[] = {
    picoquic_frame_type_connection_close,
    0x80, 0x00, 0xCF, 0xFF, 0,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    '1', '2', '3', '4', '5', '6', '7', '8', '9'
};


static uint8_t test_type_bad_connection_close2[] = {
    picoquic_frame_type_connection_close,
    0x80, 0x00, 0xCF,
};

static uint8_t test_type_bad_application_close[] = {
    picoquic_frame_type_application_close,
    0x44, 4,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    't', 'e', 's', 't'
};

static uint8_t test_frame_type_bad_max_stream_stream[] = {
    picoquic_frame_type_max_stream_data,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x80, 0x01, 0, 0
};

static uint8_t test_frame_type_max_bad_streams_bidir[] = {
    picoquic_frame_type_max_streams_bidir,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
};

static uint8_t test_frame_type_bad_max_streams_unidir[] = {
    picoquic_frame_type_max_streams_unidir,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
};

static uint8_t test_frame_type_bad_new_cid_length[] = {
    picoquic_frame_type_new_connection_id,
    7,
    0,
    0x3F,
    1, 2, 3, 4, 5, 6, 7, 8,
    0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7,
    0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF
};

static uint8_t test_frame_type_bad_new_cid_retire[] = {
    picoquic_frame_type_new_connection_id,
    7,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    8,
    1, 2, 3, 4, 5, 6, 7, 8,
    0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7,
    0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF
};


static uint8_t test_frame_type_illegal_new_cid_retire[] = {
    picoquic_frame_type_new_connection_id,
    7,
    8,
    8,
    1, 2, 3, 4, 5, 6, 7, 8,
    0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7,
    0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF
};

static uint8_t test_frame_type_too_long_new_cid[] = {
    picoquic_frame_type_new_connection_id,
    7,
    0,
    21,
    1, 2, 3, 4, 5, 6, 7, 8, 9, 0,
    1, 2, 3, 4, 5, 6, 7, 8, 9, 0,
    1,
    0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7,
    0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF
};


static uint8_t test_frame_type_bad_stop_sending[] = {
    picoquic_frame_type_stop_sending,
    19,
    0x17
};

static uint8_t test_frame_type_bad_stop_sending2[] = {
    picoquic_frame_type_stop_sending,
    19
};

static uint8_t test_frame_type_bad_new_token[] = {
    picoquic_frame_type_new_token,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17
};

static uint8_t test_frame_type_bad_ack_range[] = {
    picoquic_frame_type_ack,
    0xC0, 0, 0, 1, 2, 3, 4, 5,
    0x44, 0,
    2,
    5,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0,
    5, 12
};

static uint8_t test_frame_type_bad_ack_gaps[] = {
    picoquic_frame_type_ack,
    0xC0, 0, 0, 1, 2, 3, 4, 5,
    0x44, 0,
    2,
    5,
    0, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    5, 12
};

static uint8_t test_frame_type_bad_ack_blocks[] = {
    picoquic_frame_type_ack_ecn,
    0xC0, 0, 0, 1, 2, 3, 4, 5,
    0x44, 0,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    5,
    0, 0,
    5, 12,
    3, 0, 1
};

static uint8_t test_frame_type_bad_crypto_hs[] = {
    picoquic_frame_type_crypto_hs,
    0,
    0x8F, 0xFF, 0xFF, 0xFF,
    0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7,
    0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF
};

static uint8_t test_frame_type_bad_datagram[] = {
    picoquic_frame_type_datagram_l,
    0x8F, 0xFF, 0xFF, 0xFF, 
    0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7,
    0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF
};

static uint8_t test_frame_stream_hang[] = {
    0x01, 0x00, 0x0D, 0xFF, 0xFF, 0xFF, 0x01, 0x00,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
};

static uint8_t test_frame_type_path_abandon_bad_0[] = {
    (uint8_t)(0x80 | (picoquic_frame_type_path_abandon >> 24)), (uint8_t)(picoquic_frame_type_path_abandon >> 16),
    (uint8_t)(picoquic_frame_type_path_abandon >> 8), (uint8_t)(picoquic_frame_type_path_abandon & 0xFF),
    /* Missing path id */
    0x00, /* No error */
};

static uint8_t test_frame_type_path_abandon_bad_1[] = {
    (uint8_t)(0x80 | (picoquic_frame_type_path_abandon >> 24)), (uint8_t)(picoquic_frame_type_path_abandon >> 16),
    (uint8_t)(picoquic_frame_type_path_abandon >> 8), (uint8_t)(picoquic_frame_type_path_abandon & 0xFF),
    0x00,
    0xFF /* Bad error  */
};

static uint8_t test_frame_type_path_available_bad[] = {
    (uint8_t)(0x80 | (picoquic_frame_type_path_available>> 24)), (uint8_t)(picoquic_frame_type_path_available >> 16),
    (uint8_t)(picoquic_frame_type_path_available >> 8), (uint8_t)(picoquic_frame_type_path_available & 0xFF),
    0x00, /* Path 0 */
    /* Missing sequence */
};


static uint8_t test_frame_type_bdp_bad[] = {
    (uint8_t)(0x80 | (picoquic_frame_type_bdp >> 24)), (uint8_t)(picoquic_frame_type_bdp >> 16),
    (uint8_t)(picoquic_frame_type_bdp >> 8), (uint8_t)(picoquic_frame_type_bdp & 0xFF),
    0x01, 0x02, 0x04
};

static uint8_t test_frame_type_bdp_bad_addr[] = {
    (uint8_t)(0x80 | (picoquic_frame_type_bdp >> 24)), (uint8_t)(picoquic_frame_type_bdp >> 16),
    (uint8_t)(picoquic_frame_type_bdp >> 8), (uint8_t)(picoquic_frame_type_bdp & 0xFF),
    0x01, 0x02, 0x04, 0x05, 1, 2, 3, 4, 5
};

static uint8_t test_frame_type_bdp_bad_length[] = {
    (uint8_t)(0x80 | (picoquic_frame_type_bdp >> 24)), (uint8_t)(picoquic_frame_type_bdp >> 16),
    (uint8_t)(picoquic_frame_type_bdp >> 8), (uint8_t)(picoquic_frame_type_bdp & 0xFF),
    0x08, 0x02, 0x04, 0x8F, 0xFF, 0xFF, 0xFF, 1, 2, 3, 4
};

static uint8_t test_frame_type_bad_frame_id[] = {
    0xbf, 0xff, 0xff, 0xff,
    0x08, 0x02, 0x04, 0x8F, 0xFF, 0xFF, 0xFF, 1, 2, 3, 4
};

static uint8_t test_frame_type_bad_ack_first_range[] = {
    0x02, 0x02, 0x00, 0x01, 0x03, 0x00, 0x00, 0x00, 0x00
};

#define ERR_F PICOQUIC_TRANSPORT_FRAME_FORMAT_ERROR
#define ERR_P PICOQUIC_TRANSPORT_PROTOCOL_VIOLATION
#define ERR_S PICOQUIC_TRANSPORT_STREAM_LIMIT_ERROR

test_skip_frames_t test_frame_error_list[] = {
    TEST_SKIP_ITEM_OLD("bad_reset_stream_offset", test_frame_type_bad_reset_stream_offset, 0, 0, 3, PICOQUIC_TRANSPORT_FLOW_CONTROL_ERROR, 0),
    TEST_SKIP_ITEM_OLD("bad_reset_stream", test_frame_type_bad_reset_stream, 0, 0, 3, ERR_S, 0),
    TEST_SKIP_ITEM_OLD("bad_reset_stream2", test_frame_type_bad_reset_stream2, 0, 1, 3, ERR_F, 0),
    TEST_SKIP_ITEM_OLD("bad_connection_close", test_type_bad_connection_close, 0, 0, 3, ERR_F, 1),
    TEST_SKIP_ITEM_OLD("bad_connection_close2", test_type_bad_connection_close2, 0, 1, 3, ERR_F, 1),
    TEST_SKIP_ITEM_OLD("bad_application_close", test_type_bad_application_close, 0, 0, 3, ERR_F, 1),
    TEST_SKIP_ITEM_OLD("bad_max_stream_stream", test_frame_type_bad_max_stream_stream, 0, 0, 3, ERR_S, 0),
    TEST_SKIP_ITEM_OLD("bad_max_streams_bidir", test_frame_type_max_bad_streams_bidir, 0, 0, 3, ERR_S, 0),
    TEST_SKIP_ITEM_OLD("bad_max_streams_unidir", test_frame_type_bad_max_streams_unidir, 0, 0, 3, ERR_S, 0),
    TEST_SKIP_ITEM_OLD("bad_new_connection_id_length", test_frame_type_bad_new_cid_length, 0, 0, 3, ERR_F, 1),
    TEST_SKIP_ITEM_OLD("bad_new_connection_id_retire", test_frame_type_bad_new_cid_retire, 0, 0, 3, ERR_F, 0),
    TEST_SKIP_ITEM_OLD("illegal_new_cid_retire", test_frame_type_illegal_new_cid_retire, 0, 0, 3, ERR_F, 0),
    TEST_SKIP_ITEM_OLD("too_long_new_cid", test_frame_type_too_long_new_cid, 0, 0, 3, ERR_P, 0),
    TEST_SKIP_ITEM_OLD("bad_stop_sending", test_frame_type_bad_stop_sending, 0, 0, 3, PICOQUIC_TRANSPORT_STREAM_STATE_ERROR, 0),
    TEST_SKIP_ITEM_OLD("bad_stop_sending2", test_frame_type_bad_stop_sending2, 0, 1, 3, ERR_F, 0),
    TEST_SKIP_ITEM_OLD("bad_new_token", test_frame_type_bad_new_token, 0, 0, 3, ERR_F, 1),
    TEST_SKIP_ITEM_OLD("bad_ack_range", test_frame_type_bad_ack_range, 1, 0, 3, ERR_F, 0),
    TEST_SKIP_ITEM_OLD("bad_ack_first_range", test_frame_type_bad_ack_first_range, 1, 0, 3, ERR_F, 0),
    TEST_SKIP_ITEM_OLD("bad_ack_gaps", test_frame_type_bad_ack_gaps, 1, 0, 3, ERR_F, 0),
    TEST_SKIP_ITEM_OLD("bad_ack_blocks", test_frame_type_bad_ack_blocks, 1, 0, 3, ERR_F, 1),
    TEST_SKIP_ITEM_OLD("bad_crypto_hs", test_frame_type_bad_crypto_hs, 0, 0, 2, ERR_F, 1),
    TEST_SKIP_ITEM_OLD("bad_datagram", test_frame_type_bad_datagram, 1, 0, 3, ERR_F, 1),
    TEST_SKIP_ITEM_OLD("stream_hang", test_frame_stream_hang, 1, 0, 3, PICOQUIC_TRANSPORT_FINAL_OFFSET_ERROR, 0),
    TEST_SKIP_ITEM_OLD_MPATH("bad_abandon_0", test_frame_type_path_abandon_bad_0, 0, 1, 3, ERR_F, 1, 1),
    TEST_SKIP_ITEM_OLD_MPATH("bad_abandon_1", test_frame_type_path_abandon_bad_1, 0, 0, 3, ERR_F, 1, 1),
    TEST_SKIP_ITEM_OLD_MPATH("bad_path_available", test_frame_type_path_available_bad, 0, 1, 3, ERR_F, 1, 1),
    TEST_SKIP_ITEM_OLD_MPATH("bad_bdp", test_frame_type_bdp_bad, 1, 0, 3, ERR_F, 0, 1),
    TEST_SKIP_ITEM_OLD_MPATH("bad_bdp_addr", test_frame_type_bdp_bad_addr, 1, 0, 3, ERR_F, 0, 1),
    TEST_SKIP_ITEM_OLD_MPATH("bad_bdp_length", test_frame_type_bdp_bad_length, 1, 0, 3, ERR_F, 1, 1),
    TEST_SKIP_ITEM_OLD("bad_frame_id", test_frame_type_bad_frame_id, 1, 0, 3, ERR_F, 1)
};

size_t nb_test_frame_error_list = sizeof(test_frame_error_list) / sizeof(test_skip_frames_t);

static size_t format_random_packet(uint8_t * bytes, size_t bytes_max, uint64_t * random_context, int epoch)
{
    size_t byte_index = 0;

    while (byte_index < bytes_max) {
        /* Pick a frame from the test list */
        uint64_t r = picoquic_test_uniform_random(random_context, nb_test_skip_list);
        if (epoch == -1 || test_skip_list[r].epoch == epoch) {
            /* stack it in the packet */
            if (byte_index + test_skip_list[r].len >= bytes_max) {
                break;
            }
            else {
                memcpy(bytes + byte_index, test_skip_list[r].val, test_skip_list[r].len);
                byte_index += test_skip_list[r].len;
                if (test_skip_list[r].must_be_last) {
                    break;
                }
            }
        }
    }

    return byte_index;
}

static int skip_test_packet(uint8_t * bytes, size_t bytes_max)
{
    int pure_ack;
    int ret = 0;
    size_t byte_index = 0;
    picoquic_cnx_t cnx;
    memset(&cnx, 0, sizeof(cnx));

    while (ret == 0 && byte_index < bytes_max) {
        size_t consumed;
        ret = picoquic_skip_frame(bytes + byte_index, bytes_max - byte_index, &consumed, &pure_ack);
        if (ret == 0) {
            byte_index += consumed;
        }
    }

    return ret;
}

static void skip_test_fuzz_packet(uint8_t * target, uint8_t * source, size_t bytes_max, uint64_t * random_context)
{
    size_t fuzz_index = (size_t) picoquic_test_uniform_random(random_context, bytes_max);
    size_t fuzz_length = (size_t) (picoquic_test_uniform_random(random_context, 8) + 1);
    uint64_t fuzz_data = picoquic_test_random(random_context);

    memcpy(target, source, bytes_max);

    for (size_t i = 0; i < fuzz_length && fuzz_index + i < bytes_max; i++) {
        target[fuzz_index + i] = (uint8_t)(fuzz_data & 0xFF);
        fuzz_data >>= 8;
    }
}

static size_t create_test_varint_frame(uint8_t* buffer, size_t buffer_size, size_t i, int v)
{
    const uint8_t* bytes = test_skip_list[i].val;
    const uint8_t* bytes_max = bytes + test_skip_list[i].len;
    uint64_t u = 0;
    size_t skipped = 0;
    /* skip the type and v-1 integers */
    for (int n = 0; bytes != NULL && n < v; n++) {
        bytes = picoquic_frames_varint_skip(bytes, bytes_max);
    }
    skipped = bytes - test_skip_list[i].val;
    memcpy(buffer, test_skip_list[i].val, skipped);
    if (bytes != NULL) {
        bytes = picoquic_frames_varint_decode(bytes, bytes_max, &u);
    }
    if (bytes != NULL) {
        buffer[skipped++] = 0xc0 + (uint8_t)(u >> 56);
        buffer[skipped++] = (uint8_t)(u >> 48);
        buffer[skipped++] = (uint8_t)(u >> 40);
        buffer[skipped++] = (uint8_t)(u >> 32);
        buffer[skipped++] = (uint8_t)(u >> 24);
        buffer[skipped++] = (uint8_t)(u >> 16);
        buffer[skipped++] = (uint8_t)(u >> 8);
        /* Last byte is omitted, to force a decoding error */
    }
    else {
        skipped = 0;
    }

    return skipped;
}

int skip_frame_varint_test(uint8_t * buffer, size_t buffer_size)
{
    int ret = 0;

    for (size_t i = 0; ret == 0 && i < nb_test_skip_list; i++) {
        for (int v = 1; v <= test_skip_list[i].nb_varints; v++) {
            size_t consumed = 0;
            int pure_ack = 0;
            size_t len = create_test_varint_frame(buffer, buffer_size, i, v);
            if (len > 0 &&
                picoquic_skip_frame(buffer, len, &consumed, &pure_ack) == 0) {
                ret = -1;
            }
        }
    }
    return ret;
}

int skip_frame_test()
{
    int ret = 0;
    uint8_t buffer[PICOQUIC_MAX_PACKET_SIZE];
    uint8_t fuzz_buffer[PICOQUIC_MAX_PACKET_SIZE];
    const uint8_t extra_bytes[4] = { 0xFF, 0, 0, 0 };
    uint64_t random_context = 0xBABED011;
    int fuzz_count = 0;
    int fuzz_fail = 0;
    picoquic_cnx_t cnx;

    memset(&cnx, 0, sizeof(cnx)); /* Null value gets default test version */

    for (size_t i = 0; ret == 0 && i < nb_test_skip_list; i++) {
        for (int sharp_end = 0; ret == 0 && sharp_end < 2; sharp_end++) {
            size_t consumed = 0;
            size_t byte_max = 0;
            int pure_ack;
            int t_ret = 0;

            memcpy(buffer, test_skip_list[i].val, test_skip_list[i].len);
            byte_max = test_skip_list[i].len;
            if (test_skip_list[i].must_be_last == 0 && sharp_end == 0) {
                memcpy(buffer + byte_max, extra_bytes, sizeof(extra_bytes));
                byte_max += sizeof(extra_bytes);
            }

            t_ret = picoquic_skip_frame(buffer, byte_max, &consumed, &pure_ack);

            if (t_ret != 0) {
                DBG_PRINTF("Skip frame <%s> fails, ret = %d\n", test_skip_list[i].name, t_ret);
                ret = t_ret;
            }
            else if (consumed != test_skip_list[i].len) {
                DBG_PRINTF("Skip frame <%s> fails, wrong length, %d instead of %d\n",
                    test_skip_list[i].name, (int)consumed, (int)test_skip_list[i].len);
                ret = -1;
            }
            else if (pure_ack != test_skip_list[i].is_pure_ack) {
                DBG_PRINTF("Skip frame <%s> fails, wrong pure ack, %d instead of %d\n",
                    test_skip_list[i].name, (int)pure_ack, (int)test_skip_list[i].is_pure_ack);
                ret = -1;
            }
        }
    }

    /* Check a series of known bad packets. We are checking that an error is
     * detected and no adverse code issue happens. */
    for (size_t i = 0; ret == 0 && i < nb_test_frame_error_list; i++) {
        for (int sharp_end = 0; ret == 0 && sharp_end < 2; sharp_end++) {
            size_t consumed = 0;
            size_t byte_max = 0;
            int pure_ack;
            int t_ret = 0;
            memcpy(buffer, test_frame_error_list[i].val, test_frame_error_list[i].len);
            byte_max = test_frame_error_list[i].len;
            if (test_frame_error_list[i].must_be_last == 0 && sharp_end == 0) {
                memcpy(buffer + byte_max, extra_bytes, sizeof(extra_bytes));
                byte_max += sizeof(extra_bytes);
            }

            t_ret = picoquic_skip_frame(buffer, byte_max, &consumed, &pure_ack);

            if (t_ret == 0 && test_frame_error_list[i].skip_fails) {
                DBG_PRINTF("Skip error frame <%s> does not fails, ret = %d\n", test_frame_error_list[i].name, t_ret);
                ret = -1;
            }
        }
    }
    /* Derive and test a series of packets with bad varint encodings */
    if (ret == 0) {
        ret = skip_frame_varint_test(buffer, PICOQUIC_MAX_PACKET_SIZE);
    }

    /* Do a minimal fuzz test */
    for (size_t i = 0; ret == 0 && i < 100; i++) {
        size_t bytes_max = format_random_packet(buffer, sizeof(buffer), &random_context, -1);

        ret = skip_test_packet(buffer, bytes_max);
        if (ret != 0) {
            DBG_PRINTF("Skip packet <%d> fails, ret = %d\n", i, ret);
        } else {
            /* do the actual fuzz test */
            int suspended = debug_printf_reset(1);
            for (size_t j = 0; j < 100; j++) {
                skip_test_fuzz_packet(fuzz_buffer, buffer, bytes_max, &random_context);
                if (skip_test_packet(fuzz_buffer, bytes_max) != 0) {
                    fuzz_fail++;
                }
                fuzz_count++;
            }
            (void)debug_printf_reset(suspended);
        }
    }

    if (ret == 0) {
        DBG_PRINTF("Fuzz skip test passes after %d trials, %d error detected\n",
            fuzz_count, fuzz_fail);
    }

    return ret;
}

void parse_test_packet_cnx_fix(picoquic_cnx_t* cnx, uint64_t simulated_time, int epoch, int mpath)
{
    /* Stupid fix to ensure that the NCID decoding test will not protest */
    cnx->path[0]->p_remote_cnxid->cnx_id.id_len = 8;

    cnx->pkt_ctx[0].send_sequence = 0x0102030406;
    cnx->path[0]->pkt_ctx.send_sequence = 0x0102030406;

    /* create a local cid  which can be retired with a connection_id_retire frame */
    (void)picoquic_create_local_cnxid(cnx, 0, NULL, simulated_time);

    /* enable time stamp so it can be used in test */
    cnx->is_time_stamp_enabled = 1;

    /* Set datagram max size to pass verification */
    cnx->local_parameters.max_datagram_frame_size = PICOQUIC_MAX_PACKET_SIZE;

    /* Set min ack delay so there is no issue with ack frequency frame */
    cnx->is_ack_frequency_negotiated = 1;
    cnx->remote_parameters.min_ack_delay = 1000;

    /* Set enable_bdp so there is no issue with bdp frame */
    cnx->local_parameters.enable_bdp_frame = 3;

    /* Enable multipath so the test of multipath frames works. */
    if (mpath != 0) {
        cnx->is_multipath_enabled = 1;
        cnx->max_path_id_local = 5;
        if (mpath >= 2) {
            /* Enable the P2P extensions. */
            cnx->is_address_discovery_provider = 1;
            cnx->is_address_discovery_receiver = 1;
        }
    }

    /* if testing handshake done, set state to ready so frame is ignored. */
    if (epoch == 3) {
        cnx->cnx_state = picoquic_state_ready;
    }
}

int parse_test_packet(picoquic_quic_t* qclient, struct sockaddr* saddr, uint64_t simulated_time,
    uint8_t * buffer, size_t byte_max, int epoch, int* ack_needed, uint64_t * err, int mpath)
{
    int ret = 0;
    picoquic_packet_context_enum pc = picoquic_context_from_epoch(epoch);
    picoquic_cnx_t* cnx = picoquic_create_cnx(qclient,
        picoquic_null_connection_id, picoquic_null_connection_id, saddr,
        simulated_time, 0, "test-sni", "test-alpn", 1);


    *ack_needed = 0;

    if (cnx == NULL) {
        DBG_PRINTF("%s", "Cannot create QUIC CNX context\n");
        ret = -1;
    }
    else {
        parse_test_packet_cnx_fix(cnx, simulated_time, epoch, mpath);

        ret = picoquic_decode_frames(cnx, cnx->path[0], buffer, byte_max, NULL, epoch, 
            NULL, NULL, 0, 0, simulated_time);

        *ack_needed = cnx->ack_ctx[pc].act[0].ack_needed;

        *err = cnx->local_error;

        if (ret == 0 &&
            (cnx->cnx_state == picoquic_state_disconnecting ||
                cnx->cnx_state == picoquic_state_handshake_failure)) {
            ret = -1;
        }

        picoquic_delete_cnx(cnx);
    }

    return ret;
}

int parse_frame_varint_test(picoquic_quic_t* qclient, struct sockaddr* saddr, uint64_t simulated_time,
    uint8_t* buffer, size_t buffer_size)
{
    int ret = 0;

    for (size_t i = 0; ret == 0 && i < nb_test_skip_list; i++) {
        for (int v = 1; v <= test_skip_list[i].nb_varints; v++) {
            int ack_needed = 0;
            uint64_t err = 0;
            size_t len = create_test_varint_frame(buffer, buffer_size, i, v);
            if (len > 0 &&
                parse_test_packet(qclient, saddr, simulated_time, buffer, len,
                    test_skip_list[i].epoch, &ack_needed, &err, test_skip_list[i].mpath) == 0) {
                ret = -1;
            }
        }
    }
    return ret;
}

int parse_frame_not_mpath_test(picoquic_quic_t* qclient, struct sockaddr* saddr, uint64_t simulated_time,
    uint8_t* buffer, size_t buffer_size)
{
    int ret = 0;

    for (size_t i = 0; ret == 0 && i < nb_test_skip_list; i++) {
        if (test_skip_list[i].mpath){
            int ack_needed = 0;
            uint64_t err = 0;
            size_t len = test_skip_list[i].len;
            memcpy(buffer, test_skip_list[i].val, len);

            if (parse_test_packet(qclient, saddr, simulated_time, buffer, len,
                test_skip_list[i].epoch, &ack_needed, &err, 0) == 0) {
                ret = -1;
            }
        }
    }
    return ret;
}

int parse_frame_0rtt_test(picoquic_quic_t* qclient, struct sockaddr* saddr, uint64_t simulated_time,
    uint8_t* buffer, size_t buffer_size)
{
    int ret = 0;

    for (size_t i = 0; ret == 0 && i < nb_test_skip_list; i++) {
        uint64_t frame_type = 0;
        if (picoquic_frames_varint_decode(test_skip_list[i].val, test_skip_list[i].val + test_skip_list[i].len, &frame_type) != NULL) {
            int ack_needed = 0;
            uint64_t err = 0;
            size_t len = test_skip_list[i].len;
            int l_ret = 0;
            memcpy(buffer, test_skip_list[i].val, len);
            l_ret = parse_test_packet(qclient, saddr, simulated_time, buffer, len,
                picoquic_epoch_0rtt, &ack_needed, &err, test_skip_list[i].mpath);
            if (frame_type >= picoquic_frame_type_stream_range_min && frame_type <= picoquic_frame_type_stream_range_max) {
                if (l_ret != 0) {
                    ret = -1;
                }
            } else {
                switch (frame_type) {
                case picoquic_frame_type_padding:
                case picoquic_frame_type_ping:
                case picoquic_frame_type_reset_stream:
                case picoquic_frame_type_stop_sending:
                case picoquic_frame_type_connection_close:
                case picoquic_frame_type_application_close:
                case picoquic_frame_type_max_data:
                case picoquic_frame_type_max_stream_data:
                case picoquic_frame_type_max_streams_bidir:
                case picoquic_frame_type_max_streams_unidir:
                case picoquic_frame_type_data_blocked:
                case picoquic_frame_type_stream_data_blocked:
                case picoquic_frame_type_streams_blocked_bidir:
                case picoquic_frame_type_streams_blocked_unidir:
                case picoquic_frame_type_new_connection_id:
                case picoquic_frame_type_path_challenge:
                case picoquic_frame_type_datagram:
                case picoquic_frame_type_datagram_l:
                    if (l_ret != 0) {
                        ret = -1;
                    }
                    break;
                default:
                    if (l_ret == 0) {
                        ret = -1;
                    }
                    break;
                }
            }
        }
    }
    return ret;
}


int parse_frame_test()
{
    int ret = 0;
    uint8_t buffer[PICOQUIC_MAX_PACKET_SIZE];
    uint8_t fuzz_buffer[PICOQUIC_MAX_PACKET_SIZE];
    const uint8_t extra_bytes[4] = { 0, 0, 0, 0 };
    uint64_t simulated_time = 0;
    struct sockaddr_in saddr;
    picoquic_quic_t * qclient = picoquic_create(8, NULL, NULL, NULL, NULL, NULL,
        NULL, NULL, NULL, NULL, simulated_time,
        &simulated_time, NULL, NULL, 0);
    uint64_t random_context = 0x12345678;
    int fuzz_fail = 0;
    int fuzz_count = 0;
    uint64_t err;

    memset(&saddr, 0, sizeof(struct sockaddr_in));
    if (qclient == NULL) {
        DBG_PRINTF("%s", "Cannot create QUIC context\n");
        ret = -1;
    }

    for (size_t i = 0x0C; ret == 0 && i < nb_test_skip_list; i++) {
        for (int sharp_end = 0; ret == 0 && sharp_end < 2; sharp_end++) {
            size_t byte_max = 0;
            int t_ret = 0;
            int ack_needed = 0;

            memcpy(buffer, test_skip_list[i].val, test_skip_list[i].len);
            byte_max = test_skip_list[i].len;
            if (test_skip_list[i].must_be_last == 0 && sharp_end == 0) {
                /* add some padding to check that the end of frame is detected properly */
                memcpy(buffer + byte_max, extra_bytes, sizeof(extra_bytes));
                byte_max += sizeof(extra_bytes);
            }

            t_ret = parse_test_packet(qclient, (struct sockaddr*) & saddr, simulated_time,
                buffer, byte_max, test_skip_list[i].epoch, &ack_needed, &err, test_skip_list[i].mpath);

            if (t_ret != 0) {
                DBG_PRINTF("Parse frame <%s> fails, ret = %d\n", test_skip_list[i].name, t_ret);
                ret = t_ret;
            }
            else if ((ack_needed != 0 && test_skip_list[i].is_pure_ack != 0) ||
                (ack_needed == 0 && test_skip_list[i].is_pure_ack == 0)) {
                DBG_PRINTF("Parse frame <%s> fails, ack needed: %d, expected pure ack: %d\n",
                    test_skip_list[i].name, ack_needed, (int)test_skip_list[i].is_pure_ack);
                ret = -1;
            }
        }
    }

    /* Decode a series of packets with modified length */
    if (ret == 0) {
        ret = parse_frame_varint_test(qclient, (struct sockaddr*)&saddr, simulated_time,
            buffer, sizeof(buffer));
    }

    /* Decode a series of multipath packets without the multipath option */
    if (ret == 0) {
        ret = parse_frame_not_mpath_test(qclient, (struct sockaddr*)&saddr, simulated_time,
            buffer, sizeof(buffer));
    }

    /* Verify that 0rtt tests are properly implemented */
    if (ret == 0) {
        ret = parse_frame_0rtt_test(qclient, (struct sockaddr*)&saddr, simulated_time,
            buffer, sizeof(buffer));
    }

    /* Decode a series of known bad packets */
    for (size_t i = 0; ret == 0 && i < nb_test_frame_error_list; i++) {
        for (int sharp_end = 0; ret == 0 && sharp_end < 2; sharp_end++) {
            size_t byte_max = 0;
            int t_ret = 0;
            int ack_needed = 0;

            memcpy(buffer, test_frame_error_list[i].val, test_frame_error_list[i].len);
            byte_max = test_frame_error_list[i].len;
            if (test_frame_error_list[i].must_be_last == 0 && sharp_end == 0) {
                /* add some padding to check that the end of frame is detected properly */
                memcpy(buffer + byte_max, extra_bytes, sizeof(extra_bytes));
                byte_max += sizeof(extra_bytes);
            }

            t_ret = parse_test_packet(qclient, (struct sockaddr*) & saddr, simulated_time,
                buffer, byte_max, test_frame_error_list[i].epoch, &ack_needed, &err, test_skip_list[i].mpath);

            if (t_ret == 0) {
                DBG_PRINTF("Parse error frame <%s> does not fails, ret = %d\n", test_frame_error_list[i].name, t_ret);
                ret = -1;
            }
            else if (err != test_frame_error_list[i].expected_error) {
                DBG_PRINTF("Parse error frame <%s>, expected err %" PRIu64 " got %" PRIu64 "\n",
                    test_frame_error_list[i].name, test_frame_error_list[i].expected_error, err);
                ret = -1;
            }
        }
    }

    /* Do a minimal fuzz test */
    for (size_t i = 0; ret == 0 && i < 100; i++) {
        int ack_needed;
        size_t bytes_max = sizeof(buffer);
        size_t byte_index;

        /* Pick a frame at random and copy it at the beginning of the packet */
        uint64_t r;
        do {
            r = picoquic_test_uniform_random(&random_context, nb_test_skip_list);
        } while (test_skip_list[r].epoch != 3);

        memcpy(buffer, test_skip_list[r].val, test_skip_list[r].len);
        byte_index = test_skip_list[r].len;

        if (!test_skip_list[r].must_be_last) {
            uint64_t rr = picoquic_test_uniform_random(&random_context, 4);

            switch (rr) {
            case 0:
                memcpy(buffer + byte_index, test_frame_type_ack, sizeof(test_frame_type_ack));
                byte_index += sizeof(test_frame_type_ack);
                break;
            case 1:
                memcpy(buffer + byte_index, test_frame_type_stream_range_max, sizeof(test_frame_type_stream_range_max));
                byte_index += sizeof(test_frame_type_stream_range_max);
                break;
            case 2:
                memset(buffer + byte_index, 0, bytes_max - byte_index);
                byte_index = bytes_max;
                break;
            default:
                break;
            }
        }
        bytes_max = byte_index;

        if (test_skip_list[r].mpath == 0) {
            ret = parse_test_packet(qclient, (struct sockaddr*)&saddr, simulated_time,
                buffer, bytes_max, 3, &ack_needed, &err, test_skip_list[r].mpath);
        }
        if (ret != 0)
        {
            DBG_PRINTF("Skip packet <%d> fails, ret = %d\n", i, ret);
        } else {
            /* do the actual fuzz test */
            int suspended = debug_printf_reset(1);
            for (size_t j = 0; j < 100; j++) {
                skip_test_fuzz_packet(fuzz_buffer, buffer, bytes_max, &random_context);
                if (parse_test_packet(qclient, (struct sockaddr*) & saddr, simulated_time,
                    fuzz_buffer, bytes_max, 3, &ack_needed, &err, j%3) != 0) {
                    fuzz_fail++;
                }
                fuzz_count++;
            }
            (void)debug_printf_reset(suspended);
        }
    }

    if (ret == 0) {
        DBG_PRINTF("Fuzz skip test passes after %d trials, %d error detected\n",
            fuzz_count, fuzz_fail);
    }

    if (qclient != NULL) {
        picoquic_free(qclient);
    }

    return ret;
}

int frame_repeat_error_packet(picoquic_quic_t* qclient, struct sockaddr* saddr, uint64_t simulated_time,
    uint8_t* bytes, size_t bytes_max, int epoch, uint64_t* err, int mpath, int expect_error)
{
    int ret = 0;
    picoquic_cnx_t* cnx = picoquic_create_cnx(qclient,
        picoquic_null_connection_id, picoquic_null_connection_id, saddr,
        simulated_time, 0, "test-sni", "test-alpn", 1);

    if (cnx == NULL) {
        DBG_PRINTF("%s", "Cannot create QUIC CNX context\n");
        ret = -1;
    }
    else {
        int do_not_detect_spurious = 0;
        int is_preemptive_needed = 0;
        int no_need_to_repeat = 0;
        int c_ret = 0;
        picoquic_packet_type_enum p_type;

        switch (epoch) {
        case picoquic_epoch_initial:
            p_type = picoquic_packet_initial;
            break;
        case picoquic_epoch_0rtt:
            p_type = picoquic_packet_0rtt_protected;
            break;
        case picoquic_epoch_handshake:
            p_type = picoquic_packet_handshake;
            break;
        default:
            p_type = picoquic_packet_1rtt_protected;
            break;
        }

        parse_test_packet_cnx_fix(cnx, simulated_time, epoch, mpath);
       
        c_ret = picoquic_check_frame_needs_repeat(cnx, bytes, bytes_max, p_type,
            &no_need_to_repeat, &do_not_detect_spurious, &is_preemptive_needed);
        
        if (expect_error && c_ret == 0 &&
            !no_need_to_repeat) {
            ret = -1;
        }

        if (!expect_error && c_ret != 0) {
            ret = -1;
        }

        picoquic_delete_cnx(cnx);
    }
    return ret;
}

int frames_repeat_test()
{
    int ret = 0;
    uint8_t buffer[PICOQUIC_MAX_PACKET_SIZE];
    uint64_t simulated_time = 0;
    picoquic_quic_t* qclient = picoquic_create(8, NULL, NULL, NULL, NULL, NULL,
        NULL, NULL, NULL, NULL, simulated_time,
        &simulated_time, NULL, NULL, 0);
    struct sockaddr_in saddr = { 0 };

    if (qclient == NULL) {
        ret = -1;
    }
    else {
        for (size_t i = 0; ret == 0 && i < nb_test_skip_list; i++) {
            uint64_t err = 0;
            size_t len = test_skip_list[i].len;
            uint64_t frame_type = 0;
            const uint8_t* type_byte = NULL;
            if ((type_byte = picoquic_frames_varint_decode(test_skip_list[i].val, test_skip_list[i].val + test_skip_list[i].len, &frame_type)) != NULL) {
                memcpy(buffer, test_skip_list[i].val, len);
                if (frame_repeat_error_packet(qclient, (struct sockaddr*)&saddr, simulated_time, buffer, len,
                    test_skip_list[i].epoch, &err, test_skip_list[i].mpath, 0) != 0) {
                    ret = -1;
                }
                else if (len > 1 && !test_skip_list[i].is_pure_ack) {
                    switch (frame_type) {
                    case picoquic_frame_type_connection_close:
                    case picoquic_frame_type_application_close:
                    case picoquic_frame_type_new_token:
                    case picoquic_frame_type_path_abandon:
                    case picoquic_frame_type_bdp:
                    case picoquic_frame_type_observed_address_v4:
                    case picoquic_frame_type_observed_address_v6:
                        break;
                    default:
                        if (frame_repeat_error_packet(qclient, (struct sockaddr*)&saddr, simulated_time, buffer, len - 1,
                            test_skip_list[i].epoch, &err, test_skip_list[i].mpath, 1) != 0) {
                            if (test_skip_list[i].nb_varints > 0) {
                                /* Try again with shorter length */
                                size_t type_len = type_byte - test_skip_list[i].val;
                                if (frame_repeat_error_packet(qclient, (struct sockaddr*)&saddr, simulated_time, buffer, type_len,
                                    test_skip_list[i].epoch, &err, test_skip_list[i].mpath, 1) != 0) {
                                    ret = -1;
                                }
                            }
                            else {
                                ret = -1;
                            }
                        }
                    }
                }
            }
        }
        picoquic_free(qclient);
    }
    return ret;
}

/* Use
* void picoquic_process_ack_of_frames(picoquic_cnx_t* cnx, picoquic_packet_t* p, 
*    int is_spurious, uint64_t current_time)
 */

void frame_init_test_packet(picoquic_packet_t* p, picoquic_cnx_t* cnx, int epoch, uint64_t simulated_time)
{
    memset(p, 0, sizeof(picoquic_packet_t));
    /* struct st_picoquic_packet_t* packet_next; */
    /* struct st_picoquic_packet_t* packet_previous; */
    p->send_path = cnx->path[0];
    p->sequence_number = 12345;
    p->send_time = simulated_time / 2;

    /*
    uint64_t delivered_prior;
    uint64_t delivered_time_prior;
    uint64_t delivered_sent_prior;
    uint64_t lost_prior;
    uint64_t inflight_prior;
    size_t data_repeat_frame;
    size_t data_repeat_index;
    */

    /*
    uint64_t data_repeat_priority;
    uint64_t data_repeat_stream_id;
    uint64_t data_repeat_stream_offset;
    size_t data_repeat_stream_data_length;
    */

    /*
    unsigned int is_evaluated : 1;
    unsigned int is_ack_eliciting : 1;
    unsigned int is_mtu_probe : 1;
    unsigned int is_multipath_probe : 1;
    unsigned int is_ack_trap : 1;
    unsigned int delivered_app_limited : 1;
    unsigned int sent_cwin_limited : 1;
    unsigned int is_preemptive_repeat : 1;
    unsigned int was_preemptively_repeated : 1;
    unsigned int is_queued_to_path : 1;
    unsigned int is_queued_for_retransmit : 1;
    unsigned int is_queued_for_spurious_detection : 1;
    unsigned int is_queued_for_data_repeat : 1;
    */
    p->checksum_overhead = 16;
        switch (epoch) {
        case picoquic_epoch_initial:
            p->ptype = picoquic_packet_initial;
            p->pc = picoquic_packet_context_initial;
            break;
        case picoquic_epoch_0rtt:
            p->ptype = picoquic_packet_0rtt_protected;
            p->pc = picoquic_packet_context_application;
            break;
        case picoquic_epoch_handshake:
            p->ptype = picoquic_packet_handshake;
            p->pc = picoquic_packet_context_handshake;
            break;
        default:
            p->ptype = picoquic_packet_1rtt_protected;
            p->pc = picoquic_packet_context_application;
            break;
        }
    if (p->ptype == picoquic_packet_1rtt_protected) {
        p->offset = 1 + 8 + 4;
    }
    else {
        p->offset = 1 + 1 + 8 + 1 + 8 + 2 + 4;
    }
}

int frame_ackack_error_packet(picoquic_quic_t* qclient, struct sockaddr* saddr, uint64_t simulated_time,
    picoquic_packet_t* p, size_t i, int v, int epoch, int mpath, int * disconnected)
{
    int ret = 0;
    picoquic_cnx_t* cnx = picoquic_create_cnx(qclient,
        picoquic_null_connection_id, picoquic_null_connection_id, saddr,
        simulated_time, 0, "test-sni", "test-alpn", 1);

    if (cnx == NULL) {
        DBG_PRINTF("%s", "Cannot create QUIC CNX context\n");
        ret = -1;
    }
    else {
        int is_spurious = 0;
        size_t len;
        picoquic_state_enum previous_state;
        picoquic_packet_data_t packet_data = { 0 };

        parse_test_packet_cnx_fix(cnx, simulated_time, epoch, mpath);
        frame_init_test_packet(p, cnx, epoch, simulated_time);
        len = create_test_varint_frame(p->bytes + p->offset, PICOQUIC_MAX_PACKET_SIZE, i, v);
        p->length = p->offset + len;

        previous_state = cnx->cnx_state;
        picoquic_process_ack_of_frames(cnx, p, &packet_data, is_spurious, simulated_time);
        *disconnected = (cnx->cnx_state != previous_state);

        picoquic_delete_cnx(cnx);
    }
    return ret;
}

int frames_ackack_error_test()
{
    int ret = 0;
    uint64_t simulated_time = 0;
    picoquic_quic_t* qclient = picoquic_create(8, NULL, NULL, NULL, NULL, NULL,
        NULL, NULL, NULL, NULL, simulated_time,
        &simulated_time, NULL, NULL, 0);
    struct sockaddr_in saddr = { 0 };
    picoquic_packet_t p;
    int nb_trials = 0;
    int nb_disconnected = 0;

    if (qclient == NULL) {
        ret = -1;
    }
    else {
        for (size_t i = 0; ret == 0 && i < nb_test_skip_list; i++) {
            for (int v = 1; v <= test_skip_list[i].nb_varints; v++) {
                int disconnected = 0;
                
                frame_ackack_error_packet(qclient, (struct sockaddr*)&saddr, simulated_time, &p, i, v,
                        test_skip_list[i].epoch, test_skip_list[i].mpath, &disconnected);
                nb_trials++;
                nb_disconnected += disconnected;
            }
        }
        picoquic_free(qclient);
    }
    DBG_PRINTF("%d ackack trials, %d disconnections", nb_trials, nb_disconnected);

    return ret;
}

picoquic_cnx_t * frames_format_test_get_cnx(picoquic_quic_t * qclient, struct sockaddr * saddr, picoquic_epoch_enum epoch, uint64_t simulated_time, int mpath)
{
    picoquic_cnx_t* cnx = picoquic_create_cnx(qclient,
        picoquic_null_connection_id, picoquic_null_connection_id, saddr,
        simulated_time, 0, "test-sni", "test-alpn", 1);

    if (cnx == NULL) {
        DBG_PRINTF("%s", "Cannot create QUIC CNX context\n");
    }
    else {
        parse_test_packet_cnx_fix(cnx, simulated_time, epoch, mpath);
    }
    return cnx;
}


#define FRAME_FORMAT_TEST_ONCE(format_func, s_max, ...)                                               \
    if (ret == 0) {                                                                                   \
        bytes_max = buffer + s_max;                                                                   \
        bytes = buffer;                                                                               \
        more_data = 0;                                                                                \
        is_pure_ack = 0;                                                                              \
        bytes = format_func(__VA_ARGS__);                                                             \
        if (bytes != buffer || !more_data) {                                                          \
            ret = -1;                                                                                 \
        }                                                                                             \
    }

#define FRAME_FORMAT_TEST(format_func, ...)                                                               \
    if (ret == 0) {                                                                                       \
        bytes_max = buffer + PICOQUIC_MAX_PACKET_SIZE;                                                    \
        for (round = 0; round < 2; round++) {                                                             \
            bytes = buffer;                                                                               \
            more_data = 0;                                                                                \
            is_pure_ack = 0;                                                                              \
            bytes = format_func(__VA_ARGS__);                                                             \
            if (bytes == NULL || bytes == buffer) {                                                       \
                break;                                                                                    \
            }                                                                                             \
            bytes_max = bytes - 1;                                                                        \
        }                                                                                                 \
        if (bytes != buffer || !more_data) {                                                              \
            ret = -1;                                                                                     \
        }                                                                                                 \
    }

/* Declarations of format functions that are not already public. */
uint8_t* picoquic_format_retire_connection_id_frame(uint8_t* bytes, uint8_t* bytes_max, int* more_data, int* is_pure_ack,
    int is_mp, uint64_t unique_path_id, uint64_t sequence);
uint8_t* picoquic_format_new_token_frame(uint8_t* bytes, uint8_t* bytes_max, int* more_data, int* is_pure_ack,
    uint8_t* token, size_t token_length);
uint8_t* picoquic_format_stop_sending_frame(picoquic_stream_head_t* stream,
    uint8_t* bytes, uint8_t* bytes_max, int* more_data, int* is_pure_ack);
uint8_t* picoquic_format_stream_reset_frame(picoquic_cnx_t* cnx, picoquic_stream_head_t* stream,
    uint8_t* bytes, uint8_t* bytes_max, int* more_data, int* is_pure_ack);
uint8_t* picoquic_format_data_blocked_frame(picoquic_cnx_t* cnx, uint8_t* bytes,
    uint8_t* bytes_max, int* more_data, int* is_pure_ack);
uint8_t* picoquic_format_stream_data_blocked_frame(uint8_t* bytes,
    uint8_t* bytes_max, int* more_data, int* is_pure_ack, picoquic_stream_head_t* stream);
uint8_t* picoquic_format_stream_blocked_frame(picoquic_cnx_t* cnx, uint8_t* bytes,
    uint8_t* bytes_max, int* more_data, int* is_pure_ack, picoquic_stream_head_t* stream);
uint8_t* picoquic_format_datagram_frame(uint8_t* bytes, uint8_t* bytes_max, int* more_data, int* is_pure_ack, size_t length, const uint8_t* src);
uint8_t* picoquic_format_path_available_or_standby_frame(
    uint8_t* bytes, const uint8_t* bytes_max, uint64_t frame_type,
    uint64_t path_id, uint64_t sequence, int * more_data);
uint8_t* picoquic_format_path_blocked_frame(
    uint8_t* bytes, const uint8_t* bytes_max, uint64_t max_path_id, int* more_data);

int frames_format_test()
{
    int ret = 0;
    uint8_t buffer[PICOQUIC_MAX_PACKET_SIZE];
    uint8_t data[] = { 0xaa, 0xaa };
    uint8_t* bytes = NULL;
    uint8_t* bytes_max;
    int more_data;
    uint64_t current_time = 0;
    int is_pure_ack = 0;
    picoquic_stream_head_t* stream = NULL;
    int round;
    uint64_t simulated_time = 0;
    picoquic_quic_t* qclient = picoquic_create(8, NULL, NULL, NULL, NULL, NULL,
        NULL, NULL, NULL, NULL, simulated_time,
        &simulated_time, NULL, NULL, 0);
    struct sockaddr_in saddr = { 0 };
    uint8_t addr_bytes[4] = { 1, 2, 3, 4 };
    picoquic_cnx_t* cnx;
    picoquic_local_cnxid_list_t* local_cnxid_list = NULL;
    picoquic_local_cnxid_t* l_cid = NULL; 

    if (qclient == NULL) {
        ret = -1;
    }
    else {
        cnx = frames_format_test_get_cnx(qclient, (struct sockaddr *)&saddr, picoquic_epoch_1rtt, simulated_time, 1);
        if (cnx == NULL) {
            ret = -1;
        }
    }

    if (ret == 0)  {
        local_cnxid_list = cnx->first_local_cnxid_list;
        l_cid = picoquic_create_local_cnxid(cnx, local_cnxid_list->unique_path_id, NULL, current_time);
        picoquic_add_to_stream(cnx, 0, data, 2, 0);
        stream = picoquic_find_stream(cnx, 0);
        if (stream == NULL) {
            ret = -1;
        }
    }

    stream->reset_requested = 1; 
    FRAME_FORMAT_TEST_ONCE(picoquic_format_stream_reset_frame, 2, cnx, stream, bytes, bytes_max, &more_data, &is_pure_ack);
    stream->reset_requested = 0;
    FRAME_FORMAT_TEST(picoquic_format_new_connection_id_frame, cnx, local_cnxid_list, bytes, bytes_max, &more_data, &is_pure_ack, l_cid);
    FRAME_FORMAT_TEST(picoquic_format_retire_connection_id_frame, bytes, bytes_max, &more_data, &is_pure_ack, 1, 0, 17);
    FRAME_FORMAT_TEST(picoquic_format_new_token_frame, bytes, bytes_max, &more_data, &is_pure_ack, data, 2);
    stream->stop_sending_requested = 1;
    FRAME_FORMAT_TEST_ONCE(picoquic_format_stop_sending_frame, 2, stream, bytes, bytes_max, &more_data, &is_pure_ack);
    stream->stop_sending_requested = 0;
    stream->stop_sending_sent = 0;
    FRAME_FORMAT_TEST_ONCE(picoquic_format_data_blocked_frame, 1, cnx, bytes, bytes_max, &more_data, &is_pure_ack);
    FRAME_FORMAT_TEST(picoquic_format_stream_data_blocked_frame, bytes, bytes_max, &more_data, &is_pure_ack, stream);
    stream->stream_data_blocked_sent = 0;
    FRAME_FORMAT_TEST_ONCE(picoquic_format_stream_blocked_frame, 1, cnx, bytes, bytes_max, &more_data, &is_pure_ack, stream);
    cnx->stream_blocked_bidir_sent = 0;
    FRAME_FORMAT_TEST(picoquic_format_connection_close_frame, cnx, bytes, bytes_max, &more_data, &is_pure_ack);
    FRAME_FORMAT_TEST(picoquic_format_application_close_frame, cnx, bytes, bytes_max, &more_data, &is_pure_ack);
    FRAME_FORMAT_TEST(picoquic_format_max_stream_data_frame, cnx, stream, bytes, bytes_max, &more_data, &is_pure_ack, 100000000);
    FRAME_FORMAT_TEST(picoquic_format_path_challenge_frame, bytes, bytes_max, &more_data, &is_pure_ack, 0xaabbccddeeff0011ull);
    FRAME_FORMAT_TEST(picoquic_format_path_response_frame, bytes, bytes_max, &more_data, &is_pure_ack, 0xaabbccddeeff0011ull);
    FRAME_FORMAT_TEST(picoquic_format_datagram_frame, bytes, bytes_max, &more_data, &is_pure_ack, 2, data);
    FRAME_FORMAT_TEST_ONCE(picoquic_format_ack_frequency_frame, 2, cnx, bytes, bytes_max, &more_data);
    FRAME_FORMAT_TEST(picoquic_format_immediate_ack_frame, bytes, bytes_max, &more_data);
    FRAME_FORMAT_TEST(picoquic_format_time_stamp_frame, cnx, buffer, bytes_max, &more_data, simulated_time);
    FRAME_FORMAT_TEST(picoquic_format_path_abandon_frame, bytes, bytes_max, &more_data, 1, 3);
    FRAME_FORMAT_TEST(picoquic_format_path_available_or_standby_frame, bytes, bytes_max, picoquic_frame_type_path_available, 1, 17, &more_data);
    FRAME_FORMAT_TEST(picoquic_format_max_path_id_frame, bytes, bytes_max, 123, &more_data);
    FRAME_FORMAT_TEST(picoquic_format_path_blocked_frame, bytes, bytes_max, 123, &more_data);
    FRAME_FORMAT_TEST(picoquic_format_observed_address_frame, bytes, bytes_max, picoquic_frame_type_observed_address_v4, 13, addr_bytes, 4433, &more_data);

    if (qclient != NULL) {
        picoquic_free(qclient);
    }

    return ret;
}

void picoquic_textlog_frames(FILE* F, uint64_t cnx_id64, uint8_t* bytes, size_t length);
void picoquic_binlog_frames(FILE* F, uint8_t* bytes, size_t length);

static char const* log_test_file = "log_test.txt";
static char const* log_error_test_file = "log_error_test.txt";
static char const* log_fuzz_test_file = "log_fuzz_test.txt";
static char const* log_packet_test_file = "log_packet_test.txt";
static char const* binlog_test_file = "01020304.client.log";
static char const* binlog_error_test_file = "binlog_error_test.txt";
static char const* binlog_fuzz_test_file = "binlog_fuzz_test.log";
static char const* qlog_test_file = "01020304.qlog";

#define LOG_TEST_REF "picoquictest" PICOQUIC_FILE_SEPARATOR "log_test_ref.txt"
#define BINLOG_TEST_REF "picoquictest" PICOQUIC_FILE_SEPARATOR "binlog_ref.log"
#define QLOG_TEST_REF "picoquictest" PICOQUIC_FILE_SEPARATOR "binlog_ref.qlog"

int picoquic_compare_lines(char const* b1, char const* b2)
{
    while (*b1 != 0 && *b2 != 0) {
        if (*b1 != *b2) {
            break;
        }
        b1++;
        b2++;
    }

    while (*b1 == '\n' || *b1 == '\r') {
        b1++;
    }

    while (*b2 == '\n' || *b2 == '\r') {
        b2++;
    }

    return (*b1 == 0 && *b2 == 0) ? 0 : -1;
}

int picoquic_compare_text_files(char const * fname1, char const * fname2, FILE * F1, FILE * F2)
{
    int ret = 0;
    int nb_line = 0;

    char buffer1[256];
    char buffer2[256];

    while (ret == 0 && fgets(buffer1, sizeof(buffer1), F1) != NULL) {
        nb_line++;
        if (fgets(buffer2, sizeof(buffer2), F2) == NULL) {
            /* F2 is too short */
            DBG_PRINTF("File %s is shorter than %s\n", fname2, fname1);
            DBG_PRINTF("    Missing line %d: %s", nb_line, buffer1);
            ret = -1;
        } else {
            ret = picoquic_compare_lines(buffer1, buffer2);
            if (ret != 0)
            {
                DBG_PRINTF("File %s differs %s at line %d\n", fname2, fname1, nb_line);
                DBG_PRINTF("    Got: %s", buffer1);
                DBG_PRINTF("    Vs:  %s", buffer2);
            }
        }
    }

    if (ret == 0 && fgets(buffer2, sizeof(buffer2), F2) != NULL) {
        /* F2 is too long */
        DBG_PRINTF("File %s is longer than %s\n", fname2, fname1);
        DBG_PRINTF("    Extra line %d: %s", nb_line+1, buffer2);
        ret = -1;
    }

    return ret;
}

static int picoquic_compare_binary_files(char const* fname1, char const* fname2, FILE* f1, FILE* f2)
{
    int more_data = 0;
    int ret = 0;

    do
    {
        uint8_t buffer1[256];
        uint8_t buffer2[256];
        size_t len1 = fread(buffer1, 1, sizeof(buffer1), f1);
        size_t len2 = fread(buffer2, 1, sizeof(buffer2), f2);

        if (ret == 0 && len1 != len2) {
            DBG_PRINTF("Length %s=%z, %s=%z", fname1, len1, fname2, len2);
            ret = -1;
        }
        if (ret == 0 && memcmp(buffer1, buffer2, len1) != 0) {
            DBG_PRINTF("Content does not match for  %s, %s", fname1, fname2);
            ret = -1;
        }

        more_data = len1 == sizeof(buffer1);

    } while (ret == 0 && more_data);

    return ret;
}

int picoquic_test_compare_files(char const* fname1, char const* fname2, const char* mode,
    int (*compare)(char const* fname1, char const* fname2, FILE* f1, FILE* f2))
{
    FILE* f1 = picoquic_file_open(fname1, mode);
    FILE* f2 = picoquic_file_open(fname2, mode);
    int ret = 0;

    if (f1 == NULL || f2 == NULL) {
        DBG_PRINTF("Cannot open file %s\n", f1 == NULL ? fname1 : fname2);
        ret = -1;
    }
    else {
        ret = compare(fname1, fname2, f1, f2);
    }

    (void)picoquic_file_close(f1);
    (void)picoquic_file_close(f2);

    return ret;
}

int picoquic_test_compare_text_files(char const* fname1, char const* fname2)
{
    return picoquic_test_compare_files(fname1, fname2, "r", picoquic_compare_text_files);
}

int picoquic_test_compare_binary_files(char const* fname1, char const* fname2)
{
    return picoquic_test_compare_files(fname1, fname2, "rb", picoquic_compare_binary_files);
}

uint64_t picoquic_sum_text_file(char const* fname)
{
    uint64_t sum = 0x10000000000ull;
    FILE* F = picoquic_file_open(fname, "rt");
    if (F != NULL) {
        uint8_t buf[512];
        size_t nb_read;
        while ((nb_read = fread(buf, 1, 512, F)) > 0) {
            for (size_t i = 0; i < nb_read; i++) {
                sum += buf[i];
            }
        }
        F = picoquic_file_close(F);
    }
    return sum;
}

uint8_t log_test_ticket[] = {
    0x00, 0x00, 0x01, 0x68, 0x87, 0x88, 0x91, 0x60,
    0x00, 0x17, 0x13, 0x02, 0x00, 0x00, 0x3d, 0x00,
    0x00, 0x1c, 0x20, 0x3f, 0xc0, 0x96, 0x0b, 0x08,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x20, 0x70, 0x95, 0x61, 0xe2, 0xaa, 0x2b,
    0x6d, 0x59, 0x20, 0x6f, 0xbe, 0x00, 0xa5, 0x2f,
    0x1d, 0x2f, 0x59, 0x36, 0xb1, 0x65, 0x6a, 0xc4,
    0xdb, 0xb5, 0xde, 0x20, 0x3c, 0x85, 0x74, 0xf4,
    0xe8, 0x97, 0x00, 0x08, 0x00, 0x2a, 0x00, 0x04,
    0xff, 0xff, 0xff, 0xff, 0x00, 0x30, 0xc1, 0xcd,
    0xe8, 0x9f, 0x4c, 0x9d, 0x7c, 0x58, 0x14, 0xd6,
    0x09, 0xb7, 0xac, 0x01, 0xe1, 0xcb, 0xca, 0x4e,
    0x9c, 0xb6, 0x72, 0x72, 0x21, 0xa4, 0xd8, 0x58,
    0x3d, 0xf5, 0x58, 0x1e, 0x7d, 0x2a, 0x22, 0x38,
    0xa4, 0x00, 0xa0, 0xae, 0x08, 0x61, 0xb2, 0xa7,
    0x08, 0xab, 0xe5, 0xe2, 0xd4, 0x16 };

static const picoquic_connection_id_t logger_test_cid =
{ { 11, 12, 13, 14, 15, 16, 17, 18, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }, 8 };

static uint8_t logger_ini_packet[] = {
    picoquic_frame_type_crypto_hs,
    0,
    0x10,
    0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7,
    0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF,
    0, 0, 0, 0, 0, 0
};

static uint8_t logger_hnds_packet[] = {
    1,
    picoquic_frame_type_crypto_hs,
    0,
    0x10,
    0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7,
    0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF
};

static uint8_t logger_0rtt_packet[] = {
    picoquic_frame_type_stream_range_min | 2, 0x00, 0x40, 7,
    1, 2, 3, 4, 5, 6, 7
};

static uint8_t logger_1rtt_packet[] = {
    picoquic_frame_type_ack,
    0xC0, 0, 0, 1, 2, 3, 4, 5,
    0x44, 0,
    2,
    5,
    0, 0,
    5, 12
};

static uint8_t logger_vnego_packet[] = {
    1, 2, 3, 4, 5, 6, 7, 8, 
};

static uint8_t logger_retry_packet[] = {
    31, 32, 33, 34, 35, 36, 37, 38, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16
};

typedef struct st_logger_sample_packet_t {
    picoquic_packet_type_enum p_type;
    size_t p_size;
    uint8_t * p_bytes;
} logger_sample_packet_t;

#define LOGGER_SAMPLE_PACKET( p_type, p_sample ) { p_type, sizeof(p_sample), p_sample }

static const logger_sample_packet_t logger_sample_packets[] = {
    LOGGER_SAMPLE_PACKET(picoquic_packet_initial, logger_ini_packet),
    LOGGER_SAMPLE_PACKET(picoquic_packet_handshake, logger_hnds_packet),
    LOGGER_SAMPLE_PACKET(picoquic_packet_0rtt_protected, logger_0rtt_packet),
    LOGGER_SAMPLE_PACKET(picoquic_packet_1rtt_protected, logger_1rtt_packet),
    LOGGER_SAMPLE_PACKET(picoquic_packet_version_negotiation, logger_vnego_packet),
    LOGGER_SAMPLE_PACKET(picoquic_packet_retry, logger_retry_packet),
};

static size_t nb_logger_sample_packets = sizeof(logger_sample_packets) / sizeof(logger_sample_packet_t);


void logger_test_packets(picoquic_cnx_t* cnx)
{
    uint64_t current_time = 1234567890ull;
    picoquic_connection_id_t srce_cnx_id = { { 0 }, 0 };

    for (size_t i = 0; i < nb_logger_sample_packets; i++) {
        struct st_picoquic_packet_header_t ph = { 0 };

        ph.ptype = logger_sample_packets[i].p_type;
        ph.dest_cnx_id = logger_test_cid;
        ph.srce_cnx_id = srce_cnx_id;
        ph.pn64 = i;
        ph.pn = (uint32_t)i;
        ph.payload_length = logger_sample_packets[i].p_size;

        picoquic_log_packet(cnx, cnx->path[0], (int)i & 1, current_time, &ph,
            logger_sample_packets[i].p_bytes, logger_sample_packets[i].p_size);

    }
}

void logger_test_pdus(picoquic_quic_t* quic, picoquic_cnx_t* cnx)
{
    uint64_t current_time = cnx->start_time + 12345000;
    uint64_t val64 = 0x123456789abcdef0ull;
    struct sockaddr_in6 s6_1 = { 0 };
    struct sockaddr_in6 s6_2 = { 0 };
    struct sockaddr_in s4_1 = { 0 };
    struct sockaddr_in s4_2 = { 0 };

    s6_1.sin6_family = AF_INET6;
    s6_1.sin6_port = htons(443);
    memset(&s6_1.sin6_addr, 0x20, 16);
    s6_2.sin6_family = AF_INET6;
    s6_2.sin6_port = htons(12345);
    memset(&s6_2.sin6_addr, 0x20, 2);
    memset(((uint8_t*)&s6_2.sin6_addr)+14, 0xFF, 2);
    s4_1.sin_family = AF_INET;
    s4_1.sin_port = htons(443);
    memset(&s4_1.sin_addr, 0x01, 4);
    s4_2.sin_family = AF_INET;
    s4_2.sin_port = htons(12345);
    memset(&s4_2.sin_addr, 0x22, 4);


    picoquic_log_pdu(cnx, 1, current_time,
        (struct sockaddr*)&s6_1, (struct sockaddr*)&s6_2, 1234);
    picoquic_log_pdu(cnx, 0, current_time,
        (struct sockaddr*)&s4_1, (struct sockaddr*)&s4_2, 55);

    picoquic_log_quic_pdu(quic, 0, current_time, val64,
        (struct sockaddr*)&s6_2, (struct sockaddr*)&s6_1, 1234);
    picoquic_log_quic_pdu(quic, 1, current_time, val64,
        (struct sockaddr*)&s4_2, (struct sockaddr*)&s4_1, 55);
}

int logger_test()
{
    FILE* F = NULL;
    int ret = 0;
    uint8_t buffer[PICOQUIC_MAX_PACKET_SIZE];
    uint8_t fuzz_buffer[PICOQUIC_MAX_PACKET_SIZE];
    uint64_t random_context = 0xF00BAB;
    struct sockaddr_in6 saddr = { 0 };
    picoquic_cnx_t * cnx = NULL;
    picoquic_quic_t * quic = NULL;
    uint64_t simulated_time = 123456789;
    uint64_t running_sum = 0;

    quic = picoquic_create(8, NULL, NULL, NULL, NULL, NULL,
        NULL, NULL, NULL, NULL, simulated_time,
        &simulated_time, NULL, NULL, 0);

    saddr.sin6_family = AF_INET6;
    saddr.sin6_port = 443;
    memset(&saddr.sin6_addr, 0x20, 16);

    if (quic == NULL) {
        DBG_PRINTF("%s", "Cannot create QUIC context\n");
        ret = -1;
    }
    else if ((cnx = picoquic_create_cnx(quic, logger_test_cid, logger_test_cid, (struct sockaddr*)&saddr,
        simulated_time, 0, "test-sni", "test-alpn", 1)) == NULL) {
        DBG_PRINTF("%s", "Cannot create CNX context\n");
        ret = -1;
    }
    else if (picoquic_set_textlog(quic, log_test_file) != 0) {
        DBG_PRINTF("failed to open file:%s\n", log_test_file);
        ret = -1;
    }
    else {
        for (size_t i = 0; i < nb_test_skip_list; i++) {
            picoquic_textlog_frames(quic->F_log, 0, test_skip_list[i].val, test_skip_list[i].len);
        }
        for (size_t i = 0; i < nb_test_frame_error_list; i++) {
            picoquic_textlog_frames(quic->F_log, 0, test_frame_error_list[i].val, test_frame_error_list[i].len);
        }
        fprintf(quic->F_log, "\n");
        picoquic_log_tls_ticket(cnx,
            log_test_ticket, (uint16_t) sizeof(log_test_ticket));

        picoquic_log_app_message(cnx, "%s.", "This is an app message test");
        picoquic_log_app_message(cnx, "This is app message test #%d, severity %d.", 1, 2);

        fprintf(quic->F_log, "\n");
        logger_test_packets(cnx);
        logger_test_pdus(quic, cnx);

        quic->F_log = picoquic_file_close(quic->F_log);
    }

    if (ret == 0) {
        char log_test_ref[512];

        ret = picoquic_get_input_path(log_test_ref, sizeof(log_test_ref), picoquic_solution_dir, LOG_TEST_REF);

        if (ret != 0) {
            DBG_PRINTF("%s", "Cannot set the log ref file name.\n");
        }
        else {
            ret = picoquic_test_compare_text_files(log_test_file, log_test_ref);
        }
    }

    /* Create a set of randomized packets. Verify that they can be logged without
     * causing the dreaded "Unknown frame" message */

    for (size_t i = 0; ret == 0 && i < 100; i++) {
        char log_line[1024];
        size_t bytes_max = format_random_packet(buffer, sizeof(buffer), &random_context, -1);

        if (picoquic_set_textlog(quic, log_packet_test_file) != 0) {
            DBG_PRINTF("failed to open file:%s\n", log_packet_test_file);
            ret = -1;
        }
        else {
            ret &= fprintf(quic->F_log, "Log packet test #%d\n", (int)i);
            picoquic_textlog_frames(quic->F_log, 0, buffer, bytes_max);
            quic->F_log = picoquic_file_close(quic->F_log);
        }

        if ((F = picoquic_file_open(log_packet_test_file, "r")) == NULL) {
            DBG_PRINTF("failed to open file:%s\n", log_packet_test_file);
            ret = PICOQUIC_ERROR_INVALID_FILE;
            break;
        } else {
            while (fgets(log_line, (int)sizeof(log_line), F) != NULL) {
                /* skip blanks */
                size_t byte_index = 0;

                while (byte_index < sizeof(log_line) &&
                    (log_line[byte_index] == ' ' || log_line[byte_index] == '\t')) {
                    byte_index++;
                }

                if (byte_index + 7u < sizeof(log_line) &&
                    memcmp(&log_line[byte_index], "Unknown", 7) == 0)
                {
                    DBG_PRINTF("Packet log test #%d failed, unknown frame.\n", (int)i);
                    ret = -1;
                    break;
                }
            }
            (void)picoquic_file_close(F);
        }
    }

    /* Log a series of known bad packets  */
    for (size_t i = 0; ret == 0 && i < nb_test_frame_error_list; i++) {
        for (int sharp_end = 0; ret == 0 && sharp_end < 2; sharp_end++) {
            uint8_t extra_bytes[4] = { 0, 0, 0, 0 };
            size_t bytes_max = 0;

            if (picoquic_set_textlog(quic, log_error_test_file) != 0) {
                DBG_PRINTF("failed to open file:%s\n", log_error_test_file);
                ret = -1;
                break;
            }
            fprintf(quic->F_log, "Running_sum: %" PRIx64 "\n", running_sum);
            memcpy(buffer, test_frame_error_list[i].val, test_frame_error_list[i].len);
            bytes_max = test_frame_error_list[i].len;
            if (test_frame_error_list[i].must_be_last == 0 && sharp_end == 0) {
                /* add some padding to check that the end of frame is detected properly */
                memcpy(buffer + bytes_max, extra_bytes, sizeof(extra_bytes));
                bytes_max += sizeof(extra_bytes);
            }

            picoquic_textlog_frames(quic->F_log, 0, buffer, bytes_max);

            quic->F_log = picoquic_file_close(quic->F_log);
            running_sum += picoquic_sum_text_file(log_error_test_file);
        }
    }

    /* Do a minimal fuzz test */
    for (size_t i = 0; ret == 0 && i < 100; i++) {
        size_t bytes_max = format_random_packet(buffer, sizeof(buffer), &random_context, -1);

        if (picoquic_set_textlog(quic, log_fuzz_test_file) != 0) {
            DBG_PRINTF("failed to open file:%s\n", log_fuzz_test_file);
            ret = PICOQUIC_ERROR_INVALID_FILE;
            break;
        }

        ret &= (fprintf(quic->F_log, "Log fuzz test #%d, sum: %" PRIx64 "\n",
            (int)i, running_sum) > 0);
        picoquic_textlog_frames(quic->F_log, 0, buffer, bytes_max);

        /* Attempt to log fuzzed packets, and hope nothing crashes */
        for (size_t j = 0; j < 100; j++) {
            ret &= fprintf(quic->F_log, "Log fuzz test #%d, packet %d\n", (int)i, (int)j);
            fflush(quic->F_log);
            skip_test_fuzz_packet(fuzz_buffer, buffer, bytes_max, &random_context);
            picoquic_textlog_frames(quic->F_log, 0, fuzz_buffer, bytes_max);
        }
        quic->F_log = picoquic_file_close(quic->F_log);
        running_sum += picoquic_sum_text_file(log_fuzz_test_file);
    }

    if (quic != NULL) {
        picoquic_free(quic);
    }

    return ret;
}

// Test of binary logs.

void binlog_new_connection(picoquic_cnx_t* cnx);

void binlog_packet(FILE* f, const picoquic_connection_id_t* cid, uint64_t path_id, int receiving, uint64_t current_time,
    const picoquic_packet_header* ph, const uint8_t* bytes, size_t bytes_max);

int binlog_test()
{
    uint8_t buffer[PICOQUIC_MAX_PACKET_SIZE];
    uint8_t fuzz_buffer[PICOQUIC_MAX_PACKET_SIZE];
    uint64_t random_context = 0xF00BAB;
    int ret = 0;

    const picoquic_connection_id_t initial_cid = {
        { 1, 2, 3, 4 }, 4
    };

    const picoquic_connection_id_t dest_cid = {
        { 5, 6, 7, 8 }, 4
    };

    char log_test_ref[512];
    int ret_bin = picoquic_get_input_path(log_test_ref, sizeof(log_test_ref), picoquic_solution_dir, BINLOG_TEST_REF);

    char qlog_test_ref[512];
    int ret_qlog = picoquic_get_input_path(qlog_test_ref, sizeof(qlog_test_ref), picoquic_solution_dir, QLOG_TEST_REF);

    uint64_t simulated_time = 0;
    picoquic_quic_t* quic = picoquic_create(8, NULL, NULL, NULL, NULL, NULL,
        NULL, NULL, NULL, NULL, simulated_time,
        &simulated_time, NULL, NULL, 0);

    if (quic == NULL) {
        DBG_PRINTF("%s", "Cannot create QUIC context\n");
        ret = -1;
    } else if (ret_bin != 0 || ret_qlog != 0) {
        DBG_PRINTF("%s", "Cannot set the log ref file name.\n");
        ret = -1;
    }
    else {
        picoquic_set_binlog(quic, ".");        
        (void)picoquic_set_default_spinbit_policy(quic, picoquic_spinbit_null);

        struct sockaddr_in saddr;
        memset(&saddr, 0, sizeof(struct sockaddr_in));
        picoquic_cnx_t* cnx = picoquic_create_cnx(quic, initial_cid, dest_cid, (struct sockaddr*) & saddr,
            simulated_time, 0, "test-sni", "test-alpn", 1);

        if (cnx == NULL) {
            DBG_PRINTF("%s", "Cannot create QUIC CNX context\n");
            ret = -1;
        }
        else {
            picoquic_log_new_connection(cnx);
            /* Log of good packets */
            for (size_t i = 0; i < nb_test_skip_list; i++) {

                picoquic_packet_header ph;
                memset(&ph, 0, sizeof(ph));

                ph.ptype = picoquic_packet_1rtt_protected;
                ph.pn64 = i;
                ph.dest_cnx_id = initial_cid;
                ph.srce_cnx_id = dest_cid;

                ph.offset = 0;
                ph.payload_length = test_skip_list[i].len;

                binlog_packet(cnx->f_binlog, &initial_cid, 0, 0, 0, &ph, test_skip_list[i].val, test_skip_list[i].len);
            }
            /* Log of bad backets */
            for (size_t i = 0; i < nb_test_frame_error_list; i++) {
                picoquic_packet_header ph;
                memset(&ph, 0, sizeof(ph));

                ph.ptype = picoquic_packet_1rtt_protected;
                ph.pn64 = i;
                ph.dest_cnx_id = initial_cid;
                ph.srce_cnx_id = dest_cid;

                ph.offset = 0;
                ph.payload_length = test_frame_error_list[i].len;

                binlog_packet(cnx->f_binlog, &initial_cid, 0, 0, 0, &ph, test_frame_error_list[i].val, test_frame_error_list[i].len);
            }
            picoquic_delete_cnx(cnx);
        }
    }

    picoquic_free(quic);

    if (ret == 0) {
        ret_bin = picoquic_test_compare_binary_files(binlog_test_file, log_test_ref);
        if (ret_bin != 0) {
            DBG_PRINTF("%s", "Unexpected content in binary log file.\n");
        }

        /* Convert to QLOG and verify */
        uint64_t log_time = 0;
        uint16_t flags;
        FILE* f_binlog = picoquic_open_cc_log_file_for_read(binlog_test_file, &flags, &log_time);
        
        ret = qlog_convert(&initial_cid, f_binlog, binlog_test_file, NULL, ".", flags);
        if (ret != 0) {
            DBG_PRINTF("%s", "Cannot convert the binary log into QLOG.\n");
        } else {
            /* When changing the reference QLOG file please verify the new file at:
                https://qvis.edm.uhasselt.be/#/files */
            ret_qlog = picoquic_test_compare_text_files(qlog_test_file, qlog_test_ref);
            if (ret_qlog != 0) {
                DBG_PRINTF("%s", "Unexpected content in QLOG log file.\n");
            }
        }

        if (ret_bin != 0 || ret_qlog != 0) {
            ret = -1;
        }
    }


    /* Log a series of known bad packets  */
    for (size_t i = 0; ret == 0 && i < nb_test_frame_error_list; i++) {
        for (int sharp_end = 0; ret == 0 && sharp_end < 2; sharp_end++) {
            uint8_t extra_bytes[4] = { 0, 0, 0, 0 };
            size_t bytes_max = 0;
            FILE* F = NULL;

            if ((F = picoquic_file_open(binlog_error_test_file, "wb")) == NULL) {
                DBG_PRINTF("failed to open file:%s\n", binlog_error_test_file);
                ret = PICOQUIC_ERROR_INVALID_FILE;
                break;
            }

            memcpy(buffer, test_frame_error_list[i].val, test_frame_error_list[i].len);
            bytes_max = test_frame_error_list[i].len;
            if (test_frame_error_list[i].must_be_last == 0 && sharp_end == 0) {
                /* add some padding to check that the end of frame is detected properly */
                memcpy(buffer + bytes_max, extra_bytes, sizeof(extra_bytes));
                bytes_max += sizeof(extra_bytes);
            }

            picoquic_binlog_frames(F, buffer, bytes_max);

            (void)picoquic_file_close(F);
        }
    }

    /* Do a minimal fuzz test */
    for (size_t i = 0; ret == 0 && i < 100; i++) {
        size_t bytes_max = format_random_packet(buffer, sizeof(buffer), &random_context, -1);
        FILE* F;

        if ((F = picoquic_file_open(binlog_fuzz_test_file, "wb")) == NULL) {
            DBG_PRINTF("failed to open file:%s\n", log_fuzz_test_file);
            ret = PICOQUIC_ERROR_INVALID_FILE;
            break;
        }

        picoquic_binlog_frames(F, buffer, bytes_max);

        /* Attempt to log fuzzed packets, and hope nothing crashes */
        for (size_t j = 0; j < 100; j++) {
            fflush(F);
            skip_test_fuzz_packet(fuzz_buffer, buffer, bytes_max, &random_context);
            picoquic_binlog_frames(F, fuzz_buffer, bytes_max);
        }
        (void)picoquic_file_close(F);
    }

    return ret;
}

/* Basic test of connection ID stash, part of migration support  */
static const picoquic_remote_cnxid_t stash_test_case[] = {
    { NULL,  1,{ { 0, 1, 2, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }, 4 },
{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 } },
{ NULL,  2,{ { 1, 2, 3, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }, 4 },
{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 } },
{ NULL,  3,{ { 2, 3, 4, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }, 4 },
{ 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17 } }
};

static const picoquic_connection_id_t stash_test_init_local =
    { { 11, 11, 11, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }, 4 };

static const picoquic_connection_id_t stash_test_init_remote =
{ { 99, 99, 99, 99, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }, 4 };

static const size_t nb_stash_test_case = sizeof(stash_test_case) / sizeof(picoquic_remote_cnxid_t);

static int cnxid_stash_compare(int test_mode, picoquic_remote_cnxid_t * stashed, size_t i)
{
    int ret = 0;

    if (stashed == NULL) {
        DBG_PRINTF("Test %d, cannot dequeue cnxid %d.\n", test_mode, i);
        ret = -1;
    }
    else if (stashed->sequence != stash_test_case[i].sequence) {
        DBG_PRINTF("Test %d, cnxid %d, sequence %d instead of %d.\n", test_mode, i,
            stashed->sequence, stash_test_case[i].sequence);
        ret = -1;
    }
    else if (picoquic_compare_connection_id(&stashed->cnx_id, &stash_test_case[i].cnx_id) != 0) {
        DBG_PRINTF("Test %d, cnxid %d, CNXID values do not match.\n", test_mode, i);
        ret = -1;
    }
    else if (memcmp(&stashed->reset_secret, &stash_test_case[i].reset_secret, PICOQUIC_RESET_SECRET_SIZE) != 0) {
        DBG_PRINTF("Test %d, cnxid %d, secrets do not match.\n", test_mode, i);
        ret = -1;
    }

    return ret;
}

int cnxid_stash_test()
{
    int ret = 0;
    uint64_t simulated_time = 0;
    struct sockaddr_in saddr;
    picoquic_quic_t * qclient = picoquic_create(8, NULL, NULL, NULL, NULL, NULL,
        NULL, NULL, NULL, NULL, simulated_time,
        &simulated_time, NULL, NULL, 0);


    memset(&saddr, 0, sizeof(struct sockaddr_in));
    if (qclient == NULL) {
        DBG_PRINTF("%s", "Cannot create QUIC context\n");
        ret = -1;
    }

    /* First test: enqueue and dequeue immediately */
    /* Second test: enqueue all and then dequeue - verify order */
    /* Third test: enqueue all and then delete the connection */
    for (int test_mode = 0; ret == 0 && test_mode < 3; test_mode++) {
        picoquic_cnx_t * cnx = picoquic_create_cnx(qclient,
            picoquic_null_connection_id, picoquic_null_connection_id, (struct sockaddr *) &saddr,
            simulated_time, 0, "test-sni", "test-alpn", 1);

        picoquic_remote_cnxid_t * stashed = NULL;

        if (cnx == NULL) {
            DBG_PRINTF("%s", "Cannot create QUIC CNX context\n");
            ret = -1;
        } else {
            /* init the various connection id to a length compatible with test */
            cnx->path[0]->p_local_cnxid->cnx_id = stash_test_init_local;
            cnx->path[0]->p_remote_cnxid->cnx_id = stash_test_init_remote;
        }

        for (size_t i = 0; ret == 0 && i < nb_stash_test_case; i++) {
            uint64_t transport_error = picoquic_stash_remote_cnxid(cnx, 0, 0,
                stash_test_case[i].sequence, stash_test_case[i].cnx_id.id_len,
                stash_test_case[i].cnx_id.id, stash_test_case[i].reset_secret, &stashed);
            if (transport_error != 0) {
                DBG_PRINTF("Test %d, cannot stash cnxid %d, err 0x%" PRIx64 ".\n", test_mode, i, transport_error);
                ret = -1;
            } else {
                if (stashed == NULL) {
                    DBG_PRINTF("Test %d, cannot stash cnxid %d (duplicate).\n", test_mode, i);
                    ret = -1;
                }
                else if (test_mode == 0) {
                    stashed = picoquic_obtain_stashed_cnxid(cnx, 0);
                    stashed->nb_path_references++;
                    ret = cnxid_stash_compare(test_mode, stashed, i);
                }
            }
        }

        /* Dequeue all in mode 1, verify order */
        if (test_mode == 1) {
            for (size_t i = 0; ret == 0 && i < nb_stash_test_case; i++) {
                stashed = picoquic_obtain_stashed_cnxid(cnx, 0);
                stashed->nb_path_references++;
                ret = cnxid_stash_compare(test_mode, stashed, i);
            }
        }

        /* Verify nothing left in queue in mode 0, 1 */
        if (test_mode < 2) {
            stashed = picoquic_obtain_stashed_cnxid(cnx, 0);
            if (stashed != NULL) {
                DBG_PRINTF("Test %d, unexpected cnxid left, #%d.\n", test_mode, (int)stashed->sequence);
                ret = -1;
            }
        }

        /* Delete the connecton and free the stash */
        picoquic_delete_cnx(cnx);
    }

    if (qclient != NULL) {
        picoquic_free(qclient);
    }

    return ret;
}

int new_cnxid_test()
{
    int ret = 0;
    uint64_t simulated_time = 0;
    struct sockaddr_in saddr;
    picoquic_quic_t * qclient = picoquic_create(8, NULL, NULL, NULL, NULL, NULL,
        NULL, NULL, NULL, NULL, simulated_time,
        &simulated_time, NULL, NULL, 0);
    picoquic_cnx_t * cnx = NULL;
    uint8_t frame_buffer[256];
    size_t consumed = 0;

    memset(&saddr, 0, sizeof(struct sockaddr_in));
    saddr.sin_family = AF_INET;
    saddr.sin_port = 1000;

    if (qclient == NULL) {
        DBG_PRINTF("%s", "Cannot create QUIC context\n");
        ret = -1;
    } else {
        cnx = picoquic_create_cnx(qclient,
            picoquic_null_connection_id, picoquic_null_connection_id, (struct sockaddr *) &saddr,
            simulated_time, 0, "test-sni", "test-alpn", 1);

        if (cnx == NULL) {
            DBG_PRINTF("%s", "Cannot create QUIC CNX context\n");
            ret = -1;
        }
        else {
            /* Create a new local CID */
            picoquic_local_cnxid_t* local_cid = picoquic_create_local_cnxid(cnx, 0, NULL, simulated_time);
            picoquic_local_cnxid_list_t* local_cid_list = cnx->first_local_cnxid_list;
            
            if (local_cid == NULL || local_cid_list == NULL) {
                DBG_PRINTF("%s", "Cannot create local cnxid\n");
                ret = -1;
            }

            if (local_cid_list->nb_local_cnxid != 2) {
                DBG_PRINTF("Expected 2 CID, got %d\n", local_cid_list->nb_local_cnxid);
                ret = -1;
            }
            else if (local_cid_list->local_cnxid_first == NULL || local_cid_list->local_cnxid_first->next == NULL) {
                DBG_PRINTF("%s", "Pointer to CID is NULL in cnx context\n");
                ret = -1;
            }

            if (ret == 0) {
                int more_data = 0;
                int is_pure_ack = 1;
                uint8_t* bytes_next = picoquic_format_new_connection_id_frame(cnx, local_cid_list, frame_buffer, frame_buffer + sizeof(frame_buffer),
                    &more_data, &is_pure_ack, local_cid);

                consumed = bytes_next - frame_buffer;

                if (consumed == 0) {
                    ret = -1;
                    DBG_PRINTF("Cannot encode new connection ID frame, ret = %x\n", ret);
                }
            }

            if (ret == 0) {
                size_t skipped = 0;
                int pure_ack = 0;

                ret = picoquic_skip_frame(frame_buffer, sizeof(frame_buffer), &skipped, &pure_ack);

                if (ret != 0) {
                    DBG_PRINTF("Cannot skip connection ID frame, ret = %x\n", ret);
                }
                else if (skipped != consumed) {
                    DBG_PRINTF("Skipped %d bytes instead of %d\n", (int)skipped, (int)consumed);
                    ret = -1;
                }
                else if (pure_ack != 0) {
                    DBG_PRINTF("Pure ACK = %d instead of 0\n", (int)pure_ack);
                    ret = -1;
                }
            }
            /* Delete the connecton and free the stash */
            picoquic_delete_cnx(cnx);
        }

        picoquic_free(qclient);
    }

    return ret;
}

/*
 * Test the copy for retransmit function
 */

#define SPLIT_FRAME_TEST_SOURCE_CONTENT_67 \
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, \
   11, 12, 13, 14, 15, 16, 17, 18, 19, 20, \
   21, 22, 23, 24, 25, 26, 27, 28, 29, 30, \
   31, 32, 33, 34, 35, 36, 37, 38, 39, 40, \
   41, 42, 43, 44, 45, 46, 47, 48, 49, 50, \
   51, 52, 53, 54, 55, 56, 57, 58, 59, 60, \
   61, 62, 63, 64, 65, 66, 67

#define SPLIT_FRAME_TEST_SOURCE_CONTENT_INIT_32 \
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, \
   11, 12, 13, 14, 15, 16, 17, 18, 19, 20, \
   21, 22, 23, 24, 25, 26, 27, 28, 29, 30, \
   31, 32

#define SPLIT_FRAME_TEST_SOURCE_CONTENT_LAST_35 \
   33, 34, 35, 36, 37, 38, 39, 40, \
   41, 42, 43, 44, 45, 46, 47, 48, 49, 50, \
   51, 52, 53, 54, 55, 56, 57, 58, 59, 60, \
   61, 62, 63, 64, 65, 66, 67

#define COPY_PACKET_CID_DEST 1,2,3,4,5,6,7,8

#define SIZEOF_CID_DEST 8

#define COPY_PACKET_HEADER_1RTT 0x43, COPY_PACKET_CID_DEST, 0, 0, 0, 1

#define SIZEOF_1RTT_HEADER (SIZEOF_CID_DEST + 5)

#define SPLIT_FRAME_TEST_SOURCE_68_77 68,69,70,71,72,73,74,75,76,77

static uint8_t ct_stream0_data[] = { SPLIT_FRAME_TEST_SOURCE_CONTENT_67, SPLIT_FRAME_TEST_SOURCE_68_77 };

static uint8_t ct_test_packet1[] = {
    COPY_PACKET_HEADER_1RTT,
    picoquic_frame_type_stream_range_min | 2, 0x00, 0x40, 67,
    SPLIT_FRAME_TEST_SOURCE_CONTENT_67
};

static uint8_t ct_test_packet2[] = {
    COPY_PACKET_HEADER_1RTT,
    picoquic_frame_type_stream_range_min, 0x00,
    SPLIT_FRAME_TEST_SOURCE_CONTENT_67 };

static uint8_t ct_test_packet3[] = {
    COPY_PACKET_HEADER_1RTT,
    picoquic_frame_type_stream_range_min, 0x00,
    SPLIT_FRAME_TEST_SOURCE_CONTENT_67, SPLIT_FRAME_TEST_SOURCE_68_77
};

static uint8_t ct_test_packet4[] = {
    COPY_PACKET_HEADER_1RTT,
    picoquic_frame_type_stream_range_min | 6, 0x00, 0x40, 67, 0x0A,
    SPLIT_FRAME_TEST_SOURCE_68_77,
    picoquic_frame_type_stream_range_min, 0x00,
    SPLIT_FRAME_TEST_SOURCE_CONTENT_67
};

uint8_t ct_test_packet4_first_frame[] = {
    picoquic_frame_type_stream_range_min | 6, 0x00, 0x40, 67, 0x0A,
    SPLIT_FRAME_TEST_SOURCE_68_77 };

static uint8_t ct_test_packet5[] = {
    COPY_PACKET_HEADER_1RTT,
    picoquic_frame_type_stream_range_min | 6, 0x00, 0x40, 67, 0x0A,
    SPLIT_FRAME_TEST_SOURCE_68_77,
    picoquic_frame_type_stream_range_min | 2, 0x00, 0x40, 67,
    SPLIT_FRAME_TEST_SOURCE_CONTENT_67
};

static uint8_t ct_test_packet6[] = {
    COPY_PACKET_HEADER_1RTT,
    picoquic_frame_type_stream_range_min | 6, 0x00, 0x40, 67, 0x0A,
    SPLIT_FRAME_TEST_SOURCE_68_77,
    picoquic_frame_type_stream_range_min, 0x00,
    SPLIT_FRAME_TEST_SOURCE_CONTENT_INIT_32
};

static uint8_t ct_test_mtu_probe[] = {
    COPY_PACKET_HEADER_1RTT,
    picoquic_frame_type_ping,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

static uint8_t ct_test_ack[] = {
    COPY_PACKET_HEADER_1RTT,
    picoquic_frame_type_ack,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

typedef struct st_copy_retransmit_test_case_t {
    uint8_t* packet;
    uint32_t packet_length;
    uint32_t offset;
    int is_mtu_probe;
    int is_ack_trap;
    size_t copy_max;
    uint8_t* b1_expected;
    size_t b1_length;
    size_t b1_offset;
    uint8_t* b2_expected;
    size_t b2_length;
    uint8_t* b3_expected;
    size_t b3_length;
    int is_pure_ack_expected;
} copy_retransmit_test_case_t;

static copy_retransmit_test_case_t copy_retransmit_case[] = {
    {
        ct_test_packet1,
        (uint32_t) sizeof(ct_test_packet1),
        (uint32_t) SIZEOF_1RTT_HEADER,
        0,
        0,
        PICOQUIC_MAX_PACKET_SIZE,
        ct_test_packet1,
        (uint32_t) SIZEOF_1RTT_HEADER,
        (uint32_t) SIZEOF_1RTT_HEADER,
        ct_test_packet1 + SIZEOF_1RTT_HEADER,
        sizeof(ct_test_packet1) - SIZEOF_1RTT_HEADER,
        NULL,
        0,
        0
    },
    {
        ct_test_packet2,
        (uint32_t)sizeof(ct_test_packet2),
        (uint32_t) SIZEOF_1RTT_HEADER,
        0,
        0,
        PICOQUIC_MAX_PACKET_SIZE,
        ct_test_packet1,
        (uint32_t)SIZEOF_1RTT_HEADER,
        (uint32_t) SIZEOF_1RTT_HEADER,
        ct_test_packet2 + SIZEOF_1RTT_HEADER,
        sizeof(ct_test_packet2) - SIZEOF_1RTT_HEADER,
        NULL,
        0,
        0
    },
    {
        ct_test_packet2,
        (uint32_t)sizeof(ct_test_packet2),
        (uint32_t) SIZEOF_1RTT_HEADER,
        0,
        0,
        (uint32_t) sizeof(ct_test_packet2),
        ct_test_packet2,
        (uint32_t)SIZEOF_1RTT_HEADER,
        (uint32_t) SIZEOF_1RTT_HEADER,
        ct_test_packet2 + SIZEOF_1RTT_HEADER,
        sizeof(ct_test_packet2) - SIZEOF_1RTT_HEADER,
        NULL,
        0,
        0
    },
    {
        ct_test_packet3,
        (uint32_t) sizeof(ct_test_packet3),
        (uint32_t) SIZEOF_1RTT_HEADER,
        0,
        0,
        (uint32_t) sizeof(ct_test_packet3),
        ct_test_packet3,
        (uint32_t)SIZEOF_1RTT_HEADER,
        (uint32_t) SIZEOF_1RTT_HEADER,
        ct_test_packet3 + SIZEOF_1RTT_HEADER,
        sizeof(ct_test_packet3) - SIZEOF_1RTT_HEADER,
        NULL,
        0,
        0
    },
    {
        ct_test_packet4,
        (uint32_t) sizeof(ct_test_packet4),
        (uint32_t) SIZEOF_1RTT_HEADER,
        0,
        0,
        (uint32_t) sizeof(ct_test_packet4),
        ct_test_packet4,
        (uint32_t)SIZEOF_1RTT_HEADER,
        (uint32_t) SIZEOF_1RTT_HEADER,
        ct_test_packet4_first_frame,
        sizeof(ct_test_packet4_first_frame),
        NULL,
        0,
        0
    },
    {
        ct_test_packet4,
        (uint32_t) sizeof(ct_test_packet4),
        (uint32_t) SIZEOF_1RTT_HEADER,
        0,
        0,
        PICOQUIC_MAX_PACKET_SIZE,
        ct_test_packet5,
        (uint32_t)SIZEOF_1RTT_HEADER,
        (uint32_t) SIZEOF_1RTT_HEADER,
        ct_test_packet4_first_frame,
        sizeof(ct_test_packet4_first_frame),
        NULL,
        0,
        0
    },
    {
        ct_test_packet4,
        (uint32_t) sizeof(ct_test_packet4),
        (uint32_t) SIZEOF_1RTT_HEADER,
        0,
        0,
        (uint32_t) sizeof(ct_test_packet6),
        ct_test_packet6,
        (uint32_t)SIZEOF_1RTT_HEADER,
        (uint32_t) SIZEOF_1RTT_HEADER,
        ct_test_packet4_first_frame,
        sizeof(ct_test_packet4_first_frame),
        NULL,
        0,
        0
    },
    {
        ct_test_mtu_probe,
        (uint32_t) sizeof(ct_test_mtu_probe),
        (uint32_t) SIZEOF_1RTT_HEADER,
        1,
        0,
        PICOQUIC_MAX_PACKET_SIZE,
        NULL, 0, 0,
        NULL, 0,
        NULL, 0,
        1
    },
    {
        ct_test_ack,
        (uint32_t)sizeof(ct_test_ack),
        (uint32_t)SIZEOF_1RTT_HEADER,
        0,
        1,
        (uint32_t)SIZEOF_1RTT_HEADER,
        NULL, 0, 0,
        NULL, 0,
        NULL, 0,
        1
    },
    {
        NULL,
        0,
        0,
        0,
        1,
        PICOQUIC_MAX_PACKET_SIZE,
        NULL, 0, 0,
        NULL, 0,
        NULL, 0,
        1
    }
};

size_t nb_copy_retransmit_case = sizeof(copy_retransmit_case) / sizeof(copy_retransmit_test_case_t);

int test_copy_for_retransmit()
{
    picoquic_quic_t * qtest = NULL;
    picoquic_cnx_t * cnx = NULL;
    int ret = 0;
    picoquic_packet_t old_p;
    uint8_t new_bytes[PICOQUIC_MAX_PACKET_SIZE];
    size_t length = 0;
    int packet_is_pure_ack = 0;
    int do_not_detect_spurious = 1;
    uint64_t simulated_time = 0;
    struct sockaddr_in saddr;

    memset(&saddr, 0, sizeof(struct sockaddr_in));

    /* Initialize the connection context */
    qtest = picoquic_create(8, NULL, NULL, NULL, NULL, NULL,
        NULL, NULL, NULL, NULL, simulated_time,
        &simulated_time, NULL, NULL, 0);
    if (qtest == NULL) {
        DBG_PRINTF("%s", "Cannot create QUIC context\n");
        ret = -1;
    }

    /* Perform the tests */
    for (size_t i = 0; ret == 0 && i < nb_copy_retransmit_case; i++) {
        int add_to_data_repeat_queue = 0;

        cnx = picoquic_create_cnx(qtest,
            picoquic_null_connection_id, picoquic_null_connection_id, (struct sockaddr *) &saddr,
            simulated_time, 0, "test-sni", "test-alpn", 1);

        if (cnx == NULL) {
            DBG_PRINTF("%s", "Cannot create QUIC CNX context\n");
            ret = -1;
            break;
        }
        /* Initialize stream 0 */
        if ((ret = picoquic_add_to_stream(cnx, 0, ct_stream0_data, sizeof(ct_stream0_data), 0)) != 0) {
            DBG_PRINTF("%s", "Cannot initialize stream 0\n");
            ret = -1;
            break;
        }

        /* Initialize the old packet */
        memset(&old_p, 0, sizeof(picoquic_packet_t));
        if (copy_retransmit_case[i].packet_length > 0) {
            memcpy(old_p.bytes, copy_retransmit_case[i].packet, copy_retransmit_case[i].packet_length);
            old_p.length = copy_retransmit_case[i].packet_length;
        }
        old_p.offset = copy_retransmit_case[i].offset;
        old_p.is_mtu_probe = copy_retransmit_case[i].is_mtu_probe;
        old_p.is_ack_trap = copy_retransmit_case[i].is_ack_trap;
        old_p.send_path = cnx->path[0];

        length = copy_retransmit_case[i].b1_offset;

        ret = picoquic_copy_before_retransmit(&old_p, cnx, new_bytes,
            copy_retransmit_case[i].copy_max,
            &packet_is_pure_ack,
            &do_not_detect_spurious, 0,
            &length,
            &add_to_data_repeat_queue);

        if (ret != 0) {
            DBG_PRINTF("Cannot perform copy for test[%d]\n", i);
        } else if (packet_is_pure_ack != copy_retransmit_case[i].is_pure_ack_expected) {
            /* Check whether pure ack matches expectation */
            DBG_PRINTF("Is pure ack mismatch on test[%d], got %d\n", i,
                packet_is_pure_ack);
            ret = -1;
        }
        else if (!packet_is_pure_ack) {
            /* Compare bytes and length to expected */
            if (length != copy_retransmit_case[i].b1_length) {
                DBG_PRINTF("Length mismatch on test[%d], got %d vs %d\n", i,
                    packet_is_pure_ack, length,
                    copy_retransmit_case[i].b1_length);
                ret = -1;
            }
            else if (memcmp(new_bytes + copy_retransmit_case[i].b1_offset,
                copy_retransmit_case[i].b1_expected + copy_retransmit_case[i].b1_offset,
                length - copy_retransmit_case[i].b1_offset) != 0) {
                DBG_PRINTF("Value mismatch on test[%d]\n", i);
                ret = -1;
            }
            else {
                if (copy_retransmit_case[i].b2_expected == NULL) {
                    if (add_to_data_repeat_queue) {
                        DBG_PRINTF("Unexpected stream frame in test[%d]\n", i);
                        ret = -1;
                    }
                }
                else if (!add_to_data_repeat_queue) {
                    DBG_PRINTF("Missing stream frame in test[%d]\n", i);
                    ret = -1;
                }

                if (ret == 0) {
                    if (copy_retransmit_case[i].b3_expected == NULL) {
                        if (cnx->first_misc_frame != NULL) {
                            DBG_PRINTF("Unexpected misc frame in test[%d]\n", i);
                            ret = -1;
                        }
                    }
                    else if (cnx->first_misc_frame == NULL) {
                        DBG_PRINTF("Missing misc frame in test[%d]\n", i);
                        ret = -1;
                    }
                    else if (copy_retransmit_case[i].b3_length != cnx->first_misc_frame->length) {
                        DBG_PRINTF("Mismatching misc frame lenght in test[%d]\n", i);
                        ret = -1;
                    }
                    else if (memcmp(((uint8_t*)cnx->first_misc_frame) + sizeof(picoquic_misc_frame_header_t),
                        copy_retransmit_case[i].b3_expected, cnx->first_misc_frame->length) != 0) {
                        DBG_PRINTF("Mismatching misc frame in test[%d]\n", i);
                        ret = -1;
                    }
                }
            }
        }
        /* Free the extra frames */
        if (cnx != NULL) {
            picoquic_delete_cnx(cnx);
        }
    }

    /* Free the connection context */
    if (qtest != NULL) {
        picoquic_free(qtest);
    }
    return ret;
}


/* Test the formatting of frames queued in retransmit packets.
 * We assume an API that looks inside the queued packet, find the
 * next stream frame, and copy the next data for that frame.
 * We need to consider the following cases:
 * 
 * 1- Just one data frame in the packet, and it fits.
 * 2- Data frame does not fit in the packet, can only
 *    encode the first bytes, update the index.
 * 3- First bytes of data frame already sent, the
 *    reminder fits, send it all.
 * 4- First bytes of data frame already sent, the
 *    reminder does not fit, send first bytes only.
 * 5- Zero data, but need to send the FIN bit.
 * Add: same as 3..5, but without explicit length.
 * Add: same as 3..4, but FIN bit
 * Add: same as 3..4, no length, FIN bit.
 * Add: variants in which the outgoing frame must
 * use zero-length encoding.
 * Add: variants in which the outgoing frame must
 * use zero-length encoding and one extra pad byte.
 */

static size_t dataqueue_prepare_packet(
    picoquic_packet_t* packet, int has_length, int has_fin,
    uint64_t stream_id, uint64_t offset, size_t frame_data_length)
{
    uint8_t* bytes = packet->bytes;
    uint8_t* bytes_max = bytes + sizeof(packet->bytes);
    size_t copied_index;

    memset(packet, 0, sizeof(picoquic_packet_t));
    packet->offset = 12;
    packet->data_repeat_frame = 17;
    packet->data_repeat_index = 17;
    bytes += packet->data_repeat_frame;
    *bytes = picoquic_frame_type_stream_range_min;
    if (has_length) {
        *bytes |= 2;
    }
    if (has_fin) {
        *bytes |= 1;
    }
    *bytes++ |= 4;
    bytes = picoquic_frames_varint_encode(bytes, bytes_max, stream_id);
    bytes = picoquic_frames_varint_encode(bytes, bytes_max, offset);
    if (has_length) {
        bytes = picoquic_frames_varint_encode(bytes, bytes_max, frame_data_length);
    }
    copied_index =  packet->data_repeat_frame + (bytes - (packet->bytes + packet->data_repeat_frame));
    for (size_t i = 0; i < frame_data_length; i++) {
        *bytes++ = (uint8_t)(i + 1);
    }
    packet->length = bytes - packet->bytes;

    return copied_index;
}

static int dataqueue_prepare_test(int basic_case, int has_length, int has_fin,
    picoquic_packet_t* packet,
    size_t * next_frame, size_t * next_index, size_t * buffer_size, size_t * frame_length,
    uint8_t* data, size_t length_max)
{
    int ret = 0;
    /* Prepare the packet header before the call.
     *  -1: point to frame. If "no length", set length at final byte.
     *      If length, add padding.
     *      next frame and index point after the length.
     *  -2: same as 1. Must limit the available buffer size.
     *      next frame pointer unchanged, index after sent byte.
     *  -3: init same as 1. Index before points to data.
     *      next frame and index point after the length.
     *      datasize must be limited.
     *  -4: init same as 1. Index before points to data.
     *      Must limit the available buffer size.
     *      next frame pointer unchanged, index after sent byte.
     *  -5: init just a header. either last byte or not.
     * 
     */
    uint8_t* bytes;
    uint8_t* bytes_max;
    uint8_t* frame_data;
    uint64_t offset = 1023;
    uint64_t copied_index = 0;
    uint64_t copied_offset = offset;
    uint64_t stream_id = 8;
    size_t frame_data_length = 2 * 65;
    size_t copied_length;
    size_t extra_byte = 0;
    int copied_fin = has_fin;
    int constrained_buffer = 0;

    if (basic_case == 5) {
        frame_data_length = 0;
    }

    copied_index = dataqueue_prepare_packet(packet, has_length, has_fin,
        stream_id, offset, frame_data_length);
    frame_data = packet->bytes + copied_index;

    switch (basic_case) {
    case 2:
        copied_length = frame_data_length/2;
        *next_frame = packet->data_repeat_frame;
        *next_index = (frame_data + copied_length) - packet->bytes;
        copied_fin = 0;
        constrained_buffer = 1;
        break;
    case 3:
        packet->data_repeat_index = (frame_data + frame_data_length/2) - packet->bytes;
        copied_index += frame_data_length/2;
        copied_offset += frame_data_length/2;
        copied_length = frame_data_length - frame_data_length/2;
        *next_frame = packet->length;
        *next_index = packet->length;
        break;
    case 4:
        constrained_buffer = 1;
        copied_length = frame_data_length;
        *next_frame = packet->length;
        *next_index = packet->length;
        break;
    case 6:
        constrained_buffer = 1;
        copied_length = frame_data_length;
        *next_frame = packet->length;
        *next_index = packet->length;
        extra_byte = 1;
        break;
    case 1:
    default:
        copied_length = frame_data_length;
        *next_frame = packet->length;
        *next_index = packet->length;
        break;
    }

    /* Prepare the outcoming buffer: */
    *buffer_size = 0;
    *frame_length = 0;
    bytes = data;
    bytes_max = data + length_max;
    ret = -1;
    if (bytes + extra_byte < bytes_max) {
        if (extra_byte) {
            *bytes++ = 0;
        }
        *bytes = picoquic_frame_type_stream_range_min;
        if (!constrained_buffer) {
            /* Use length encoding */
            *bytes |= 2;
        }
        if (copied_fin) {
            *bytes |= 1;
        }
        *bytes++ |= 4;
        if ((bytes = picoquic_frames_varint_encode(bytes, bytes_max, stream_id)) != NULL &&
            (bytes = picoquic_frames_varint_encode(bytes, bytes_max, copied_offset)) != NULL) {
            if (!constrained_buffer) {
                bytes = picoquic_frames_varint_encode(bytes, bytes_max, copied_length);
            }
        }
        if (bytes != NULL && bytes + copied_length < bytes_max) {
            memcpy(bytes, packet->bytes + copied_index, copied_length);
            bytes += copied_length;
            ret = 0;
        }
        else {
            bytes = NULL;
            ret = -1;
        }
    }
    if (ret == 0){
        *frame_length = bytes - data;
        if (!constrained_buffer) {
            for (int i = 0; i < 4 && bytes < bytes_max; i++) {
                *bytes++ = 1; /* add a ping frame... */
            }
        }
        *buffer_size = bytes - data;
    }

    return ret;
}

static size_t dataqueue_verify_test(picoquic_packet_t* packet,
    size_t next_frame, size_t next_index, size_t frame_length,
    uint8_t* data, uint8_t *output, size_t output_length)
{
    int ret = 0;
    if (packet->data_repeat_frame != next_frame) {
        DBG_PRINTF("Expected frame at %zu, got %zu", packet->data_repeat_frame, next_frame);
        ret = -1;
    }
    else if (packet->data_repeat_index != next_index) {
        DBG_PRINTF("Expected index at %zu, got %zu", packet->data_repeat_index, next_index);
        ret = -1;
    }
    else if (output_length != frame_length) {
        DBG_PRINTF("Expected frame length %zu, got %zu", frame_length, output_length);
        ret = -1;
    }
    else if (memcmp(data, output, output_length) != 0) {
        DBG_PRINTF("%s", "Produced frame does not match");
        ret = -1;
    }
    return ret;
}

int dataqueue_copy_test()
{
    int ret = 0;
    picoquic_packet_t packet;
    uint8_t data[1536];
    uint8_t output[1536];
    size_t length_max = 1536;

    for (int case_opt = 0; ret == 0 && case_opt < 5; case_opt++) {
        int has_length = (case_opt & 1) == 0;
        int has_fin = (case_opt & 2) == 2;

        for (int basic_case = 1; ret == 0 && basic_case <= 6; basic_case++) {
            size_t next_frame = 0;
            size_t next_index = 0;
            size_t buffer_size = 0;
            size_t frame_length = 0;

            ret = dataqueue_prepare_test(basic_case, has_length, has_fin, &packet,
                &next_frame, &next_index, &buffer_size, &frame_length, data, length_max);

            if (ret != 0) {
                DBG_PRINTF("Prepare test fails for case %d, option &x", basic_case, case_opt);
                ret = -1;
            }
            else {
                uint8_t* next_byte = picoquic_copy_stream_frame_for_retransmit(
                    NULL, &packet, output, output + buffer_size);
                if (next_byte == NULL) {
                    DBG_PRINTF("Copy stream frame fails for case %d, option &x", basic_case, case_opt);
                    ret = -1;
                }
                else
                {
                    size_t output_length = next_byte - output;
                    if (dataqueue_verify_test(&packet, next_frame, next_index, frame_length, data, output, output_length) != 0) {
                        DBG_PRINTF("Verify data fails for case %d, option &x", basic_case, case_opt);
                        ret = -1;
                    }
                }
            }
        }
    }

    return ret;
}

/* Test the API picoquic_copy_stream_frames_for_retransmit
* Create a connection.
* Create a data queue packet with 256 bytes of data.
* First call: buffer size < min size. Expect "more data" to
* be set, but no data sent. ACK only is expected.
* Second call: buffer size < packet size. Expect buffer to
* be filled with data. More data should be set. ACK only = 0.
* Third call: large buffer size. Expect large packet. More data
* should not be set. ACK only = 0. 
* Fourth call: large buffer size. Expect no data, more data=0,
* ACK only = 1.
* Add another packet in the queue, or maybe two.
* Clean everything. The ASAN/UBSAN run will detect any memory leak.
 */

int dataqueue_packet_test_iterate(int test_id, picoquic_cnx_t* cnx, size_t buffer_size, int expect_data, int expect_more_data, int expect_is_pure_ack)
{
    int ret = 0;
    uint8_t buffer[PICOQUIC_MAX_PACKET_SIZE];
    int more_data = 0;
    int is_pure_ack = 1;
    uint8_t* next_bytes = picoquic_copy_stream_frames_for_retransmit(cnx, buffer, buffer + buffer_size, UINT64_MAX, &more_data, &is_pure_ack);

    if (next_bytes == NULL) {
        DBG_PRINTF("Test %d, returns NULL", test_id);
        ret = -1;
    }
    else {
        int has_data = next_bytes > buffer;

        if (has_data && !expect_data) {
            DBG_PRINTF("Test %d, got data, not expected", test_id);
            ret = -1;
        } else if (!has_data && expect_data) {
            DBG_PRINTF("Test %d, no data, some expected", test_id);
            ret = -1;
        } else if (more_data && !expect_more_data) {
            DBG_PRINTF("Test %d, more data not expected", test_id);
            ret = -1;
        }  else if (!more_data && expect_more_data) {
            DBG_PRINTF("Test %d, more data expected", test_id);
            ret = -1;
        } else if (is_pure_ack && !expect_is_pure_ack) {
            DBG_PRINTF("Test %d, unexpected pure ACK", test_id);
            ret = -1;
        } else if (!is_pure_ack && expect_is_pure_ack) {
            DBG_PRINTF("Test %d, pure ACK expected", test_id);
            ret = -1;
        }
    }
    return ret;
}

int dataqueue_packet_test()
{
    picoquic_quic_t* qtest = NULL;
    picoquic_cnx_t* cnx = NULL;
    int ret = 0;
    uint64_t simulated_time = 0;
    struct sockaddr_in saddr;

    memset(&saddr, 0, sizeof(struct sockaddr_in));

    /* Initialize the connection context */
    if (ret == 0) {
        qtest = picoquic_create(8, NULL, NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL, simulated_time,
            &simulated_time, NULL, NULL, 0);
        if (qtest == NULL) {
            DBG_PRINTF("%s", "Cannot create QUIC context\n");
            ret = -1;
        }
        else {
            cnx = picoquic_create_cnx(qtest,
                picoquic_null_connection_id, picoquic_null_connection_id, (struct sockaddr*) & saddr,
                simulated_time, 0, "test-sni", "test-alpn", 1);

            if (cnx == NULL) {
                ret = -1;
            }
            else {
                /* Create stream 0 so the later tests succeed */
                uint8_t new_bytes[256];
                memset(new_bytes, 0, sizeof(new_bytes));
                if ((ret = picoquic_add_to_stream(cnx, 0, new_bytes, sizeof(new_bytes), 0)) != 0) {
                    DBG_PRINTF("%s", "Cannot initialize stream 0\n");
                    ret = -1;
                }
            }
        }
    }

    if (ret == 0) {
        /* Create a packet and chain it to the data queue */
        picoquic_packet_t* packet = picoquic_create_packet(qtest);
        if (packet == NULL) {
            ret = -1;
        }
        else {
            (void)dataqueue_prepare_packet(packet, 1, 0, 0, 0, 256);
            picoquic_queue_data_repeat_packet(cnx, packet);
        }
    }

    if (ret == 0 &&
        (ret = dataqueue_packet_test_iterate(1, cnx, 2, 0, 1, 1)) == 0 &&
        (ret = dataqueue_packet_test_iterate(2, cnx, 128, 1, 1, 0)) == 0 &&
        (ret = dataqueue_packet_test_iterate(3, cnx, 1024, 1, 0, 0)) == 0) {
        ret = dataqueue_packet_test_iterate(4, cnx, 1024, 0, 0, 1);
    }

    if (ret == 0) {
        /* Create a packet and chain it to the data queue */
        picoquic_packet_t* packet = picoquic_create_packet(qtest);
        if (packet == NULL) {
            ret = -1;
        }
        else {
            (void)dataqueue_prepare_packet(packet, 1, 0, 0, 0, 256);
            picoquic_dequeue_data_repeat_packet(cnx, packet);
        }
    }

    /* Free the connection context */
    if (cnx != NULL) {
        picoquic_delete_cnx(cnx);
    }

    if (qtest != NULL) {
        picoquic_free(qtest);
    }
    return ret;
}

/* Testing the sending of blocked frames */
struct st_stream_blocked_test_t {
    uint64_t stream_id;
    int is_id_blocked;
    int is_data_blocked;
    int is_client;
    int expect_bidir_blocked;
    int expect_unidir_blocked;
    int expect_data_blocked;
};

static const struct st_stream_blocked_test_t stream_blocked_test[] = {
    { 4, 1, 0, 1, 1, 0, 0},
    { 4, 1, 1, 0, 0, 0, 1},
    { 4, 0, 1, 0, 0, 0, 1}
};

static const size_t nb_stream_blocked_test = sizeof(stream_blocked_test) / sizeof(struct st_stream_blocked_test_t);

int send_stream_blocked_test_one(const struct st_stream_blocked_test_t * test)
{
    int ret = 0;
    uint8_t buf[1024];
    uint8_t bytes[1024];
    uint64_t simulated_time = 0;
    picoquic_quic_t* quic = picoquic_create(8, NULL, NULL, NULL, NULL, NULL,
        NULL, NULL, NULL, NULL, simulated_time,
        &simulated_time, NULL, NULL, 0);
    picoquic_cnx_t * cnx = NULL;
    struct sockaddr_storage addr;
    picoquic_stream_head_t* stream = NULL;

    if (quic == NULL) {
        ret = -1;
    }
    else {
        ret = picoquic_store_text_addr(&addr, "10.0.0.1", 1234);
        if (ret == 0) {
            cnx = picoquic_create_client_cnx(quic, (struct sockaddr*) & addr, simulated_time, 0, PICOQUIC_TEST_SNI, PICOQUIC_TEST_ALPN, NULL, NULL);
            if (cnx == NULL) {
                ret = -1;
            }
        }
    }

    if (ret == 0) {
        /* Setup the initial conditions */
        if (!test->is_client) {
            cnx->client_mode = 0;
        }
        if (test->is_id_blocked) {
            cnx->remote_parameters.initial_max_stream_id_bidir = 1;
            cnx->remote_parameters.initial_max_stream_id_unidir = 0;
        }
        else {
            cnx->remote_parameters.initial_max_stream_id_bidir = 64;
            cnx->remote_parameters.initial_max_stream_id_unidir = 64;
        }

        cnx->max_stream_id_bidir_remote = STREAM_ID_FROM_RANK(
            cnx->remote_parameters.initial_max_stream_id_bidir, cnx->client_mode, 0);
        cnx->max_stream_id_unidir_remote = STREAM_ID_FROM_RANK(
            cnx->remote_parameters.initial_max_stream_id_unidir, cnx->client_mode, 1);

        if (test->is_data_blocked) {
            cnx->remote_parameters.initial_max_stream_data_bidi_local = 0;
            cnx->remote_parameters.initial_max_stream_data_bidi_remote = 0;
            cnx->remote_parameters.initial_max_stream_data_uni = 0;
            cnx->remote_parameters.initial_max_data = PICOQUIC_DEFAULT_0RTT_WINDOW;
        }
        else {
            cnx->remote_parameters.initial_max_stream_data_bidi_local = 100000;
            cnx->remote_parameters.initial_max_stream_data_bidi_remote = 100000;
            cnx->remote_parameters.initial_max_stream_data_uni = 100000;
            cnx->remote_parameters.initial_max_data = 1000000;
        }
        cnx->maxdata_remote = cnx->remote_parameters.initial_max_data;

        /* Create the stream so it picks the required parameters */
        stream = picoquic_create_stream(cnx, test->stream_id);
        if (stream != NULL) {
            memset(buf, 0, sizeof(buf));
            ret = picoquic_add_to_stream(cnx, test->stream_id, buf, sizeof(buf), 0);
        }
        if (stream == NULL) {
            DBG_PRINTF("Could not find stream #%d", (int)test->stream_id);
            ret = -1;
        }
        if (ret == 0) {
            /* Call the blocked frame API */
            uint8_t* bytes_next;
            int is_pure_ack = 1;
            int more_data = 0;

            bytes_next = picoquic_format_one_blocked_frame(cnx, bytes, bytes + sizeof(bytes), &more_data, &is_pure_ack, stream);

            if (bytes_next != bytes && (is_pure_ack || more_data)) {
                DBG_PRINTF("Error formatting blocked frames, stream: %" PRIu64", length: %zu, more: %d, pure ack: %d",
                    test->stream_id, bytes_next - bytes, more_data, is_pure_ack);
                ret = -1;
            }
        }

        if (ret == 0 &&
            test->expect_bidir_blocked != cnx->stream_blocked_bidir_sent){
            DBG_PRINTF("Stream blocked bidir: %d vs %d", test->expect_bidir_blocked, cnx->stream_blocked_bidir_sent);
            ret = -1;
        }

        if (ret == 0 &&
            test->expect_unidir_blocked != cnx->stream_blocked_unidir_sent) {
            DBG_PRINTF("Stream blocked bidir: %d vs %d", test->expect_unidir_blocked, cnx->stream_blocked_unidir_sent);
            ret = -1;
        }

        if (ret == 0 &&
            test->expect_data_blocked != stream->stream_data_blocked_sent) {
            DBG_PRINTF("Stream data blocked: %d vs %d", test->expect_data_blocked, stream->stream_data_blocked_sent);
            ret = -1;
        }

    }
    

    if (quic != NULL) {
        picoquic_free(quic);
    }

    return ret;
}

int send_stream_blocked_test()
{
    int ret = 0;

    for (size_t i = 0; ret == 0 && i < nb_stream_blocked_test; i++) {
        if ((ret = send_stream_blocked_test_one(&stream_blocked_test[i])) != 0) {
            DBG_PRINTF("Stream blocked test %d failed", (int)i);
        }
    }

    return ret;
}

int picoquic_queue_network_input(picoquic_quic_t * quic, picosplay_tree_t* tree, uint64_t consumed_offset,
    uint64_t stream_ofs, const uint8_t* bytes, size_t length, int is_last_frame, picoquic_stream_data_node_t* received_data, int* new_data_available);

int64_t picoquic_stream_data_node_compare(void* l, void* r);
picosplay_node_t* picoquic_stream_data_node_create(void* value);
void picoquic_stream_data_node_delete(void* tree, picosplay_node_t* node);
void* picoquic_stream_data_node_value(picosplay_node_t* node);

int queue_network_input_test()
{
    int ret = 0;

    uint64_t simulated_time = 0;
    picoquic_quic_t* quic = picoquic_create(8, NULL, NULL, NULL, NULL, NULL,
        NULL, NULL, NULL, NULL, simulated_time,
        &simulated_time, NULL, NULL, 0);

    const size_t expected_length[3] = { 4, 2, 4 };
    const uint8_t expected[3][4] = {
        { 0, 1, 2, 3 },
        { 4, 5 },
        { 6, 7, 8, 9 }
    };

    const uint8_t data[10] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };
    int new_data_available = 0;

    picosplay_tree_t* tree = picosplay_new_tree(
        picoquic_stream_data_node_compare,
        picoquic_stream_data_node_create,
        picoquic_stream_data_node_delete,
        picoquic_stream_data_node_value);

    if (quic == NULL || tree == NULL) {
        ret = -1;
    }

    /* Fill 0..3 */
    if (ret == 0) {
        new_data_available = 0;
        if ((ret = picoquic_queue_network_input(quic, tree, 0, 0, data, 4, 1, NULL,
            &new_data_available)) != 0) {
            DBG_PRINTF("picoquic_queue_network_input(0, 0, 4) failed (%d)", ret);
        }
        else if (new_data_available == 0) {
            DBG_PRINTF("new_data_available doesn't signal new data (%d)", new_data_available);
            ret = 1;
        }
    }

    /* Fill 6..9 */
    if (ret == 0) {
        new_data_available = 0;
        if ((ret = picoquic_queue_network_input(quic, tree, 0, 6, data + 6, 4, 1, NULL, &new_data_available)) != 0) {
            DBG_PRINTF("picoquic_queue_network_input(0, 6, 4) failed (%d)", ret);
        } else if (new_data_available == 0) {
            DBG_PRINTF("new_data_available doesn't signal new data (%d)", new_data_available);
            ret = 1;
        }
    }

    /* Fill the gap from 4..5 with a chunk from 2..7 */
    if (ret == 0) {
        new_data_available = 0;
        if ((ret = picoquic_queue_network_input(quic, tree, 0, 2, data + 2, 6, 1, NULL, &new_data_available)) != 0) {
            DBG_PRINTF("picoquic_queue_network_input(0, 2, 6) failed (%d)", ret);
        } else if (new_data_available == 0) {
            DBG_PRINTF("new_data_available signals new data (%d)", new_data_available);
            ret = 1;
        }
    }

    /* No new data delivered by chunk 2..7 */
    if (ret == 0) {
        new_data_available = 0;
        if ((ret = picoquic_queue_network_input(quic, tree, 0, 2, data, 6, 1, NULL, &new_data_available)) != 0) {
            DBG_PRINTF("picoquic_queue_network_input(0, 2, 6) failed (%d)", ret);
        }

        if (new_data_available != 0) {
            DBG_PRINTF("new_data_available signals new data (%d)", new_data_available);
            ret = 1;
        }
    }

    if (ret == 0) {
        picoquic_stream_data_node_t* next = (picoquic_stream_data_node_t*)picosplay_first(tree);
        for (int i = 0; i < 3; ++i) {
            if (next == NULL) {
                DBG_PRINTF("tree does not contain enough data (%d chunks vs 3 exptected)", i);
                ret = 1;
                break;
            }
            else {
                if (expected_length[i] != next->length
                    || memcmp(next->bytes, expected[i], next->length) != 0) {
                    DBG_PRINTF("tree does not contain correct data (length: %zu vs %zu expected)", next->length, expected_length[i]);
                    ret = 1;
                    break;
                }
            }
            next = (picoquic_stream_data_node_t*)picosplay_next(&next->stream_data_node);
        }
    }

    if (tree != NULL) {
        picosplay_empty_tree(tree);
        free(tree);
    }

    if (quic != NULL) {
        picoquic_free(quic);
    }

    return ret;
}

#define QLOG_OVERFLOW_REF "picoquictest" PICOQUIC_FILE_SEPARATOR "app_msg_overflow_ref.qlog"
static char const* qlog_overflow_bin = "0809000102030405.client.log";
static char const* qlog_overflow_file = "0809000102030405.qlog";

int app_message_overflow_test()
{
    int ret = 0;
    uint64_t simulated_time = 0;
    picoquic_cnx_t* cnx = NULL;
    struct sockaddr_storage addr;
    const picoquic_connection_id_t initial_cid = { { 8, 9, 0, 1, 2, 3, 4, 5 }, 8 };
    const picoquic_connection_id_t dest_cid = { { 16, 17, 18, 19, 20, 21, 22, 23 }, 8 };
    char qlog_test_ref[512];
    int ret_qlog = picoquic_get_input_path(qlog_test_ref, sizeof(qlog_test_ref),
        picoquic_solution_dir, QLOG_OVERFLOW_REF);
    picoquic_quic_t* quic = picoquic_create(8, NULL, NULL, NULL, NULL, NULL,
        NULL, NULL, NULL, NULL, simulated_time,
        &simulated_time, NULL, NULL, 0);

    if (quic == NULL || ret_qlog != 0) {
        ret = -1;
    }
    else {
        picoquic_set_binlog(quic, ".");
        ret = picoquic_store_text_addr(&addr, "10.0.0.1", 1234);
        if (ret == 0) {
            cnx = picoquic_create_cnx(quic, initial_cid, dest_cid, (struct sockaddr*) & addr,
                simulated_time, 0, "test-sni", "test-alpn", 1);
            if (cnx == NULL) {
                ret = -1;
            }
            else {
                picoquic_log_new_connection(cnx);
            }
        }
    }
    if (ret == 0) {
        char test[BYTESTREAM_MAX_BUFFER_SIZE];

        memset(test, 'x', sizeof(test) - 3);
        test[sizeof(test) - 3] = '!';
        test[sizeof(test) - 2] = 0;

        for (int i = 0; i < 16; i++) {
            picoquic_log_app_message(cnx, "s:%s", &test[15 - i]);
        }

        picoquic_delete_cnx(cnx);
    }

    picoquic_free(quic);

    if (ret == 0) {
        /* Convert to QLOG and verify */
        uint64_t log_time = 0;
        uint16_t flags = 0;
        FILE* f_binlog = picoquic_open_cc_log_file_for_read(qlog_overflow_bin, &flags, &log_time);

        if (f_binlog == NULL) {
            DBG_PRINTF("Cannot open binlog file: %s.", qlog_overflow_bin);
            ret = -1;
        }
        else {
            ret = qlog_convert(&initial_cid, f_binlog, qlog_overflow_file, NULL, ".", flags);
            if (ret != 0) {
                DBG_PRINTF("%s", "Cannot convert the binary log into QLOG.\n");
            }
            else {
                ret = picoquic_test_compare_text_files(qlog_overflow_file, qlog_test_ref);
                if (ret != 0) {
                    DBG_PRINTF("%s", "Unexpected content in QLOG log file.\n");
                }
            }
            picoquic_file_close(f_binlog);
        }
    }

    return ret;
}

/* Testing the ack of stream functions
 *
 * Initialize streams in the application context 
 *
 * For a set of received packets, initialize sack list by running 
 * static int picoquic_process_ack_of_stream_frame(picoquic_cnx_t* cnx, uint8_t* bytes,
 *  size_t bytes_max, size_t* consumed)
 * Then, for a series of frames, verify that expected frames are not set to be repeated,
 * and that non expected frames are, using calls to:
 * - int picoquic_check_frame_needs_repeat(picoquic_cnx_t* cnx, const uint8_t* bytes,
 *       size_t bytes_max, int* no_need_to_repeat)
 * This is implemented by having two sets of packets:
 * - packets that contain frames and are acknowledged.
 * - packets that contain frames and are not yet acknowledged.
 * Test cases shall include:
 * - Single frame from start to FIN (stream 0)
 * - FIN only frame with offset 0 (stream 4)
 * - FIN only frame with large offset (stream 8)
 * - Regular frame offset 0, no specified length (stream 8)
 * - Regular frame offset 0, specified length (stream 12)
 * - Regular frame offset N, specified length (stream 12)
 * - Regular frame offset N, no specified length (stream 12)
 * - Regular frame offset N, no specified length, FIN (stream 12)
 * - Regular frame offset N, specified length, FIN (stream 16)
 * - Regular frame offset N, no FIN (stream 20)
 * - FIN only frame with large offset and unspecified length (stream 20)
 * Non acked tests shall include:
 * - Single frame from start to FIN (stream 20)
 * - 
 * 
 */

static uint64_t stream_ack_stream_list[] = { 0, 4, 8, 12, 16, 20 };

static uint8_t stream_ack_packet_1[] = {
    0x08 | 1 | 2, 0, 8, 1, 2, 3, 4, 5, 6, 7, 8, /* stream 0, 0..FIN */
    0x08 | 1 | 2, 4, 0, /* Stream 4, FIN */
    0x08 | 1 | 2 | 4, 8, 64, 64, 0,  /* Stream 8, FIN */
    0x08 | 4, 8, 32, 1, 2, 3, 4, 5, 6, 7, 8 /* Stream 8, 32..39, unspec */
};

static uint8_t stream_ack_packet_2[] = {
    0x08 | 2, 12, 8, 0, 1, 2, 3, 4, 5, 6, 7, /* stream 12, 0..7 */
    0x08 | 2 | 4, 12, 16, 8, 1, 2, 3, 4, 5, 6, 7, 8, /* Stream 12, 16..23, spec */
    0x08 | 4, 12, 24, 1, 2, 3, 4, 5, 6, 7, 8 /* Stream 12, 24..31, unspec */
};

static uint8_t stream_ack_packet_3[] = {
    0x08 | 1 | 2 | 4, 16, 32, 8, 1, 2, 3, 4, 5, 6, 7, 8, /* Stream 16, 32..39, FIN */
    0x08 | 2 | 4, 20, 4, 8, 1, 2, 3, 4, 5, 6, 7, 8, /* Stream 20, 4..11, spec */
    0x08 | 1 | 4, 20, 16, /* Stream 20, offset 16, unspec, FIN */
};

static uint8_t stream_ack_packet_4[] = {
    0x08 | 1, 20, 4, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8,
    9, 10, 11, 12, /* Stream 20, 0..FIN */
    0x08 | 1 | 2 | 4, 8, 63, 1, 0,  /* Stream 8, 63..FIN */
    0x08 | 4, 8, 32, 1, 2, 3, 4, 5, 6, 7, 8, 9 /* Stream 8, 32..40, unspec */
};

typedef struct st_stream_ack_case_t {
    uint8_t* bytes;
    size_t length;
    int should_ack;
} stream_ack_case_t;

static stream_ack_case_t stream_ack_case[] = {
    { stream_ack_packet_1, sizeof(stream_ack_packet_1), 1 },
    { stream_ack_packet_2, sizeof(stream_ack_packet_2), 1 },
    { stream_ack_packet_3, sizeof(stream_ack_packet_3), 1 },
    { stream_ack_packet_4, sizeof(stream_ack_packet_4), 0 },
};

static size_t nb_stream_ack_case = sizeof(stream_ack_case) / sizeof(stream_ack_case_t);

int picoquic_process_ack_of_stream_frame(picoquic_cnx_t* cnx, uint8_t* bytes,
    size_t bytes_max, size_t* consumed);

int stream_ack_test()
{
    int ret = 0;
    uint64_t simulated_time = 0;
    picoquic_cnx_t* cnx = NULL;
    struct sockaddr_storage addr;
    picoquic_quic_t* quic = picoquic_create(8, NULL, NULL, NULL, NULL, NULL,
        NULL, NULL, NULL, NULL, simulated_time,
        &simulated_time, NULL, NULL, 0);

    if (quic == NULL) {
        ret = -1;
    }
    else {
        ret = picoquic_store_text_addr(&addr, "10.0.0.1", 1234);
        if (ret == 0) {
            cnx = picoquic_create_cnx(quic, picoquic_null_connection_id,
                picoquic_null_connection_id, (struct sockaddr*) & addr,
                simulated_time, 0, "test-sni", "test-alpn", 1);
            if (cnx == NULL) {
                ret = -1;
            }
        }
    }

    if (ret == 0) {
        /* Create the required streams */
        for (size_t i = 0; i < sizeof(stream_ack_stream_list) / sizeof(uint64_t); i++) {
            if (picoquic_create_stream(cnx, stream_ack_stream_list[i]) == NULL) {
                DBG_PRINTF("Cannot create stream %" PRIu64, stream_ack_stream_list[i]);
                ret = -1;
                break;
            }
        }
    }

    if (ret == 0) {
        /* Acknowledge the specified packets */
        for (size_t i = 0; ret == 0 && i < nb_stream_ack_case; i++) {
            uint8_t * bytes = stream_ack_case[i].bytes;
            uint8_t * bytes_max = bytes + stream_ack_case[i].length;
            while (bytes < bytes_max && stream_ack_case[i].should_ack) {
                size_t consumed = 0;

                ret = picoquic_process_ack_of_stream_frame(cnx,
                    bytes, bytes_max - bytes, &consumed);
                if (ret != 0) {
                    DBG_PRINTF("Case %zu, cannot process frame index %zu",
                        i, bytes - stream_ack_case[i].bytes);
                    ret = -1;
                    break;
                }
                else {
                    bytes += consumed;
                }
            }
        }
    }

    if (ret == 0) {
        /* verify the expected acks */
        for (size_t i = 0; i < nb_stream_ack_case; i++) {
            uint8_t * bytes = stream_ack_case[i].bytes;
            size_t byte_index = 0;
            size_t bytes_max = stream_ack_case[i].length;
            while (byte_index < stream_ack_case[i].length){
                size_t consumed = 0;
                int is_pure_ack = 0;
                int do_not_detect_spurious = 0;

                ret = picoquic_skip_frame(
                    bytes + byte_index, bytes_max - byte_index, &consumed, &is_pure_ack);
                if (ret != 0) {
                    DBG_PRINTF("Case %zu, cannot process frame index %zu",
                        i, byte_index);
                    ret = -1;
                    break;
                }
                else {
                    int no_need_to_repeat;

                    ret = picoquic_check_frame_needs_repeat(cnx,
                        bytes + byte_index, consumed, picoquic_packet_1rtt_protected, &no_need_to_repeat, &do_not_detect_spurious, 0);
                    if (no_need_to_repeat && !stream_ack_case[i].should_ack) {
                        DBG_PRINTF("Case %zu, failed to repeat frame index %zu",
                            i, byte_index);
                        ret = -1;
                        break;
                    } else if (!no_need_to_repeat && stream_ack_case[i].should_ack) {
                        DBG_PRINTF("Case %zu, unneeded repeat frame index %zu",
                            i, byte_index);
                        ret = -1;
                        break;
                    }
                    byte_index += consumed;
                }
            }
        }
    }

    if (quic != NULL) {
        picoquic_free(quic);
    }

    return ret;
}
