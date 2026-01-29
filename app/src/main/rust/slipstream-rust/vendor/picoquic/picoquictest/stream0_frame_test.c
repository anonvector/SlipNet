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

#include <string.h>
#include "picoquic_internal.h"

/*
 * Testing Arrival of Frame for Stream Zero
 */

/*
 * New definitions, using variable int coding.
 */

static uint8_t v0_1[] = {
    0x10, /* Start Byte: F=0, Len=0, Off=0 */
    0, /* One byte stream ID */
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10 /* Some random data */
};

static uint8_t v0_2[] = {
    0x14, /* Start Byte: F=0, Len=0, Off=4 */
    0, /* One byte stream ID */
    10, /* One byte offset */
    11, 12, 13, 14, 15, 16, 17, 18, 19, 20 /* Some random data */
};

static uint8_t v0_3[] = {
    0x14, /* Start Byte: F=0, Len=0, Off=4 */
    0x40, 0, /* Two  byte stream ID, still 0 */
    0x40, 20, /* Two byte offset */
    21, 22, 23, 24, 25, 26, 27, 28, 29, 30 /* Some random data */
};

static uint8_t v0_4[] = {
    0x16, /* Start Byte: F=0, Len=2, Off=4 */
    0x40, 0, /* Two  byte stream ID */
    0x80, 0, 0, 30, /* Four byte offset */
    0x40, 10, /* two byte length */
    31, 32, 33, 34, 35, 36, 37, 38, 39, 40 /* Some random data */
};

static uint8_t v0_5[] = {
    0x16, /* Start Byte: F=0, Len=2, Off=4 */
    0x80, 0, 0, 0, /* Four  byte stream ID */
    0xC0, 0, 0, 0, 0, 0, 0, 40, /* Eight byte offset */
    0x40, 10, /* Two byte length */
    41, 42, 43, 44, 45, 46, 47, 48, 49, 50, /* Some random data */
    0, 0, 0, 0, 0 /* Some random padding */
};

static uint8_t v0_45_overlap[] = {
    0x16, /* Start Byte: F=0, Len=2, Off=4 */
    0, /* One  byte stream ID */
    0x40, 35, /* Two byte offset */
    0x40, 10, /* Two byte length */
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF /* Some random data */
};

struct packet {
    uint8_t* packet;
    size_t packet_length;
    size_t offset;
    size_t data_length;
    size_t invalid_length;
};

static struct packet list_v1[] = {
    { v0_1, sizeof(v0_1), 0, 10, 0 },
    { v0_2, sizeof(v0_2), 10, 10, 0 },
    { v0_3, sizeof(v0_3), 20, 10, 0 },
    { v0_4, sizeof(v0_4), 30, 10, 0 },
    { v0_5, sizeof(v0_5), 40, 10, 0 }
};

static struct packet list_v2[] = {
    { v0_2, sizeof(v0_2), 10, 10, 0 },
    { v0_3, sizeof(v0_3), 20, 10, 0 },
    { v0_1, sizeof(v0_1), 0, 10, 0 },
    { v0_5, sizeof(v0_5), 40, 10, 0 },
    { v0_4, sizeof(v0_4), 30, 10, 0 },
};

static struct packet list_v3[] = {
    { v0_1, sizeof(v0_1), 0, 10, 0 },
    { v0_2, sizeof(v0_2), 10, 10, 0 },
    { v0_3, sizeof(v0_3), 20, 10, 0 },
    { v0_2, sizeof(v0_2), 10, 10, 0 },
    { v0_3, sizeof(v0_3), 20, 10, 0 },
    { v0_4, sizeof(v0_4), 30, 10, 0 },
    { v0_4, sizeof(v0_4), 30, 10, 0 },
    { v0_5, sizeof(v0_5), 40, 10, 0 },
    { v0_45_overlap, sizeof(v0_45_overlap), 35, 10, 0 }
};

struct test_case_st {
    const char* name;
    struct packet* list;
    size_t list_size;
    size_t expected_length;
};

static struct test_case_st test_case[] = {
    { "test_v1", list_v1, sizeof(list_v1) / sizeof(struct packet), 50 },
    { "test_v2", list_v2, sizeof(list_v2) / sizeof(struct packet), 50 },
    { "test_v3", list_v3, sizeof(list_v3) / sizeof(struct packet), 50 }
};

static size_t const nb_test_cases = sizeof(test_case) / sizeof(struct test_case_st);

#define FAIL(test, fmt, ...) DBG_PRINTF("Test %s failed: " fmt, (test)->name, __VA_ARGS__)

static int StreamZeroFrameOneTest(struct test_case_st* test)
{
    int ret = 0;

    uint64_t current_time = 0;
    picoquic_quic_t *quic = NULL;
    picoquic_cnx_t *cnx = NULL;
    struct sockaddr_in saddr;

    quic = picoquic_create(8, NULL, NULL, NULL, NULL, NULL,
        NULL, NULL, NULL, NULL, current_time,
        &current_time, NULL, NULL, 0);

    memset(&saddr, 0, sizeof(struct sockaddr_in));
    saddr.sin_family = AF_INET;
    saddr.sin_port = 1000;

    if (quic == NULL) {
        DBG_PRINTF("%s", "Cannot create QUIC context\n");
        ret = -1;
    }
    else {
        cnx = picoquic_create_cnx(quic,
            picoquic_null_connection_id, picoquic_null_connection_id, (struct sockaddr *) &saddr,
            current_time, 0, "test-sni", "test-alpn", 1);

        if (cnx == NULL) {
            DBG_PRINTF("%s", "Cannot create connection\n");
            ret = -1;
        }
        else {
            cnx->client_mode = 0;

            for (size_t i = 0; ret == 0 && i < test->list_size; i++) {
                if (NULL == picoquic_decode_stream_frame(cnx, test->list[i].packet,
                    test->list[i].packet + test->list[i].packet_length, NULL, current_time)) {
                    FAIL(test, "packet %" PRIst, i);
                    ret = -1;
                }
            }

            if (ret == 0 && picoquic_first_stream(cnx) == NULL) {
                FAIL(test, "%s", "No stream created");
                ret = -1;
            }

            if (ret == 0 && picoquic_first_stream(cnx)->stream_id != 0) {
                FAIL(test, "%s", "Other stream than 0");
                ret = -1;
            }

            if (ret == 0) {
                /* Check the content of all the data in the context */
                picoquic_stream_data_node_t* data = (picoquic_stream_data_node_t*)picosplay_first(&picoquic_first_stream(cnx)->stream_data_tree);
                size_t data_rank = 0;

                while (data != NULL) {
                    if (data->bytes == NULL) {
                        FAIL(test, "%s", "No data bytes");
                        ret = -1;
                    }

                    for (size_t i = 0; ret == 0 && i < data->length; i++) {
                        data_rank++;
                        if (data->bytes[i] != data_rank) {
                            FAIL(test, "byte %" PRIst " is %u instead of %" PRIst, i, data->bytes[i], data_rank);
                            ret = -1;
                        }
                    }

                    data = (picoquic_stream_data_node_t*)picosplay_next(&data->stream_data_node);
                }

                if (ret == 0 && data_rank != test->expected_length) {
                    FAIL(test, "total byte %" PRIst " bytes instead of %" PRIst, data_rank, test->expected_length);
                    ret = -1;
                }
            }

            picoquic_delete_cnx(cnx);
        }

        picoquic_free(quic);
    }

    return ret;
}

int StreamZeroFrameTest()
{
    int ret = 0;

    for (size_t i = 0; ret == 0 && i < nb_test_cases; i++) {
        ret = StreamZeroFrameOneTest(&test_case[i]);
    }

    return ret;
}


/*
* Testing Arrival of Frame for TLS Stream
*/

static uint8_t tlsv0_1[] = {
    0x18, 
    0, /* One byte offset */
    0x0A, /* One byte length */
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10 /* Some random data */
};

static uint8_t tlsv0_2[] = {
    0x18, 
    10, /* One byte offset */
    0x0A, /* One byte length */
    11, 12, 13, 14, 15, 16, 17, 18, 19, 20 /* Some random data */
};

static uint8_t tlsv0_3[] = {
    0x18, 
    0x40, 20, /* Two byte offset */
    0x40, 0x0A, /* Two byte length */
    21, 22, 23, 24, 25, 26, 27, 28, 29, 30 /* Some random data */
};

static uint8_t tlsv0_4[] = {
    0x18,
    0x80, 0, 0, 30, /* Four byte offset */
    0x40, 10, /* two byte length */
    31, 32, 33, 34, 35, 36, 37, 38, 39, 40 /* Some random data */
};

static uint8_t tlsv0_5[] = {
    0x18,
    0xC0, 0, 0, 0, 0, 0, 0, 40, /* Eight byte offset */
    0x40, 10, /* Two byte length */
    41, 42, 43, 44, 45, 46, 47, 48, 49, 50, /* Some random data */
    0, 0, 0, 0, 0 /* Some random padding */
};

static uint8_t tlsv0_45_overlap[] = {
    0x18,
    0x40, 35, /* Two byte offset */
    0x40, 10, /* Two byte length */
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF /* Some random data */
};

static uint8_t tlsv0_550_overlap2[] = {
    0x18,
    0x05, /* Offset */
    0x2d, /* length */
    6, 7, 8, 9, 10, /* Some random data */
    11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 
    21, 22, 23, 24, 25, 26, 27, 28, 29, 30,
    31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
    41, 42, 43, 44, 45, 46, 47, 48, 49, 50
};

static uint8_t tlsv0_05[] = {
    0x18,
    0, /* One byte offset */
    0x05, /* One byte length */
    1, 2, 3, 4, 5, /* Some random data */
};

static struct packet tlslist_v1[] = {
    { tlsv0_1, sizeof(tlsv0_1), 0, 10, 0 },
    { tlsv0_2, sizeof(tlsv0_2), 10, 10, 0 },
    { tlsv0_3, sizeof(tlsv0_3), 20, 10, 0 },
    { tlsv0_4, sizeof(tlsv0_4), 30, 10, 0 },
    { tlsv0_5, sizeof(tlsv0_5), 40, 10, 0 }
};

static struct packet tlslist_v2[] = {
    { tlsv0_2, sizeof(tlsv0_2), 10, 10, 0 },
    { tlsv0_3, sizeof(tlsv0_3), 20, 10, 0 },
    { tlsv0_1, sizeof(tlsv0_1), 0, 10, 0 },
    { tlsv0_5, sizeof(tlsv0_5), 40, 10, 0 },
    { tlsv0_4, sizeof(tlsv0_4), 30, 10, 0 },
};

static struct packet tlslist_v3[] = {
    { tlsv0_1, sizeof(tlsv0_1), 0, 10, 0 },
    { tlsv0_2, sizeof(tlsv0_2), 10, 10, 0 },
    { tlsv0_3, sizeof(tlsv0_3), 20, 10, 0 },
    { tlsv0_2, sizeof(tlsv0_2), 10, 10, 0 },
    { tlsv0_3, sizeof(tlsv0_3), 20, 10, 0 },
    { tlsv0_4, sizeof(tlsv0_4), 30, 10, 0 },
    { tlsv0_4, sizeof(tlsv0_4), 30, 10, 0 },
    { tlsv0_5, sizeof(tlsv0_5), 40, 10, 0 },
    { tlsv0_45_overlap, sizeof(tlsv0_45_overlap), 35, 10, 0 }
};

static struct packet tlslist_v4[] = {
    { tlsv0_3, sizeof(tlsv0_3), 20, 10, 0 },
    { tlsv0_4, sizeof(tlsv0_4), 30, 10, 0 },
    { tlsv0_550_overlap2, sizeof(tlsv0_550_overlap2), 5, 45, 0 },
    { tlsv0_05, sizeof(tlsv0_05), 0, 5, 0 }
};

static struct test_case_st tls_test_case[] = {
    { "tlstest_v1", tlslist_v1, sizeof(tlslist_v1) / sizeof(struct packet), 50 },
    { "tlstest_v2", tlslist_v2, sizeof(tlslist_v2) / sizeof(struct packet), 50 },
    { "tlstest_v3", tlslist_v3, sizeof(tlslist_v3) / sizeof(struct packet), 50 },
    { "tlstest_v4", tlslist_v4, sizeof(tlslist_v4) / sizeof(struct packet), 50 }
};

static size_t const nb_tls_test_cases = sizeof(tls_test_case) / sizeof(struct test_case_st);

int64_t picoquic_stream_data_node_compare(void* l, void* r);
picosplay_node_t* picoquic_stream_data_node_create(void* value);
void* picoquic_stream_data_node_value(picosplay_node_t* node);
void picoquic_stream_data_node_delete(void* tree, picosplay_node_t* node);

static int TlsStreamFrameOneTest(struct test_case_st* test)
{
    int ret = 0;
    int test_epoch = 2; /* epoch = 2 for handshake */
    uint64_t current_time = 0;
    picoquic_quic_t* quic = NULL;
    picoquic_cnx_t cnx = { 0 };

    quic = picoquic_create(8, NULL, NULL, NULL, NULL, NULL,
        NULL, NULL, NULL, NULL, current_time,
        &current_time, NULL, NULL, 0);
    cnx.quic = quic;
    
    if (quic == NULL) {
        ret = -1;
    }
    else {
        picosplay_init_tree(&cnx.tls_stream[2].stream_data_tree, picoquic_stream_data_node_compare, picoquic_stream_data_node_create, picoquic_stream_data_node_delete, picoquic_stream_data_node_value);
    }

    for (size_t i = 0; ret == 0 && i < test->list_size; i++) {
        if (NULL == picoquic_decode_crypto_hs_frame(&cnx, test->list[i].packet,
                test->list[i].packet + test->list[i].packet_length, NULL, test_epoch )) {
            FAIL(test, "packet %" PRIst, i);
            ret = -1;
        }
    }

    if (ret == 0) {
        /* Check the content of all the data in the context */
        picoquic_stream_data_node_t* data = (picoquic_stream_data_node_t* )picosplay_first(&cnx.tls_stream[test_epoch].stream_data_tree);
        size_t data_rank = 0;

        while (data != NULL) {
            if (data->bytes == NULL) {
                FAIL(test, "%s", "No data bytes");
                ret = -1;
            }

            for (size_t i = 0; ret == 0 && i < data->length; i++) {
                data_rank++;
                if (data->bytes[i] != data_rank) {
                    FAIL(test, "byte %" PRIst " is %u instead of %" PRIst, i, data->bytes[i], data_rank);
                    ret = -1;
                }
            }

            data = (picoquic_stream_data_node_t*)picosplay_next(&data->stream_data_node);
        }

        if (ret == 0 && data_rank != test->expected_length) {
            FAIL(test, "total byte %" PRIst " bytes instead of %" PRIst, data_rank, test->expected_length);
            ret = -1;
        }
    }

    picosplay_empty_tree(&cnx.tls_stream[2].stream_data_tree);

    if (quic != NULL) {
        picoquic_free(quic);
    }

    return ret;
}

int TlsStreamFrameTest()
{
    int ret = 0;

    for (size_t i = 0; ret == 0 && i < nb_tls_test_cases; i++) {
        ret = TlsStreamFrameOneTest(&tls_test_case[i]);
    }

    return ret;
}

/*
 * Test creation and deletion of streams.
 */
int check_stream_splay_node_sanity(picosplay_node_t *x, void *floor, void *ceil, picosplay_comparator comp) {
    int count = 0;

    if (x != NULL) {
        count = 1;
        if (x->left != NULL) {
            if (x->left->parent == x) {
                void *new_floor;
                if (floor == NULL || comp(picoquic_stream_from_node(x), floor) < 0)
                    new_floor = picoquic_stream_from_node(x);
                else
                    new_floor = floor;
                count += check_stream_splay_node_sanity(x->left, new_floor, ceil, comp);
            }
            else {
                DBG_PRINTF("%s", "Invalid node, left->parent != node.\n");
                count = -1;
            }
        }
        if (x->right != NULL && count > 0) {
            if (x->right->parent == x) {
                void *new_ceil;
                if (ceil == NULL || comp(picoquic_stream_from_node(x), ceil) > 0)
                    new_ceil = picoquic_stream_from_node(x);
                else
                    new_ceil = ceil;
                count += check_stream_splay_node_sanity(x->right, floor, new_ceil, comp);
            }
            else {
                DBG_PRINTF("%s", "Invalid node, left->parent != node.\n");
                count = -1;
            }
        }
    }

    return count;
}

int stream_splay_test()
{
    int ret = 0;
    int count = 0;
    picoquic_quic_t *quic = NULL;
    picoquic_cnx_t *cnx = NULL;
    uint64_t simulated_time = 0;
    struct sockaddr_in saddr;
    uint64_t values[] = { 3, 4, 1, 2, 8, 5, 7 };
    uint64_t ordered[] = { 1, 2, 3, 4, 5, 7, 8 };
    uint64_t values_first[] = { 3, 3, 1, 1, 1, 1, 1 };
    uint64_t values_last[] = { 3, 4, 4, 4, 8, 8, 8 };
    uint64_t value2_first[] = { 1, 1, 2, 5, 5, 7, 0 };
    uint64_t value2_last[] = { 8, 8, 8, 8, 7, 7, 0 };


    quic = picoquic_create(8, NULL, NULL, NULL, NULL, NULL,
        NULL, NULL, NULL, NULL, simulated_time,
        &simulated_time, NULL, NULL, 0);

    memset(&saddr, 0, sizeof(struct sockaddr_in));
    saddr.sin_family = AF_INET;
    saddr.sin_port = 1000;

    if (quic == NULL) {
        DBG_PRINTF("%s", "Cannot create QUIC context\n");
        ret = -1;
    }
    else {
        cnx = picoquic_create_cnx(quic,
            picoquic_null_connection_id, picoquic_null_connection_id, (struct sockaddr *) &saddr,
            simulated_time, 0, "test-sni", "test-alpn", 1);

        if (cnx == NULL) {
            DBG_PRINTF("%s", "Cannot create connection\n");
            ret = -1;
        } else {
            picoquic_stream_head_t * stream;
            int rank = 0;

            /* test creation of streams */
            for (int i = 0; ret == 0 && i < 7; i++) {
                picoquic_create_stream(cnx, values[i]);
                /* Verify sanity and count after each insertion */
                count = check_stream_splay_node_sanity(cnx->stream_tree.root, NULL, NULL, cnx->stream_tree.comp);
                if (count != i + 1) {
                    DBG_PRINTF("Insert v[%d] = %d, expected %d nodes, got %d instead\n",
                        i, values[i], i + 1, count);
                    ret = -1;
                }
                else if (cnx->stream_tree.size != count) {
                    DBG_PRINTF("Insert v[%d] = %d, expected tree size %d, got %d instead\n",
                        i, values[i], count, cnx->stream_tree.size);
                    ret = -1;
                }
                else if (picoquic_first_stream(cnx)->stream_id != values_first[i]) {
                    DBG_PRINTF("Insert v[%d] = %d, expected first = %d, got %d instead\n",
                        i, values[i],
                        values_first[i], (int)picoquic_first_stream(cnx)->stream_id);
                    ret = -1;
                }
                else if (picoquic_last_stream(cnx)->stream_id != values_last[i]) {
                    DBG_PRINTF("Insert v[%d] = %d, expected first = %d, got %d instead\n",
                        i, values[i],
                        values_last[i], (int)picoquic_last_stream(cnx)->stream_id);
                    ret = -1;
                }
            }

            /* test order */
            stream = picoquic_first_stream(cnx);
            while (ret == 0 && rank < 7) {
                if (stream == NULL) {
                    DBG_PRINTF("Stream[%d] is NULL\n", rank);
                    ret = -1;
                }
                else if (stream->stream_id != ordered[rank]) {
                    DBG_PRINTF("Stream[%d].stream_id = %d, expected %d\n", rank, (int)stream->stream_id, (int)ordered[rank]);
                    ret = -1;
                }
                else {
                    stream = picoquic_next_stream(stream);
                    rank++;
                }
            }


            /* Test deletion of streams */
            for (int i = 0; ret == 0 && i < 7; i++) {
                stream = picoquic_find_stream(cnx, values[i]);
                if (stream == NULL) {
                    DBG_PRINTF("Cannot find stream %d\n", (int)values[i]);
                    ret = -1;
                    break;
                }
                picoquic_delete_stream(cnx, stream);
                /* Verify sanity and count after each deletion */
                count = check_stream_splay_node_sanity(cnx->stream_tree.root, NULL, NULL, cnx->stream_tree.comp);
                if (count != 6 - i) {
                    DBG_PRINTF("Delete v[%d] = %d, expected %d nodes, got %d instead\n",
                        i, values[i], 6 - i, count);
                    ret = -1;
                }
                else if (cnx->stream_tree.size != count) {
                    DBG_PRINTF("Insert v[%d] = %d, expected cnx->stream_tree size %d, got %d instead\n",
                        i, values[i], count, cnx->stream_tree.size);
                    ret = -1;
                }
                else if (i < 6) {
                    if (picoquic_first_stream(cnx)->stream_id != value2_first[i]) {
                        DBG_PRINTF("Delete v[%d] = %d, expected first = %d, got %d instead\n",
                            i, values[i], value2_first[i], (int)picoquic_first_stream(cnx)->stream_id);
                        ret = -1;
                    }
                    else if (picoquic_last_stream(cnx)->stream_id != value2_last[i]) {
                        DBG_PRINTF("Delete v[%d] = %d, expected first = %d, got %d instead\n",
                            i, values[i], value2_last[i], (int)picoquic_last_stream(cnx)->stream_id);
                        ret = -1;
                    }
                }
            }

            if (ret == 0 && cnx->stream_tree.root != NULL) {
                DBG_PRINTF("%s", "Final cnx->stream_tree root should be NULL, is not.\n");
                ret = -1;
            }

            picoquic_delete_cnx(cnx);
            cnx = NULL;
        }

        picoquic_free(quic);
        quic = NULL;
    }

    return ret;
}

/* Test that the list of active streams is properly maintained */

static int stream_output_test_callback(picoquic_cnx_t* cnx,
    uint64_t stream_id, uint8_t* bytes, size_t length,
    picoquic_call_back_event_t fin_or_event, void* callback_ctx, void* v_stream_ctx)
{
#ifdef _WINDOWS
    UNREFERENCED_PARAMETER(cnx);
    UNREFERENCED_PARAMETER(stream_id);
    UNREFERENCED_PARAMETER(bytes);
    UNREFERENCED_PARAMETER(length);
    UNREFERENCED_PARAMETER(fin_or_event);
    UNREFERENCED_PARAMETER(callback_ctx);
    UNREFERENCED_PARAMETER(v_stream_ctx);
#endif
    return 0;
}

static int stream_output_test_list(picoquic_cnx_t * cnx, size_t nb_output, uint64_t * output)
{
    int ret = 0;
    picoquic_stream_head_t * stream;
    size_t nb_found = 0;

    /* test order and value of output list */
    stream = cnx->first_output_stream;
    while (ret == 0) {
        if (stream == NULL) {
            if (nb_found < nb_output) {
                DBG_PRINTF("Stream[%d] is NULL\n", (int)nb_found);
                ret = -1;
            }
            break;
        }
        else if (nb_found >= nb_output) {
            if (nb_found < nb_output) {
                DBG_PRINTF("Stream[%d] is not NULL\n", (int)nb_found);
                ret = -1;
            }
        }
        else if (stream->stream_id != output[nb_found]) {
            DBG_PRINTF("Stream[%d].stream_id = %d, expected %d\n", (int)nb_found, (int)stream->stream_id, (int)output[nb_found]);
            ret = -1;
        }
        else {
            stream = stream->next_output_stream;
            nb_found++;
        }
    }

    return ret;
}

int stream_output_test_delete(picoquic_cnx_t * cnx, uint64_t stream_id, int R_or_F)
{
    int ret = 0;
    picoquic_stream_head_t * stream = picoquic_find_stream(cnx, stream_id);
    picoquic_stream_head_t * previous = NULL;
    picoquic_stream_head_t * ready_stream = NULL;
    int is_last = 0;

    if (stream == NULL) {
        DBG_PRINTF("Stream[%d] was already deleted\n", (int)stream_id);
        ret = -1;
    }
    else if (!stream->is_output_stream) {
        DBG_PRINTF("Stream[%d] is not output stream\n", (int)stream_id);
        ret = -1;
    }
    else {
        /* Set the flags to mimic termination */
        if (R_or_F == 0) {
            stream->fin_requested = 1;
            stream->fin_sent = 1;
            ret = picoquic_sack_list_reset(&stream->sack_list, 0, stream->sent_offset + 1, 0);
        }
        else {
            stream->reset_requested = 1;
            stream->reset_sent = 1;
            stream->reset_acked = 1;
        }
    }
    if (ret == 0) {
        stream->is_active = 0;

        if (IS_BIDIR_STREAM_ID(stream_id)) {
            stream->fin_received = 1;
            stream->fin_signalled = 1;
        }

        /* Make sure the search will start at this specific stream */
        if (stream == cnx->first_output_stream && stream->next_output_stream == NULL) {
            previous = NULL;
            is_last = 1;
        }
        else {
            previous = cnx->first_output_stream;
            while (previous != NULL) {
                if (previous->next_output_stream == stream) {
                    break;
                }
                previous = previous->next_output_stream;
            }
        }
        /* Delete the stream explicitly */
        picoquic_remove_output_stream(cnx, stream);
        picoquic_delete_stream_if_closed(cnx, stream);
        /* Call ready stream to check availability after deletion  */
        ready_stream = picoquic_find_ready_stream(cnx);
        /* Verify that ready stream is as expected */
        if (ready_stream == NULL) {
            if (!is_last) {
                DBG_PRINTF("No stream available after delete[%d]\n", stream_id);
                ret = -1;
            }
        }
        else if (is_last) {
            DBG_PRINTF("Stream available after delete[%d]\n", stream_id);
            ret = -1;
        }
        else if (ready_stream->stream_id == stream_id) {
            DBG_PRINTF("Stream still available after delete[%d]\n", stream_id);
            ret = -1;
        }

        /* Verify that the stream is removed from the output list */
        previous = cnx->first_output_stream;
        while (ret == 0 && previous != NULL) {
            if (previous->stream_id == stream_id) {
                DBG_PRINTF("Stream %d not removed from list\n", (int)stream_id);
                ret = -1;
                break;
            }
            previous = previous->next_output_stream;
        }

        if (ret == 0) {
            /* Verify that stream is deleted */
            if ((stream = picoquic_find_stream(cnx, stream_id)) != NULL ) {
                DBG_PRINTF("Stream %d not deleted, closed: %d\n", (int)stream_id, stream->is_closed);
                ret = -1;
            }
        }
    }
    return ret;
}

int stream_output_test()
{
    int ret = 0;
    picoquic_quic_t *quic = NULL;
    picoquic_cnx_t *cnx = NULL;
    uint64_t simulated_time = 0;
    struct sockaddr_in saddr;
    uint64_t values[] = { 0, 3, 4, 1, 2, 8, 5, 7 };
    uint64_t output1[] = { 0, 1, 2, 4, 5 };
    uint64_t output2[] = { 0, 1, 2, 4, 5, 8 };
    uint64_t delete_order[] = { 1, 0, 4, 2, 5, 8 };
    picoquic_stream_head_t * stream = NULL;

    quic = picoquic_create(8, NULL, NULL, NULL, NULL, NULL,
        NULL, NULL, NULL, NULL, simulated_time,
        &simulated_time, NULL, NULL, 0);

    memset(&saddr, 0, sizeof(struct sockaddr_in));
    saddr.sin_family = AF_INET;
    saddr.sin_port = 1000;

    if (quic == NULL) {
        DBG_PRINTF("%s", "Cannot create QUIC context\n");
        ret = -1;
    }
    else {
        cnx = picoquic_create_cnx(quic,
            picoquic_null_connection_id, picoquic_null_connection_id, (struct sockaddr *) &saddr,
            simulated_time, 0, "test-sni", "test-alpn", 1);

        if (cnx == NULL) {
            DBG_PRINTF("%s", "Cannot create connection\n");
            ret = -1;
        }
        else {
            picoquic_set_callback(cnx, stream_output_test_callback, NULL);
            /* Set parameter data to a plausible value so tests can run */
            cnx->maxdata_remote = PICOQUIC_DEFAULT_0RTT_WINDOW;
            cnx->remote_parameters.initial_max_stream_data_bidi_remote = PICOQUIC_DEFAULT_0RTT_WINDOW;
            cnx->remote_parameters.initial_max_stream_data_uni = PICOQUIC_DEFAULT_0RTT_WINDOW;
            cnx->max_stream_id_bidir_remote = (cnx->client_mode) ? 4 : 0;
            cnx->max_stream_id_unidir_remote = (cnx->client_mode) ? 10 : 0;

            cnx->high_priority_stream_id = 1;

            /* Create the list of streams */
            for (int i = 0; i < 7; i++) {
                picoquic_create_stream(cnx, values[i]);
            }

            ret = stream_output_test_list(cnx, sizeof(output1) / sizeof(uint64_t), output1);

            if (ret == 0) {
                /* Relax the max stream id value and test order again */
                uint64_t old_limit = cnx->max_stream_id_bidir_remote;
                cnx->max_stream_id_bidir_remote = 8;
                picoquic_add_output_streams(cnx, old_limit, 8, 1);
                ret = stream_output_test_list(cnx, sizeof(output2) / sizeof(uint64_t), output2);
            }

            if (ret == 0) {
                /* Check that find ready stream returns NULL when no stream is ready */
                stream = picoquic_find_ready_stream(cnx);
                if (stream != NULL) {
                    DBG_PRINTF("Unexpected ready stream[%d]\n", (int)stream->stream_id);
                    ret = -1;
                }
            }

            if (ret == 0) {
                /* Mark all streams as active */
                stream = cnx->first_output_stream;

                while (stream != NULL) {
                    stream->maxdata_remote = 4096;
                    picoquic_mark_active_stream(cnx, stream->stream_id, 1, NULL);
                    stream = stream->next_output_stream;
                }

                /* Check that first stream is what we expect */
                stream = picoquic_find_ready_stream(cnx);
                if (stream == NULL) {
                    DBG_PRINTF("Expected stream[%d],got NULL\n", (int)output2[0]);
                    ret = -1;
                }
                else if (stream->stream_id != output2[0]) {
                    DBG_PRINTF("Expected stream[%d],got %d\n", (int)output2[0], (int)stream->stream_id);
                    ret = -1;
                }
            }

            if (ret == 0) {
                /* Check automated stream deletion */
                for (size_t i = 0; ret == 0 && i < (sizeof(delete_order) / sizeof(uint64_t)); i++) {
                    ret = stream_output_test_delete(cnx, delete_order[i], i & 1);
                }
            }

            picoquic_delete_cnx(cnx);
            cnx = NULL;
        }

        picoquic_free(quic);
        quic = NULL;
    }

    return ret;
}

/* Test the STREAM ID and STREAM RANK macros
 */

int stream_rank_test_one(size_t n, uint64_t *rank, uint64_t *stream_id, 
    unsigned int is_unidir, unsigned int client_mode)
{
    int ret = 0;

    for (size_t i = 0; i < n; i++) {
        uint64_t r = STREAM_RANK_FROM_ID(stream_id[i]);
        uint64_t s = STREAM_ID_FROM_RANK(rank[i], client_mode, is_unidir);

        if (r != rank[i]) {
            DBG_PRINTF("For stream: %d, expect rank: %d, got %d\n",
                (int)stream_id[i], (int)rank[i], (int)r);
            ret = -1;
        }

        if (s != stream_id[i]) {
            DBG_PRINTF("For rank: %d, uni: %d, server: %d, expect stream %d, got %d\n",
                (int)rank[i], is_unidir, client_mode, (int)stream_id[i], (int)s);
            ret = -1;
        }
    }

    return ret;
}

int stream_rank_test()
{
    uint64_t stream_rank[] = { 1, 2, 3, 1000, 10000 };
    uint64_t stream_client_bidir[] = { 0, 4, 8, 3996, 39996 };
    uint64_t stream_client_unidir[] = { 2, 6, 10, 3998, 39998 };
    uint64_t stream_server_bidir[] = { 1, 5, 9, 3997, 39997 };
    uint64_t stream_server_unidir[] = { 3, 7, 11, 3999, 39999 };
    size_t n = sizeof(stream_rank) / sizeof(uint64_t);
    int ret = 0;

    ret |= stream_rank_test_one(n, stream_rank, stream_client_bidir, 0, 1);
    ret |= stream_rank_test_one(n, stream_rank, stream_client_unidir, 1, 1);
    ret |= stream_rank_test_one(n, stream_rank, stream_server_bidir, 0, 0);
    ret |= stream_rank_test_one(n, stream_rank, stream_server_unidir, 1, 0);

    return ret;
}

/* Unit test of "picoquic_provide_stream_data_buffer"
 */

static int picoquic_set_stream_buffer_context(picoquic_stream_data_buffer_argument_t * stream_data_context,
    uint8_t * bytes, uint8_t * bytes_max, uint64_t stream_id, uint64_t stream_offset)
{
    int ret = 0;
    uint8_t* bytes0 = bytes;
    memset(stream_data_context, 0, sizeof(picoquic_stream_data_buffer_argument_t));
    if ((bytes = picoquic_format_stream_frame_header(bytes, bytes_max, stream_id, stream_offset)) == NULL) {
        ret = -1;
    }
    else {
        /* Compute the length */
        stream_data_context->bytes = bytes0;
        stream_data_context->byte_index = bytes - bytes0;
        stream_data_context->allowed_space = bytes_max - bytes;
        stream_data_context->byte_space = bytes_max - bytes;
        stream_data_context->length = 0;
        stream_data_context->is_fin = 0;
        stream_data_context->is_still_active = 0;
        stream_data_context->app_buffer = NULL;
    }
    return ret;
}

typedef enum {
    size_test_full = 0,
    size_test_minus_1,
    size_test_minus_2,
    size_test_minus_3,
    size_test_1,
    size_test_0,
    size_test_too_long,
    size_test_last
} size_test_enum;

int provide_stream_buffer_test_one(uint64_t stream_id, uint64_t stream_offset, size_test_enum size_test, int is_fin)
{
    uint8_t packet[512];
    uint8_t test_data[512];
    picoquic_stream_data_buffer_argument_t stream_data_context;
    int ret = picoquic_set_stream_buffer_context(&stream_data_context, packet, packet + sizeof(packet), stream_id, stream_offset);
    size_t length = 0;

    if (ret == 0) {

        switch (size_test) {
        case size_test_full:
            length = stream_data_context.byte_space;
            break;
        case size_test_minus_1:
            length = stream_data_context.byte_space - 1;
            break;
        case size_test_minus_2:
            length = stream_data_context.byte_space - 2;
            break;
        case size_test_minus_3:
            length = stream_data_context.byte_space - 3;
            break;
        case size_test_1:
            length = 1;
            break;
        case size_test_0:
            length = 0;
            break;
        case size_test_too_long:
            length = stream_data_context.byte_space;
            stream_data_context.allowed_space = length - 1;
            break;
        default:
            ret = -1;
            break;
        }
    }

    if (ret == 0) {
        uint8_t * data_ptr = picoquic_provide_stream_data_buffer(&stream_data_context, length, is_fin, 0);

        if (size_test == size_test_too_long) {
            ret = (data_ptr == NULL) ? 0 : -1;
        }
        else if (data_ptr == NULL) {
            ret = -1;
        }
        else if (data_ptr + length > packet + sizeof(packet)) {
            ret = -1;
        }
        else {
            uint8_t* packet_start = packet;
            uint64_t received_stream_id;
            uint64_t received_offset;
            size_t received_length = 0;
            size_t consumed = 0;
            int received_fin = 0;

            if (length > 0) {
                /* set test data value */
                for (size_t i = 0; i < length; i++) {
                    test_data[i] = (uint8_t)(i ^ 0x7f);
                }
                /* Fill the data space */
                memcpy(data_ptr, test_data, length);
            }
            /* Get the start point of the data frame */
            while (*packet_start == picoquic_frame_type_padding && packet_start < packet + sizeof(packet)) {
                packet_start++;
            }
            /* decode the stream header */
            if (picoquic_parse_stream_header(packet_start,
                sizeof(packet) - (packet_start - packet), &received_stream_id, &received_offset,
                &received_length, &received_fin, &consumed) != 0) {
                ret = -1;
            }
            else if (received_stream_id != stream_id ||
                received_offset != stream_offset ||
                received_length != length ||
                received_fin != is_fin) {
                ret = -1;
            }
            else if (length > 0 &&
                memcmp(packet_start + consumed, test_data, length) != 0) {
                ret = -1;
            }
        }
    }
    return ret;
}

int provide_stream_buffer_test()
{
    uint64_t stream_ids[4] = { 0, 7, 127, 0x10000 };
    uint64_t offsets[4] = { 0, 1, 65, 0x10000 };
    int ret = 0;

    for (int i_stream = 0; ret == 0 && i_stream < 4; i_stream++) {
        for (int i_offset = 0; ret == 0 &&  i_offset < 4; i_offset++) {
            for (int is_fin = 0; ret == 0 &&  is_fin < 2; is_fin++) {
                for (size_test_enum size_test = 0; ret == 0 &&  size_test < size_test_last; size_test++) {
                    ret = provide_stream_buffer_test_one(stream_ids[i_stream], offsets[i_offset], size_test, is_fin);
                    if (ret != 0) {
                        DBG_PRINTF("Fails for stream %" PRIu64 ", offset %" PRIu64 ", fin %d, test %d",
                            stream_ids[i_stream], offsets[i_offset], is_fin, size_test);
                        break;
                    }
                }
            }
        }
    }
    return ret;
}