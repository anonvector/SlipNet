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
#ifdef _WINDOWS
#include <malloc.h>
#endif
#include <string.h>
#include "picoquictest_internal.h"

static const picoquic_connection_id_t expected_cnxid[4] = {
    { { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 0, 0, 0, 0 } , 16 },
    { { 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10, 0, 0, 0, 0, 0, 0, 0, 0 } , 8 },
    { { 0xca, 0xfe, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 } , 2 },
    { { 0x77, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 } , 1 },
};

static const char* expected_str[4] = {
    "000102030405060708090a0b0c0d0e0f",
    "fedcba9876543210",
    "cafe",
    "77"
};

static size_t test_cases = sizeof(expected_cnxid) / sizeof(picoquic_connection_id_t);

int util_connection_id_print_test()
{
    int ret = 0;  
    char cnxid_str[2 * PICOQUIC_CONNECTION_ID_MAX_SIZE + 1];
  
    for (size_t i = 0; i < test_cases; ++i)
    {
        int result = picoquic_print_connection_id_hexa(cnxid_str, sizeof(cnxid_str), &expected_cnxid[i]);
        if (result != 0) {
            DBG_PRINTF("picoquic_print_connection_id_hexa failed with: %d\n", result);
            ret = -1;
        }
        if (strcmp(cnxid_str, expected_str[i]) != 0) {
            DBG_PRINTF("result: %s, expected: %s\n", cnxid_str, expected_str[i]);
            ret = -1;
        }
    }

    // Test invalid call
    if (picoquic_print_connection_id_hexa("", 0, &expected_cnxid[0]) == 0) {
        DBG_PRINTF("%s", "picoquic_print_connection_id_hexa did not fail\n");
        ret = -1;
    }

    return ret;
}

int util_connection_id_parse_test()
{
    int ret = 0;  
    for (size_t i = 0; i < test_cases; ++i) {
        picoquic_connection_id_t cnxid;
        uint8_t id_len = picoquic_parse_connection_id_hexa(expected_str[i], strlen(expected_str[i]), &cnxid);
        if (id_len != expected_cnxid[i].id_len) {
            DBG_PRINTF("Wrong length returned. result: %d, expected: %d\n", id_len, expected_cnxid[i].id_len);
            ret = -1;
        }
        if (picoquic_compare_connection_id(&cnxid, &expected_cnxid[i]) != 0) {
            DBG_PRINTF("%s", "the returned connection id is different than expected.\n");
            ret = -1;
        }
    }
    return ret;
}

int util_sprintf_test()
{
    int ret = 0;
    size_t nb_chars;
    char str[8];
    if (picoquic_sprintf(str, sizeof(str), NULL, "%s%s", "foo", "bar") != 0) {
        DBG_PRINTF("%s", "'foobar' test failed.");
        ret = -1;
    }
    if (picoquic_sprintf(str, sizeof(str), &nb_chars, "%s%s%s", "foo", PICOQUIC_FILE_SEPARATOR, "bar") != 0 ||
        nb_chars != 7) {
        DBG_PRINTF("'foo/bar' test failed. Nb_chars = %d", (int)nb_chars);
        ret = -1;
    }
    if (picoquic_sprintf(str, sizeof(str), NULL, "%s%s%s", "fooo", PICOQUIC_FILE_SEPARATOR, "bar") == 0) {
        DBG_PRINTF("%s", "'fooo/bar' test failed.");
        ret = -1;
    }
    if (picoquic_sprintf(str, sizeof(str), NULL, "%s%s%s", "fooo", PICOQUIC_FILE_SEPARATOR, "barr") == 0) {
        DBG_PRINTF("%s", "'fooo/barr' test failed.");
        ret = -1;
    }
    return ret;
}

/* Test the constant time memcmp for correctness and for
 * time constants. The test suite will include two 4MB
 * strings each comprising blocks of 16 bytes.
 *
 * The first block is composed of simple sequences of
 * pseudo random numbers. For each trial, each slice of
 * 16 bytes in the second matches the first one up to a
 * length L. We do the tests with L = 0 to 16, and measure
 * the execution time for each length. They are suppose
 * to not vary with the length. We also measure the
 * execution time of memcmp.
 *
 * The test pass if all the tests at length 0..15 return
 * non zero, if all the tests at length 16 return 0,
 * and if the time differences are not too high
 */

int util_memcmp_test()
{
    int ret = 0;
    size_t nb8 = (1 << 20) / sizeof(uint64_t);
    size_t l_total = nb8 * sizeof(uint64_t);
    uint64_t* x8 = (uint64_t*)malloc(l_total);
    uint8_t* x = (uint8_t*)x8;
    uint8_t* y = (uint8_t*)malloc(l_total);
    uint64_t random_seed = 0xbabac001;
    uint64_t time_start;
    uint64_t const_compare_time[16];
#if 0
    uint64_t memcmp_time[2];
#endif
    uint64_t carry;
    uint64_t nb_round = 2;

    if (x == NULL || y == NULL) {
        ret = -1;
    }
    else {
        x8[0] = 0;
        x8[1] = 0;
        x8[2] = 0xffffffffffffffffull;
        x8[3] = 0xffffffffffffffffull;

        for (size_t i = 4; i < nb8; i++) {
            x8[i] = picoquic_test_random(&random_seed);
        }
        /* test for correct detection of equality */
        memcpy(y, x, l_total);
        for (size_t j = 0; j < l_total; j += 16) {
            if (picoquic_constant_time_memcmp(x + j, y + j, 16) != 0) {
                DBG_PRINTF("Unexpected mismatch, rank %d\n", (int)j);
                ret = -1;
                break;
            }
        }

        for (size_t i = 0; ret == 0 && i < 16; i++) {
            /* prepare the y string */
            memcpy(y, x, l_total);
            for (size_t j = i; j < l_total; j += 16) {
                y[j] ^= (uint8_t)0xff;
            }

            /* test for correct detection of differences */
            for (size_t j = 0; j < l_total; j += 16) {
                if (picoquic_constant_time_memcmp(x + j, y + j, 16) == 0) {
                    DBG_PRINTF("Unexpected match, step %d, rank %d\n", (int)i, (int)j);
                    ret = -1;
                    break;
                }
            }
        }


        /* Time measurement: Compare a long string, at 16 different intervals. */
        while (ret == 0) {
            int zero_found = 0;
            for (size_t i = 0; ret == 0 && i < 16; i++) {
                /* prepare the y string */
                memcpy(y, x, l_total);
                y[1 + ((i * l_total) / 16)] ^= 0xff;

                carry = 1;
                time_start = picoquic_current_time();
                for (int j = 0; j < nb_round; j++) {
                    x[j] ^= 1;
                    y[j] ^= 1;
                    carry &= (picoquic_constant_time_memcmp(x, y, l_total) != 0);
                }
                const_compare_time[i] = picoquic_current_time() - time_start;
                if (carry != 1) {
                    DBG_PRINTF("Unexpected match, step %d\n", (int)i);
                    ret = -1;
                    break;
                }
                if (i == 0 && const_compare_time[i] < 2000) {
                    zero_found = 1;
                    break;
                }
            }

            if (zero_found) {
                nb_round *= 2;
            }
            else {
                break;
            }
        }
    }

    if (ret == 0) {
        DBG_PRINTF("%s", "Delta at, const memcmp (ns)\n");
        for (size_t i = 0; ret == 0 && i < 16; i++) {
            double d = 1000.0*(double)(const_compare_time[i]) / (double)(nb_round * l_total / 16);
            DBG_PRINTF("%d, %f\n", 1 + ((i * l_total) / 16), d);
        }
    }

    for (size_t i = 0; ret == 0 && i < 16; i++) {
        /* The time tests are information only, because measuring time is to susceptible to random noise */
        if (i > 0 && const_compare_time[0] >= 1000 && const_compare_time[i] >= 1000 && ((const_compare_time[i] > 2 * const_compare_time[0]) || (const_compare_time[0] > 2 * const_compare_time[i]))) {
            DBG_PRINTF("Step %d, const cmp time different from step 0, %d vs %d\n", (int)i, (int)const_compare_time[i], (int)const_compare_time[0]);
        }
    }

    #if 0
    while (ret == 0) {
        for (size_t i = 0; ret == 0 && i < 2; i++) {
            /* prepare the y string */
            memcpy(y, x, l_total);

            for (size_t j = 15*i; j < l_total; j += 16) {
                y[j] ^= (uint8_t)0xff;
            }


            carry = 1;
            time_start = picoquic_current_time();

            for (int r = 0; r < nb_round; r++) {
                /* measure compare time */
                for (size_t j = 0; j < l_total; j += 16) {
                    carry &= (memcmp(x, y, 16) != 0);
                }

                if (carry != 1) {
                    DBG_PRINTF("Unexpected memcmp match, step %d\n", (int)i);
                    ret = -1;
                    break;
                }
            }

            memcmp_time[i] = picoquic_current_time() - time_start;
        }

        if (memcmp_time[0] > 2000 && memcmp_time[1] > 2000) {
            break;
        }
        nb_round *= 2;
    } 

    if (ret == 0){
        if (memcmp_time[1] > 2 * memcmp_time[0]) {
            DBG_PRINTF("Memcmp not constant time on 16 bytes: t[0] = %d, t[15] = %d\n", (int)memcmp_time[0], (int)memcmp_time[1]);
            DBG_PRINTF("%s", "Need to compile with -DPICOQUIC_USE_CONSTANT_TIME_MEMCMP");
            ret = -1;
        }
        else {
            DBG_PRINTF("Memcmp constant time on 16 bytes: t[0] = %d, t[15] = %d\n", (int)memcmp_time[0], (int)memcmp_time[1]);
        }
    }
#endif

    if (x != NULL) {
        free(x);
    }

    if (y != NULL) {
        free(y);
    }

    return ret;
}

/* Testing the minimal thread support.
 *
 * We create one mutex and one event to synchronize two threads: one as a mutex demo,
 * the other as a start on event demo. The mutex
 *
 */

typedef struct st_thread_test_data_t {
    uint64_t data;
    picoquic_mutex_t mutex;
    picoquic_event_t event;
} thread_test_data_t;

static picoquic_thread_return_t thread_test_function(void* vctx )
{
    thread_test_data_t* ctx = (thread_test_data_t*)vctx;
    uint64_t x;

    for (int i = 0; i < 20; i++)
    {
        picoquic_lock_mutex(&ctx->mutex);
        x = ctx->data;
        ctx->data = x + 1;
        picoquic_unlock_mutex(&ctx->mutex);

        picoquic_signal_event(&ctx->event);
    }

    picoquic_thread_do_return;
}

int util_threading_test()
{
    thread_test_data_t ctx;
    picoquic_thread_t thread;
    uint64_t x;
    int ret;

    memset(&ctx, 0, sizeof(ctx));
    ret = picoquic_create_mutex(&ctx.mutex);
    if (ret != 0) {
        DBG_PRINTF("Create mutex returns %d (0x%x)", ret, ret);
    }

    if (ret == 0){
        ret = picoquic_create_event(&ctx.event);
        if (ret != 0) {
            DBG_PRINTF("Create event returns %d (0x%x)", ret, ret);
        }
    }

    if (ret == 0) {
        ret = picoquic_create_thread(&thread, thread_test_function, &ctx);
        if (ret != 0) {
            DBG_PRINTF("Create thread returns %d (0x%x)", ret, ret);
        }
    }

    while (ret == 0 && ctx.data == 0) {
        ret = picoquic_wait_for_event(&ctx.event, 10000);
        if (ret != 0) {
            DBG_PRINTF("Cannot wait for event, ret = %d (0x%x)", ret, ret);
        }
    }

    for (int i = 0; ret == 0 && i < 10; i++)
    {
        ret = picoquic_lock_mutex(&ctx.mutex);
        if (ret == 0) {
            x = ctx.data;
            ctx.data = x + 1;
            ret = picoquic_unlock_mutex(&ctx.mutex);
            if (ret != 0) {
                DBG_PRINTF("Cannot unlock the mutex, ret = %d (0x%x)", ret, ret);
            }
        }
        else {
            DBG_PRINTF("Cannot lock the mutex, ret = %d (0x%x)", ret, ret);
        }
    }

    while (ret == 0 && ctx.data < 30) {
        ret = picoquic_wait_for_event(&ctx.event, 10000);
        if (ret != 0) {
            DBG_PRINTF("Cannot wait for event, ret = %d (0x%x)", ret, ret);
        }
    }

    picoquic_delete_thread(&thread);
    picoquic_delete_event(&ctx.event);
    picoquic_delete_mutex(&ctx.mutex);

    if (ret == 0 && ctx.data != 30) {
        DBG_PRINTF("Could not count to %d, got %d", 30, ctx.data);
        ret = -1;
    }

    return ret;
}