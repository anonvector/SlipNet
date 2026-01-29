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

#include <stdlib.h>
#include <string.h>
#ifdef _WINDOWS
#include <malloc.h>
#endif

#include "picoquic_internal.h"
#include "picohash.h"

struct hashtestkey {
    uint64_t x;
    picohash_item item;
};

static uint64_t hashtest_hash(const void* v)
{
    const struct hashtestkey* k = (const struct hashtestkey*)v;
    uint64_t hash = (k->x + 0xDEADBEEFull);
    return hash;
}

static int hashtest_compare(const void* v1, const void* v2)
{
    const struct hashtestkey* k1 = (const struct hashtestkey*)v1;
    const struct hashtestkey* k2 = (const struct hashtestkey*)v2;

    return (k1->x == k2->x) ? 0 : -1;
}

static picohash_item * hashtest_key_to_item(const void * key)
{
    struct hashtestkey* p = (struct hashtestkey*)key;

    return &p->item;
}

static struct hashtestkey* hashtest_item(uint64_t x)
{
    struct hashtestkey* p = (struct hashtestkey*)malloc(sizeof(struct hashtestkey));

    if (p != NULL) {
        memset(p, 0, sizeof(struct hashtestkey));
        p->x = x;
    }

    return p;
}

int picohash_test_one(int embedded_item)
{
    /* Create a hash table */
    int ret = 0;
    picohash_table* t = NULL;
    
    if (!embedded_item) {
        t = picohash_create(32, hashtest_hash, hashtest_compare);
    }
    else {
        t = picohash_create_ex(32, hashtest_hash, hashtest_compare, hashtest_key_to_item);
    }

    if (t == NULL) {
        DBG_PRINTF("%s", "picohash_create() failed\n");
        ret = -1;
    } else {
        struct hashtestkey hk;

        if (t->count != 0) {
            DBG_PRINTF("picohash empty table count != 0 (count=%"PRIst")\n", t->count);
            ret = -1;
        }

        /* Enter a bunch of values, all different */
        for (uint64_t i = 1; ret == 0 && i < 10; i += 2) {
            if (picohash_insert(t, hashtest_item(i)) != 0) {
                DBG_PRINTF("picohash_insert(%"PRId64") failed\n", i);
                ret = -1;
            }
        }

        if (t->count != 5) {
            DBG_PRINTF("picohash table count != 5 (count=%"PRIst")\n", t->count);
            ret = -1;
        }

        /* Test whether each value can be retrieved */
        for (uint64_t i = 1; ret == 0 && i < 10; i += 2) {
            hk.x = i;
            picohash_item* pi = picohash_retrieve(t, &hk);

            if (pi == NULL) {
                DBG_PRINTF("picohash_retrieve(%"PRId64") failed\n", i);
                ret = -1;
            }
        }

        /* Create a bunch of collisions */
        for (uint64_t k = 1; ret == 0 && k < 6; k += 4) {
            for (uint64_t j = 1; ret == 0 && j <= k; j++) {
                if (picohash_insert(t, hashtest_item(k + 32 * j)) != 0) {
                    DBG_PRINTF("picohash_insert(%"PRId64" + 32 * %"PRId64") failed\n", k, j);
                    ret = -1;
                }
            }
        }

        if (t->count != 11) {
            DBG_PRINTF("picohash table count != 11 (count=%"PRIst")\n", t->count);
            ret = -1;
        }

        /* Check that the collisions can be retrieved */
        for (uint64_t k = 1; ret == 0 && k < 6; k += 4) {
            for (uint64_t j = 1; ret == 0 && j <= k; j++) {
                hk.x = k + 32 * j;
                picohash_item* pi = picohash_retrieve(t, &hk);

                if (pi == NULL) {
                    DBG_PRINTF("picohash_retrieve(%"PRId64" + 32 * %"PRId64") failed\n", k, j);
                    ret = -1;
                }
            }
        }

        /* Test whether different values cannot be retrieved */
        for (uint64_t i = 0; ret == 0 && i <= 10; i += 2) {
            hk.x = i;
            picohash_item* pi = picohash_retrieve(t, &hk);

            if (pi != NULL) {
                DBG_PRINTF("picohash_retrieve(%"PRId64") returned invalid item\n", i);
                ret = -1;
            }
        }

        /* Delete first, last and middle */
        for (uint64_t i = 1; ret == 0 && i < 10; i += 4) {
            hk.x = i;
            picohash_item* pi = picohash_retrieve(t, &hk);

            if (pi == NULL) {
                DBG_PRINTF("picohash_retrieve(%"PRId64") failed\n", i);
                ret = -1;
            } else {
                picohash_delete_item(t, pi, 1);
            }
        }

        /* Check that the deleted are gone */

        if (t->count != 8) {
            DBG_PRINTF("picohash table count != 8 (count=%"PRIst")\n", t->count);
            ret = -1;
        }

        for (uint64_t i = 1; ret == 0 && i < 10; i += 4) {
            hk.x = i;
            picohash_item* pi = picohash_retrieve(t, &hk);

            if (pi != NULL) {
                DBG_PRINTF("picohash_retrieve(%"PRId64") deleted value still found\n", i);
                ret = -1;
            }
        }

        /* Delete the table */
        picohash_delete(t, 1);
    }

    return ret;
}

int picohash_test()
{
    return(picohash_test_one(0));
}

int picohash_embedded_test()
{
    return(picohash_test_one(1));
}
