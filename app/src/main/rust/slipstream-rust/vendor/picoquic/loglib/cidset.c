/*
* Author: Christian Huitema
* Copyright (c) 2019, Private Octopus, Inc.
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
#include <stdio.h>
#include <stdlib.h>
#include "cidset.h"
#include "picoquic_utils.h"

/* Hash and compare for CNX hash tables */
static uint64_t picoquic_cid_hash(const void* key)
{
    const picoquic_connection_id_t* cid = (const picoquic_connection_id_t*)key;
    return picoquic_connection_id_hash(cid);
}

static int picoquic_cid_compare(const void* key0, const void* key1)
{
    const picoquic_connection_id_t* cid0 = (const picoquic_connection_id_t*)key0;
    const picoquic_connection_id_t* cid1 = (const picoquic_connection_id_t*)key1;

    return picoquic_compare_connection_id(cid0, cid1);
}

picohash_table * cidset_create()
{
    return picohash_create(32, picoquic_cid_hash, picoquic_cid_compare);
}

picohash_table * cidset_delete(picohash_table * cids)
{
    picohash_delete(cids, 1);
    return NULL;
}

int cidset_insert(picohash_table* cids, const picoquic_connection_id_t * cid)
{
    int ret = 0;

    const picohash_item * item = picohash_retrieve(cids, cid);
    if (item == NULL) {
        picoquic_connection_id_t * key = (picoquic_connection_id_t*)malloc(sizeof(picoquic_connection_id_t));
        if (key == NULL) {
            ret = -1;
        } else {
            *key = *cid;
            ret = picohash_insert(cids, key);
        }
    }

    return ret;
}

int cidset_has_cid(picohash_table * cids, const picoquic_connection_id_t * cid)
{
    return picohash_retrieve(cids, cid) != NULL;
}

int cidset_iterate(const picohash_table * cids, int(*cb)(const picoquic_connection_id_t *, void *), void * cbptr)
{
    int ret = 0;
    for (size_t i = 0; ret == 0 && i < cids->nb_bin; i++) {
        for (picohash_item* item = cids->hash_bin[i]; ret == 0 && item != NULL; item = item->next_in_bin) {
            ret = cb((const picoquic_connection_id_t *)(item->key), cbptr);
        }
    }
    return ret;
}

static int print_cid(const picoquic_connection_id_t * cid, void * cbptr)
{
    FILE * f = (FILE*)cbptr;

    fprintf(f, "  <");
    for (uint8_t i = 0; i < cid->id_len; i++) {
        fprintf(f, "%02x", cid->id[i]);
    }
    fprintf(f, ">\n");
    return 0;
}

void cidset_print(FILE * f, picohash_table * cids)
{
    cidset_iterate(cids, print_cid, f);
}
