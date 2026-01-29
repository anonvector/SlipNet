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
 * Basic hash implementation, like we have seen tons off already.
 */
#include "picohash.h"
#include <stdlib.h>
#include <string.h>

picohash_table* picohash_create_ex(size_t nb_bin,
    uint64_t (*picohash_hash)(const void*),
    int (*picohash_compare)(const void*, const void*),
    picohash_item * (*picohash_key_to_item)(const void*))
{
    picohash_table* t = (picohash_table*)malloc(sizeof(picohash_table));
    size_t items_length = sizeof(picohash_item*) * nb_bin;
    t->hash_bin = NULL;
    if (t != NULL && (items_length / sizeof(picohash_item*)) == nb_bin) {
        t->hash_bin = (picohash_item**)malloc(sizeof(picohash_item*) * nb_bin);
    }

    if (t->hash_bin == NULL) {
        free(t);
        t = NULL;
    } else {
        (void)memset(t->hash_bin, 0, sizeof(picohash_item*) * nb_bin);
        t->nb_bin = nb_bin;
        t->count = 0;
        t->picohash_hash = picohash_hash;
        t->picohash_compare = picohash_compare;
        t->picohash_key_to_item = picohash_key_to_item;
    }

    return t;
}

picohash_table* picohash_create(size_t nb_bin,
    uint64_t(*picohash_hash)(const void*),
    int (*picohash_compare)(const void*, const void*))
{
    return picohash_create_ex(nb_bin, picohash_hash, picohash_compare, NULL);
}

picohash_item* picohash_retrieve(picohash_table* hash_table, const void* key)
{
    uint64_t hash = hash_table->picohash_hash(key);
    uint32_t bin = (uint32_t)(hash % hash_table->nb_bin);
    picohash_item* item = hash_table->hash_bin[bin];

    while (item != NULL) {
        if (hash_table->picohash_compare(key, item->key) == 0) {
            break;
        } else {
            item = item->next_in_bin;
        }
    }

    return item;
}

int picohash_insert(picohash_table* hash_table, const void* key)
{
    uint64_t hash = hash_table->picohash_hash(key);
    uint32_t bin = (uint32_t)(hash % hash_table->nb_bin);
    int ret = 0;
    picohash_item* item;
    
    if (hash_table->picohash_key_to_item == NULL) {
        item = (picohash_item*)malloc(sizeof(picohash_item));
    }
    else {
        item = hash_table->picohash_key_to_item(key);
    }

    if (item == NULL) {
        ret = -1;
    } else {
        item->hash = hash;
        item->key = key;
        item->next_in_bin = hash_table->hash_bin[bin];
        hash_table->hash_bin[bin] = item;
        hash_table->count++;
    }

    return ret;
}

void picohash_delete_item(picohash_table* hash_table, picohash_item* item, int delete_key_too)
{
    uint32_t bin = (uint32_t)(item->hash % hash_table->nb_bin);
    picohash_item* previous = hash_table->hash_bin[bin];
    const void* shall_delete = NULL;

    if (previous == item) {
        hash_table->hash_bin[bin] = item->next_in_bin;
        hash_table->count--;
    } else {
        while (previous != NULL) {
            if (previous->next_in_bin == item) {
                previous->next_in_bin = item->next_in_bin;
                hash_table->count--;
                break;
            } else {
                previous = previous->next_in_bin;
            }
        }
    }

    shall_delete = item->key;

    if (hash_table->picohash_key_to_item == NULL) {
        free(item);
    }

    if (delete_key_too) {
        free((void*)shall_delete);
    }
}

void picohash_delete_key(picohash_table* hash_table, void* key, int delete_key_too)
{
    picohash_item* item = picohash_retrieve(hash_table, key);

    if (item != NULL) {
        picohash_delete_item(hash_table, item, delete_key_too);
    }
    else if (delete_key_too) {
        free(key);
    }
}

void picohash_delete(picohash_table* hash_table, int delete_key_too)
{
    for (uint32_t i = 0; i < hash_table->nb_bin; i++) {
        picohash_item* item = hash_table->hash_bin[i];
        while (item != NULL) {
            picohash_item* tmp = item;
            const void* key_to_delete = tmp->key;

            item = item->next_in_bin;

            if (hash_table->picohash_key_to_item == NULL) {
                free(tmp);
            }
            if (delete_key_too) {
                free((void*)key_to_delete);
            }
        }
    }

    free(hash_table->hash_bin);
    free(hash_table);
}

uint64_t picohash_hash_mix(uint64_t hash, uint64_t h2)
{
    h2 ^= (hash << 17) ^ (hash >> 37);
    hash ^= ((h2 << 31) ^ (h2 >> 17));

    return hash;
}

uint64_t picohash_bytes(const uint8_t* key, uint32_t length)
{
    uint64_t hash = 0xDEADBEEF;

    for (uint32_t i = 0; i < length; i++) {
        hash ^= key[i];
        hash ^= ((hash << 31) ^ (hash >> 17));
    }

    return hash;
}

