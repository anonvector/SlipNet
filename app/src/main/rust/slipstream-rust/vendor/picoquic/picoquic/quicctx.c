
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

#include "picoquic.h"
#include "picoquic_internal.h"
#include "picoquic_utils.h"
#include "picoquic_unified_log.h"
#include "tls_api.h"
#include <stdlib.h>
#include <string.h>
#ifndef _WINDOWS
#include <sys/time.h>
#include <time.h>
#include <errno.h>
#endif


/*
 * Supported versions. Specific versions may mandate different processing of different
 * formats.
 * The first version in the list is the preferred version.
 * The protection of clear text packets will be a function of the version negotiation.
 */

static uint8_t picoquic_cleartext_internal_test_1_salt[] = {
    0x30, 0x67, 0x16, 0xd7, 0x63, 0x75, 0xd5, 0x55,
    0x4b, 0x2f, 0x60, 0x5e, 0xef, 0x78, 0xd8, 0x33,
    0x3d, 0xc1, 0xca, 0x36
};

static uint8_t picoquic_cleartext_draft_23_salt[] = {
    0xc3, 0xee, 0xf7, 0x12, 0xc7, 0x2e, 0xbb, 0x5a,
    0x11, 0xa7, 0xd2, 0x43, 0x2b, 0xb4, 0x63, 0x65,
    0xbe, 0xf9, 0xf5, 0x02
};

uint8_t picoquic_retry_protection_key_25[32] = {
    0x65, 0x6e, 0x61, 0xe3, 0x36, 0xae, 0x94, 0x17, 0xf7, 0xf0, 0xed, 0xd8, 0xd7, 0x8d, 0x46, 0x1e,
    0x2a, 0xa7, 0x08, 0x4a, 0xba, 0x7a, 0x14, 0xc1, 0xe9, 0xf7, 0x26, 0xd5, 0x57, 0x09, 0x16, 0x9a };

static uint8_t picoquic_cleartext_draft_29_salt[] = {
    0xaf, 0xbf, 0xec, 0x28, 0x99, 0x93, 0xd2, 0x4c,
    0x9e, 0x97, 0x86, 0xf1, 0x9c, 0x61, 0x11, 0xe0,
    0x43, 0x90, 0xa8, 0x99
};

uint8_t picoquic_retry_protection_key_29[32] = {
    0x8b, 0x0d, 0x37, 0xeb, 0x85, 0x35, 0x02, 0x2e, 0xbc, 0x8d, 0x76, 0xa2, 0x07, 0xd8, 0x0d, 0xf2,
    0x26, 0x46, 0xec, 0x06, 0xdc, 0x80, 0x96, 0x42, 0xc3, 0x0a, 0x8b, 0xaa, 0x2b, 0xaa, 0xff, 0x4c };

static uint8_t picoquic_cleartext_v1_salt[] = {
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3,
    0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a
};

uint8_t picoquic_retry_protection_v1[32] = {
    0xd9, 0xc9, 0x94, 0x3e, 0x61, 0x01, 0xfd, 0x20, 0x00, 0x21, 0x50, 0x6b, 0xcc, 0x02, 0x81, 0x4c,
    0x73, 0x03, 0x0f, 0x25, 0xc7, 0x9d, 0x71, 0xce, 0x87, 0x6e, 0xca, 0x87, 0x6e, 0x6f, 0xca, 0x8e
};

static uint8_t picoquic_cleartext_v2_salt[] = {
    0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb,
    0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb,
    0xf9, 0xbd, 0x2e, 0xd9
};

uint8_t picoquic_retry_protection_v2[32] = {
    0xc4, 0xdd, 0x24, 0x84, 0xd6, 0x81, 0xae, 0xfa,
    0x4f, 0xf4, 0xd6, 0x9c, 0x2c, 0x20, 0x29, 0x99,
    0x84, 0xa7, 0x65, 0xa5, 0xd3, 0xc3, 0x19, 0x82,
    0xf3, 0x8f, 0xc7, 0x41, 0x62, 0x15, 0x5e, 0x9f
};

/* In this version, we still provide support for the QUIC V2 draft, whose
 * codepoint is still declared as "provisional" in the IESG approved draft */

static uint8_t picoquic_cleartext_v2_draft_salt[] = {
    0xa7, 0x07, 0xc2, 0x03, 0xa5, 0x9b, 0x47, 0x18,
    0x4a, 0x1d, 0x62, 0xca, 0x57, 0x04, 0x06, 0xea,
    0x7a, 0xe3, 0xe5, 0xd3
};

uint8_t picoquic_retry_protection_v2_draft[32] = {
    0x34, 0x25, 0xc2, 0x0c, 0xf8, 0x87, 0x79, 0xdf,
    0x2f, 0xf7, 0x1e, 0x8a, 0xbf, 0xa7, 0x82, 0x49,
    0x89, 0x1e, 0x76, 0x3b, 0xbe, 0xd2, 0xf1, 0x3c,
    0x04, 0x83, 0x43, 0xd3, 0x48, 0xc0, 0x60, 0xe2
};

/* The update from field is populated with a zero terminated
 * array of version numbers from which update to the specified
 * version is allowed.
 */

uint32_t picoquic_version_upgrade_from_v1[] = { PICOQUIC_V1_VERSION, 0 };

/* The table of supported version is used for version negotiation,
 * and for documenting version specific parameters.
 */

const picoquic_version_parameters_t picoquic_supported_versions[] = {
    { PICOQUIC_V1_VERSION,
        sizeof(picoquic_cleartext_v1_salt),
        picoquic_cleartext_v1_salt,
        sizeof(picoquic_retry_protection_v1),
        picoquic_retry_protection_v1,
        PICOQUIC_LABEL_QUIC_V1_KEY_BASE,
        PICOQUIC_LABEL_V1_TRAFFIC_UPDATE,
        PICOQUIC_V1_VERSION,
        NULL },
    { PICOQUIC_V2_VERSION,
        sizeof(picoquic_cleartext_v2_salt),
        picoquic_cleartext_v2_salt,
        sizeof(picoquic_retry_protection_v2),
        picoquic_retry_protection_v2,
        PICOQUIC_LABEL_QUIC_V2_KEY_BASE,
        PICOQUIC_LABEL_V2_TRAFFIC_UPDATE,
        PICOQUIC_V2_VERSION,
        picoquic_version_upgrade_from_v1 },
    { PICOQUIC_V2_VERSION_DRAFT,
        sizeof(picoquic_cleartext_v2_draft_salt),
        picoquic_cleartext_v2_draft_salt,
        sizeof(picoquic_retry_protection_v2_draft),
        picoquic_retry_protection_v2_draft,
        PICOQUIC_LABEL_QUIC_V2_KEY_BASE,
        PICOQUIC_LABEL_V2_TRAFFIC_UPDATE,
        PICOQUIC_V2_VERSION,
        picoquic_version_upgrade_from_v1 },
    { PICOQUIC_POST_IESG_VERSION,
        sizeof(picoquic_cleartext_v1_salt),
        picoquic_cleartext_v1_salt,
        sizeof(picoquic_retry_protection_v1),
        picoquic_retry_protection_v1,
        PICOQUIC_LABEL_QUIC_V1_KEY_BASE,
        PICOQUIC_LABEL_V1_TRAFFIC_UPDATE,
        PICOQUIC_V1_VERSION,
        NULL },
    { PICOQUIC_TWENTYFIRST_INTEROP_VERSION,
        sizeof(picoquic_cleartext_v1_salt),
        picoquic_cleartext_v1_salt,
        sizeof(picoquic_retry_protection_v1),
        picoquic_retry_protection_v1,
        PICOQUIC_LABEL_QUIC_V1_KEY_BASE,
        PICOQUIC_LABEL_V1_TRAFFIC_UPDATE,
        PICOQUIC_V1_VERSION,
        NULL },
    { PICOQUIC_TWENTIETH_INTEROP_VERSION,
        sizeof(picoquic_cleartext_draft_29_salt),
        picoquic_cleartext_draft_29_salt,
        sizeof(picoquic_retry_protection_key_29),
        picoquic_retry_protection_key_29,
        PICOQUIC_LABEL_QUIC_V1_KEY_BASE,
        PICOQUIC_LABEL_V1_TRAFFIC_UPDATE,
        PICOQUIC_V1_VERSION,
        NULL },
    { PICOQUIC_TWENTIETH_PRE_INTEROP_VERSION,
        sizeof(picoquic_cleartext_draft_29_salt),
        picoquic_cleartext_draft_29_salt,
        sizeof(picoquic_retry_protection_key_29),
        picoquic_retry_protection_key_29,
        PICOQUIC_LABEL_QUIC_V1_KEY_BASE,
        PICOQUIC_LABEL_V1_TRAFFIC_UPDATE,
        PICOQUIC_V1_VERSION,
        NULL },
    { PICOQUIC_NINETEENTH_INTEROP_VERSION,
        sizeof(picoquic_cleartext_draft_29_salt),
        picoquic_cleartext_draft_29_salt,
        sizeof(picoquic_retry_protection_key_29),
        picoquic_retry_protection_key_29,
        PICOQUIC_LABEL_QUIC_V1_KEY_BASE,
        PICOQUIC_LABEL_V1_TRAFFIC_UPDATE,
        PICOQUIC_V1_VERSION,
        NULL },
    { PICOQUIC_NINETEENTH_BIS_INTEROP_VERSION,
        sizeof(picoquic_cleartext_draft_29_salt),
        picoquic_cleartext_draft_29_salt,
        sizeof(picoquic_retry_protection_key_29),
        picoquic_retry_protection_key_29,
        PICOQUIC_LABEL_QUIC_V1_KEY_BASE,
        PICOQUIC_LABEL_V1_TRAFFIC_UPDATE,
        PICOQUIC_V1_VERSION,
        NULL },
    { PICOQUIC_EIGHTEENTH_INTEROP_VERSION,
        sizeof(picoquic_cleartext_draft_23_salt),
        picoquic_cleartext_draft_23_salt,
        sizeof(picoquic_retry_protection_key_25),
        picoquic_retry_protection_key_25,
        PICOQUIC_LABEL_QUIC_V1_KEY_BASE,
        PICOQUIC_LABEL_V1_TRAFFIC_UPDATE,
        PICOQUIC_V1_VERSION,
        NULL },
    { PICOQUIC_SEVENTEENTH_INTEROP_VERSION,
        sizeof(picoquic_cleartext_draft_23_salt),
        picoquic_cleartext_draft_23_salt,
        sizeof(picoquic_retry_protection_key_25),
        picoquic_retry_protection_key_25,
        PICOQUIC_LABEL_QUIC_V1_KEY_BASE,
        PICOQUIC_LABEL_V1_TRAFFIC_UPDATE,
        PICOQUIC_V1_VERSION,
        NULL },
    { PICOQUIC_INTERNAL_TEST_VERSION_2,
        sizeof(picoquic_cleartext_internal_test_1_salt),
        picoquic_cleartext_internal_test_1_salt,
        sizeof(picoquic_retry_protection_key_25),
        picoquic_retry_protection_key_25,
        PICOQUIC_LABEL_QUIC_V1_KEY_BASE,
        PICOQUIC_LABEL_V1_TRAFFIC_UPDATE,
        PICOQUIC_V1_VERSION,
        NULL },
    { PICOQUIC_INTERNAL_TEST_VERSION_1,
        sizeof(picoquic_cleartext_internal_test_1_salt),
        picoquic_cleartext_internal_test_1_salt,
        sizeof(picoquic_retry_protection_key_25),
        picoquic_retry_protection_key_25,
        PICOQUIC_LABEL_QUIC_V1_KEY_BASE,
        PICOQUIC_LABEL_V1_TRAFFIC_UPDATE,
        PICOQUIC_V1_VERSION,
        NULL },
};

const size_t picoquic_nb_supported_versions = sizeof(picoquic_supported_versions) / sizeof(picoquic_version_parameters_t);

/*
* Structures used in the hash table of connections
*/

typedef struct st_picoquic_net_id_key_t {
    struct sockaddr_storage saddr;
    picoquic_cnx_t* cnx;
    picoquic_path_t* path;
    struct st_picoquic_net_id_key_t* next_net_id;
} picoquic_net_id_key_t;

typedef struct st_picoquic_net_secret_key_t {
    struct sockaddr_storage saddr;
    uint8_t reset_secret[PICOQUIC_RESET_SECRET_SIZE];
    picoquic_cnx_t* cnx;
} picoquic_net_secret_key_t;

/* Hash and compare for CNX hash tables */
static uint64_t picoquic_local_cnxid_hash(const void* key)
{
    const picoquic_local_cnxid_t* l_cid = (const picoquic_local_cnxid_t*)key;
    return picoquic_connection_id_hash(&l_cid->cnx_id);
}

static int picoquic_local_cnxid_compare(const void* key1, const void* key2)
{
    const picoquic_local_cnxid_t* l_cid1 = (const picoquic_local_cnxid_t*)key1;
    const picoquic_local_cnxid_t* l_cid2 = (const picoquic_local_cnxid_t*)key2;

    return picoquic_compare_connection_id(&l_cid1->cnx_id, &l_cid2->cnx_id);
}

static picohash_item * picoquic_local_cnxid_to_item(const void* key)
{
    picoquic_local_cnxid_t* l_cid = (picoquic_local_cnxid_t*)key;

    return &l_cid->hash_item;
}

static uint64_t picoquic_net_id_hash(const void* key)
{
    const picoquic_path_t* path_x = (const picoquic_path_t*)key;

    // return picohash_bytes((uint8_t*)&net->saddr, sizeof(net->saddr));
    return picoquic_hash_addr((struct sockaddr*) & path_x->registered_peer_addr);
}

static picohash_item * picoquic_local_netid_to_item(const void* key)
{
    picoquic_path_t* path_x = (picoquic_path_t*)key;

    return &path_x->net_id_hash_item;
}


static int picoquic_net_id_compare(const void* key1, const void* key2)
{
    const picoquic_path_t* path_x1 = (const picoquic_path_t*)key1;
    const picoquic_path_t* path_x2 = (const picoquic_path_t*)key2;

    return picoquic_compare_addr((struct sockaddr*) & path_x1->registered_peer_addr, (struct sockaddr*) & path_x2->registered_peer_addr);
}



static uint64_t picoquic_net_icid_hash(const void* key)
{
    const picoquic_cnx_t* cnx = (const picoquic_cnx_t*)key;

    return picohash_hash_mix(picoquic_hash_addr((struct sockaddr*) & cnx->registered_icid_addr), 
        picoquic_connection_id_hash(&cnx->initial_cnxid));
}

static int picoquic_net_icid_compare(const void* key1, const void* key2)
{
    const picoquic_cnx_t* cnx1 = (const picoquic_cnx_t*)key1;
    const picoquic_cnx_t* cnx2 = (const picoquic_cnx_t*)key2;
    int ret = picoquic_compare_addr((struct sockaddr*) & cnx1->registered_icid_addr, (struct sockaddr*) & cnx2->registered_icid_addr);
    if (ret == 0) {
        ret = picoquic_compare_connection_id(&cnx1->initial_cnxid, &cnx2->initial_cnxid);
    }

    return ret;
}

static picohash_item * picoquic_net_icid_to_item(const void* key)
{
    picoquic_cnx_t* cnx = (picoquic_cnx_t*)key;

    return &cnx->registered_icid_item;
}

static uint64_t picoquic_net_secret_hash(const void* key)
{
    const picoquic_cnx_t* cnx = (const picoquic_cnx_t*)key;

    return picohash_hash_mix(picoquic_hash_addr((struct sockaddr*) & cnx->registered_secret_addr), 
        picohash_bytes(cnx->registered_reset_secret, PICOQUIC_RESET_SECRET_SIZE));
}

static int picoquic_net_secret_compare(const void* key1, const void* key2)
{
    const picoquic_cnx_t* cnx1 = (const picoquic_cnx_t*)key1;
    const picoquic_cnx_t* cnx2 = (const picoquic_cnx_t*)key2;
    int ret = picoquic_compare_addr((struct sockaddr*) & cnx1->registered_secret_addr, (struct sockaddr*) & cnx2->registered_secret_addr);

    if (ret == 0) {
#ifdef PICOQUIC_USE_CONSTANT_TIME_MEMCMP
        ret = picoquic_constant_time_memcmp(cnx1->registered_reset_secret, cnx2->registered_reset_secret, PICOQUIC_RESET_SECRET_SIZE);
#else
        ret = memcmp(cnx1->registered_reset_secret, cnx2->registered_reset_secret, PICOQUIC_RESET_SECRET_SIZE);
#endif
    }
    return ret;
}

static picohash_item * picoquic_net_secret_to_item(const void* key)
{
    picoquic_cnx_t* cnx = (picoquic_cnx_t*)key;

    return &cnx->registered_reset_secret_item;
}

picoquic_packet_context_enum picoquic_context_from_epoch(int epoch)
{
    static picoquic_packet_context_enum const pc[4] = {
        picoquic_packet_context_initial,
        picoquic_packet_context_application,
        picoquic_packet_context_handshake,
        picoquic_packet_context_application
    };

    return (epoch >= 0 && epoch < 4) ? pc[epoch] : 0;
}

/* Management of issued tickets.
 * For each issued ticket, we create a ticket key:
 * - ticket id
 * - properties
 * The tickets are accessible through a hash table, keyed by ticket ID.
 * They are also organized as an LRU list, with a max number set by default
 * to the number of connections.
 */

static uint64_t picoquic_issued_ticket_hash(const void* key)
{
    const picoquic_issued_ticket_t* ticket_key = (const picoquic_issued_ticket_t*)key;

    return ticket_key->ticket_id;
}

static int picoquic_issued_ticket_compare(const void* key1, const void* key2)
{
    const picoquic_issued_ticket_t* ticket_key1 = (const picoquic_issued_ticket_t*)key1;
    const picoquic_issued_ticket_t* ticket_key2 = (const picoquic_issued_ticket_t*)key2;
    int ret = (ticket_key1->ticket_id == ticket_key2->ticket_id)?0:1;

    return ret;
}

picohash_item* picoquic_issued_ticket_key_to_item(const void* key)
{
    picoquic_issued_ticket_t* ticket_key = (picoquic_issued_ticket_t*)key;

    return &ticket_key->hash_item;
}

picoquic_issued_ticket_t* picoquic_retrieve_issued_ticket(picoquic_quic_t* quic,
    uint64_t ticket_id)
{
    picoquic_issued_ticket_t* ret = NULL;
    picohash_item* item;
    picoquic_issued_ticket_t key;

    memset(&key, 0, sizeof(key));
    key.ticket_id = ticket_id;

    item = picohash_retrieve(quic->table_issued_tickets, &key);

    if (item != NULL) {
        ret = (picoquic_issued_ticket_t*)item->key;
    }
    return ret;
}

static void picoquic_update_issued_ticket(
    picoquic_issued_ticket_t* ticket,
    uint64_t rtt,
    uint64_t cwin,
    const uint8_t* ip_addr,
    uint8_t ip_addr_length)
{
    /* Update in place */
    if (ip_addr_length > PICOQUIC_STORED_IP_MAX) {
        ip_addr_length = PICOQUIC_STORED_IP_MAX;
    }
    ticket->ip_addr_length = ip_addr_length;
    memcpy(ticket->ip_addr, ip_addr, ip_addr_length);
    ticket->rtt = rtt;
    ticket->cwin = cwin;
}

static void picoquic_delete_issued_ticket(picoquic_quic_t* quic, picoquic_issued_ticket_t* ticket)
{
    /* Update the linked list */
    if (ticket->next_ticket == NULL) {
        quic->table_issued_tickets_last = ticket->previous_ticket;
    }
    else {
        ticket->next_ticket->previous_ticket = ticket->previous_ticket;
    }

    if (ticket->previous_ticket == NULL) {
        quic->table_issued_tickets_first = ticket->next_ticket;
    }
    else {
        ticket->previous_ticket->next_ticket = ticket->next_ticket;
    }

    picohash_delete_key(quic->table_issued_tickets, ticket, 1);

    if (quic->table_issued_tickets_nb > 0) {
        quic->table_issued_tickets_nb--;
    }
}

int picoquic_remember_issued_ticket(picoquic_quic_t* quic,
    uint64_t ticket_id,
    uint64_t rtt,
    uint64_t cwin,
    const uint8_t* ip_addr,
    uint8_t ip_addr_length)
{
    int ret = 0;

    picoquic_issued_ticket_t* ticket = picoquic_retrieve_issued_ticket(quic,
        ticket_id);
    if (ticket != NULL) {
        picoquic_update_issued_ticket(ticket, rtt, cwin, ip_addr, ip_addr_length);
    }
    else {
        while (quic->table_issued_tickets_nb > quic->max_number_connections) {
            picoquic_delete_issued_ticket(quic, quic->table_issued_tickets_last);
        }
        ticket = (picoquic_issued_ticket_t*)malloc(sizeof(picoquic_issued_ticket_t));
        if (ticket != NULL) {
            memset(ticket, 0, sizeof(picoquic_issued_ticket_t));
            ticket->ticket_id = ticket_id;
            picoquic_update_issued_ticket(ticket, rtt, cwin, ip_addr, ip_addr_length);
            ticket->next_ticket = quic->table_issued_tickets_first;
            quic->table_issued_tickets_first = ticket;
            if (ticket->next_ticket == NULL) {
                quic->table_issued_tickets_last = ticket;
            }
            else {
                ticket->next_ticket->previous_ticket = ticket;
            }
            picohash_insert(quic->table_issued_tickets, ticket);
        }
        else {
            ret = PICOQUIC_ERROR_MEMORY;
        }
    }

    return ret;
}

/* Token reuse management */

static int64_t picoquic_registered_token_compare(void* l, void* r)
{
    /* STream values are from 0 to 2^62-1, which means we are not worried with rollover */
    picoquic_registered_token_t* rt_l = (picoquic_registered_token_t*)l;
    picoquic_registered_token_t* rt_r = (picoquic_registered_token_t*)r;
    int64_t ret = 0;
    if (rt_l->token_time == rt_r->token_time) {
        if (rt_l->token_hash > rt_r->token_hash) {
            ret = 1;
        }
        else if (rt_l->token_hash < rt_r->token_hash) {
            ret = -1;
        }
    }
    else if (rt_l->token_time > rt_r->token_time) {
        ret = 1;
    }
    else {
        ret = -1;
    }
    return ret;
}

static picosplay_node_t* picoquic_registered_token_create(void* value)
{
    return &((picoquic_registered_token_t*)value)->registered_token_node;
}


static void* picoquic_registered_token_value(picosplay_node_t* node)
{
    return (void*)((node == NULL)?NULL:((char*)node - offsetof(struct st_picoquic_registered_token_t, registered_token_node)));
}

static void picoquic_registered_token_delete(void* tree, picosplay_node_t* node)
{
    picoquic_registered_token_t* rt = (picoquic_registered_token_t*)picoquic_registered_token_value(node);
    free(rt);
}

int picoquic_registered_token_check_reuse(picoquic_quic_t * quic,
    const uint8_t * token, size_t token_length, uint64_t expiry_time)
{
    int ret = -1;
    if (token_length >= 8) {
        picoquic_registered_token_t* rt = (picoquic_registered_token_t*)malloc(sizeof(picoquic_registered_token_t));
        if (rt != NULL) {
            picosplay_node_t* rt_n = NULL;
            memset(rt, 0, sizeof(picoquic_registered_token_t));
            rt->token_time = expiry_time;
            rt->token_hash = PICOPARSE_64(token + token_length - 8);
            rt->count = 1;
            rt_n = picosplay_find(&quic->token_reuse_tree, rt);
            if (rt_n != NULL) {
                free(rt);
                rt = (picoquic_registered_token_t*)picoquic_registered_token_value(rt_n);
                rt->count++;
                DBG_PRINTF("Token reuse detected, count=%d", rt->count);
            }
            else {
                (void)picosplay_insert(&quic->token_reuse_tree, rt);
                ret = 0;
            }
        }
    }

    return ret;
}

void picoquic_registered_token_clear(picoquic_quic_t* quic, uint64_t expiry_time_max)
{
    int end_reached = 0;
    do {
        picoquic_registered_token_t* rt_first = (picoquic_registered_token_t*)
            picoquic_registered_token_value(picosplay_first(&quic->token_reuse_tree));
        if (rt_first == NULL || rt_first->token_time >= expiry_time_max) {
            end_reached = 1;
        }
        else {
            picosplay_delete_hint(&quic->token_reuse_tree, &rt_first->registered_token_node);
        }
    } while (!end_reached);
}

int picoquic_adjust_max_connections(picoquic_quic_t * quic, uint32_t max_nb_connections)
{
    if (max_nb_connections <= quic->max_number_connections) {
        quic->tentative_max_number_connections = max_nb_connections;
        return 0;
    }

    return -1;
}

uint32_t picoquic_current_number_connections(picoquic_quic_t * quic)
{
    return quic->current_number_connections;
}

/* Forward reference */
static void picoquic_wake_list_init(picoquic_quic_t* quic);

/* QUIC context create and dispose */
picoquic_quic_t* picoquic_create(uint32_t max_nb_connections,
    char const* cert_file_name,
    char const* key_file_name, 
    char const * cert_root_file_name,
    char const* default_alpn,
    picoquic_stream_data_cb_fn default_callback_fn,
    void* default_callback_ctx,
    picoquic_connection_id_cb_fn cnx_id_callback,
    void* cnx_id_callback_ctx,
    uint8_t reset_seed[PICOQUIC_RESET_SECRET_SIZE],
    uint64_t current_time,
    uint64_t* p_simulated_time,
    char const* ticket_file_name,
    const uint8_t* ticket_encryption_key,
    size_t ticket_encryption_key_length)
{
    picoquic_quic_t* quic = (picoquic_quic_t*)malloc(sizeof(picoquic_quic_t));
    int ret = 0;

    if (quic != NULL) {
        /* TODO: winsock init */
        /* TODO: open UDP sockets - maybe */
        memset(quic, 0, sizeof(picoquic_quic_t));

        quic->default_callback_fn = default_callback_fn;
        quic->default_callback_ctx = default_callback_ctx;
        quic->default_congestion_alg = PICOQUIC_DEFAULT_CONGESTION_ALGORITHM;
        quic->default_alpn = picoquic_string_duplicate(default_alpn);
        quic->cnx_id_callback_fn = cnx_id_callback;
        quic->cnx_id_callback_ctx = cnx_id_callback_ctx;
        quic->p_simulated_time = p_simulated_time;
        quic->local_cnxid_length = 8; /* TODO: should be lower on clients-only implementation */
        quic->padding_multiple_default = 0; /* TODO: consider default = 128 */
        quic->padding_minsize_default = PICOQUIC_RESET_PACKET_MIN_SIZE;
        quic->crypto_epoch_length_max = 0;
        quic->max_simultaneous_logs = PICOQUIC_DEFAULT_SIMULTANEOUS_LOGS;
        quic->max_half_open_before_retry = PICOQUIC_DEFAULT_HALF_OPEN_RETRY_THRESHOLD;
        quic->default_lossbit_policy = 0; /* For compatibility with old behavior. Consider 0 */
        quic->local_cnxid_ttl = UINT64_MAX;
        quic->stateless_reset_next_time = current_time;
        quic->stateless_reset_min_interval = PICOQUIC_MICROSEC_STATELESS_RESET_INTERVAL_DEFAULT;
        quic->default_stream_priority = PICOQUIC_DEFAULT_STREAM_PRIORITY;
        quic->default_datagram_priority = PICOQUIC_DEFAULT_STREAM_PRIORITY;
        quic->cwin_max = UINT64_MAX;
        quic->sequence_hole_pseudo_period = PICOQUIC_DEFAULT_HOLE_PERIOD;

        picoquic_init_transport_parameters(&quic->default_tp, 0);

        quic->random_initial = 1;
        picoquic_wake_list_init(quic);

        if (cnx_id_callback != NULL) {
            quic->unconditional_cnx_id = 1;
        }
        if (ticket_file_name != NULL) {
            quic->ticket_file_name = ticket_file_name;
        }

        if (ret == 0) {
            size_t max_cnx4 = 0;
            if (max_nb_connections == 0) {
                max_nb_connections = 1;
            }

            quic->tentative_max_number_connections = max_nb_connections;
            quic->max_number_connections = max_nb_connections;
            max_cnx4 = 4 * (size_t)max_nb_connections;



            if (max_cnx4 < (size_t)max_nb_connections ||
                (quic->table_cnx_by_id = picohash_create_ex((size_t)max_nb_connections * 4,
                picoquic_local_cnxid_hash, picoquic_local_cnxid_compare, picoquic_local_cnxid_to_item)) == NULL ||
                (quic->table_cnx_by_net = picohash_create_ex((size_t)max_nb_connections * 4,
                    picoquic_net_id_hash, picoquic_net_id_compare, picoquic_local_netid_to_item)) == NULL ||
                (quic->table_cnx_by_icid = picohash_create_ex((size_t)max_nb_connections,
                    picoquic_net_icid_hash, picoquic_net_icid_compare, picoquic_net_icid_to_item)) == NULL ||
                (quic->table_cnx_by_secret = picohash_create_ex((size_t)max_nb_connections * 4,
                    picoquic_net_secret_hash, picoquic_net_secret_compare, picoquic_net_secret_to_item)) == NULL ||
                (quic->table_issued_tickets = picohash_create_ex((size_t)max_nb_connections,
                    picoquic_issued_ticket_hash, picoquic_issued_ticket_compare, picoquic_issued_ticket_key_to_item)) == NULL) {
                ret = -1;
                DBG_PRINTF("%s", "Cannot initialize hash tables\n");
            }
            else {
                picosplay_init_tree(&quic->token_reuse_tree, picoquic_registered_token_compare,
                    picoquic_registered_token_create, picoquic_registered_token_delete, picoquic_registered_token_value);
                if (picoquic_master_tlscontext(quic, cert_file_name, key_file_name, cert_root_file_name, ticket_encryption_key, ticket_encryption_key_length) != 0) {
                    ret = -1;
                    DBG_PRINTF("%s", "Cannot create TLS context \n");
                }
                else {
                    /* In the absence of certificate or key, we assume that this is a client only context */
                    quic->enforce_client_only = (cert_file_name == NULL || key_file_name == NULL);
                    /* the random generator was initialized as part of the TLS context.
                     * Use it to create the seed for generating the per context stateless
                     * resets and the retry tokens */

                    if (!reset_seed)
                        picoquic_crypto_random(quic, quic->reset_seed, sizeof(quic->reset_seed));
                    else
                        memcpy(quic->reset_seed, reset_seed, sizeof(quic->reset_seed));

                    picoquic_crypto_random(quic, quic->retry_seed, sizeof(quic->retry_seed));

                    /* If there is no root certificate context specified, use a null certifier. */
                    /* Load tickets */
                    if (quic->ticket_file_name != NULL) {
                        ret = picoquic_load_tickets(quic, ticket_file_name);

                        if (ret == PICOQUIC_ERROR_NO_SUCH_FILE) {
                            DBG_PRINTF("Ticket file <%s> not created yet.\n", ticket_file_name);
                            ret = 0;
                        }
                        else if (ret != 0) {
                            DBG_PRINTF("Cannot load tickets from <%s>\n", ticket_file_name);
                            ret = 0;
                        }
                    }
                }
            }
        }
#ifdef BBRExperiment
        if (ret == 0) {
            quic->bbr_exp_flags.do_early_exit = 1;
            quic->bbr_exp_flags.do_rapid_start = 1;
            quic->bbr_exp_flags.do_handle_suspension = 1;
            quic->bbr_exp_flags.do_control_lost = 1;
            quic->bbr_exp_flags.do_exit_probeBW_up_on_delay = 1;
            quic->bbr_exp_flags.do_enter_probeBW_after_limited = 1;
        }
#endif

        if (ret != 0) {
            picoquic_free(quic);
            quic = NULL;
        }
    }

    return quic;
}

int picoquic_load_token_file(picoquic_quic_t* quic, char const * token_file_name)
{
    int ret = picoquic_load_tokens(quic, token_file_name);

    if (ret == PICOQUIC_ERROR_NO_SUCH_FILE) {
        DBG_PRINTF("Ticket file <%s> not created yet.\n", token_file_name);
        ret = 0;
    }
    else if (ret != 0) {
        DBG_PRINTF("Cannot load tickets from <%s>\n", token_file_name);
    }

    if (ret == 0) {
        quic->token_file_name = token_file_name;
    }

    return ret;
}

int picoquic_set_default_tp(picoquic_quic_t* quic, picoquic_tp_t * tp)
{
    int ret = 0;

    if (tp == NULL) {
        picoquic_init_transport_parameters(&quic->default_tp, 0);
    }
    else {
        memcpy(&quic->default_tp, tp, sizeof(picoquic_tp_t));
    }

    return ret;
}

picoquic_tp_t const* picoquic_get_default_tp(picoquic_quic_t* quic)
{
    return &quic->default_tp;
}

void picoquic_set_default_padding(picoquic_quic_t* quic, uint32_t padding_multiple, uint32_t padding_minsize)
{
    quic->padding_minsize_default = padding_minsize;
    quic->padding_multiple_default = padding_multiple;
}

int picoquic_set_default_spinbit_policy(picoquic_quic_t * quic, picoquic_spinbit_version_enum default_spinbit_policy)
{
    int ret = 0;

    if (default_spinbit_policy <= picoquic_spinbit_on) {
        quic->default_spin_policy = default_spinbit_policy;
    }
    else {
        ret = -1;
    }
    return ret;
}

int picoquic_set_spinbit_policy(picoquic_cnx_t* cnx, picoquic_spinbit_version_enum spinbit_policy)
{
    int ret = 0;

    if (spinbit_policy < picoquic_spinbit_on) {
        cnx->spin_policy = spinbit_policy;
    }
    else
    {
        ret = -1;
    }
    return ret;
}

void picoquic_set_default_lossbit_policy(picoquic_quic_t* quic, picoquic_lossbit_version_enum default_lossbit_policy)
{
    quic->default_lossbit_policy = default_lossbit_policy;
    quic->default_tp.enable_loss_bit = (int)default_lossbit_policy;
}

void picoquic_set_default_direct_receive_callback(picoquic_quic_t* quic,
    picoquic_stream_direct_receive_fn direct_receive_fn, void* direct_receive_ctx)
{
    quic->default_direct_receive_fn = direct_receive_fn;
    quic->default_direct_receive_ctx = direct_receive_ctx;
}

void picoquic_set_stream_data_consumption_mode(picoquic_quic_t* quic, int defer_stream_data_consumption)
{
    int enable = (defer_stream_data_consumption != 0);
    if (enable && quic->defer_stream_data_consumption == 0) {
        picoquic_cnx_t* cnx = quic->cnx_list;
        while (cnx != NULL) {
            picoquic_stream_head_t* stream = picoquic_first_stream(cnx);
            while (stream != NULL) {
                stream->delivered_offset = stream->consumed_offset;
                stream = picoquic_next_stream(stream);
            }
            for (size_t epoch = 0; epoch < PICOQUIC_NUMBER_OF_EPOCHS; epoch++) {
                cnx->tls_stream[epoch].delivered_offset = cnx->tls_stream[epoch].consumed_offset;
            }
            cnx = cnx->next_in_table;
        }
    }
    else if (!enable && quic->defer_stream_data_consumption != 0) {
        picoquic_cnx_t* cnx = quic->cnx_list;
        while (cnx != NULL) {
            picoquic_stream_head_t* stream = picoquic_first_stream(cnx);
            while (stream != NULL) {
                picoquic_stream_head_t* next_stream = picoquic_next_stream(stream);
                if (stream->delivered_offset > stream->consumed_offset) {
                    (void)picoquic_stream_data_consumed(cnx, stream->stream_id, stream->delivered_offset);
                }
                stream = next_stream;
            }
            for (size_t epoch = 0; epoch < PICOQUIC_NUMBER_OF_EPOCHS; epoch++) {
                if (cnx->tls_stream[epoch].delivered_offset > cnx->tls_stream[epoch].consumed_offset) {
                    cnx->tls_stream[epoch].consumed_offset = cnx->tls_stream[epoch].delivered_offset;
                }
            }
            cnx = cnx->next_in_table;
        }
    }
    quic->defer_stream_data_consumption = enable;
}

void picoquic_set_default_multipath_option(picoquic_quic_t* quic, int multipath_option)
{
    quic->default_multipath_option = multipath_option;

    if (multipath_option & 1) {
        quic->default_tp.is_multipath_enabled = 1;
        quic->default_tp.initial_max_path_id = 2;
    }
}

void picoquic_set_default_address_discovery_mode(picoquic_quic_t* quic, int mode)
{
    if (mode > 0 && mode <= 3) {
        quic->default_tp.address_discovery_mode = mode;
    }
    else
    {
        quic->default_tp.address_discovery_mode = 0;
    }
}

void picoquic_set_cwin_max(picoquic_quic_t* quic, uint64_t cwin_max)
{
    quic->cwin_max = (cwin_max == 0) ? UINT64_MAX : cwin_max;
}

void picoquic_set_max_data_control(picoquic_quic_t* quic, uint64_t max_data)
{
    picoquic_cnx_t* cnx = quic->cnx_list;
    quic->max_data_limit = max_data;

    quic->default_tp.initial_max_data = max_data;

    while (cnx != NULL) {
        /* If the connection is not yet initialized, reset the maxdata parameter */
        if (cnx->client_mode &&
            cnx->cnx_state == picoquic_state_client_init &&
            cnx->tls_stream[0].sent_offset == 0 &&
            cnx->tls_stream[0].send_queue == NULL){
            cnx->local_parameters.initial_max_data = max_data;
            cnx->maxdata_local = max_data;
        }
        cnx = cnx->next_in_table;
    }
}

void picoquic_set_default_idle_timeout(picoquic_quic_t* quic, uint64_t idle_timeout_ms)
{
    quic->default_tp.max_idle_timeout = idle_timeout_ms;
}

void picoquic_set_default_handshake_timeout(picoquic_quic_t* quic, uint64_t handshake_timeout_us)
{
    quic->default_handshake_timeout = handshake_timeout_us;
}

void picoquic_set_default_crypto_epoch_length(picoquic_quic_t* quic, uint64_t crypto_epoch_length_max)
{
    quic->crypto_epoch_length_max = (crypto_epoch_length_max == 0) ?
        PICOQUIC_DEFAULT_CRYPTO_EPOCH_LENGTH : crypto_epoch_length_max;
}

uint64_t picoquic_get_default_crypto_epoch_length(picoquic_quic_t* quic)
{
    return quic->crypto_epoch_length_max;
}

void picoquic_set_crypto_epoch_length(picoquic_cnx_t* cnx, uint64_t crypto_epoch_length_max)
{
    cnx->crypto_epoch_length_max = (crypto_epoch_length_max == 0) ?
        PICOQUIC_DEFAULT_CRYPTO_EPOCH_LENGTH : crypto_epoch_length_max;
}

uint64_t picoquic_get_crypto_epoch_length(picoquic_cnx_t* cnx)
{
    return cnx->crypto_epoch_length_max;
}


uint8_t picoquic_get_local_cid_length(picoquic_quic_t* quic)
{
    return quic->local_cnxid_length;
}

int picoquic_is_local_cid(picoquic_quic_t* quic, picoquic_connection_id_t* cid)
{
    return (cid->id_len == quic->local_cnxid_length &&
        picoquic_cnx_by_id(quic, *cid, NULL) != NULL);
}

void picoquic_set_max_simultaneous_logs(picoquic_quic_t* quic, uint32_t max_simultaneous_logs)
{
    quic->max_simultaneous_logs = max_simultaneous_logs;
}

uint32_t picoquic_get_max_simultaneous_logs(picoquic_quic_t* quic)
{
    return quic->max_simultaneous_logs;
}

void picoquic_set_default_bdp_frame_option(picoquic_quic_t* quic, int bdp_option)
{
    quic->default_send_receive_bdp_frame = bdp_option;
}

void picoquic_free(picoquic_quic_t* quic)
{
    if (quic != NULL) {

        /* delete all the connection contexts -- do this before any other
         * action, as deleting connections may add packets to queues or
         * change connection lists */
        while (quic->cnx_list != NULL) {
            picoquic_delete_cnx(quic->cnx_list);
        }

        /* Delete TLS and AEAD cntexts */
        picoquic_delete_retry_protection_contexts(quic);

        if (quic->aead_encrypt_ticket_ctx != NULL) {
            picoquic_aead_free(quic->aead_encrypt_ticket_ctx);
            quic->aead_encrypt_ticket_ctx = NULL;
        }

        if (quic->aead_decrypt_ticket_ctx != NULL) {
            picoquic_aead_free(quic->aead_decrypt_ticket_ctx);
            quic->aead_decrypt_ticket_ctx = NULL;
        }

        if (quic->default_alpn != NULL) {
            free((void*)quic->default_alpn);
            quic->default_alpn = NULL;
        }

        /* delete the stored tickets */
        picoquic_free_tickets(&quic->p_first_ticket);

        /* Delete the stored tokens */
        picoquic_free_tokens(&quic->p_first_token);

        /* Deelete the reused tokens tree */
        picosplay_empty_tree(&quic->token_reuse_tree);

        /* delete packets in pool */
        while (quic->p_first_packet != NULL) {
            picoquic_packet_t * p = quic->p_first_packet->packet_previous;
            free(quic->p_first_packet);
            quic->p_first_packet = p;
            quic->nb_packets_allocated--;
            quic->nb_packets_in_pool--;
        }

        /* delete data nodes in pool */
        while (quic->p_first_data_node != NULL) {
            picoquic_stream_data_node_t* p = quic->p_first_data_node->next_stream_data;
            free(quic->p_first_data_node);
            quic->p_first_data_node = p;
            quic->nb_data_nodes_allocated--;
            quic->nb_data_nodes_in_pool--;
        }

        /* delete all pending stateless packets */
        while (quic->pending_stateless_packet != NULL) {
            picoquic_stateless_packet_t* to_delete = quic->pending_stateless_packet;
            quic->pending_stateless_packet = to_delete->next_packet;
            free(to_delete);
        }

        if (quic->table_cnx_by_id != NULL) {
            picohash_delete(quic->table_cnx_by_id, 0);
        }

        if (quic->table_cnx_by_net != NULL) {
            picohash_delete(quic->table_cnx_by_net, 0);
        }

        if (quic->table_cnx_by_icid != NULL) {
            picohash_delete(quic->table_cnx_by_icid, 0);
        }

        if (quic->table_issued_tickets != NULL) {
            picohash_delete(quic->table_issued_tickets, 1);
        }

        if (quic->table_cnx_by_secret != NULL) {
            picohash_delete(quic->table_cnx_by_secret, 1);
        }

        if (quic->verify_certificate_callback != NULL) {
            picoquic_dispose_verify_certificate_callback(quic);
        }

        /* Delete the picotls context */
        if (quic->tls_master_ctx != NULL) {
            picoquic_master_tlscontext_free(quic);

            free(quic->tls_master_ctx);
            quic->tls_master_ctx = NULL;
        }

        /* Close the logs */
        picoquic_log_close_logs(quic);

        quic->binlog_dir = picoquic_string_free(quic->binlog_dir);
        quic->qlog_dir = picoquic_string_free(quic->qlog_dir);

        if (quic->perflog_fn != NULL) {
            (void)(quic->perflog_fn)(quic, NULL, 1);
        }

        free(quic);
    }
}

int picoquic_set_low_memory_mode(picoquic_quic_t* quic, int low_memory_mode)
{
    quic->use_low_memory = (low_memory_mode == 0) ? 0 : 1;
    return picoquic_set_cipher_suite(quic, 0);
}

void picoquic_set_null_verifier(picoquic_quic_t* quic) {
    picoquic_dispose_verify_certificate_callback(quic);
}

void picoquic_set_cookie_mode(picoquic_quic_t* quic, int cookie_mode)
{
    if (cookie_mode&1) {
        quic->force_check_token = 1;
    } else {
        quic->force_check_token = 0;
    }

    if (cookie_mode & 2) {
        quic->provide_token = 1;
    }
    else {
        quic->provide_token = 0;
    }

    quic->check_token = (quic->force_check_token || quic->max_half_open_before_retry <= quic->current_number_half_open);
}

void picoquic_set_max_half_open_retry_threshold(picoquic_quic_t* quic,  uint32_t max_half_open_before_retry)
{
    quic->max_half_open_before_retry = max_half_open_before_retry;
}

uint32_t picoquic_get_max_half_open_retry_threshold(picoquic_quic_t* quic)
{
    return quic->max_half_open_before_retry;
}

picoquic_stateless_packet_t* picoquic_create_stateless_packet(picoquic_quic_t* quic)
{
#ifdef _WINDOWS
    UNREFERENCED_PARAMETER(quic);
#endif
    return (picoquic_stateless_packet_t*)malloc(sizeof(picoquic_stateless_packet_t));
}

void picoquic_delete_stateless_packet(picoquic_stateless_packet_t* sp)
{
    free(sp);
}

void picoquic_queue_stateless_packet(picoquic_quic_t* quic, picoquic_stateless_packet_t* sp)
{
    picoquic_stateless_packet_t** pnext = &quic->pending_stateless_packet;

    while ((*pnext) != NULL) {
        pnext = &(*pnext)->next_packet;
    }

    *pnext = sp;
    sp->next_packet = NULL;
}

picoquic_stateless_packet_t* picoquic_dequeue_stateless_packet(picoquic_quic_t* quic)
{
    picoquic_stateless_packet_t* sp = quic->pending_stateless_packet;

    if (sp != NULL) {
        quic->pending_stateless_packet = sp->next_packet;
        sp->next_packet = NULL;
        picoquic_log_quic_pdu(quic, 0, picoquic_get_quic_time(quic), sp->cnxid_log64,
            (struct sockaddr*) & sp->addr_to, (struct sockaddr*) & sp->addr_local, sp->length);
    }

    return sp;
}

int picoquic_cnx_is_still_logging(picoquic_cnx_t* cnx)
{
    int ret =
        (cnx->nb_packets_logged < PICOQUIC_LOG_PACKET_MAX_SEQUENCE || cnx->quic->use_long_log);

    return ret;
}

/* Connection context creation and registration */
int picoquic_register_cnx_id(picoquic_quic_t* quic, picoquic_cnx_t* cnx, picoquic_local_cnxid_t* l_cid)
{
    int ret = 0;
    picohash_item* item;

    item = picohash_retrieve(quic->table_cnx_by_id, l_cid);
    if (item != NULL) {
        ret = -1;
    } else {
        l_cid->registered_cnx = cnx;
        ret = picohash_insert(quic->table_cnx_by_id, l_cid);
    }

    return ret;
}

void picoquic_unregister_net_id(picoquic_cnx_t* cnx, picoquic_path_t* path_x)
{
    if (path_x->net_id_hash_item.key != NULL) {
        picohash_item* item = picohash_retrieve(cnx->quic->table_cnx_by_net, path_x);
        if (item != NULL) {
            picohash_delete_item(cnx->quic->table_cnx_by_net, item, 0);
        }
        memset(&path_x->registered_peer_addr, 0, sizeof(struct sockaddr_storage));
    }
}

int picoquic_register_net_id(picoquic_quic_t* quic, picoquic_cnx_t* cnx, picoquic_path_t * path_x)
{
    int ret = 0;
    picohash_item* item;

    /* If registration was present, remove it */
    picoquic_unregister_net_id(cnx, path_x);
    /* Try registering the new address */
    picoquic_store_addr(&path_x->registered_peer_addr, (struct sockaddr *)&path_x->peer_addr);
    item = picohash_retrieve(quic->table_cnx_by_net, path_x);

    if (item != NULL) {
        ret = -1;
    } else {
        ret = picohash_insert(quic->table_cnx_by_net, path_x);
    }

    return ret;
}

/* The initial CID and the reset secret are tracked in specific tables:
 *
 * - quic->table_cnx_by_icid: keyed by client address and initial CID. Created
 *   when the connection for the specified initial CID and address is created
 *   by the server (or the peer receiving the connection in P2P cases)
 * - quic->table_cnx_by_secret: keyed by peer address and reset secret for
 *   the default path of the connection (cnx->path[0]).
 *
 * In both cases, the address is that associated to the default path. The
 * path can be updated after migration, either by an address change or by
 * a change of CID and secret while keeping the address constant.
 *
 * If either the default address or the default reset secret changes, the
 * old table entry is updated to track the new address and secret. The
 * entry is kept up to date until the connection closes.
 *
 * Migration can only happen after a connection is established, but
 * packets could still arrive after that, maybe due to network delays.
 * In order to keep the design simple, the ICID entry is created once, and
 * kept for the duration of the connection.
 *
 * To facilitate management, the hash table keys are remembered in the
 * connection context as:
 *
 * - cnx->reset_secret_key
 * - cnx->net_icid_key
 */

int picoquic_register_net_icid(picoquic_cnx_t* cnx)
{
    int ret = 0;
    picohash_item* item;
    picoquic_store_addr(&cnx->registered_icid_addr, (struct sockaddr*)&cnx->path[0]->peer_addr);
    item = picohash_retrieve(cnx->quic->table_cnx_by_icid, cnx);

    if (item != NULL) {
        ret = -1;
    }
    else {
        ret = picohash_insert(cnx->quic->table_cnx_by_icid, cnx);
    }
    return ret;
}

void picoquic_unregister_net_icid(picoquic_cnx_t* cnx)
{
    if (cnx->registered_icid_item.key != 0) {
        picohash_delete_item(cnx->quic->table_cnx_by_icid, &cnx->registered_icid_item, 0);
        memset(&cnx->registered_icid_addr, 0, sizeof(struct sockaddr_storage));
        memset(&cnx->registered_icid_item, 0, sizeof(picohash_item));
    }
}

void picoquic_unregister_net_secret(picoquic_cnx_t* cnx)
{
    if (cnx->registered_secret_addr.ss_family != 0) {
        picohash_delete_key(cnx->quic->table_cnx_by_secret, cnx, 0);
        memset(&cnx->registered_secret_addr, 0, sizeof(struct sockaddr_storage));
        memset(&cnx->registered_reset_secret, 0, sizeof(PICOQUIC_RESET_SECRET_SIZE));
    }
}

int picoquic_register_net_secret(picoquic_cnx_t* cnx)
{
    int ret = 0;

    if (cnx->path[0]->peer_addr.ss_family != 0) {
        picohash_item* item;
        picoquic_unregister_net_secret(cnx);
        picoquic_store_addr(&cnx->registered_secret_addr, (struct sockaddr *)&cnx->path[0]->peer_addr);
        memcpy(&cnx->registered_reset_secret, cnx->path[0]->p_remote_cnxid->reset_secret, PICOQUIC_RESET_SECRET_SIZE);

        item = picohash_retrieve(cnx->quic->table_cnx_by_secret, cnx);
        if (item != NULL) {
            ret = -1;
        } 
        else {
            ret = picohash_insert(cnx->quic->table_cnx_by_secret, cnx);
        }
    }
    return ret;
}

void picoquic_init_transport_parameters(picoquic_tp_t* tp, int client_mode)
{
    memset(tp, 0, sizeof(picoquic_tp_t));
    tp->initial_max_stream_data_bidi_local = 0x200000;
    tp->initial_max_stream_data_bidi_remote = 65635;
    tp->initial_max_stream_data_uni = 65535;
    tp->initial_max_data = 0x100000;
    tp->initial_max_stream_id_bidir = 512;
    tp->initial_max_stream_id_unidir = 512;
    tp->max_idle_timeout = PICOQUIC_MICROSEC_HANDSHAKE_MAX/1000;
    tp->max_packet_size = PICOQUIC_PRACTICAL_MAX_MTU;
    tp->max_datagram_frame_size = 0;
    tp->ack_delay_exponent = 3;
    tp->active_connection_id_limit = PICOQUIC_NB_PATH_TARGET;
    tp->max_ack_delay = PICOQUIC_ACK_DELAY_MAX;
    tp->enable_loss_bit = 2;
    tp->min_ack_delay = PICOQUIC_ACK_DELAY_MIN;
    tp->enable_time_stamp = 0;
    tp->enable_bdp_frame = 0;
}


/* management of the list of connections in context */

picoquic_quic_t* picoquic_get_quic_ctx(picoquic_cnx_t* cnx)
{
    return (cnx == NULL)?NULL:cnx->quic;
}

picoquic_cnx_t* picoquic_get_first_cnx(picoquic_quic_t* quic)
{
    return quic->cnx_list;
}

picoquic_cnx_t* picoquic_get_next_cnx(picoquic_cnx_t* cnx)
{
    return cnx->next_in_table;
}

static void picoquic_insert_cnx_in_list(picoquic_quic_t* quic, picoquic_cnx_t* cnx)
{
    if (quic->cnx_list != NULL) {
        quic->cnx_list->previous_in_table = cnx;
        cnx->next_in_table = quic->cnx_list;
    } else {
        quic->cnx_last = cnx;
        cnx->next_in_table = NULL;
    }
    quic->cnx_list = cnx;
    cnx->previous_in_table = NULL;
    quic->current_number_connections++;
}

static void picoquic_remove_cnx_from_list(picoquic_cnx_t* cnx)
{
    if (cnx->next_in_table == NULL) {
        cnx->quic->cnx_last = cnx->previous_in_table;
    } else {
        cnx->next_in_table->previous_in_table = cnx->previous_in_table;
    }

    if (cnx->previous_in_table == NULL) {
        cnx->quic->cnx_list = cnx->next_in_table;
    }
    else {
        cnx->previous_in_table->next_in_table = cnx->next_in_table;
    }

    picoquic_unregister_net_icid(cnx);
    picoquic_unregister_net_secret(cnx);

    cnx->quic->current_number_connections--;
}

/* Management of the list of connections, sorted by wake time */

static void* picoquic_wake_list_node_value(picosplay_node_t* cnx_wake_node)
{
    return (cnx_wake_node == NULL)?NULL:(void*)((char*)cnx_wake_node - offsetof(struct st_picoquic_cnx_t, cnx_wake_node));
}

static int64_t picoquic_wake_list_compare(void* l, void* r) {
    const uint64_t ltime = ((picoquic_cnx_t*)l)->next_wake_time;
    const uint64_t rtime = ((picoquic_cnx_t*)r)->next_wake_time;
    if (ltime < rtime) return -1;
    if (ltime > rtime) return 1;
    return 0;
}

static picosplay_node_t* picoquic_wake_list_create_node(void* v_cnx)
{
    return &((picoquic_cnx_t*)v_cnx)->cnx_wake_node;
}

static void picoquic_wake_list_delete_node(void* tree, picosplay_node_t* node)
{
#ifdef _WINDOWS
    UNREFERENCED_PARAMETER(tree);
#endif
    memset(node, 0, sizeof(picosplay_node_t));
}

static void picoquic_wake_list_init(picoquic_quic_t * quic)
{
    picosplay_init_tree(&quic->cnx_wake_tree, picoquic_wake_list_compare,
        picoquic_wake_list_create_node, picoquic_wake_list_delete_node, picoquic_wake_list_node_value);
}

static void picoquic_remove_cnx_from_wake_list(picoquic_cnx_t* cnx)
{
    picosplay_delete_hint(&cnx->quic->cnx_wake_tree, &cnx->cnx_wake_node);
}

static void picoquic_insert_cnx_by_wake_time(picoquic_quic_t* quic, picoquic_cnx_t* cnx)
{
    picosplay_insert(&quic->cnx_wake_tree, cnx);
}

void picoquic_reinsert_by_wake_time(picoquic_quic_t* quic, picoquic_cnx_t* cnx, uint64_t next_time)
{
    picoquic_remove_cnx_from_wake_list(cnx);
    cnx->next_wake_time = next_time;
    picoquic_insert_cnx_by_wake_time(quic, cnx);
}

picoquic_cnx_t* picoquic_get_earliest_cnx_to_wake(picoquic_quic_t* quic, uint64_t max_wake_time)
{
    picoquic_cnx_t* cnx = (picoquic_cnx_t *)picoquic_wake_list_node_value(picosplay_first(&quic->cnx_wake_tree));
    if (cnx != NULL && max_wake_time != 0 && cnx->next_wake_time > max_wake_time)
    {
        cnx = NULL;
    }

    return cnx;
}

uint64_t picoquic_get_next_wake_time(picoquic_quic_t* quic, uint64_t current_time)
{
    uint64_t wake_time = UINT64_MAX;

    if (quic->pending_stateless_packet != NULL) {
        wake_time = current_time;
    }
    else{
        picoquic_cnx_t* cnx_wake_first = (picoquic_cnx_t*)picoquic_wake_list_node_value(
            picosplay_first(&quic->cnx_wake_tree));

        if (cnx_wake_first != NULL) {
            wake_time = cnx_wake_first->next_wake_time;
        }
    }

    return wake_time;
}

int64_t picoquic_get_next_wake_delay(picoquic_quic_t* quic,
    uint64_t current_time, int64_t delay_max)
{
    /* We assume that "current time" is no more than 100,000 years in the
     * future, which implies the time in microseconds is less than 2^62.
     * The delay MAX is lower than INT64_MAX, i.e., 2^63.
     * The next wake time is often set to UINT64_MAX, and might sometime
     * me just under that value, so we make sure to avoid integer
     * overflow in the computation.
     */
    uint64_t next_wake_time = picoquic_get_next_wake_time(quic, current_time);
    int64_t wake_delay = 0;

    if (next_wake_time > current_time) {
        uint64_t delta_m = current_time + delay_max;

        if (next_wake_time >= delta_m) {
            wake_delay = delay_max;
        }
        else {
            wake_delay = (int64_t)(next_wake_time - current_time);
        }
    }
    return wake_delay;
}

static uint64_t picoquic_get_wake_time(picoquic_cnx_t* cnx, uint64_t current_time)
{
    uint64_t wake_time = UINT64_MAX;

    if (cnx->quic->pending_stateless_packet != NULL) {
        wake_time = current_time;
    } else {
        wake_time = cnx->next_wake_time;
    }

    return wake_time;
}

int64_t picoquic_get_wake_delay(picoquic_cnx_t* cnx,
    uint64_t current_time, int64_t delay_max)
{
    /* See get_next_wake_delay for reasoning about integer overflow */
    uint64_t next_wake_time = picoquic_get_wake_time(cnx, current_time);
    int64_t wake_delay = 0;

    if (next_wake_time > current_time) {
        uint64_t delta_m = current_time + delay_max;

        if (next_wake_time >= delta_m) {
            wake_delay = delay_max;
        }
        else {
            wake_delay = (int64_t)(next_wake_time - current_time);
        }
    }

    return wake_delay;
}

/* Other context management functions */

int picoquic_get_version_index(uint32_t proposed_version)
{
    int ret = -1;

    for (size_t i = 0; i < picoquic_nb_supported_versions; i++) {
        if (picoquic_supported_versions[i].version == proposed_version) {
            ret = (int)i;
            break;
        }
    }

    return ret;
}

static void picoquic_create_random_cnx_id(picoquic_quic_t* quic, picoquic_connection_id_t * cnx_id, uint8_t id_length)
{
    if (id_length > 0) {
        picoquic_crypto_random(quic, cnx_id->id, id_length);
    }
    if (id_length < sizeof(cnx_id->id)) {
        memset(cnx_id->id + id_length, 0, sizeof(cnx_id->id) - id_length);
    }
    cnx_id->id_len = id_length;
}

void picoquic_create_local_cnx_id(picoquic_quic_t* quic, picoquic_connection_id_t* cnx_id, uint8_t id_length, picoquic_connection_id_t cnx_id_remote)
{
    /* First call fills the CID with a random value */
    picoquic_create_random_cnx_id(quic, cnx_id, quic->local_cnxid_length);
    /* if required for application, call to function update that definition */
    if (quic->cnx_id_callback_fn) {
        quic->cnx_id_callback_fn(quic, *cnx_id, cnx_id_remote, quic->cnx_id_callback_ctx, cnx_id);
    }
}

uint64_t picoquic_find_avalaible_unique_path_id(picoquic_cnx_t* cnx, uint64_t requested_id)
{
    uint64_t unique_path_id = requested_id;

    if (requested_id == UINT64_MAX) {
        if (!cnx->is_multipath_enabled) {
            unique_path_id = cnx->unique_path_id_next;
            cnx->unique_path_id_next++;
        }
        else {
            /* Look at available stashes. exlcude stash if id=0, as this is the
             * always used.
             */
            picoquic_remote_cnxid_stash_t* stash = cnx->first_remote_cnxid_stash;

            while (stash != NULL && (stash->is_in_use || stash->unique_path_id == 0)){
                stash = stash->next_stash;
            }
            if (stash != NULL) {
                unique_path_id = stash->unique_path_id;
            }
        }
    }
    return unique_path_id;
}

/* Shortcuts to packet numbers, last ack, last ack time.
 */
uint64_t picoquic_get_sequence_number(picoquic_cnx_t* cnx, picoquic_path_t* path_x, picoquic_packet_context_enum pc)
{
    return (cnx->is_multipath_enabled && pc == picoquic_packet_context_application) ? path_x->pkt_ctx.send_sequence:
        cnx->pkt_ctx[pc].send_sequence;
}

uint64_t picoquic_get_ack_number(picoquic_cnx_t* cnx, picoquic_path_t* path_x, picoquic_packet_context_enum pc)
{
    return (cnx->is_multipath_enabled && pc == picoquic_packet_context_application) ? path_x->pkt_ctx.highest_acknowledged :
        cnx->pkt_ctx[pc].highest_acknowledged;
}

picoquic_packet_t* picoquic_get_last_packet(picoquic_cnx_t* cnx, picoquic_path_t* path_x, picoquic_packet_context_enum pc)
{
    return (cnx->is_multipath_enabled && pc == picoquic_packet_context_application) ? path_x->pkt_ctx.pending_last :
        cnx->pkt_ctx[pc].pending_last;
}

/* Path management -- returns the index of the path that was created. */
int picoquic_create_path(picoquic_cnx_t* cnx, uint64_t start_time, const struct sockaddr* local_addr,
    const struct sockaddr* peer_addr, uint64_t requested_id)
{
    int ret = -1;

    if (cnx->nb_paths >= cnx->nb_path_alloc)
    {
        int new_alloc = (cnx->nb_path_alloc == 0) ? 1 : 2 * cnx->nb_path_alloc;
        picoquic_path_t ** new_path = (picoquic_path_t **)malloc(new_alloc * sizeof(picoquic_path_t *));

        if (new_path != NULL)
        {
            if (cnx->path != NULL)
            {
                memset (new_path, 0, new_alloc * sizeof(picoquic_path_t*));
                if (cnx->nb_paths > 0)
                {
                    memcpy(new_path, cnx->path, cnx->nb_paths * sizeof(picoquic_path_t *));
                }
                free(cnx->path);
            }
            cnx->path = new_path;
            cnx->nb_path_alloc = new_alloc;
        }
    }

    if (cnx->nb_paths < cnx->nb_path_alloc)
    {
        uint64_t unique_path_id = picoquic_find_avalaible_unique_path_id(cnx, requested_id);
        picoquic_path_t * path_x = (unique_path_id == UINT64_MAX)?NULL:
            (picoquic_path_t *)malloc(sizeof(picoquic_path_t));

        if (path_x != NULL)
        {
            memset(path_x, 0, sizeof(picoquic_path_t));
            /* Register the sequence number */
            path_x->unique_path_id = unique_path_id;
            path_x->cnx = cnx;

            /* Set the addresses */
            picoquic_update_peer_addr(path_x, peer_addr);
            picoquic_store_addr(&path_x->local_addr, local_addr);
            /* Initialize per path time measurement */
            path_x->smoothed_rtt = PICOQUIC_INITIAL_RTT;
            path_x->rtt_variant = 0;
            path_x->retransmit_timer = PICOQUIC_INITIAL_RETRANSMIT_TIMER;
            path_x->rtt_min = 0;

            /* Initialize per path congestion control state */
            path_x->cwin = PICOQUIC_CWIN_INITIAL;
            path_x->bytes_in_transit = 0;
            path_x->congestion_alg_state = NULL;

            /* Initialize per path pacing state */
            picoquic_pacing_init(&path_x->pacing, start_time);

            /* Initialize the MTU */
            picoquic_reset_path_mtu(path_x);

            /* initialize the quality reporting thresholds */
            path_x->rtt_update_delta = cnx->rtt_update_delta;
            path_x->pacing_rate_update_delta = cnx->pacing_rate_update_delta;
            picoquic_refresh_path_quality_thresholds(path_x);

            /* In case of unique path_id multipath, initialize the context. We do that systematically,
             * because path 0 is created before multipath options are negotiated.
             */
            picoquic_init_ack_ctx(cnx, &path_x->ack_ctx);
            picoquic_init_packet_ctx(cnx, &path_x->pkt_ctx, picoquic_packet_context_application);
            /* Record the path */
            cnx->path[cnx->nb_paths] = path_x;
            ret = cnx->nb_paths++;

            /* Set the challenge used for this path */
            picoquic_set_path_challenge(cnx, cnx->nb_paths-1, start_time);
        }
    }

    return ret;
}

/*
 * Register the path in the hash tables.
 * This only registers the address associated with the path.
 */
void picoquic_register_path(picoquic_cnx_t* cnx, picoquic_path_t * path_x)
{
    if (path_x->peer_addr.ss_family != 0 && cnx->quic->local_cnxid_length == 0) {
        (void)picoquic_register_net_id(cnx->quic, cnx, path_x);
    }
}

/* To delete a path, we need to delete the data allocated to the path: search items in
 * the hash tables, and congestion algorithm context. Then delete the path data itself,
 * and finally remove the path reference from the table of paths in the connection
 * context.
 */

static void picoquic_clear_path_data(picoquic_cnx_t* cnx, picoquic_path_t * path_x) 
{
    picoquic_unregister_net_id(cnx, path_x);
    /* Remove the congestion data */
    if (cnx->congestion_alg != NULL) {
        cnx->congestion_alg->alg_delete(path_x);
    }

    /* Free the record */
    free(path_x);
}

void picoquic_delete_path(picoquic_cnx_t* cnx, int path_index)
{
    picoquic_path_t * path_x = cnx->path[path_index];
    picoquic_packet_t* p = NULL;
    picoquic_stream_head_t* stream = NULL;

    picoquic_reset_packet_context(cnx, &path_x->pkt_ctx);
    picoquic_reset_ack_context(&path_x->ack_ctx);

    if (cnx->quic->F_log != NULL) {
        fflush(cnx->quic->F_log);
    }

    /* if there are references to path in streams, remove them */
    stream = picoquic_first_stream(cnx);
    while (stream != NULL) {
        if (stream->affinity_path == path_x) {
            stream->affinity_path = NULL;
        }
        stream = picoquic_next_stream(stream);
    }

    /* Signal to the application */
    if (cnx->are_path_callbacks_enabled &&
        cnx->callback_fn(cnx, path_x->unique_path_id, NULL, 0, picoquic_callback_path_deleted,
        cnx->callback_ctx, path_x->app_path_ctx) != 0) {
        picoquic_connection_error_ex(cnx, PICOQUIC_TRANSPORT_INTERNAL_ERROR, 0, "Path deleted callback failed.");
    }
    /* Remove old path data from retransmitted queue */
    /* TODO: what if using multiple number spaces? */
    for (picoquic_packet_context_enum pc = 0; pc < picoquic_nb_packet_context; pc++)
    {
        p = cnx->pkt_ctx[pc].retransmitted_newest;
        while (p != NULL) {
            if (p->send_path == path_x) {
                DBG_PRINTF("Erase path for old packet pc: %d, seq:%" PRIu64 "\n", pc, p->sequence_number);
                p->send_path = NULL;
            }
            p = p->packet_next;
        }
    }

    if (cnx->is_multipath_enabled) {
        /* delete the local CID context used by the path */
        picoquic_local_cnxid_list_t* local_cnxid_list = picoquic_find_or_create_local_cnxid_list(cnx, path_x->unique_path_id, 0);
        if (local_cnxid_list != NULL) {
            picoquic_delete_local_cnxid_list(cnx, local_cnxid_list);
        }
    }

    /* Free the data and free the path context. */
    picoquic_clear_path_data(cnx, path_x);

    /* Compact the path table  */
    for (int i = path_index + 1; i < cnx->nb_paths; i++) {
        cnx->path[i-1] = cnx->path[i];
    }

    cnx->nb_paths--;
    cnx->path[cnx->nb_paths] = NULL;
}

/*
 * Path challenges may be abandoned if they are tried too many times without success. 
 */

void picoquic_delete_abandoned_paths(picoquic_cnx_t* cnx, uint64_t current_time, uint64_t * next_wake_time)
{
    int path_index_good = 1;
    int path_index_current = 1;
    unsigned int is_demotion_in_progress = 0;

    if (cnx->is_multipath_enabled && cnx->nb_paths > 1) {
        path_index_good = 0;
        path_index_current = 0;
    }

    while (path_index_current < cnx->nb_paths) {
        /* Demote the path if marked for demotion */
        if (!cnx->path[path_index_current]->path_is_demoted){
            if (cnx->path[path_index_current]->challenge_failed ||
                (path_index_current > 0 && cnx->path[path_index_current]->challenge_verified &&
                    current_time - cnx->path[path_index_current]->latest_sent_time >= cnx->idle_timeout)) {
                picoquic_demote_path(cnx, path_index_current, current_time, 0, NULL);
            }
        }
        if (cnx->path[path_index_current]->path_is_demoted &&
            current_time >= cnx->path[path_index_current]->demotion_time) {
            /* Waited enough,should now delete this path. */
            path_index_current++;
            is_demotion_in_progress |= 1;
        } else {
            /* Need to keep this path a bit longer */
            /* First set the wake up timer so we don't miss the coming demotion */
            if (cnx->path[path_index_current]->path_is_demoted &&
                current_time < cnx->path[path_index_current]->demotion_time){
                is_demotion_in_progress |= 1;
                if (*next_wake_time > cnx->path[path_index_current]->demotion_time) {
                    *next_wake_time = cnx->path[path_index_current]->demotion_time;
                    SET_LAST_WAKE(cnx->quic, PICOQUIC_QUICCTX);
                }
            }
            /* Then pack the list of paths */
            if (path_index_current > path_index_good) {
                /* swap the path indexed good with current */
                picoquic_path_t * path_x = cnx->path[path_index_current];
                cnx->path[path_index_current] = cnx->path[path_index_good];
                cnx->path[path_index_good] = path_x;
            }
            /* increment both indices */
            path_index_current++;
            path_index_good++;
        }
    }

    while (cnx->nb_paths > path_index_good) {
        int d_path = cnx->nb_paths - 1;
        picoquic_dereference_stashed_cnxid(cnx, cnx->path[d_path], 0);
        picoquic_delete_path(cnx, d_path);
    }

    /* TODO: what if there are no paths left? */
    cnx->path_demotion_needed = is_demotion_in_progress;
    int path_left = -1;
    int path_backup = -1;
    if (is_demotion_in_progress && cnx->is_multipath_enabled) {
        /* Verify that if one path is demoted, the other
         * becomes available */
        for (int i = 0; i < cnx->nb_paths; i++) {
            if (cnx->path[i]->path_is_demoted) {
                continue;
            }
            if (cnx->path[i]->path_is_standby && path_backup < 0) {
                path_backup = i;
            }
            else {
                path_left = i;
                break;
            }
        }
        if (path_left < 0 && path_backup >= 0) {
            cnx->path[path_backup]->path_is_standby = 0;
            (void)picoquic_queue_path_available_or_standby_frame(cnx, cnx->path[path_backup], picoquic_path_status_available);
        }
    }
}

/* 
 * Demote path, compute the effective time for demotion.
 */
void picoquic_demote_path(picoquic_cnx_t* cnx, int path_index, uint64_t current_time, uint64_t reason, char const * phrase)
{
    if (!cnx->path[path_index]->path_is_demoted) {
        uint64_t demote_timer = cnx->path[path_index]->retransmit_timer;

        if (demote_timer < PICOQUIC_INITIAL_MAX_RETRANSMIT_TIMER &&
            !cnx->is_multipath_enabled) {
            demote_timer = PICOQUIC_INITIAL_MAX_RETRANSMIT_TIMER;
        }

        cnx->path[path_index]->path_is_demoted = 1;
        cnx->path[path_index]->demotion_time = current_time + 3* demote_timer;
        cnx->path_demotion_needed = 1;

        /* TODO: add suspended callback */
        if (cnx->is_multipath_enabled) {
             /* Special case for path 0: we want to reorder the paths so the path[0]
             * is always a valid path.
             */
            if (path_index == 0) {
                int alt_path0 = 0;
                for (int i = 1; i < cnx->nb_paths; i++) {
                    if (cnx->path[path_index]->p_remote_cnxid != NULL) {
                        alt_path0 = i;
                        break;
                    }
                }
                if (alt_path0 != 0) {
                    picoquic_path_t* path_x = cnx->path[0];
                    cnx->path[0] = cnx->path[alt_path0];
                    cnx->path[alt_path0] = path_x;
                    path_index = alt_path0;
                }
            }
            if (path_index == 0) {
                picoquic_log_app_message(cnx, "Cannot demote path index 0, unique_id %" PRIu64", was reason % " PRIu64,
                    cnx->path[path_index]->unique_path_id, reason);
            }
            else if (!cnx->path[path_index]->path_abandon_sent) {
                uint64_t path_id = cnx->path[path_index]->unique_path_id;
                if (picoquic_queue_path_abandon_frame(cnx, path_id, reason) == 0){
                    picoquic_remote_cnxid_stash_t* remote_cnxid_stash = 
                        picoquic_find_or_create_remote_cnxid_stash(cnx, 
                            cnx->path[path_index]->unique_path_id, 0);
                    if (remote_cnxid_stash != NULL && path_index != 0) {
                        cnx->path[path_index]->p_remote_cnxid = NULL;
                        picoquic_delete_remote_cnxid_stash(cnx, remote_cnxid_stash);
                    }
                    else {
                        DBG_PRINTF("Cannot abandon path[%d]", cnx->path[path_index]->unique_path_id);
                    }
                    picoquic_log_app_message(cnx, "Abandon path, unique_id %" PRIu64", reason % " PRIu64,
                        cnx->path[path_index]->unique_path_id, reason);
                    cnx->path[path_index]->path_abandon_sent = 1;
                } else {
                    picoquic_log_app_message(cnx, "Cannot queue abandon path [%" PRIu64 "]",
                        cnx->path[path_index]->unique_path_id);
                }
            }
        }
    }
}

/* Promote path to default. This happens when a new path is verified, at the end
 * of a migration, and becomes the new default path.
 */

void picoquic_promote_path_to_default(picoquic_cnx_t* cnx, int path_index, uint64_t current_time)
{
    if (path_index > 0 && path_index < cnx->nb_paths) {
        picoquic_path_t * path_x = cnx->path[path_index];

        if (cnx->path[path_index]->path_is_preferred_path) {
            /* this is a migration to the preferred path requested by the server */
            if (cnx->client_mode) {
                cnx->remote_parameters.migration_disabled = 0;
            }
            else {
                cnx->local_parameters.migration_disabled = 0;
            }
        }

        if (cnx->quic->F_log != NULL || cnx->f_binlog != NULL) {
            char src_ip[128];
            char dst_ip[128];

            picoquic_log_app_message(cnx, "Path %d promoted to default at T=%fs, Local: %s, Remote: %s",
                path_index, (double)(current_time - cnx->start_time) / 1000000.0,
                picoquic_addr_text((struct sockaddr*) & cnx->path[path_index]->local_addr, src_ip, sizeof(src_ip)),
                picoquic_addr_text((struct sockaddr*) & cnx->path[path_index]->peer_addr, dst_ip, sizeof(dst_ip)));
        }

        /* Set the congestion algorithm for the new path */
        if (cnx->congestion_alg != NULL) {
            cnx->congestion_alg->alg_init(cnx, path_x, current_time);
        }

        /* Mark old path as demoted */
        picoquic_demote_path(cnx, 0, current_time, 0, NULL);

        /* Swap */
        cnx->path[path_index] = cnx->path[0];
        cnx->path[0] = path_x;

        /* Update the secret */
        (void)picoquic_register_net_secret(cnx);
    }
}

/* Set or renew challenge for a path */
void picoquic_set_path_challenge(picoquic_cnx_t* cnx, int path_id, uint64_t current_time)
{
    if (!cnx->path[path_id]->challenge_required || cnx->path[path_id]->challenge_verified) {
        /* Reset the path challenge */
        cnx->path[path_id]->challenge_required = 1;
        cnx->path[path_id]->challenge_time_first = current_time;
        for (int ichal = 0; ichal < PICOQUIC_CHALLENGE_REPEAT_MAX; ichal++) {
            if (cnx->quic->use_constant_challenges) {
                cnx->path[path_id]->challenge[ichal] = current_time*(0xdeadbeefull + ichal);
            }
            else {
                cnx->path[path_id]->challenge[ichal] = picoquic_public_random_64();
            }
        }
        if (cnx->path[path_id]->challenge_verified && cnx->are_path_callbacks_enabled) {
            if (cnx->callback_fn(cnx, cnx->path[path_id]->unique_path_id, NULL, 0, picoquic_callback_path_suspended,
                cnx->callback_ctx, cnx->path[path_id]->app_path_ctx) != 0) {
                picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_INTERNAL_ERROR, picoquic_frame_type_path_challenge);
            }
        }
        cnx->path[path_id]->challenge_verified = 0;
        cnx->path[path_id]->challenge_time = current_time;
        cnx->path[path_id]->challenge_repeat_count = 0;
    }
}

/* Find path by address pair
 */
int picoquic_find_path_by_address(picoquic_cnx_t* cnx, const struct sockaddr* addr_local, 
    const struct sockaddr* addr_peer, int * partial_match)
{
    int path_id = -1;
    int is_null_from = 0;
    struct sockaddr_storage null_addr;

    *partial_match = -1;

    if (addr_peer != NULL || addr_local != NULL) {
        if (addr_peer == NULL || addr_local == NULL) {
            memset(&null_addr, 0, sizeof(struct sockaddr_storage));
            if (addr_peer == NULL) {
                addr_peer = (struct sockaddr*) & null_addr;
            }
            else {
                addr_local = (struct sockaddr*) & null_addr;
            }
            is_null_from = 1;
        }
        else if (addr_local->sa_family == 0) {
            is_null_from = 1;
        }

        /* Find whether an existing path matches the  pair of addresses */
        for (int i = 0; i < cnx->nb_paths; i++) {
            if (picoquic_compare_addr((struct sockaddr*) & cnx->path[i]->peer_addr,
                addr_peer) == 0) {
                if (cnx->path[i]->local_addr.ss_family == 0) {
                    *partial_match = i;
                }
                else if (picoquic_compare_addr((struct sockaddr*) & cnx->path[i]->local_addr,
                    addr_local) == 0) {
                    path_id = i;
                    break;
                }
            }

            if (path_id < 0 && is_null_from) {
                path_id = *partial_match;
                *partial_match = -1;
            }
        }
    }

    if (path_id == -1) {
        char text1[128];
        char text2[128];
        DBG_PRINTF("Could not find path by addr, local: %s, peer: %s", 
            picoquic_addr_text(addr_local, text1, sizeof(text1)),
            picoquic_addr_text(addr_peer, text2, sizeof(text2)));
    }

    return path_id;
}

int picoquic_find_path_by_unique_id(picoquic_cnx_t* cnx, uint64_t unique_path_id)
{
    int path_index = -1;
    
    for (int i = 0; i < cnx->nb_paths; i++) {
        if (cnx->path[i]->unique_path_id == unique_path_id) {
            path_index = i;
            break;
        }
    }

    return path_index;
}

/* Process a destination unreachable notification. */
void picoquic_notify_destination_unreachable(picoquic_cnx_t* cnx, uint64_t current_time,
    struct sockaddr* addr_peer, struct sockaddr* addr_local, int if_index, int socket_err)
{
    if (cnx != NULL && addr_peer != NULL) {
        int no_path_left = 1;
        int partial_match = 0;
        int path_id = picoquic_find_path_by_address(cnx, addr_local, addr_peer, &partial_match);

        if (path_id >= 0) {
            for (int i = 0; no_path_left && i < cnx->nb_paths; i++) {
                no_path_left &= cnx->path[i]->path_is_demoted;         
            }
            if (no_path_left) {
                /* Caution here: ICMP packets could be forged */
                if (cnx->cnx_state == picoquic_state_ready) {
                    picoquic_set_path_challenge(cnx, path_id, current_time);
                }
            }
            else {
                picoquic_log_app_message(cnx, "Demoting path %d after socket error %d, if %d", path_id, socket_err, if_index);
                picoquic_demote_path(cnx, path_id, current_time, 0, NULL);
            }
        }
    }
}

void picoquic_notify_destination_unreachable_by_cnxid(picoquic_quic_t * quic, picoquic_connection_id_t* cnxid,
    uint64_t current_time, struct sockaddr* addr_peer, struct sockaddr* addr_local, int if_index, int socket_err)
{
    picoquic_cnx_t* cnx = NULL;

    if (quic->local_cnxid_length == 0 || cnxid->id_len == 0) {
        cnx = picoquic_cnx_by_net(quic, addr_peer);
    }
    else if (cnxid->id_len == quic->local_cnxid_length) {
        cnx = picoquic_cnx_by_id(quic, *cnxid, NULL);
    }

    if (cnx != NULL) {
        picoquic_notify_destination_unreachable(cnx, current_time, addr_peer, addr_local, if_index, socket_err);
    }
}


/* Assign CID to path */
int picoquic_assign_peer_cnxid_to_path(picoquic_cnx_t* cnx, int path_index)
{
    int ret = -1;
    uint64_t unique_path_id = (cnx->is_multipath_enabled) ? cnx->path[path_index]->unique_path_id : 0;
    picoquic_remote_cnxid_stash_t* stash = picoquic_find_or_create_remote_cnxid_stash(cnx, unique_path_id, 0);
    
    if (stash != NULL) {
        picoquic_remote_cnxid_t* available_cnxid = picoquic_get_cnxid_from_stash(stash);

        if (available_cnxid != NULL) {
            cnx->path[path_index]->p_remote_cnxid = available_cnxid;
            available_cnxid->nb_path_references++;
            stash->is_in_use = 1;
            ret = 0;
        }
    }

    return ret;
}

/* Create a new path in order to trigger a migration */
int picoquic_probe_new_path_ex(picoquic_cnx_t* cnx, const struct sockaddr* addr_peer,
    const struct sockaddr* addr_local, int if_index, uint64_t current_time, int to_preferred_address, int* path_id_p)
{
    int ret = 0;
    int partial_match_path = -1;
    int path_id = -1;

    if ((cnx->remote_parameters.migration_disabled && !to_preferred_address ) ||
        cnx->local_parameters.migration_disabled) {
        /* Do not create new paths if migration is disabled */
        ret = PICOQUIC_ERROR_MIGRATION_DISABLED;
        DBG_PRINTF("Tried to create probe with migration disabled = %d", cnx->remote_parameters.migration_disabled);
    }
    else if ((path_id = picoquic_find_path_by_address(cnx, addr_local, addr_peer, &partial_match_path)) >= 0) {
        /* This path already exists. Will not create it, but will restore it in working order if disabled. */
        ret = -1;
    }
    else if (partial_match_path >= 0 && addr_peer->sa_family == 0) {
        /* This path already exists. Will not create it, but will restore it in working order if disabled. */
        ret = -1;
    }
    else if (cnx->first_remote_cnxid_stash->cnxid_stash_first == NULL) {
        /* No CNXID available yet. */
        ret = -1;
    }
    else if (cnx->nb_paths >= PICOQUIC_NB_PATH_TARGET) {
        /* Too many paths created already */
        ret = -1;
    }
    else if (picoquic_create_path(cnx, current_time, addr_local, addr_peer, UINT64_MAX) > 0) {
        path_id = cnx->nb_paths - 1;
        ret = picoquic_assign_peer_cnxid_to_path(cnx, path_id);

        if (ret != 0) {
            /* delete the path that was just created! */
            picoquic_dereference_stashed_cnxid(cnx, cnx->path[path_id], 0);
            picoquic_delete_path(cnx, path_id);
        }
        else {
            cnx->path[path_id]->path_is_published = 1;
            picoquic_register_path(cnx, cnx->path[path_id]);
            picoquic_set_path_challenge(cnx, path_id, current_time);
            cnx->path[path_id]->path_is_preferred_path = to_preferred_address;
            cnx->path[path_id]->is_nat_challenge = 0;
            cnx->path[path_id]->if_index_dest = if_index;
        }
    }

    if (path_id_p != NULL) {
        *path_id_p = path_id;
    }

    return ret;
}

void picoquic_enable_path_callbacks(picoquic_cnx_t* cnx, int are_enabled)
{
    cnx->are_path_callbacks_enabled = are_enabled;
}

void picoquic_enable_path_callbacks_default(picoquic_quic_t* quic, int are_enabled)
{
    quic->are_path_callbacks_enabled = are_enabled;
}

int picoquic_get_path_id_from_unique(picoquic_cnx_t* cnx, uint64_t unique_path_id)
{
    int ret = -1;

    for (int i = 0; i < cnx->nb_paths; i++) {
        if (cnx->path[i]->unique_path_id == unique_path_id) {
            ret = i;
            break;
        }
    }

    return ret;
}

int picoquic_set_app_path_ctx(picoquic_cnx_t* cnx, uint64_t unique_path_id, void* app_path_ctx)
{
    int ret = 0;
    int path_id = picoquic_get_path_id_from_unique(cnx, unique_path_id);
    if (path_id >= 0) {
        cnx->path[path_id]->app_path_ctx = app_path_ctx;
    } else {
        ret = -1;
    }
    return ret;
}

int picoquic_probe_new_path(picoquic_cnx_t* cnx, const struct sockaddr* addr_peer,
    const struct sockaddr* addr_local, uint64_t current_time)
{
    return picoquic_probe_new_path_ex(cnx, addr_peer, addr_local, 0, current_time, 0, NULL);
}

int picoquic_demote_local_cnxid_list(picoquic_cnx_t* cnx, uint64_t unique_path_id,
    uint64_t reason, uint64_t current_time)
{
    int ret = 0;
    picoquic_local_cnxid_list_t* local_cnxid_list =
        picoquic_find_or_create_local_cnxid_list(cnx, unique_path_id, 0);

    if (local_cnxid_list != NULL &&
        !local_cnxid_list->is_demoted) {
        if ((ret = picoquic_queue_path_abandon_frame(cnx, unique_path_id, reason)) == 0) {
            picoquic_remote_cnxid_stash_t* remote_cnxid_stash =
                picoquic_find_or_create_remote_cnxid_stash(cnx, unique_path_id, 0);
            if (remote_cnxid_stash != NULL) {
                picoquic_delete_remote_cnxid_stash(cnx, remote_cnxid_stash);
            }
            local_cnxid_list->is_demoted = 1;
        }
        else {
            DBG_PRINTF("Cannot abandon path %" PRIu64, unique_path_id);
        }
    }
    return ret;
}


int picoquic_abandon_path(picoquic_cnx_t* cnx, uint64_t unique_path_id, 
    uint64_t reason, char const * phrase, uint64_t current_time)
{
    int ret = 0;

    if (!cnx->is_multipath_enabled) {
        ret = -1;
    }
    else if (unique_path_id > cnx->max_path_id_remote ||
        unique_path_id > cnx->max_path_id_local) {
        /* that path has not been created yet */
        ret = -1;
    }
    else {
        /* Check whether there is a path by that ID */
        int path_index = picoquic_get_path_id_from_unique(cnx, unique_path_id);

        if (path_index >= 0) {
            /* Check whether this is the last path */
            if (cnx->nb_paths <= 1) {
                /* That would mean deleting the last path. Don't do that */
                ret = -1;
            }
            else if (!cnx->path[path_index]->path_is_demoted) {
                /* if demotion is not already in progress, demote the path,
                * and if the path can be properly identified, post a path abandon frame.
                */
                picoquic_demote_path(cnx, path_index, current_time, reason, phrase);
            }
        }
        else {
            /* The path ID is not in use yet, but local cid have been allocated.
             * We need to send an abandon if not sent yet, mark the local CID
             * as demoted, and delete the stash. The stash has to remain deleted
             * even if we receive new CID for that path.
             */
            ret = picoquic_demote_local_cnxid_list(cnx, unique_path_id,
                reason, current_time);
        }
    }

    return ret;
}

/* Management of "path_quality" feedback.
 */
void picoquic_refresh_path_quality_thresholds(picoquic_path_t* path_x)
{
    if (path_x->rtt_update_delta > 0) {
        if (path_x->smoothed_rtt > path_x->rtt_update_delta) {
            path_x->rtt_threshold_low = path_x->smoothed_rtt - path_x->rtt_update_delta;
        }
        else {
            path_x->rtt_threshold_low = 0;
        }
        path_x->rtt_threshold_high = path_x->smoothed_rtt + path_x->rtt_update_delta;
    }

    if (path_x->pacing_rate_update_delta > 0) {
        if (path_x->pacing.rate > path_x->pacing_rate_update_delta) {
            path_x->pacing_rate_threshold_low = path_x->pacing.rate - path_x->pacing_rate_update_delta;
        }
        else {
            path_x->pacing_rate_threshold_low = 0;
        }
        path_x->pacing_rate_threshold_high = path_x->pacing.rate + path_x->pacing_rate_update_delta;
        if (path_x->receive_rate_estimate > path_x->pacing_rate_update_delta) {
            path_x->receive_rate_threshold_low = path_x->receive_rate_estimate - path_x->pacing_rate_update_delta;
        }
        else {
            path_x->receive_rate_threshold_low = 0;
        }
        path_x->receive_rate_threshold_high = path_x->receive_rate_estimate + path_x->pacing_rate_update_delta;
    }
}

int picoquic_issue_path_quality_update(picoquic_cnx_t* cnx, picoquic_path_t* path_x)
{
    int ret = 0;

    if ((path_x->rtt_update_delta > 0 && (
        path_x->smoothed_rtt < path_x->rtt_threshold_low || 
        path_x->smoothed_rtt > path_x->rtt_threshold_high)) ||
        (path_x->pacing_rate_update_delta > 0 && (
            path_x->pacing.rate < path_x->pacing_rate_threshold_low ||
            path_x->pacing.rate > path_x->pacing_rate_threshold_high ||
            path_x->receive_rate_estimate < path_x->receive_rate_threshold_low ||
            path_x->receive_rate_estimate > path_x->receive_rate_threshold_high))) {
        picoquic_refresh_path_quality_thresholds(path_x);
        ret = cnx->callback_fn(cnx, path_x->unique_path_id, NULL, 0, picoquic_callback_path_quality_changed, cnx->callback_ctx, NULL);
    }
    return ret;
}

static void picoquic_get_path_quality_from_context(picoquic_path_t* path_x, picoquic_path_quality_t* quality)
{
    picoquic_refresh_path_quality_thresholds(path_x);
    quality->cwin = path_x->cwin;
    quality->rtt = path_x->smoothed_rtt;
    quality->rtt_sample = path_x->rtt_sample;
    quality->rtt_min = path_x->rtt_min;
    quality->rtt_max = path_x->rtt_max;
    quality->rtt_variant = path_x->rtt_variant;
    quality->pacing_rate = path_x->pacing.rate;
    quality->receive_rate_estimate = path_x->receive_rate_estimate;
    quality->sent = picoquic_get_sequence_number(path_x->cnx, path_x, picoquic_packet_context_application);
    quality->lost = path_x->nb_losses_found;
    quality->timer_losses = path_x->nb_timer_losses;
    quality->spurious_losses = path_x->nb_spurious;
    quality->max_spurious_rtt = path_x->max_spurious_rtt;
    quality->max_reorder_delay = path_x->max_reorder_delay;
    quality->max_reorder_gap = path_x->max_reorder_gap;
    quality->bytes_in_transit = path_x->bytes_in_transit;
}

int picoquic_get_path_quality(picoquic_cnx_t* cnx, uint64_t unique_path_id, picoquic_path_quality_t* quality)
{
    int ret = -1;
    int path_id = picoquic_get_path_id_from_unique(cnx, unique_path_id);
    if (path_id >= 0) {
        picoquic_path_t* path_x = cnx->path[path_id];
        picoquic_get_path_quality_from_context(path_x, quality);
        ret = 0;
    }
    return ret;
}

void picoquic_get_default_path_quality(picoquic_cnx_t* cnx, picoquic_path_quality_t* quality)
{
    picoquic_path_t* path_x = cnx->path[0];
    picoquic_get_path_quality_from_context(path_x, quality);
}

void picoquic_subscribe_to_quality_update_per_path_context(picoquic_path_t * path_x,
    uint64_t pacing_rate_delta, uint64_t rtt_delta)
{
    path_x->pacing_rate_update_delta = pacing_rate_delta;
    path_x->rtt_update_delta = rtt_delta;
    picoquic_refresh_path_quality_thresholds(path_x);
}

int picoquic_subscribe_to_quality_update_per_path(picoquic_cnx_t* cnx, uint64_t unique_path_id,
    uint64_t pacing_rate_delta, uint64_t rtt_delta)
{
    int ret = 0;

    cnx->is_path_quality_update_requested = 1;

    int path_id = picoquic_get_path_id_from_unique(cnx, unique_path_id);
    if (path_id >= 0) {
        picoquic_subscribe_to_quality_update_per_path_context(cnx->path[path_id],
            pacing_rate_delta, rtt_delta);
    }
    else {
        ret = -1;
    }

    return ret;
}

void picoquic_subscribe_to_quality_update(picoquic_cnx_t* cnx, uint64_t pacing_rate_delta, uint64_t rtt_delta)
{
    cnx->pacing_rate_update_delta = pacing_rate_delta;
    cnx->rtt_update_delta = rtt_delta;
    cnx->is_path_quality_update_requested = 1;

    for (int i = 0; i < cnx->nb_paths; i++) {
        picoquic_subscribe_to_quality_update_per_path_context(cnx->path[i],
            pacing_rate_delta, rtt_delta);
    }
}

void picoquic_default_quality_update(picoquic_quic_t* quic, uint64_t pacing_rate_delta, uint64_t rtt_delta)
{
    quic->pacing_rate_update_delta = pacing_rate_delta;
    quic->rtt_update_delta = rtt_delta;
}

int picoquic_refresh_path_connection_id(picoquic_cnx_t* cnx, uint64_t unique_path_id)
{
    int ret = -1;
    int path_id = picoquic_get_path_id_from_unique(cnx, unique_path_id);
    if (path_id >= 0) {
        ret = picoquic_renew_path_connection_id(cnx, cnx->path[path_id]);
    }
    return ret;
}

int picoquic_set_stream_path_affinity(picoquic_cnx_t* cnx, uint64_t stream_id, uint64_t unique_path_id)
{
    int ret = 0;
    picoquic_stream_head_t* stream = picoquic_find_stream(cnx, stream_id);

    if (stream == NULL) {
        ret = -1;
    } else if (unique_path_id == UINT64_MAX) {
        stream->affinity_path = NULL;
    }
    else {
        int path_id = picoquic_get_path_id_from_unique(cnx, unique_path_id);
        if (path_id >= 0) {
            stream->affinity_path = cnx->path[path_id];
        }
        else {
            ret = -1;
        }
    }
    return ret;
}

int picoquic_set_path_status(picoquic_cnx_t* cnx, uint64_t unique_path_id, picoquic_path_status_enum status)
{
    int ret = 0;
    int path_id = picoquic_get_path_id_from_unique(cnx, unique_path_id);
    if (path_id >= 0) {
        cnx->path[path_id]->path_is_standby = (status != picoquic_path_status_available);
        ret = picoquic_queue_path_available_or_standby_frame(cnx, cnx->path[path_id], status);
    }
    return ret;
}

int picoquic_get_path_addr(picoquic_cnx_t* cnx, uint64_t unique_path_id, int local, struct sockaddr_storage* addr)
{
    int ret = 0;
    int path_id = picoquic_get_path_id_from_unique(cnx, unique_path_id);
    if (path_id >= 0) {
        struct sockaddr_storage* local_addr = NULL;
        switch (local) {
        case 1:
            local_addr = &cnx->path[path_id]->local_addr;
            break;
        case 2:
            local_addr = &cnx->path[path_id]->peer_addr;
            break;
        case 3:
            local_addr = &cnx->path[path_id]->observed_addr;
            break;
        default:
            break;
        }
        if (local_addr == NULL) {
            ret = -1;
        }
        else {
            picoquic_store_addr(addr, (struct sockaddr*)local_addr);
        }
    }

    return ret;
}

void picoquic_update_peer_addr(picoquic_path_t* path_x, const struct sockaddr* peer_addr)
{
    /* Set the addresses */
    picoquic_store_addr(&path_x->peer_addr, peer_addr);
    /* Keep track of the update */
    path_x->observed_addr_acked = 0;
    path_x->nb_observed_repeat = 0;
}

/* Reset the path MTU, for example if too many packet losses are detected */
void picoquic_reset_path_mtu(picoquic_path_t* path_x)
{
    /* Re-initialize the MTU */
    picoquic_quic_t* quic = path_x->cnx->quic;
    int is_ipv4 = path_x->peer_addr.ss_family == 0 || path_x->peer_addr.ss_family == AF_INET;
    if (is_ipv4 && quic->initial_send_mtu_ipv4 > 0) {
        path_x->send_mtu = quic->initial_send_mtu_ipv4;
    } else if (!is_ipv4 && quic->initial_send_mtu_ipv6 > 0) {
        path_x->send_mtu = quic->initial_send_mtu_ipv6;
    } else {
        path_x->send_mtu = (is_ipv4) ? PICOQUIC_INITIAL_MTU_IPV4 : PICOQUIC_INITIAL_MTU_IPV6;
    }

    if (path_x->send_mtu > quic->mtu_max) {
        DBG_PRINTF("path MTU too large: send_mtu %d > mtu_max\n", path_x->send_mtu, quic->mtu_max);
    }

    /* Reset the MTU discovery context */
    path_x->send_mtu_max_tried = 0;
    path_x->mtu_probe_sent = 0;
}

/* Manage ACK context and Packet context */
void picoquic_init_ack_ctx(picoquic_cnx_t* cnx, picoquic_ack_context_t* ack_ctx)
{
    picoquic_sack_list_init(&ack_ctx->sack_list);
    ack_ctx->time_stamp_largest_received = UINT64_MAX;
    ack_ctx->act[0].highest_ack_sent = 0;
    ack_ctx->act[0].highest_ack_sent_time = cnx->start_time;
    ack_ctx->act[0].ack_needed = 0;
    ack_ctx->act[1].highest_ack_sent = 0;
    ack_ctx->act[1].highest_ack_sent_time = cnx->start_time;
    ack_ctx->act[1].ack_needed = 0;
}

void picoquic_init_packet_ctx(picoquic_cnx_t* cnx, picoquic_packet_context_t* pkt_ctx, picoquic_packet_context_enum pc)
{
    if (cnx->quic->random_initial && 
        (pc == picoquic_packet_context_initial || cnx->quic->random_initial > 1)){
        pkt_ctx->send_sequence = picoquic_crypto_uniform_random(cnx->quic, PICOQUIC_PN_RANDOM_RANGE) +
            PICOQUIC_PN_RANDOM_MIN;
    }
    else {
        pkt_ctx->send_sequence = 0;
    }
    pkt_ctx->pending_last = NULL;
    pkt_ctx->pending_first = NULL;
    pkt_ctx->highest_acknowledged = pkt_ctx->send_sequence - 1;
    pkt_ctx->latest_time_acknowledged = cnx->start_time;
    pkt_ctx->highest_acknowledged_time = cnx->start_time;
}

/*
 * Manage the stash of connection IDs sent by the peer 
 */
picoquic_remote_cnxid_stash_t* picoquic_find_or_create_remote_cnxid_stash(picoquic_cnx_t* cnx, uint64_t unique_path_id, int do_create)
{
    picoquic_remote_cnxid_stash_t* remote_cnxid_stash = cnx->first_remote_cnxid_stash;
    picoquic_remote_cnxid_stash_t** p_previous = &cnx->first_remote_cnxid_stash;

    while (remote_cnxid_stash != NULL && remote_cnxid_stash->unique_path_id != unique_path_id) {
        p_previous = &remote_cnxid_stash->next_stash;
        remote_cnxid_stash = remote_cnxid_stash->next_stash;
    }

    if (remote_cnxid_stash == NULL && do_create) {
        remote_cnxid_stash = (picoquic_remote_cnxid_stash_t*)malloc(sizeof(picoquic_remote_cnxid_stash_t));
        if (remote_cnxid_stash != NULL) {
            memset(remote_cnxid_stash, 0, sizeof(picoquic_remote_cnxid_stash_t));
            remote_cnxid_stash->unique_path_id = unique_path_id;
            *p_previous = remote_cnxid_stash;
        }
    }

    return remote_cnxid_stash;
}

int picoquic_init_cnxid_stash(picoquic_cnx_t* cnx)
{
    int ret = 0;
    picoquic_remote_cnxid_stash_t* remote_cnxid_stash = picoquic_find_or_create_remote_cnxid_stash(cnx, 0, 1);
    if (remote_cnxid_stash == NULL || remote_cnxid_stash->cnxid_stash_first != NULL) {
        ret = PICOQUIC_TRANSPORT_INTERNAL_ERROR;
    }
    else {
        remote_cnxid_stash->cnxid_stash_first = (picoquic_remote_cnxid_t*)malloc(sizeof(picoquic_remote_cnxid_t));
        cnx->path[0]->p_remote_cnxid = remote_cnxid_stash->cnxid_stash_first;
        if (remote_cnxid_stash->cnxid_stash_first == NULL) {
            ret = PICOQUIC_TRANSPORT_INTERNAL_ERROR;
        }
        else {
            memset(remote_cnxid_stash->cnxid_stash_first, 0, sizeof(picoquic_remote_cnxid_t));
            remote_cnxid_stash->cnxid_stash_first->nb_path_references++;

            /* Initialize the reset secret to a random value. This
            * will prevent spurious matches to an all zero value, for example.
            * The real value will be set when receiving the transport parameters.
            */
            picoquic_public_random(remote_cnxid_stash->cnxid_stash_first->reset_secret, PICOQUIC_RESET_SECRET_SIZE);
        }
    }
    return ret;
}

uint64_t picoquic_add_remote_cnxid_to_stash(picoquic_cnx_t* cnx, picoquic_remote_cnxid_stash_t* remote_cnxid_stash, uint64_t retire_before,
    const uint64_t sequence, const uint8_t cid_length, const uint8_t* cnxid_bytes,
    const uint8_t* secret_bytes, picoquic_remote_cnxid_t** pstashed)
{
    int ret = 0;
    int is_duplicate = 0;
    size_t nb_cid_received = 0;
    picoquic_connection_id_t cnx_id;
    picoquic_remote_cnxid_t* next_stash = remote_cnxid_stash->cnxid_stash_first;
    picoquic_remote_cnxid_t* last_stash = NULL;
    picoquic_remote_cnxid_t* stashed = NULL;
    int nb_cid_retired_before = 0;

    if (retire_before < remote_cnxid_stash->retire_cnxid_before) {
        retire_before = remote_cnxid_stash->retire_cnxid_before;
    }

    /* verify the format */
    if (picoquic_parse_connection_id(cnxid_bytes, cid_length, &cnx_id) == 0) {
        ret = PICOQUIC_TRANSPORT_FRAME_FORMAT_ERROR;
    }

    if (ret == 0 && cnx->path[0]->p_remote_cnxid->cnx_id.id_len == 0) {
        /* Protocol error. The peer is using null length cnx_id */
        ret = PICOQUIC_TRANSPORT_PROTOCOL_VIOLATION;
    }

    while (ret == 0 && is_duplicate == 0 && next_stash != NULL) {
        if (picoquic_compare_connection_id(&cnx_id, &next_stash->cnx_id) == 0)
        {
            if (next_stash->sequence == sequence &&
                cnx_id.id_len == next_stash->cnx_id.id_len &&
                (cnx_id.id_len == 0 || memcmp(cnx_id.id, next_stash->cnx_id.id, cnx_id.id_len) == 0) &&
                memcmp(secret_bytes, next_stash->reset_secret, PICOQUIC_RESET_SECRET_SIZE) == 0) {
                is_duplicate = 1;
            }
            else {
                ret = PICOQUIC_TRANSPORT_PROTOCOL_VIOLATION;
            }
            break;
        }
        else if (next_stash->sequence == sequence) {
            ret = PICOQUIC_TRANSPORT_PROTOCOL_VIOLATION;
        }
        else if (memcmp(secret_bytes, next_stash->reset_secret, PICOQUIC_RESET_SECRET_SIZE) == 0) {
            ret = PICOQUIC_TRANSPORT_PROTOCOL_VIOLATION;
        }
        else {
            if (next_stash->sequence < retire_before || next_stash->retire_sent) {
                nb_cid_retired_before++;
            }
            nb_cid_received++;
        }
        last_stash = next_stash;
        next_stash = next_stash->next;
    }

    if (ret == 0 && is_duplicate == 0) {
        if (nb_cid_received >= cnx->local_parameters.active_connection_id_limit + nb_cid_retired_before ||
            nb_cid_received >= 2*cnx->local_parameters.active_connection_id_limit) {
            ret = PICOQUIC_TRANSPORT_CONNECTION_ID_LIMIT_ERROR;
        }
        else {
            stashed = (picoquic_remote_cnxid_t*)malloc(sizeof(picoquic_remote_cnxid_t));

            if (stashed == NULL) {
                ret = PICOQUIC_TRANSPORT_INTERNAL_ERROR;
            }
            else {
                memset(stashed, 0, sizeof(picoquic_remote_cnxid_t));
                (void)picoquic_parse_connection_id(cnxid_bytes, cid_length, &stashed->cnx_id);
                stashed->sequence = sequence;
                memcpy(stashed->reset_secret, secret_bytes, PICOQUIC_RESET_SECRET_SIZE);
                stashed->next = NULL;

                if (last_stash == NULL) {
                    remote_cnxid_stash->cnxid_stash_first = stashed;
                }
                else {
                    last_stash->next = stashed;
                }
            }
        }
    }

    /* the return argument is only used in tests */

    if (pstashed != NULL) {
        *pstashed = stashed;
    }

    return ret;
}

uint64_t picoquic_stash_remote_cnxid(picoquic_cnx_t* cnx, uint64_t retire_before_next,
    const uint64_t unique_path_id, const uint64_t sequence, const uint8_t cid_length, const uint8_t* cnxid_bytes,
    const uint8_t* secret_bytes, picoquic_remote_cnxid_t** pstashed)
{
    uint64_t transport_error = 0;
    picoquic_remote_cnxid_stash_t* remote_cnxid_stash = picoquic_find_or_create_remote_cnxid_stash(cnx, unique_path_id, 1);

    if (remote_cnxid_stash == NULL) {
        transport_error = PICOQUIC_TRANSPORT_INTERNAL_ERROR;
    }
    else {
        transport_error = picoquic_add_remote_cnxid_to_stash(cnx, remote_cnxid_stash, retire_before_next,
            sequence, cid_length, cnxid_bytes, secret_bytes, pstashed);
    }
    return transport_error;
}

picoquic_remote_cnxid_t* picoquic_remove_cnxid_from_stash(picoquic_cnx_t* cnx, picoquic_remote_cnxid_stash_t* remote_cnxid_stash,
    picoquic_remote_cnxid_t* removed, picoquic_remote_cnxid_t* previous)
{
    picoquic_remote_cnxid_t* stashed = NULL;

    if (cnx != NULL && remote_cnxid_stash != NULL && remote_cnxid_stash->cnxid_stash_first != NULL && removed != NULL) {
        stashed = remote_cnxid_stash->cnxid_stash_first;
        /* Verify the value of the previous pointer */
        if (previous != NULL) {
            if (previous->next == removed) {
                stashed = removed;
            }
            else {
                previous = NULL;
            }
        }
        /* If the previous pointer was NULL or invalid, reset it */
        if (previous == NULL) {
            while (stashed != NULL && removed != stashed) {
                previous = stashed;
                stashed = stashed->next;
            }
        }
        /* Actually remove the element from the stash */
        if (stashed != NULL) {
            stashed = stashed->next;
            if (previous == NULL) {
                remote_cnxid_stash->cnxid_stash_first = stashed;
            }
            else {
                previous->next = stashed;
            }
            free(removed);
        }
    }
    return stashed;
}

picoquic_remote_cnxid_t* picoquic_remove_stashed_cnxid(picoquic_cnx_t* cnx, uint64_t unique_path_id,
    picoquic_remote_cnxid_t* removed, picoquic_remote_cnxid_t* previous)
{
    picoquic_remote_cnxid_stash_t* remote_cnxid_stash = picoquic_find_or_create_remote_cnxid_stash(cnx,
        (cnx->is_multipath_enabled)?unique_path_id:0, 0);

    return picoquic_remove_cnxid_from_stash(cnx, remote_cnxid_stash, removed, previous);
}

picoquic_remote_cnxid_t* picoquic_get_cnxid_from_stash(picoquic_remote_cnxid_stash_t* stash)
{
    picoquic_remote_cnxid_t* stashed = NULL;
    if (stash != NULL) {
        stashed = stash->cnxid_stash_first;
        while (stashed != NULL && stashed->cnx_id.id_len > 0
            && (stashed->nb_path_references != 0 || stashed->needs_removal)) {
            stashed = stashed->next;
        }
    }
    return stashed;
}

picoquic_remote_cnxid_t* picoquic_obtain_stashed_cnxid(picoquic_cnx_t* cnx, uint64_t unique_path_id)
{
    picoquic_remote_cnxid_stash_t* stash = picoquic_find_or_create_remote_cnxid_stash(cnx, unique_path_id, 0);
    picoquic_remote_cnxid_t* stashed = picoquic_get_cnxid_from_stash(stash);
    
    return stashed;
}

void picoquic_dereference_stashed_cnxid(picoquic_cnx_t* cnx, picoquic_path_t * path_x, int is_deleting_cnx)
{
    if (path_x->p_remote_cnxid != NULL) {
        if (path_x->p_remote_cnxid->nb_path_references <= 1) {
            uint64_t unique_path_id = (cnx->is_multipath_enabled) ? path_x->unique_path_id : 0;
            if (!is_deleting_cnx && !path_x->p_remote_cnxid->retire_sent) {
                /* if this was the last reference, retire the old cnxid */
                if (picoquic_queue_retire_connection_id_frame(cnx, unique_path_id, path_x->p_remote_cnxid->sequence) != 0) {
                    DBG_PRINTF("Could not properly retire CID[%" PRIu64 "]", path_x->p_remote_cnxid->sequence);
                }
                else {
                    path_x->p_remote_cnxid->retire_sent = 1;
                }
            }
            if (is_deleting_cnx || path_x->p_remote_cnxid->retire_acked) {
                /* Delete and perhaps recycle the queued packets */
                (void)picoquic_remove_stashed_cnxid(cnx, path_x->unique_path_id, path_x->p_remote_cnxid, NULL);
            }
        }
        else {
            path_x->p_remote_cnxid->nb_path_references--;
        }
    }
    path_x->p_remote_cnxid = NULL;
}

uint64_t picoquic_remove_not_before_from_stash(picoquic_cnx_t* cnx, picoquic_remote_cnxid_stash_t* cnxid_stash, uint64_t not_before, uint64_t current_time)
{
    uint64_t ret = 0;
    if (cnxid_stash != NULL) {

        picoquic_remote_cnxid_t* next_stash = cnxid_stash->cnxid_stash_first;
        picoquic_remote_cnxid_t* previous_stash = NULL;

        while (ret == 0 && next_stash != NULL) {
            next_stash->needs_removal |= (next_stash->sequence < not_before);
            if (next_stash->needs_removal && next_stash->nb_path_references == 0) {
                if (!next_stash->retire_sent) {
                    ret = picoquic_queue_retire_connection_id_frame(cnx, cnxid_stash->unique_path_id, next_stash->sequence);
                    if (ret == 0) {
                        next_stash->retire_sent = 1;
                    }
                }
                if (ret == 0 && next_stash->retire_acked) {
                    next_stash = picoquic_remove_cnxid_from_stash(cnx, cnxid_stash, next_stash, previous_stash);
                }
                else {
                    previous_stash = next_stash;
                    next_stash = next_stash->next;
                }
            }
            else {
                previous_stash = next_stash;
                next_stash = next_stash->next;
            }
        }

        /* We need to stop transmitting data to the old CID. But we cannot just delete
        * the correspondng paths,because there may be some data in transit. We must
        * also ensure that at least one default path migrates successfully to a
        * valid CID. As long as new CID are available, we can simply replace the
        * old one by a new one. If no CID is available, the old path should be marked
        * as failing, and thus scheduled for deletion after a time-out */

        if (cnx->is_multipath_enabled) {
            int path_id = picoquic_find_path_by_unique_id(cnx, cnxid_stash->unique_path_id);
            if (path_id >= 0) {
                if (cnx->path[path_id]->p_remote_cnxid->sequence < not_before &&
                    cnx->path[path_id]->p_remote_cnxid->cnx_id.id_len > 0 &&
                    !cnx->path[path_id]->path_is_demoted) {
                    ret = picoquic_renew_connection_id(cnx, path_id);
                    if (ret != 0) {
                        DBG_PRINTF("Renew CNXID returns %x\n", ret);
                        if (path_id == 0) {
                            ret = PICOQUIC_TRANSPORT_PROTOCOL_VIOLATION;
                        }
                        else {
                            ret = 0;
                            picoquic_demote_path(cnx, path_id, current_time, 0, NULL);
                        }
                    }
                }
            }
        }
        else {
            for (int i = 0; ret == 0 && i < cnx->nb_paths; i++) {
                if (cnx->path[i]->p_remote_cnxid->sequence < not_before &&
                    cnx->path[i]->p_remote_cnxid->cnx_id.id_len > 0 &&
                    !cnx->path[i]->path_is_demoted) {
                    ret = picoquic_renew_connection_id(cnx, i);
                    if (ret != 0) {
                        DBG_PRINTF("Renew CNXID returns %x\n", ret);
                        if (i == 0) {
                            ret = PICOQUIC_TRANSPORT_PROTOCOL_VIOLATION;
                        }
                        else {
                            ret = 0;
                            picoquic_demote_path(cnx, i, current_time, 0, NULL);
                        }
                    }
                }
            }
        }
    }

    return ret;
}

uint64_t picoquic_remove_not_before_cid(picoquic_cnx_t* cnx, uint64_t unique_path_id, uint64_t not_before, uint64_t current_time)
{
    uint64_t transport_error = 0;
    picoquic_remote_cnxid_stash_t* cnxid_stash = picoquic_find_or_create_remote_cnxid_stash(cnx, unique_path_id, 0);

    if (cnxid_stash != NULL) {
        transport_error = picoquic_remove_not_before_from_stash(cnx, cnxid_stash, not_before, current_time);
    }

    return transport_error;
}

void picoquic_delete_remote_cnxid_stash(picoquic_cnx_t* cnx, picoquic_remote_cnxid_stash_t* cnxid_stash)
{
    picoquic_remote_cnxid_stash_t* previous = cnx->first_remote_cnxid_stash;

    while (cnxid_stash->cnxid_stash_first != NULL) {
        picoquic_remove_cnxid_from_stash(cnx, cnxid_stash, cnxid_stash->cnxid_stash_first, NULL);
    }

    if (previous == cnxid_stash) {
        cnx->first_remote_cnxid_stash = cnxid_stash->next_stash;
    }
    else {
        while (previous != NULL) {
            if (previous->next_stash == cnxid_stash) {
                previous->next_stash = cnxid_stash->next_stash;
                break;
            }
            previous = previous->next_stash;
        }
    }
    free(cnxid_stash);
}

void picoquic_delete_remote_cnxid_stashes(picoquic_cnx_t* cnx)
{
    while (cnx->first_remote_cnxid_stash != NULL) {
        picoquic_delete_remote_cnxid_stash(cnx, cnx->first_remote_cnxid_stash);
    }
}

/* Start using a new connection ID for the existing path
 */
int picoquic_renew_path_connection_id(picoquic_cnx_t* cnx, picoquic_path_t* path_x)
{
    int ret = 0;
    picoquic_remote_cnxid_t* stashed = NULL;
    uint64_t cid_path_id = (cnx->is_multipath_enabled) ? path_x->unique_path_id : 0;
    picoquic_remote_cnxid_stash_t* cnxid_stash = picoquic_find_or_create_remote_cnxid_stash(cnx, cid_path_id, 0);

    if (cnxid_stash == NULL) {
        ret = PICOQUIC_ERROR_CNXID_NOT_AVAILABLE;
    }
    else if ((cnx->remote_parameters.migration_disabled != 0 &&
            path_x->p_remote_cnxid != NULL &&
            path_x->p_remote_cnxid->sequence >= cnxid_stash->retire_cnxid_before) ||
            cnx->local_parameters.migration_disabled != 0) {
            /* Do not switch cnx_id if migration is disabled */
            ret = PICOQUIC_ERROR_MIGRATION_DISABLED;
        }
    else {
        stashed = picoquic_obtain_stashed_cnxid(cnx, cid_path_id);

        if (stashed == NULL) {
            ret = PICOQUIC_ERROR_CNXID_NOT_AVAILABLE;
        }
        else if (path_x->p_remote_cnxid != NULL &&
            stashed->sequence == path_x->p_remote_cnxid->sequence) {
            /* If the available cnx_id is same as old one, we do nothing */
            ret = PICOQUIC_ERROR_CNXID_NOT_AVAILABLE;
        }
        else {
            picoquic_dereference_stashed_cnxid(cnx, path_x, 0);

            /* Install the new value */
            path_x->p_remote_cnxid = stashed;
            stashed->nb_path_references++;

            /* If default path, reset the secret pointer */
            if (path_x == cnx->path[0]) {
                ret = picoquic_register_net_secret(cnx);
            }
        }
    }

    return ret;
}

int picoquic_renew_connection_id(picoquic_cnx_t* cnx, int path_id)
{
    int ret;

    if (path_id >= cnx->nb_paths) {
        ret = -1;
    }
    else {
        ret = picoquic_renew_path_connection_id(cnx, cnx->path[path_id]);
    }

    return ret;
}

/* stream data splay management */
int64_t picoquic_stream_data_node_compare(void* l, void* r)
{
    /* Offset values are from 0 to 2^62-1, which means we are not worried with rollover */
    return ((picoquic_stream_data_node_t*)l)->offset - ((picoquic_stream_data_node_t*)r)->offset;
}

picosplay_node_t* picoquic_stream_data_node_create(void* value)
{
    return &((picoquic_stream_data_node_t*)value)->stream_data_node;
}


void* picoquic_stream_data_node_value(picosplay_node_t* node)
{
    return (void*)((char*)node - offsetof(struct st_picoquic_stream_data_node_t, stream_data_node));
}

void picoquic_stream_data_node_recycle(picoquic_stream_data_node_t* stream_data)
{
    if (stream_data->quic->nb_data_nodes_in_pool < PICOQUIC_MAX_PACKETS_IN_POOL) {
        stream_data->next_stream_data = stream_data->quic->p_first_data_node;
        stream_data->quic->p_first_data_node = stream_data;
        stream_data->quic->nb_data_nodes_in_pool++;
    }
    else {
        stream_data->quic->nb_data_nodes_allocated--;
        free(stream_data);
    }
}

void picoquic_stream_data_node_delete(void* tree, picosplay_node_t* node)
{
    picoquic_stream_data_node_t* stream_data = (picoquic_stream_data_node_t*)picoquic_stream_data_node_value(node);

    picoquic_stream_data_node_recycle(stream_data);
}

picoquic_stream_data_node_t* picoquic_stream_data_node_alloc(picoquic_quic_t* quic)
{
    picoquic_stream_data_node_t* stream_data = quic->p_first_data_node;
    
    if (stream_data == NULL) {
        stream_data = (picoquic_stream_data_node_t*)
            malloc(sizeof(picoquic_stream_data_node_t));

        if (stream_data != NULL) {
            /* It might be sufficient to zero the metadata, but zeroing everything
             * appears safer, and does not confuse checkers like valgrind.
             */
            memset(stream_data, 0, sizeof(picoquic_stream_data_node_t));
            stream_data->quic = quic;
            quic->nb_data_nodes_allocated++;
            if (quic->nb_data_nodes_allocated > quic->nb_data_nodes_allocated_max) {
                quic->nb_data_nodes_allocated_max = quic->nb_data_nodes_allocated;
            }
        }
    }
    else {
        quic->p_first_data_node = stream_data->next_stream_data;
        stream_data->next_stream_data = NULL;
        stream_data->bytes = NULL;
        quic->nb_data_nodes_in_pool--;
    }

    return stream_data;
}


/* Stream splay management */

static int64_t picoquic_stream_node_compare(void *l, void *r)
{
    /* STream values are from 0 to 2^62-1, which means we are not worried with rollover */
    return ((picoquic_stream_head_t*)l)->stream_id - ((picoquic_stream_head_t*)r)->stream_id;
}

static picosplay_node_t * picoquic_stream_node_create(void * value)
{
    return &((picoquic_stream_head_t *)value)->stream_node;
}


static void * picoquic_stream_node_value(picosplay_node_t * node)
{
    return (void*)((char*)node - offsetof(struct st_picoquic_stream_head_t, stream_node));
}

void picoquic_clear_stream(picoquic_stream_head_t* stream)
{
    picoquic_stream_queue_node_t* ready = stream->send_queue;
    picoquic_stream_queue_node_t* next;

    while ((next = ready) != NULL) {
        ready = next->next_stream_data;
        if (next->bytes != NULL) {
            free(next->bytes);
        }
        free(next);
    }
    stream->send_queue = NULL;
    if (stream->is_output_stream) {
        picoquic_remove_output_stream(stream->cnx, stream);
    }
    picosplay_empty_tree(&stream->stream_data_tree);
    picoquic_sack_list_free(&stream->sack_list);
}


static void picoquic_stream_node_delete(void * tree, picosplay_node_t * node)
{
    picoquic_stream_head_t * stream = picoquic_stream_node_value(node);

    picoquic_clear_stream(stream);

    free(stream);
}

/* Management of streams */

picoquic_stream_head_t * picoquic_stream_from_node(picosplay_node_t * node)
{
#ifdef TOO_CAUTIOUS
    return(picoquic_stream_head_t *)((node == NULL)?NULL:picoquic_stream_node_value(node));
#else
    return (picoquic_stream_head_t *)node;
#endif
}

picoquic_stream_head_t * picoquic_first_stream(picoquic_cnx_t* cnx)
{
#ifdef TOO_CAUTIOUS
    return picoquic_stream_from_node(picosplay_first(&cnx->stream_tree));
#else
    return (picoquic_stream_head_t *)picosplay_first(&cnx->stream_tree);
#endif
}

picoquic_stream_head_t * picoquic_last_stream(picoquic_cnx_t* cnx)
{
#ifdef TOO_CAUTIOUS
    return picoquic_stream_from_node(picosplay_last(&cnx->stream_tree));
#else
    return (picoquic_stream_head_t *)picosplay_last(&cnx->stream_tree);
#endif
}

int picoquic_compare_stream_priority(picoquic_stream_head_t * stream, picoquic_stream_head_t * other) {
    int ret = 1;
    if (stream->stream_priority < other->stream_priority) {
        ret = -1;
    }
    else if (stream->stream_priority == other->stream_priority) {
        if (stream->stream_id < other->stream_id) {
            ret = -1;
        }
        else if (stream->stream_id == other->stream_id) {
            ret = 0;
        }
    }
    return ret;
}

/* This code assumes that the stream is not currently present in the output stream.
 */
void picoquic_insert_output_stream(picoquic_cnx_t* cnx, picoquic_stream_head_t* stream)
{
    if (stream->is_output_stream == 0)  
    {
        if (IS_CLIENT_STREAM_ID(stream->stream_id) == cnx->client_mode) {
            if (stream->stream_id > ((IS_BIDIR_STREAM_ID(stream->stream_id)) ? cnx->max_stream_id_bidir_remote : cnx->max_stream_id_unidir_remote)) {
                return;
            }
        }

        if (cnx->last_output_stream == NULL) {
            /* insert first stream */
            cnx->last_output_stream = stream;
            cnx->first_output_stream = stream;
        }
        else if (picoquic_compare_stream_priority(stream, cnx->last_output_stream) >= 0) {
            /* insert after last stream. Common case for most applications. */
            stream->previous_output_stream = cnx->last_output_stream;
            cnx->last_output_stream->next_output_stream = stream;
            cnx->last_output_stream = stream;
        }
        else {
            picoquic_stream_head_t* current = cnx->first_output_stream;

            while (current != NULL) {
                int cmp = picoquic_compare_stream_priority(stream, current);

                if (cmp < 0) {
                    /* insert before the current stream, then break */
                    stream->previous_output_stream = current->previous_output_stream;
                    if (stream->previous_output_stream == NULL) {
                        cnx->first_output_stream = stream;
                    }
                    else {
                        stream->previous_output_stream->next_output_stream = stream;
                    }
                    current->previous_output_stream = stream;
                    stream->next_output_stream = current;
                    break;
                }
                else if (cmp == 0) {
                    /* Stream is already there. This is unexpected */
                    break;
                }
                else {
                    current = current->next_output_stream;
                }
            }
            if (current == NULL) {
                /* insert after last stream */
                stream->previous_output_stream = cnx->last_output_stream;
                cnx->last_output_stream->next_output_stream = stream;
                cnx->last_output_stream = stream;
            }
        }

        stream->is_output_stream = 1;
    }
}

void picoquic_remove_output_stream(picoquic_cnx_t* cnx, picoquic_stream_head_t * stream)
{
    if (stream->is_output_stream) {
        stream->is_output_stream = 0;

        if (stream->previous_output_stream == NULL) {
            cnx->first_output_stream = stream->next_output_stream;
        }
        else {
            stream->previous_output_stream->next_output_stream = stream->next_output_stream;
        }

        if (stream->next_output_stream == NULL) {
            cnx->last_output_stream = stream->previous_output_stream;
        }
        else {
            stream->next_output_stream->previous_output_stream = stream->previous_output_stream;
        }
        stream->previous_output_stream = NULL;
        stream->next_output_stream = NULL;
    }
}

/* Reorder streams by priorities and rank.
 * A stream is deemed out of order if:
 * - the previous stream in the list has a higher priority, or
 * - the new stream has a lower priority.
 */
void picoquic_reorder_output_stream(picoquic_cnx_t* cnx, picoquic_stream_head_t* stream)
{
    if (stream->is_output_stream) {
        if ((stream->previous_output_stream != NULL &&
            picoquic_compare_stream_priority(stream, stream->previous_output_stream) < 0) ||
            (stream->next_output_stream != NULL &&
                picoquic_compare_stream_priority(stream, stream->next_output_stream) > 0)) {
            picoquic_remove_output_stream(cnx, stream);
            stream->is_output_stream = 0;
            picoquic_insert_output_stream(cnx, stream);
        }
    }
}

picoquic_stream_head_t * picoquic_next_stream(picoquic_stream_head_t * stream)
{
    return (picoquic_stream_head_t *)picosplay_next((picosplay_node_t *)stream);
}

picoquic_stream_head_t* picoquic_find_stream(picoquic_cnx_t* cnx, uint64_t stream_id)
{
    picoquic_stream_head_t target;
    target.stream_id = stream_id;

    return (picoquic_stream_head_t *)picosplay_find(&cnx->stream_tree, (void*)&target);
}

void picoquic_add_output_streams(picoquic_cnx_t* cnx, uint64_t old_limit, uint64_t new_limit, unsigned int is_bidir)
{
    uint64_t old_rank = STREAM_RANK_FROM_ID(old_limit);
    uint64_t first_new_id = STREAM_ID_FROM_RANK(old_rank + 1ull, cnx->client_mode, !is_bidir);
    picoquic_stream_head_t* stream = picoquic_find_stream(cnx, first_new_id );

    while (stream) {
        if (stream->stream_id > old_limit) {
            if (stream->stream_id > new_limit) {
                break;
            }
            if (IS_LOCAL_STREAM_ID(stream->stream_id, cnx->client_mode) && IS_BIDIR_STREAM_ID(stream->stream_id) == is_bidir) {
                picoquic_insert_output_stream(cnx, stream);
            }
        }
        stream = picoquic_next_stream(stream);
    }
}

picoquic_stream_head_t* picoquic_create_stream(picoquic_cnx_t* cnx, uint64_t stream_id)
{
    picoquic_stream_head_t* stream = (picoquic_stream_head_t*)malloc(sizeof(picoquic_stream_head_t));
    if (stream != NULL) {
        memset(stream, 0, sizeof(picoquic_stream_head_t));
        picoquic_sack_list_init(&stream->sack_list);
    }

    if (stream != NULL){
        int is_output_stream = 0;
        stream->stream_id = stream_id;
        stream->cnx = cnx;

        if (cnx->quic->default_direct_receive_fn != NULL &&
            (IS_BIDIR_STREAM_ID(stream_id) || !IS_LOCAL_STREAM_ID(stream_id, cnx->client_mode))) {
            stream->direct_receive_fn = cnx->quic->default_direct_receive_fn;
            stream->direct_receive_ctx = cnx->quic->default_direct_receive_ctx;
        }

        if (IS_LOCAL_STREAM_ID(stream_id, cnx->client_mode)) {
            if (IS_BIDIR_STREAM_ID(stream_id)) {
                stream->maxdata_local = cnx->local_parameters.initial_max_stream_data_bidi_local;
                stream->maxdata_remote = cnx->remote_parameters.initial_max_stream_data_bidi_remote;
                is_output_stream = stream->stream_id <= cnx->max_stream_id_bidir_remote;

            }
            else {
                stream->maxdata_local = 0;
                stream->maxdata_remote = cnx->remote_parameters.initial_max_stream_data_uni;
                is_output_stream = stream->stream_id <= cnx->max_stream_id_unidir_remote;
            }
        }
        else {
            if (IS_BIDIR_STREAM_ID(stream_id)) {
                stream->maxdata_local = cnx->local_parameters.initial_max_stream_data_bidi_remote;
                stream->maxdata_remote = cnx->remote_parameters.initial_max_stream_data_bidi_local;
                is_output_stream = 1;
            }
            else {
                stream->maxdata_local = cnx->local_parameters.initial_max_stream_data_uni;
                stream->maxdata_remote = 0;
                is_output_stream = 0;
            }
        }

        stream->stream_priority = cnx->quic->default_stream_priority;

        picosplay_init_tree(&stream->stream_data_tree, picoquic_stream_data_node_compare, picoquic_stream_data_node_create, picoquic_stream_data_node_delete, picoquic_stream_data_node_value);

        picosplay_insert(&cnx->stream_tree, stream);
        if (is_output_stream) {
            picoquic_insert_output_stream(cnx, stream);
        }
        else {
            picoquic_remove_output_stream(cnx, stream);
            picoquic_delete_stream_if_closed(cnx, stream);
        }

        if (stream_id >= cnx->next_stream_id[STREAM_TYPE_FROM_ID(stream_id)]) {
            cnx->next_stream_id[STREAM_TYPE_FROM_ID(stream_id)] = NEXT_STREAM_ID_FOR_TYPE(stream_id);
        }
    }

    return stream;
}

void picoquic_delete_stream(picoquic_cnx_t * cnx, picoquic_stream_head_t* stream)
{
    picosplay_delete(&cnx->stream_tree, stream);
}

int picoquic_mark_direct_receive_stream(picoquic_cnx_t* cnx, uint64_t stream_id, picoquic_stream_direct_receive_fn direct_receive_fn, void* direct_receive_ctx)
{
    int ret = 0;
    picoquic_stream_head_t* stream = picoquic_find_stream(cnx, stream_id);
    picoquic_stream_data_node_t* data;

    if (stream == NULL) {
        ret = PICOQUIC_ERROR_INVALID_STREAM_ID;
    }
    else if (!IS_BIDIR_STREAM_ID(stream_id) && IS_LOCAL_STREAM_ID(stream_id, cnx->client_mode)) {
        ret = PICOQUIC_ERROR_INVALID_STREAM_ID;
    }
    else if (direct_receive_fn == NULL) {
        /* This is illegal! */
        ret = PICOQUIC_ERROR_NO_CALLBACK_PROVIDED;
    }
    else {
        stream->direct_receive_fn = direct_receive_fn;
        stream->direct_receive_ctx = direct_receive_ctx;
        /* If there is pending data, pass it. */
        while ((data = (picoquic_stream_data_node_t*)picosplay_first(&stream->stream_data_tree)) != NULL) {
            size_t length = data->length;
            uint64_t offset = data->offset;

            if (offset < stream->consumed_offset) {
                if (offset + length < stream->consumed_offset) {
                    length = 0;
                }
                else {
                    size_t delta_offset = (size_t)(stream->consumed_offset - offset);
                    length -= delta_offset;
                    offset += delta_offset;
                }
            }

            if (length > 0) {
                ret = direct_receive_fn(cnx, stream_id, 0, data->bytes, offset, length, direct_receive_ctx);
            }

            if (ret == 0) {
                picosplay_delete_hint(&stream->stream_data_tree, &data->stream_data_node);
            }
            else {
                break;
            }
        }

        /* If there is a fin offset, pass it. */
        if (ret == 0 && stream->fin_received && !stream->fin_signalled) {
            uint8_t fin_bytes[8];
            ret = direct_receive_fn(cnx, stream_id, 1, fin_bytes, stream->fin_offset, 0, direct_receive_ctx);
        }
    }

    return ret;
}

int picoquic_stream_data_consumed(picoquic_cnx_t* cnx, uint64_t stream_id, uint64_t new_offset)
{
    picoquic_stream_head_t* stream = picoquic_find_stream(cnx, stream_id);
    if (stream == NULL) {
        return PICOQUIC_ERROR_INVALID_STREAM_ID;
    }
    if (new_offset < stream->consumed_offset) {
        return 0;
    }
    if (new_offset > stream->fin_offset) {
        return PICOQUIC_ERROR_UNEXPECTED_STATE;
    }

    if (new_offset > stream->consumed_offset) {
        cnx->data_consumed += (new_offset - stream->consumed_offset);
        stream->consumed_offset = new_offset;
    }

    if (stream->fin_received && !stream->fin_signalled && stream->consumed_offset >= stream->fin_offset) {
        stream->fin_signalled = 1;
    }

    if (!stream->fin_received && !stream->reset_received && 2 * stream->consumed_offset > stream->maxdata_local) {
        cnx->max_stream_data_needed = 1;
    }

    if (stream->fin_signalled) {
        picoquic_delete_stream_if_closed(cnx, stream);
    }

    return 0;
}


/* Management of local CID.
 * Local CID are created and registered on demand.
 */

picoquic_local_cnxid_list_t* picoquic_find_or_create_local_cnxid_list(picoquic_cnx_t* cnx, uint64_t unique_path_id, int do_create)
{
    picoquic_local_cnxid_list_t* local_cnxid_list = cnx->first_local_cnxid_list;
    picoquic_local_cnxid_list_t** p_previous = &cnx->first_local_cnxid_list;

    while (local_cnxid_list != NULL) {
        if (local_cnxid_list->unique_path_id == unique_path_id) {
            break;
        }
        p_previous = &local_cnxid_list->next_list;
        local_cnxid_list = local_cnxid_list->next_list;
    }

    if (local_cnxid_list == NULL && do_create) {
        local_cnxid_list = (picoquic_local_cnxid_list_t*)malloc(sizeof(picoquic_local_cnxid_list_t));
        if (local_cnxid_list != NULL) {
            memset(local_cnxid_list, 0, sizeof(picoquic_local_cnxid_list_t));
            local_cnxid_list->unique_path_id = unique_path_id;
            *p_previous = local_cnxid_list;
            cnx->nb_local_cnxid_lists++;
            if (unique_path_id >= cnx->next_path_id_in_lists) {
                cnx->next_path_id_in_lists = unique_path_id + 1;
            }
        }
    }

    return local_cnxid_list;
}



picoquic_local_cnxid_t* picoquic_create_local_cnxid(picoquic_cnx_t* cnx, 
    uint64_t unique_path_id, picoquic_connection_id_t* suggested_value, uint64_t current_time)
{
    picoquic_local_cnxid_list_t* local_cnxid_list = picoquic_find_or_create_local_cnxid_list(cnx, unique_path_id, 1);
    picoquic_local_cnxid_t* l_cid = NULL;
    int is_unique = 0;

    if (local_cnxid_list != NULL) {
        l_cid = (picoquic_local_cnxid_t*)malloc(sizeof(picoquic_local_cnxid_t));

        if (l_cid != NULL) {
            memset(l_cid, 0, sizeof(picoquic_local_cnxid_t));
            l_cid->create_time = current_time;

            if (cnx->quic->local_cnxid_length == 0) {
                is_unique = 1;
            }
            else {
                for (int i = 0; i < 32; i++) {
                    if (i == 0 && suggested_value != NULL) {
                        l_cid->cnx_id = *suggested_value;
                    }
                    else {
                        picoquic_create_local_cnx_id(cnx->quic, &l_cid->cnx_id, cnx->quic->local_cnxid_length, cnx->initial_cnxid);
                    }

                    if (picoquic_cnx_by_id(cnx->quic, l_cid->cnx_id, NULL) == NULL) {
                        is_unique = 1;
                        break;
                    }
                }
            }

            if (is_unique) {
                picoquic_local_cnxid_t* previous = NULL;
                picoquic_local_cnxid_t* next = local_cnxid_list->local_cnxid_first;

                while (next != NULL) {
                    previous = next;
                    next = next->next;
                }

                if (previous == NULL) {
                    local_cnxid_list->local_cnxid_first = l_cid;
                }
                else {
                    previous->next = l_cid;
                }

                l_cid->sequence = local_cnxid_list->local_cnxid_sequence_next++;
                l_cid->path_id = unique_path_id;
                local_cnxid_list->nb_local_cnxid++;

                if (cnx->quic->local_cnxid_length > 0) {
                    picoquic_register_cnx_id(cnx->quic, cnx, l_cid);
                }
                if (l_cid->sequence == 0) {
                    local_cnxid_list->local_cnxid_oldest_created = current_time;
                }
            }
            else {
                free(l_cid);
                l_cid = NULL;
            }
        }
    }

    return l_cid;
}

void picoquic_delete_local_cnxid_listed(picoquic_cnx_t* cnx,
    picoquic_local_cnxid_list_t* local_cnxid_list, picoquic_local_cnxid_t* l_cid)
{
    picoquic_local_cnxid_t* previous = NULL;

    /* Set l_cid references to NULL in path contexts */
    for (int i = 0; i < cnx->nb_paths; i++) {
        if (cnx->path[i]->p_local_cnxid == l_cid) {
            cnx->path[i]->p_local_cnxid = NULL;
            cnx->path[i]->was_local_cnxid_retired = 1;
        }
    }

    if (l_cid->cnx_id.id_len > 0) {
        /* Remove the registration in hash tables */
        if (l_cid->registered_cnx != NULL) {
            picohash_item* item = &l_cid->hash_item;
            picohash_delete_item(cnx->quic->table_cnx_by_id, item, 0);
        }
        l_cid->registered_cnx = NULL;
    }

    if (local_cnxid_list != NULL) {
        picoquic_local_cnxid_t* next = local_cnxid_list->local_cnxid_first;

        /* Remove from list */
        while (next != NULL) {
            if (next == l_cid) {
                if (previous == NULL) {
                    local_cnxid_list->local_cnxid_first = next->next;
                }
                else {
                    previous->next = next->next;
                }
                local_cnxid_list->nb_local_cnxid--;
                break;
            }
            else {
                previous = next;
                next = next->next;
            }
        }

        /* Update the expired count if necessary */
        if (l_cid->sequence < local_cnxid_list->local_cnxid_retire_before &&
            local_cnxid_list->nb_local_cnxid_expired > 0) {
            local_cnxid_list->nb_local_cnxid_expired--;
        }
    }

    /* Delete and done */
    free(l_cid);
}

void picoquic_delete_local_cnxid(picoquic_cnx_t* cnx,  picoquic_local_cnxid_t* l_cid)
{
    picoquic_local_cnxid_list_t* local_cnxid_list = picoquic_find_or_create_local_cnxid_list(cnx, l_cid->path_id, 0);

    picoquic_delete_local_cnxid_listed(cnx, local_cnxid_list, l_cid);
}

void picoquic_delete_local_cnxid_list(picoquic_cnx_t* cnx, picoquic_local_cnxid_list_t* local_cnxid_list)
{
    while (local_cnxid_list->local_cnxid_first != NULL) {
        picoquic_delete_local_cnxid_listed(cnx, local_cnxid_list, local_cnxid_list->local_cnxid_first);
    }

    if (local_cnxid_list == cnx->first_local_cnxid_list) {
        cnx->first_local_cnxid_list = local_cnxid_list->next_list;
    }
    else {
        picoquic_local_cnxid_list_t* previous = cnx->first_local_cnxid_list;

        while (previous != NULL) {
            if (previous->next_list == local_cnxid_list) {
                previous->next_list = local_cnxid_list->next_list;
            }
            previous = previous->next_list;
        }
    }

    free(local_cnxid_list);
    cnx->nb_local_cnxid_lists--;
}

void picoquic_delete_local_cnxid_lists(picoquic_cnx_t* cnx)
{
    while (cnx->first_local_cnxid_list != NULL) {
        picoquic_delete_local_cnxid_list(cnx, cnx->first_local_cnxid_list);
    }
}

void picoquic_retire_local_cnxid(picoquic_cnx_t* cnx, uint64_t unique_path_id, uint64_t sequence)
{
    picoquic_local_cnxid_list_t* local_cnxid_list = picoquic_find_or_create_local_cnxid_list(cnx, unique_path_id, 0);

    if (local_cnxid_list != NULL) {
        picoquic_local_cnxid_t* local_cnxid = local_cnxid_list->local_cnxid_first;

        while (local_cnxid != NULL) {
            if (local_cnxid->sequence == sequence) {
                break;
            }
            else {
                local_cnxid = local_cnxid->next;
            }
        }

        if (local_cnxid != NULL) {
            picoquic_delete_local_cnxid_listed(cnx, local_cnxid_list, local_cnxid);
        }
    }
}

void picoquic_check_local_cnxid_ttl(picoquic_cnx_t* cnx, picoquic_local_cnxid_list_t* local_cnxid_list, uint64_t current_time, uint64_t * next_wake_time)
{
    if (current_time - local_cnxid_list->local_cnxid_oldest_created >= cnx->quic->local_cnxid_ttl) {
        picoquic_local_cnxid_t* l_cid = local_cnxid_list->local_cnxid_first;
        local_cnxid_list->local_cnxid_oldest_created = current_time;

        local_cnxid_list->nb_local_cnxid_expired = 0;
        while (l_cid != NULL) {
            if ((current_time - l_cid->create_time) >= cnx->quic->local_cnxid_ttl) {
                local_cnxid_list->nb_local_cnxid_expired++;
                if (l_cid->sequence >= local_cnxid_list->local_cnxid_retire_before) {
                    local_cnxid_list->local_cnxid_retire_before = l_cid->sequence + 1;
                }
            }
            else if (l_cid->create_time < local_cnxid_list->local_cnxid_oldest_created) {
                local_cnxid_list->local_cnxid_oldest_created = l_cid->create_time;
            }
            l_cid = l_cid->next;
        }

        cnx->next_wake_time = current_time;
        SET_LAST_WAKE(cnx->quic, PICOQUIC_QUICCTX);
    } else {
        if (*next_wake_time - local_cnxid_list->local_cnxid_oldest_created > cnx->quic->local_cnxid_ttl) {
            *next_wake_time = local_cnxid_list->local_cnxid_oldest_created + cnx->quic->local_cnxid_ttl;
            SET_LAST_WAKE(cnx->quic, PICOQUIC_QUICCTX);
        }
    }
}

picoquic_local_cnxid_t* picoquic_find_local_cnxid(picoquic_cnx_t* cnx, uint64_t unique_path_id, picoquic_connection_id_t* cnxid)
{
    picoquic_local_cnxid_t* local_cnxid = NULL;
    picoquic_local_cnxid_list_t* local_cnxid_list = picoquic_find_or_create_local_cnxid_list(cnx, unique_path_id, 0);
    
    if (local_cnxid_list != NULL && (local_cnxid = local_cnxid_list->local_cnxid_first) != NULL) {
        while (local_cnxid != NULL) {
            if (picoquic_compare_connection_id(&local_cnxid->cnx_id, cnxid) == 0) {
                break;
            }
            else {
                local_cnxid = local_cnxid->next;
            }
        }
    }
    
    return local_cnxid;
}

/* Connection management
 */

picoquic_cnx_t* picoquic_create_cnx(picoquic_quic_t* quic,
    picoquic_connection_id_t initial_cnx_id, picoquic_connection_id_t remote_cnx_id, 
    const struct sockaddr* addr_to, uint64_t start_time, uint32_t preferred_version,
    char const* sni, char const* alpn, char client_mode)
{
    picoquic_cnx_t* cnx = (picoquic_cnx_t*)malloc(sizeof(picoquic_cnx_t));

    if (cnx != NULL) {
        int ret;
        picoquic_local_cnxid_t* cnxid0;

        memset(cnx, 0, sizeof(picoquic_cnx_t));
        cnx->start_time = start_time;
        cnx->phase_delay = INT64_MAX;
        cnx->client_mode = client_mode;
        if (client_mode) {
            if (picoquic_is_connection_id_null(&initial_cnx_id)) {
                picoquic_create_random_cnx_id(quic, &initial_cnx_id, 8);
            }
        }
        cnx->initial_cnxid = initial_cnx_id;
        cnx->quic = quic;
        cnx->pmtud_policy = quic->default_pmtud_policy;
        /* Create the connection ID number 0 */
        cnxid0 = picoquic_create_local_cnxid(cnx, 0, NULL, start_time);

        /* Initialize path updates and quality updates before creating the first path */
        cnx->are_path_callbacks_enabled = quic->are_path_callbacks_enabled;
        cnx->rtt_update_delta = quic->rtt_update_delta;
        cnx->pacing_rate_update_delta = quic->pacing_rate_update_delta;

        /* Initialize the stream data repeat queue */
        picoquic_queue_data_repeat_init(cnx);

        /* Initialize the connection ID stash */
        ret = picoquic_create_path(cnx, start_time, NULL, addr_to, 0);
        if (ret == 0) {
            /* Should return 0, since this is the first path */
            ret = picoquic_init_cnxid_stash(cnx);
        }

        if (ret != 0 || cnxid0 == NULL) {
            picoquic_delete_cnx(cnx);
            /* free(cnx); */
            cnx = NULL;
        } else {
            cnx->next_wake_time = start_time;
            SET_LAST_WAKE(quic, PICOQUIC_QUICCTX);
            picoquic_insert_cnx_in_list(quic, cnx);
            picoquic_insert_cnx_by_wake_time(quic, cnx);
            /* Do not require verification for default path */
            cnx->path[0]->p_local_cnxid = cnxid0;
            cnx->path[0]->challenge_verified = 1;

            cnx->datagram_priority = cnx->quic->default_datagram_priority;
            cnx->high_priority_stream_id = UINT64_MAX;
            for (int i = 0; i < 4; i++) {
                cnx->next_stream_id[i] = i;
            }
            picoquic_pacing_init(&cnx->priority_bypass_pacing, start_time);
            picoquic_register_path(cnx, cnx->path[0]);
        }
    }

    if (cnx != NULL) {
        memcpy(&cnx->local_parameters, &quic->default_tp, sizeof(picoquic_tp_t));
        /* If the default parameters include preferred address, document it */
        if (cnx->local_parameters.prefered_address.is_defined) {
            /* Create an additional CID -- this depends on the multipath variant being already negotiated */
            uint64_t unique_path_id = (cnx->is_multipath_enabled) ? 1 : 0;
            picoquic_local_cnxid_t* cnxid1 = picoquic_create_local_cnxid(cnx, unique_path_id, NULL, start_time);
            if (cnxid1 != NULL){
                /* copy the connection ID into the local parameter */
                cnx->local_parameters.prefered_address.connection_id = cnxid1->cnx_id;
                /* Create the reset secret */
                (void)picoquic_create_cnxid_reset_secret(cnx->quic, &cnxid1->cnx_id,
                    cnx->local_parameters.prefered_address.statelessResetToken);
            }
        }

        /* Apply the defined MTU MAX if specified and not set in defaults. */
        if (cnx->local_parameters.max_packet_size == 0 && cnx->quic->mtu_max > 0)
        {
            cnx->local_parameters.max_packet_size = cnx->quic->mtu_max -
                PICOQUIC_MTU_OVERHEAD(addr_to);
        }

        /* If local connection ID size is null, don't allow migration */
        if (!cnx->client_mode && quic->local_cnxid_length == 0) {
            cnx->local_parameters.migration_disabled = 1;
        }

        /* Initialize BDP transport parameter */
        if (quic->default_send_receive_bdp_frame) {
           /* Accept and send BDP extension frame */
            cnx->local_parameters.enable_bdp_frame = 1;
        }
 
        /* Initialize local flow control variables to advertised values */
        cnx->maxdata_local = ((uint64_t)cnx->local_parameters.initial_max_data);
        cnx->max_stream_id_bidir_local = STREAM_ID_FROM_RANK(
            cnx->local_parameters.initial_max_stream_id_bidir, cnx->client_mode, 0);
        cnx->max_stream_id_bidir_local_computed = STREAM_TYPE_FROM_ID(cnx->max_stream_id_bidir_local);
        cnx->max_stream_id_unidir_local = STREAM_ID_FROM_RANK(
            cnx->local_parameters.initial_max_stream_id_unidir, cnx->client_mode, 1);
        cnx->max_stream_id_unidir_local_computed = STREAM_TYPE_FROM_ID(cnx->max_stream_id_unidir_local);
       
        /* Initialize padding policy to default for context */
        cnx->padding_multiple = quic->padding_multiple_default;
        cnx->padding_minsize = quic->padding_minsize_default;

        /* Initialize spin policy, ensure that at least 1/8th of connections do not spin */
        cnx->spin_policy = quic->default_spin_policy;
        if (cnx->spin_policy == picoquic_spinbit_basic) {
            uint8_t rand256 = (uint8_t)picoquic_public_random_64();
            if (rand256 < PICOQUIC_SPIN_RESERVE_MOD_256) {
                cnx->spin_policy = picoquic_spinbit_null;
            }
        }
        else if (cnx->spin_policy == picoquic_spinbit_on) {
            /* Option used in test to avoid randomizing spin bit on/off */
            cnx->spin_policy = picoquic_spinbit_basic;
        }

        if (sni != NULL) {
            cnx->sni = picoquic_string_duplicate(sni);
        }

        if (alpn != NULL) {
            cnx->alpn = picoquic_string_duplicate(alpn);
        }

        cnx->callback_fn = quic->default_callback_fn;
        cnx->callback_ctx = quic->default_callback_ctx;
        cnx->congestion_alg = quic->default_congestion_alg;
        cnx->is_preemptive_repeat_enabled = quic->is_preemptive_repeat_enabled;

        /* Initialize key rotation interval to default value */
        cnx->crypto_epoch_length_max = quic->crypto_epoch_length_max;

        for (int epoch = 0; epoch < PICOQUIC_NUMBER_OF_EPOCHS; epoch++) {
            cnx->tls_stream[epoch].send_queue = NULL;
        }

        /* Perform different initializations for clients and servers */
        if (cnx->client_mode) {
            if (preferred_version == 0) {
                cnx->proposed_version = picoquic_supported_versions[0].version;
                cnx->version_index = 0;
            } else {
                cnx->version_index = picoquic_get_version_index(preferred_version);
                if (cnx->version_index < 0) {
                    cnx->version_index = PICOQUIC_INTEROP_VERSION_INDEX;
                    if ((preferred_version & 0x0A0A0A0A) == 0x0A0A0A0A) {
                        /* This is a hack, to allow greasing the cnx ID */
                        cnx->proposed_version = preferred_version;

                    } else {
                        cnx->proposed_version = picoquic_supported_versions[PICOQUIC_INTEROP_VERSION_INDEX].version;
                    }
                } else {
                    cnx->proposed_version = preferred_version;
                }
            }

            cnx->cnx_state = picoquic_state_client_init;

            if (!quic->is_cert_store_not_empty) {
                /* The open SSL certifier always fails if no certificate is stored, so we just use a NULL verifier */
                picoquic_log_app_message(cnx, "No root crt list specified -- certificate will not be verified.\n");

                picoquic_set_null_verifier(quic);
            }
        } else {
            cnx->is_half_open = 1;
            cnx->quic->current_number_half_open += 1;
            if (cnx->quic->current_number_half_open > cnx->quic->max_half_open_before_retry) {
                cnx->quic->check_token = 1;
            }
            cnx->cnx_state = picoquic_state_server_init;
            cnx->initial_cnxid = initial_cnx_id;
            cnx->path[0]->p_remote_cnxid->cnx_id = remote_cnx_id;

            cnx->version_index = picoquic_get_version_index(preferred_version);
            if (cnx->version_index < 0) {
                /* TODO: this is an internal error condition, should not happen */
                cnx->version_index = 0;
                cnx->proposed_version = picoquic_supported_versions[0].version;
            } else {
                cnx->proposed_version = preferred_version;
            }
        }

        for (picoquic_packet_context_enum pc = 0;
            pc < picoquic_nb_packet_context; pc++) {
            picoquic_init_ack_ctx(cnx, &cnx->ack_ctx[pc]);
            picoquic_init_packet_ctx(cnx, &cnx->pkt_ctx[pc], pc);
        }
        /* Initialize the ACK behavior. By default, picoquic abides with the recommendation to send
         * ACK immediately if packets are received out of order (ack_ignore_order_remote = 0),
         * but this behavior creates too many ACKS on high speed links, so picoquic will request
         * the peer to not do that if the "delayed ACK" extension is available (ack_ignore_order_local = 1)
         */
        cnx->ack_ignore_order_local = 1;
        cnx->ack_ignore_order_remote = 0;

        cnx->latest_progress_time = start_time;
        cnx->latest_receive_time = start_time;

        for (int epoch = 0; epoch < PICOQUIC_NUMBER_OF_EPOCHS; epoch++) {
            cnx->tls_stream[epoch].stream_id = 0;
            cnx->tls_stream[epoch].consumed_offset = 0;
            cnx->tls_stream[epoch].fin_offset = 0;
            cnx->tls_stream[epoch].stream_node.left = NULL;
            cnx->tls_stream[epoch].stream_node.parent = NULL;
            cnx->tls_stream[epoch].stream_node.right = NULL;
            cnx->tls_stream[epoch].sent_offset = 0;
            cnx->tls_stream[epoch].local_error = 0;
            cnx->tls_stream[epoch].remote_error = 0;
            cnx->tls_stream[epoch].maxdata_local = UINT64_MAX;
            cnx->tls_stream[epoch].maxdata_remote = UINT64_MAX;

            picosplay_init_tree(&cnx->tls_stream[epoch].stream_data_tree, picoquic_stream_data_node_compare, picoquic_stream_data_node_create, picoquic_stream_data_node_delete, picoquic_stream_data_node_value);
            picoquic_sack_list_init(&cnx->tls_stream[epoch].sack_list);
            /* No need to reset the state flags, as they are not used for the crypto stream */
        }
        
        cnx->ack_frequency_sequence_local = UINT64_MAX;
        cnx->ack_gap_local = 10;
        cnx->ack_frequency_delay_local = PICOQUIC_ACK_DELAY_MAX_DEFAULT;
        cnx->ack_frequency_sequence_remote = UINT64_MAX;
        cnx->ack_gap_remote = 2;
        cnx->ack_delay_remote = PICOQUIC_ACK_DELAY_MIN;
        cnx->max_ack_delay_remote = cnx->ack_delay_remote;
        cnx->max_ack_gap_remote = cnx->ack_gap_remote;
        cnx->max_ack_delay_local = cnx->ack_frequency_delay_local;
        cnx->max_ack_gap_local = cnx->ack_gap_local;
        cnx->min_ack_delay_remote = cnx->ack_delay_remote;
        cnx->min_ack_delay_local = cnx->ack_frequency_delay_local;


        picosplay_init_tree(&cnx->stream_tree, picoquic_stream_node_compare, picoquic_stream_node_create, picoquic_stream_node_delete, picoquic_stream_node_value);

        cnx->congestion_alg = cnx->quic->default_congestion_alg;
        if (cnx->congestion_alg != NULL) {
            cnx->congestion_alg->alg_init(cnx, cnx->path[0], start_time);
        }
    }

    /* Only initialize TLS after all parameters have been set */
    if (cnx != NULL && picoquic_tlscontext_create(quic, cnx, start_time) != 0) {
        /* Cannot just do partial creation! */
        picoquic_delete_cnx(cnx);
        cnx = NULL;
    }

    if (cnx != NULL) {
        if (picoquic_setup_initial_traffic_keys(cnx)) {
            /* Cannot initialize aead for initial packets */
            picoquic_delete_cnx(cnx);
            cnx = NULL;
        }
    }

    if (cnx != NULL && !client_mode && quic->local_cnxid_length > 0) {
        if (picoquic_register_net_icid(cnx) != 0) {
            DBG_PRINTF("%s", "Could not register the ICID in table.\n");
            picoquic_delete_cnx(cnx);
            cnx = NULL;
        }
    }

    if (quic->use_unique_log_names) {
        picoquic_crypto_random(quic, &cnx->log_unique, sizeof(cnx->log_unique));
    }

    if (cnx != NULL && !cnx->client_mode) {
        picoquic_log_new_connection(cnx);
    }

    return cnx;
}

picoquic_cnx_t* picoquic_create_client_cnx(picoquic_quic_t* quic,
    struct sockaddr* addr, uint64_t start_time, uint32_t preferred_version,
    char const* sni, char const* alpn, picoquic_stream_data_cb_fn callback_fn, void* callback_ctx)
{
    picoquic_cnx_t* cnx = picoquic_create_cnx(quic, picoquic_null_connection_id, picoquic_null_connection_id, addr, start_time, preferred_version, sni, alpn, 1);

    if (cnx != NULL) {
        int ret;

        if (callback_fn != NULL)
            cnx->callback_fn = callback_fn;
        if (callback_ctx != NULL)
            cnx->callback_ctx = callback_ctx;
        ret = picoquic_start_client_cnx(cnx);
        if (ret != 0) {
            /* Cannot just do partial initialization! */
            picoquic_delete_cnx(cnx);
            cnx = NULL;
        }
    }

    return cnx;
}

int picoquic_start_client_cnx(picoquic_cnx_t * cnx)
{
    int ret = 0;

    if (cnx->cnx_state != picoquic_state_client_init ||
        cnx->tls_stream[0].sent_offset > 0 ||
        cnx->tls_stream[0].send_queue != NULL) {
        DBG_PRINTF("%s", "picoquic_start_client_cnx called twice.");
        return -1;
    }

    picoquic_log_new_connection(cnx);
        
    ret = picoquic_initialize_tls_stream(cnx, picoquic_get_quic_time(cnx->quic));
    /* A remote session ticket may have been loaded as part of initializing TLS,
     * and remote parameters may have been initialized to the initial value
     * of the previous session. Apply these new parameters. */
    cnx->maxdata_remote = cnx->remote_parameters.initial_max_data;
    cnx->max_stream_id_bidir_remote =
        STREAM_ID_FROM_RANK(cnx->remote_parameters.initial_max_stream_id_bidir, cnx->client_mode, 0);
    cnx->max_stream_id_unidir_remote = 
        STREAM_ID_FROM_RANK(cnx->remote_parameters.initial_max_stream_id_unidir, cnx->client_mode, 1);
    cnx->max_stream_data_remote = cnx->remote_parameters.initial_max_data;
    cnx->max_stream_data_local = cnx->local_parameters.initial_max_stream_data_bidi_local;

    picoquic_reinsert_by_wake_time(cnx->quic, cnx, picoquic_get_quic_time(cnx->quic));

    return ret;
}

void picoquic_set_transport_parameters(picoquic_cnx_t * cnx, picoquic_tp_t const * tp)
{
    cnx->local_parameters = *tp;

    if (cnx->quic->mtu_max > 0 && cnx->local_parameters.max_packet_size == 0)
    {
        cnx->local_parameters.max_packet_size = cnx->quic->mtu_max - 
            PICOQUIC_MTU_OVERHEAD((struct sockaddr*)&(cnx->path[0])->peer_addr);
    }

    /* Initialize local flow control variables to advertised values */

    cnx->maxdata_local = ((uint64_t)cnx->local_parameters.initial_max_data);
    cnx->max_stream_id_bidir_local = STREAM_ID_FROM_RANK(
        cnx->local_parameters.initial_max_stream_id_bidir, cnx->client_mode, 0);
    cnx->max_stream_id_unidir_local = STREAM_ID_FROM_RANK(
        cnx->local_parameters.initial_max_stream_id_unidir, cnx->client_mode, 1);
}

picoquic_tp_t const* picoquic_get_transport_parameters(picoquic_cnx_t* cnx, int get_local)
{
    return(get_local) ? &cnx->local_parameters : &cnx->remote_parameters;
}

void picoquic_get_peer_addr(picoquic_cnx_t* cnx, struct sockaddr** addr)
{
    *addr = (struct sockaddr*)&cnx->path[0]->peer_addr;
}

void picoquic_get_local_addr(picoquic_cnx_t* cnx, struct sockaddr** addr)
{
    *addr = (struct sockaddr*)&cnx->path[0]->local_addr;
}

unsigned long picoquic_get_local_if_index(picoquic_cnx_t* cnx)
{
    return cnx->path[0]->if_index_dest;
}

picoquic_connection_id_t picoquic_get_local_cnxid(picoquic_cnx_t* cnx)
{
    return cnx->path[0]->p_local_cnxid->cnx_id;
}

picoquic_connection_id_t picoquic_get_remote_cnxid(picoquic_cnx_t* cnx)
{
    return cnx->path[0]->p_remote_cnxid->cnx_id;
}

picoquic_connection_id_t picoquic_get_initial_cnxid(picoquic_cnx_t* cnx)
{
    return cnx->initial_cnxid;
}

picoquic_connection_id_t picoquic_get_client_cnxid(picoquic_cnx_t* cnx)
{
    return (cnx->client_mode)?cnx->path[0]->p_local_cnxid->cnx_id : cnx->path[0]->p_remote_cnxid->cnx_id;
}

picoquic_connection_id_t picoquic_get_server_cnxid(picoquic_cnx_t* cnx)
{
    return (cnx->client_mode) ? cnx->path[0]->p_remote_cnxid->cnx_id : cnx->path[0]->p_local_cnxid->cnx_id;
}

picoquic_connection_id_t picoquic_get_logging_cnxid(picoquic_cnx_t* cnx)
{
    return cnx->initial_cnxid;
}

uint64_t picoquic_get_cnx_start_time(picoquic_cnx_t* cnx)
{
    return cnx->start_time;
}

picoquic_state_enum picoquic_get_cnx_state(picoquic_cnx_t* cnx)
{
    return cnx->cnx_state;
}

int picoquic_is_0rtt_available(picoquic_cnx_t* cnx)
{
    return (cnx->crypto_context[picoquic_epoch_0rtt].aead_encrypt == NULL) ? 0 : 1;
}

void picoquic_cnx_set_padding_policy(picoquic_cnx_t * cnx, uint32_t padding_multiple, uint32_t padding_minsize)
{
    cnx->padding_multiple = padding_multiple;
    cnx->padding_minsize = padding_minsize;
}

void picoquic_cnx_get_padding_policy(picoquic_cnx_t * cnx, uint32_t * padding_multiple, uint32_t * padding_minsize)
{
    *padding_multiple = cnx->padding_multiple;
    *padding_minsize = cnx->padding_minsize;
}

void picoquic_cnx_set_spinbit_policy(picoquic_cnx_t * cnx, picoquic_spinbit_version_enum spinbit_policy)
{
    cnx->spin_policy = spinbit_policy;
}

void picoquic_seed_bandwidth(picoquic_cnx_t* cnx, uint64_t rtt_min, uint64_t cwin, 
    const uint8_t * ip_addr, uint8_t ip_addr_length)
{
    cnx->seed_rtt_min = rtt_min;
    cnx->seed_cwin = cwin;
    if (ip_addr_length > PICOQUIC_STORED_IP_MAX) {
        ip_addr_length = PICOQUIC_STORED_IP_MAX;
    }
    memcpy(cnx->seed_ip_addr, ip_addr, ip_addr_length);
    cnx->seed_ip_addr_length = ip_addr_length;
}

void picoquic_set_default_pmtud_policy(picoquic_quic_t* quic, picoquic_pmtud_policy_enum pmtud_policy)
{
    quic->default_pmtud_policy = pmtud_policy;
}

void picoquic_cnx_set_pmtud_policy(picoquic_cnx_t* cnx, picoquic_pmtud_policy_enum pmtud_policy)
{
    cnx->pmtud_policy = pmtud_policy;
}

void picoquic_cnx_set_pmtud_required(picoquic_cnx_t* cnx, int is_pmtud_required)
{
    cnx->pmtud_policy = (is_pmtud_required) ? picoquic_pmtud_required : picoquic_pmtud_basic;
}

/*
 * Provide clock time
 */
uint64_t picoquic_current_time()
{
    uint64_t now;
#ifdef _WINDOWS
    FILETIME ft;
    /*
    * The GetSystemTimeAsFileTime API returns  the number
    * of 100-nanosecond intervals since January 1, 1601 (UTC),
    * in FILETIME format.
    */
    GetSystemTimePreciseAsFileTime(&ft);

    /*
    * Convert to plain 64 bit format, without making
    * assumptions about the FILETIME structure alignment.
    */
    now = ft.dwHighDateTime;
    now <<= 32;
    now |= ft.dwLowDateTime;
    /*
    * Convert units from 100ns to 1us
    */
    now /= 10;
    /*
    * Account for microseconds elapsed between 1601 and 1970.
    */
    now -= 11644473600000000ULL;
#elif defined(CLOCK_MONOTONIC)
    /*
    * Use CLOCK_MONOTONIC if exists (more accurate)
    */
    struct timespec currentTime;
    (void)clock_gettime(CLOCK_MONOTONIC, &currentTime);
    now = (currentTime.tv_sec * 1000000ull) + currentTime.tv_nsec / 1000ull;
#else
    struct timeval tv;
    (void)gettimeofday(&tv, NULL);
    now = (tv.tv_sec * 1000000ull) + tv.tv_usec;
#endif
    return now;
}

/*
* Get the same time simulation as used for TLS
*/

uint64_t picoquic_get_quic_time(picoquic_quic_t* quic)
{
    uint64_t now;
    if (quic->p_simulated_time == NULL) {
        now = picoquic_current_time();
    }
    else {
        now = *quic->p_simulated_time;
    }

    return now;
}

void picoquic_set_fuzz(picoquic_quic_t * quic, picoquic_fuzz_fn fuzz_fn, void * fuzz_ctx)
{
    quic->fuzz_fn = fuzz_fn;
    quic->fuzz_ctx = fuzz_ctx;
}

void picoquic_set_log_level(picoquic_quic_t* quic, int log_level)
{
    /* Only two level for now: log first 100 packets, or log everything. */
    quic->use_long_log = (log_level > 0) ? 1 : 0;
}

void picoquic_use_unique_log_names(picoquic_quic_t* quic, int use_unique_log_names)
{
    quic->use_unique_log_names = use_unique_log_names;
}

#ifndef PICOQUIC_WITHOUT_SSLKEYLOG
void picoquic_enable_sslkeylog(picoquic_quic_t* quic, int enable_sslkeylog)
{
    quic->enable_sslkeylog = (enable_sslkeylog != 0);
}

int picoquic_is_sslkeylog_enabled(picoquic_quic_t* quic)
{
    return quic->enable_sslkeylog;
}
#endif

void picoquic_set_random_initial(picoquic_quic_t* quic, int random_initial)
{
    /* If set, triggers randomization of initial PN numbers. */
    quic->random_initial = (random_initial > 1) ? 2 : ((random_initial > 0) ? 1 : 0);
}

void picoquic_set_packet_train_mode(picoquic_quic_t* quic, int train_mode)
{
    /* TODO: consider setting high water mark for pacing. */
    /* If set, wait until pacing bucket is full enough to allow further transmissions. */
    quic->packet_train_mode = (train_mode > 0) ? 1 : 0;
}

void picoquic_set_padding_policy(picoquic_quic_t* quic, uint32_t padding_min_size, uint32_t padding_multiple)
{
    quic->padding_minsize_default = padding_min_size;
    quic->padding_multiple_default = padding_multiple;
}

int picoquic_set_default_connection_id_length(picoquic_quic_t* quic, uint8_t cid_length)
{
    int ret = 0;

    if (cid_length != quic->local_cnxid_length) {
        if (cid_length > PICOQUIC_CONNECTION_ID_MAX_SIZE) {
            ret = PICOQUIC_ERROR_CNXID_CHECK;
        }
        else if (quic->cnx_list != NULL) {
            ret = PICOQUIC_ERROR_CANNOT_CHANGE_ACTIVE_CONTEXT;
        }
        else {
            quic->local_cnxid_length = cid_length;
        }
    }

    return ret;
}

void picoquic_set_default_connection_id_ttl(picoquic_quic_t* quic, uint64_t ttl_usec)
{
    quic->local_cnxid_ttl = ttl_usec;
}

uint64_t picoquic_get_default_connection_id_ttl(picoquic_quic_t* quic)
{
    return quic->local_cnxid_ttl;
}

void picoquic_set_mtu_max(picoquic_quic_t* quic, uint32_t mtu_max)
{
    quic->mtu_max = mtu_max;
    quic->default_tp.max_packet_size = mtu_max;
}

void picoquic_set_initial_send_mtu(picoquic_quic_t* quic, uint32_t intitial_mtu_ipv4, uint32_t intitial_mtu_ipv6)
{
    quic->initial_send_mtu_ipv4 = intitial_mtu_ipv4;
    quic->initial_send_mtu_ipv6 = intitial_mtu_ipv6;
}

void picoquic_set_alpn_select_fn(picoquic_quic_t* quic, picoquic_alpn_select_fn alpn_select_fn)
{
    if (quic->default_alpn != NULL) {
        free((void *)quic->default_alpn);
        quic->default_alpn = NULL;
    }
    quic->alpn_select_fn = alpn_select_fn;
}

void picoquic_set_default_callback(picoquic_quic_t* quic,
    picoquic_stream_data_cb_fn callback_fn, void* callback_ctx)
{
    quic->default_callback_fn = callback_fn;
    quic->default_callback_ctx = callback_ctx;
}

void picoquic_set_default_stateless_reset_min_interval(picoquic_quic_t* quic, uint64_t min_interval_usec)
{
    quic->stateless_reset_next_time = picoquic_get_quic_time(quic);
    quic->stateless_reset_min_interval = min_interval_usec;
}

void picoquic_set_callback(picoquic_cnx_t* cnx,
    picoquic_stream_data_cb_fn callback_fn, void* callback_ctx)
{
    cnx->callback_fn = callback_fn;
    cnx->callback_ctx = callback_ctx;
}

picoquic_stream_data_cb_fn picoquic_get_default_callback_function(picoquic_quic_t* quic)
{
    return quic->default_callback_fn;
}

void * picoquic_get_default_callback_context(picoquic_quic_t* quic)
{
    return quic->default_callback_ctx;
}

picoquic_stream_data_cb_fn picoquic_get_callback_function(picoquic_cnx_t * cnx)
{
    return cnx->callback_fn;
}

void * picoquic_get_callback_context(picoquic_cnx_t * cnx)
{
    return cnx->callback_ctx;
}

picoquic_misc_frame_header_t* picoquic_create_misc_frame(const uint8_t* bytes, size_t length, int is_pure_ack,
    picoquic_packet_context_enum pc)
{
    size_t l_alloc = sizeof(picoquic_misc_frame_header_t) + length;

    if (l_alloc < sizeof(picoquic_misc_frame_header_t)) {
        return NULL;
    }
    else {
        picoquic_misc_frame_header_t* head = (picoquic_misc_frame_header_t*)malloc(l_alloc);
        if (head != NULL) {
            memset(head, 0, sizeof(picoquic_misc_frame_header_t));
            head->length = length;
            head->is_pure_ack = is_pure_ack;
            head->pc = pc;
            memcpy(((uint8_t *)head) + sizeof(picoquic_misc_frame_header_t), bytes, length);
        }
        return head;
    }
}

int picoquic_queue_misc_or_dg_frame(picoquic_cnx_t * cnx, picoquic_misc_frame_header_t** first, 
    picoquic_misc_frame_header_t** last, const uint8_t* bytes, size_t length, int is_pure_ack,
    picoquic_packet_context_enum pc)
{
    int ret = 0;
    picoquic_misc_frame_header_t* misc_frame = picoquic_create_misc_frame(bytes, length, is_pure_ack, pc);

    if (misc_frame == NULL) {
        ret = PICOQUIC_ERROR_MEMORY;
    } else {
        if (*last == NULL) {
            *first = misc_frame;
            *last = misc_frame;
        }
        else {
            (*last)->next_misc_frame = misc_frame;
            misc_frame->previous_misc_frame = *last;
            *last = misc_frame;
        }
    }

    picoquic_reinsert_by_wake_time(cnx->quic, cnx, picoquic_get_quic_time(cnx->quic));

    return ret;
}

int picoquic_queue_misc_frame(picoquic_cnx_t* cnx, const uint8_t* bytes, size_t length,
    int is_pure_ack, picoquic_packet_context_enum pc)
{
    return picoquic_queue_misc_or_dg_frame(cnx, &cnx->first_misc_frame, &cnx->last_misc_frame, bytes, length, is_pure_ack, pc);
}

void picoquic_purge_misc_frames_after_ready(picoquic_cnx_t* cnx)
{
    picoquic_misc_frame_header_t* misc_frame = cnx->first_misc_frame;

    while (misc_frame != NULL) {
        picoquic_misc_frame_header_t* next_frame = misc_frame->next_misc_frame;

        if (misc_frame->pc != picoquic_packet_context_application) {
            picoquic_delete_misc_or_dg(&cnx->first_misc_frame, &cnx->last_misc_frame, misc_frame);
        }
        misc_frame = next_frame;
    }
}

void picoquic_delete_misc_or_dg(picoquic_misc_frame_header_t** first, picoquic_misc_frame_header_t** last, picoquic_misc_frame_header_t* frame)
{
    if (frame->next_misc_frame) {
        frame->next_misc_frame->previous_misc_frame = frame->previous_misc_frame;
    }
    else {
        *last = frame->previous_misc_frame;
    }

    if (frame->previous_misc_frame) {
        frame->previous_misc_frame->next_misc_frame = frame->next_misc_frame;
    }
    else {
        *first = frame->next_misc_frame;
    }

    free(frame);
}

void picoquic_clear_ack_ctx(picoquic_ack_context_t* ack_ctx)
{
    picoquic_sack_list_free(&ack_ctx->sack_list);

}


void picoquic_reset_ack_context(picoquic_ack_context_t* ack_ctx)
{
    picoquic_clear_ack_ctx(ack_ctx);

    picoquic_sack_list_init(&ack_ctx->sack_list);

    ack_ctx->ecn_ect0_total_local = 0;
    ack_ctx->ecn_ect1_total_local = 0;
    ack_ctx->ecn_ce_total_local = 0;
}


void picoquic_reset_packet_context(picoquic_cnx_t* cnx,
    picoquic_packet_context_t * pkt_ctx)
{
    while (pkt_ctx->pending_last != NULL) {
        (void)picoquic_dequeue_retransmit_packet(cnx, pkt_ctx, pkt_ctx->pending_last, 1, 0);
    }
    
    while (pkt_ctx->retransmitted_newest != NULL) {
        picoquic_dequeue_retransmitted_packet(cnx, pkt_ctx, pkt_ctx->retransmitted_newest);
    }

    pkt_ctx->retransmitted_oldest = NULL;

    /* Reset the ECN data */
    pkt_ctx->ecn_ect0_total_remote = 0;
    pkt_ctx->ecn_ect1_total_remote = 0;
    pkt_ctx->ecn_ce_total_remote = 0;
}

/*
* Reset the connection after an incoming retry packet.
*
* Can only happen after sending the client init packet.
* Result of reset:
*
* - connection ID is not changed.
* - sequence number is not changed.
* - all queued 0-RTT retransmission will be considered lost (to do with 0-RTT)
* - Client Initial packet is considered lost, free. A new one will have to be formatted.
* - TLS stream is reset, all TLS data is freed.
* - TLS API is called again.
* - State changes.
*/

int picoquic_reset_cnx(picoquic_cnx_t* cnx, uint64_t current_time)
{
    int ret = 0;

    /* Delete the packets queued for retransmission */
    for (picoquic_packet_context_enum pc = 0;
        pc < picoquic_nb_packet_context; pc++) {
        /* Do not reset the application context, in order to keep the 0-RTT
         * packets, and to keep using the same sequence number space in
         * the new connection */
        if (pc != picoquic_packet_context_application) {
            /* TODO: special case for 0-RTT packets! */
            picoquic_reset_packet_context(cnx, &cnx->pkt_ctx[pc]);
            picoquic_reset_ack_context(&cnx->ack_ctx[pc]);
        }
    }

    /* Reset the crypto stream */
    for (int epoch = 0; epoch < PICOQUIC_NUMBER_OF_EPOCHS; epoch++) {
        picoquic_clear_stream(&cnx->tls_stream[epoch]);
        cnx->tls_stream[epoch].consumed_offset = 0;
        cnx->tls_stream[epoch].fin_offset = 0;
        cnx->tls_stream[epoch].sent_offset = 0;
        /* No need to reset the state flags, are they are not used for the crypto stream */
    }

    for (int k = 0; k < 4; k++) {
        picoquic_crypto_context_free(&cnx->crypto_context[k]);
    }

    picoquic_crypto_context_free(&cnx->crypto_context_new);

    ret = picoquic_setup_initial_traffic_keys(cnx);

    /* Reset the TLS context, Re-initialize the tls connection */
    if (cnx->tls_ctx != NULL) {
        picoquic_tlscontext_free(cnx->tls_ctx);
        cnx->tls_ctx = NULL;
    }

    picoquic_log_new_connection(cnx);

    if (ret == 0) {
        ret = picoquic_tlscontext_create(cnx->quic, cnx, current_time);
    }
    if (ret == 0) {
        ret = picoquic_initialize_tls_stream(cnx, current_time);
    }

    return ret;
}

int picoquic_connection_error_ex(picoquic_cnx_t* cnx, uint64_t local_error, uint64_t frame_type, char const * local_reason)
{
    if (local_error > PICOQUIC_ERROR_CLASS) {
        local_error = PICOQUIC_TRANSPORT_INTERNAL_ERROR;
    }

    if (cnx->cnx_state == picoquic_state_ready || 
        cnx->cnx_state == picoquic_state_client_ready_start || cnx->cnx_state == picoquic_state_server_false_start) {
        cnx->local_error = local_error;
        cnx->local_error_reason = local_reason;
        cnx->cnx_state = picoquic_state_disconnecting;
    } else if (cnx->cnx_state < picoquic_state_server_false_start) {
        if (cnx->cnx_state != picoquic_state_handshake_failure &&
            cnx->cnx_state != picoquic_state_handshake_failure_resend) {
            cnx->local_error = local_error;
            cnx->local_error_reason = local_reason;
            cnx->cnx_state = picoquic_state_handshake_failure;
        }
    }

    cnx->offending_frame_type = frame_type;

    picoquic_log_app_message(cnx, "Protocol error 0x%x, frame %" PRIu64 ", reason: %s",
        local_error, frame_type, (local_reason==NULL)?"?":local_reason);
    DBG_PRINTF("Protocol error 0x%x, frame %" PRIu64 ", reason: %s",
        local_error, frame_type, (local_reason==NULL)?"?":local_reason);

    return PICOQUIC_ERROR_DETECTED;
}

int picoquic_connection_error(picoquic_cnx_t* cnx, uint64_t local_error, uint64_t frame_type)
{
    return picoquic_connection_error_ex(cnx, local_error, frame_type, NULL);
}

void picoquic_connection_disconnect(picoquic_cnx_t* cnx)
{
    if (cnx->cnx_state != picoquic_state_disconnected) {
        cnx->cnx_state = picoquic_state_disconnected;
        if (cnx->callback_fn) {
            (void)(cnx->callback_fn)(cnx, 0, NULL, 0, picoquic_callback_close, cnx->callback_ctx, NULL);
        }
    }
}

int picoquic_start_key_rotation(picoquic_cnx_t* cnx)
{
    int ret = 0;

    /* Verify that a packet of the previous rotation was acked */
    if (cnx->cnx_state != picoquic_state_ready ||
        cnx->crypto_epoch_sequence >
        picoquic_sack_list_last(&cnx->ack_ctx[picoquic_packet_context_application].sack_list)) {
        ret = PICOQUIC_ERROR_KEY_ROTATION_NOT_READY;
    }
    else {
        ret = picoquic_compute_new_rotated_keys(cnx);
    }

    if (ret == 0) {
        picoquic_apply_rotated_keys(cnx, 1);
        picoquic_crypto_context_free(&cnx->crypto_context_old);
        cnx->crypto_epoch_sequence = cnx->pkt_ctx[picoquic_packet_context_application].send_sequence;
    }

    return ret;
}

void picoquic_delete_sooner_packets(picoquic_cnx_t* cnx)
{
    picoquic_stateless_packet_t* packet = cnx->first_sooner;

    while (packet != NULL) {
        picoquic_stateless_packet_t* next_packet = packet->next_packet;
        picoquic_delete_stateless_packet(packet);
        packet = next_packet;
    }
    cnx->first_sooner = NULL;
}

void picoquic_delete_cnx(picoquic_cnx_t* cnx)
{
    if (cnx != NULL) {
#ifdef PICOQUIC_MEMORY_LOG
        if (cnx->memlog_call_back != NULL) {
            cnx->memlog_call_back(cnx, NULL, cnx->memlog_ctx, 1, 0);
        }
#endif
        if (cnx->quic->perflog_fn != NULL) {
            (void)(cnx->quic->perflog_fn)(cnx->quic, cnx, 0);
        }

        picoquic_log_close_connection(cnx);

        if (cnx->is_half_open && cnx->quic->current_number_half_open > 0) {
            cnx->quic->current_number_half_open--;
            cnx->is_half_open = 0;
        }

        if (cnx->cnx_state < picoquic_state_disconnected) {
            /* Give the application a chance to clean up its state */
            picoquic_connection_disconnect(cnx);
        }

        if (cnx->alpn != NULL) {
            free((void*)cnx->alpn);
            cnx->alpn = NULL;
        }

        if (cnx->sni != NULL) {
            free((void*)cnx->sni);
            cnx->sni = NULL;
        }

        if (cnx->retry_token != NULL) {
            free(cnx->retry_token);
            cnx->retry_token = NULL;
        }

        picoquic_delete_sooner_packets(cnx);

        picoquic_remove_cnx_from_list(cnx);
        picoquic_remove_cnx_from_wake_list(cnx);

        for (int i = 0; i < PICOQUIC_NUMBER_OF_EPOCHS; i++) {
            picoquic_crypto_context_free(&cnx->crypto_context[i]);
        }

        picoquic_crypto_context_free(&cnx->crypto_context_new);
        picoquic_crypto_context_free(&cnx->crypto_context_old);

        for (picoquic_packet_context_enum pc = 0;
            pc < picoquic_nb_packet_context; pc++) {
            picoquic_reset_packet_context(cnx, &cnx->pkt_ctx[pc]);
            picoquic_reset_ack_context(&cnx->ack_ctx[pc]);
        }

        while (cnx->first_misc_frame != NULL) {
            picoquic_delete_misc_or_dg(&cnx->first_misc_frame, &cnx->last_misc_frame, cnx->first_misc_frame);
        }

        while (cnx->first_datagram != NULL) {
            picoquic_delete_misc_or_dg(&cnx->first_datagram, &cnx->last_datagram, cnx->first_datagram);
        }

        picosplay_empty_tree(&cnx->queue_data_repeat_tree);

        for (int epoch = 0; epoch < PICOQUIC_NUMBER_OF_EPOCHS; epoch++) {
            picoquic_clear_stream(&cnx->tls_stream[epoch]);
        }

        picosplay_empty_tree(&cnx->stream_tree);

        if (cnx->tls_ctx != NULL) {
            picoquic_tlscontext_free(cnx->tls_ctx);
            cnx->tls_ctx = NULL;
        }

        if (cnx->path != NULL)
        {
            while (cnx->nb_paths > 0) {
                picoquic_dereference_stashed_cnxid(cnx, cnx->path[cnx->nb_paths - 1], 1);
                picoquic_delete_path(cnx, cnx->nb_paths - 1);
            }

            free(cnx->path);
            cnx->path = NULL;
        }

        picoquic_delete_local_cnxid_lists(cnx);
        picoquic_delete_remote_cnxid_stashes(cnx);

        picoquic_unregister_net_icid(cnx);

        free(cnx);
    }
}

int picoquic_is_handshake_error(uint64_t error_code)
{
    return ((error_code & 0xFF00) == PICOQUIC_TRANSPORT_CRYPTO_ERROR(0) ||
        error_code == PICOQUIC_TLS_HANDSHAKE_FAILED);
}

void picoquic_get_close_reasons(picoquic_cnx_t* cnx, uint64_t* local_reason, 
    uint64_t* remote_reason, uint64_t* local_application_reason, uint64_t* remote_application_reason)
{
    *local_reason = cnx->local_error;
    *remote_reason = cnx->remote_error;
    *local_application_reason = cnx->application_error;
    *remote_application_reason = cnx->remote_application_error;
}

/* set the app wake up time (or cancel it by setting it to zero) */
void picoquic_set_app_wake_time(picoquic_cnx_t* cnx, uint64_t app_wake_time)
{
    cnx->app_wake_time = app_wake_time;
    if (cnx->app_wake_time != 0 && cnx->app_wake_time < cnx->next_wake_time) {
        picoquic_reinsert_by_wake_time(cnx->quic, cnx, app_wake_time);
    }
}

/* Setting up version negotiation parameters */
void picoquic_set_desired_version(picoquic_cnx_t* cnx, uint32_t desired_version)
{
    cnx->desired_version = desired_version;
    cnx->do_version_negotiation = 1;
}

void picoquic_set_rejected_version(picoquic_cnx_t* cnx, uint32_t rejected_version)
{
    cnx->desired_version = rejected_version;
    cnx->do_version_negotiation = 1;
}

/* Context retrieval functions */
picoquic_cnx_t* picoquic_cnx_by_id_(picoquic_quic_t* quic, picoquic_connection_id_t cnx_id) {
    return picoquic_cnx_by_id(quic, cnx_id, NULL);
}

picoquic_cnx_t* picoquic_cnx_by_id(picoquic_quic_t* quic, picoquic_connection_id_t cnx_id,
    struct st_picoquic_local_cnxid_t** l_cid)
{
    picoquic_cnx_t* ret = NULL;
    picohash_item* item;
    picoquic_local_cnxid_t key;

    memset(&key, 0, sizeof(key));
    key.cnx_id = cnx_id;

    item = picohash_retrieve(quic->table_cnx_by_id, &key);

    if (item != NULL) {
        ret = ((picoquic_local_cnxid_t*)item->key)->registered_cnx;
        if (l_cid != NULL) {
            *l_cid = ((picoquic_local_cnxid_t*)item->key);
        }
    }
    else if (l_cid != NULL) {
        *l_cid = NULL;
    }

    return ret;
}

picoquic_cnx_t* picoquic_cnx_by_net(picoquic_quic_t* quic, const struct sockaddr* addr)
{
    picoquic_cnx_t* ret = NULL;
    picohash_item* item;
    picoquic_path_t dummy_path_x = { 0 };

    picoquic_store_addr(&dummy_path_x.registered_peer_addr, addr);

    item = picohash_retrieve(quic->table_cnx_by_net, &dummy_path_x);

    if (item != NULL) {
        ret = ((picoquic_path_t*)item->key)->cnx;
    }
    return ret;
}

picoquic_cnx_t* picoquic_cnx_by_icid(picoquic_quic_t* quic, picoquic_connection_id_t* icid,
    const struct sockaddr* addr)
{
    picoquic_cnx_t* ret = NULL;
    picohash_item* item;
    picoquic_cnx_t dummy_cnx = { 0 };

    picoquic_store_addr(&dummy_cnx.registered_icid_addr, addr);
    dummy_cnx.initial_cnxid = *icid;

    item = picohash_retrieve(quic->table_cnx_by_icid, &dummy_cnx);

    if (item != NULL) {
        ret = (picoquic_cnx_t*)item->key;
    }
    return ret;
}

picoquic_cnx_t* picoquic_cnx_by_secret(picoquic_quic_t* quic, const uint8_t* reset_secret, const struct sockaddr* addr)
{
    picoquic_cnx_t* ret = NULL;
    picohash_item* item;
    picoquic_cnx_t dummy_cnx = { 0 };

    picoquic_store_addr(&dummy_cnx.registered_secret_addr, addr);
    memcpy(dummy_cnx.registered_reset_secret, reset_secret, PICOQUIC_RESET_SECRET_SIZE);

    item = picohash_retrieve(quic->table_cnx_by_secret, &dummy_cnx);

    if (item != NULL) {
        ret = ((picoquic_cnx_t*)item->key);
    }
    return ret;
}

/* Get congestion control algorithm by name
 * TODO: if we want to minimize code size, we should not require linking a whole library
 * of congestion control algorithms. Intead, the application should have a list of
 * configured algorithms, and the configuration program should select from that list.
 */
picoquic_congestion_algorithm_t const* picoquic_get_congestion_algorithm(char const* alg_name)
{
    picoquic_congestion_algorithm_t const* alg = NULL;
    if (alg_name != NULL) {
        if (strcmp(alg_name, "reno") == 0) {
            alg = picoquic_newreno_algorithm;
        }
        else if (strcmp(alg_name, "cubic") == 0) {
            alg = picoquic_cubic_algorithm;
        }
        else if (strcmp(alg_name, "dcubic") == 0) {
            alg = picoquic_dcubic_algorithm;
        }
        else if (strcmp(alg_name, "fast") == 0) {
            alg = picoquic_fastcc_algorithm;
        }
        else if (strcmp(alg_name, "bbr") == 0) {
            alg = picoquic_bbr_algorithm;
        }
        else if (strcmp(alg_name, "prague") == 0) {
            alg = picoquic_prague_algorithm;
        }
        else if (strcmp(alg_name, "bbr1") == 0) {
            alg = picoquic_bbr1_algorithm;
        }
        else {
            alg = NULL;
        }
    }
    return alg;
}
/*
 * Set or reset the congestion control algorithm
 */

void picoquic_set_default_congestion_algorithm(picoquic_quic_t* quic, picoquic_congestion_algorithm_t const* alg)
{
    quic->default_congestion_alg = alg;
}

void picoquic_set_default_congestion_algorithm_by_name(picoquic_quic_t* quic, char const * alg_name)
{
    quic->default_congestion_alg = picoquic_get_congestion_algorithm(alg_name);
}

/*
 * Set the optimistic ack policy
 */

void picoquic_set_optimistic_ack_policy(picoquic_quic_t* quic, uint32_t sequence_hole_pseudo_period)
{
    quic->sequence_hole_pseudo_period = sequence_hole_pseudo_period;
}

void picoquic_set_preemptive_repeat_policy(picoquic_quic_t* quic, int do_repeat)
{
    quic->is_preemptive_repeat_enabled = (do_repeat) ? 1 : 0;
}

void picoquic_set_preemptive_repeat_per_cnx(picoquic_cnx_t* cnx, int do_repeat)
{
    cnx->is_preemptive_repeat_enabled = (do_repeat) ? 1 : 0;
}

void picoquic_set_congestion_algorithm(picoquic_cnx_t* cnx, picoquic_congestion_algorithm_t const* alg)
{
    if (cnx->congestion_alg != NULL) {
        if (cnx->path != NULL) {
            for (int i = 0; i < cnx->nb_paths; i++) {
                cnx->congestion_alg->alg_delete(cnx->path[i]);
            }
        }
    }

    cnx->congestion_alg = alg;

    if (cnx->congestion_alg != NULL) {
        if (cnx->path != NULL) {
            for (int i = 0; i < cnx->nb_paths; i++) {
                cnx->congestion_alg->alg_init(cnx, cnx->path[i], picoquic_get_quic_time(cnx->quic));
            }
        }
    }
}

void picoquic_set_default_wifi_shadow_rtt(picoquic_quic_t* quic, uint64_t wifi_shadow_rtt)
{
    quic->wifi_shadow_rtt = wifi_shadow_rtt;
}

void picoquic_set_default_bbr_quantum_ratio(picoquic_quic_t* quic, double quantum_ratio)
{
    quic->bbr_quantum_ratio = quantum_ratio;
}

#ifdef BBRExperiment
void picoquic_set_bbr_exp(picoquic_quic_t* quic, bbr_exp* exp)
{
    quic->bbr_exp_flags = *exp;
}
#endif
void picoquic_set_priority_limit_for_bypass(picoquic_cnx_t* cnx, uint8_t priority_limit)
{
    cnx->priority_limit_for_bypass = priority_limit;
    if (priority_limit > 0) {
        picoquic_update_pacing_parameters(&cnx->priority_bypass_pacing,
            PICOQUIC_PRIORITY_BYPASS_MAX_RATE, PICOQUIC_PRIORITY_BYPASS_QUANTUM,
            cnx->path[0]->send_mtu, cnx->path[0]->smoothed_rtt, NULL);
    }
}

void picoquic_set_feedback_loss_notification(picoquic_cnx_t* cnx, unsigned int should_notify)
{
    cnx->is_lost_feedback_notification_required = should_notify;
}

void picoquic_request_forced_probe_up(picoquic_cnx_t* cnx, unsigned int request_forced_probe_up)
{
    cnx->is_forced_probe_up_required = request_forced_probe_up;
}

void picoquic_subscribe_pacing_rate_updates(picoquic_cnx_t* cnx, uint64_t decrease_threshold, uint64_t increase_threshold)
{
    cnx->pacing_decrease_threshold = decrease_threshold;
    cnx->pacing_increase_threshold = increase_threshold;
    cnx->is_pacing_update_requested = (decrease_threshold != UINT64_MAX || increase_threshold != UINT64_MAX);
}

uint64_t picoquic_get_pacing_rate(picoquic_cnx_t* cnx)
{
    return cnx->path[0]->pacing.rate;
}

uint64_t picoquic_get_cwin(picoquic_cnx_t* cnx)
{
    return cnx->path[0]->cwin;
}

uint64_t picoquic_get_rtt(picoquic_cnx_t* cnx)
{
    return cnx->path[0]->smoothed_rtt;
}

int picoquic_set_local_addr(picoquic_cnx_t* cnx, struct sockaddr* addr)
{
    int ret = 0;

    if (cnx != NULL && cnx->path[0] != NULL && cnx->path[0]->local_addr.ss_family == 0) {
        picoquic_store_addr(&cnx->path[0]->local_addr, addr);
        ret = (cnx->path[0]->local_addr.ss_family == 0) ? -1 : 0;
    }
    else {
        ret = -1;
    }

    return ret;
}

void picoquic_enable_keep_alive(picoquic_cnx_t* cnx, uint64_t interval)
{
    if (interval == 0) {
        /* Use the negotiated value */
        uint64_t idle_timeout = cnx->idle_timeout;
        if (idle_timeout == 0) {
            /* Idle timeout is only initialized after parameters are negotiated  */
            idle_timeout = cnx->local_parameters.max_idle_timeout * 1000ull;
        }
        /* Ensure at least 3 PTO*/
        if (idle_timeout < 3 * cnx->path[0]->retransmit_timer) {
            idle_timeout = 3 * cnx->path[0]->retransmit_timer;
        }
        /* set interval to half that value */
        cnx->keep_alive_interval = idle_timeout / 2;
    } else {
        cnx->keep_alive_interval = interval;
    }
}

void picoquic_disable_keep_alive(picoquic_cnx_t* cnx)
{
    cnx->keep_alive_interval = 0;
}

void picoquic_set_verify_certificate_callback(picoquic_quic_t* quic, 
    ptls_verify_certificate_t * cb, picoquic_free_verify_certificate_ctx free_fn) {
    picoquic_dispose_verify_certificate_callback(quic);

    picoquic_tls_set_verify_certificate_callback(quic, cb, free_fn);
}

int picoquic_is_client(picoquic_cnx_t* cnx)
{
    return cnx->client_mode;
}

/* Retrieve the error codes after failure of a connection or of a stream */

uint64_t picoquic_get_local_error(picoquic_cnx_t* cnx)
{
    return cnx->local_error;
}

uint64_t picoquic_get_remote_error(picoquic_cnx_t* cnx)
{
    return cnx->remote_error;
}

uint64_t picoquic_get_application_error(picoquic_cnx_t* cnx)
{
    return cnx->remote_application_error;
}

uint64_t picoquic_get_remote_stream_error(picoquic_cnx_t* cnx, uint64_t stream_id)
{
    uint64_t remote_error = 0;
    picoquic_stream_head_t* stream = picoquic_find_stream(cnx, stream_id);
    if (stream != NULL) {
        remote_error = stream->remote_error;
    }
    return remote_error;
}

uint64_t picoquic_get_data_sent(picoquic_cnx_t* cnx)
{
    return cnx->data_sent;
}

uint64_t picoquic_get_data_received(picoquic_cnx_t* cnx)
{
    return cnx->data_received;
}

void picoquic_set_client_authentication(picoquic_quic_t* quic, int client_authentication) {
    picoquic_tls_set_client_authentication(quic, client_authentication);
}

void picoquic_enforce_client_only(picoquic_quic_t* quic, int do_enforce)
{
    quic->enforce_client_only = (do_enforce)?1:0;
}

/* Supported version upgrade.
 * Upgrades are only supported between compatible versions.
 * 
 * When upgrading, there may be a need to update more than the version field. For example,
 * there may be a need to update encryption contexts if they were computed differently,
 * or to revisit some default options.
 * 
 * The function takes three arguments: connection context, old version_index and new version.
 * The return code is zero if the upgrade was done, -1 if it could not be.
 * If the function is called with a null connection context, it returns 0 if the
 * upgrade is possible, -1 if it is not.
 */

int picoquic_process_version_upgrade(picoquic_cnx_t* cnx, int old_version_index, int new_version_index)
{
    int ret = -1;
    /* Check whether upgrade is supported */
    if (new_version_index == old_version_index) {
        /* not an upgrade, nothing to do. */
        ret = 0;
    } else if (picoquic_supported_versions[new_version_index].upgrade_from != NULL) {
        int i = 0;

        while (picoquic_supported_versions[new_version_index].upgrade_from[i] != 0) {
            if (picoquic_supported_versions[new_version_index].upgrade_from[i] ==
                picoquic_supported_versions[old_version_index].version) {
                /* Supported */
                ret = 0;
                if (cnx != NULL) {
                    /* Install the new keys */
                    cnx->version_index = new_version_index;
                    picoquic_crypto_context_free(&cnx->crypto_context[picoquic_epoch_initial]);
                    ret = picoquic_setup_initial_traffic_keys(cnx);
                    break;
                }
            }
        }
    }
    return ret;
}

/* Simple portable number generation. */
uint64_t picoquic_uniform_random(uint64_t rnd_max)
{
    return picoquic_public_uniform_random(rnd_max);
}
