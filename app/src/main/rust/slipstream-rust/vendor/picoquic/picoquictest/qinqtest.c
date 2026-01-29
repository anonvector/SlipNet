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

#include "picoquic_internal.h"
#include "picoquictest_internal.h"
#include <stdlib.h>
#include <string.h>
#include "h3zero.h"
#include "democlient.h"
#include "demoserver.h"
#include "democlient.h"
#include "qinqproto.h"
#include "qinqserver.h"
#include "qinqclient.h"

struct st_qinq_test_rh_t {
    uint64_t direction;
    uint64_t hcid;
    size_t address_length;
    uint8_t address[16];
    uint16_t port;
    picoquic_connection_id_t cid;
};

static uint8_t qinq_rh1[] = {
    QINQ_PROTO_RESERVE_HEADER, 0, 1, 4, 10, 0, 0, 1, 1, 187, 4, 0x01, 0x02, 0x03, 0x04
};

static struct st_qinq_test_rh_t rh1 = {
    0, 1, 4, {10, 0, 0, 1}, 443, { { 0x01, 0x02, 0x03, 0x04}, 4}
};

static uint8_t qinq_rh2[] = {
    QINQ_PROTO_RESERVE_HEADER, 1, 2, 16,
    0x20, 0x01, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
    0x12, 0x34, 8, 11, 12, 13, 14, 15, 16, 17, 18
};

static struct st_qinq_test_rh_t rh2 = {
    1, 2, 16, {0x20, 0x01, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}, 
    0x1234, { { 11, 12, 13, 14, 15, 16, 17, 18}, 8}
};

static int qinq_test_one_rh(const struct st_qinq_test_rh_t* rh, size_t length, uint8_t* message)
{
    int ret = 0;
    uint64_t direction= UINT64_MAX;
    uint64_t hcid = UINT64_MAX;
    picoquic_connection_id_t cid = { {0}, 0 };
    uint8_t* bytes = message;
    uint8_t* bytes_max = message + length;
    struct sockaddr_storage addr_s;
    struct sockaddr_storage addr_target;

    memset(&addr_target, 0, sizeof(struct sockaddr_storage));

    if (rh->address_length == 4) {
        struct sockaddr_in* addr4 = (struct sockaddr_in*) & addr_target;
        addr4->sin_family = AF_INET;
        memcpy(&addr4->sin_addr, rh->address, 4);
        addr4->sin_port = rh->port;
    }
    else if (rh->address_length == 16) {
        struct sockaddr_in6* addr6 = (struct sockaddr_in6*) & addr_target;
        addr6->sin6_family = AF_INET6;
        memcpy(&addr6->sin6_addr, rh->address, 16);
        addr6->sin6_port = rh->port;
    }

    if ((bytes = picoquic_frames_varint_skip(bytes, bytes_max)) != NULL) {
        bytes = picoqinq_decode_reserve_header(bytes, bytes_max, &direction, &hcid, &addr_s, &cid);
    }

    if (bytes == NULL) {
        ret = -1;
        DBG_PRINTF("Parsing reserve header returns: %d\n", ret);
    }
    else if (bytes_max > bytes) {
        DBG_PRINTF("Bytes remain after parsing reserve header: %llu\n",
            (unsigned long long)(bytes_max - bytes));
        ret = -1;
    }
    else if (direction != rh->direction) {
        DBG_PRINTF("Wrong direction: %d\n", direction);
        ret = -1;
    }
    else if (hcid != rh->hcid) {
        DBG_PRINTF("Wrong hcid: %d\n", hcid);
        ret = -1;
    }
    else if (picoquic_compare_addr((struct sockaddr *)&addr_target, (struct sockaddr*) & addr_s) != 0){
        DBG_PRINTF("Wrong address, family: %d\n", addr_s.ss_family);
        ret = -1;
    }
    else if (picoquic_compare_connection_id(&cid, &rh->cid) != 0) {
        DBG_PRINTF("Wrong CID: %d: { %d, %d, %d, %d, ... }\n", cid.id_len, cid.id[0], cid.id[1], cid.id[2], cid.id[3]);
        ret = -1;
    }

    if (ret == 0) {
        uint8_t buf[256];
        
        bytes_max = buf + sizeof(buf);

        bytes = picoqinq_encode_reserve_header(buf, bytes_max, direction, hcid, (struct sockaddr *)&addr_target, &cid);
        if (bytes == NULL) {
            ret = -1;
            DBG_PRINTF("Preparing reserve header returns: %d\n", ret);
        }
        else if (bytes - buf != length) {
            DBG_PRINTF("Preparing reserve header wrong length: %llu\n", (unsigned long long)(bytes - buf));
            ret = -1;
        }
        else if (memcmp(buf, message, length) != 0) {
            DBG_PRINTF("%s", "Prepared reserve header does not match\n");
            ret = -1;
        }
    }

    return ret;
}

int qinq_rh_test()
{
    int ret;

    if ((ret = qinq_test_one_rh(&rh1, sizeof(qinq_rh1), qinq_rh1)) == 0) {
        ret = qinq_test_one_rh(&rh2, sizeof(qinq_rh2), qinq_rh2);
    }

    return ret;
}

static struct st_qinq_test_rh_t* header_list[] = { &rh1, &rh2 };
size_t header_list_nb = sizeof(header_list) / sizeof(struct st_qinq_test_rh_t*);

uint8_t qinq_dg1[] = {
    0,  4, 10, 0, 0, 1, 1, 187, 0x0, 0x01, 0x02, 0x03, 0x04, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef };
uint8_t qinq_dg1c[] = {
    1,  0x0, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef };
uint8_t qinq_dg2[] = {
    0,  16, 0x20, 0x01, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 0x12, 0x34, 0xCF, 0xff, 0x00, 0x00, 0x17, 8, 11, 12, 13, 14, 15, 16, 17, 18, 8, 41, 42, 43, 44, 45, 46, 47, 48, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef };
uint8_t qinq_dg2c[] = {
    2,  0xCF, 0xff, 0x00, 0x00, 0x17, 8, 41, 42, 43, 44, 45, 46, 47, 48, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef };

struct st_qinq_test_dg_t {
    uint64_t hcid;
    size_t address_length;
    uint8_t * address;
    uint16_t port;
    picoquic_connection_id_t cid;
    uint8_t * dg;
    size_t dg_length;
    uint8_t * packet;
    size_t packet_length;
    size_t parsed_bytes;
};

static struct st_qinq_test_dg_t dg_list[] = {
    { 0, 4, &qinq_dg1[2], 443, {{0}, 0}, qinq_dg1, sizeof(qinq_dg1), &qinq_dg1[8], sizeof(qinq_dg1) - 8, 8},
    { 1, 4, &qinq_dg1[2], 443, {{0x01, 0x02, 0x03, 0x04}, 4}, qinq_dg1c, sizeof(qinq_dg1c), &qinq_dg1[8], sizeof(qinq_dg1) - 8, 1 },
    { 0, 16, &qinq_dg2[2], 0x1234, {{0}, 0}, qinq_dg2, sizeof(qinq_dg2), &qinq_dg2[20], sizeof(qinq_dg2) - 20, 20 },
    { 2, 16, &qinq_dg2[2], 0x1234, {{ 11, 12, 13, 14, 15, 16, 17, 18}, 8}, qinq_dg2c, sizeof(qinq_dg2c), &qinq_dg2[20], sizeof(qinq_dg2) - 20, 1}
};

size_t dg_list_nb = sizeof(dg_list) / sizeof(struct st_qinq_test_dg_t);

int qinq_incoming_datagram_parse_test()
{
    int ret = 0;
    picoqinq_header_compression_t* hc_head = NULL;

    for (size_t i = 0; ret == 0 && i < header_list_nb; i++) {
        struct sockaddr_storage addr_s;
        if (qinq_copy_address(&addr_s, header_list[i]->address_length, header_list[i]->address, header_list[i]->port) != 0) {
            DBG_PRINTF("Cannot copy address #%d, length: %d\n", (int)i, (int)header_list[i]->address_length);
            ret = -1;
        }
        else {
            picoqinq_header_compression_t* hc = picoqinq_create_header((uint64_t)i + 1, (struct sockaddr*) & addr_s, &header_list[i]->cid, 0);
            if (hc == NULL) {
                DBG_PRINTF("Cannot create hc #%d\n", (int)i);
                ret = -1;
            }
            else {
                picoqinq_reserve_header(hc, &hc_head);
            }
        }
    }

    /* Unit test of datagram parser */
    for (size_t i = 0; ret == 0 && i < dg_list_nb; i++) {
        struct sockaddr_storage addr_s;
        struct sockaddr_storage addr_ref;
        if (qinq_copy_address(&addr_ref, dg_list[i].address_length, dg_list[i].address, dg_list[i].port) != 0) {
            DBG_PRINTF("Cannot copy address #%d, length: %d\n", (int)i, (int)dg_list[i].address_length);
            ret = -1;
        }
        else {
            picoquic_connection_id_t* cid;
            uint8_t* bytes = dg_list[i].dg;
            uint8_t* bytes_max = bytes + dg_list[i].dg_length;

            bytes = picoqinq_decode_datagram_header(bytes, bytes_max, &addr_s, &cid, &hc_head, 0);
            if (bytes == NULL) {
                ret = -1;
                DBG_PRINTF("Parsing header of dg[%d] fails\n", (int)i);
            }
            else if (picoquic_compare_addr((struct sockaddr*) & addr_s, (struct sockaddr*) & addr_ref) != 0) {
                ret = -1;
                DBG_PRINTF("Parsing header of dg[%d]: address mismatch\n", (int)i);
            }
            else if (cid == NULL && dg_list[i].cid.id_len > 0) {
                ret = -1;
                DBG_PRINTF("Parsing header of dg[%d]: cid not parsed\n", (int)i);
            }
            else if (cid != NULL && dg_list[i].cid.id_len == 0) {
                ret = -1;
                DBG_PRINTF("Parsing header of dg[%d]: unexpected cid parsed\n", (int)i);
            }
            else if (dg_list[i].cid.id_len > 0 && picoquic_compare_connection_id(&dg_list[i].cid, cid) != 0) {
                ret = -1;
                DBG_PRINTF("Parsing header of dg[%d]: cid mismatch\n", (int)i);
            }
            else if (bytes - dg_list[i].dg != dg_list[i].parsed_bytes) {
                ret = -1;
                DBG_PRINTF("Parsing header of dg[%d]: parsed bytes count mismatch\n", (int)i);
            }
        }
    }

    /* Unit test of datagram to packet */
    for (size_t i = 0; ret == 0 && i < dg_list_nb; i++) {
        struct sockaddr_storage addr_s;
        struct sockaddr_storage addr_ref;
        if (qinq_copy_address(&addr_ref, dg_list[i].address_length, dg_list[i].address, dg_list[i].port) != 0) {
            DBG_PRINTF("Cannot copy address #%d, length: %d\n", (int)i, (int)dg_list[i].address_length);
            ret = -1;
        }
        else {
            uint8_t* bytes = dg_list[i].dg;
            uint8_t* bytes_max = bytes + dg_list[i].dg_length;
            uint8_t packet[1024];
            size_t packet_length;
            picoquic_connection_id_t* cid = NULL;
            ret = picoqinq_datagram_to_packet(bytes, bytes_max, &addr_s, &cid, packet, sizeof(packet), &packet_length, &hc_head, 0);
            if (ret != 0) {
                DBG_PRINTF("Packeting of dg[%d] fails\n", (int)i);
            }
            else if (picoquic_compare_addr((struct sockaddr*) & addr_s, (struct sockaddr*) & addr_ref) != 0) {
                ret = -1;
                DBG_PRINTF("Packeting of dg[%d]: address mismatch\n", (int)i);
            }
            else if (cid == NULL && dg_list[i].cid.id_len > 0) {
                ret = -1;
                DBG_PRINTF("Packeting of dg[%d]: cid not parsed\n", (int)i);
            }
            else if (cid != NULL && dg_list[i].cid.id_len == 0) {
                ret = -1;
                DBG_PRINTF("Packeting of dg[%d]: unexpected cid parsed\n", (int)i);
            }
            else if (dg_list[i].cid.id_len > 0 && picoquic_compare_connection_id(&dg_list[i].cid, cid) != 0) {
                ret = -1;
                DBG_PRINTF("Packeting of dg[%d]: cid mismatch\n", (int)i);
            }
            else if (packet_length != dg_list[i].packet_length) {
                ret = -1;
                DBG_PRINTF("Packeting  of dg[%d]: packet length mismatch\n", (int)i);
            }
            else if (memcmp(dg_list[i].packet, packet, packet_length) != 0) {
                ret = -1;
                DBG_PRINTF("Packeting  of dg[%d]: packet mismatch\n", (int)i);
            }
        }
    }

    /* Finally */
    while (hc_head != NULL) {
        picoqinq_header_compression_t* hc = hc_head;
        hc_head = hc_head->next_hc;
        free(hc);
    }

    return ret;
}

/* Test of the server side address table management.
 *  - Simulate prior departure of a number of packets from the server.
 *  - Simulate packet arrival.
 *  - Verify that the test provides the desired outcome.
 *
 * The addresses are entered in a test list, which is parsed to a list
 * of sockaddr * in the test program.
 *

 */

struct st_qinq_test_address_list_t {
    char const* ip_addr;
    uint16_t port;
};

struct st_qinq_test_address_table_t {
    int direction; /* departure = 0, arrival = 1 */
    int address_list_index;
    uint64_t time_interval;
    int cnx_index; /* -1 if retrieval is not expected */
};

#define QINQ_NB_TEST_ADDRESS 9
#define QINQ_NB_TEST_CNX 4

static const struct st_qinq_test_address_list_t address_list[QINQ_NB_TEST_ADDRESS] = {
    { "10.0.0.1", 443 },
    { "10.0.0.1", 4433 },
    { "10.0.0.1", 4434 },
    { "10.0.0.2", 443 },
    { "10.0.0.2", 4433 },
    { "10.0.0.2", 4434 },
    { "2001::dead:beef", 443},
    { "2001::c001:ca7", 443},
    { "2001::bad:cafe", 443}
};

static const struct st_qinq_test_address_table_t address_event[] = {
    { 1, 0, 0, -1}, /* No answer if unknown */
    { 0, 0, 100000, 0},
    { 1, 0, 100000, 0}, /* answer if known */
    { 1, 0, PICOQINQ_ADDRESS_USE_TIME_DEFAULT + 100000, -1}, /* Disappears after delay */
    { 0, 0, 100000, 0},
    { 0, 0, 100000, 1},
    { 1, 0, 100000, 1}, /* Most recent win */
    { 0, 1, 100000, 2},
    { 0, 2, 100000, 3},
    { 1, 1, 1000, 2}, /* use correct address */
    { 1, 2, 1000, 3}, /* use correct address */
    { 1, 3, 1000, -1}, /* unknown */
    { 0, 6, 1000, 0},
    { 1, 6, 1000, 0}, /* retreive IPv6 */
    { 0, 7, 1000, 1}, 
    { 0, 8, 1000, 2}, 
    { 1, 7, 1000, 1}, /* use correct IPv6 */
    { 0, 7, 1000, 2},
    { 1, 7, 1000, 2}, /* use most recent IPv6 IPv6 */
    { 2, 0, 1000, 2}, /* Delete connection #2 */
    { 1, 7, 1000, 1} /* use correct IPv6 */
};

static const size_t nb_address_event = sizeof(address_event) / sizeof(struct st_qinq_test_address_table_t);

int qinq_address_table_test()
{
    struct sockaddr_storage addr_s[QINQ_NB_TEST_ADDRESS];
    picoqinq_srv_ctx_t* qinq;
    picoqinq_srv_cnx_ctx_t* cnx_ctx[QINQ_NB_TEST_CNX];
    picoqinq_srv_cnx_ctx_t* c;
    int c_match;
    int ret = 0;
    uint64_t current_time = 0;

    memset(cnx_ctx, 0, sizeof(cnx_ctx));

    qinq = picoqinq_create_srv_ctx(NULL, 4, QINQ_NB_TEST_CNX);
    if (qinq == NULL) {
        DBG_PRINTF("Cannot create qinq context with %d connections\n", QINQ_NB_TEST_CNX);
        ret = -1;
    }

    for (size_t i = 0; ret == 0 && i < QINQ_NB_TEST_ADDRESS; i++) {
        if ((ret = picoquic_store_text_addr(&addr_s[i], address_list[i].ip_addr, address_list[i].port)) != 0) {
            DBG_PRINTF("Cannot parse address %s, port %d, ret=%d\n", address_list[i].ip_addr, address_list[i].port, ret);
        }
    }

    for (int x = 0; ret == 0 && x < QINQ_NB_TEST_CNX; x++) {
        if ((cnx_ctx[x] = picoqinq_create_srv_cnx_ctx(qinq, NULL)) == NULL) {
            DBG_PRINTF("Cannot create connection #%d\n", x);
            ret = -1;
        }
    }

    for (size_t i = 0; ret == 0 && i < nb_address_event; i++) {
        current_time += address_event[i].time_interval;

        switch (address_event[i].direction) {
        case 0:
            ret = picoqinq_cnx_address_link_create_or_touch(cnx_ctx[address_event[i].cnx_index],
                (const struct sockaddr*) & addr_s[address_event[i].address_list_index], current_time);
            if (ret != 0) {
                DBG_PRINTF("Cannot touch address %d, conx %d at event %d\n",
                    address_event[i].address_list_index, address_event[i].cnx_index, (int)i);
            }
            break;
        case 1:
            c = picoqinq_find_best_proxy_for_incoming(qinq, (picoquic_connection_id_t*)NULL, (const struct sockaddr*) & addr_s[address_event[i].address_list_index], current_time);
            c_match = -1;

            for (int x = 0; ret == 0 && x < QINQ_NB_TEST_CNX; x++) {
                if (cnx_ctx[x] == c) {
                    c_match = x;
                    break;
                }
            }
            if (c_match != address_event[i].cnx_index) {
                DBG_PRINTF("For event %d, found connection %d instead of %d", (int)i, c_match, address_event[i].cnx_index);
                ret = -1;
            } else if (c_match != -1 && c == NULL){
                DBG_PRINTF("For event %d, found connection %x instead of NULL", (int)i, c);
                ret = -1;
            }
            break;
        case 2:
            picoqinq_delete_srv_cnx_ctx(cnx_ctx[address_event[i].cnx_index]);
            cnx_ctx[address_event[i].cnx_index] = NULL;
            break;
        default:
            DBG_PRINTF("Unsupported event: %d\n", address_event[i].direction);
            ret = -1;
            break;
        }
    }

    for (int x = 0; x < QINQ_NB_TEST_CNX; x++) {
        if (cnx_ctx[x] != NULL) {
            picoqinq_delete_srv_cnx_ctx(cnx_ctx[x]);
            cnx_ctx[x] = NULL;
        } 
    }

    if (qinq != NULL) {
        picoqinq_delete_srv_ctx(qinq);
        qinq = NULL;
    }

    return ret;
}

/* Proxy simulation setup */
#define PICOQINQ_SIM_NB_CTX 3
#define PICOQINQ_SIM_NB_LINK 4
#define PICOQINQ_SIM_CLIENT 0
#define PICOQINQ_SIM_SERVER 1
#define PICOQINQ_SIM_PROXY 2

struct st_picoqinq_test_ctx_t {
    uint64_t simulated_time;
    picoquic_quic_t* qctx[PICOQINQ_SIM_NB_CTX];
    struct sockaddr_storage addr_s[PICOQINQ_SIM_NB_CTX];
    picoqinq_srv_ctx_t* qinq_srv;
    char test_server_cert_file[512];
    char test_server_key_file[512];
    char test_server_cert_store_file[512];
    picoquictest_sim_link_t* link[PICOQINQ_SIM_NB_LINK];
    int link_src[PICOQINQ_SIM_NB_LINK];
    int link_dest[PICOQINQ_SIM_NB_LINK];
    picoquic_demo_callback_ctx_t callback_ctx;
    picoquic_cnx_t* cnx_proxy;
};

void picoqinq_test_ctx_delete(struct st_picoqinq_test_ctx_t* test_ctx)
{
    for (int i = 0; i < PICOQINQ_SIM_NB_CTX; i++) {
        if (test_ctx->qctx[i] != NULL) {
            picoquic_free(test_ctx->qctx[i]);
            test_ctx->qctx[i] = NULL;
        }
    }

    for (int i = 0; i < PICOQINQ_SIM_NB_LINK; i++) {
        if (test_ctx->link[i] != NULL) {
            picoquictest_sim_link_delete(test_ctx->link[i]);
            test_ctx->link[i] = NULL;
        }
    }

    free(test_ctx);
}

struct st_picoqinq_test_ctx_t* picoqinq_test_ctx_init()
{
    struct st_picoqinq_test_ctx_t* test_ctx = (struct st_picoqinq_test_ctx_t*)malloc(sizeof(struct st_picoqinq_test_ctx_t));
    const char* addr_txt[3] = { "10.0.0.1", "10.0.0.2", "10.0.0.3" };

    if (test_ctx != NULL) {
        int ret = 0;

        memset(test_ctx, 0, sizeof(struct st_picoqinq_test_ctx_t));

        ret = picoquic_get_input_path(test_ctx->test_server_cert_file, sizeof(test_ctx->test_server_cert_file), picoquic_solution_dir, PICOQUIC_TEST_FILE_SERVER_CERT);

        if (ret == 0) {
            ret = picoquic_get_input_path(test_ctx->test_server_key_file, sizeof(test_ctx->test_server_key_file), picoquic_solution_dir, PICOQUIC_TEST_FILE_SERVER_KEY);
        }

        if (ret == 0) {
            ret = picoquic_get_input_path(test_ctx->test_server_cert_store_file, sizeof(test_ctx->test_server_cert_store_file), picoquic_solution_dir, PICOQUIC_TEST_FILE_CERT_STORE);
        }

        for (int i = 0; ret == 0 && i < PICOQINQ_SIM_NB_CTX; i++) {
            if ((ret = picoquic_store_text_addr(&test_ctx->addr_s[i], addr_txt[i], 443)) != 0) {
                DBG_PRINTF("Cannot initialize addresses, ret=%d\n", ret);
            }
        }

        if (ret == 0 && (
            (test_ctx->qctx[PICOQINQ_SIM_CLIENT] = picoquic_create(8, NULL, NULL, test_ctx->test_server_cert_store_file, NULL, NULL, NULL, NULL, NULL, NULL, test_ctx->simulated_time, &test_ctx->simulated_time, NULL, NULL, 0)) == NULL ||
            (test_ctx->qctx[PICOQINQ_SIM_SERVER] = picoquic_create(8, test_ctx->test_server_cert_file, test_ctx->test_server_key_file, test_ctx->test_server_cert_store_file, PICOHTTP_ALPN_H3_LATEST, h3zero_server_callback, NULL, NULL, NULL, NULL, test_ctx->simulated_time, &test_ctx->simulated_time, NULL, NULL, 0)) == NULL ||
            (test_ctx->qctx[PICOQINQ_SIM_PROXY] = picoquic_create(8, test_ctx->test_server_cert_file, test_ctx->test_server_key_file, test_ctx->test_server_cert_store_file, PICOQINQ_ALPN, picoqinq_server_callback, NULL, NULL, NULL, NULL, test_ctx->simulated_time, &test_ctx->simulated_time, NULL, NULL, 0)) == NULL ||
            (test_ctx->qinq_srv = picoqinq_create_srv_ctx(test_ctx->qctx[PICOQINQ_SIM_PROXY], 4, 8)) == NULL )){
            ret = -1;
        }
        else {
            picoquic_set_default_callback(test_ctx->qctx[2], picoqinq_server_callback, test_ctx->qinq_srv);
        }

        for (int i = 0; ret == 0 && i < PICOQINQ_SIM_NB_LINK; i++) {
            if ((test_ctx->link[i] = picoquictest_sim_link_create(0.01, 10000, NULL, 0, 0)) == NULL) {
                ret = -1;
            }
        }

        if (ret == 0) {
            test_ctx->link_src[0] = PICOQINQ_SIM_CLIENT;
            test_ctx->link_src[1] = PICOQINQ_SIM_SERVER;
            test_ctx->link_src[2] = PICOQINQ_SIM_PROXY;
            test_ctx->link_src[3] = PICOQINQ_SIM_PROXY;
            test_ctx->link_dest[0] = PICOQINQ_SIM_PROXY;
            test_ctx->link_dest[1] = PICOQINQ_SIM_PROXY;
            test_ctx->link_dest[2] = PICOQINQ_SIM_CLIENT;
            test_ctx->link_dest[3] = PICOQINQ_SIM_SERVER;
        }


        if (ret != 0) {
            DBG_PRINTF("%s", "Cannot allocate initial contexts.\n");
            picoqinq_test_ctx_delete(test_ctx);
            test_ctx = NULL;
        }

    }

    return test_ctx;
}

int picoqinq_test_sim_step(struct st_picoqinq_test_ctx_t* test_ctx)
{
    int ret = 0;
    int selected_link = -1;
    int selected_ctx = -1;
    int is_stateless = 0;
    uint64_t next_time = UINT64_MAX;

    /* Find next arrival or departure time */
    for (int i=0; i< PICOQINQ_SIM_NB_CTX; i++){
        if (test_ctx->qctx[i]->pending_stateless_packet != NULL) {
            selected_ctx = i;
            is_stateless = 1;
            next_time = test_ctx->simulated_time;
        } else if (test_ctx->qctx[i]->cnx_wake_first != NULL) {
            if (test_ctx->qctx[i]->cnx_wake_first->next_wake_time < next_time) {
                selected_ctx = i;
                is_stateless = 0;
                next_time = test_ctx->qctx[i]->cnx_wake_first->next_wake_time;
            }
        }
    }

    for (int i = 0; i < PICOQINQ_SIM_NB_LINK; i++) {
        picoquictest_sim_packet_t* packet = test_ctx->link[i]->first_packet;

        if (packet != NULL && packet->arrival_time < next_time) {
            next_time = packet->arrival_time;
            selected_link = i;
        }
    }

    /* Progress the time */
    if (next_time < UINT64_MAX && next_time > test_ctx->simulated_time) {
        test_ctx->simulated_time = next_time;
    }

    /* If next event is arrival, do it */
    if (selected_link >= 0) {
        picoquictest_sim_packet_t* packet = picoquictest_sim_link_dequeue(test_ctx->link[selected_link], test_ctx->simulated_time);

        if (packet == NULL) {
            ret = -1;
        } else {
            int dest = test_ctx->link_dest[selected_link];

            if (dest == PICOQINQ_SIM_PROXY) {
                ret = picoqinq_server_incoming_packet(test_ctx->qinq_srv, packet->bytes, (uint32_t)packet->length,
                    (struct sockaddr*) & packet->addr_from,
                    (struct sockaddr*) & packet->addr_to, 0, 0,
                    test_ctx->simulated_time);
            }
            else {
                ret = picoquic_incoming_packet(test_ctx->qctx[test_ctx->link_dest[selected_link]], packet->bytes, (uint32_t)packet->length,
                    (struct sockaddr*) & packet->addr_from,
                    (struct sockaddr*) & packet->addr_to, 0, 0,
                    test_ctx->simulated_time);
                free(packet);
            }
        }
    }
    else if (selected_ctx >= 0) {
        picoquictest_sim_packet_t* packet = picoquictest_sim_link_create_packet();

        if (packet == NULL) {
            ret = -1;
        }
        else if (is_stateless) {
            picoquic_stateless_packet_t* sp = picoquic_dequeue_stateless_packet(test_ctx->qctx[selected_ctx]);

            if (sp == NULL) {
                ret = -1;
            } else {
                if (sp->length > 0) {
                    picoquic_store_addr(&packet->addr_from, (struct sockaddr*) & sp->addr_local);
                    picoquic_store_addr(&packet->addr_to, (struct sockaddr*) & sp->addr_to);
                    memcpy(packet->bytes, sp->bytes, sp->length);
                    packet->length = sp->length;
                }
                picoquic_delete_stateless_packet(sp);
            }
        }
        else if (test_ctx->qctx[selected_ctx]->cnx_wake_first == NULL) {
            ret = -1; /* unexpected */
        }
        else {
            /* check whether there is something to send */

            ret = picoquic_prepare_packet(test_ctx->qctx[selected_ctx]->cnx_wake_first, test_ctx->simulated_time,
                packet->bytes, PICOQUIC_MAX_PACKET_SIZE, &packet->length,
                &packet->addr_to, &packet->addr_from);
            if (ret != 0)
            {
                /* useless test, but makes it easier to add a breakpoint under debugger */
                ret = -1;
            }
        }

        if (ret == 0 && packet->length > 0 && selected_ctx == PICOQINQ_SIM_CLIENT &&
            picoquic_compare_addr((struct sockaddr*) & packet->addr_from, (struct sockaddr*) & test_ctx->addr_s[PICOQINQ_SIM_PROXY]) == 0) {
            /* Simulate interception by proxy connection */
            ret = picoqinq_forward_outgoing_packet(test_ctx->cnx_proxy, packet->bytes, packet->length, (struct sockaddr*) & packet->addr_to, test_ctx->simulated_time);
            packet->length = 0;
        }

        if (ret == 0 && packet->length > 0) {
             /* Verify that addresses are what we expect */
            int target_link = -1;
            if (packet->addr_from.ss_family == 0) {
                (void)picoquic_store_addr(&packet->addr_from, (struct sockaddr*) & test_ctx->addr_s[selected_ctx]);
            }
            else if (picoquic_compare_addr((struct sockaddr*) &packet->addr_from, (struct sockaddr*) & test_ctx->addr_s[selected_ctx]) != 0) {
                /* topology violation*/
                DBG_PRINTF("Wrong source address for ctx: %d", selected_ctx);
                ret = -1;
            }

            if (ret == 0) {
                for (int i = 0; i < PICOQINQ_SIM_NB_LINK; i++) {
                    if (picoquic_compare_addr((struct sockaddr*) &packet->addr_from, (struct sockaddr*) & test_ctx->addr_s[test_ctx->link_src[i]]) == 0 &&
                        picoquic_compare_addr((struct sockaddr*) &packet->addr_to, (struct sockaddr*) & test_ctx->addr_s[test_ctx->link_dest[i]]) == 0) {
                        target_link = i;
                        break;
                    }
                }

                if (target_link < 0) {
                    DBG_PRINTF("No link for address selected by ctx: %d", selected_ctx);
                    ret = -1;
                }
                else {
                    picoquictest_sim_link_submit(test_ctx->link[target_link], packet, test_ctx->simulated_time);
                }
            }
        }

        if (ret != 0 || packet->length == 0) {
            free(packet);
        }
    }
    else
    {
        ret = -1;
    }


    return ret;
}

/* Connection check
 */
int picoqinq_test_sim_connection(struct st_picoqinq_test_ctx_t* test_ctx, picoquic_cnx_t* cnx_ctx)
{
    int ret = 0;

    while (ret == 0 && cnx_ctx->cnx_state < picoquic_state_client_almost_ready) {
        ret = picoqinq_test_sim_step(test_ctx);
    }

    if (ret == 0 && cnx_ctx->cnx_state > picoquic_state_ready) {
        DBG_PRINTF("Connection failed, state: %d", cnx_ctx->cnx_state);
        ret = -1;
    }

    return ret;
}

/* End to end test 
 * Set a network with three nodes: client, proxy and server.
 * Server supports test.
 * Client supports test and qinq.
 * Proxy supports qinq.
 *
 * Set proxy connection from client to proxy.
 * Set connection from client to server.
 * 
 * Verify that the connection is routed via the proxy.
 * Verify that a basic scenario works.
 * 
 * Close.
 */

int qinq_e2e_basic_test()
{
    struct st_picoqinq_test_ctx_t* test_ctx = picoqinq_test_ctx_init();
    int ret = 0;

    if (test_ctx == NULL) {
        ret = -1;
    }
    else {
        /* First, set a connection between client and proxy */

        test_ctx->cnx_proxy = picoquic_create_client_cnx(
            test_ctx->qctx[PICOQINQ_SIM_CLIENT],(struct sockaddr*) & test_ctx->addr_s[PICOQINQ_SIM_PROXY], 
            test_ctx->simulated_time, 0, PICOQUIC_TEST_SNI, PICOQINQ_ALPN, picoqinq_client_callback, NULL);

        if (test_ctx->cnx_proxy != NULL) {
            /* Simulate the connection establishment */
            ret = picoqinq_test_sim_connection(test_ctx, test_ctx->cnx_proxy);
        }
        else {
            ret = -1;
        }

        if (ret == 0) {
            size_t client_sc_nb = 0;
            picoquic_demo_stream_desc_t* client_sc;

            test_ctx->cnx_proxy->path[0]->send_mtu = 1400;

            ret = demo_client_parse_scenario_desc("/", &client_sc_nb, &client_sc);
            if (ret != 0) {
                fprintf(stdout, "Cannot parse the specified scenario.\n");
                return -1;
            }
            else {
                ret = picoquic_demo_client_initialize_context(&test_ctx->callback_ctx, client_sc, client_sc_nb, PICOHTTP_ALPN_H3_LATEST, 0, 0);
            }
        }

        if (ret == 0) {
            /* Set a connection between client and server. Set local address to proxy address. */
            picoquic_cnx_t* cnx_client = picoqinq_create_proxied_cnx(
                test_ctx->cnx_proxy, (struct sockaddr*) & test_ctx->addr_s[PICOQINQ_SIM_SERVER],
                test_ctx->simulated_time, 0, PICOQUIC_TEST_SNI, PICOHTTP_ALPN_H3_LATEST,
                picoquic_demo_client_callback, &test_ctx->callback_ctx);

            if (cnx_client == NULL) {
                ret = -1;
                DBG_PRINTF("%s", "Could not create the client connection");
            }
            else {
                /* Simulate the three party connection until established. */
                ret = picoqinq_test_sim_connection(test_ctx, cnx_client);
                if (ret != 0) {
                    DBG_PRINTF("Could not establish the end to end connection, ret=%x", ret);
                }
            }
        }

        /* TODO: Send one data request over client connection */

        /* TODO: Run until some data is received */

        /* TODO: If data arrived, declare victory */

        picoqinq_test_ctx_delete(test_ctx);
    }

    return ret;
}