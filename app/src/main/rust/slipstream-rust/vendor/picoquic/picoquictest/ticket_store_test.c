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
#include "picoquictest_internal.h"
#include <stdlib.h>
#include <string.h>

static char const* test_ticket_file_name = "ticket_store_test.bin";
static char const* test_token_file_name = "token_store_test.bin";
static char const* test_sni[] = { "example.com", "example.net", "test.example.com" };
static char const* test_alpn[] = { "hq05", "hq07", "hq09" };
static const uint32_t test_version[] = { 0x00000001, 0xFF000020, 0x00000002 };
static const size_t nb_test_sni = sizeof(test_sni) / sizeof(char const*);
static const size_t nb_test_alpn = sizeof(test_alpn) / sizeof(char const*);
static picoquic_tp_t test_tp = {
    123, 456, 78, 91011, 1234, 567, 0, 0, 0, 0, 0, 0,
    { 0, {0,0,0,0}, 0, {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}, 0,
        {{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}, 0},
        {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}}, 0
};

static int create_test_ticket(uint64_t current_time, uint32_t ttl, uint8_t* buf, uint16_t len)
{
    int ret = 0;
    if (len < 35) {
        ret = -1;
    } else {
        uint16_t t_length = len - 31;
        picoformat_64(buf, current_time);
        buf[8] = 0;
        buf[9] = 1;
        buf[10] = 0;
        buf[11] = (uint8_t)(t_length >> 8);
        buf[12] = (uint8_t)(t_length & 0xFF);
        picoformat_32(buf + 13, ttl);
        memset(buf + 17, 0xcc, len - 17);
        buf[len - 18] = 0;
        buf[len - 17] = 16;
    }

    return ret;
}

static int ticket_store_compare(picoquic_stored_ticket_t* s1, picoquic_stored_ticket_t* s2)
{
    int ret = 0;
    picoquic_stored_ticket_t* c1 = s1;
    picoquic_stored_ticket_t* c2 = s2;

    while (ret == 0 && c1 != 0) {
        if (c2 == 0) {
            ret = -1;
        } else {
            if (c1->time_valid_until != c2->time_valid_until ||
                c1->sni_length != c2->sni_length || c1->alpn_length != c2->alpn_length ||
                c1->version != c2->version ||
                c1->ip_addr_length != c2->ip_addr_length || c1->ticket_length != c2->ticket_length ||
                memcmp(c1->sni, c2->sni, c1->sni_length) != 0 || 
                memcmp(c1->alpn, c2->alpn, c1->alpn_length) != 0 ||
                memcmp(c1->ip_addr, c2->ip_addr, c1->ip_addr_length) != 0 ||
                memcmp(c1->ip_addr_client, c2->ip_addr_client, c1->ip_addr_client_length) != 0 ||
                memcmp(c1->ticket, c2->ticket, c1->ticket_length) != 0) {
                ret = -1;
            } else {
                for (int i = 0; i < PICOQUIC_NB_TP_0RTT; i++) {
                    if (c1->tp_0rtt[i] != c2->tp_0rtt[i]) {
                        ret = -1;
                        break;
                    }
                }
                if (ret == 0) {
                    c1 = c1->next_ticket;
                    c2 = c2->next_ticket;
                }
            }
        }
    }

    if (ret == 0 && c1 == NULL && c2 != NULL) {
        ret = -1;
    }

    return ret;
}

int ticket_store_test()
{
    int ret = 0;
    picoquic_stored_ticket_t* p_first_ticket = NULL;
    picoquic_stored_ticket_t* p_first_ticket_bis = NULL;
    picoquic_stored_ticket_t* p_first_ticket_ter = NULL;
    uint8_t ipv4_test[4] = { 10, 0, 0, 1 };
    uint8_t ipv6_test[16] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };

    uint64_t ticket_time = 40000000000ull;
    uint64_t current_time = 50000000000ull;
    uint64_t retrieve_time = 60000000000ull;
    uint64_t too_late_time = 150000000000ull;
    uint32_t ttl = 100000;
    uint8_t ticket[128];
    uint64_t simulated_time = current_time;
    picoquic_quic_t * quic = picoquic_create(8, NULL, NULL, NULL, NULL, NULL, NULL,
        NULL, NULL, NULL, 0, &simulated_time, NULL, NULL, 0);

    if (quic == NULL) {
        ret = -1;
    }

    if (ret == 0) {
        /* Writing an empty file */
        ret = picoquic_save_tickets(p_first_ticket, current_time, test_ticket_file_name);
    }

    /* Load the empty file again */
    if (ret == 0) {
        simulated_time = retrieve_time;
        ret = picoquic_load_tickets(quic, test_ticket_file_name);

        /* Verify that the content is empty */
        if (quic->p_first_ticket != NULL) {
            if (ret == 0) {
                ret = -1;
            }
            picoquic_free_tickets(&quic->p_first_ticket);
        }
    }

    /* Generate a set of tickets */
    for (size_t i = 0; ret == 0 && i < nb_test_sni; i++) {
        for (size_t j = 0; ret == 0 && j < nb_test_alpn; j++) {
            uint16_t ticket_length = (uint16_t)(64 + j * nb_test_sni + i);
            uint64_t test_ticket_time = ticket_time / 1000;
            size_t delta_factor = (i * nb_test_alpn) + j;
            uint64_t delta_time = ((uint64_t)1000) * delta_factor;
            uint8_t ip_addr_length = 0;
            uint8_t* ip_addr = NULL;
            uint8_t ip_addr_client_length = 0;
            uint8_t* ip_addr_client = NULL;

            test_ticket_time += delta_time;
            ret = create_test_ticket(test_ticket_time, ttl, ticket, ticket_length);

            if (ret != 0) {
                break;
            }

            if ((i & 7) != 0) {
                if ((i & 1) != 0) {
                    ip_addr_length = 16;
                    ip_addr = ipv6_test;
                }
                else {
                    ip_addr_length = 4;
                    ip_addr = ipv4_test;
                }
                if ((i & 2) != 0) {
                    ip_addr_client_length = 16;
                    ip_addr_client = ipv6_test;
                }
                else {
                    ip_addr_client_length = 4;
                    ip_addr_client = ipv4_test;
                }
            }
            ret = picoquic_store_ticket(quic,
                test_sni[i], (uint16_t)strlen(test_sni[i]),
                test_alpn[j], (uint16_t)strlen(test_alpn[j]),
                test_version[j], ip_addr, ip_addr_length,
                ip_addr_client, ip_addr_client_length,
                ticket, ticket_length, &test_tp);
            if (ret != 0) {
                break;
            }
        }
        p_first_ticket = quic->p_first_ticket;
    }

    /* Verify that they can be retrieved */
    for (size_t i = 0; ret == 0 && i < nb_test_sni; i++) {
        for (size_t j = 0; ret == 0 && j < nb_test_alpn; j++) {
            uint16_t ticket_length = 0;
            uint16_t expected_length = (uint16_t)(64 + j * nb_test_sni + i);
            uint8_t* ticket = NULL;
            ret = picoquic_get_ticket(quic,
                test_sni[i], (uint16_t)strlen(test_sni[i]),
                test_alpn[j], (uint16_t)strlen(test_alpn[j]),
                test_version[j],
                &ticket, &ticket_length, NULL, 0);
            if (ret != 0) {
                break;
            }
            if (ticket_length != expected_length) {
                ret = -1;
                break;
            }
        }
    }
    /* Store them on a file */
    if (ret == 0) {
        ret = picoquic_save_tickets(quic->p_first_ticket, current_time, test_ticket_file_name);
    }
    /* Load the file again */
    if (ret == 0) {
        p_first_ticket = quic->p_first_ticket;
        quic->p_first_ticket = NULL;

        simulated_time = retrieve_time;
        ret = picoquic_load_tickets(quic, test_ticket_file_name);
    }

    /* Verify that the two contents match */
    if (ret == 0) {
        p_first_ticket_bis = quic->p_first_ticket;
        ret = ticket_store_compare(p_first_ticket, p_first_ticket_bis);
    }

    /* Reload after a long time */
    if (ret == 0) {
        quic->p_first_ticket = NULL;
        simulated_time = too_late_time;
        ret = picoquic_load_tickets(quic, test_ticket_file_name);
        p_first_ticket_ter = quic->p_first_ticket;
        quic->p_first_ticket = NULL;
        if (ret == 0 && p_first_ticket_ter != NULL) {
            ret = -1;
        }
    }
    /* Free what needs be */
    picoquic_free_tickets(&p_first_ticket);
    picoquic_free_tickets(&p_first_ticket_bis);
    picoquic_free_tickets(&p_first_ticket_ter);

    if (quic != NULL) {
        picoquic_free(quic);
    }

    return ret;
}

/*
 * The token store is extremely similar to the ticket store.
 */


static uint8_t const test_addr1[] = { 127, 0, 0, 1 };
static uint8_t const test_addr2[] = { 128, 12, 34, 56 };
static uint8_t const test_addr3[] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
static uint8_t const test_addr4[] = { 0x20, 1, 2, 3, 4, 5, 6, 7, 0, 0, 0, 0, 0, 0, 0, 1 };

typedef struct st_test_token_store_addr_t {
    uint8_t const * ip_addr;
    uint8_t ip_addr_length;
} test_token_store_addr_t;

static test_token_store_addr_t test_ip_addr[] = {
    { test_addr1, (uint8_t)sizeof(test_addr1) },
    { test_addr2, (uint8_t)sizeof(test_addr2) },
    { test_addr3, (uint8_t)sizeof(test_addr3) },
    { test_addr4, (uint8_t)sizeof(test_addr4) },
};

static size_t nb_test_ip_addr = sizeof(test_ip_addr) / sizeof(test_token_store_addr_t);

static int create_test_token(uint64_t current_time, uint32_t ttl, uint8_t* buf, uint16_t len)
{
    int ret = 0;
    if (len < 35) {
        ret = -1;
    }
    else {
        uint16_t t_length = len - 31;
        picoformat_64(buf, current_time);
        buf[8] = 0;
        buf[9] = 1;
        buf[10] = 0;
        buf[11] = (uint8_t)(t_length >> 8);
        buf[12] = (uint8_t)(t_length & 0xFF);
        picoformat_32(buf + 13, ttl);
        memset(buf + 17, 0xcc, len - 17);
        buf[len - 18] = 0;
        buf[len - 17] = 16;
    }

    return ret;
}

static int token_store_compare(picoquic_stored_token_t* s1, picoquic_stored_token_t* s2)
{
    int ret = 0;
    picoquic_stored_token_t* c1 = s1;
    picoquic_stored_token_t* c2 = s2;

    while (ret == 0 && c1 != 0) {
        if (c2 == 0) {
            ret = -1;
        }
        else {
            if (c1->time_valid_until != c2->time_valid_until || c1->sni_length != c2->sni_length || 
                c1->ip_addr_length != c2->ip_addr_length || c1->token_length != c2->token_length ||
                memcmp(c1->sni, c2->sni, c1->sni_length) != 0 || 
                memcmp(c1->ip_addr, c2->ip_addr, c1->ip_addr_length) != 0 || 
                memcmp(c1->token, c2->token, c1->token_length) != 0) {
                ret = -1;
            }
            else {
                c1 = c1->next_token;
                c2 = c2->next_token;
            }
        }
    }

    if (ret == 0 && c1 == NULL && c2 != NULL) {
        ret = -1;
    }

    return ret;
}

int token_store_test()
{
    int ret = 0;
    picoquic_stored_token_t* p_first_token = NULL;
    picoquic_stored_token_t* p_first_token_bis = NULL;
    picoquic_stored_token_t* p_first_token_ter = NULL;

    uint64_t token_time = 40000000000ull;
    uint64_t current_time = 50000000000ull;
    uint64_t retrieve_time = 60000000000ull;
    uint64_t too_late_time = 150000000000ull;
    uint32_t ttl = 100000;
    uint8_t token[128];
    uint64_t simulated_time = current_time;
    picoquic_quic_t * quic = picoquic_create(8, NULL, NULL, NULL, NULL, NULL, NULL,
        NULL, NULL, NULL, 0, &simulated_time, NULL, NULL, 0);

    /* Writing an empty file */
    ret = picoquic_save_tokens(quic, test_token_file_name);

    /* Load the empty file again */
    if (ret == 0) {
        simulated_time = retrieve_time;
        ret = picoquic_load_tokens(quic, test_token_file_name);

        /* Verify that the content is empty */
        if (quic->p_first_token != NULL) {
            if (ret == 0) {
                ret = -1;
            }
            picoquic_free_tokens(&quic->p_first_token);
        }
    }

    /* Generate a set of tokens */
    for (size_t i = 0; ret == 0 && i < nb_test_sni; i++) {
        for (size_t j = 0; ret == 0 && j < nb_test_ip_addr; j++) {
            uint16_t token_length = (uint16_t)(64 + j * nb_test_sni + i);
            uint64_t test_ticket_time = token_time / 1000;
            size_t delta_factor = (i * nb_test_ip_addr) + j;
            uint64_t delta_time = ((uint64_t)1000) * delta_factor;
            test_ticket_time += delta_time;
            ret = create_test_token(test_ticket_time, ttl, token, token_length);

            if (ret != 0) {
                break;
            }
            ret = picoquic_store_token(quic,
                test_sni[i], (uint16_t)strlen(test_sni[i]),
                test_ip_addr[j].ip_addr, test_ip_addr[j].ip_addr_length,
                token, token_length);
            if (ret != 0) {
                break;
            }
        }
    }

    /* Verify that they can be retrieved */
    for (size_t i = 0; ret == 0 && i < nb_test_sni; i++) {
        for (size_t j = 0; ret == 0 && j < nb_test_alpn; j++) {
            uint16_t token_length = 0;
            uint16_t expected_length = (uint16_t)(64 + j * nb_test_sni + i);
            uint8_t* token = NULL;
            ret = picoquic_get_token(quic,
                test_sni[i], (uint16_t)strlen(test_sni[i]),
                test_ip_addr[j].ip_addr, test_ip_addr[j].ip_addr_length,
                &token, &token_length, 0);
            if (ret != 0) {
                break;
            }
            if (token_length != expected_length) {
                ret = -1;
                break;
            }

            if (token != NULL) {
                free(token);
                token = NULL;
            }
        }
    }
    /* Store them on a file */
    if (ret == 0) {
        ret = picoquic_save_tokens(quic, test_token_file_name);
        p_first_token = quic->p_first_token;
        quic->p_first_token = NULL;
    }
    /* Load the file again */
    if (ret == 0) {
        simulated_time = retrieve_time;
        ret = picoquic_load_tokens(quic, test_token_file_name);
        p_first_token_bis = quic->p_first_token;
        quic->p_first_token = NULL;
    }

    /* Verify that the two contents match */
    if (ret == 0) {
        ret = token_store_compare(p_first_token, p_first_token_bis);
    }

    /* Reload after a long time */
    if (ret == 0) {
        simulated_time = too_late_time;
        ret = picoquic_load_tokens(quic, test_token_file_name);

        p_first_token_ter = quic->p_first_token;
        quic->p_first_token = NULL;
        if (ret == 0 && p_first_token_ter != NULL) {
            ret = -1;
        }
    }
    /* Free what needs be */
    picoquic_free_tokens(&p_first_token);
    picoquic_free_tokens(&p_first_token_bis);
    picoquic_free_tokens(&p_first_token_ter);

    if (quic != NULL) {
        picoquic_free(quic);
    }
    return ret;
}

/* Check the protection against token reuse */
typedef struct st_token_reuse_api_case_t {
    uint64_t expiry_date;
    uint8_t token[16];
    size_t token_length;
} token_reuse_api_case_t;

static token_reuse_api_case_t token_reuse_api_cases[] = {
    { 2, { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}, 12},
    { 3, { 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14}, 12},
    { 3, { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}, 12},
    { 3, { 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}, 12},
    { 5, { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}, 12},
    { 7, { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}, 12},
    { 1, { 1, 2, 3, 4, 5, 6, 7, 8}, 8},
};

static size_t nb_token_reuse_api_cases = sizeof(token_reuse_api_cases) / sizeof(token_reuse_api_case_t);

int token_reuse_api_test()
{
    int ret = 0;
    uint64_t test_time = 4;
    uint64_t simulated_time = 0;
    picoquic_quic_t * quic = picoquic_create(4, NULL, NULL, NULL, "test", NULL, NULL, NULL, NULL,
        NULL, 0, &simulated_time, NULL, NULL, 0);

    if (quic == NULL) {
        DBG_PRINTF("%s", "Cannot create QUIC context");
        ret = -1;
    }
    else {
        /* Test that all tokens can be created */
        for (size_t i = 0; ret == 0 && i < nb_token_reuse_api_cases; i++) {
            if (picoquic_registered_token_check_reuse(quic,
                token_reuse_api_cases[i].token,
                token_reuse_api_cases[i].token_length,
                token_reuse_api_cases[i].expiry_date) != 0) {
                DBG_PRINTF("Token[%z] already used?", i);
                ret = -1;
            }
        }
        /* Test that all tokens can be detected as in use */
        for (size_t i = 0; ret == 0 && i < nb_token_reuse_api_cases; i++) {
            if (picoquic_registered_token_check_reuse(quic,
                token_reuse_api_cases[i].token,
                token_reuse_api_cases[i].token_length,
                token_reuse_api_cases[i].expiry_date) == 0) {
                DBG_PRINTF("Token[%z] not already used?", i);
                ret = -1;
            }
        }
        /* Remove tokens with t <= test_time */
        picoquic_registered_token_clear(quic, test_time);
        /* Test that all deleted tokens are absent and others are not */
        for (size_t i = 0; ret == 0 && i < nb_token_reuse_api_cases; i++) {
            int x = picoquic_registered_token_check_reuse(quic,
                token_reuse_api_cases[i].token,
                token_reuse_api_cases[i].token_length,
                token_reuse_api_cases[i].expiry_date);
            if (x == 0 && token_reuse_api_cases[i].expiry_date >= test_time){
                DBG_PRINTF("Token[%z], time %" PRIu64 " not already used?", i, token_reuse_api_cases[i].expiry_date);
                ret = -1;
            }
            if (x != 0 && token_reuse_api_cases[i].expiry_date < test_time) {
                DBG_PRINTF("Token[%z], time %" PRIu64 " already used?", i, token_reuse_api_cases[i].expiry_date);
                ret = -1;
            }
        }
        /* Check refusal with length < 8 */
        for (size_t l = 0; ret == 0 && l < 8; l++) {
            if (picoquic_registered_token_check_reuse(quic,
                token_reuse_api_cases[0].token, l,
                token_reuse_api_cases[0].expiry_date) == 0) {
                DBG_PRINTF("Token[1] length %z accepted?", l);
                ret = -1;
            }
        }

        picoquic_free(quic);
    }

    return ret;
}

/* Ticket seed. Do a connection, and verify that server and client have properly
 * documented the congestion parameters in the outgoing or incoming tickets
 */
static char const* ticket_seed_store = "ticket_seed_store.bin";
static test_api_stream_desc_t test_scenario_ticket_seed[] = {
    { 4, 0, 257, 1000000 }
};

int ticket_seed_test_one(int bdp_option)
{
    int ret = 0;
    uint64_t simulated_time = 0;
    uint64_t loss_mask = 0;
    uint64_t max_completion_microsec = 1000000;
    uint64_t server_ticket_id = 0;
    uint64_t client_ticket_id = 0;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;

    /* Initialize an empty ticket store */
    ret = picoquic_save_tickets(NULL, simulated_time, ticket_seed_store);

    /* Prepare a first connection */
    ret = tls_api_init_ctx(&test_ctx, PICOQUIC_INTERNAL_TEST_VERSION_1,
        PICOQUIC_TEST_SNI, PICOQUIC_TEST_ALPN, &simulated_time, ticket_seed_store, NULL, 0, 0, 0);

    picoquic_set_default_bdp_frame_option(test_ctx->qclient, bdp_option);
    picoquic_set_default_bdp_frame_option(test_ctx->qserver, bdp_option);

    if (ret == 0) {
        ret = tls_api_connection_loop(test_ctx, &loss_mask, 0, &simulated_time);
    }

    /* Prepare to send data */
    if (ret == 0) {
        ret = test_api_init_send_recv_scenario(test_ctx, test_scenario_ticket_seed, sizeof(test_scenario_ticket_seed));
    }

    /* Perform a data sending loop */
    if (ret == 0) {
        ret = tls_api_data_sending_loop(test_ctx, &loss_mask, &simulated_time, 0);
    }

    if (ret == 0) {
        ret = tls_api_one_scenario_body_verify(test_ctx, &simulated_time, max_completion_microsec);
    }

    if (ret == 0) {
        /* Check the ticket store at the client. */
        picoquic_stored_ticket_t* client_ticket;
        client_ticket = picoquic_get_stored_ticket(test_ctx->qclient,
            PICOQUIC_TEST_SNI, (uint16_t)strlen(PICOQUIC_TEST_SNI),
            PICOQUIC_TEST_ALPN, (uint16_t)strlen(PICOQUIC_TEST_ALPN),
            0, 0, test_ctx->cnx_client->issued_ticket_id);

        if (client_ticket == NULL) {
            DBG_PRINTF("%s", "No ticket found for client.");
            ret = -1;
        }
        else {
            client_ticket_id = test_ctx->cnx_client->issued_ticket_id;

            if (client_ticket->tp_0rtt[picoquic_tp_0rtt_rtt_local] == 0) {
                DBG_PRINTF("%s", "RTT not set for client ticket.");
                ret = -1;
            }
            if (client_ticket->tp_0rtt[picoquic_tp_0rtt_cwin_local] == 0) {
                DBG_PRINTF("%s", "CWIN not set for client ticket.");
                ret = -1;
            }
        }
    }

    if (ret == 0) {
        /* Check the issued tickets list at the server. */
        picoquic_issued_ticket_t* server_ticket;

        if (test_ctx->cnx_server == NULL) {
            server_ticket = test_ctx->qserver->table_issued_tickets_first;
        }
        else {
            server_ticket = picoquic_retrieve_issued_ticket(test_ctx->qserver,
                test_ctx->cnx_server->issued_ticket_id);
        }
        if (server_ticket == NULL) {
            DBG_PRINTF("%s", "No ticket found for server.");
            ret = -1;
        }
        else {
            server_ticket_id = server_ticket->ticket_id;

            if (server_ticket->rtt == 0) {
                DBG_PRINTF("%s", "RTT not set for server ticket.");
                ret = -1;
            }
            if (server_ticket->cwin == 0) {
                DBG_PRINTF("%s", "CWIN not set for server ticket.");
                ret = -1;
            }
        }
    }

    /* Now we remove the client connection and create a new one. */
    if (ret == 0) {
        picoquic_delete_cnx(test_ctx->cnx_client);
        if (test_ctx->cnx_server != NULL) {
            picoquic_delete_cnx(test_ctx->cnx_server);
            test_ctx->cnx_server = NULL;
        }

        /* Clean the data allocated to test the streams */
        test_api_delete_test_streams(test_ctx);

        test_ctx->cnx_client = picoquic_create_cnx(test_ctx->qclient,
            picoquic_null_connection_id, picoquic_null_connection_id,
            (struct sockaddr*) & test_ctx->server_addr, simulated_time,
            PICOQUIC_INTERNAL_TEST_VERSION_1, PICOQUIC_TEST_SNI, PICOQUIC_TEST_ALPN, 1);

        if (test_ctx->cnx_client == NULL) {
            ret = -1;
        }
        else {
            ret = picoquic_start_client_cnx(test_ctx->cnx_client);
        }
    }

    if (ret == 0) {
        ret = tls_api_connection_loop(test_ctx, &loss_mask, 0, &simulated_time);
    }

    /* Prepare to send second batch of data */
    if (ret == 0) {
        ret = test_api_init_send_recv_scenario(test_ctx, test_scenario_ticket_seed, sizeof(test_scenario_ticket_seed));
    }

    /* Perform a data sending loop */
    if (ret == 0) {
        ret = tls_api_data_sending_loop(test_ctx, &loss_mask, &simulated_time, 0);
    }

    if (ret == 0) {
        ret = tls_api_one_scenario_body_verify(test_ctx, &simulated_time, max_completion_microsec);
    }

    if (ret == 0) {
        /* verify that the client resume ticket id is the same as the previous one */
        if (test_ctx->cnx_client->resumed_ticket_id != client_ticket_id) {
            DBG_PRINTF("Client ticket id = 0x%" PRIx64 ", expected 0x%" PRIx64, 
                test_ctx->cnx_client->resumed_ticket_id, client_ticket_id);
            ret = -1;
        }
        if (test_ctx->cnx_client->seed_rtt_min == 0) {
            DBG_PRINTF("%s", "RTT not set for client ticket.");
            ret = -1;
        }
        if (test_ctx->cnx_client->seed_cwin == 0) {
            DBG_PRINTF("%s", "CWIN not set for client ticket.");
            ret = -1;
        }
    }

    if (ret == 0) {
        /* verify that the server resume ticket id is the same as the previous one */
        if (test_ctx->cnx_server != NULL && test_ctx->cnx_server->resumed_ticket_id != server_ticket_id) {
            DBG_PRINTF("Server ticket id = 0x%" PRIx64 ", expected 0x%" PRIx64,
                test_ctx->cnx_server->resumed_ticket_id, server_ticket_id);
            ret = -1;
        }
        if (test_ctx->cnx_client->seed_rtt_min == 0) {
            DBG_PRINTF("%s", "RTT not set for server ticket.");
            ret = -1;
        }
        if (test_ctx->cnx_client->seed_cwin == 0) {
            DBG_PRINTF("%s", "CWIN not set for server ticket.");
            ret = -1;
        }
    }

    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }

    return ret;
}

int ticket_seed_test() {
    
   return ticket_seed_test_one(1);
}


int ticket_seed_from_bdp_frame_test() {
    
   return ticket_seed_test_one(2);
}
