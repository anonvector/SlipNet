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

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#ifdef _WINDOWS
#define WIN32_LEAN_AND_MEAN
#include "getopt.h"
#include <WinSock2.h>
#include <Windows.h>

#define SERVER_CERT_FILE "certs\\cert.pem"
#define SERVER_KEY_FILE  "certs\\key.pem"

#else /* Linux */

#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>

#ifndef __USE_XOPEN2K
#define __USE_XOPEN2K
#endif
#ifndef __USE_POSIX
#define __USE_POSIX
#endif
#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/select.h>

#define SERVER_CERT_FILE "certs/cert.pem"
#define SERVER_KEY_FILE "certs/key.pem"

#endif

static const int default_server_port = 4443;
static const char* default_server_name = "::";
static const char* ticket_store_filename = "demo_ticket_store.bin";
static const char* token_store_filename = "demo_token_store.bin";


#include "picoquic.h"
#include "picoquic_packet_loop.h"
#include "picoquic_internal.h"
#include "picoquic_utils.h"
#include "autoqlog.h"
#include "h3zero.h"
#include "h3zero_common.h"
#include "pico_webtransport.h"
#include "wt_baton.h"
#include "democlient.h"
#include "demoserver.h"
#include "quicperf.h"
#include "picoquic_unified_log.h"
#include "picoquic_logger.h"
#include "picoquic_binlog.h"
#include "performance_log.h"
#include "picoquic_config.h"
#include "picoquic_lb.h"
#ifdef PICOQUIC_MEMORY_LOG
#include "auto_memlog.h"
#endif

void print_address(FILE* F_log, struct sockaddr* address, char* label, picoquic_connection_id_t cnx_id)
{
    char hostname[256];

    const char* x = inet_ntop(address->sa_family,
        (address->sa_family == AF_INET) ? (void*)&(((struct sockaddr_in*)address)->sin_addr) : (void*)&(((struct sockaddr_in6*)address)->sin6_addr),
        hostname, sizeof(hostname));

    fprintf(F_log, "%016llx : ", (unsigned long long)picoquic_val64_connection_id(cnx_id));

    if (x != NULL) {
        fprintf(F_log, "%s %s, port %d\n", label, x,
            (address->sa_family == AF_INET) ? ((struct sockaddr_in*)address)->sin_port : ((struct sockaddr_in6*)address)->sin6_port);
    } else {
        fprintf(F_log, "%s: inet_ntop failed with error # %ld\n", label, WSA_LAST_ERROR(errno));
    }
}

/* server loop call back management */
typedef struct st_server_loop_cb_t {
    int just_once;
    int first_connection_seen;
    int connection_done;
} server_loop_cb_t;

static int server_loop_cb(picoquic_quic_t* quic, picoquic_packet_loop_cb_enum cb_mode,
    void* callback_ctx, void * callback_arg)
{
    int ret = 0;
    server_loop_cb_t* cb_ctx = (server_loop_cb_t*)callback_ctx;

    if (cb_ctx == NULL) {
        ret = PICOQUIC_ERROR_UNEXPECTED_ERROR;
    }
    else {
        switch (cb_mode) {
        case picoquic_packet_loop_ready:
            fprintf(stdout, "Waiting for packets.\n");
            break;
        case picoquic_packet_loop_after_receive:
            break;
        case picoquic_packet_loop_after_send:
            break;
        case picoquic_packet_loop_port_update:
            break;
        default:
            ret = PICOQUIC_ERROR_UNEXPECTED_ERROR;
            break;
        }

        if (ret == 0 && cb_ctx->just_once){
            if (!cb_ctx->first_connection_seen && picoquic_get_first_cnx(quic) != NULL) {
#ifdef PICOQUIC_MEMORY_LOG
                if (memlog_init(picoquic_get_first_cnx(quic), 1000000, "./memlog.csv") != 0) {
                    fprintf(stderr, "Could not initialize memlog as ./memlog.csv\n");
                }
                else {
                    fprintf(stdout, "Initialized memlog as ./memlog.csv\n");
                }
#endif
                cb_ctx->first_connection_seen = 1;
                fprintf(stdout, "First connection noticed.\n");
            } else if (cb_ctx->first_connection_seen && picoquic_get_first_cnx(quic) == NULL) {
                fprintf(stdout, "No more active connections.\n");
                cb_ctx->connection_done = 1;
                ret = PICOQUIC_NO_ERROR_TERMINATE_PACKET_LOOP;
            }
        }
    }
    return ret;
}

/* Define a "post" context used to test the "post" function "end to end".
 */
typedef struct st_demoserver_post_test_t {
    size_t nb_received;
    size_t nb_sent;
    size_t response_length;
    char posted[256];
} demoserver_post_test_t;

int demoserver_post_callback(picoquic_cnx_t* cnx,
    uint8_t* bytes, size_t length,
    picohttp_call_back_event_t event, h3zero_stream_ctx_t* stream_ctx,
    void * callback_ctx)
{
    int ret = 0;
    demoserver_post_test_t* ctx = (demoserver_post_test_t*)stream_ctx->path_callback_ctx;

    switch (event) {
    case picohttp_callback_get: /* Received a get command */
        break;
    case picohttp_callback_post: /* Received a post command */
        if (ctx == NULL) {
            ctx = (demoserver_post_test_t*)malloc(sizeof(demoserver_post_test_t));
            if (ctx == NULL) {
                /* cannot handle the stream -- TODO: reset stream? */
                return -1;
            }
            else {
                memset(ctx, 0, sizeof(demoserver_post_test_t));
                stream_ctx->path_callback_ctx = (void*)ctx;
            }
        }
        else {
            /* unexpected. Should not have a context here */
            return -1;
        }
        break;
    case picohttp_callback_post_data: /* Data received from peer on stream N */
    case picohttp_callback_post_fin: /* All posted data have been received, prepare the response now. */
        /* Add data to echo size */
        if (ctx == NULL) {
            ret = -1;
        }
        else {
            ctx->nb_received += length;
            if (event == picohttp_callback_post_fin) {
                if (ctx != NULL) {
                    size_t nb_chars = 0;
                    if (picoquic_sprintf(ctx->posted, sizeof(ctx->posted), &nb_chars, "Received %zu bytes.\n", ctx->nb_received) >= 0) {
                        ctx->response_length = nb_chars;
                        ret = (int)nb_chars;
                        if (ctx->response_length <= length) {
                            memcpy(bytes, ctx->posted, ctx->response_length);
                        }
                    }
                    else {
                        ret = -1;
                    }
                }
                else {
                    ret = -1;
                }
            }
        }
        break;
    case picohttp_callback_provide_data:
        if (ctx == NULL || ctx->nb_sent > ctx->response_length) {
            ret = -1;
        }
        else
        {
            /* Provide data. */
            uint8_t* buffer;
            size_t available = ctx->response_length - ctx->nb_sent;
            int is_fin = 1;

            if (available > length) {
                available = length;
                is_fin = 0;
            }

            buffer = picoquic_provide_stream_data_buffer(bytes, available, is_fin, !is_fin);
            if (buffer != NULL) {
                memcpy(buffer, ctx->posted + ctx->nb_sent, available);
                ctx->nb_sent += available;
                ret = 0;
            }
            else {
                ret = -1;
            }
        }
        break;
    case picohttp_callback_reset: /* stream is abandoned */
        stream_ctx->path_callback = NULL;
        stream_ctx->path_callback_ctx = NULL;

        if (ctx != NULL) {
            free(ctx);
        }
        break;
    default:
        ret = -1;
        break;
    }

    return ret;
}

picohttp_server_path_item_t path_item_list[2] =
{
    {
        "/post",
        5,
        demoserver_post_callback,
        NULL
    },
    {
        "/baton",
        6,
        wt_baton_callback,
        NULL
    }
};

int quic_server(const char* server_name, picoquic_quic_config_t * config, int just_once)
{
    /* Start: start the QUIC process with cert and key files */
    int ret = 0;
    picoquic_quic_t* qserver = NULL;
    uint64_t current_time = 0;
    picohttp_server_parameters_t picoquic_file_param;
    server_loop_cb_t loop_cb_ctx;

    memset(&picoquic_file_param, 0, sizeof(picohttp_server_parameters_t));
    picoquic_file_param.web_folder = config->www_dir;
    picoquic_file_param.path_table = path_item_list;
    picoquic_file_param.path_table_nb = 2;

    memset(&loop_cb_ctx, 0, sizeof(server_loop_cb_t));
    loop_cb_ctx.just_once = just_once;

    /* Setup the server context */
    if (ret == 0) {
        current_time = picoquic_current_time();
        /* Create QUIC context */

        if (config->ticket_file_name == NULL) {
            ret = picoquic_config_set_option(config, picoquic_option_Ticket_File_Name, ticket_store_filename);
        }
        if (ret == 0 && config->token_file_name == NULL) {
            ret = picoquic_config_set_option(config, picoquic_option_Token_File_Name, token_store_filename);
        }
        if (ret == 0) {
            qserver = picoquic_create_and_configure(config, picoquic_demo_server_callback, &picoquic_file_param, current_time, NULL);
            if (qserver == NULL) {
                ret = -1;
            }
            else {
                picoquic_set_key_log_file_from_env(qserver);

                picoquic_set_alpn_select_fn(qserver, picoquic_demo_server_callback_select_alpn);

                picoquic_use_unique_log_names(qserver, 1);

                if (config->qlog_dir != NULL)
                {
                    picoquic_set_qlog(qserver, config->qlog_dir);
                }
                if (config->performance_log != NULL)
                {
                    ret = picoquic_perflog_setup(qserver, config->performance_log);
                }
                if (ret == 0 && config->cnx_id_cbdata != NULL) {
                    picoquic_load_balancer_config_t lb_config;
                    ret = picoquic_lb_compat_cid_config_parse(&lb_config, config->cnx_id_cbdata, strlen(config->cnx_id_cbdata));
                    if (ret != 0) {
                        fprintf(stdout, "Cannot parse the CNX_ID config policy: %s.\n", config->cnx_id_cbdata);
                    }
                    else {
                        ret = picoquic_lb_compat_cid_config(qserver, &lb_config);
                        if (ret != 0) {
                            fprintf(stdout, "Cannot set the CNX_ID config policy: %s.\n", config->cnx_id_cbdata);
                        }
                    }
                }
                if (ret == 0) {
                    fprintf(stdout, "Accept enable multipath: %d.\n", qserver->default_multipath_option);
                }
            }
        }
    }

    if (ret == 0) {
        /* Wait for packets */
#if _WINDOWS_BUT_WE_ARE_UNIFYING
        ret = picoquic_packet_loop_win(qserver, config->server_port, 0, config->dest_if, 
            config->socket_buffer_size, server_loop_cb, &loop_cb_ctx);
#else
        ret = picoquic_packet_loop(qserver, config->server_port, 0, config->dest_if,
            config->socket_buffer_size, config->do_not_use_gso, server_loop_cb, &loop_cb_ctx);
#endif
    }

    /* And exit */
    printf("Server exit, ret = 0x%x\n", ret);

    /* Clean up */
    if (config->cnx_id_cbdata != NULL) {
        picoquic_lb_compat_cid_config_free(qserver);
    }
    if (qserver != NULL) {
        picoquic_free(qserver);
    }

    return ret;
}

static const char * test_scenario_default = "0:index.html;4:test.html;8:/1234567;12:main.jpg;16:war-and-peace.txt;20:en/latest/;24:/file-123K";

/* Client loop call back management.
 * This is pretty complex, because the demo client is used to test a variety of interop
 * scenarios, for example:
 *
 * Variants of migration:
 * - Basic NAT traversal (1)
 * - Simple CID swap (2)
 * - Organized migration (3)
 * Encryption key rotation, after some number of packets have been sent.
 *
 * The client loop terminates when the client connection is closed.
 */

typedef struct st_client_loop_cb_t {
    picoquic_cnx_t* cnx_client;
    picoquic_demo_callback_ctx_t* demo_callback_ctx;
    int notified_ready;
    int established;
    int migration_to_preferred_started;
    int migration_to_preferred_finished;
    int migration_started;
    int address_updated;
    int force_migration;
    int nb_packets_before_key_update;
    int key_update_done;
    int zero_rtt_available;
    int is_quicperf;
    int socket_buffer_size;
    int multipath_probe_done;
    char const* saved_alpn;
    struct sockaddr_storage server_address;
    struct sockaddr_storage client_address;
    struct sockaddr_storage client_alt_address[PICOQUIC_NB_PATH_TARGET];
    int client_alt_if[PICOQUIC_NB_PATH_TARGET];
    int nb_alt_paths;
    uint16_t local_port;
    uint16_t alt_port;
    picoquic_connection_id_t server_cid_before_migration;
    picoquic_connection_id_t client_cid_before_migration;
    packet_loop_system_call_duration_t sc_duration;
} client_loop_cb_t;


char * picoquic_strsep(char **stringp, const char *delim)
{
#ifdef _WINDOWS
    if (*stringp == NULL) {
        return NULL;
    }
    char *token_start = *stringp;
    *stringp = strpbrk(token_start, delim);
    if (*stringp) {
        **stringp = '\0';
        (*stringp)++;
    }
    return token_start;
#else
    return strsep(stringp, delim);
#endif
}

/*
 * mp_config is consisted with src_if and alt_ip, seperated by "/" and ","
 * e.g. 10.0.0.2/3,10.0.0.3/4,10.0.0.4/5
 * where src_if is an int list, and alt_ip is a string list.
 * alt_ip is the ip of the alternative path
 * src_if is the index of the interface where the alt_ip is bounded with
 */
int picoquic_parse_client_multipath_config(char *mp_config, int *src_if, struct sockaddr_storage *alt_ip, int *nb_alt_paths)
{
    int ret = 0;
    int valid_ip, valid_index = 0;
    char *token, *token2, *ptr, *str;
    str = malloc(sizeof(char) * (strlen(mp_config) + 1));
    if (str == NULL) {
        ret = -1;
    }
    memcpy(str, mp_config, sizeof(char) * (strlen(mp_config) + 1));
    ptr = str;

    while ((token = picoquic_strsep(&str, ","))) {
        struct sockaddr_storage ip;
        valid_index = valid_ip = 0;

        while ((token2 = picoquic_strsep(&token, "/"))) {
            if (picoquic_store_text_addr(&ip, token2, 0) == 0) {
                memcpy(alt_ip+(*nb_alt_paths), &ip, sizeof(struct sockaddr_storage));
                valid_ip = 1;
            }
            if (atoi(token2) >= 0) {
                *(src_if+(*nb_alt_paths)) = atoi(token2);
                valid_index = 1;
            }
        }

        if ((valid_ip == 1) && (valid_index == 1)){
            (*nb_alt_paths)++;
            /* If more than PICOQUIC_NB_PATH_TARGET alt paths are specified, the remaining are ignored */
            if (*nb_alt_paths >= PICOQUIC_NB_PATH_TARGET) {
                break;
            }
        }
    }
    free(ptr);
    return ret;
}

static int simulate_migration(client_loop_cb_t* cb_ctx)
{
    int ret = 0;
    struct sockaddr_storage addr_from = { 0 };

    picoquic_store_addr(&addr_from,
        (struct sockaddr*)&cb_ctx->cnx_client->path[0]->local_addr);
    if (addr_from.ss_family == AF_INET6) {
        ((struct sockaddr_in6*)&addr_from)->sin6_port = htons(cb_ctx->alt_port);
    } else {
        ((struct sockaddr_in*)&addr_from)->sin_port = htons(cb_ctx->alt_port);
    }

    ret = picoquic_probe_new_path(cb_ctx->cnx_client,
        (struct sockaddr*)&cb_ctx->server_address,
        (struct sockaddr*)&addr_from,
        picoquic_get_quic_time(cb_ctx->cnx_client->quic));

    return ret;
}

int client_loop_cb(picoquic_quic_t* quic, picoquic_packet_loop_cb_enum cb_mode, 
    void* callback_ctx, void * callback_arg)
{
    int ret = 0;
    client_loop_cb_t* cb_ctx = (client_loop_cb_t*)callback_ctx;

    if (cb_ctx == NULL) {
        ret = PICOQUIC_ERROR_UNEXPECTED_ERROR;
    }
    else {
        switch (cb_mode) {
        case picoquic_packet_loop_ready: {
            picoquic_packet_loop_options_t* options = (picoquic_packet_loop_options_t*)callback_arg;
            options->do_system_call_duration = 1;
            options->provide_alt_port = 1;
            fprintf(stdout, "Waiting for packets.\n");
            break;
        }
        case picoquic_packet_loop_after_receive:
            /* Post receive callback */
            if ((!cb_ctx->is_quicperf && cb_ctx->demo_callback_ctx->connection_closed) ||
                cb_ctx->cnx_client->cnx_state == picoquic_state_disconnected) {
                fprintf(stdout, "The connection is closed!\n");
                ret = PICOQUIC_NO_ERROR_TERMINATE_PACKET_LOOP;
                break;
            }
            /* Keeping track of the addresses and ports, as we
             * need them to verify the migration behavior */
            if (!cb_ctx->address_updated && cb_ctx->cnx_client->path[0]->local_addr.ss_family != 0) {
                uint16_t updated_port = (cb_ctx->cnx_client->path[0]->local_addr.ss_family == AF_INET) ?
                    ((struct sockaddr_in*) & cb_ctx->cnx_client->path[0]->local_addr)->sin_port :
                    ((struct sockaddr_in6*) & cb_ctx->cnx_client->path[0]->local_addr)->sin6_port;
                if (updated_port != 0) {
                    cb_ctx->address_updated = 1;
                    picoquic_store_addr(&cb_ctx->client_address, (struct sockaddr*) & cb_ctx->cnx_client->path[0]->local_addr);
                    fprintf(stdout, "Client port (AF=%d): %d.\n", cb_ctx->client_address.ss_family, updated_port);
                }
            }
            if (picoquic_get_cnx_state(cb_ctx->cnx_client) == picoquic_state_client_almost_ready && cb_ctx->notified_ready == 0) {
                /* if almost ready, display results of negotiation */
                if (picoquic_tls_is_psk_handshake(cb_ctx->cnx_client)) {
                    fprintf(stdout, "The session was properly resumed!\n");
                    picoquic_log_app_message(cb_ctx->cnx_client,
                        "%s", "The session was properly resumed!");
                }

                if (cb_ctx->cnx_client->zero_rtt_data_accepted) {
                    fprintf(stdout, "Zero RTT data is accepted!\n");
                    picoquic_log_app_message(cb_ctx->cnx_client,
                        "%s", "Zero RTT data is accepted!");
                }

                if (cb_ctx->cnx_client->alpn != NULL) {
                    fprintf(stdout, "Negotiated ALPN: %s\n", cb_ctx->cnx_client->alpn);
                    picoquic_log_app_message(cb_ctx->cnx_client,
                        "Negotiated ALPN: %s", cb_ctx->cnx_client->alpn);
                    cb_ctx->saved_alpn = picoquic_string_duplicate(cb_ctx->cnx_client->alpn);
                }
                fprintf(stdout, "Almost ready!\n\n");
                cb_ctx->notified_ready = 1;
            }
            else if (ret == 0 && (picoquic_get_cnx_state(cb_ctx->cnx_client) == picoquic_state_ready ||
                picoquic_get_cnx_state(cb_ctx->cnx_client) == picoquic_state_client_ready_start)) {
                int simulate_multipath = 0;

                if (picoquic_get_cnx_state(cb_ctx->cnx_client) == picoquic_state_ready && cb_ctx->multipath_probe_done == 0) {
                    /* Create the required additional paths. 
                     * In some cases, we just want to test the software from a computer that is not actually
                     * multihomed. In that case, the client_alt_address is set to ::0 (IPv6 null address),
                     * and the callback will return "PICOQUIC_NO_ERROR_SIMULATE_MIGRATION", which
                     * causes the socket code to create an additional socket, and issue a 
                     * picoquic_probe_new_path request for the corresponding address.
                     */
                    int remote_cid_ready = (picoquic_obtain_stashed_cnxid(cb_ctx->cnx_client, 1) != NULL);
                    if (remote_cid_ready) {
                        struct sockaddr_in6 addr_zero6 = { 0 };
                        struct sockaddr_in addr_zero4 = { 0 };
                        struct sockaddr_storage path0_addr = { 0 };
                        addr_zero6.sin6_family = AF_INET6;
                        addr_zero4.sin_family = AF_INET;

                        if (picoquic_get_path_addr(cb_ctx->cnx_client, 0, 1, &path0_addr) != 0) {
                            /* This should never happen, as path[0] is always defined before the first migration. */
                            picoquic_log_app_message(cb_ctx->cnx_client, "Cannot use multipath. Cannot get address of path 0");
                        }

                        for (int i = 0; i < cb_ctx->nb_alt_paths; i++) {
                            if (picoquic_compare_addr((struct sockaddr*)&addr_zero6, (struct sockaddr*)&cb_ctx->client_alt_address[i]) == 0 ||
                                picoquic_compare_addr((struct sockaddr*)&addr_zero4, (struct sockaddr*)&cb_ctx->client_alt_address[i]) == 0) {
                                simulate_multipath = 1;
                                picoquic_log_app_message(cb_ctx->cnx_client, "%s\n", "Will try to simulate new path");
                            }
                            else if (cb_ctx->client_alt_address[i].ss_family != path0_addr.ss_family) {
                                picoquic_log_app_message(cb_ctx->cnx_client, "Cannot add new path, wrong address family, %d vs. %d\n", 
                                    cb_ctx->client_alt_address[i].ss_family, path0_addr.ss_family);
                            } else {
#if 0
                                /* The configuration code sets the port number in "client_alt_address" to zero,
                                * but it should be set to the actual value because of the "matching address"
                                * test when processing path challenges. The actual value is the same as
                                * used in the default path. */
                                if (cb_ctx->client_alt_address[i].ss_family == AF_INET6) {
                                    ((struct sockaddr_in6*)&cb_ctx->client_alt_address[i])->sin6_port =
                                        ((struct sockaddr_in6*)&path0_addr)->sin6_port;
                                }
                                else {
                                    ((struct sockaddr_in*)&cb_ctx->client_alt_address[i])->sin_port =
                                        ((struct sockaddr_in*)&path0_addr)->sin_port;
                                }
#endif
                                if ((ret = picoquic_probe_new_path_ex(cb_ctx->cnx_client, (struct sockaddr*)&cb_ctx->server_address,
                                    (struct sockaddr*)&cb_ctx->client_alt_address[i], cb_ctx->client_alt_if[i], picoquic_get_quic_time(quic), 0, NULL)) != 0) {
                                    picoquic_log_app_message(cb_ctx->cnx_client, "Probe new path failed with exit code %d", ret);
                                }
                                else {
                                    picoquic_log_app_message(cb_ctx->cnx_client, "New path added, total path available %d", cb_ctx->cnx_client->nb_paths);
                                }
                            }
                        }

                        cb_ctx->multipath_probe_done = 1;

                        if (simulate_multipath) {
                            ret = simulate_migration(cb_ctx);
                        }
                    }
                }

                /* Track the migration to server preferred address */
                if (cb_ctx->cnx_client->remote_parameters.prefered_address.is_defined && !cb_ctx->migration_to_preferred_finished) {
                    if (picoquic_compare_addr(
                        (struct sockaddr*) & cb_ctx->server_address, (struct sockaddr*) & cb_ctx->cnx_client->path[0]->peer_addr) != 0) {
                        fprintf(stdout, "Migrated to server preferred address!\n");
                        picoquic_log_app_message(cb_ctx->cnx_client, "%s", "Migrated to server preferred address!");
                        cb_ctx->migration_to_preferred_finished = 1;
                    }
                    else if (cb_ctx->cnx_client->nb_paths > 1 && !cb_ctx->migration_to_preferred_started) {
                        cb_ctx->migration_to_preferred_started = 1;
                        fprintf(stdout, "Attempting migration to server preferred address.\n");
                        picoquic_log_app_message(cb_ctx->cnx_client, "%s", "Attempting migration to server preferred address.");

                    }
                    else if (cb_ctx->cnx_client->nb_paths == 1 && cb_ctx->migration_to_preferred_started) {
                        fprintf(stdout, "Could not migrate to server preferred address!\n");
                        picoquic_log_app_message(cb_ctx->cnx_client, "%s", "Could not migrate to server preferred address!");
                        cb_ctx->migration_to_preferred_finished = 1;
                    }
                }

                /* Execute the migration trials
                 * The actual change of sockets is delegated to the packet loop function,
                 * so it can be integrated with other aspects of socket management.
                 * If a new socket is needed, two special error codes will be used.
                 */
                if (cb_ctx->force_migration && cb_ctx->migration_started == 0 && cb_ctx->address_updated &&
                    picoquic_get_cnx_state(cb_ctx->cnx_client) == picoquic_state_ready &&
                    (cb_ctx->cnx_client->first_remote_cnxid_stash->cnxid_stash_first != NULL || cb_ctx->force_migration == 1) &&
                    (!cb_ctx->cnx_client->remote_parameters.prefered_address.is_defined ||
                        cb_ctx->migration_to_preferred_finished)) {
                    int mig_ret = 0;
                    cb_ctx->migration_started = 1;
                    cb_ctx->server_cid_before_migration = cb_ctx->cnx_client->path[0]->p_remote_cnxid->cnx_id;
                    if (cb_ctx->cnx_client->path[0]->p_local_cnxid != NULL) {
                        cb_ctx->client_cid_before_migration = cb_ctx->cnx_client->path[0]->p_local_cnxid->cnx_id;
                    }
                    else {
                        /* Special case of forced migration after preferred address migration */
                        memset(&cb_ctx->client_cid_before_migration, 0, sizeof(picoquic_connection_id_t));
                    }
                    switch (cb_ctx->force_migration) {
                    case 1:
                        fprintf(stdout, "Switch to new port. Will test NAT rebinding support.\n");
                        ret = PICOQUIC_NO_ERROR_SIMULATE_NAT;
                        break;
                    case 2:
                        mig_ret = picoquic_renew_connection_id(cb_ctx->cnx_client, 0);
                        if (mig_ret != 0) {
                            if (mig_ret == PICOQUIC_ERROR_MIGRATION_DISABLED) {
                                fprintf(stdout, "Migration disabled, cannot test CNXID renewal.\n");
                            }
                            else {
                                fprintf(stdout, "Renew CNXID failed, error: %x.\n", mig_ret);
                            }
                            cb_ctx->migration_started = -1;
                        }
                        else {
                            fprintf(stdout, "Switching to new CNXID.\n");
                        }
                        break;
                    case 3:
                        fprintf(stdout, "Will test migration to new port.\n");
                        ret = simulate_migration(cb_ctx);
                        cb_ctx->migration_started = 1;
                        break;
                    default:
                        cb_ctx->migration_started = -1;
                        fprintf(stdout, "Invalid migration code: %d!\n", cb_ctx->force_migration);
                        break;
                    }
                }

                /* Track key update */
                if (cb_ctx->nb_packets_before_key_update > 0 &&
                    !cb_ctx->key_update_done &&
                    picoquic_get_cnx_state(cb_ctx->cnx_client) == picoquic_state_ready &&
                    cb_ctx->cnx_client->nb_packets_received > (uint64_t)cb_ctx->nb_packets_before_key_update) {
                    int key_rot_ret = picoquic_start_key_rotation(cb_ctx->cnx_client);
                    if (key_rot_ret != 0) {
                        fprintf(stdout, "Will not test key rotation.\n");
                        picoquic_log_app_message(cb_ctx->cnx_client, "%s", "Will not test key rotation.");
                        cb_ctx->key_update_done = -1;
                    }
                    else {
                        fprintf(stdout, "Key rotation started.\n");
                        picoquic_log_app_message(cb_ctx->cnx_client, "%s", "Key rotation started.");
                        cb_ctx->key_update_done = 1;
                    }
                }

                if (!cb_ctx->is_quicperf && cb_ctx->demo_callback_ctx->nb_open_streams == 0) {
                    fprintf(stdout, "All done, Closing the connection.\n");
                    picoquic_log_app_message(cb_ctx->cnx_client, "%s", "All done, Closing the connection.");

                    ret = picoquic_close(cb_ctx->cnx_client, 0);
                }
            }
            break;
        case picoquic_packet_loop_after_send:
            if (picoquic_get_cnx_state(cb_ctx->cnx_client) == picoquic_state_disconnected) {
                ret = PICOQUIC_NO_ERROR_TERMINATE_PACKET_LOOP;
            }
            else if (ret == 0 && cb_ctx->established == 0 && (picoquic_get_cnx_state(cb_ctx->cnx_client) == picoquic_state_ready ||
                picoquic_get_cnx_state(cb_ctx->cnx_client) == picoquic_state_client_ready_start)) {
                printf("Connection established. Version = %x, I-CID: %llx, verified: %d\n",
                    picoquic_supported_versions[cb_ctx->cnx_client->version_index].version,
                    (unsigned long long)picoquic_val64_connection_id(picoquic_get_logging_cnxid(cb_ctx->cnx_client)),
                    cb_ctx->cnx_client->is_hcid_verified);

                picoquic_log_app_message(cb_ctx->cnx_client,
                    "Connection established. Version = %x, I-CID: %llx, verified: %d",
                    picoquic_supported_versions[cb_ctx->cnx_client->version_index].version,
                    (unsigned long long)picoquic_val64_connection_id(picoquic_get_logging_cnxid(cb_ctx->cnx_client)),
                    cb_ctx->cnx_client->is_hcid_verified);
                cb_ctx->established = 1;

                if (!cb_ctx->zero_rtt_available && !cb_ctx->is_quicperf) {
                    /* Start the download scenario */
                    ret = picoquic_demo_client_start_streams(cb_ctx->cnx_client, cb_ctx->demo_callback_ctx, PICOQUIC_DEMO_STREAM_ID_INITIAL);
                }
            }
            break;
        case picoquic_packet_loop_port_update:
            break;
        case picoquic_packet_loop_alt_port:
            cb_ctx->alt_port = *((uint16_t*)callback_arg);
            break;
        case picoquic_packet_loop_system_call_duration:
            memcpy(&cb_ctx->sc_duration, callback_arg, sizeof(packet_loop_system_call_duration_t));
            break;
        default:
            ret = PICOQUIC_ERROR_UNEXPECTED_ERROR;
            break;
        }
    }
    return ret;
}

/* Quic Client */
int quic_client(const char* ip_address_text, int server_port, 
    picoquic_quic_config_t * config, int force_migration,
    int nb_packets_before_key_update, char const * client_scenario_text)
{
    /* Start: start the QUIC process with cert and key files */
    int ret = 0;
    picoquic_quic_t* qclient = NULL;
    picoquic_cnx_t* cnx_client = NULL;
    picoquic_demo_callback_ctx_t callback_ctx = { 0 };
    uint64_t current_time = 0;

    int is_name = 0;
    size_t client_sc_nb = 0;
    picoquic_demo_stream_desc_t * client_sc = NULL;
    int is_quicperf = 0;
    quicperf_ctx_t* quicperf_ctx = NULL;
    client_loop_cb_t loop_cb;
    picoquic_packet_loop_param_t param = { 0 };
    const char* sni = config->sni;

    memset(&loop_cb, 0, sizeof(client_loop_cb_t));

    if (ret == 0) {
        ret = picoquic_get_server_address(ip_address_text, server_port, &loop_cb.server_address, &is_name);
        if (sni == NULL && is_name != 0) {
            sni = ip_address_text;
        }
    }

    /* Create QUIC context */
    current_time = picoquic_current_time();
    callback_ctx.last_interaction_time = current_time;

    if (ret == 0) {
        if (config->ticket_file_name == NULL) {
            ret = picoquic_config_set_option(config, picoquic_option_Ticket_File_Name, ticket_store_filename);
        }
        if (ret == 0 && config->token_file_name == NULL) {
            ret = picoquic_config_set_option(config, picoquic_option_Token_File_Name, token_store_filename);
        }
        if (ret == 0) {
            qclient = picoquic_create_and_configure(config, NULL, NULL, current_time, NULL);
            if (qclient == NULL) {
                ret = -1;
            }
            else {
                picoquic_set_key_log_file_from_env(qclient);

                if (config->qlog_dir != NULL)
                {
                    picoquic_set_qlog(qclient, config->qlog_dir);
                }

                if (config->performance_log != NULL)
                {
                    ret = picoquic_perflog_setup(qclient, config->performance_log);
                }
            }
        }
    }

    /* If needed, set ALPN and proposed version from tickets */
    if (ret == 0) {
        if (config->alpn == NULL || config->proposed_version == 0) {
            char const* ticket_alpn;
            uint32_t ticket_version;
            if (picoquic_demo_client_get_alpn_and_version_from_tickets(qclient, sni, config->alpn,
                config->proposed_version, &ticket_alpn, &ticket_version) == 0) {
                if (ticket_alpn != NULL) {
                    fprintf(stdout, "Set ALPN to %s based on stored ticket\n", ticket_alpn);
                    picoquic_config_set_option(config, picoquic_option_ALPN, ticket_alpn);
                }

                if (ticket_version != 0) {
                    fprintf(stdout, "Set version to 0x%08x based on stored ticket\n", ticket_version);
                    config->proposed_version = ticket_version;
                }
            }
        }
    }

    if (ret == 0) {
        if (config->alpn != NULL && strcmp(config->alpn, QUICPERF_ALPN) == 0) {
            /* Set a QUICPERF client */
            is_quicperf = 1;
            quicperf_ctx = quicperf_create_ctx(client_scenario_text);
            if (quicperf_ctx == NULL) {
                fprintf(stdout, "Could not get ready to run QUICPERF\n");
                return -1;
            }
            fprintf(stdout, "Getting ready to run QUICPERF\n");
        }
        else {
            if (config->no_disk) {
                fprintf(stdout, "Files not saved to disk (-D, no_disk)\n");
            }

            if (client_scenario_text == NULL) {
                client_scenario_text = test_scenario_default;
            }

            fprintf(stdout, "Testing scenario: <%s>\n", client_scenario_text);
            ret = demo_client_parse_scenario_desc(client_scenario_text, &client_sc_nb, &client_sc);
            if (ret != 0) {
                fprintf(stdout, "Cannot parse the specified scenario.\n");
                return -1;
            }
            else {
                ret = picoquic_demo_client_initialize_context(&callback_ctx, client_sc, client_sc_nb, config->alpn, config->no_disk, 0);
                callback_ctx.out_dir = config->out_dir;
            }
        }
    }
    /* Check that if we are using H3 the SNI is not NULL */
    if (ret == 0 && sni == NULL) {
        fprintf(stdout, "Careful: NULL SNI is incompatible with HTTP 3. Expect errors!\n");
    }

    /* Create the client connection */
    if (ret == 0) {
        /* Create a client connection */
        cnx_client = picoquic_create_cnx(qclient, picoquic_null_connection_id, picoquic_null_connection_id,
            (struct sockaddr*)&loop_cb.server_address, current_time,
            config->proposed_version, sni, config->alpn, 1);

        if (cnx_client == NULL) {
            ret = -1;
        }
        else {
            /* Set PMTUD policy to delayed on the client, leave to default=basic on server */
            picoquic_cnx_set_pmtud_policy(cnx_client, picoquic_pmtud_delayed);
            picoquic_set_default_pmtud_policy(qclient, picoquic_pmtud_delayed);

            if (is_quicperf) {
                picoquic_set_callback(cnx_client, quicperf_callback, quicperf_ctx);
                cnx_client->local_parameters.max_datagram_frame_size = 1532;
            }
            else {
                picoquic_set_callback(cnx_client, picoquic_demo_client_callback, &callback_ctx);

                /* Requires TP grease, for interop tests */
                cnx_client->grease_transport_parameters = 1;
                cnx_client->local_parameters.enable_time_stamp = 3;
                cnx_client->local_parameters.do_grease_quic_bit = 1;

                if (callback_ctx.tp != NULL) {
                    picoquic_set_transport_parameters(cnx_client, callback_ctx.tp);
                }
            }

            if (config->large_client_hello) {
                cnx_client->test_large_chello = 1;
            }

            if (config->desired_version != 0) {
                picoquic_set_desired_version(cnx_client, config->desired_version);
            }

            fprintf(stdout, "Max stream id bidir remote before start = %d (%d)\n",
                (int)cnx_client->max_stream_id_bidir_remote,
                (int)cnx_client->remote_parameters.initial_max_stream_id_bidir);

            if (ret == 0) {
                ret = picoquic_start_client_cnx(cnx_client);

                printf("Starting client connection. Version = %x, I-CID: %llx\n",
                    picoquic_supported_versions[cnx_client->version_index].version,
                    (unsigned long long)picoquic_val64_connection_id(picoquic_get_logging_cnxid(cnx_client)));

                fprintf(stdout, "Max stream id bidir remote after start = %d (%d)\n",
                    (int)cnx_client->max_stream_id_bidir_remote,
                    (int)cnx_client->remote_parameters.initial_max_stream_id_bidir);
            }

            if (ret == 0 && !is_quicperf) {
                if (picoquic_is_0rtt_available(cnx_client) && (config->proposed_version & 0x0a0a0a0a) != 0x0a0a0a0a) {
                    loop_cb.zero_rtt_available = 1;

                    fprintf(stdout, "Max stream id bidir remote after 0rtt = %d (%d)\n",
                        (int)cnx_client->max_stream_id_bidir_remote,
                        (int)cnx_client->remote_parameters.initial_max_stream_id_bidir);

                    /* Queue a simple frame to perform 0-RTT test */
                    /* Start the download scenario */

                    ret = picoquic_demo_client_start_streams(cnx_client, &callback_ctx, PICOQUIC_DEMO_STREAM_ID_INITIAL);
                }
            }
        }
    }
    /* Wait for packets */
    if (ret == 0) {
        if (config->multipath_alt_config != NULL) {
            picoquic_parse_client_multipath_config(config->multipath_alt_config, loop_cb.client_alt_if, loop_cb.client_alt_address, &loop_cb.nb_alt_paths);
        }

        loop_cb.cnx_client = cnx_client;
        loop_cb.force_migration = force_migration;
        loop_cb.nb_packets_before_key_update = nb_packets_before_key_update;
        loop_cb.is_quicperf = is_quicperf;
        loop_cb.socket_buffer_size = config->socket_buffer_size;
        if (!is_quicperf) {
            loop_cb.demo_callback_ctx = &callback_ctx;
        }

        /* In case needed, program an extra path, so we can simulate multipath or migration */
        param.local_af = loop_cb.server_address.ss_family;
        param.socket_buffer_size = config->socket_buffer_size;
        param.do_not_use_gso = config->do_not_use_gso;
        param.extra_socket_required = 0;
        if (force_migration == 1 || force_migration == 3 || config->multipath_alt_config != NULL) {
            param.local_port = (uint16_t)picoquic_uniform_random(30000) + 20000;
            param.extra_socket_required = 1;
        }
        loop_cb.local_port = param.local_port;

        ret = picoquic_packet_loop_v2(qclient, &param, client_loop_cb, &loop_cb);
    }

    if (ret == 0) {
        uint64_t last_err;

        if ((last_err = picoquic_get_local_error(cnx_client)) != 0) {
            fprintf(stdout, "Connection end with local error 0x%" PRIx64 ".\n", last_err);
            ret = -1;
        }
        if ((last_err = picoquic_get_remote_error(cnx_client)) != 0) {
            fprintf(stdout, "Connection end with remote error 0x%" PRIx64 ".\n", last_err);
            ret = -1;
        }
        if ((last_err = picoquic_get_application_error(cnx_client)) != 0) {
            fprintf(stdout, "Connection end with application error 0x%" PRIx64 ".\n", last_err);
            ret = -1;
        }

        /* Report on successes and failures */
        if (cnx_client->nb_zero_rtt_sent != 0) {
            fprintf(stdout, "Out of %d zero RTT packets, %d were acked by the server.\n",
                cnx_client->nb_zero_rtt_sent, cnx_client->nb_zero_rtt_acked);
            picoquic_log_app_message(cnx_client, "Out of %d zero RTT packets, %d were acked by the server.",
                cnx_client->nb_zero_rtt_sent, cnx_client->nb_zero_rtt_acked);
        }
        fprintf(stdout, "Address Discovery mode: %d / %d (%u:%u)\n",
            cnx_client->local_parameters.address_discovery_mode,
            cnx_client->remote_parameters.address_discovery_mode,
            cnx_client->is_address_discovery_provider,
            cnx_client->is_address_discovery_receiver);
        fprintf(stdout, "Quic Bit was %sgreased by the client.\n", (cnx_client->quic_bit_greased) ? "" : "NOT ");
        fprintf(stdout, "Quic Bit was %sgreased by the server.\n", (cnx_client->quic_bit_received_0) ? "" : "NOT ");

        if (cnx_client->ack_ctx[picoquic_packet_context_application].ecn_ect0_total_local != 0 ||
            cnx_client->ack_ctx[picoquic_packet_context_application].ecn_ect1_total_local != 0 ||
            cnx_client->ack_ctx[picoquic_packet_context_application].ecn_ce_total_local != 0) {
            fprintf(stdout, "ECN was received (ect0: %" PRIu64 ", ect1: %" PRIu64 ", ce: %" PRIu64 ").\n",
                cnx_client->ack_ctx[picoquic_packet_context_application].ecn_ect0_total_local,
                cnx_client->ack_ctx[picoquic_packet_context_application].ecn_ect1_total_local,
                cnx_client->ack_ctx[picoquic_packet_context_application].ecn_ce_total_local);
        }
        else {
            fprintf(stdout, "ECN was not received.\n");
        }

        if (cnx_client->pkt_ctx[picoquic_packet_context_application].ecn_ect0_total_remote != 0 ||
            cnx_client->pkt_ctx[picoquic_packet_context_application].ecn_ect1_total_remote != 0 ||
            cnx_client->pkt_ctx[picoquic_packet_context_application].ecn_ce_total_remote != 0) {
            fprintf(stdout, "ECN was acknowledged (ect0: %" PRIu64 ", ect1: %" PRIu64 ", ce: %" PRIu64 ").\n",
                cnx_client->pkt_ctx[picoquic_packet_context_application].ecn_ect0_total_remote,
                cnx_client->pkt_ctx[picoquic_packet_context_application].ecn_ect1_total_remote,
                cnx_client->pkt_ctx[picoquic_packet_context_application].ecn_ce_total_remote);
        }
        else {
            fprintf(stdout, "ECN was not acknowledged.\n");
        }

        if (config->desired_version != 0) {
            uint32_t v = picoquic_supported_versions[cnx_client->version_index].version;
            if (v == config->desired_version) {
                fprintf(stdout, "Successfully negotiated version 0x%" PRIx32 ".\n", v);
            }
            else {
                fprintf(stdout, "Could not negotiate version 0x%" PRIx32 ", used version 0x%" PRIu32 ".\n", 
                    config->desired_version, v);
            }
        }

        if ((config->multipath_option&1) != 0) {
            fprintf(stdout, "Enable multipath: %s.\n", (cnx_client->is_multipath_enabled)?"Success":"Refused");
        }

        if (loop_cb.force_migration){
            if (!loop_cb.migration_started) {
                fprintf(stdout, "Could not start testing migration.\n");
                picoquic_log_app_message(cnx_client, "%s", "Could not start testing migration.");
                loop_cb.migration_started = -1;
            }
            else {
                int source_addr_cmp = picoquic_compare_addr(
                    (struct sockaddr*) & cnx_client->path[0]->local_addr,
                    (struct sockaddr*) & loop_cb.client_address);
                int dest_cid_cmp = picoquic_compare_connection_id(
                    &cnx_client->path[0]->p_remote_cnxid->cnx_id,
                    &loop_cb.server_cid_before_migration);
                fprintf(stdout, "After migration:\n");
                fprintf(stdout, "- Default source address %s\n", (source_addr_cmp) ? "changed" : "did not change");
                if (cnx_client->path[0]->p_local_cnxid == NULL) {
                    fprintf(stdout, "- Local CID is NULL!\n");
                }
                else {
                    int source_cid_cmp = picoquic_compare_connection_id(
                        &cnx_client->path[0]->p_local_cnxid->cnx_id,
                        &loop_cb.client_cid_before_migration);
                    fprintf(stdout, "- Local CID %s\n", (source_cid_cmp) ? "changed" : "did not change");
                }
                fprintf(stdout, "- Remode CID %s\n", (dest_cid_cmp) ? "changed" : "did not change");
            }
        }

        if (loop_cb.nb_packets_before_key_update > 0) {
            if (loop_cb.key_update_done == 0) {
                fprintf(stdout, "Did not start key rotation.\n");
            }
            else if (loop_cb.key_update_done == -1) {
                fprintf(stdout, "Error when starting key rotation.\n");
            }
            else {
                uint64_t crypto_rotation_sequence;
                if (cnx_client->is_multipath_enabled) {
                    crypto_rotation_sequence = cnx_client->path[0]->ack_ctx.crypto_rotation_sequence;
                }
                else {
                    crypto_rotation_sequence = cnx_client->ack_ctx[picoquic_packet_context_application].crypto_rotation_sequence;
                }
                fprintf(stdout, "Crypto rotation sequence: %" PRIu64 ", phase ENC: %d, phase DEC: %d\n",
                    crypto_rotation_sequence, cnx_client->key_phase_enc, cnx_client->key_phase_dec);
            }
        }

        if (picoquic_get_data_received(cnx_client) > 0 || is_quicperf) {
            uint64_t start_time = picoquic_get_cnx_start_time(cnx_client);
            uint64_t close_time = picoquic_get_quic_time(qclient);
            double duration_usec = (double)(close_time - start_time);

            if (duration_usec > 0) {
                if (is_quicperf){
                    if (picoquic_get_data_received(cnx_client)) {
                        double duration_sec = duration_usec / 1000000.0;
                        printf("Connection_duration_sec: %f\n", duration_sec);
                        printf("Nb_transactions: %" PRIu64"\n", quicperf_ctx->nb_streams);
                        printf("Upload_bytes: %" PRIu64"\n", quicperf_ctx->data_sent);
                        printf("Download_bytes: %" PRIu64"\n", quicperf_ctx->data_received);
                        printf("TPS: %f\n", ((double)quicperf_ctx->nb_streams) / duration_sec);
                        printf("Upload_Mbps: %f\n", ((double)quicperf_ctx->data_sent) * 8.0 / duration_usec);
                        printf("Download_Mbps: %f\n", ((double)quicperf_ctx->data_received) * 8.0 / duration_usec);
                    }

                    (void)quicperf_print_report(stdout, quicperf_ctx);

                    picoquic_log_app_message(cnx_client, "Received %" PRIu64 " bytes in %f seconds, %f Mbps.",
                        picoquic_get_data_received(cnx_client), duration_usec, ((double)quicperf_ctx->data_received) * 8.0 / duration_usec);
                }
                else {
                    double receive_rate_mbps = 8.0 * ((double)picoquic_get_data_received(cnx_client)) / duration_usec;
                    double send_rate_mbps = 8.0* ((double)picoquic_get_data_sent(cnx_client)) / duration_usec;
                    fprintf(stdout, "Received %" PRIu64 " bytes in %f seconds, %f Mbps.\n",
                        picoquic_get_data_received(cnx_client),
                        duration_usec / 1000000.0, receive_rate_mbps);
                    picoquic_log_app_message(cnx_client, "Received %" PRIu64 " bytes in %f seconds, %f Mbps.",
                        picoquic_get_data_received(cnx_client),
                        duration_usec / 1000000.0, receive_rate_mbps);
                    fprintf(stdout, "Sent %" PRIu64 " bytes in %f seconds, %f Mbps.\n",
                        picoquic_get_data_sent(cnx_client),
                        duration_usec / 1000000.0, send_rate_mbps);
                    picoquic_log_app_message(cnx_client, "Sent %" PRIu64 " bytes in %f seconds, %f Mbps.",
                        picoquic_get_data_sent(cnx_client),
                        duration_usec / 1000000.0, send_rate_mbps);
                }
                /* Print those for debugging the effects of ack frequency and flow control */
                printf("max_data_local: %" PRIu64 "\n", cnx_client->maxdata_local);
                printf("max_stream_data_local: %" PRIu64 "\n", cnx_client->max_stream_data_local);
                printf("max_data_remote: %" PRIu64 "\n", cnx_client->maxdata_remote);
                printf("max_stream_data_remote: %" PRIu64 "\n", cnx_client->max_stream_data_remote);
                printf("ack_delay_remote: %" PRIu64 " ... %" PRIu64 "\n",
                    cnx_client->min_ack_delay_remote, cnx_client->max_ack_delay_remote);
                printf("max_ack_gap_remote: %" PRIu64 "\n", cnx_client->max_ack_gap_remote);
                printf("ack_delay_local: %" PRIu64 " ... %" PRIu64 "\n",
                    cnx_client->min_ack_delay_local, cnx_client->max_ack_delay_local);
                printf("max_ack_gap_local: %" PRIu64 "\n", cnx_client->max_ack_gap_local);
                printf("max_mtu_sent: %zu\n", cnx_client->max_mtu_sent);
                printf("max_mtu_received: %zu\n", cnx_client->max_mtu_received);
                if (config->multipath_option != 0) {
                    for (int i = 0; i < cnx_client->nb_paths; i++) {
                        printf("Path[%d], packets sent: %" PRIu64 "\n", i,
                            cnx_client->path[i]->pkt_ctx.send_sequence);
                    }
                }
                /* Print details on system call durations */
                printf("System call duration max: %"PRIu64 "\n", loop_cb.sc_duration.scd_max);
                printf("System call duration smoothed: %"PRIu64 "\n", loop_cb.sc_duration.scd_smoothed);
                printf("System call duration deviation: %"PRIu64 "\n", loop_cb.sc_duration.scd_dev);
            }
        }
    }

    if (qclient != NULL) {
        uint8_t* ticket;
        uint16_t ticket_length;
        if (sni != NULL && loop_cb.saved_alpn != NULL && 0 == picoquic_get_ticket(qclient, sni, (uint16_t)strlen(sni), loop_cb.saved_alpn,
            (uint16_t)strlen(loop_cb.saved_alpn), 0, &ticket, &ticket_length, NULL, 0)) {
            fprintf(stdout, "Received ticket from %s (%s):\n", sni, loop_cb.saved_alpn);
            picoquic_textlog_picotls_ticket(stdout, picoquic_null_connection_id, ticket, ticket_length);
        }

        if (picoquic_save_session_tickets(qclient, config->ticket_file_name) != 0) {
            fprintf(stderr, "Could not store the saved session tickets to <%s>.\n", config->ticket_file_name);
        }

        if (picoquic_save_retry_tokens(qclient, config->token_file_name) != 0) {
            fprintf(stderr, "Could not save tokens to <%s>.\n", config->token_file_name);
        }

        picoquic_free(qclient);
    }

    /* Clean up */
    if (is_quicperf) {
        if (quicperf_ctx != NULL) {
            quicperf_delete_ctx(quicperf_ctx);
        }
    }
    else {
        picoquic_demo_client_delete_context(&callback_ctx);
    }

    if (loop_cb.saved_alpn != NULL) {
        free((void *)loop_cb.saved_alpn);
        loop_cb.saved_alpn = NULL;
    }

    if (client_scenario_text != NULL && client_sc != NULL) {
        demo_client_delete_scenario_desc(client_sc_nb, client_sc);
        client_sc = NULL;
    }
    return ret;
}

/* TODO: rewrite using common code */
void usage()
{
    fprintf(stderr, "PicoQUIC demo client and server\n");
    fprintf(stderr, "Usage: picoquicdemo <options> [server_name [port [scenario]]] \n");
    fprintf(stderr, "  For the client mode, specify server_name and port.\n");
    fprintf(stderr, "  For the server mode, use -p to specify the port.\n");
    picoquic_config_usage();
    fprintf(stderr, "Picoquic demo options:\n");
    fprintf(stderr, "  -A \"ip/ifindex[,ip/ifindex]\"  IP and interface index for multipath alternative\n");
    fprintf(stderr, "                        path, e.g. \"10.0.0.2/3,10.0.0.3/4\". This option only\n");
    fprintf(stderr, "                        affects the behavior of the client.\n");
    fprintf(stderr, "                        Use -A ::0/0 or -A 0.0.0.0/0 to test multipath with\n");
    fprintf(stderr, "                        a second path from the same IP and different port.\n");
    fprintf(stderr, "  -f migration_mode     Force client to migrate to start migration:\n");
    fprintf(stderr, "                        -f 1  test NAT rebinding,\n");
    fprintf(stderr, "                        -f 2  test CNXID renewal,\n");
    fprintf(stderr, "                        -f 3  test migration to new address.\n");
    fprintf(stderr, "  -u nb                 trigger key update after receiving <nb> packets on client\n");
    fprintf(stderr, "  -1                    Once: close the server after processing 1 connection.\n");

    fprintf(stderr, "\nThe scenario argument specifies the set of files that should be retrieved,\n");
    fprintf(stderr, "and their order. The syntax is:\n");
    fprintf(stderr, "  *{[<stream_id>':'[<previous_stream>':'[<format>:]]]path;}\n");
    fprintf(stderr, "where:\n");
    fprintf(stderr, "  <stream_id>:          The numeric ID of the QUIC stream, e.g. 4. By default, the\n");
    fprintf(stderr, "                        next stream in the logical QUIC order, 0, 4, 8, etc.");
    fprintf(stderr, "  <previous_stream>:    The numeric ID of the previous stream. The GET command will\n");
    fprintf(stderr, "                        be issued after that stream's transfer finishes. By default,\n");
    fprintf(stderr, "                        previous stream in this scenario.\n");
    fprintf(stderr, "  <format>:             Whether the received file should be written to disc as\n");
    fprintf(stderr, "                        binary(b) or text(t). Defaults to text.\n");
    fprintf(stderr, "  <path>:               The name of the document that should be retrieved\n");
    fprintf(stderr, "If no scenario is specified, the client executes the default scenario.\n");

    exit(1);
}

int main(int argc, char** argv)
{
    picoquic_quic_config_t config;
    char option_string[512];
    int opt;
    const char* server_name = default_server_name;
    int server_port = default_server_port;
    char default_server_cert_file[512];
    char default_server_key_file[512];
    char* client_scenario = NULL;
    int nb_packets_before_update = 0;
    int force_migration = 0;
    int just_once = 0;
    int is_client = 0;
    int ret;

#ifdef _WINDOWS
    WSADATA wsaData = { 0 };
    (void)WSA_START(MAKEWORD(2, 2), &wsaData);
#endif
    picoquic_config_init(&config);
    memcpy(option_string, "A:u:f:1", 7);
    ret = picoquic_config_option_letters(option_string + 7, sizeof(option_string) - 7, NULL);

    if (ret == 0) {
        /* Get the parameters */
        while ((opt = getopt(argc, argv, option_string)) != -1) {
            switch (opt) {
            case 'u':
                if ((nb_packets_before_update = atoi(optarg)) <= 0) {
                    fprintf(stderr, "Invalid number of packets: %s\n", optarg);
                    usage();
                }
                break;
            case 'f':
                force_migration = atoi(optarg);
                if (force_migration <= 0 || force_migration > 3) {
                    fprintf(stderr, "Invalid migration mode: %s\n", optarg);
                    usage();
                }
                break;
            case '1':
                just_once = 1;
                break;
            case 'A':
                config.multipath_alt_config = malloc(sizeof(char) * (strlen(optarg) + 1));
                memcpy(config.multipath_alt_config, optarg, sizeof(char) * (strlen(optarg) + 1));
                printf("config.multipath_alt_config: %s\n", config.multipath_alt_config);
                break;
            default:
                if (picoquic_config_command_line(opt, &optind, argc, (char const **)argv, optarg, &config) != 0) {
                    usage();
                }
                break;
            }
        }
    }

    /* Simplified style params */
    if (optind < argc) {
        server_name = argv[optind++];
        is_client = 1;
    }

    if (optind < argc) {
        if ((server_port = atoi(argv[optind++])) <= 0) {
            fprintf(stderr, "Invalid port: %s\n", optarg);
            usage();
        }
    }

    if (optind < argc) {
        client_scenario = argv[optind++];
    }

    if (optind < argc) {
        usage();
    }

    if (is_client == 0) {
        if (config.server_port == 0) {
            config.server_port = server_port;
        }

        if (config.server_cert_file == NULL &&
            picoquic_get_input_path(default_server_cert_file, sizeof(default_server_cert_file), config.solution_dir, SERVER_CERT_FILE) == 0) {
            /* Using set option call to ensure proper memory management*/
            picoquic_config_set_option(&config, picoquic_option_CERT, default_server_cert_file);
        }

        if (config.server_key_file == NULL &&
            picoquic_get_input_path(default_server_key_file, sizeof(default_server_key_file), config.solution_dir, SERVER_KEY_FILE) == 0) {
            /* Using set option call to ensure proper memory management*/
            picoquic_config_set_option(&config, picoquic_option_KEY, default_server_key_file);
        }

        /* Run as server */
        printf("Starting Picoquic server (v%s) on port %d, server name = %s, just_once = %d, do_retry = %d\n",
            PICOQUIC_VERSION, config.server_port, server_name, just_once, config.do_retry);
        ret = quic_server(server_name, &config, just_once);
        printf("Server exit with code = %d\n", ret);
    }
    else {
        /* Run as client */
        printf("Starting Picoquic (v%s) connection to server = %s, port = %d\n", PICOQUIC_VERSION, server_name, server_port);
        ret = quic_client(server_name, server_port, &config,
            force_migration, nb_packets_before_update, client_scenario);

        printf("Client exit with code = %d\n", ret);
    }

    picoquic_config_clear(&config);
}
