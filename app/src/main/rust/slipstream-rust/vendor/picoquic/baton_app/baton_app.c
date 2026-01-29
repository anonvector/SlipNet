/*
* Author: Christian Huitema
* Copyright (c) 2023, Private Octopus, Inc.
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

/* This is the client side implementation of the "baton" app,
 * built on top of picoquic using web transport.
 * It is mostly a test that we have the right architecture for developing web transport.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <picosocks.h>
#include <picoquic.h>
#include <picoquic_utils.h>
#include <h3zero.h>
#include <h3zero_common.h>
#include <picoquic_packet_loop.h>
#include <autoqlog.h>
#include <performance_log.h>
#include <picoquic_config.h>
#include "wt_baton.h"
#include "pico_webtransport.h"


#ifdef _WINDOWS
#include <getopt.c>
#endif 

int wt_baton_client(char const* server_name, int server_port, char const* path, picoquic_quic_config_t * config);
int baton_client_loop_cb(picoquic_quic_t* quic, picoquic_packet_loop_cb_enum cb_mode,
    void* callback_ctx, void* callback_arg);

static void usage(char const * sample_name)
{
    fprintf(stderr, "Usage:\n");
    fprintf(stderr, "    %s [options] server_name port path\n", sample_name);
    fprintf(stderr, "The path argument may include parameters:\n");
    fprintf(stderr, " - version: baton protocol version,\n");
    fprintf(stderr, " - baton: initial version value,\n");
    fprintf(stderr, " - count: number of rounds,\n");
    fprintf(stderr, " - inject: inject error for testing\n");
    fprintf(stderr, "For example, set a path like /baton?count=17 to have 17 rounds of baton exchange.");
    picoquic_config_usage();
    exit(1);
}

int get_port(char const* sample_name, char const* port_arg)
{
    int server_port = atoi(port_arg);
    if (server_port <= 0) {
        fprintf(stderr, "Invalid port: %s\n", port_arg);
        usage(sample_name);
    }

    return server_port;
}

int main(int argc, char** argv)
{
    int ret = 0;
    picoquic_quic_config_t config;
    char option_string[512];
#ifdef _WINDOWS
    WSADATA wsaData = { 0 };
    (void)WSA_START(MAKEWORD(2, 2), &wsaData);
#endif

    picoquic_config_init(&config);
    ret = picoquic_config_option_letters(option_string, sizeof(option_string), NULL);
    if (ret == 0) {
        int opt;
        while ((opt = getopt(argc, argv, option_string)) != -1) {
            if (picoquic_config_command_line(opt, &optind, argc, (char const**)argv, optarg, &config) != 0) {
                usage(argv[0]);
                ret = -1;
                break;
            }
        }
    }

    if (optind + 3 != argc){
        usage(argv[0]);
    }
    else {
        char const* server_name = argv[optind++];
        int server_port = get_port(argv[0], argv[optind++]);
        char const * path = argv[optind];

        ret = wt_baton_client(server_name, server_port, path, &config);

        if (ret != 0) {
            fprintf(stderr, "Baton dropped, ret=%d\n", ret);
        }
    }
    exit(ret);
}

/* Client:
* - Find the server's address
* - Create a client context and a client connection.
* - On a forever loop:
*     - get the next wakeup time
*     - wait for arrival of message on sockets until that time
*     - if a message arrives, process it.
*     - else, check whether there is something to send.
*       if there is, send it.
* - The loop breaks if the client connection is finished.
*/

#define PICOQUIC_BATON_CLIENT_TICKET_STORE "baton_ticket_store.bin";
#define PICOQUIC_BATON_CLIENT_TOKEN_STORE "baton_token_store.bin";
#define PICOQUIC_BATON_CLIENT_QLOG_DIR ".";

int wt_baton_client(char const* server_name, int server_port, char const* path, picoquic_quic_config_t* config)
{
    int ret = 0;
    struct sockaddr_storage server_address;
    char const* sni = "test";
    picoquic_quic_t* quic = NULL;
    picoquic_cnx_t* cnx = NULL;
    uint64_t current_time = picoquic_current_time();
    wt_baton_ctx_t baton_ctx = { 0 };
    h3zero_callback_ctx_t* h3_ctx = NULL;
    h3zero_stream_ctx_t* control_stream_ctx = NULL;

    if (ret == 0) {
        /* Get the server's address */
        int is_name = 0;

        ret = picoquic_get_server_address(server_name, server_port, &server_address, &is_name);
        if (ret != 0) {
            fprintf(stderr, "Cannot get the IP address for <%s> port <%d>", server_name, server_port);
        }
        else if (is_name) {
            sni = server_name;
        }
    }

    if (ret == 0) {
        /* Prepare the QUIC context in which the web transport connection
         * will be created. This will set the required transport parameters,
         * and apply the option specified in the command line.
         */
        quic = picoquic_create_and_configure(config, NULL, NULL, current_time, NULL);
        if (quic == NULL) {
            fprintf(stderr, "Cannot create the Quic context\n");
            ret = -1;
        }
    }

    if (ret == 0) {
        /* The default QUIC context creation does not initiate logging, because
        * logging is an optional component. Some applications do not use logging
        * at all, in an effort to reduce the code size. In our case, we enable
        * the components by including the autoqlog.h and performance_log.h headers.
        * We also enable the export of keys in a key log file, to enable QUIC
        * parsing in wireshark
         */
        picoquic_set_key_log_file_from_env(quic);

        if (config->qlog_dir != NULL)
        {
            picoquic_set_qlog(quic, config->qlog_dir);
        }

        if (config->performance_log != NULL)
        {
            int ret = picoquic_perflog_setup(quic, config->performance_log);

            if (ret != 0) {
                DBG_PRINTF("Cannot open performance log: %s, ret = 0x%x", config->performance_log, ret);
                picoquic_free(quic);
                quic = NULL;
            }
        }
    }

    if (ret == 0) {
        /* Prepare a QUIC connection and allocate the parameters required for
        * the web transport setup:
        * - cnx is the "raw" QUIc connection.
        * - h3_ctx holds the parameter required for managing the HTTP3 protocol.
        * - control_stream_ctx holds the parameter for the "control stream" of
        *   the web transport connection.
         */
        ret = picowt_prepare_client_cnx(quic, (struct sockaddr*)&server_address,
            &cnx, &h3_ctx, &control_stream_ctx, current_time, sni);
    }

    if (ret == 0) {
        /* At this stage, we have allocated the QUIC connection, the
        * HTTP3 context, and the control stream. This, and the parameters
        * encoded in the path, is enough to build the context of the
        * application.
        * The example here builds a baton application context. Other
        * applications will replace that by their own values.
         */
        ret = wt_baton_prepare_context(cnx, &baton_ctx, h3_ctx, control_stream_ctx,
            sni, path);
    }
    if (ret == 0) {
        /* Once the application context has been initialized, we pass it to the
        * "connect" request, with a pointer to the application specific callback.
        * Of course, other application would follow the same logic and implement their
        * own callback.
         */
        ret = picowt_connect(cnx, h3_ctx, control_stream_ctx, baton_ctx.authority, baton_ctx.server_path,
            wt_baton_callback, &baton_ctx);

        if (ret != 0) {
            fprintf(stderr, "Could not program the web transport connection\n");
        }
    }

    if (ret == 0) {
        /*
        * Until the call to `picoquic_start_client_cnx`, the Quic connection
        * is "intert". The previous calls to `wt_prepare_client_cnx` have
        * set the context and prepared a variety of stream data, but we need to
        * pull the trigger and start the client so the connection actions are properly
        * executed inside `picoquic_packet_loop`.
        */
        ret = picoquic_start_client_cnx(cnx);

        if (ret != 0) {
            fprintf(stderr, "Could not start the connection\n");
        }
    }

    if (ret == 0) {
        /* Not strictly necessary, but helpful: the log files will be
        * identified by the initial CID. Printing that value now will
        * allow us to identify these log files in the logging
        * directory.
         */
        picoquic_connection_id_t icid = picoquic_get_initial_cnxid(cnx);
        printf("Initial connection ID: ");
        for (uint8_t i = 0; i < icid.id_len; i++) {
            printf("%02x", icid.id[i]);
        }
        printf("\n");
    }

    if (ret == 0) {
        /* Time to start the "packet loop", which will manage the UDP sockets
        * and send and receive messages. The application will be called
        * back when messages arrrive, etc., through the application
        * callback, "wt_baton_callback" in our example. The application
        * may receive socket level events through another callback,
        * `baton_client_loop_cb` in our examples. We mainly use that
        * to exit the packet loop when the application is done.
         */
        ret = picoquic_packet_loop(quic, 0, server_address.ss_family, 0, 0, 0, baton_client_loop_cb, &baton_ctx);
    }

    /* Done. At this stage, we print out statistics, etc.
    * In the example, these are statistics specific to the
    * "baton" application. Other applications will replace this
    * code and use their own logic.
     */
    printf("Final baton state: %d\n", baton_ctx.baton_state);
    printf("Nb turns: %d\n", baton_ctx.nb_turns);
    /* print statistics per lane */
    for (size_t i = 0; i < baton_ctx.nb_lanes; i++) {
        printf("Lane %zu, first baton: 0x%02x, last sent: 0x%02x, last received: 0x%02x\n", i,
            baton_ctx.lanes[i].first_baton, baton_ctx.lanes[i].baton, baton_ctx.lanes[i].baton_received);
    }
    printf("Baton bytes received: %" PRIu64 "\n", baton_ctx.nb_baton_bytes_received);
    printf("Baton bytes sent: %" PRIu64 "\n", baton_ctx.nb_baton_bytes_sent);
    printf("datagrams sent: %d\n", baton_ctx.nb_datagrams_sent);
    printf("datagrams received: %d\n", baton_ctx.nb_datagrams_received);
    printf("datagrams bytes sent: %zu\n", baton_ctx.nb_datagram_bytes_sent);
    printf("datagrams bytes received: %zu\n", baton_ctx.nb_datagram_bytes_received);
    printf("Last sent datagram baton: 0x%02x\n", baton_ctx.baton_datagram_send_next);
    printf("Last received datagram baton: 0x%02x\n", baton_ctx.baton_datagram_received);
    if (baton_ctx.capsule.h3_capsule.is_stored) {
        char log_text[256];
        printf("Capsule received.\n");
        printf("Error code: %lu\n", (unsigned long)baton_ctx.capsule.error_code);
        printf("Error message: %s\n",
            picoquic_uint8_to_str(log_text, sizeof(log_text), baton_ctx.capsule.error_msg,
                baton_ctx.capsule.error_msg_len));
    }


    /* Save the session resume tickets and the address verification tokens into
    * their respective files. Tickets and tokens will be read into the QUIC
    * context when the program runs again, provided of course that successive
    * runs use the same tickets and tokens file names. Tickets and tokens are
    * server specific, and for tokens IP address specific. 
    * 
    * If a ticket is available, the next connection will try to use `session
    * resume' and `0 RTT`. If a token is available, the IP address of the
    * client will be immediately validate, without requiring any
    * validation roundtrip.
     */
    if (quic != NULL) {
        if (config->ticket_file_name != NULL &&
            picoquic_save_session_tickets(quic, config->ticket_file_name) != 0) {
            fprintf(stderr, "Could not save session tickets to <%s>.\n", config->ticket_file_name);
        }
        if (config->token_file_name != NULL &&
            picoquic_save_retry_tokens(quic, config->token_file_name) != 0) {
            fprintf(stderr, "Could not save tokens to <%s>.\n", config->token_file_name);
        }
    }

    /* Freeing the memory that was allocated: first the HTTP three context, and
    * then the QUIC context. Deleting the HTTP3 context also deletes HTTP3
    * objects such as stream contexts. Deleting the Quic context also deletes
    * the quic connections started in that context.
    * 
    * Freeing the stream contexts includes freeing the "control stream" context.
    * When that happens, the application receives a callback of type
    * "picohttp_callback_deregister". The baton application frees all allocated
    * data during that callback -- except for the "baton_ctx", which
    * in our case is entrely allocated on the stack. Other applications
    * may want to do some memory clean up here.
     */

    if (h3_ctx != NULL) {
        h3zero_callback_delete_context(cnx, h3_ctx);
    }

    if (quic != NULL) {
        picoquic_free(quic);
    }

    return ret;
}

 /* Sample client,  loop call back management.
 * The function "picoquic_packet_loop" will call back the application when it is ready to
 * receive or send packets, after receiving a packet, and after sending a packet.
 * We implement here a minimal callback that instruct  "picoquic_packet_loop" to exit
 * when the connection is complete.
 */

int baton_client_loop_cb(picoquic_quic_t* quic, picoquic_packet_loop_cb_enum cb_mode, 
    void* callback_ctx, void * callback_arg)
{
    int ret = 0;
    wt_baton_ctx_t * cb_ctx = (wt_baton_ctx_t*)callback_ctx;

    if (cb_ctx == NULL) {
        ret = PICOQUIC_ERROR_UNEXPECTED_ERROR;
    }
    else {
        switch (cb_mode) {
        case picoquic_packet_loop_ready:
            fprintf(stdout, "Waiting for packets.\n");
            break;
        case picoquic_packet_loop_after_receive:
        case picoquic_packet_loop_after_send:
            if (picoquic_get_cnx_state(cb_ctx->cnx) == picoquic_state_disconnected) {
                ret = PICOQUIC_NO_ERROR_TERMINATE_PACKET_LOOP;
            }
            break;
            if (picoquic_get_cnx_state(cb_ctx->cnx) == picoquic_state_disconnected) {
                ret = PICOQUIC_NO_ERROR_TERMINATE_PACKET_LOOP;
            }
            break;
        case picoquic_packet_loop_port_update:
            break;
        default:
            ret = PICOQUIC_ERROR_UNEXPECTED_ERROR;
            break;
        }
    }
    return ret;
}
