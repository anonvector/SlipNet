/*
* Author: Christian Huitema
* Copyright (c) 2020, Private Octopus, Inc.
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

/* The "sample" project builds a simple file transfer program that can be
 * instantiated in client or server mode. The "sample_client" implements
 * the client components of the sample application.
 *
 * Developing the client requires two main components:
 *  - the client "callback" that implements the client side of the
 *    application protocol, managing the client side application context
 *    for the connection.
 *  - the client loop, that reads messages on the socket, submits them
 *    to the Quic context, let the client prepare messages, and send
 *    them on the appropriate socket.
 *
 * The Sample Client uses the "qlog" option to produce Quic Logs as defined
 * in https://datatracker.ietf.org/doc/draft-marx-qlog-event-definitions-quic-h3/.
 * This is an optional feature, which requires linking with the "loglib" library,
 * and using the picoquic_set_qlog() API defined in "autoqlog.h". When a connection
 * completes, the code saves the log as a file named after the Initial Connection
 * ID (in hexa), with the suffix ".client.qlog".
 */

#include <stdint.h>
#include <stdio.h>
#include <picoquic.h>
#include <picoquic_utils.h>
#include <picosocks.h>
#include <autoqlog.h>
#include <picoquic_packet_loop.h>
#include "picoquic_sample.h"

 /* Background thread management:
  * 
  * The "background" sample is an example of application split
  * between application threads for the application logic, and a
  * background thread for the picoquic stack. 
  * 
  * In the "background client" mode, the files are requested from
  * the UI thread, but the corresponding streams are created in the
  * background thread. The shared state between the two
  * threads is kept in the "background context", visible by
  * both threads, and all interactions with the stack happen
  * in the background thread, because the stack code is not
  * thread safe.
  * 
  * The goal of the sample is not to demonstrate distributed programming
  * techniques. In a real application, the code running in the background
  * would probably send messages and events to the application, but that
  * kind of code is very application specific. In our sample, we use a simple
  * ad hoc coordination between the two threads:
  * - the variable "nb_files" documents the number of files
  *   that have been documented by the client. It is updated by
  *   the UI thread when a new file is requested.
  * - the variable "nb_files_processed" documents the number
  *   of files for which a stream has been created. It is
  *   updated by the UI thread.
  * - the flag "is_closing_requested" is set by the application
  *   when it wants to close the connection. The background thread
  *   will call the `picoquic_close` API in the background thread,
  *   set the flag `is_closing` after that, and set the flag
  *   `is_disconnected` when the stack has completed the closing.
  * After the application updates the shared state, it calls the
  * API `picoquic_wake_up_network_thread`. This cause the background
  * thread to stop waiting for packets or timeout, and to issue
  * a loop callback `picoquic_packet_loop_wake_up`, during which the
  * application provided call can interact safely with the
  * picoquic stack.
  */

typedef struct st_sample_background_stream_ctx_t {
    struct st_sample_background_stream_ctx_t* next_stream;
    size_t file_rank;
    uint64_t stream_id;
    size_t name_length;
    size_t name_sent_length;
    FILE* F;
    size_t bytes_received;
    uint64_t remote_error;
    unsigned int is_name_sent : 1;
    unsigned int is_file_open : 1;
    unsigned int is_stream_reset : 1;
    unsigned int is_stream_finished : 1;
} sample_background_stream_ctx_t;

typedef struct st_sample_background_ctx_t {
    unsigned int is_closing : 1;
    unsigned int is_closing_requested : 1;
    picoquic_cnx_t* cnx;
    char const* default_dir;
    char const** file_names;
    sample_background_stream_ctx_t* first_stream;
    sample_background_stream_ctx_t* last_stream;
    int nb_files;
    int nb_files_processed;
    int nb_files_received;
    int nb_files_failed;
    int is_disconnected;
} sample_background_ctx_t;

static int sample_background_create_stream(picoquic_cnx_t* cnx,
    sample_background_ctx_t* client_ctx, int file_rank)
{
    int ret = 0;
    sample_background_stream_ctx_t* stream_ctx = (sample_background_stream_ctx_t*)
        malloc(sizeof(sample_background_stream_ctx_t));

    if (stream_ctx == NULL) {
        fprintf(stdout, "Memory Error, cannot create stream for file number %d\n", (int)file_rank);
        ret = -1;
    }
    else {
        memset(stream_ctx, 0, sizeof(sample_background_stream_ctx_t));
        if (client_ctx->first_stream == NULL) {
            client_ctx->first_stream = stream_ctx;
            client_ctx->last_stream = stream_ctx;
        }
        else {
            client_ctx->last_stream->next_stream = stream_ctx;
            client_ctx->last_stream = stream_ctx;
        }
        stream_ctx->file_rank = file_rank;
        stream_ctx->stream_id = picoquic_get_next_local_stream_id(client_ctx->cnx, 0);
        stream_ctx->name_length = strlen(client_ctx->file_names[file_rank]);

        /* Mark the stream as active. The callback will be asked to provide data when 
         * the connection is ready. */
        ret = picoquic_mark_active_stream(cnx, stream_ctx->stream_id, 1, stream_ctx);
        if (ret != 0) {
            fprintf(stdout, "Error %d, cannot initialize stream for file number %d\n", ret, (int)file_rank);
        }
    }

    return ret;
}

static void sample_background_report(sample_background_ctx_t* client_ctx)
{
    sample_background_stream_ctx_t* stream_ctx = client_ctx->first_stream;

    while (stream_ctx != NULL) {
        char const* status;
        if (stream_ctx->is_stream_finished) {
            status = "complete";
        }
        else if (stream_ctx->is_stream_reset) {
            status = "reset";
        }
        else {
            status = "unknown status";
        }
        printf("%s: %s, received %zu bytes", client_ctx->file_names[stream_ctx->file_rank], status, stream_ctx->bytes_received);
        if (stream_ctx->is_stream_reset && stream_ctx->remote_error != PICOQUIC_SAMPLE_NO_ERROR){
            char const* error_text = "unknown error";
            switch (stream_ctx->remote_error) {
            case PICOQUIC_SAMPLE_INTERNAL_ERROR:
                error_text = "internal error";
                break;
            case PICOQUIC_SAMPLE_NAME_TOO_LONG_ERROR:
                error_text = "internal error";
                break;
            case PICOQUIC_SAMPLE_NO_SUCH_FILE_ERROR:
                error_text = "no such file";
                break;
            case PICOQUIC_SAMPLE_FILE_READ_ERROR:
                error_text = "file read error";
                break;
            case PICOQUIC_SAMPLE_FILE_CANCEL_ERROR:
                error_text = "cancelled";
                break;
            default:
                break;
            }
            printf(", error 0x%" PRIx64 " -- %s", stream_ctx->remote_error, error_text);
        }
        printf("\n");
        stream_ctx = stream_ctx->next_stream;
    }
}

static void sample_background_free_context(sample_background_ctx_t* client_ctx)
{
    sample_background_stream_ctx_t* stream_ctx;

    while ((stream_ctx = client_ctx->first_stream) != NULL) {
        client_ctx->first_stream = stream_ctx->next_stream;
        if (stream_ctx->F != NULL) {
            (void)picoquic_file_close(stream_ctx->F);
        }
        free(stream_ctx);
    }
    client_ctx->last_stream = NULL;
}


int sample_background_callback(picoquic_cnx_t* cnx,
    uint64_t stream_id, uint8_t* bytes, size_t length,
    picoquic_call_back_event_t fin_or_event, void* callback_ctx, void* v_stream_ctx)
{
    int ret = 0;
    sample_background_ctx_t* client_ctx = (sample_background_ctx_t*)callback_ctx;
    sample_background_stream_ctx_t* stream_ctx = (sample_background_stream_ctx_t*)v_stream_ctx;

    if (client_ctx == NULL) {
        /* This should never happen, because the callback context for the client is initialized 
         * when creating the client connection. */
        return -1;
    }

    if (ret == 0) {
        switch (fin_or_event) {
        case picoquic_callback_stream_data:
        case picoquic_callback_stream_fin:
            /* Data arrival on stream #x, maybe with fin mark */
            if (stream_ctx == NULL) {
                /* This is unexpected, as all contexts were declared when initializing the
                 * connection. */
                return -1;
            }
            else if (!stream_ctx->is_name_sent) {
                /* Unexpected: should not receive data before sending the file name to the server */
                return -1;
            }
            else if (stream_ctx->is_stream_reset || stream_ctx->is_stream_finished) {
                /* Unexpected: receive after fin */
                return -1;
            }
            else
            {
                if (stream_ctx->F == NULL) {
                    /* Open the file to receive the data. This is done at the last possible moment,
                     * to minimize the number of files open simultaneously.
                     * When formatting the file_path, verify that the directory name is zero-length,
                     * or terminated by a proper file separator.
                     */
                    char file_path[1024];
                    size_t dir_len = strlen(client_ctx->default_dir);
                    size_t file_name_len = strlen(client_ctx->file_names[stream_ctx->file_rank]);

                    if (dir_len > 0 && dir_len < sizeof(file_path)) {
                        memcpy(file_path, client_ctx->default_dir, dir_len);
                        if (file_path[dir_len - 1] != PICOQUIC_FILE_SEPARATOR[0]) {
                            file_path[dir_len] = PICOQUIC_FILE_SEPARATOR[0];
                            dir_len++;
                        }
                    }

                    if (dir_len + file_name_len + 1 >= sizeof(file_path)) {
                        /* Unexpected: could not format the file name */
                        fprintf(stderr, "Could not format the file path.\n");
                        ret = -1;
                    } else {
                        memcpy(file_path + dir_len, client_ctx->file_names[stream_ctx->file_rank],
                            file_name_len);
                        file_path[dir_len + file_name_len] = 0;
                        stream_ctx->F = picoquic_file_open(file_path, "wb");

                        if (stream_ctx->F == NULL) {
                            /* Could not open the file */
                            fprintf(stderr, "Could not open the file: %s\n", file_path);
                            ret = -1;
                        }
                    }
                }

                if (ret == 0 && length > 0) {
                    /* write the received bytes to the file */
                    if (fwrite(bytes, length, 1, stream_ctx->F) != 1) {
                        /* Could not write file to disk */
                        fprintf(stderr, "Could not write data to disk.\n");
                        ret = -1;
                    }
                    else {
                        stream_ctx->bytes_received += length;
                    }
                }

                if (ret == 0 && fin_or_event == picoquic_callback_stream_fin) {
                    stream_ctx->F = picoquic_file_close(stream_ctx->F);
                    stream_ctx->is_stream_finished = 1;
                    client_ctx->nb_files_received++;
                }
            }
            break;
        case picoquic_callback_stop_sending: /* Should not happen, treated as reset */
            /* Mark stream as abandoned, close the file, etc. */
            picoquic_reset_stream(cnx, stream_id, 0);
            /* Fall through */
        case picoquic_callback_stream_reset: /* Server reset stream #x */
            if (stream_ctx == NULL) {
                /* This is unexpected, as all contexts were declared when initializing the
                 * connection. */
                return -1;
            }
            else if (stream_ctx->is_stream_reset || stream_ctx->is_stream_finished) {
                /* Unexpected: receive after fin */
                return -1;
            }
            else {
                stream_ctx->remote_error = picoquic_get_remote_stream_error(cnx, stream_id);
                stream_ctx->is_stream_reset = 1;
                client_ctx->nb_files_failed++;
            }
            break;
        case picoquic_callback_stateless_reset:
        case picoquic_callback_close: /* Received connection close */
        case picoquic_callback_application_close: /* Received application close */
            client_ctx->is_disconnected = 1;
            /* Remove the application callback */
            picoquic_set_callback(cnx, NULL, NULL);
            break;
        case picoquic_callback_version_negotiation:
            /* The client did not get the right version.
             * TODO: some form of negotiation?
             */
            fprintf(stderr, "Received a version negotiation request:");
            for (size_t byte_index = 0; byte_index + 4 <= length; byte_index += 4) {
                uint32_t vn = 0;
                for (int i = 0; i < 4; i++) {
                    vn <<= 8;
                    vn += bytes[byte_index + i];
                }
                fprintf(stderr, "%s%08x", (byte_index == 0) ? " " : ", ", vn);
            }
            fprintf(stdout, "\n");
            break;
        case picoquic_callback_stream_gap:
            /* This callback is never used. */
            break;
        case picoquic_callback_prepare_to_send:
            /* Active sending API */
            if (stream_ctx == NULL) {
                /* Decidedly unexpected */
                return -1;
            } else if (stream_ctx->name_sent_length < stream_ctx->name_length){
                uint8_t* buffer;
                size_t available = stream_ctx->name_length - stream_ctx->name_sent_length;
                int is_fin = 1;

                /* The length parameter marks the space available in the packet */
                if (available > length) {
                    available = length;
                    is_fin = 0;
                }
                /* Needs to retrieve a pointer to the actual buffer 
                 * the "bytes" parameter points to the sending context 
                 */
                buffer = picoquic_provide_stream_data_buffer(bytes, available, is_fin, !is_fin);
                if (buffer != NULL) {
                    char const* filename = client_ctx->file_names[stream_ctx->file_rank];
                    memcpy(buffer, filename + stream_ctx->name_sent_length, available);
                    stream_ctx->name_sent_length += available;
                    stream_ctx->is_name_sent = is_fin;
                }
                else {
                    fprintf(stderr, "\nError, could not get data buffer.\n");
                    ret = -1;
                }
            }
            else {
                /* Nothing to send, just return */
            }
            break;
        case picoquic_callback_almost_ready:
            break;
        case picoquic_callback_ready:
            break;
        default:
            /* unexpected -- just ignore. */
            break;
        }
    }

    return ret;
}

/* Prepare the context used by the background client.:
 * - Create the QUIC context.
 * - Open the sockets
 * - Find the server's address
 * - Initialize the client context and create a client connection.
 */
static int sample_background_init(char const* server_name, int server_port, char const* default_dir,
    char const* ticket_store_filename, char const* token_store_filename,
    struct sockaddr_storage * server_address, picoquic_quic_t** quic, picoquic_cnx_t** cnx, sample_background_ctx_t *client_ctx)
{
    int ret = 0;
    char const* sni = PICOQUIC_SAMPLE_SNI;
    char const* qlog_dir = PICOQUIC_SAMPLE_CLIENT_QLOG_DIR;
    uint64_t current_time = picoquic_current_time();

    *quic = NULL;
    *cnx = NULL;

    /* Get the server's address */
    if (ret == 0) {
        int is_name = 0;

        ret = picoquic_get_server_address(server_name, server_port, server_address, &is_name);
        if (ret != 0) {
            fprintf(stderr, "Cannot get the IP address for <%s> port <%d>", server_name, server_port);
        }
        else if (is_name) {
            sni = server_name;
        }
    }

    /* Create a QUIC context. It could be used for many connections, but in this sample we
     * will use it for just one connection.
     * The sample code exercises just a small subset of the QUIC context configuration options:
     * - use files to store tickets and tokens in order to manage retry and 0-RTT
     * - set the congestion control algorithm to BBR
     * - enable logging of encryption keys for wireshark debugging.
     * - instantiate a binary log option, and log all packets.
     */
    if (ret == 0) {
        *quic = picoquic_create(1, NULL, NULL, NULL, PICOQUIC_SAMPLE_ALPN, NULL, NULL,
            NULL, NULL, NULL, current_time, NULL,
            ticket_store_filename, NULL, 0);

        if (*quic == NULL) {
            fprintf(stderr, "Could not create quic context\n");
            ret = -1;
        }
        else {
            if (picoquic_load_retry_tokens(*quic, token_store_filename) != 0) {
                fprintf(stderr, "No token file present. Will create one as <%s>.\n", token_store_filename);
            }

            picoquic_set_default_congestion_algorithm(*quic, picoquic_bbr_algorithm);

            picoquic_set_key_log_file_from_env(*quic);
            picoquic_set_qlog(*quic, qlog_dir);
            picoquic_set_log_level(*quic, 1);
        }
    }
    /* Initialize the callback context and create the connection context.
     * We use minimal options on the client side, keeping the transport
     * parameter values set by default for picoquic. This could be fixed later.
     */

    if (ret == 0) {
        client_ctx->default_dir = default_dir;

        printf("Starting connection to %s, port %d\n", server_name, server_port);

        /* Create a client connection */
        *cnx = picoquic_create_cnx(*quic, picoquic_null_connection_id, picoquic_null_connection_id,
            (struct sockaddr*)server_address, current_time, 0, sni, PICOQUIC_SAMPLE_ALPN, 1);

        if (*cnx == NULL) {
            fprintf(stderr, "Could not create connection context\n");
            ret = -1;
        }
        else {
            /* Document connection in client's context */
            client_ctx->cnx = *cnx;
            /* Set the client callback context */
            picoquic_set_callback(*cnx, sample_background_callback, client_ctx);
            /* Client connection parameters could be set here, before starting the connection. */
            ret = picoquic_start_client_cnx(*cnx);
            if (ret < 0) {
                fprintf(stderr, "Could not activate connection\n");
            }
            else {
                /* Printing out the initial CID, which is used to identify log files */
                picoquic_connection_id_t icid = picoquic_get_initial_cnxid(*cnx);
                printf("Initial connection ID: ");
                for (uint8_t i = 0; i < icid.id_len; i++) {
                    printf("%02x", icid.id[i]);
                }
                printf("\n");
            }
        }
    }

    return ret;
}

/* Loop callback for the background client.
* 
* The main difference with the simpler loop used for the basic client
* is the support for the "wake up" callback, which we use to create
* streams inside the background thread because the picoquic code
* is not generally thread safe.
* 
* The support for the wakeup call is declared 
* 
* 
* In the "background client" mode, the files are requested from
* the UI thread, but the corresponding streams are created in the
* background thread. We use a very simple thread coordination
* process to keep the sample simple:
* - the variable "nb_files" documents the number of files
*   that have been documented by the client. It is updated by
*   the UI thread when a new file is requested.
* - the variable "nb_files_processed" documents the number
*   of files for which a stream has been created. It is
*   updated by the UI thread.
* This is implemented in the "sample process wakeup" function.
*/


static int sample_background_wakeup(sample_background_ctx_t* client_ctx)
{
    int ret = 0;

    while (client_ctx->nb_files > client_ctx->nb_files_processed) {
        ret = sample_background_create_stream(client_ctx->cnx, client_ctx, client_ctx->nb_files_processed);
        if (ret < 0) {
            fprintf(stderr, "\nCould not initiate stream for file #%d, %s\n", 
                client_ctx->nb_files_processed,
                client_ctx->file_names[client_ctx->nb_files_processed]);
            break;
        }
        client_ctx->nb_files_processed++;
    }

    if (client_ctx->is_closing_requested && !client_ctx->is_closing) {
        picoquic_close(client_ctx->cnx, 0);
    }

    return ret;
}

static int sample_background_loop_cb(picoquic_quic_t* quic, picoquic_packet_loop_cb_enum cb_mode, 
    void* callback_ctx, void * callback_arg)
{
    int ret = 0;
    sample_background_ctx_t* client_ctx = (sample_background_ctx_t*)callback_ctx;

    if (client_ctx == NULL) {
        ret = PICOQUIC_ERROR_UNEXPECTED_ERROR;
    }
    else {
        switch (cb_mode) {
        case picoquic_packet_loop_ready:
            break;
        case picoquic_packet_loop_wake_up:
            ret = sample_background_wakeup(client_ctx);
            break;
        case picoquic_packet_loop_after_receive:
            break;
        case picoquic_packet_loop_after_send:
            if (client_ctx->is_disconnected) {
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

/* Background client.
*/
int picoquic_sample_background(char const* server_name, int server_port, char const* default_dir)
{
    int ret = 0;
    struct sockaddr_storage server_address;
    picoquic_quic_t* quic = NULL;
    picoquic_cnx_t* cnx = NULL;
    sample_background_ctx_t client_ctx = { 0 };
    char const* ticket_store_filename = PICOQUIC_SAMPLE_CLIENT_TICKET_STORE;
    char const* token_store_filename = PICOQUIC_SAMPLE_CLIENT_TOKEN_STORE;
    picoquic_network_thread_ctx_t* thread_ctx = NULL;
    int thread_ret = 0;
    int wait_cycles = 0;
    int wait_limit_sec = 1; /* By default, wait 1 second until completion */
    picoquic_packet_loop_param_t param = { 0 };
    char const* file_names[PICOQUIC_SAMPLE_BACKGROUND_MAX_FILES];
    char buf[256];

    ret = sample_background_init(server_name, server_port, default_dir,
        ticket_store_filename, token_store_filename,
        &server_address, &quic, &cnx, &client_ctx);

    /* Initialize the files field in the context to an empty vector*/
    client_ctx.file_names = file_names;

    /* set the thread parameters */
    param.local_af = server_address.ss_family;

    /* Start the background thread. */
    thread_ctx = picoquic_start_custom_network_thread(quic, &param,
        picoquic_internal_thread_create, picoquic_internal_thread_delete,
        picoquic_internal_thread_setname,"sample_background", 
        sample_background_loop_cb,
        &client_ctx, &thread_ret);

    /* Loop on the UI until the client calls it quit. */
    while (!client_ctx.is_closing_requested && !client_ctx.is_disconnected &&
        client_ctx.nb_files < PICOQUIC_SAMPLE_BACKGROUND_MAX_FILES) {
        size_t line_size = 0;
        printf("\nNext file (or empty line to quit)?\n");
        if (fgets(buf, sizeof(buf), stdin) != NULL) {
            /* clean the line feed characters if present */
            line_size = strlen(buf);
            while(line_size > 0) {
                int c = buf[line_size - 1];
                if (c != '\n' && c != '\r' && c != ' ' && c != '\t') {
                    break;
                }
                line_size--;
            }
        }
        if (line_size == 0) {
            printf("OK, empty name, closing.\n");
            break;
        }
        else {
            char * f_name = (char*)malloc(line_size + 1);
            if (f_name == NULL) {
                /* Error! Cannot continue */
                printf("Not enough memory for name, closing.\n");
                client_ctx.is_closing_requested = 1;
            }
            else {
                memcpy(f_name, buf, line_size);
                f_name[line_size] = 0;
                file_names[client_ctx.nb_files] = f_name;
                client_ctx.nb_files++;
            }
        }
        /* wakeup the background thread */
        picoquic_wake_up_network_thread(thread_ctx);
    }

    /* Wait until all files have been received.
    * If this was not just a sample, we would develop some code
    * to wait until the completion of the transport. Here,
    * we simply resort to active polling.
     */
    while (!thread_ctx->thread_is_closed) {
        if (client_ctx.is_disconnected) {
            printf("Disconnected.\n");
            break;
        }
        if ((client_ctx.nb_files_received + client_ctx.nb_files_failed) >= client_ctx.nb_files &&
            !client_ctx.is_closing_requested) {
            client_ctx.is_closing_requested = 1;
            picoquic_wake_up_network_thread(thread_ctx);
        }
        else {
#ifdef _WINDOWS
            Sleep(10);
#else
            usleep(10000);
#endif
            wait_cycles++;
            if (wait_cycles > wait_limit_sec * 100) {
                printf("\nDo you want to wait longer (y|n, default=y)?\n");
                if (fgets(buf, sizeof(buf), stdin) == NULL) {
                    break;
                }
                else {
                    if (buf[0] != 'n') {
                        wait_limit_sec *= 2;
                    }
                    else {
                        break;
                    }
                }
            }
        }
    }

    /* close the network thread. */
    picoquic_delete_network_thread(thread_ctx);
    thread_ctx = NULL;

    /* Done. At this stage, we could print out statistics, etc. */
    sample_background_report(&client_ctx);

    /* Save tickets and tokens, and free the QUIC context */
    if (quic != NULL) {
        if (picoquic_save_session_tickets(quic, ticket_store_filename) != 0) {
            fprintf(stderr, "Could not store the saved session tickets.\n");
        }
        if (picoquic_save_retry_tokens(quic, token_store_filename) != 0) {
            fprintf(stderr, "Could not save tokens to <%s>.\n", token_store_filename);
        }
        picoquic_free(quic);
    }
    /* Free the file names */
    for (int i = 0; i < client_ctx.nb_files; i++) {
        if (client_ctx.file_names[i] != NULL) {
            free((void*)client_ctx.file_names[i]);
        }
    }
    /* Free the Client context */
    sample_background_free_context(&client_ctx);

    return ret;
}