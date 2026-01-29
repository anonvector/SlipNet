#include "targetver.h"

#define WIN32_LEAN_AND_MEAN             // Exclude rarely-used stuff from Windows headers
#include <stdlib.h>
#include <malloc.h>
#include <memory.h>
#include <WinSock2.h>
#include <Windows.h>
#include <tchar.h>
#include <assert.h>
#include <iphlpapi.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <ws2tcpip.h>
#include "picoquic.h"
#include "h3zero.h"
#include "h3zero_common.h"
#include "democlient.h"
#include "quicwind.h"
#include "autoqlog.h"

#ifndef SOCKET_TYPE
#define SOCKET_TYPE SOCKET
#endif
#ifndef socklen_t
#define socklen_t int
#endif

#include "picoquic.h"
#include "picoquic_internal.h"
#include "picosocks.h"
#include "picoquic_utils.h"
#include "h3zero.h"
#include "democlient.h"
#include "picoquic_packet_loop.h"

static const char* ticket_store_filename = "demo_ticket_store.bin";
static const char* token_store_filename = "demo_token_store.bin";

/* Callback function 
 * TODO: remove the "queue of docs" logic, replace with UI requests.
 * TODO: remove fprintf(), replace by message queue. 
 * TODO: support multiple parallel connections. 
 * TODO: add state evaluation */

typedef struct st_quicwind_stream_desc_t {
    uint64_t stream_id;
    uint64_t previous_stream_id;
    char const* doc_name;
    char const* f_name;
    int is_binary;
} quicwind_stream_desc_t;


#define PICOQUIC_DEMO_STREAM_LIST_MAX 16

typedef struct st_quicwind_stream_ctx_t quicwind_stream_ctx_t;

typedef struct st_quicwind_stream_ctx_t {
    quicwind_stream_ctx_t* next_stream;
    h3zero_data_stream_state_t stream_state;
    size_t received_length;
    uint64_t stream_id;
    FILE* F; /* NULL if stream is closed. */
} quicwind_stream_ctx_t;

typedef struct st_quicwind_callback_ctx_t {
    quicwind_stream_ctx_t* first_stream;
    uint64_t last_interaction_time;
    uint32_t nb_client_streams;
    int nb_open_streams;
    picoquic_alpn_enum alpn;
    int progress_observed;
} quicwind_callback_ctx_t;

/* Loop callback context.
 */
typedef struct st_quicwind_loop_ctx_t {
    picoquic_quic_t * qclient;
    /* Address for wakeup calls */
    struct sockaddr_storage loopback_address;
    /* socket for wakeup calls */
    SOCKET_TYPE wakeup_socket;
    int wakeup_socket_af;
    /* event queue and state */
    int quicwind_is_closing;
    quicwind_work_item_t* work_item_first;
    HANDLE work_item_mutex;

} quicwind_loop_ctx_t;

quicwind_loop_ctx_t q_loop_ctx;

static quicwind_stream_ctx_t* quicwind_find_stream(
    quicwind_callback_ctx_t* ctx, uint64_t stream_id)
{
    quicwind_stream_ctx_t * stream_ctx = ctx->first_stream;

    while (stream_ctx != NULL && stream_ctx->stream_id != stream_id) {
        stream_ctx = stream_ctx->next_stream;
    }

    return stream_ctx;
}

static void quicwind_delete_stream_context(quicwind_callback_ctx_t* ctx,
    quicwind_stream_ctx_t * stream_ctx)
{
    int removed_from_context = 0;

    stream_ctx->F = picoquic_file_close(stream_ctx->F);

    if (stream_ctx == ctx->first_stream) {
        ctx->first_stream = stream_ctx->next_stream;
        removed_from_context = 1;
    }
    else {
        quicwind_stream_ctx_t * previous = ctx->first_stream;

        while (previous != NULL) {
            if (previous->next_stream == stream_ctx) {
                previous->next_stream = stream_ctx->next_stream;
                removed_from_context = 1;
                break;
            }
            else {
                previous = previous->next_stream;
            }
        }
    }

    if (removed_from_context) {
        ctx->nb_open_streams--;
    }

    free(stream_ctx);
}

static void quicwind_delete_context(picoquic_cnx_t * cnx, quicwind_callback_ctx_t* ctx)
{
   quicwind_stream_ctx_t * stream_ctx;

    picoquic_set_callback(cnx, NULL, NULL);

    while ((stream_ctx = ctx->first_stream) != NULL) {
        quicwind_delete_stream_context(ctx, stream_ctx);
    }

    free(ctx);
}

int quicwind_callback(picoquic_cnx_t* cnx,
    uint64_t stream_id, uint8_t* bytes, size_t length,
    picoquic_call_back_event_t fin_or_event, void* callback_ctx, void* v_stream_ctx)
{
    int ret = 0;
    uint64_t fin_stream_id = PICOQUIC_DEMO_STREAM_ID_INITIAL;

    quicwind_callback_ctx_t* ctx = (quicwind_callback_ctx_t*)callback_ctx;
    quicwind_stream_ctx_t* stream_ctx;

    if (ctx == NULL) {
        return -1;
    }

    ctx->last_interaction_time = picoquic_get_quic_time(cnx->quic);
    ctx->progress_observed = 1;

    switch (fin_or_event) {
    case picoquic_callback_stream_data:
    case picoquic_callback_stream_fin:
        /* Data arrival on stream #x, maybe with fin mark */
        /* TODO: parse the frames. */
        /* TODO: check settings frame */
        stream_ctx = quicwind_find_stream(ctx, stream_id);
        if (stream_ctx != NULL && stream_ctx->F != NULL) {
            if (length > 0) {
                switch (ctx->alpn) {
                case picoquic_alpn_http_3: {
                    uint64_t error_found = 0;
                    size_t available_data = 0;
                    uint8_t * bytes_max = bytes + length;
                    while (bytes < bytes_max) {
                        bytes = h3zero_parse_data_stream(bytes, bytes_max, &stream_ctx->stream_state, &available_data, &error_found);
                        if (bytes == NULL) {
                            AppendText(_T("Error parsing H3 stream, closing the connection.\r\n"));
                            ret = picoquic_close(cnx, error_found);
                            break;
                        }
                        else if (available_data > 0) {
                            ret = (fwrite(bytes, 1, available_data, stream_ctx->F) > 0) ? 0 : -1;
                            stream_ctx->received_length += available_data;
                            bytes += available_data;
                        }
                    }
                    break;
                }
                case picoquic_alpn_http_0_9:
                default:
                    ret = (fwrite(bytes, 1, length, stream_ctx->F) > 0) ? 0 : -1;
                    stream_ctx->received_length += length;
                    break;
                }
            }

            if (fin_or_event == picoquic_callback_stream_fin) {
                quicwind_delete_stream_context(ctx, stream_ctx);
                AppendText(_T("Stream ended\r\n"));
            }
        }
        break;
    case picoquic_callback_stream_reset: /* Server reset stream #x */
    case picoquic_callback_stop_sending: /* Server asks client to reset stream #x */
        AppendText(_T("Received a stream reset.\n"));
        /* TODO: special case for uni streams. */
        stream_ctx = quicwind_find_stream(ctx, stream_id);
        quicwind_delete_stream_context(ctx, stream_ctx);
        picoquic_reset_stream(cnx, stream_id, 0);
        /* TODO: higher level notify? */
        break;
    case picoquic_callback_stateless_reset:
        AppendText(_T("Received a stateless reset.\n"));
        quicwind_delete_context(cnx, ctx);
        break;
    case picoquic_callback_close: /* Received connection close */
        AppendText(_T("Received a request to delete the connection.\n"));
        quicwind_delete_context(cnx, ctx);
        break;
    case picoquic_callback_application_close: /* Received application close */
        AppendText(_T("Received a request to close the application.\n"));
        quicwind_delete_context(cnx, ctx);
        break;
    case picoquic_callback_version_negotiation: /* Received version negotiation */
        AppendText(_T("Received a version negotiation request.\n"));
        break;
    case picoquic_callback_stream_gap:
        /* Gap indication, when unreliable streams are supported */
        AppendText(_T("Received a gap indication.\r\n"));
        stream_ctx = quicwind_find_stream(ctx, stream_id);
        if (stream_ctx != NULL && stream_ctx->F != NULL) {
            stream_ctx->F = picoquic_file_close(stream_ctx->F);
            ctx->nb_open_streams--;
            fin_stream_id = stream_id;
        }
        /* TODO: Define what error. Stop sending? */
        picoquic_reset_stream(cnx, stream_id, H3ZERO_INTERNAL_ERROR);
        break;
    case picoquic_callback_prepare_to_send:
        /* Used for active streams -- never used on client */
        break;
    case picoquic_callback_almost_ready:
        AppendText(_T("Connection Almost Ready.\n"));
        break;
    case picoquic_callback_ready:
        AppendText(_T("Connection Ready.\n"));
        break;
    default:
        /* unexpected */
        AppendText(_T("Callback unexpected.\n"));
        break;
    }

    /* that's it */
    return ret;
}

/* Create the client context */
picoquic_quic_t* quicwind_create_context(const char * alpn, int mtu_max, const char * root_crt, uint8_t client_cnx_id_length)
{
    /* Start: start the QUIC process with cert and key files */
    int ret = 0;
    picoquic_quic_t* qclient = NULL;
    picoquic_demo_callback_ctx_t callback_ctx;
    SOCKET_TYPE fd = INVALID_SOCKET;
    int server_addr_length = 0;
    size_t send_length = 0;
    uint64_t key_update_done = 0;
    uint64_t current_time = 0;
    int client_ready_loop = 0;
    int client_receive_loop = 0;
    int established = 0;
    int is_name = 0;
    int migration_started = 0;
    int address_updated = 0;
    int64_t delay_max = 10000000;
    int64_t delta_t = 0;

    /* Create QUIC context */
    current_time = picoquic_current_time();
    callback_ctx.last_interaction_time = current_time;

    if (ret == 0) {
        qclient = picoquic_create(8, NULL, NULL, root_crt, alpn, NULL, NULL, NULL, NULL, NULL, current_time, NULL, ticket_store_filename, NULL, 0);

        picoquic_set_default_congestion_algorithm(qclient, picoquic_cubic_algorithm);

        if (picoquic_load_tokens(qclient, token_store_filename) != 0) {
            AppendText(_T("Could not load tokens.\r\n"));
        }

        if (qclient == NULL) {
            ret = -1;
        }
        else {
            qclient->mtu_max = mtu_max;

            (void)picoquic_set_default_connection_id_length(qclient, client_cnx_id_length);

            if (root_crt == NULL) {

                /* Standard verifier would crash */
                AppendText(_T("No root crt list specified, certificate will not be verified.\r\n"));
                picoquic_set_null_verifier(qclient);
            }

        }
    }

    return qclient;
}

/* Wake up the network */
void quicwind_wake_up_network()
{
    if (q_loop_ctx.loopback_address.ss_family == AF_UNSPEC) {
        AppendText(_T("Background thread is not ready.\r\n"));
    }
    else {
        uint8_t wakeup[4] = { 0xc0, 0xff, 0xee, 0x11 };

        /* Send the wakeup message to the loopback. */
        int sent = sendto(q_loop_ctx.wakeup_socket, wakeup, sizeof(wakeup), 0,
            (struct sockaddr*)&q_loop_ctx.loopback_address,
            (q_loop_ctx.loopback_address.ss_family == AF_INET) ?
            sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6));
        if (sent != sizeof(wakeup)) {
            AppendText(_T("Cannot send wakeup message"));
        }
    }
}

/* Start download of a document
 */
int quicwind_start_download(picoquic_cnx_t * cnx, quicwind_callback_ctx_t * ctx, char const * doc_name)
{
    int ret = 0;
    quicwind_stream_ctx_t* s_ctx;

    s_ctx = (quicwind_stream_ctx_t*)malloc(sizeof(quicwind_stream_ctx_t));
    if (s_ctx == NULL) {
        ret = -1;
    }
    else {
        char file_name[256];
        char name_buffer[256];
        char request[256];
        uint8_t * path;
        size_t path_len;
        size_t request_length = 0;
        int name_index = 0;
        int doc_index = 0;

        memset(s_ctx, 0, sizeof(quicwind_stream_ctx_t));
        /* Set stream ID */
        s_ctx->stream_id = ((uint64_t)ctx->nb_client_streams)*4u;

        /* make sure that the doc name is properly formated */
        path = (uint8_t *)doc_name;
        path_len = strlen(doc_name);
        if (doc_name[0] != '/' && strlen(doc_name) + 1 <= sizeof(name_buffer)) {
            name_buffer[0] = '/';
            if (path_len > 0) {
                memcpy(&name_buffer[1], doc_name, path_len);
            }
            path = name_buffer;
            path_len++;
            name_buffer[path_len] = 0;
        }

        /* Derive file name from doc name */
        if (doc_name[0] == '/') {
            doc_index++;
        }

        while (doc_name[doc_index] != 0 && name_index < 255) {
            int c = doc_name[doc_index++];
            if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '.')) {
                c = '_';
            }
            file_name[name_index++] = c;
        }

        if (name_index == 0) {
            file_name[name_index++] = '_';
        }

        file_name[name_index] = 0;

        if (fopen_s(&s_ctx->F, file_name, "wb") != 0) {
            ret = -1;
            free(s_ctx);
        } else {
            /* Open file to receive stream */
            /* Add stream to context */
            s_ctx->next_stream = ctx->first_stream;
            ctx->first_stream = s_ctx;
            ctx->nb_client_streams++;
            ctx->nb_open_streams++;

            /* Format the protocol specific request */
            switch (ctx->alpn) {
            case picoquic_alpn_http_3:
                ret = h3zero_client_create_stream_request(
                    request, sizeof(request), path, path_len, 0, cnx->sni, &request_length);
                break;
            case picoquic_alpn_http_0_9:
            default:
                ret = h09_demo_client_prepare_stream_open_command(
                    request, sizeof(request), path, path_len, 0, cnx->sni, &request_length);
                break;
            }

            /* Send the request and report */
            if (ret == 0) {
                ret = picoquic_add_to_stream(cnx, s_ctx->stream_id, request, request_length, 1);
            }

            if (ret < 0) {
                AppendText(_T("Something really bad happened - closing the connection\r\n"));
                /* Something really bad happened */
                ret = picoquic_close(cnx, 0xFFFF);
            }
        }
    }

    return ret;
}

/* Start a new connection.
 * Create a connection in the client context,
 * set addresses, etc. Add a first stream if needed.
 */
int quicwind_start_connection(picoquic_quic_t * qclient,
    char const * name, char const *port_number, char const * doc_name,
    char const * alpn, char const *sni)
{

    int ret = 0;
    int port = 443;
    struct sockaddr_storage server_address;
    int is_name = 0;
    picoquic_cnx_t * cnx_client = NULL;

    if (qclient == NULL) {
        ret = -1;
    } else if (port_number != NULL) {
        port = atoi(port_number);
        if (port <= 0) {
            AppendText(_T("Bad port number"));
            ret = -1;
        }
    }

    if (ret == 0) {
        ret = picoquic_get_server_address(name, port, &server_address, &is_name);
        if (sni == NULL && is_name != 0) {
            sni = name;
        }
    }
    /* Create the client connection */
    if (ret == 0) {
        /* Create a client connection */
        cnx_client = picoquic_create_cnx(qclient, picoquic_null_connection_id, picoquic_null_connection_id,
            (struct sockaddr*)&server_address, picoquic_get_quic_time(qclient),
            0xFF000012, sni, alpn, 1);

        if (cnx_client == NULL) {
            AppendText(_T("Create connection failed."));
            ret = -1;
        }
        else {
            /* create callback context! */
            quicwind_callback_ctx_t * ctx = (quicwind_callback_ctx_t *)malloc(sizeof(quicwind_callback_ctx_t));
            if (ctx == NULL) {
                AppendText(_T("Create callback context failed."));
                ret = -1;
            }
            else {
                memset(ctx, 0, sizeof(quicwind_callback_ctx_t));

                ctx->alpn = picoquic_parse_alpn(alpn);

                picoquic_set_callback(cnx_client, quicwind_callback, ctx);

                ret = picoquic_start_client_cnx(cnx_client);

                if (ret == 0) {
                    switch (ctx->alpn) {
                    case picoquic_alpn_http_3:
                        ret = h3zero_protocol_init(cnx_client);
                        break;
                    default:
                        break;
                    }
                }
                else {
                    AppendText(_T("Start connection failed."));
                }

                if (ret == 0 && doc_name != 0) {
                    /* TODO: Start the download scenario */
                    ret = quicwind_start_download(cnx_client, ctx, doc_name);
                }
            }
        }
    }

    return ret;
}

/* Get a connection list, at it to the menu item */
int quicwind_get_cnx_list(picoquic_quic_t * qclient, HWND hDlg, int list_box_id)
{
    
    // Add items to list. 
    HWND hwndList = GetDlgItem(hDlg, list_box_id);
    picoquic_cnx_t * cnx = picoquic_get_first_cnx(qclient);
    int nb_cnx = 0;
    int pos;

    while (cnx != NULL) {
        int cid = 0;
        for (int x = 0; x < cnx->initial_cnxid.id_len && x < 4; x++) {
            cid <<= 8;
            cid |= cnx->initial_cnxid.id[x];
        }
        pos = (int)SendMessageA(hwndList, LB_ADDSTRING, 0,(LPARAM)cnx->sni);
        SendMessageA(hwndList, LB_SETITEMDATA, pos, (LPARAM)cid);
        nb_cnx++;
        cnx = cnx->next_in_table;
    }

    if (nb_cnx > 0){
        /* Set selection to the first item */
        SendMessageA(hwndList, LB_SETCURSEL, 0, 0);
        /* Set input focus to the list box. */
        SetFocus(hwndList);
    }

    return nb_cnx;
}

picoquic_cnx_t * quicwind_find_cid(picoquic_quic_t * qclient, int sel_cid)
{
    picoquic_cnx_t * cnx = picoquic_get_first_cnx(qclient);

    while (cnx != NULL) {
        int cid = 0;
        for (int x = 0; x < cnx->initial_cnxid.id_len && x < 4; x++) {
            cid <<= 8;
            cid |= cnx->initial_cnxid.id[x];
        }

        if (cid == sel_cid) {
            break;
        }
        
        cnx = cnx->next_in_table;
    }

    return cnx;
}

/* Ask to load a file, for the selected connection */
int quicwind_load_file(picoquic_quic_t * qclient, int sel_cid, char const * doc_name)
{
    int ret = 0;
    picoquic_cnx_t * cnx = quicwind_find_cid(qclient, sel_cid);

    if (cnx == NULL) {
        ret = -1;
    }
    else {
        /* Retrieve the app context from the connection */
        void * v_ctx = picoquic_get_callback_context(cnx);

        if (v_ctx == NULL) {
            ret = -1;
        }
        else {
            /* Request to load the file */
            ret = quicwind_start_download(cnx, (quicwind_callback_ctx_t *)v_ctx, doc_name);
        }
    }

    return ret;
}

/* Ask to close a connection */
int quicwind_disconnect(picoquic_quic_t * qclient, int sel_cid)
{
    int ret = 0;
    picoquic_cnx_t * cnx = quicwind_find_cid(qclient, sel_cid);

    if (cnx == NULL) {
        AppendText(_T("No connection context available.\r\n"));
        ret = -1;
    }
    else {
        ret = picoquic_close(cnx, 0);
    }

    return ret;

}

void quicwind_orderly_exit(picoquic_quic_t* qclient, HANDLE qclient_thread, DWORD dw_qclient_thread_id)
{
    /* Need to orderly stop the client thread. */
    if (qclient_thread != NULL) {
        /* Set the close thread flag */
        q_loop_ctx.quicwind_is_closing = 1;

        quicwind_wake_up_network();

        /* Wait until background thread has terminated, or 3 seconds. */
        if (WaitForMultipleObjects(1, &qclient_thread, TRUE, 3000) == WAIT_TIMEOUT) {
            TerminateThread(qclient_thread, 0);
        }
        /* Close the thread handle */
        CloseHandle(qclient_thread);
    }
    if (qclient != NULL) {
        picoquic_free(qclient);
    }
}

/* Add a message to the work queue 
 */
int quicwind_add_work_item(quicwind_work_item_enum item_type,
    int sel_cid, char const* name, char const* port_number, char const* doc_name, char const* alpn, char const* sni)
{
    int ret = 0;
    DWORD w_ret = 0;
    quicwind_work_item_t* w = NULL;

    if (q_loop_ctx.work_item_mutex == NULL) {
        AppendText(_T("Background thread is not ready.\r\n"));
        ret = -1;
    }
    else {
        w = (quicwind_work_item_t*)malloc(sizeof(quicwind_work_item_t));

        if (w == NULL) {
            AppendText(_T("Out of memory.\r\n"));
            ret = -1;
        }
        else {
            w->next = NULL;
            w->item_type = item_type;
            w->sel_cid = sel_cid;

            w->name[0] = 0;
            w->port[0] = 0;
            w->doc[0] = 0;
            w->alpn[0] = 0;
            w->sni[0] = 0;

            if (ret == 0 && name != NULL) {
                ret = memcpy_s(w->name, sizeof(w->name), name, sizeof(w->name));
            }

            if (ret == 0 && port_number != NULL) {
                ret = memcpy_s(w->port, sizeof(w->port), port_number, sizeof(w->port));
            }

            if (ret == 0 && doc_name != NULL) {
                ret = memcpy_s(w->doc, sizeof(w->doc), doc_name, sizeof(w->doc));
            }

            if (ret == 0 && alpn != NULL) {
                ret = memcpy_s(w->alpn, sizeof(w->alpn), alpn, sizeof(w->alpn));
            }

            if (ret == 0 && sni != NULL) {
                ret = memcpy_s(w->sni, sizeof(w->sni), sni, sizeof(w->sni));
            }

            if (ret != 0) {
                AppendText(_T("Cannot copy the work item.\r\n"));
            }
            else {
                w_ret = WaitForSingleObject(q_loop_ctx.work_item_mutex, 1000);
                switch (w_ret) {
                case WAIT_OBJECT_0: {
                    quicwind_work_item_t* next = q_loop_ctx.work_item_first;
                    quicwind_work_item_t* last = NULL;

                    while (next) {
                        last = next;
                        next = next->next;
                    }

                    if (last) {
                        last->next = w;
                    }
                    else {
                        q_loop_ctx.work_item_first = w;
                    }
                    if (!ReleaseMutex(q_loop_ctx.work_item_mutex)) {
                        AppendText(_T("Cannot release the work item mutex.\r\n"));
                    }

                    quicwind_wake_up_network();

                    break;
                }
                default:
                    AppendText(_T("Cannot obtain the work item mutex.\r\n"));
                    ret = -1;
                    break;
                }
            }

            if (ret != 0) {
                free(w);
            }
        }
    }

    return ret;
}

/* Consume the first work item in the queue */

int quicwind_execute_work_item(picoquic_quic_t * qclient)
{
    int ret = 0;
    DWORD w_ret;
    quicwind_work_item_t * w = NULL;

    if (q_loop_ctx.work_item_mutex == NULL) {
        AppendText(_T("Background thread is not ready.\r\n"));
        ret = -1;
    }
    else {
        w_ret = WaitForSingleObject(q_loop_ctx.work_item_mutex, 1000);
        switch (w_ret) {
        case WAIT_OBJECT_0: {
            if (q_loop_ctx.work_item_first != NULL) {
                w = q_loop_ctx.work_item_first;
                q_loop_ctx.work_item_first = w->next;
            }

            if (!ReleaseMutex(q_loop_ctx.work_item_mutex)) {
                AppendText(_T("Thread cannot release the work item mutex.\r\n"));
            }
            break;
        }
        default:
            AppendText(_T("Cannot obtain the work item mutex.\r\n"));
            ret = -1;
            break;
        }
    }

    if (w != NULL) {
        switch (w->item_type) {
        case quicwind_work_item_connection:
            if (quicwind_start_connection(qclient,
                (w->name[0] != 0) ? w->name : NULL, (w->port[0] != 0) ? w->port : NULL,
                (w->doc[0] != 0 > 0) ? w->doc : NULL, (w->alpn[0] != 0) ? w->alpn : NULL,
                (w->sni[0] != 0) ? w->sni : NULL) != 0) {
                AppendText(_T("Could not create the connection.\r\n"));
            }
            else {
                AppendText(_T("Created a connection\r\n"));
            }
            break;
        case quicwind_work_item_load_file:
            if (quicwind_load_file(qclient, w->sel_cid, w->doc) != 0) {
                AppendText(_T("Something happened, could not request the document.\r\n"));
            }
            break;
        case quicwind_work_item_disconnect:
            if (quicwind_disconnect(qclient, w->sel_cid) != 0) {
                AppendText(_T("Something happened, could not close the connection.\r\n"));
            }
            break;
        default:
            AppendText(_T("Thread found unknown item type.\r\n"));
            break;
        }
        free(w);
    }

    return ret;
}

void quicwind_clear_work_items()
{
    DWORD w_ret;
    quicwind_work_item_t * w = NULL;

    if (q_loop_ctx.work_item_mutex != NULL) {
        w_ret = WaitForSingleObject(q_loop_ctx.work_item_mutex, 1000);
        switch (w_ret) {
        case WAIT_OBJECT_0: {
            while (q_loop_ctx.work_item_first != NULL) {
                w = q_loop_ctx.work_item_first;
                q_loop_ctx.work_item_first = w->next;
                free(w);
            }
            CloseHandle(q_loop_ctx.work_item_mutex);
            q_loop_ctx.work_item_mutex = NULL;
            break;
        }
        default:
            AppendText(_T("Cannot obtain the work item mutex.\r\n"));
            break;
        }
    }
}

/* Start the protocol thread upon launching the application.
 * This is done by calling the default loop for windows,
 * and defining a specific loop callback.
 */

static int quicwind_loop_cb(picoquic_quic_t* quic, picoquic_packet_loop_cb_enum cb_mode, 
    void* callback_ctx, void * callback_arg)
{
    int ret = 0;
    quicwind_loop_ctx_t* cb_ctx = (quicwind_loop_ctx_t*)callback_ctx;

    if (cb_ctx == NULL || cb_ctx != (void*)&q_loop_ctx) {
        ret = PICOQUIC_ERROR_UNEXPECTED_ERROR;
    }
    else {
        switch (cb_mode) {
        case picoquic_packet_loop_ready:
            /* fprintf(stdout, "Waiting for packets.\n"); */
            break;
        case picoquic_packet_loop_after_receive:
            /* Consider loop on local event processing */
            if (*((size_t*)callback_arg) > 0) {
                AppendText(_T("Packet received\r\n"));
            }
            break;
        case picoquic_packet_loop_after_send:
            /* if disconnected, return PICOQUIC_NO_ERROR_TERMINATE_PACKET_LOOP */
            if (*((size_t*)callback_arg) > 0) {
                AppendText(_T("Packet sent\r\n"));
            }
            break;
        case picoquic_packet_loop_port_update:
            picoquic_store_addr(&q_loop_ctx.loopback_address, (struct sockaddr*)callback_arg);
            if (q_loop_ctx.loopback_address.ss_family != q_loop_ctx.wakeup_socket_af) {
                if (q_loop_ctx.wakeup_socket_af != AF_UNSPEC) {
                    SOCKET_CLOSE(q_loop_ctx.wakeup_socket);
                    q_loop_ctx.wakeup_socket = INVALID_SOCKET;
                    q_loop_ctx.wakeup_socket_af = AF_UNSPEC;
                }
                q_loop_ctx.wakeup_socket = picoquic_open_client_socket(q_loop_ctx.loopback_address.ss_family);
                if (q_loop_ctx.wakeup_socket == INVALID_SOCKET) {
                    AppendText(_T("Could not create wakeup socket\r\n"));
                    ret = PICOQUIC_ERROR_UNEXPECTED_ERROR;
                }
                else {
                    q_loop_ctx.wakeup_socket_af = q_loop_ctx.loopback_address.ss_family;
                }
            }
            if (ret == 0) {
                AppendText(_T("Wakeup port updated\r\n"));
            }
            break;
        default:
            ret = PICOQUIC_ERROR_UNEXPECTED_ERROR;
            break;
        }

        while (ret == 0 && q_loop_ctx.work_item_first != NULL) {
            ret = quicwind_execute_work_item(q_loop_ctx.qclient);
        }
    }
    return ret;
}

DWORD WINAPI quicwind_background_thread(LPVOID lpParam)
{

    /* Wait for packets */
    picoquic_quic_t* qclient = (picoquic_quic_t*)lpParam;
    int ret = 0;

    memset(&q_loop_ctx, 0, sizeof(quicwind_loop_ctx_t));
    q_loop_ctx.work_item_mutex = CreateMutex(NULL, FALSE, NULL);
    q_loop_ctx.qclient = qclient;

#ifdef _WINDOWS
    ret = picoquic_packet_loop_win(qclient, 0, 0, 0, 0, quicwind_loop_cb, &q_loop_ctx);
#else
    ret = picoquic_packet_loop(qclient, 0, 0, 0, 0, 0, quicwind_loop_cb, &q_loop_ctx);
#endif

    /* Exit from the loop */
    quicwind_clear_work_items();

    if (!q_loop_ctx.quicwind_is_closing) {
        AppendText(_T("Error: Network thread exit.\r\n"));
    }

    return ret;
}

