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

/* Socket loop implements the "wait for messages" loop common to most servers
 * and many clients.
 *
 * Second step: support simple servers and simple client.
 *
 * The "call loop back" function is called: when ready, after receiving, and after sending. The
 * loop will terminate if the callback return code is not zero -- except for special processing
 * of the migration testing code.
 * TODO: in Windows, use WSA asynchronous calls instead of sendmsg, allowing for multiple parallel sends.
 * TODO: in Linux, use multiple send per call API
 * TDOO: trim the #define list.
 * TODO: support the QuicDoq scenario, manage extra socket.
 */

#ifndef _WINDOWS
#include "picoquic_packet_loop.h"

int picoquic_packet_loop_win(picoquic_quic_t* quic,
    int local_port,
    int local_af,
    int dest_if,
    int socket_buffer_size,
    picoquic_packet_loop_cb_fn loop_callback,
    void* loop_callback_ctx)
{
    return -1;
}
#else
#define WIN32_LEAN_AND_MEAN
#include <WinSock2.h>
#include <Windows.h>
#include <assert.h>
#include <iphlpapi.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <ws2def.h>
#include <ws2tcpip.h>

#ifndef SOCKET_TYPE
#define SOCKET_TYPE SOCKET
#endif
#ifndef SOCKET_CLOSE
#define SOCKET_CLOSE(x) closesocket(x)
#endif
#ifndef WSA_LAST_ERROR
#define WSA_LAST_ERROR(x) WSAGetLastError()
#endif
#ifndef socklen_t
#define socklen_t int
#endif

#include "picosocks.h"
#include "picoquic.h"
#include "picoquic_internal.h"
#include "picoquic_packet_loop.h"
#include "picoquic_unified_log.h"

 /* Test support for UDP coalescing */
void picoquic_socks_win_coalescing_test(int * recv_coalesced, int * send_coalesced)
{
    int ret;
    DWORD option_value;
    int option_length;
    int last_error;

    *recv_coalesced = 0;
    *send_coalesced = 0;

    SOCKET_TYPE fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

    if (fd != INVALID_SOCKET) {
#ifdef UDP_SEND_MSG_SIZE
        option_length = (int)sizeof(option_value);

        if ((ret = getsockopt(fd, IPPROTO_UDP, UDP_SEND_MSG_SIZE, (char *)&option_value, &option_length)) != 0) {
            last_error = GetLastError();
            DBG_PRINTF("UDP_SEND_MSG_SIZE not supported, returns %d (%d)", ret, last_error);
        }
        else {
            *send_coalesced = 1;
        }
#endif
#ifdef UDP_RECV_MAX_COALESCED_SIZE
        option_value = 1;
        option_length = (int)sizeof(option_value);
        if ((ret = getsockopt(fd, IPPROTO_UDP, UDP_RECV_MAX_COALESCED_SIZE, (char*)&option_value, &option_length)) != 0) {
            last_error = GetLastError();
            DBG_PRINTF("UDP_RECV_MAX_COALESCED_SIZE not supported, returns %d (%d)", ret, last_error);
        }
        else {
            *recv_coalesced = 1;
        }
#endif
        closesocket(fd);
    }
}

/* Open a set of sockets in asynch mode. */
int picoquic_packet_loop_open_sockets_win(int local_port, int local_af, 
    picoquic_recvmsg_async_ctx_t** sock_ctx, int * sock_af, uint16_t * sock_ports,
    int socket_buffer_size, HANDLE * events, int nb_sockets_max)
{
    int ret = 0;
    int nb_sockets = (local_af == AF_UNSPEC) ? 2 : 1;
    int recv_coalesced;
    int send_coalesced;

    /* Assess whether coalescing is supported */
    picoquic_socks_win_coalescing_test(&recv_coalesced, &send_coalesced);

    /* Compute how many sockets are necessary */
    if (nb_sockets > nb_sockets_max) {
        DBG_PRINTF("Cannot open %d sockets, max set to %d\n", nb_sockets, nb_sockets_max);
        nb_sockets = 0;
    } else if (local_af == AF_UNSPEC) {
        sock_af[0] = AF_INET;
        sock_af[1] = AF_INET6;
    }
    else if (local_af == AF_INET || local_af == AF_INET6) {
        sock_af[0] = local_af;
    }
    else {
        DBG_PRINTF("Cannot open socket(AF=%d), unsupported AF\n", local_af);
        nb_sockets = 0;
    }

    for (int i = 0; i < nb_sockets; i++) {
        int recv_set = 0;
        int send_set = 0;

        sock_ctx[i] = picoquic_create_async_socket(sock_af[i], recv_coalesced, send_coalesced);
        if (sock_ctx[i] == NULL) {
            ret = -1;
            events[i] = NULL;
        }
        else {
            struct sockaddr_storage local_address;

            if (picoquic_socket_set_ecn_options(sock_ctx[i]->fd, sock_af[i], &recv_set, &send_set) != 0 ||
                picoquic_socket_set_pkt_info(sock_ctx[i]->fd, sock_af[i]) != 0 ||
                picoquic_bind_to_port(sock_ctx[i]->fd, sock_af[i], local_port) != 0 ||
                picoquic_get_local_address(sock_ctx[i]->fd, &local_address) != 0){
                DBG_PRINTF("Cannot set socket (af=%d, port = %d)\n", sock_af[i], local_port);
                for (int j = 0; j < i; j++) {
                    if (sock_ctx[i] != NULL) {
                        picoquic_delete_async_socket(sock_ctx[i]);
                        sock_ctx[i] = NULL;

                    }
                }
                nb_sockets = 0;
                break;
            }
            else {
                int opt_len;
                int opt_ret;

                if (local_address.ss_family == AF_INET6) {
                    sock_ports[i] = ntohs(((struct sockaddr_in6*)&local_address)->sin6_port);
                }
                else if (local_address.ss_family == AF_INET) {
                    sock_ports[i] = ntohs(((struct sockaddr_in*)&local_address)->sin_port);
                }

                events[i] = sock_ctx[i]->overlap.hEvent;
                if (socket_buffer_size > 0) {
                    opt_len = sizeof(int);
                    sock_ctx[i]->so_sndbuf = socket_buffer_size;
                    opt_ret = setsockopt(sock_ctx[i]->fd, SOL_SOCKET, SO_SNDBUF, (const char*)&sock_ctx[i]->so_sndbuf, opt_len);
                    if (opt_ret != 0) {
                        int sock_error = WSAGetLastError();
                        opt_ret = getsockopt(sock_ctx[i]->fd, SOL_SOCKET, SO_SNDBUF, (char*)&sock_ctx[i]->so_sndbuf, &opt_len);
                        DBG_PRINTF("Cannot set SO_SNDBUF to %d, err=%d, so_sndbuf=%d (%d)", socket_buffer_size, 
                            sock_error, sock_ctx[i]->so_sndbuf, opt_ret);
                    }
                    opt_len = sizeof(int);
                    sock_ctx[i]->so_rcvbuf = socket_buffer_size;
                    opt_ret = setsockopt(sock_ctx[i]->fd, SOL_SOCKET, SO_RCVBUF, (const char*)&sock_ctx[i]->so_rcvbuf, opt_len); if (opt_ret != 0) {
                        int sock_error = WSAGetLastError();
                        opt_ret = getsockopt(sock_ctx[i]->fd, SOL_SOCKET, SO_RCVBUF, (char*)&sock_ctx[i]->so_rcvbuf, &opt_len);
                        DBG_PRINTF("Cannot set SO_RCVBUF to %d, err=%d, so_rcvbuf=%d (%d)", socket_buffer_size, sock_error, sock_ctx[i]->so_rcvbuf, opt_ret);
                    }
                }
            }
        }
    }

    return nb_sockets;
}

/* Async version of Sendto.
 * The goal is to use WSASendMsg in asynchronous mode.
 * Each send operation operates with a buffer of type picoquic_sendmsg_ctx_t,
 * with the following steps:
 * 1) A call to picoquic_prepare_next_packet fills data buffer, addresses, etc.
 * 2) A call to picooquic_sendmsg_start formats the sendmsg parameters and
 *    calls sendmsg in asynchronous mode.
 * 3) When the send completes, the completion routine fills number of
 *    bytes sent, error codes, etc.
 * 4) The send loop verifies that the previous send is complete before
 *    reusing the buffer
 * The step (4) is the most tricky. We envisage that the application will
 * manage several buffers so as to be able to send several packets in a
 * batch. We can manage the list of buffer as a heap, with the first sent
 * packet on top. If that packet is available (send complete or not yet sent)
 * the loop picks it, use it, and chains it at the end of the list. If
 * the list is long enough, there should never be a need to wait. When that
 * happens, the application has to actively wait for the completion,
 * maybe by running another "wait for receive or return immediately".
 */

typedef struct st_picoquic_sendmsg_ctx_t {
    WSAOVERLAPPED overlap;
    struct st_picoquic_sendmsg_ctx_t* next;
    picoquic_connection_id_t local_cnxid;
    WSABUF dataBuf;
    WSAMSG msg;
    char cmsg_buffer[1024];
    uint8_t * send_buffer;
    size_t send_buffer_size;
    struct sockaddr_storage addr_from;
    struct sockaddr_storage addr_dest;
    socklen_t from_length;
    socklen_t dest_length;
    int dest_if;
    size_t send_length;
    size_t send_msg_size;
    int bytes_sent;
    int ret;
    int last_err;
    GUID WSASendMsg_GUID;
    unsigned int is_started:1;
    unsigned int is_complete:1;
} picoquic_sendmsg_ctx_t;

void CALLBACK picoquic_sendmsg_complete_cb(
    IN DWORD dwError,
    IN DWORD cbTransferred,
    IN LPWSAOVERLAPPED lpOverlapped,
    IN DWORD dwFlags
)
{
    picoquic_sendmsg_ctx_t* send_ctx = (picoquic_sendmsg_ctx_t*)
        (((uint8_t*)lpOverlapped) - offsetof(struct st_picoquic_sendmsg_ctx_t, overlap));
    send_ctx->bytes_sent = (int)cbTransferred;
    send_ctx->ret = dwError;
    send_ctx->last_err = (dwError == 0) ? 0 : GetLastError();
    send_ctx->is_complete = 1;
}

int picoquic_sendmsg_start(picoquic_recvmsg_async_ctx_t* sock_ctx, picoquic_sendmsg_ctx_t* send_ctx)
{
    int ret = 0;
    DWORD numberOfBytesSent = 0;
    int should_retry;

    do {
        should_retry = 0;

        /* Format the message header */
        send_ctx->is_started = 1;
        memset(&send_ctx->msg, 0, sizeof(send_ctx->msg));
        send_ctx->msg.name = (struct sockaddr*) & send_ctx->addr_dest;
        send_ctx->msg.namelen = picoquic_addr_length((struct sockaddr*) & send_ctx->addr_dest);
        send_ctx->dataBuf.buf = (char*)send_ctx->send_buffer;
        send_ctx->dataBuf.len = (ULONG)send_ctx->send_length;
        send_ctx->msg.lpBuffers = &send_ctx->dataBuf;
        send_ctx->msg.dwBufferCount = 1;
        send_ctx->msg.Control.buf = (char*)send_ctx->cmsg_buffer;
        send_ctx->msg.Control.len = sizeof(send_ctx->cmsg_buffer);

        /* Format the control message */
        picoquic_socks_cmsg_format(&send_ctx->msg, send_ctx->send_length, send_ctx->send_msg_size,
            (struct sockaddr*) & send_ctx->addr_from, send_ctx->dest_if);

        /* Send the message */
        /* TODO: allo for immediate termination. */
        ret = sock_ctx->WSASendMsg(sock_ctx->fd, &send_ctx->msg, 0, &numberOfBytesSent, &send_ctx->overlap, picoquic_sendmsg_complete_cb);
        if (ret != 0) {
            DWORD last_err = WSAGetLastError();
            if (last_err == WSA_IO_PENDING) {
                ret = 0;
            }
            else if (last_err == WSAECONNRESET) {
                should_retry = 1;
                ret = 0;
            }
            else {
                send_ctx->last_err = WSAGetLastError();
                send_ctx->ret = ret;
            }
        }
        else {
            /* Immediate completion */
            send_ctx->bytes_sent = (int)numberOfBytesSent;
            send_ctx->ret = 0;
            send_ctx->last_err = 0;
            send_ctx->is_complete = 1;
        }
    } while (should_retry);

    return ret;
}

picoquic_sendmsg_ctx_t* picoquic_socks_create_send_ctx(size_t send_buffer_size)
{
    picoquic_sendmsg_ctx_t* send_ctx = (picoquic_sendmsg_ctx_t*)malloc(sizeof(picoquic_sendmsg_ctx_t));
    if (send_ctx == NULL) {
        DBG_PRINTF("Cannot allocate send ctx (%x)", send_ctx);
    }
    else {
        uint8_t* send_buffer = (uint8_t*)malloc(send_buffer_size);
        if (send_buffer == NULL) {
            DBG_PRINTF("Cannot allocate send buffer (%x) size %zu",
                send_buffer, send_buffer);
            free(send_ctx);
            send_ctx = NULL;
        }
        else {
            memset(send_ctx, 0, sizeof(picoquic_sendmsg_ctx_t));
            send_ctx->send_buffer = send_buffer;
            send_ctx->send_buffer_size = send_buffer_size;
        }
    }

    return send_ctx;
}

int picoquic_socks_create_send_ctx_list(int nb_ctx, size_t send_buffer_size,
    picoquic_sendmsg_ctx_t** p_send_ctx_first, picoquic_sendmsg_ctx_t** p_send_ctx_last)
{
    int ret = 0;

    for (int i = 0; i < nb_ctx; i++) {
        picoquic_sendmsg_ctx_t* send_ctx = picoquic_socks_create_send_ctx(send_buffer_size);

        if (send_ctx == NULL) {
            ret = -1;
            break;
        }
        else {
            if (*p_send_ctx_last == NULL) {
                *p_send_ctx_last = send_ctx;
            }
            send_ctx->next = *p_send_ctx_first;
            *p_send_ctx_first = send_ctx;
        }
    }

    return ret;
}

void  picoquic_socks_delete_send_ctx(picoquic_sendmsg_ctx_t* send_ctx)
{
    if (send_ctx != NULL) {
        if (send_ctx->send_buffer != NULL) {
            free(send_ctx->send_buffer);
        }
        free(send_ctx);
    }
}

void picoquic_socks_delete_send_ctx_list(picoquic_sendmsg_ctx_t** p_send_ctx_first, picoquic_sendmsg_ctx_t** p_send_ctx_last)
{
    while (*p_send_ctx_first != NULL) {
        picoquic_sendmsg_ctx_t* send_ctx = *p_send_ctx_first;
        *p_send_ctx_first = send_ctx->next;
        picoquic_socks_delete_send_ctx(send_ctx);
    }
    *p_send_ctx_last = NULL;
}

/* Specialized packet loop using Windows sockets.
 */

int picoquic_packet_loop_win(picoquic_quic_t* quic,
    int local_port,
    int local_af,
    int dest_if,
    int socket_buffer_size,
    picoquic_packet_loop_cb_fn loop_callback,
    void* loop_callback_ctx)
{
    int ret = 0;
    uint64_t current_time = picoquic_get_quic_time(quic);
    int64_t delay_max = 10000000;
    picoquic_connection_id_t log_cid;
    picoquic_recvmsg_async_ctx_t* sock_ctx[PICOQUIC_PACKET_LOOP_SOCKETS_MAX];
    int sock_af[PICOQUIC_PACKET_LOOP_SOCKETS_MAX];
    uint16_t sock_ports[PICOQUIC_PACKET_LOOP_SOCKETS_MAX];
    HANDLE events[PICOQUIC_PACKET_LOOP_SOCKETS_MAX];
    int nb_sockets = 0;
    int testing_migration = 0; /* Hook for the migration test */
    uint16_t next_port = 0; /* Data for the migration test */
    picoquic_cnx_t* last_cnx = NULL;
    int path_id = -1;
    picoquic_sendmsg_ctx_t* send_ctx_first = NULL;
    picoquic_sendmsg_ctx_t* send_ctx_last = NULL;
    picoquic_packet_loop_options_t options = { 0 };
    uint64_t next_send_time = current_time + PICOQUIC_PACKET_LOOP_SEND_DELAY_MAX;
    WSADATA wsaData = { 0 };
    /* TODO: rewrite the code and avoid using the "loop_immediate" state variable */
    int loop_immediate = 0;
    (void)WSA_START(MAKEWORD(2, 2), &wsaData);
    memset(sock_af, 0, sizeof(sock_af));
    memset(sock_ports, 0, sizeof(sock_ports));

    /* Open the sockets */
    if ((nb_sockets = picoquic_packet_loop_open_sockets_win(
        local_port, local_af, sock_ctx, sock_af, sock_ports, socket_buffer_size, events, PICOQUIC_PACKET_LOOP_SOCKETS_MAX)) <= 0) {
        ret = PICOQUIC_ERROR_UNEXPECTED_ERROR;
    }
    else if (loop_callback != NULL) {
        struct sockaddr_storage l_addr;
        ret = loop_callback(quic, picoquic_packet_loop_ready, loop_callback_ctx, &options);
        if (picoquic_store_loopback_addr(&l_addr, sock_af[0], sock_ports[0]) == 0) {
            ret = loop_callback(quic, picoquic_packet_loop_port_update, loop_callback_ctx, &l_addr);
        }
    }

    /* Create a list of contexts for sending packets */
    if (ret == 0) {
        size_t send_buffer_size = PICOQUIC_MAX_PACKET_SIZE;
        if (sock_ctx[0]->supports_udp_send_coalesced) {
            send_buffer_size *= 10;
        }
        ret = picoquic_socks_create_send_ctx_list(PICOQUIC_PACKET_LOOP_SEND_MAX, send_buffer_size,
            &send_ctx_first, &send_ctx_last);
    }

    /* If the socket is already bound, start asynch receive */
    if (ret == 0) {
        for (int i = 0; i < nb_sockets; i++) {
            if (!sock_ctx[i]->is_started) {
                sock_ctx[i]->is_started = 1;
                ret = picoquic_recvmsg_async_start(sock_ctx[i]);
                if (ret == -1) {
                    DBG_PRINTF("%s", "Cannot start async recv");
                }
            }
        }
    }

    while (ret == 0) {
        int socket_rank = -1;
        int64_t delta_t;
        DWORD delta_t_ms=0;
        /* TODO: rewrite the code and avoid using the "loop_immediate" state variable */
        if (!loop_immediate) {
            delta_t = picoquic_get_next_wake_delay(quic, current_time, delay_max);

            if (options.do_time_check) {
                packet_loop_time_check_arg_t time_check_arg;
                time_check_arg.current_time = current_time;
                time_check_arg.delta_t = delta_t;
                ret = loop_callback(quic, picoquic_packet_loop_time_check, loop_callback_ctx, &time_check_arg);
                if (time_check_arg.delta_t < delta_t) {
                    delta_t = time_check_arg.delta_t;
                }
            }

            delta_t_ms = (delta_t < 0) ? 0 : (DWORD)(delta_t / 1000);
        }
        loop_immediate = 0;
        DWORD ret_event = WSAWaitForMultipleEvents(nb_sockets, events, FALSE, delta_t_ms, TRUE);
        current_time = picoquic_get_quic_time(quic);

        if (ret_event == WSA_WAIT_FAILED) {
            DBG_PRINTF("WSAWaitForMultipleEvents fails, error 0x%x", WSAGetLastError());
            ret = -1;
        } else if (ret_event >= WSA_WAIT_EVENT_0) {
            socket_rank = ret_event - WSA_WAIT_EVENT_0;
            /* if received data on a socket, process it. */
            if (socket_rank < nb_sockets) {
                /* Received data on socket i */
                ret = picoquic_recvmsg_async_finish(sock_ctx[socket_rank]);
                ResetEvent(sock_ctx[socket_rank]->overlap.hEvent);

                if (ret != 0) {
                    DBG_PRINTF("%s", "Cannot finish async recv");
                }
                else
                {
                    size_t recv_bytes = 0;
                    if (sock_ctx[socket_rank]->bytes_recv > 0) {
                        /* Document incoming port. By default, there is just one port in use.
                         * But we also have special code for supporting migration tests, which requires
                         * a second socket with a different port number.
                         */
                        uint16_t current_recv_port;

                        if (testing_migration && socket_rank != 0) {
                            current_recv_port = next_port;
                        }
                        else {
                            current_recv_port = sock_ports[socket_rank];
                        }

                        if (sock_ctx[socket_rank]->addr_dest.ss_family == AF_INET6) {
                            ((struct sockaddr_in6*) & sock_ctx[socket_rank]->addr_dest)->sin6_port = current_recv_port;
                        }
                        else if (sock_ctx[socket_rank]->addr_dest.ss_family == AF_INET) {
                            ((struct sockaddr_in*) & sock_ctx[socket_rank]->addr_dest)->sin_port = current_recv_port;
                        }

                        while (recv_bytes < (size_t)sock_ctx[socket_rank]->bytes_recv) {
                            size_t recv_length = (size_t)(sock_ctx[socket_rank]->bytes_recv - recv_bytes);

                            if (sock_ctx[socket_rank]->udp_coalesced_size > 0 &&
                                recv_length > sock_ctx[socket_rank]->udp_coalesced_size){
                                recv_length = sock_ctx[socket_rank]->udp_coalesced_size;
                            }

                            if (recv_length == 4) {
                                DBG_PRINTF("Local!");
                            }
                            else {
                                /* Submit the packet to the client */
                                ret = picoquic_incoming_packet_ex(quic, sock_ctx[socket_rank]->recv_buffer + recv_bytes,
                                    recv_length, (struct sockaddr*)&sock_ctx[socket_rank]->addr_from,
                                    (struct sockaddr*)&sock_ctx[socket_rank]->addr_dest, sock_ctx[socket_rank]->dest_if,
                                    sock_ctx[socket_rank]->received_ecn, &last_cnx, &path_id, current_time);
                                recv_bytes += recv_length;
                            }
                        }
                    }

                    if (ret == 0) {
                        /* Restart waiting for packets on the socket */
                        ret = picoquic_recvmsg_async_start(sock_ctx[socket_rank]);
                        if (ret == -1) {
                            DBG_PRINTF("%s", "Cannot re-start async recv");
                        }
                    }
                    else {
                        DBG_PRINTF("Packet processing error\r\n");
                    }

                    if (ret == 0 && loop_callback != NULL) {
                        ret = loop_callback(quic, picoquic_packet_loop_after_receive, loop_callback_ctx, &recv_bytes);
                    }


                    if (ret == 0 && current_time < next_send_time) {
                        /* Try to receive more packets if possible */
                        loop_immediate = 1;
                        continue;
                    }
                    else {
                        next_send_time = current_time + PICOQUIC_PACKET_LOOP_SEND_DELAY_MAX;
                    }
                }
            }
            else {
                /* Receive timer */
                ret = 0;
            }
            /* Send packets that are now ready */
            if (ret != PICOQUIC_NO_ERROR_SIMULATE_NAT && ret != PICOQUIC_NO_ERROR_SIMULATE_MIGRATION) {
                size_t bytes_sent = 0;

                if (ret == 0 &&
                    (!send_ctx_first->is_started || send_ctx_first->is_complete)) {
                    do {
                        picoquic_recvmsg_async_ctx_t* sock_ctx_send = NULL;
                        picoquic_sendmsg_ctx_t* send_ctx = send_ctx_first;

                        if (send_ctx_first->is_started && send_ctx_first->is_complete) {
                            /* TODO: the error codes should be processed faster! */
                            if (send_ctx->ret != 0 && picoquic_socket_error_implies_unreachable(send_ctx->last_err)) {
                                picoquic_notify_destination_unreachable_by_cnxid(quic, &send_ctx->local_cnxid, current_time,
                                    (struct sockaddr*)&send_ctx->addr_dest, (struct sockaddr*)&send_ctx->addr_from,
                                    send_ctx->dest_if, send_ctx->last_err);
                            }
                        }

                        memset(&send_ctx->overlap, 0, sizeof(send_ctx->overlap));
                        send_ctx->is_started = 0;
                        send_ctx->is_complete = 0;
                        send_ctx->last_err = 0;
                        send_ctx->ret = 0;
                        send_ctx->send_msg_size = 0;

                        ret = picoquic_prepare_next_packet_ex(quic, current_time,
                            send_ctx->send_buffer, send_ctx->send_buffer_size, &send_ctx->send_length,
                            &send_ctx->addr_dest, &send_ctx->addr_from, &send_ctx->dest_if, &log_cid, &last_cnx,
                            (sock_ctx[0]->supports_udp_send_coalesced) ? &send_ctx->send_msg_size : NULL);

                        bytes_sent += send_ctx->send_length;

                        if (ret == 0 && send_ctx->send_length > 0) {
                            for (int i = 0; i < nb_sockets; i++) {
                                if (sock_af[i] == send_ctx->addr_dest.ss_family) {
                                    sock_ctx_send = sock_ctx[i];
                                    break;
                                }
                            }

                            if (testing_migration) {
                                /* This code path is only used in the migration tests */
                                uint16_t send_port = (send_ctx->addr_dest.ss_family == AF_INET) ?
                                    ((struct sockaddr_in*)&send_ctx->addr_from)->sin_port :
                                    ((struct sockaddr_in6*)&send_ctx->addr_from)->sin6_port;

                                if (send_port == next_port) {
                                    sock_ctx_send = sock_ctx[nb_sockets - 1];
                                }
                            }
                            if (sock_ctx_send == NULL) {
                                picoquic_log_app_message(last_cnx,
                                    "Could not find socket for AF_to=%d, AF_from=%d",
                                    send_ctx->addr_dest.ss_family, send_ctx->addr_from.ss_family);
                                ret = -1;
                                send_ctx->last_err = -1;
                            }
                            else {
                                if (last_cnx != NULL && last_cnx->path[0]->p_local_cnxid != NULL) {
                                    /* Store the connection ID, in case there is an error */
                                    send_ctx->local_cnxid = last_cnx->path[0]->p_local_cnxid->cnx_id;
                                }
                                else {
                                    send_ctx->local_cnxid.id_len = 0;
                                }
                                ret = picoquic_sendmsg_start(sock_ctx_send, send_ctx);
                            }

                            if (ret == 0) {
                                /* Queue the send context at the end of the buffer chain,
                                 * but only if there is more than 1 such context */
                                send_ctx->is_started = 1;
                                if (send_ctx != send_ctx_last) {
                                    send_ctx_last->next = send_ctx;
                                    send_ctx_first = send_ctx->next;
                                    send_ctx->next = NULL;
                                    send_ctx_last = send_ctx;
                                }
                            }
                            else {
                                DBG_PRINTF("Cannot start sendsmg, error: %d", send_ctx->last_err);
                                if (last_cnx != NULL && picoquic_socket_error_implies_unreachable(send_ctx->last_err)) {
                                    picoquic_notify_destination_unreachable(last_cnx, current_time,
                                        (struct sockaddr*)&send_ctx->addr_dest, (struct sockaddr*)&send_ctx->addr_from,
                                        send_ctx->dest_if, send_ctx->last_err);
                                }
                                ret = 0;
                            }
                        }
                        else {
                            break;
                        }
                    } while (ret == 0 && (!send_ctx_first->is_started || send_ctx_first->is_complete));
                }
                else {
                    DBG_PRINTF("%s", "No completion routine called on time!");
                    Sleep(1);
                }
                if (ret == 0 && loop_callback != NULL) {
                    ret = loop_callback(quic, picoquic_packet_loop_after_send, loop_callback_ctx, &bytes_sent);
                }
            }
        }

        /* Special code for managing tests */
        if (ret == PICOQUIC_NO_ERROR_SIMULATE_NAT || ret == PICOQUIC_NO_ERROR_SIMULATE_MIGRATION) {
            /* Two pseudo error codes used for testing migration!
             * What follows is really test code, which we write here because it has to handle
             * the sockets, which interferes a lot with the handling of the packet loop.
             */
            int s_mig_af;
            picoquic_recvmsg_async_ctx_t* sock_ctx_mig = NULL;
            int testing_nat = (ret == PICOQUIC_NO_ERROR_SIMULATE_NAT);
            HANDLE mig_sock_event = NULL;

            if (picoquic_packet_loop_open_sockets_win(0, sock_af[0], &sock_ctx_mig, &s_mig_af,
                &next_port, socket_buffer_size, &mig_sock_event, 1) != 1){
                if (last_cnx != NULL) {
                    picoquic_log_app_message(last_cnx, "Could not create socket for migration test, port=%d, af=%d",
                        next_port, sock_af[0]);
                }
            } else{
                sock_ctx_mig->is_started = 1;
                if (last_cnx != NULL) {
                    picoquic_log_app_message(last_cnx,
                        "Bound migration socket, AF = %d, port = %d", sock_af[0], next_port);
                }

                if (picoquic_recvmsg_async_start(sock_ctx_mig) != 0) {
                    if (last_cnx != NULL) {
                        picoquic_log_app_message(last_cnx, "Could not start migration socket, port=%d, af=%d",
                            next_port, sock_af[0]);
                    }
                    else {
                        DBG_PRINTF("%s", "Cannot start the migration socket");
                    }
                    picoquic_delete_async_socket(sock_ctx_mig);
                    sock_ctx_mig = NULL;
                    ret = -1;
                }
            }
            if (ret == PICOQUIC_NO_ERROR_SIMULATE_NAT || ret == PICOQUIC_NO_ERROR_SIMULATE_MIGRATION) {
                if (last_cnx == NULL) {
                    /* Fix for cases when the last_cnx is not set for migration tests. */
                    last_cnx = quic->cnx_list;
                }
                if (testing_nat) {
                    if (sock_ctx[0] != NULL) {
                        picoquic_delete_async_socket(sock_ctx[0]);
                    }
                    sock_ctx[0] = sock_ctx_mig;
                    sock_ports[0] = next_port;
                    events[0] = mig_sock_event;
                    ret = 0;
                    if (last_cnx != NULL) {
                        picoquic_log_app_message(last_cnx, "Testing NAT rebinding, port=%d, af=%d",
                            next_port, sock_af[0]);
                    }
                    if (loop_callback != NULL) {
                        struct sockaddr_storage l_addr;
                        if (picoquic_store_loopback_addr(&l_addr, sock_af[0], sock_ports[0]) == 0) {
                            ret = loop_callback(quic, picoquic_packet_loop_port_update, loop_callback_ctx, &l_addr);
                        }
                    }
                }
                else {
                    /* Testing organized migration */
                    if (nb_sockets < PICOQUIC_PACKET_LOOP_SOCKETS_MAX && last_cnx != NULL) {
                        struct sockaddr_storage local_address;
                        if (last_cnx != NULL) {
                            picoquic_log_app_message(last_cnx, "Testing organized migration, port=%d, af=%d",
                                next_port, sock_af[0]);
                        }
                        picoquic_store_addr(&local_address, (struct sockaddr*) & last_cnx->path[0]->local_addr);
                        if (local_address.ss_family == AF_INET6) {
                            ((struct sockaddr_in6*) & local_address)->sin6_port = next_port;
                        }
                        else if (local_address.ss_family == AF_INET) {
                            ((struct sockaddr_in*) & local_address)->sin_port = next_port;
                        }
                        sock_ctx[nb_sockets] = sock_ctx_mig;
                        sock_ports[nb_sockets] = next_port;
                        events[nb_sockets] = mig_sock_event;
                        nb_sockets++;
                        testing_migration = 1;
                        ret = picoquic_probe_new_path(last_cnx, (struct sockaddr*) & last_cnx->path[0]->peer_addr,
                            (struct sockaddr*) & local_address, current_time);
                    }
                    else {
                        picoquic_delete_async_socket(sock_ctx_mig);
                    }
                }
            }
        }
    }

    if (ret == PICOQUIC_NO_ERROR_TERMINATE_PACKET_LOOP) {
        /* Normal termination requested by the application, returns no error */
        ret = 0;
    }

    /* Close the sockets */
    for (int i = 0; i < nb_sockets; i++) {
        if (sock_ctx[i] != NULL) {
            picoquic_delete_async_socket(sock_ctx[i]);
            sock_ctx[i] = NULL;
            events[i] = NULL;
        }
    }

    /* Free the list of contexts */
    picoquic_socks_delete_send_ctx_list(&send_ctx_first, &send_ctx_last);

    return ret;
}

#endif /* _Windows */