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

#ifdef _WINDOWS
#define WIN32_LEAN_AND_MEAN
#include <WinSock2.h>
#include <Windows.h>
#include <assert.h>
#include <iphlpapi.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
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

#else /* Linux */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
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

#ifndef __APPLE__
#ifdef __LINUX__
#include <linux/prctl.h>  /* Definition of PR_* constants */
#else
#include <sys/prctl.h>
#endif
#endif

#include <pthread.h>

#ifndef SOCKET_TYPE
#define SOCKET_TYPE int
#endif
#ifndef INVALID_SOCKET
#define INVALID_SOCKET -1
#endif
#ifndef SOCKET_CLOSE
#define SOCKET_CLOSE(x) close(x)
#endif
#ifndef WSA_LAST_ERROR
#define WSA_LAST_ERROR(x) ((long)(x))
#endif
#endif

#include "picosocks.h"
#include "picoquic.h"
#include "picoquic_internal.h"
#include "picoquic_packet_loop.h"
#include "picoquic_unified_log.h"

#if defined(_WINDOWS)
#ifdef UDP_SEND_MSG_SIZE
static int udp_gso_available = 1;
#else
static int udp_gso_available = 0;
#endif
#else
# if defined(UDP_SEGMENT)
static int udp_gso_available = 1;
#else
static int udp_gso_available = 0;
#endif
#endif

#ifdef _WINDOWS
/* Test support for UDP coalescing */
void picoquic_sockloop_win_coalescing_test(int * recv_coalesced, int * send_coalesced)
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
        if (udp_gso_available) {
            option_length = (int)sizeof(option_value);

            if ((ret = getsockopt(fd, IPPROTO_UDP, UDP_SEND_MSG_SIZE, (char*)&option_value, &option_length)) != 0) {
                last_error = GetLastError();
                DBG_PRINTF("UDP_SEND_MSG_SIZE not supported, returns %d (%d)", ret, last_error);
                udp_gso_available = 0;
            }
            else {
                *send_coalesced = 1;
            }
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

int picoquic_win_recvmsg_async_start(picoquic_socket_ctx_t* ctx)
{
    int last_error;
    int ret = 0;
    DWORD numberOfBytesReceived = 0;
    int should_retry;

    do {
        should_retry = 0;
        ctx->from_length = 0;
        ctx->dest_length = 0;
        ctx->dest_if = 0;
        ctx->received_ecn = 0;
        ctx->bytes_recv = 0;
        ctx->udp_coalesced_size = 0;

        ctx->overlap.Internal = 0;
        ctx->overlap.InternalHigh = 0;
        ctx->overlap.Offset = 0;
        ctx->overlap.OffsetHigh = 0;

        ctx->is_started = 0;

        ctx->dataBuf.buf = (char*)ctx->recv_buffer;
        ctx->dataBuf.len = (ULONG)ctx->recv_buffer_size;

        ctx->msg.name = (struct sockaddr*) & ctx->addr_from;
        ctx->msg.namelen = sizeof(ctx->addr_from);
        ctx->msg.lpBuffers = &ctx->dataBuf;
        ctx->msg.dwBufferCount = 1;
        ctx->msg.dwFlags = 0;
        ctx->msg.Control.buf = ctx->cmsg_buffer;
        ctx->msg.Control.len = sizeof(ctx->cmsg_buffer);

        /* Setting the &nbReceived parameter to NULL to force async behavior */
        ret = ctx->WSARecvMsg(ctx->fd, &ctx->msg, &numberOfBytesReceived, &ctx->overlap, NULL);

        if (ret != 0) {
            last_error = WSAGetLastError();
            if (last_error == WSA_IO_PENDING) {
                ret = 0;
            }
            else if (last_error == WSAECONNRESET) {
                /* Ignore the ICMP errors */
                should_retry = 1;
                ret = 0;
            }
            else {
                DBG_PRINTF("Could not start receive async (WSARecvMsg) on UDP socket %d = %d!\n",
                    (int)ctx->fd, last_error);
                ctx->bytes_recv = -1;
            }
        }
        else {
            ctx->nb_immediate_receive++;
        }
    } while (should_retry);

    return ret;
}

int picoquic_packet_set_windows_socket(int send_coalesced, int recv_coalesced, picoquic_socket_ctx_t* s_ctx)
{
    int ret = 0;
    GUID WSARecvMsg_GUID = WSAID_WSARECVMSG;
    GUID WSASendMsg_GUID = WSAID_WSASENDMSG;
    DWORD NumberOfBytes_recvguid = 0;
    DWORD NumberOfBytes_sendguid = 0;
    int nResult = 0;
    int last_error = 0;

    if ((nResult = WSAIoctl(s_ctx->fd, SIO_GET_EXTENSION_FUNCTION_POINTER,
        &WSARecvMsg_GUID, sizeof(WSARecvMsg_GUID),
        &s_ctx->WSARecvMsg, sizeof(s_ctx->WSARecvMsg),
        &NumberOfBytes_recvguid, NULL, NULL)) == SOCKET_ERROR ||
        (nResult = WSAIoctl(s_ctx->fd, SIO_GET_EXTENSION_FUNCTION_POINTER,
            &WSASendMsg_GUID, sizeof(WSASendMsg_GUID),
            &s_ctx->WSASendMsg, sizeof(s_ctx->WSASendMsg),
            &NumberOfBytes_sendguid, NULL, NULL)) == SOCKET_ERROR ||
        (s_ctx->overlap.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL))
        == WSA_INVALID_EVENT){
        last_error = WSAGetLastError();
        DBG_PRINTF("Could not initialize Windows parameters on socket %d= %d!\n",
            (int)s_ctx->fd, last_error);
        ret = -1;
    }

    if (ret == 0) {
        s_ctx->supports_udp_send_coalesced = send_coalesced;
        s_ctx->supports_udp_recv_coalesced = recv_coalesced;
        if (recv_coalesced) {
            s_ctx->recv_buffer_size = 0x10000;
        }
        else {
            s_ctx->recv_buffer_size = PICOQUIC_MAX_PACKET_SIZE;
        }
        s_ctx->recv_buffer = (uint8_t*)malloc(s_ctx->recv_buffer_size);
        if (s_ctx->recv_buffer == NULL) {
            DBG_PRINTF("Could not allocate buffer size %zu for socket %d!\n",
                s_ctx->recv_buffer_size, (int)s_ctx->fd);
            ret = -1;
        }
        else if (recv_coalesced) {
            DWORD coalesced_size = (DWORD) s_ctx->recv_buffer_size;
            if (setsockopt(s_ctx->fd, IPPROTO_UDP, UDP_RECV_MAX_COALESCED_SIZE, (char*)&coalesced_size,
                (int)sizeof(coalesced_size)) != 0) {
                last_error = GetLastError();
                DBG_PRINTF("Cannot set UDP_RECV_MAX_COALESCED_SIZE %d, returns %d (%d)",
                    coalesced_size, ret, last_error);
                ret = -1;
            }
        }
    }

    if (ret == 0) {
        ret = picoquic_win_recvmsg_async_start(s_ctx);
    }

    return ret;
}

int picoquic_win_recvmsg_async_finish(
    picoquic_socket_ctx_t* s_ctx)
{
    DWORD cbTransferred = 0;
    DWORD ret = 0;
    DWORD flags = 0;

    if (s_ctx == NULL) {
        return -1;
    }

    if (!WSAGetOverlappedResult(s_ctx->fd, &s_ctx->overlap, &cbTransferred, FALSE, &flags)) {
        ret = WSAGetLastError();
        if (ret == WSAECONNRESET) {
            s_ctx->bytes_recv = 0;
            ret = picoquic_win_recvmsg_async_start(s_ctx);
        }
        else {
            DBG_PRINTF("Could not complete async call (WSARecvMsg) on UDP socket %d = %d!\n",
                (int)s_ctx->fd, ret);
            s_ctx->bytes_recv = -1;
        }
    } 
    else {
        s_ctx->bytes_recv = cbTransferred;
        s_ctx->from_length = s_ctx->msg.namelen;

        picoquic_socks_cmsg_parse(&s_ctx->msg, &s_ctx->addr_dest, &s_ctx->dest_if, &s_ctx->received_ecn, &s_ctx->udp_coalesced_size);
    }

    return ret;
}

#endif

void picoquic_packet_loop_close_socket(picoquic_socket_ctx_t* s_ctx)
{
    if (s_ctx->fd != INVALID_SOCKET) {
        SOCKET_CLOSE(s_ctx->fd);
        s_ctx->fd = INVALID_SOCKET;
    }
#ifdef _WINDOWS
    if (s_ctx->overlap.hEvent != WSA_INVALID_EVENT) {
        WSACloseEvent(s_ctx->overlap.hEvent);
        s_ctx->overlap.hEvent = WSA_INVALID_EVENT;
    }

    if (s_ctx->recv_buffer != NULL) {
        free(s_ctx->recv_buffer);
        s_ctx->recv_buffer = NULL;
    }
#endif
}

int picoquic_packet_loop_open_socket(int socket_buffer_size, int do_not_use_gso,
    picoquic_socket_ctx_t* s_ctx)
{
    int ret = 0;
    struct sockaddr_storage local_address;
    int recv_set = 0;
    int send_set = 0;
#ifdef _WINDOWS
    int recv_coalesced = 0;
    int send_coalesced = 0;

    /* Assess whether coalescing is supported */
    if (!do_not_use_gso) {
        picoquic_sockloop_win_coalescing_test(&recv_coalesced, &send_coalesced);
#if 0
        /* TODO: remove temporary fix, after we figure how to work that out. */
        recv_coalesced = 0;
#endif
    }
    s_ctx->overlap.hEvent = WSA_INVALID_EVENT;
    s_ctx->fd = WSASocket(s_ctx->af, SOCK_DGRAM, IPPROTO_UDP, NULL, 0, WSA_FLAG_OVERLAPPED);
#else
    s_ctx->fd = socket(s_ctx->af, SOCK_DGRAM, IPPROTO_UDP);
#endif

    if (s_ctx->fd == INVALID_SOCKET ||
        /* TODO: set option IPv6 only */
        picoquic_socket_set_ecn_options(s_ctx->fd, s_ctx->af, &recv_set, &send_set) != 0 ||
        picoquic_socket_set_pkt_info(s_ctx->fd, s_ctx->af) != 0 ||
        picoquic_bind_to_port(s_ctx->fd,s_ctx->af, s_ctx->port) != 0 ||
        picoquic_get_local_address(s_ctx->fd, &local_address) != 0 ||
        picoquic_socket_set_pmtud_options(s_ctx->fd, s_ctx->af) != 0)
    {
        DBG_PRINTF("Cannot set socket (af=%d, port = %d)\n", s_ctx->af, s_ctx->port);
        ret = -1;
    }
    else {
        if (local_address.ss_family == AF_INET6) {
            s_ctx->port = ntohs(((struct sockaddr_in6*)&local_address)->sin6_port);
        }
        else if (local_address.ss_family == AF_INET) {
            s_ctx->port = ntohs(((struct sockaddr_in*)&local_address)->sin_port);
        }

        if (socket_buffer_size > 0) {
            socklen_t opt_len;
            int opt_ret;
            int so_sndbuf;
            int so_rcvbuf;
            int last_op = SO_SNDBUF;
            char const* last_op_name = "SO_SNDBUF";

            opt_len = sizeof(int);
            so_sndbuf = socket_buffer_size;
            opt_ret = setsockopt(s_ctx->fd, SOL_SOCKET, SO_SNDBUF, (const char*)&so_sndbuf, opt_len);
            if (opt_ret == 0) {
                last_op = SO_RCVBUF;
                last_op_name = "SO_RECVBUF";
                opt_len = sizeof(int);
                so_rcvbuf = socket_buffer_size;
                opt_ret = setsockopt(s_ctx->fd, SOL_SOCKET, SO_RCVBUF, (const char*)&so_rcvbuf, opt_len);
            }
            if (opt_ret != 0) {
                int so_errbuf = 0;
#ifdef _WINDOWS
                int sock_error = WSAGetLastError();
#else
                int sock_error = errno;
#endif
                opt_ret = getsockopt(s_ctx->fd, SOL_SOCKET, last_op, (char*)&so_errbuf, &opt_len);
                DBG_PRINTF("Cannot set %s to %d, err=%d, so_sndbuf=%d (%d)",
                    last_op_name, socket_buffer_size, sock_error, so_errbuf, opt_ret);
                ret = -1;
            }
        }
#ifdef _WINDOWS
        if (ret == 0) {
            ret = picoquic_packet_set_windows_socket(send_coalesced, recv_coalesced, s_ctx);
        }
#endif
    }

    return ret;
}

int picoquic_packet_loop_open_sockets(uint16_t local_port, int local_af, int socket_buffer_size, int extra_socket_required,
    int do_not_use_gso, picoquic_socket_ctx_t* s_ctx)
{
    int nb_sockets = 0;

    /* Compute how many sockets are necessary, and set the intial value of AF and port per socket */
    for (int iteration = 0; iteration < 1 + (extra_socket_required); iteration++) {
        uint16_t current_port = (iteration == 0) ? local_port : 0;
        if (local_af == AF_UNSPEC) {
            s_ctx[nb_sockets].af = AF_INET;
            s_ctx[nb_sockets].port = current_port;
            nb_sockets++;
            s_ctx[nb_sockets].af = AF_INET6;
            s_ctx[nb_sockets].port = current_port;
            nb_sockets++;
        }
        else {
            s_ctx[nb_sockets].af = local_af;
            s_ctx[nb_sockets].port = current_port;
            nb_sockets++;
        }
    }
    for (int i = 0; i < nb_sockets; i++) {
        if (picoquic_packet_loop_open_socket(socket_buffer_size, do_not_use_gso, &s_ctx[i]) != 0) {
            DBG_PRINTF("Cannot set socket (af=%d, port = %d)\n", s_ctx[i].af, s_ctx[i].port);
            for (int j = 0; j < i; j++) {
                picoquic_packet_loop_close_socket(&s_ctx[j]);
            }
            nb_sockets = 0;
            break;
        }
    }

    return nb_sockets;
}

/*
* Windows: use asynchronous receive. Asynchronous receive requires
* declaring an overlap context and event per socket, as well as a
* buffer per socket. This should probably be an option. Instead of
* calling socket, just use a "wait for event" to find out which
* readmsg has completed on what socket. If a read is available,
* return it. The memory is allocated per socket. After the loop
* has processed the message, it needs to "rearm" the socket to
* ready it for the next message.
* 
* Unix: use select. (Consider using poll instead?). If data is
* available, read it. This uses a shared buffer.
* 
* Both can return on timeout.
* 
* Both can accomodate a "wakeup" event. Should there be a
* specific callback if the wakeup event fires?
* 
 */
#ifdef _WINDOWS
/* TODO: manage coalesced receive in a portable way. 
 */
int picoquic_packet_loop_wait(picoquic_socket_ctx_t* s_ctx,
    int nb_sockets,
    struct sockaddr_storage* addr_from,
    struct sockaddr_storage* addr_dest,
    int* dest_if,
    unsigned char* received_ecn,
    uint8_t** received_buffer,
    int64_t delta_t,
    int* is_wake_up_event,
    picoquic_network_thread_ctx_t * thread_ctx,
    int* socket_rank)
{
    int bytes_recv = 0;
    HANDLE events[5];
    DWORD ret_event;
    DWORD nb_events = 0;
    int wake_up_event_rank = -1;
    DWORD dwDeltaT = (DWORD)((delta_t <= 0)? 0: (delta_t / 1000));

    for (int i = 0; i < 4 && i < nb_sockets; i++) {
        events[i] = s_ctx[i].overlap.hEvent;
        nb_events++;
    }
    *is_wake_up_event = 0;
    if (thread_ctx->wake_up_defined) {
        wake_up_event_rank = nb_events;
        events[nb_events] = thread_ctx->wake_up_event;
        nb_events++;
    }
    
    ret_event = WSAWaitForMultipleEvents(nb_events, events, FALSE, dwDeltaT, TRUE);
    if (ret_event == WSA_WAIT_FAILED) {
        DBG_PRINTF("WSAWaitForMultipleEvents fails, error 0x%x", WSAGetLastError());
        bytes_recv = -1;
    }
    else if (ret_event == STATUS_TIMEOUT) {
        bytes_recv = 0;
    }
    else if (ret_event >= WSA_WAIT_EVENT_0) {
        int event_rank = ret_event - WSA_WAIT_EVENT_0;

        if (event_rank < nb_sockets) {
            *socket_rank = event_rank;
            /* if received data on a socket, process it. */
            if (*socket_rank < nb_sockets) {
                /* Received data on socket i */
                int ret = picoquic_win_recvmsg_async_finish(&s_ctx[*socket_rank]);
                ResetEvent(s_ctx[*socket_rank].overlap.hEvent);

                if (ret != 0) {
                    DBG_PRINTF("%s", "Cannot finish async recv");
                    bytes_recv = -1;
                }
                else {
                    bytes_recv = s_ctx[*socket_rank].bytes_recv;
                    *received_ecn = s_ctx[*socket_rank].received_ecn;
                    *received_buffer = s_ctx[*socket_rank].recv_buffer;
                    picoquic_store_addr(addr_dest, (struct sockaddr*)&s_ctx[*socket_rank].addr_dest);
                    picoquic_store_addr(addr_from, (struct sockaddr*)&s_ctx[*socket_rank].addr_from);
                    /* Document incoming port */
                    if (addr_dest->ss_family == AF_INET6) {
                        ((struct sockaddr_in6*)addr_dest)->sin6_port = htons(s_ctx[*socket_rank].port);
                    }
                    else if (addr_dest->ss_family == AF_INET) {
                        ((struct sockaddr_in*)addr_dest)->sin_port = htons(s_ctx[*socket_rank].port);
                    }
                }
            }
        }
        else if (event_rank == wake_up_event_rank) {
            *is_wake_up_event = 1;
            if (ResetEvent(thread_ctx->wake_up_event) == 0) {
                DBG_PRINTF("Cannot reset network event, error 0x%x", GetLastError());
                bytes_recv = -1;
            }
        }
    }
    return bytes_recv;
}
#else
int picoquic_packet_loop_select(picoquic_socket_ctx_t* s_ctx,
    int nb_sockets,
    struct sockaddr_storage* addr_from,
    struct sockaddr_storage* addr_dest,
    int* dest_if,
    unsigned char * received_ecn,
    uint8_t* buffer, int buffer_max,
    int64_t delta_t,
    int * is_wake_up_event,
    picoquic_network_thread_ctx_t * thread_ctx,
    int * socket_rank)
{
    fd_set readfds;
    struct timeval tv;
    int ret_select = 0;
    int bytes_recv = 0;
    int sockmax = 0;

    if (received_ecn != NULL) {
        *received_ecn = 0;
    }

    FD_ZERO(&readfds);

    for (int i = 0; i < nb_sockets; i++) {
        if (sockmax < (int)s_ctx[i].fd) {
            sockmax = (int)s_ctx[i].fd;
        }
        FD_SET(s_ctx[i].fd, &readfds);
    }

    *is_wake_up_event = 0;
    if (thread_ctx->wake_up_defined) {
        if (sockmax < (int)thread_ctx->wake_up_pipe_fd[0]) {
            sockmax = (int)thread_ctx->wake_up_pipe_fd[0];
        }
        FD_SET(thread_ctx->wake_up_pipe_fd[0], &readfds);
    }

    if (delta_t <= 0) {
        tv.tv_sec = 0;
        tv.tv_usec = 0;
    } else {
        if (delta_t > 10000000) {
            tv.tv_sec = (long)10;
            tv.tv_usec = 0;
        } else {
            tv.tv_sec = (long)(delta_t / 1000000);
            tv.tv_usec = (long)(delta_t % 1000000);
        }
    }

    ret_select = select(sockmax + 1, &readfds, NULL, NULL, &tv);

    if (ret_select < 0) {
        bytes_recv = -1;
        DBG_PRINTF("Error: select returns %d\n", ret_select);
    } else if (ret_select > 0) {
        /* Check if the 'wake up' pipe is full. If it is, read the data on it,
         * set the is_wake_up_event flag, and ignore the other file descriptors. */
        if (thread_ctx->wake_up_defined && FD_ISSET(thread_ctx->wake_up_pipe_fd[0], &readfds)) {
            /* Something was written on the "wakeup" pipe. Read it. */
            uint8_t eventbuf[8];
            int pipe_recv;
            if ((pipe_recv = read(thread_ctx->wake_up_pipe_fd[0], eventbuf, sizeof(eventbuf))) <= 0) {
                bytes_recv = -1;
                DBG_PRINTF("Error: read pipe returns %d\n", (pipe_recv == 0)?EPIPE:errno);
            }
            else {
                *is_wake_up_event = 1;
            }
        }
        else
        {
            for (int i = 0; i < nb_sockets; i++) {
                if (FD_ISSET(s_ctx[i].fd, &readfds)) {
                    *socket_rank = i;
                    bytes_recv = picoquic_recvmsg(s_ctx[i].fd, addr_from,
                        addr_dest, dest_if, received_ecn,
                        buffer, buffer_max);

                    if (bytes_recv <= 0) {
                        DBG_PRINTF("Could not receive packet on UDP socket[%d]= %d!\n",
                            i, (int)s_ctx[i].fd);
                        break;
                    }
                    else {
                        /* Document incoming port */
                        if (addr_dest->ss_family == AF_INET6) {
                            ((struct sockaddr_in6*)addr_dest)->sin6_port = htons(s_ctx[i].port);
                        }
                        else if (addr_dest->ss_family == AF_INET) {
                            ((struct sockaddr_in*)addr_dest)->sin_port = htons(s_ctx[i].port);
                        }
                        break;
                    }
                }
            }
        }
    }

    return bytes_recv;
}
#endif

static int monitor_system_call_duration(packet_loop_system_call_duration_t* sc_duration, uint64_t current_time, uint64_t previous_time)
{
    uint64_t duration = current_time - previous_time;
    int64_t dev = sc_duration->scd_smoothed - duration;
    int shall_notify = 0;

    if (duration > sc_duration->scd_max) {
        shall_notify = 1;
        sc_duration->scd_max = duration;
    }
    else if (duration != sc_duration->scd_last) {
        int64_t delta_d = sc_duration->scd_last - duration;

        if (delta_d > 1000 || delta_d < -1000 || delta_d < (int64_t)sc_duration->scd_last) {
            shall_notify = 1;
        }
        sc_duration->scd_last = duration;
    }

    sc_duration->scd_smoothed = (duration + 15 * sc_duration->scd_smoothed) / 16;
    if (dev < 0) {
        dev = -dev;
    }
    sc_duration->scd_dev = (7 * sc_duration->scd_dev + dev) / 8;

    return shall_notify;
}


#ifdef _WINDOWS
    DWORD WINAPI picoquic_packet_loop_v3(LPVOID v_ctx)
#else
void* picoquic_packet_loop_v3(void* v_ctx)
#endif
{
    picoquic_network_thread_ctx_t* thread_ctx = (picoquic_network_thread_ctx_t*)v_ctx;
    picoquic_quic_t* quic = thread_ctx->quic;
    picoquic_packet_loop_param_t* param = thread_ctx->param;
    picoquic_packet_loop_cb_fn loop_callback = thread_ctx->loop_callback;
    void* loop_callback_ctx = thread_ctx->loop_callback_ctx;
    int ret = 0;
    uint64_t current_time = picoquic_get_quic_time(quic);
    int64_t delay_max = 10000000;
    struct sockaddr_storage addr_from;
    struct sockaddr_storage addr_to;
    int if_index_to;
#ifndef _WINDOWS
    uint8_t buffer[1536];
#endif
    uint8_t* send_buffer = NULL;
    size_t send_length = 0;
    size_t send_msg_size = 0;
    size_t send_buffer_size = param->socket_buffer_size;
    size_t* send_msg_ptr = NULL;
    int bytes_recv;
    picoquic_connection_id_t log_cid;
    picoquic_socket_ctx_t s_ctx[4];
    int nb_sockets = 0;
    int nb_sockets_available = 0;
    picoquic_cnx_t* last_cnx = NULL;
    int last_path_id = -1;
    int loop_immediate = 0;
    unsigned int nb_loop_immediate = 0;
    picoquic_packet_loop_options_t options = { 0 };
    packet_loop_system_call_duration_t sc_duration = { 0 };

    int is_wake_up_event;
#ifdef _WINDOWS
    WSADATA wsaData = { 0 };
    (void)WSA_START(MAKEWORD(2, 2), &wsaData);
#endif

    if (thread_ctx->thread_name != NULL) {
        thread_ctx->thread_setname_fn(thread_ctx->thread_name);
    }

    if (send_buffer_size == 0) {
        send_buffer_size = 0xffff;
    }

    memset(s_ctx, 0, sizeof(s_ctx));
    if ((nb_sockets = picoquic_packet_loop_open_sockets(param->local_port,
        param->local_af, param->socket_buffer_size,
        param->extra_socket_required, param->do_not_use_gso, s_ctx)) <= 0) {
        ret = PICOQUIC_ERROR_UNEXPECTED_ERROR;
    }
    else if (loop_callback != NULL) {
        struct sockaddr_storage l_addr;
        ret = loop_callback(quic, picoquic_packet_loop_ready, loop_callback_ctx, &options);

        if (picoquic_store_loopback_addr(&l_addr, s_ctx[0].af, s_ctx[0].port) == 0) {
            ret = loop_callback(quic, picoquic_packet_loop_port_update, loop_callback_ctx, &l_addr);
        }
        if (ret == 0 && options.provide_alt_port) {
            uint16_t alt_port = ntohs(s_ctx[1].port);
            ret = loop_callback(quic, picoquic_packet_loop_alt_port, loop_callback_ctx, &alt_port);
        }
    }

    if (ret == 0) {
        nb_sockets_available = nb_sockets;

        if (udp_gso_available && !param->do_not_use_gso) {
            send_buffer_size = 0xFFFF;
            send_msg_ptr = &send_msg_size;
        }
        send_buffer = malloc(send_buffer_size);
        if (send_buffer == NULL) {
            ret = -1;
        }
    }

    if (ret == 0) {
        thread_ctx->thread_is_ready = 1;
    }
    else {
        DBG_PRINTF("%s", "Thread cannot run");
    }

    /* Wait for packets */
    /* TODO: add stopping condition, was && (!just_once || !connection_done) */
    /* Actually, no, rely on the callback return code for that? */
    while (ret == 0 && !thread_ctx->thread_should_close) {
        int socket_rank = -1;
        int64_t delta_t = 0;
        uint8_t received_ecn;
        uint8_t* received_buffer;
        uint64_t previous_time;

        if_index_to = 0;
        /* The "loop immediate" condition is set when a packet has been
        * received and processed successfully. We call select again with
        * a delay set to zero to check whether more packets need to be
        * received, trying to empty the receive queue before sending
        * more packet. However, this code is a bit dangerous, 
        * because it can lead to long series of receiving packets without
        * ever sending responses or ACKs. We moderate that by counting the number
        * of loops in "immediate" mode, and ignoring the "loop
        * immediate" condition if that number reaches a limit */
        current_time = picoquic_current_time();
        if (!loop_immediate) {
            nb_loop_immediate = 1;
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
        }
        else {
            nb_loop_immediate++;
        }
        /* The "loop immediate flag is set by default to zero. It will be
        * set to 1 if a packet has been received and the number of
        * packets received "immediately" does not exceed the limit.
         */
        loop_immediate = 0;
        /* Remember the time before the select call, so it duration be monitored */
        previous_time = current_time;
#ifdef _WINDOWS
        bytes_recv = picoquic_packet_loop_wait(s_ctx, nb_sockets_available,
            &addr_from, &addr_to, &if_index_to, &received_ecn, &received_buffer,
            delta_t, &is_wake_up_event, thread_ctx, &socket_rank);
#else
        bytes_recv = picoquic_packet_loop_select(s_ctx, nb_sockets_available,
            &addr_from,
            &addr_to, &if_index_to, &received_ecn,
            buffer, sizeof(buffer),
            delta_t, &is_wake_up_event, thread_ctx, &socket_rank);
        received_buffer = buffer;
#endif
        current_time = picoquic_current_time();
        if (options.do_system_call_duration && delta_t == 0 &&
            monitor_system_call_duration(&sc_duration, current_time, previous_time)) {
            ret = loop_callback(quic, picoquic_packet_loop_system_call_duration,
                loop_callback_ctx, &sc_duration);
        }

        if (bytes_recv < 0) {
            /* The interrupt error is expected if the loop is closing. */
            ret = (thread_ctx->thread_should_close) ? PICOQUIC_NO_ERROR_TERMINATE_PACKET_LOOP : -1;
        }
        else if (bytes_recv == 0 && is_wake_up_event) {
            ret = loop_callback(quic, picoquic_packet_loop_wake_up, loop_callback_ctx, NULL);
        }
        else {
            uint64_t loop_time = current_time;
            size_t bytes_sent = 0;
            size_t nb_packets_sent = 0;

            if (bytes_recv > 0) {
#ifdef _WINDOWS
                size_t recv_bytes = 0;
                while (recv_bytes < (size_t)bytes_recv && ret == 0) {
                    size_t recv_length = (size_t)(bytes_recv - recv_bytes);

                    if (s_ctx[socket_rank].udp_coalesced_size > 0 &&
                        recv_length > s_ctx[socket_rank].udp_coalesced_size) {
                        recv_length = s_ctx[socket_rank].udp_coalesced_size;
                    }
                    /* Submit the packet to the client */
                    ret = picoquic_incoming_packet_ex(quic, s_ctx[socket_rank].recv_buffer + recv_bytes,
                        recv_length, (struct sockaddr*)&addr_from,
                        (struct sockaddr*)&addr_to,
                        s_ctx[socket_rank].dest_if,
                        s_ctx[socket_rank].received_ecn, &last_cnx, &last_path_id, current_time);
                    recv_bytes += recv_length;
                }
                if (ret == 0) {
                    ret = picoquic_win_recvmsg_async_start(&s_ctx[socket_rank]);
                }
#else
                /* Submit the packet to the server */
                ret = picoquic_incoming_packet_ex(quic, received_buffer,
                    (size_t)bytes_recv, (struct sockaddr*)&addr_from,
                    (struct sockaddr*)&addr_to, if_index_to, received_ecn,
                    &last_cnx, &last_path_id, current_time);
#endif


                if (loop_callback != NULL) {
                    size_t b_recvd = (size_t)bytes_recv;
                    ret = loop_callback(quic, picoquic_packet_loop_after_receive, loop_callback_ctx, &b_recvd);
                }

                /* If the number of packets received in immediate mode has not
                * reached the threshold, set the "immediate" flag and bypass
                * the sending code. 
                 */
                if (ret == 0 && nb_loop_immediate < PICOQUIC_PACKET_LOOP_RECV_MAX) {
                    loop_immediate = 1;
                    continue;
                }
            }

            if (ret == PICOQUIC_NO_ERROR_SIMULATE_NAT) {
                if (param->extra_socket_required) {
                    /* Stop using the extra socket.
                     * This will simulate a NAT:
                     * - on the receive side, packets arriving to the old address will be ignored.
                     * - on the send side, client packets will be sent through the main socket,
                     *   and appear to come from that port instead of the extra port.
                     * - since the CID does not change, the server will execute the NAT behavior.
                     * The client will have to update its path -- but that can be avoided if the
                     * test code overrides the value of the "local" address that the client
                     * memorized for that path.
                     */
                    nb_sockets_available = nb_sockets / 2;
                }
                ret = 0;
            }
            /* We limit the number of packets sent in a loop, no make sure that
            * the code will not spend a lot of time sending packets while
            * packets may be adding in the receive queue.
             */

            while (ret == 0 && nb_packets_sent < PICOQUIC_PACKET_LOOP_SEND_MAX) {
                struct sockaddr_storage peer_addr;
                struct sockaddr_storage local_addr = { 0 };
                int if_index = param->dest_if;
                int sock_ret = 0;
                int sock_err = 0;

                ret = picoquic_prepare_next_packet_ex(quic, loop_time,
                    send_buffer, send_buffer_size, &send_length,
                    &peer_addr, &local_addr, &if_index, &log_cid, &last_cnx,
                    send_msg_ptr);

                if (ret == 0 && send_length > 0) {
                    /* If send_msg_size is defined, sendmsg may send more than one packet.
                     * We compute that to update the number of packets sent in the loop.
                     */
                    nb_packets_sent += (send_msg_size == 0) ? 1 :
                        (send_length + send_msg_size - 1) / (send_msg_size);
                    if (send_length > param->send_length_max) {
                        param->send_length_max = send_length;
                    }
                    /* We have multiple sockets, with support for
                    * either IPv6, or IPv4, or both, and binding to a port number.
                    * Find the first socket where:
                    * - the destination AF is supported.
                    * - either the source port is not specified, or it matches the local port.
                    */
                    SOCKET_TYPE send_socket = INVALID_SOCKET;
                    uint16_t send_port = (peer_addr.ss_family == AF_INET) ?
                        ((struct sockaddr_in*)&local_addr)->sin_port :
                        ((struct sockaddr_in6*)&local_addr)->sin6_port;

                    bytes_sent += send_length;

                    /* TODO: verify htons/ntohs */
                    for (int i = 0; i < nb_sockets_available; i++) {
                        if (s_ctx[i].af == peer_addr.ss_family) {
                            send_socket = s_ctx[i].fd;
                            if (send_port != 0 && htons(s_ctx[i].port) == send_port)
                                break;
                        }
                    }

                    if (send_socket == INVALID_SOCKET) {
                        sock_ret = -1;
                        sock_err = -1;
                    }
                    else if (param->simulate_eio && send_length > PICOQUIC_MAX_PACKET_SIZE) {
                        /* Test hook, simulating a driver that does not support GSO */
                        sock_ret = -1;
                        sock_err = EIO;
                        param->simulate_eio = 0;
                    }
                    else {
                        sock_ret = picoquic_sendmsg(send_socket,
                            (struct sockaddr*)&peer_addr, (struct sockaddr*)&local_addr, if_index,
                            (const char*)send_buffer, (int)send_length, (int)send_msg_size, &sock_err);
                    }

                    if (sock_ret <= 0) {
                        /* TODO: add a test in which the socket fails. */
                        if (last_cnx == NULL) {
                            picoquic_log_context_free_app_message(quic, &log_cid, "Could not send message to AF_to=%d, AF_from=%d, if=%d, ret=%d, err=%d",
                                peer_addr.ss_family, local_addr.ss_family, if_index, sock_ret, sock_err);
                        }
                        else {
                            picoquic_log_app_message(last_cnx, "Could not send message to AF_to=%d, AF_from=%d, if=%d, ret=%d, err=%d",
                                peer_addr.ss_family, local_addr.ss_family, if_index, sock_ret, sock_err);

                            if (picoquic_socket_error_implies_unreachable(sock_err)) {
                                picoquic_notify_destination_unreachable(last_cnx, current_time,
                                    (struct sockaddr*)&peer_addr, (struct sockaddr*)&local_addr, if_index,
                                    sock_err);
                            }
                            else if (sock_err == EIO) {
                                /* TODO: this is an error encountered if the system supports GSO, but
                                 * the specific interface driver does not. Main example is Mininet.
                                 * Not sure that we can treat that correctly. Try to minimize the
                                 * amount of untested code? Rely on config flag? Rely on error
                                 * recovery? */
                                size_t packet_index = 0;
                                size_t packet_size = send_msg_size;

                                while (packet_index < send_length) {
                                    if (packet_index + packet_size > send_length) {
                                        packet_size = send_length - packet_index;
                                    }
                                    sock_ret = picoquic_sendmsg(send_socket,
                                        (struct sockaddr*)&peer_addr, (struct sockaddr*)&local_addr, if_index,
                                        (const char*)(send_buffer + packet_index), (int)packet_size, 0, &sock_err);
                                    if (sock_ret > 0) {
                                        packet_index += packet_size;
                                    }
                                    else {
                                        picoquic_log_app_message(last_cnx, "Retry with packet size=%zu fails at index %zu, ret=%d, err=%d.",
                                            packet_size, packet_index, sock_ret, sock_err);
                                        break;
                                    }
                                }
                                if (sock_ret > 0) {
                                    picoquic_log_app_message(last_cnx, "Retry of %zu bytes by chunks of %zu bytes succeeds.",
                                        send_length, send_msg_size);
                                }
                                if (send_msg_ptr != NULL) {
                                    /* Make sure that we do not use GSO anymore in this run */
                                    send_msg_ptr = NULL;
                                    picoquic_log_app_message(last_cnx, "%s", "UDP GSO was disabled");
                                }
                            }
                        }
                    }
                }
                else {
                    break;
                }
            }

            if (ret == 0 && loop_callback != NULL) {
                ret = loop_callback(quic, picoquic_packet_loop_after_send, loop_callback_ctx, &bytes_sent);
            }
        }
    }

    thread_ctx->thread_is_ready = 0;

    if (ret == PICOQUIC_NO_ERROR_TERMINATE_PACKET_LOOP) {
        /* Normal termination requested by the application, returns no error */
        ret = 0;
    }

    /* Close the sockets */
    for (int i = 0; i < nb_sockets; i++) {
        picoquic_packet_loop_close_socket(&s_ctx[i]);
    }

    if (send_buffer != NULL) {
        free(send_buffer);
    }
    thread_ctx->return_code = ret;
#ifdef _WINDOWS
    return (DWORD)ret;
#else
    if (thread_ctx->is_threaded) {
        pthread_exit((void*)&thread_ctx->return_code);
    }
    return(NULL);
#endif
}

int picoquic_packet_loop_v2(picoquic_quic_t* quic,
    picoquic_packet_loop_param_t* param,
    picoquic_packet_loop_cb_fn loop_callback,
    void* loop_callback_ctx)
{
    picoquic_network_thread_ctx_t thread_ctx = { 0 };

    thread_ctx.quic = quic;
    thread_ctx.param = param;
    thread_ctx.loop_callback = loop_callback;
    thread_ctx.loop_callback_ctx = loop_callback_ctx;

    (void)picoquic_packet_loop_v3((void*)&thread_ctx);
    return thread_ctx.return_code;
}

/* Support for legacy API */

int picoquic_packet_loop(picoquic_quic_t* quic,
    int local_port,
    int local_af,
    int dest_if,
    int socket_buffer_size,
    int do_not_use_gso,
    picoquic_packet_loop_cb_fn loop_callback,
    void* loop_callback_ctx)
{
    picoquic_packet_loop_param_t param = { 0 };

    param.local_port = (uint16_t)local_port;
    param.local_af = local_af;
    param.dest_if = dest_if;
    param.socket_buffer_size = socket_buffer_size;
    param.do_not_use_gso = do_not_use_gso;

    return picoquic_packet_loop_v2(quic, &param, loop_callback, loop_callback_ctx);
}

/* Management of background thread. */

static void picoquic_close_network_wake_up(picoquic_network_thread_ctx_t* thread_ctx)
{
    if (thread_ctx->wake_up_defined) {
#ifdef _WINDOWS
        CloseHandle(thread_ctx->wake_up_event);
#else
        for (int i = 0; i < 2; i++) {
            (void)close(thread_ctx->wake_up_pipe_fd[i]);
        }
#endif
        thread_ctx->wake_up_defined = 0;
    }
}

void picoquic_open_network_wake_up(picoquic_network_thread_ctx_t* thread_ctx, int *ret)
{
    thread_ctx->wake_up_defined = 0;
#ifdef _WINDOWS
    thread_ctx->wake_up_event = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (thread_ctx->wake_up_event == NULL) {
        *ret = GetLastError();
    }
    else {
        thread_ctx->wake_up_defined = 1;
    }
#else
    if (pipe(thread_ctx->wake_up_pipe_fd) != 0) {
        *ret = errno;
    }
    else
    {
        thread_ctx->wake_up_defined = 1;
    }
#endif
}

int picoquic_internal_thread_create(void** thread_id, picoquic_thread_fn thread_fn, void* thread_arg)
{
    int ret = picoquic_create_thread((picoquic_thread_t*)thread_id, thread_fn, thread_arg);
    return ret;
}

void picoquic_internal_thread_setname(char const * thread_name)
{
#ifdef _WINDOWS
    wchar_t wname[257];
    wname[0] = 0;

    if (swprintf(wname, 256, L"%S", thread_name) < 0) {
        DBG_PRINTF("Cannot convert thread name <%s> to wchar[256], err: 0x%x",
            thread_name, GetLastError());
    }
    else {
        HRESULT r = SetThreadDescription(GetCurrentThread(), wname);
        if (r != 0) {
            DBG_PRINTF("Set thread name <%S> returns: 0x%x", wname, r);
        }
    }
#else
#ifdef __APPLE__
    pthread_setname_np(thread_name);
#else
    int r=prctl(PR_SET_NAME, thread_name, 0, 0, 0);
    if (r != 0) {
        DBG_PRINTF("Set thread name <%s> returns: 0x%x", thread_name, r);
    }
#endif
#endif
}

void picoquic_internal_thread_delete(void** v_thread_id)
{
    picoquic_delete_thread((picoquic_thread_t *)v_thread_id);
}

picoquic_network_thread_ctx_t* picoquic_start_custom_network_thread(picoquic_quic_t* quic, picoquic_packet_loop_param_t* param,
    picoquic_custom_thread_create_fn thread_create_fn, picoquic_custom_thread_delete_fn thread_delete_fn,
    picoquic_custom_thread_setname_fn thread_setname_fn, char const* thread_name,
    picoquic_packet_loop_cb_fn loop_callback, void* loop_callback_ctx, int* ret)
{
    picoquic_network_thread_ctx_t* thread_ctx = (picoquic_network_thread_ctx_t*)malloc(sizeof(picoquic_network_thread_ctx_t));
    *ret = 0;

    if (thread_ctx == NULL) {
        /* Error, no memory */
    }
    else {
        memset(thread_ctx, 0, sizeof(picoquic_network_thread_ctx_t));
        /* Fill the arguments in the context */
        thread_ctx->quic = quic;
        thread_ctx->param = param;
        thread_ctx->loop_callback = loop_callback;
        thread_ctx->loop_callback_ctx = loop_callback_ctx;
        /* Open the wake up pipe or event */
        picoquic_open_network_wake_up(thread_ctx, ret);
        /* Start thread at specified entry point */
        if (thread_ctx->wake_up_defined){
            thread_ctx->is_threaded = 1;
            if (thread_create_fn == NULL) {
                thread_create_fn = picoquic_internal_thread_create;
            }
            if ((thread_ctx->thread_setname_fn = thread_setname_fn) == NULL) {
                thread_ctx->thread_setname_fn = picoquic_internal_thread_setname;
            }
            if ((thread_ctx->thread_delete_fn = thread_delete_fn) == NULL) {
                thread_ctx->thread_delete_fn = picoquic_internal_thread_delete;
            }
            thread_ctx->thread_name = thread_name;
            if ((*ret = thread_create_fn((void **)&thread_ctx->pthread, picoquic_packet_loop_v3, (void*)thread_ctx)) != 0) {
                /* Free the context and return error condition if something went wrong */
                thread_ctx->is_threaded = 0;
                picoquic_delete_network_thread(thread_ctx);
                thread_ctx = NULL;
            }
        }
    }
    return thread_ctx;
}

picoquic_network_thread_ctx_t* picoquic_start_network_thread(picoquic_quic_t* quic,
    picoquic_packet_loop_param_t* param, picoquic_packet_loop_cb_fn loop_callback, void* loop_callback_ctx, int* ret)
{
    return picoquic_start_custom_network_thread(quic, param, NULL, NULL, NULL, NULL, loop_callback, loop_callback_ctx, ret);
}

int picoquic_wake_up_network_thread(picoquic_network_thread_ctx_t* thread_ctx)
{
    int ret = 0;

    if (thread_ctx->wake_up_defined) {
#ifdef _WINDOWS
        if (SetEvent(thread_ctx->wake_up_event) == 0) {
            DWORD err = WSAGetLastError();
            DBG_PRINTF("Set network event fails, error 0x%x", err);
            ret = (int)err;
        }
#else
        /* TODO: write to network pipe */
        ssize_t written = 0;
        if ((written = write(thread_ctx->wake_up_pipe_fd[1], &ret, 1)) != 1) {
            if (written == 0) {
                ret = EPIPE;
            }
            else {
                ret = errno;
            }
        }
#endif
    }
    else {
        DBG_PRINTF("%s", "Wake up event not defined.");
        ret = -1;
    }
    return ret;
}

void picoquic_delete_network_thread(picoquic_network_thread_ctx_t* thread_ctx)
{
    /* set the should_close flag, so the thread knows the loop should stop */
    thread_ctx->thread_should_close = 1;
    /* Delete the wake up event. This ought to create a fault 
     * in the wait for event call, causing the thread to wake up,
     * notice the flag, and exit.
     */
    picoquic_close_network_wake_up(thread_ctx);
    /* delete the thread */
    if (thread_ctx->is_threaded) {
        thread_ctx->thread_delete_fn((void**)&thread_ctx->pthread);
    }
    /* Free the context */
    free(thread_ctx);
}