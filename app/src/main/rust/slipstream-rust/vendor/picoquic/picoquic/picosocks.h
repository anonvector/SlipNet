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

#ifndef PICOSOCKS_H
#define PICOSOCKS_H

#ifdef _WINDOWS
/* clang-format off */
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <Ws2def.h>
#include <WinSock2.h>
#include <ws2ipdef.h>
#include <Mswsock.h>
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
#ifndef WSA_START_DATA
#define WSA_START_DATA WSADATA
#endif
#ifndef WSA_START
#define WSA_START(x, y) WSAStartup((x), (y))
#endif
#ifndef WSA_LAST_ERROR
#define WSA_LAST_ERROR(x) WSAGetLastError()
#endif
#ifndef socklen_t
#define socklen_t int
#endif
/* clang-format on */
#else /* Linux, FreeBSD */

#include "getopt.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#ifndef SOL_IPV6 /* required on FreeBSD */
#define SOL_IPV6 IPPROTO_IPV6
#endif

#ifndef __USE_XOPEN2K
#define __USE_XOPEN2K
#endif
#ifndef __USE_POSIX
#define __USE_POSIX
#endif
#ifndef __USE_GNU
#define __USE_GNU
#endif
#ifndef __APPLE_USE_RFC_3542
#define __APPLE_USE_RFC_3542 /* IPV6_PKTINFO */
#endif

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <sys/select.h>

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
#ifndef IPV6_RECVPKTINFO
#define IPV6_RECVPKTINFO IPV6_PKTINFO /* Cygwin */
#endif
#endif

#define PICOQUIC_ECN_ECT_0 0x02
#define PICOQUIC_ECN_ECT_1 0x01
#define PICOQUIC_ECN_CE 0x03

#include "picoquic.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifdef _WINDOWS
typedef struct st_picoquic_recvmsg_async_ctx_t {
    WSAOVERLAPPED overlap;
    LPFN_WSARECVMSG WSARecvMsg;
    LPFN_WSASENDMSG WSASendMsg;
    WSABUF dataBuf;
    WSAMSG msg;
    char cmsg_buffer[1024];
    size_t recv_buffer_size;
    uint8_t* recv_buffer;
    struct sockaddr_storage addr_from;
    struct sockaddr_storage addr_dest;
    socklen_t from_length;
    socklen_t dest_length;
    SOCKET_TYPE fd;
    int dest_if;
    unsigned char received_ecn;
    size_t udp_coalesced_size;
    int nb_immediate_receive;
    int bytes_recv;
    int so_sndbuf;
    int so_rcvbuf;
    unsigned int is_started : 1;
    unsigned int supports_udp_send_coalesced : 1;
    unsigned int supports_udp_recv_coalesced : 1;
} picoquic_recvmsg_async_ctx_t;

//
// Not yet available in the SDK. When available this code can be removed.
//
#ifndef UDP_SEND_MSG_SIZE
#define UDP_SEND_MSG_SIZE           2
#endif
#ifndef UDP_RECV_MAX_COALESCED_SIZE
#define UDP_RECV_MAX_COALESCED_SIZE 3
#endif
#ifndef UDP_COALESCED_INFO
#define UDP_COALESCED_INFO          3
#endif

picoquic_recvmsg_async_ctx_t * picoquic_create_async_socket(int af, int recv_coalesced, int send_coalesced);
void picoquic_delete_async_socket(picoquic_recvmsg_async_ctx_t * ctx);
int picoquic_recvmsg_async_start(picoquic_recvmsg_async_ctx_t * ctx); 
int picoquic_recvmsg_async_finish(picoquic_recvmsg_async_ctx_t * ctx);

#endif

#define PICOQUIC_NB_SERVER_SOCKETS 2

typedef struct st_picoquic_server_sockets_t {
    SOCKET_TYPE s_socket[PICOQUIC_NB_SERVER_SOCKETS];
} picoquic_server_sockets_t;

int picoquic_bind_to_port(SOCKET_TYPE fd, int af, int port);

int picoquic_get_local_address(SOCKET_TYPE sd, struct sockaddr_storage * addr);

SOCKET_TYPE picoquic_open_client_socket(int af);

int picoquic_open_server_sockets(picoquic_server_sockets_t* sockets, int port);

void picoquic_close_server_sockets(picoquic_server_sockets_t* sockets);

int picoquic_socket_set_pkt_info(SOCKET_TYPE sd, int af);
int picoquic_socket_set_ecn_options(SOCKET_TYPE sd, int af, int * recv_set, int * send_set);
int picoquic_socket_set_pmtud_options(SOCKET_TYPE sd, int af);

int picoquic_select(SOCKET_TYPE* sockets, int nb_sockets,
    struct sockaddr_storage* addr_from,
    struct sockaddr_storage* addr_dest,
    int* dest_if,
    unsigned char * received_ecn,
    uint8_t* buffer, int buffer_max,
    int64_t delta_t,
    uint64_t* current_time);

int picoquic_select_ex(SOCKET_TYPE* sockets,
    int nb_sockets,
    struct sockaddr_storage* addr_from,
    struct sockaddr_storage* addr_dest,
    int* dest_if,
    unsigned char* received_ecn,
    uint8_t* buffer, int buffer_max,
    int64_t delta_t,
    int* socket_rank,
    uint64_t* current_time);

int picoquic_recvmsg(SOCKET_TYPE fd,
    struct sockaddr_storage* addr_from,
    struct sockaddr_storage* addr_dest,
    int* dest_if,
    unsigned char* received_ecn,
    uint8_t* buffer, int buffer_max);

int picoquic_sendmsg(SOCKET_TYPE fd,
    struct sockaddr* addr_dest,
    struct sockaddr* addr_from,
    int dest_if,
    const char* bytes, int length,
    int send_msg_size, int * sock_err);

int picoquic_send_through_socket(
    SOCKET_TYPE fd,
    struct sockaddr* addr_dest,
    struct sockaddr* addr_from, int from_if,
    const char* bytes, int length, int* sock_err);

int picoquic_send_through_server_sockets(
    picoquic_server_sockets_t* sockets,
    struct sockaddr* addr_dest, 
    struct sockaddr* addr_from, int from_if,
    const char* bytes, int length, int * sock_err);

int picoquic_get_server_address(const char* ip_address_text, int server_port,
    struct sockaddr_storage* server_address,
    int* is_name);

/* Wireshark needs the session keys in order to decrypt and analyze packets.
 * In Unix and Windows, Wireshark reads these keys from a file. The name
 * of the file is passed in the environment variable SSLKEYLOGFILE,
 * which is accessed through system dependent API.
 */
void picoquic_set_key_log_file_from_env(picoquic_quic_t* quic);

/* Some socket errors, but not all, indicate that a destination is
 * unreachable and that the corresponding "path" should be abandoned.
 */
int picoquic_socket_error_implies_unreachable(int sock_err);

/* Utility functions for implementing async sockets
 */

void picoquic_socks_cmsg_parse(
    void* vmsg,
    struct sockaddr_storage* addr_dest,
    int* dest_if,
    unsigned char* received_ecn,
    size_t* udp_coalesced_size);

void picoquic_socks_cmsg_format(
    void* vmsg,
    size_t message_length,
    size_t send_msg_size,
    struct sockaddr* addr_from,
    int dest_if);

#ifdef __cplusplus
}
#endif
#endif
