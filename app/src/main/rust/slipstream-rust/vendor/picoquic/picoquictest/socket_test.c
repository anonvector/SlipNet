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

#include "picosocks.h"
#include "picoquic_utils.h"

static int socket_ping_pong(SOCKET_TYPE fd, struct sockaddr* server_addr,
    picoquic_server_sockets_t* server_sockets)
{
    int ret = 0;
    uint64_t current_time = picoquic_current_time();
    uint8_t message[1440];
    uint8_t buffer[1536];
    int bytes_sent = 0;
    int bytes_recv = 0;
    struct sockaddr_storage addr_from;
    struct sockaddr_storage addr_dest;
    int dest_if = 0;
    struct sockaddr_storage addr_back;
    int server_address_length = (server_addr->sa_family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);

    for (size_t i = 0; i < sizeof(message);) {
        for (int j = 0; j < 64 && i < sizeof(message); j += 8, i++) {
            message[i++] = (uint8_t)(current_time >> j);
        }
    }

    /* send from client to sever address */
    bytes_sent = sendto(fd, (const char*)&message, sizeof(message), 0, server_addr, server_address_length);

    if (bytes_sent != (int)sizeof(message)) {
        DBG_PRINTF("Sendto sent %d bytes, expected %d\n", bytes_sent, (int)sizeof(message));
        ret = -1;
    }

    /* perform select at server */
    if (ret == 0) {
        unsigned char received_ecn;
        memset(buffer, 0, sizeof(buffer));

        bytes_recv = picoquic_select(server_sockets->s_socket, PICOQUIC_NB_SERVER_SOCKETS,
            &addr_from, &addr_dest, &dest_if, &received_ecn,
            buffer, sizeof(buffer), 1000000, &current_time);

        if (bytes_recv != bytes_sent) {
            DBG_PRINTF("Select returns %d bytes, expected %d\n", bytes_recv, bytes_sent);
            ret = -1;
        }
    }

    /* Convert message using XOR  and send to address from which the message was received */
    if (ret == 0) {
        int sock_err = 0;
        for (int i = 0; i < bytes_recv; i++) {
            buffer[i] ^= 0xFF;
        }

        if (picoquic_send_through_server_sockets(server_sockets,
                (struct sockaddr*)&addr_from,
                (struct sockaddr*)&addr_dest, dest_if,
                (char*)buffer, bytes_recv, &sock_err)
            != bytes_recv) {
            DBG_PRINTF("Send_through_server_sockets return %d, err %d", ret, sock_err);
            ret = -1;
        }
    }

    /* perform select at client */
    if (ret == 0) {
        unsigned char received_ecn;
        memset(buffer, 0, sizeof(buffer));

        bytes_recv = picoquic_select(&fd, 1,
            &addr_back, NULL, NULL, &received_ecn,
            buffer, sizeof(buffer), 1000000, &current_time);

        if (bytes_recv != bytes_sent) {
            DBG_PRINTF("Second select returns %d bytes, expected %d\n", bytes_recv, bytes_sent);
            ret = -1;
        } else {
            /* Check that the message matches what was sent initially */

            for (int i = 0; ret == 0 && i < bytes_recv; i++) {
                if (message[i] != (buffer[i] ^ 0xFF)) {
                    DBG_PRINTF("Second select, message mismatch at position %d\n", i);
                    ret = -1;
                }
            }

            DBG_PRINTF("Received ecn: %x\n", received_ecn);
        }
    }

    return ret;
}

static int socket_test_one(char const* addr_text, int server_port, int should_be_name,
    picoquic_server_sockets_t* server_sockets)
{
    int ret = 0;
    struct sockaddr_storage server_address;
    int is_name;
    SOCKET_TYPE fd = INVALID_SOCKET;

    /* Resolve the server address -- check the "is_name" property */
    ret = picoquic_get_server_address(addr_text, server_port, &server_address, &is_name);

    if (ret == 0) {
        if (is_name != should_be_name) {
            ret = -1;
        } else {
            fd = socket(server_address.ss_family, SOCK_DGRAM, IPPROTO_UDP);
            if (fd == INVALID_SOCKET) {
                ret = -1;
            } else {
                ret = socket_ping_pong(fd, (struct sockaddr*)&server_address, server_sockets);
            }

            SOCKET_CLOSE(fd);
        }
    }

    return ret;
}

int socket_test_port(picoquic_server_sockets_t* server_sockets, int test_port)
{
    int ret = 0;

    /* For a series of server addresses, do a ping pong test */
    if (socket_test_one("127.0.0.1", test_port, 0, server_sockets) != 0) {
        ret = -1;
    }
    else if (socket_test_one("::1", test_port, 0, server_sockets) != 0) {
        ret = -1;
    }
    else if (socket_test_one("localhost", test_port, 1, server_sockets) != 0) {
        ret = -1;
    }

    return ret;
}

int socket_test()
{
    int ret = 0;
    int test_port = 12345;
    int test_port2 = 1234;

    /* Open server sockets */
    picoquic_server_sockets_t server_sockets;
    ret = picoquic_open_server_sockets(&server_sockets, test_port);

    if (ret == 0) {

        /* Test with one server socket */
        ret = socket_test_port(&server_sockets, test_port);

        if (ret == 0) {
            /* Test with two server sockets */
            picoquic_server_sockets_t server_sockets2;
            ret = picoquic_open_server_sockets(&server_sockets2, test_port2);

            if (ret == 0) {
                ret = socket_test_port(&server_sockets2, test_port2);
                picoquic_close_server_sockets(&server_sockets2);
            }
        }

        /* Close the sockets */
        picoquic_close_server_sockets(&server_sockets);
    }

    return ret;
}

/*
 * Test whether ECN values can be set.
 */

int socket_ecn_test_one(int af_domain)
{
    int ret = 0;
    SOCKET_TYPE fd = picoquic_open_client_socket(af_domain);

    if (fd == INVALID_SOCKET) {
        ret = -1;
    }
    else {
        int recv_set = 0;
        int send_set = 0;

        ret = picoquic_socket_set_ecn_options(fd, af_domain, &recv_set, &send_set);

        if (ret != 0) {
            DBG_PRINTF("Cannot set ECN options, af = %d, ret = %d\n", af_domain, ret);
        } else if (!recv_set) {
            DBG_PRINTF("Cannot receive ECN flags, af = %d\n", af_domain);
            ret = -1;
        } else if (!send_set){
            DBG_PRINTF("Cannot send ECN 0, af = %d\n", af_domain);
#ifndef _WINDOWS
            ret = -1;
#endif
        }

        SOCKET_CLOSE(fd);
    }

    return ret;
}

int socket_ecn_test()
{
    int ret;

    ret = socket_ecn_test_one(AF_INET);

    if (ret == 0) {
        ret = socket_ecn_test_one(AF_INET6);
    }

    return ret;
}
