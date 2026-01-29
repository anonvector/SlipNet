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
#include <stdlib.h>
#ifdef _WINDOWS
#include <malloc.h>
#endif
#include <string.h>

/* 
 * Cnx creation unit test
 * - Create QUIC context
 * - Create a set of connections, with variations:
 * - IPv4 or IPv6 address
 * - Different ports
 * - either no connection ID or a connection ID.
 *
 *  - Verify that all these connections can be retrieved using their
 *    registered attributes.
 *  - Verify that a non registered connection can be retrieved.
 *
 *  - Delete connections first-middle-last.
 *  - Verify that deleted connections cannot be retrieved, and the others can.
 *
 *  - delete QUIC context.
 */

#define TEST_CNX_COUNT 7
#define TEST_CNX_ID(x) {{ x, x, x, x, x, x, x, x, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0} , 8 }

int create_cnx_test()
{
    int ret = 0;
    picoquic_quic_t* quic = NULL;
    picoquic_cnx_t* test_cnx[TEST_CNX_COUNT] = { NULL, NULL, NULL, NULL, NULL, NULL, NULL };
    struct sockaddr_in test4[5];
    struct sockaddr_in6 test6[3];
    const uint8_t test_ipv4[4] = { 192, 0, 2, 0 };
    const uint8_t test_ipv6[16] = { 0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01 };
    const uint8_t test_ipv4l[4] = { 127, 0, 0, 1 };
    const uint8_t test_ipv6l[16] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01 };
    picoquic_connection_id_t test_cid[TEST_CNX_COUNT];

    const picoquic_connection_id_t test_cnx_id[TEST_CNX_COUNT] = {
        TEST_CNX_ID(1), TEST_CNX_ID(2), TEST_CNX_ID(3), TEST_CNX_ID(4),
        TEST_CNX_ID(5), TEST_CNX_ID(6), TEST_CNX_ID(7) };

    struct sockaddr* test_cnx_addr[TEST_CNX_COUNT] = {
        (struct sockaddr*)&test4[0],
        (struct sockaddr*)&test4[1],
        (struct sockaddr*)&test4[2],
        (struct sockaddr*)&test4[4],
        (struct sockaddr*)&test6[0],
        (struct sockaddr*)&test6[1],
        (struct sockaddr*)&test6[2]
    };

    /*
     * Initialize the sockaddr values
     */
    for (int i = 0; i < 5; i++) {
        uint8_t* addr = (uint8_t*)&test4[i].sin_addr;
        memset(&test4[i], 0, sizeof(test4[i]));
        test4[i].sin_family = AF_INET;
        if (i < 4) {
            addr[0] = test_ipv4[0];
            addr[1] = test_ipv4[1];
            addr[2] = test_ipv4[2];
            addr[3] = (i == 0) ? 1 : 2;
        }
        else {
            addr[0] = test_ipv4l[0];
            addr[1] = test_ipv4l[1];
            addr[2] = test_ipv4l[2];
            addr[3] = test_ipv4l[3];
        }
        test4[i].sin_port = 1000 + i;
    }

    for (int i = 0; i < 3; i++) {
        uint8_t* addr = (uint8_t*)&test6[i].sin6_addr;
        memset(&test6[i], 0, sizeof(test6[i]));
        test6[i].sin6_family = AF_INET6;
        for (int j = 0; j < 16; j++) {
            if (i < 2) {
                addr[j] = test_ipv6[j];
            }
            else {
                addr[j] = test_ipv6l[j];
            }
        }
        if (i < 2) {
            addr[15] = i + 1;
        }
        test6[i].sin6_port = 1000 + i;
    }

    for (int l = 0; ret == 0 && l < 2; l++) {
        /* Create QUIC context */
        quic = picoquic_create(8, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 0, NULL, NULL, NULL, 0);
        if (quic == NULL) {
            ret = -1;
        }
        else if (l == 0) {
            quic->local_cnxid_length = 0;
        }
        /*
        * Create a set of connections, with variations :
        * -IPv4 or IPv6 address
        * -Different ports
        * -either no connection ID or a connection ID.
        */

        for (int i = 0; ret == 0 && i < TEST_CNX_COUNT; i++) {
            test_cnx[i] = picoquic_create_cnx(quic,
                (quic->local_cnxid_length == 0) ? picoquic_null_connection_id : test_cnx_id[i],
                picoquic_null_connection_id, test_cnx_addr[i], 0, 0, NULL, NULL, 1);
            if (test_cnx[i] == NULL) {
                ret = -1;
            }
            else {
                test_cid[i] = test_cnx[i]->path[0]->p_local_cnxid->cnx_id;
            }
        }

        /*
         *  -Verify that all these connections can be retrieved using their
         *    registered attributes.
         */
        if (quic->local_cnxid_length == 0) {
            for (int i = 0; ret == 0 && i < TEST_CNX_COUNT; i++) {
                picoquic_cnx_t* cnx = picoquic_cnx_by_net(quic, test_cnx_addr[i]);

                if (cnx == NULL) {
                    ret = -1;
                }
            }
        }

        /*
         * Verify that the iterator returns all connections.
         */
        if (ret == 0) {
            int counter = 0;
            for (picoquic_cnx_t* cnx = picoquic_get_first_cnx(quic); cnx != NULL; cnx = picoquic_get_next_cnx(cnx)) {
                counter += 1;
            }

            if (counter != TEST_CNX_COUNT) {
                ret = -1;
            }
        }

        /* TODO: cannot retrieve connections by initial ID yet, should work on it */
        /*
        *  -Verify that a non registered connection cannot be retrieved.
        */

        if (ret == 0) {
            if (quic->local_cnxid_length == 0) {
                picoquic_cnx_t* cnx = picoquic_cnx_by_net(quic, (struct sockaddr*)&test4[3]);
                if (cnx != NULL) {
                    ret = -1;
                }
            }
            else {
                picoquic_connection_id_t bad_target = { { 1,2,3,4,5,6,7,8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, 8 };
                picoquic_cnx_t* cnx = picoquic_cnx_by_id(quic, bad_target, NULL);
                if (cnx != NULL) {
                    ret = -1;
                }
            }
        }


        /* Delete connections first - middle - last. */
        for (int i = 0; ret == 0 && i < TEST_CNX_COUNT; i += 2) {
            picoquic_delete_cnx(test_cnx[i]);
            test_cnx[i] = NULL;
        }

        /* Verify that deleted connections cannot be retrieved, and the others can. */
        if (quic->local_cnxid_length == 0) {
            for (int i = 0; ret == 0 && i < TEST_CNX_COUNT; i++) {
                picoquic_cnx_t* cnx = picoquic_cnx_by_net(quic, test_cnx_addr[i]);

                if (cnx != NULL && (i & 1) == 0) {
                    ret = -1;
                }
                else if (cnx == NULL && (i & 1) != 0) {
                    ret = -1;
                }
            }
        }
        else {
            for (int i = 0; ret == 0 && i < TEST_CNX_COUNT; i++) {
                picoquic_cnx_t* cnx = picoquic_cnx_by_id(quic, test_cid[i], NULL);

                if (cnx != NULL && (i & 1) == 0) {
                    ret = -1;
                }
                else if (cnx == NULL && (i & 1) != 0) {
                    ret = -1;
                }
            }
        }

        /* delete QUIC context. */
        if (quic != NULL) {
            picoquic_free(quic);
        }
    }

    return ret;
}

int create_quic_test()
{
    int ret = 0;
    char const* bad_dir = "..";
    char const* bad_file = "no_such_file_should_exist.pem";
    picoquic_quic_t* quic = NULL;

    /* Check that 0 connection == 1 */
    if (ret == 0) {
        quic = picoquic_create(0, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 0, NULL, NULL, NULL, 0);
        if (quic == NULL || quic->max_number_connections != 1) {
            ret = -1;
        }
        picoquic_free(quic);
        quic = NULL;
    }

    /* Check that bad context, bad key or bad store crashes connection */
    if (ret == 0) {
        char test_server_cert_file[512];
        char test_server_key_file[512];

        ret = picoquic_get_input_path(test_server_cert_file, sizeof(test_server_cert_file), picoquic_solution_dir,
            PICOQUIC_TEST_FILE_SERVER_CERT);

        if (ret == 0) {
            ret = picoquic_get_input_path(test_server_key_file, sizeof(test_server_key_file), picoquic_solution_dir,
                PICOQUIC_TEST_FILE_SERVER_KEY);
        }

        if (ret == 0) {
            if ((quic = picoquic_create(8, bad_file, test_server_key_file, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 0, NULL, NULL, NULL, 0)) != NULL ||
                (quic = picoquic_create(8, test_server_cert_file, bad_file, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 0, NULL, NULL, NULL, 0)) != NULL) {
                ret = -1;
                picoquic_free(quic);
                quic = NULL;
            }
        }
    }

    /* Check that bad ticket store does not crash a client connection */
    if (ret == 0) {
        if ((quic = picoquic_create(0, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 0, NULL, bad_file, NULL, 0)) == NULL) {
            ret = -1;
        }
        else {
            picoquic_free(quic);
            if ((quic = picoquic_create(0, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 0, NULL, bad_dir, NULL, 0)) == NULL) {
                ret = -1;
            }
            else {
                picoquic_free(quic);
                quic = NULL;
            }
        }
    }

    /* Check loading of token file (always work) and not a valid file name (always fail).
    * However, this test is not very portable, because reading a bad directory only
    * fails on Windows.
     */
    if (ret == 0) {
        if ((quic = picoquic_create(8, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 0, NULL, NULL, NULL, 0)) == NULL) {
            ret = -1;
        }
        else
        {
            int rbf = 0;
            int rbd = 0;
            if ((rbf = picoquic_load_token_file(quic, bad_file)) != 0 &&
                (rbd = picoquic_load_token_file(quic, bad_dir)) == 0) {
                ret = -1;
            }
            DBG_PRINTF("Load token %s %s",
                bad_file, (rbf == 0) ? "Succeeds" : "Fails");
            DBG_PRINTF("Load token %s %s",
                bad_dir, (rbd == 0) ? "Succeeds" : "Fails");
            picoquic_free(quic);
            quic = NULL;
        }
    }

    /* Check that loading a NULL TP loads the default */
    if (ret == 0) {
        if ((quic = picoquic_create(8, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 0, NULL, NULL, NULL, 0)) == NULL) {
            ret = -1;
        }
        else
        {
            if (picoquic_set_default_tp(quic, NULL) != 0) {
                ret = -1;
            }
            picoquic_free(quic);
            quic = NULL;
        }
    }

    return ret;
}