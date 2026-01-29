/*
* Author: Christian Huitema
* Copyright (c) 2021, Private Octopus, Inc.
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
#include "picoquic_utils.h"
#include "tls_api.h"
#include "picoquictest_internal.h"
#ifdef _WINDOWS
#include "wincompat.h"
#endif
#include <picotls.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "picoquic_binlog.h"
#include "csv.h"
#include "qlog.h"
#include "autoqlog.h"
#include "picoquic_logger.h"
#include "performance_log.h"
#include "picoquictest.h"

/* Verify that server certificates are properly verified by the client.
 * test parameters:
 * - server name (SNI)
 * - server key file
 * - server cert file
 * - client side root certificate file
 * - result expectation, i.e., success or failure.
 */
static const uint8_t verifier_encrypt_key[32] = {
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31
};

int cert_verify_set_ctx(picoquic_test_tls_api_ctx_t** pctx, uint64_t * p_simulated_time,
    char const* key_file, char const* cert_file, char const* root_certs_file, char const * sni)
{
    int ret = 0;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    char full_key_file_buf[512];
    char full_cert_file_buf[512];
    char full_root_certs_file_buf[512];
    char* full_key_file = NULL;
    char* full_cert_file = NULL;
    char* full_root_certs_file= NULL;

    /* Rebase the file names according to the current location */
    if (ret == 0 && key_file != NULL) {
        ret = picoquic_get_input_path(full_key_file_buf, sizeof(full_key_file_buf), picoquic_solution_dir,
            key_file);
        full_key_file = full_key_file_buf;
    }
    if (ret == 0 && cert_file != NULL) {
        ret = picoquic_get_input_path(full_cert_file_buf, sizeof(full_cert_file_buf), picoquic_solution_dir,
            cert_file);
        full_cert_file = full_cert_file_buf;
    }
    if (ret == 0 && root_certs_file != NULL) {
        ret = picoquic_get_input_path(full_root_certs_file_buf, sizeof(full_root_certs_file_buf),
            picoquic_solution_dir, root_certs_file);
        full_root_certs_file = full_root_certs_file_buf;
    }
    if (ret != 0) {
        DBG_PRINTF("%s", "Cannot set key file names.");
    }
    else {
        test_ctx = (picoquic_test_tls_api_ctx_t*)
            malloc(sizeof(picoquic_test_tls_api_ctx_t));

        if (test_ctx == NULL) {
            ret = -1;
        }
        else {
            /* Init to NULL */
            memset(test_ctx, 0, sizeof(picoquic_test_tls_api_ctx_t));
            test_ctx->client_callback.client_mode = 1;

            /* Init of the IP addresses */
            picoquic_set_test_address(&test_ctx->client_addr, 0x0A000002, 1234);
            picoquic_set_test_address(&test_ctx->server_addr, 0x0A000001, 4321);

            /* Test the creation of the client and server contexts */
            test_ctx->qclient = picoquic_create(8, NULL, NULL, full_root_certs_file, NULL, test_api_callback,
                (void*)&test_ctx->client_callback, NULL, NULL, NULL, *p_simulated_time,
                p_simulated_time, NULL, NULL, 0);

            test_ctx->qserver = picoquic_create(8,
                full_key_file, full_cert_file, full_root_certs_file, PICOQUIC_TEST_ALPN, test_api_callback,
                (void*)&test_ctx->server_callback, NULL, NULL, NULL,
                *p_simulated_time, p_simulated_time, NULL,
                verifier_encrypt_key, sizeof(verifier_encrypt_key));

            if (test_ctx->qclient == NULL || test_ctx->qserver == NULL) {
                ret = -1;
            }

            /* register the links */
            if (ret == 0) {
                test_ctx->c_to_s_link = picoquictest_sim_link_create(0.01, 10000, NULL, 0, 0);
                test_ctx->s_to_c_link = picoquictest_sim_link_create(0.01, 10000, NULL, 0, 0);

                if (test_ctx->c_to_s_link == NULL || test_ctx->s_to_c_link == NULL) {
                    ret = -1;
                }
            }

            if (ret == 0) {
                /* Create the send buffer as requested */
                test_ctx->send_buffer_size = PICOQUIC_MAX_PACKET_SIZE;
                test_ctx->send_buffer = (uint8_t*)malloc(test_ctx->send_buffer_size);
                if (test_ctx->send_buffer == NULL) {
                    ret = -1;
                }
            }

            if (ret == 0) {
                /* Create a client connection */
                test_ctx->cnx_client = picoquic_create_cnx(test_ctx->qclient, picoquic_null_connection_id,
                    picoquic_null_connection_id,
                    (struct sockaddr*) & test_ctx->server_addr, *p_simulated_time,
                    PICOQUIC_INTERNAL_TEST_VERSION_1, sni, PICOQUIC_TEST_ALPN, 1);

                if (test_ctx->cnx_client == NULL) {
                    ret = -1;
                }
                else {
                    ret = picoquic_start_client_cnx(test_ctx->cnx_client);
                }
            }
        }
    }

    if (ret != 0 && test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }

    *pctx = test_ctx;

    return ret;
}

int cert_verify_test_one(int expect_success,
    char const* key_file, char const* cert_file, char const* root_certs_file, char const* sni)
{
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    uint64_t simulated_time = 0; /* TODO: set to Jan 1, 2021 */
    int ret = cert_verify_set_ctx(&test_ctx, &simulated_time, key_file, cert_file, root_certs_file, sni);

    if (ret == 0) {
        uint64_t loss_mask = 0;
        int c_ret = tls_api_connection_loop(test_ctx, &loss_mask, 0, &simulated_time);

        if (c_ret == 0 && !(TEST_CLIENT_READY && TEST_SERVER_READY)){
            c_ret = -1;
        }

        if ((c_ret == 0 && !expect_success) || (c_ret != 0 && expect_success))
        {
            DBG_PRINTF("Connection loop returns %d, expected %s\n", c_ret, 
                (expect_success)?"success":"reject");
            ret = -1;
        }
    }

    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
    }

    return ret;
}

/* Different tests use different combinations of keys, certs and roots.
 */

#ifdef _WINDOWS
#define CERT_VERIFY_RSA_CERT "certs\\cert.pem"
#define CERT_VERIFY_RSA_BAD_CERT "certs\\badcert.pem"
#define CERT_VERIFY_RSA_KEY "certs\\key.pem"
#define CERT_VERIFY_TEST_CA "certs\\test-ca.crt"
#else
#define CERT_VERIFY_RSA_CERT "certs/cert.pem"
#define CERT_VERIFY_RSA_BAD_CERT "certs/badcert.pem"
#define CERT_VERIFY_RSA_KEY "certs/key.pem"
#define CERT_VERIFY_TEST_CA "certs/test-ca.crt"
#endif
#define CERT_VERIFY_TEST_SNI "test.example.com"
#define CERT_VERIFY_TEST_BAD_SNI "bad.example.com"

/* NULL test: do not specify a list of root CAs.
 * Verfication defaults to just testing that the SNI maps the name in the certificate */
int cert_verify_null_test()
{
    int ret = cert_verify_test_one(1, CERT_VERIFY_RSA_CERT, CERT_VERIFY_RSA_KEY,
        NULL, CERT_VERIFY_TEST_SNI);
    return ret;
}

/* RSA test: the certificate specifies an RSA key, and the certificate authority is
 * added to the trusted list. */
int cert_verify_rsa_test()
{
    int ret = cert_verify_test_one(1, CERT_VERIFY_RSA_CERT, CERT_VERIFY_RSA_KEY,
        CERT_VERIFY_TEST_CA, CERT_VERIFY_TEST_SNI);
    return ret;
}

/* BAD CERT: the server uses the wrong certificate.
 */
int cert_verify_bad_cert_test()
{
    int ret = cert_verify_test_one(0, CERT_VERIFY_RSA_BAD_CERT, CERT_VERIFY_RSA_KEY,
        CERT_VERIFY_TEST_CA, CERT_VERIFY_TEST_SNI);
    return ret;
}

/* BAD SNI: the name certified in the server's certificate does not match the
 * SNI set by the client. Verification should fail.
 */
int cert_verify_bad_sni_test()
{
    int ret = cert_verify_test_one(0, CERT_VERIFY_RSA_CERT, CERT_VERIFY_RSA_KEY,
        CERT_VERIFY_TEST_CA, CERT_VERIFY_TEST_BAD_SNI);
    return ret;
}

/* NULL SNI: the client does not provide an SNI.
 * Treated as indicating that the client does not care for the SNI.
 */
int cert_verify_null_sni_test()
{
    int ret = cert_verify_test_one(1, CERT_VERIFY_RSA_CERT, CERT_VERIFY_RSA_KEY,
        CERT_VERIFY_TEST_CA, NULL);
    return ret;
}