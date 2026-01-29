/*
* Author: Christian Huitema
* Copyright (c) 2024, Private Octopus, Inc.
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
#include "picosocks.h"
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

#include "picotls.h"
#include "picoquic_crypto_provider_api.h"

#ifdef PTLS_WITHOUT_OPENSSL
int openssl_cert_test()
{
    /* Nothing to do, as the module is not loaded. */
    return 0;
}
#else

ptls_iovec_t* picoquic_openssl_get_certs_from_file(char const* file_name, size_t* count);

#ifdef _WINDOWS
#define TEST_CERT1 "certs\\tests\\cert.pem"
#define TEST_CERT2 "certs\\tests\\chain.pem"
#define TEST_CERT3 "certs\\tests\\fullchain.pem"
#else
#define TEST_CERT1 "certs/tests/cert.pem"
#define TEST_CERT2 "certs/tests/chain.pem"
#define TEST_CERT3 "certs/tests/fullchain.pem"
#endif

static int openssl_cert_test_one(char const * cert_file_name, int expected_count)
{
    /* Nothing to do, as the module is not loaded. */
    int ret = 0;
    size_t count = 0;
    char cert_file_path[512];

    ret = picoquic_get_input_path(cert_file_path, sizeof(cert_file_path), picoquic_solution_dir, cert_file_name);

    if (ret == 0) {
        ptls_iovec_t* certs_vec = picoquic_openssl_get_certs_from_file(cert_file_path, &count);

        if (count != expected_count) {
            DBG_PRINTF("Expected %d certs for %s, got=%d", expected_count, cert_file_path, count);
            ret = -1;
        }
        if (certs_vec == NULL) {
            if (count > 0) {
                DBG_PRINTF("No certificate vector for %s, count=%d", cert_file_path, count);
                ret = -1;
            }
        }
        else {
            for (size_t i = 0; i < count; i++) {
                free(certs_vec[i].base);
                certs_vec[i] = ptls_iovec_init(NULL, 0);
            }
            free(certs_vec);
        }
    }
    return 0;
}


int openssl_cert_test()
{
    /* Nothing to do, as the module is not loaded. */
    int ret = 0;

    if (openssl_cert_test_one(TEST_CERT1, 1) != 0 ||
        openssl_cert_test_one(TEST_CERT2, 1) != 0 ||
        openssl_cert_test_one(TEST_CERT3, 2) != 0) {
        ret = -1;
    }
    return ret;
}

#endif /* !PTLS_WITHOUT_OPENSSL */