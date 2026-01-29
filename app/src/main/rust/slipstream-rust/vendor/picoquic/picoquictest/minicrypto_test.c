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

#include <stddef.h>
#include <stdint.h>
#include "picoquic.h"
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
#include "picoquic_crypto_provider_api.h"
#include "picotls/minicrypto.h"

/* Minicrypto test:
 * Use the "flag" option of tls_api_init to only load specified
 * providers -- specifically, do not load openssl.
 * Then, run a basic connection test, to check that negotiation
 * succeeds.
 * Then, unload the tls api provider and reset the control flag
 * to zero.
 */
#ifndef PICOQUIC_WITH_MBEDTLS
/* This is defined even if Mbedtls is not. */
void picoquic_mbedtls_load(int unload);
#endif

static test_api_stream_desc_t test_scenario_minicrypto[] = {
    { 4, 0, 2000, 2000 }
};

int minicrypto_test()
{
    uint64_t simulated_time = 0;
    uint64_t loss_mask = 0;
    uint64_t target_time = 1000000;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    picoquic_connection_id_t initial_cid = { {0x81, 0x81, 0xc8, 0x19, 0x40, 0, 6, 7}, 8 };
    int ret = 0;

    picoquic_tls_api_reset(TLS_API_INIT_FLAGS_NO_OPENSSL);
#ifndef PICOQUIC_WITH_MBEDTLS
    picoquic_mbedtls_load(0);
#endif
    ret = tls_api_init_ctx_ex2(&test_ctx, PICOQUIC_INTERNAL_TEST_VERSION_1,
        PICOQUIC_TEST_SNI, PICOQUIC_TEST_ALPN, &simulated_time, NULL, NULL, 0, 0, 0, &initial_cid, 8, 0, 0, 1);
    if (ret == 0) {
        picoquic_set_binlog(test_ctx->qserver, ".");
        test_ctx->qserver->use_long_log = 1;
    }

    if (ret == 0) {
        ret = tls_api_connection_loop(test_ctx, &loss_mask, 20000, &simulated_time);
    }

    /* Prepare to send data */
    if (ret == 0) {
        ret = test_api_init_send_recv_scenario(test_ctx, test_scenario_minicrypto, sizeof(test_scenario_minicrypto));
    }

    /* Try to complete the data sending loop */
    if (ret == 0) {
        ret = tls_api_data_sending_loop(test_ctx, &loss_mask, &simulated_time, 0);
    }

    /* verify that the transmission was complete */
    if (ret == 0) {
        ret = tls_api_one_scenario_body_verify(test_ctx, &simulated_time, target_time);
    }

    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }

    picoquic_tls_api_reset(0);

    return ret;
}

extern ptls_cipher_suite_t ptls_minicrypto_aes128gcmsha256;
extern picoquic_set_private_key_from_file_t picoquic_minicrypto_set_key_fn;
extern picoquic_set_private_key_from_file_t picoquic_set_private_key_from_file_fn;
int minicrypto_is_last_test()
{
    int ret = 0;
    int expected_aes128gcm_sha256 = 1;
    int expected_aes128gcm_sha256_low = 1;
    int expected_set_key = 1;
    int using_aes128gcm_sha256;
    int using_aes128gcm_sha256_low;
    int actual_set_key;
    void* actual_aes128gcm_sha256 = picoquic_get_aes128gcm_sha256_v(0);
    void* actual_aes128gcm_sha256_low = picoquic_get_aes128gcm_sha256_v(1);

    picoquic_tls_api_reset(0);

#if defined(PICOQUIC_WITH_MBEDTLS) || !defined(PTLS_WITHOUT_OPENSSL) || !defined(PTLS_WITHOUT_FUSION)
    expected_aes128gcm_sha256 = 0;
    expected_set_key = 0;
#endif
#if defined(PICOQUIC_WITH_MBEDTLS) || !defined(PTLS_WITHOUT_OPENSSL)
    expected_aes128gcm_sha256_low = 0;
#endif
#if !defined(PTLS_WITHOUT_OPENSSL)
    expected_set_key = 0;
#endif
    using_aes128gcm_sha256 = (actual_aes128gcm_sha256 == (void*)&ptls_minicrypto_aes128gcmsha256);
    using_aes128gcm_sha256_low = (actual_aes128gcm_sha256_low == (void*)&ptls_minicrypto_aes128gcmsha256);
    actual_set_key = (picoquic_set_private_key_from_file_fn == picoquic_minicrypto_set_key_fn);
    if (using_aes128gcm_sha256 != expected_aes128gcm_sha256) {
        DBG_PRINTF("Wrong aes gcm 128 sha 256. Expected: %s, actual: %s",
            (expected_aes128gcm_sha256) ? "minicrypto" : "other",
            (using_aes128gcm_sha256) ? "minicrypto" : "other");
        ret = -1;
    }
    if (using_aes128gcm_sha256_low != expected_aes128gcm_sha256_low) {
        DBG_PRINTF("Wrong aes gcm 128 sha 256 low. Expected: %s, actual: %s",
            (expected_aes128gcm_sha256_low) ? "minicrypto" : "other",
            (using_aes128gcm_sha256_low) ? "minicrypto" : "other");
        ret = -1;
    }
    if (actual_set_key != expected_set_key) {
        DBG_PRINTF("Wrong set key function. Expected: %s, actual: %s",
            (expected_set_key) ? "minicrypto" : "other",
            (actual_set_key) ? "minicrypto" : "other");
        ret = -1;
    }

    return ret;
}
