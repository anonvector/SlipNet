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
#include <picotls.h>
#if 0
#include "psa/crypto.h"
#include "psa/crypto_struct.h"
#endif
#include "picotls/minicrypto.h"

#ifdef PICOQUIC_WITH_MBEDTLS
#include "mbedtls/mbedtls_config.h"
#include "mbedtls/build_info.h"
#include "psa/crypto.h"
#include "psa/crypto_struct.h"
#include "psa/crypto_values.h"
#include "picotls.h"
#include "ptls_mbedtls.h"
#endif
/* Mbedtls test:
 * Use the "flag" option of tls_api_init to only load specified
 * providers -- specifically, do not load openssl, nor "fusion".
 * Then, run a basic connection test, to check that negotiation
 * succeeds.
 * Then, unload the tls api provider and reset the control flag
 * to zero.
 */

static test_api_stream_desc_t test_scenario_mbedtls[] = {
    { 4, 0, 2000, 2000 }
};

int mbedtls_test()
{
    uint64_t simulated_time = 0;
    uint64_t loss_mask = 0;
    uint64_t target_time = 1000000;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    picoquic_connection_id_t initial_cid = { {0x99, 0xbe, 0xd7, 0x15, 0, 0, 0, 0}, 8 };
    int ret = 0;

    picoquic_tls_api_reset(TLS_API_INIT_FLAGS_NO_OPENSSL|TLS_API_INIT_FLAGS_NO_FUSION);

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
        ret = test_api_init_send_recv_scenario(test_ctx, test_scenario_mbedtls, sizeof(test_scenario_mbedtls));
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

/* The following test verifies that the MBED TLS library is properly
* mapped to the "picotls" APIs.
 */

#ifdef PICOQUIC_WITH_MBEDTLS
#include "mbedtls/build_info.h"

extern ptls_hash_algorithm_t ptls_mbedtls_sha256;
extern ptls_hash_algorithm_t ptls_mbedtls_sha512;
#if defined(MBEDTLS_SHA384_C)
extern ptls_hash_algorithm_t ptls_mbedtls_sha384;
#endif

extern ptls_cipher_algorithm_t ptls_mbedtls_aes128ecb;
extern ptls_cipher_algorithm_t ptls_mbedtls_aes256ecb;
extern ptls_cipher_algorithm_t ptls_mbedtls_aes128ctr;
extern ptls_cipher_algorithm_t ptls_mbedtls_aes256ctr;
extern ptls_cipher_algorithm_t ptls_mbedtls_chacha20;

extern ptls_aead_algorithm_t ptls_mbedtls_aes128gcm;
extern ptls_aead_algorithm_t ptls_mbedtls_aes256gcm;
extern ptls_aead_algorithm_t ptls_mbedtls_chacha20poly1305;

extern ptls_cipher_suite_t ptls_mbedtls_aes128gcmsha256;
extern ptls_cipher_suite_t ptls_mbedtls_aes256gcmsha384;
extern ptls_cipher_suite_t ptls_mbedtls_chacha20poly1305sha256;

extern ptls_key_exchange_algorithm_t ptls_mbedtls_secp256r1;
extern ptls_key_exchange_algorithm_t ptls_mbedtls_x25519;

int ptls_mbedtls_init();
void ptls_mbedtls_free();
void ptls_mbedtls_random_bytes(void* buf, size_t len);
static int test_random();
static int test_hash(ptls_hash_algorithm_t* algo, ptls_hash_algorithm_t* ref);
static int test_label(ptls_hash_algorithm_t* hash, ptls_hash_algorithm_t* ref);
static int test_cipher(ptls_cipher_algorithm_t* cipher, ptls_cipher_algorithm_t* cipher_ref);
static int test_aead(ptls_aead_algorithm_t* algo, ptls_hash_algorithm_t* hash, ptls_aead_algorithm_t* ref, ptls_hash_algorithm_t* hash_ref);
static int test_key_exchange(ptls_key_exchange_algorithm_t* client, ptls_key_exchange_algorithm_t* server);

int mbedtls_crypto_test()
{
    ptls_cipher_algorithm_t* cipher_test[5] = {
        &ptls_mbedtls_aes128ecb,
        &ptls_mbedtls_aes128ctr,
        &ptls_mbedtls_aes256ecb,
        &ptls_mbedtls_aes256ctr,
        &ptls_mbedtls_chacha20
    };
    ptls_cipher_algorithm_t* cipher_ref[5] = {
        &ptls_minicrypto_aes128ecb,
        &ptls_minicrypto_aes128ctr,
        &ptls_minicrypto_aes256ecb,
        &ptls_minicrypto_aes256ctr,
        &ptls_minicrypto_chacha20
    };
    int ret = 0;

    /* Initialize the PSA crypto library. */
    if ((ret = ptls_mbedtls_init()) != 0) {
        DBG_PRINTF("%s", "psa_crypto_init fails.");
    }
    else {
        ret = test_random();
        DBG_PRINTF("test random returns: %d\n", ret);

        if (ret == 0) {
            ret = test_hash(&ptls_mbedtls_sha256, &ptls_minicrypto_sha256);
            DBG_PRINTF("test hash returns: %d\n", ret);
        }

        if (ret == 0) {
            ret = test_label(&ptls_mbedtls_sha256, &ptls_minicrypto_sha256);
            DBG_PRINTF("test label returns: %d\n", ret);
        }

        if (ret == 0) {
            for (int i = 0; i < 5; i++) {
                if (test_cipher(cipher_test[i], cipher_ref[i]) != 0) {
                    DBG_PRINTF("test cipher %d fails\n", i);
                    ret = -1;
                }
            }
            DBG_PRINTF("test ciphers returns: %d\n", ret);
        }

        if (ret == 0) {
            ret = test_aead(&ptls_mbedtls_aes128gcm, &ptls_mbedtls_sha256, &ptls_minicrypto_aes128gcm, &ptls_minicrypto_sha256);
            DBG_PRINTF("test aeads returns: %d\n", ret);
        }

        if (ret == 0) {
            ret = test_key_exchange(&ptls_mbedtls_secp256r1, &ptls_minicrypto_secp256r1);
            if (ret != 0) {
                DBG_PRINTF("%s", "test key exchange secp256r1 mbedtls to minicrypto fails\n");
            }
            else {
                ret = test_key_exchange(&ptls_minicrypto_secp256r1, &ptls_mbedtls_secp256r1);
                if (ret != 0) {
                    DBG_PRINTF("%s", "test key exchange secp256r1 minicrypto to mbedtls fails\n");
                }
            }
            ret = test_key_exchange(&ptls_mbedtls_x25519, &ptls_minicrypto_x25519);
            if (ret != 0) {
                DBG_PRINTF("%s", "test key exchange x25519 mbedtls to minicrypto fails\n");
            }
            else {
                ret = test_key_exchange(&ptls_minicrypto_x25519, &ptls_mbedtls_x25519);
                if (ret != 0) {
                    DBG_PRINTF("%s", "test key exchange x25519 minicrypto to mbedtls fails\n");
                }
            }
            DBG_PRINTF("test key exchange returns: %d\n", ret);
        }

        /* Deinitialize the PSA crypto library. */
        ptls_mbedtls_free();
    }
    return (ret == 0) ? 0 : -1;
}

#define PTLS_MBEDTLS_RANDOM_TEST_LENGTH 1021

static int test_random()
{
    /* The random test is just trying to check that we call the API properly. 
    * This is done by getting a vector of 1021 bytes, computing the sum of
    * all values, and comparing to theoretical min and max,
    * computed as average +- 8*standard deviation for sum of 1021 terms.
    * 8 random deviations results in an extremely low probability of random
    * failure.
    * Note that this does not actually test the random generator.
    */

    uint8_t buf[PTLS_MBEDTLS_RANDOM_TEST_LENGTH];
    uint64_t sum = 0;
    const uint64_t max_sum_1021 = 149505;
    const uint64_t min_sum_1021 = 110849;
    int ret = 0;

    ptls_mbedtls_random_bytes(buf, PTLS_MBEDTLS_RANDOM_TEST_LENGTH);
    for (size_t i = 0; i < PTLS_MBEDTLS_RANDOM_TEST_LENGTH; i++) {
        sum += buf[i];
    }
    if (sum > max_sum_1021 || sum < min_sum_1021) {
        ret = -1;
    }

    return ret;
}

static int hash_trial(ptls_hash_algorithm_t* algo, const uint8_t* input, size_t len1, size_t len2, uint8_t* final_hash)
{
    int ret = 0;
    ptls_hash_context_t* hash_ctx = algo->create();

    hash_ctx->update(hash_ctx, input, len1);
    if (len2 > 0) {
        hash_ctx->update(hash_ctx, input + len1, len2);
    }
    hash_ctx->final(hash_ctx, final_hash, PTLS_HASH_FINAL_MODE_FREE);

    return ret;
}

static int hash_reset_trial(ptls_hash_algorithm_t* algo, const uint8_t* input, size_t len1, size_t len2, 
    uint8_t* hash1, uint8_t* hash2)
{
    int ret = 0;
    ptls_hash_context_t* hash_ctx = algo->create();

    hash_ctx->update(hash_ctx, input, len1);
    hash_ctx->final(hash_ctx, hash1, PTLS_HASH_FINAL_MODE_RESET);
    hash_ctx->update(hash_ctx, input + len1, len2);
    hash_ctx->final(hash_ctx, hash2, PTLS_HASH_FINAL_MODE_FREE);

    return ret;
}

static int test_hash(ptls_hash_algorithm_t* algo, ptls_hash_algorithm_t* ref)
{
    int ret = 0;
    uint8_t input[1234];
    uint8_t final_hash[32];
    uint8_t final_ref[32];
    uint8_t hash1[32], hash2[32], href1[32], href2[32];

    memset(input, 0xba, sizeof(input));

    ret = hash_trial(algo, input, sizeof(input), 0, final_hash);
    if (ret == 0) {
        ret = hash_trial(ref, input, sizeof(input), 0, final_ref);
    }
    if (ret == 0) {
        if (memcmp(final_hash, final_ref, ref->digest_size) != 0) {
            ret = -1;
        }
    }
    if (ret == 0) {
        ret = hash_trial(algo, input, sizeof(input) - 17, 17, final_hash);
    }
    if (ret == 0) {
        if (memcmp(final_hash, final_ref, ref->digest_size) != 0) {
            ret = -1;
        }
    }

    if (ret == 0) {
        ret = hash_reset_trial(algo, input, sizeof(input) - 126, 126, hash1, hash2);
    }
    if (ret == 0) {
        ret = hash_reset_trial(ref, input, sizeof(input) - 126, 126, href1, href2);
    }
    if (ret == 0) {
        if (memcmp(hash1, href1, ref->digest_size) != 0) {
            ret = -1;
        }
        else if (memcmp(hash2, href2, ref->digest_size) != 0) {
            ret = -1;
        }
    }

    return ret;
}

static int cipher_trial(ptls_cipher_algorithm_t * cipher, const uint8_t * key, const uint8_t * iv, int is_enc, const uint8_t * v_in, uint8_t * v_out1, uint8_t * v_out2, size_t len)
{
    int ret = 0;
    ptls_cipher_context_t* test_cipher = ptls_cipher_new(cipher, is_enc, key);
    if (test_cipher == NULL) {
        ret = -1;
    } else {
        if (test_cipher->do_init != NULL) {
            ptls_cipher_init(test_cipher, iv);
        }
        ptls_cipher_encrypt(test_cipher, v_out1, v_in, len);
        if (test_cipher->do_init != NULL) {
            ptls_cipher_init(test_cipher, iv);
        }
        ptls_cipher_encrypt(test_cipher, v_out2, v_out1, len);
        ptls_cipher_free(test_cipher);
    }

    return ret;
}

static int test_cipher(ptls_cipher_algorithm_t * cipher, ptls_cipher_algorithm_t * cipher_ref)
{
    uint8_t key[32];
    uint8_t iv[16];
    uint8_t v_in[16];
    uint8_t v_out_1a[16], v_out_2a[16], v_out_1b[16], v_out_2b[16], v_out_1d[16], v_out_2d[16];
    int ret = 0;

    /* Set initial values */
    memset(key, 0x55, sizeof(key));
    memset(iv, 0x33, sizeof(iv));
    memset(v_in, 0xaa, sizeof(v_in));

    /* Encryption test */
    ret = cipher_trial(cipher, key, iv, 1, v_in, v_out_1a, v_out_2a, 16);
    if (ret == 0) {
        ret = cipher_trial(cipher_ref, key, iv, 1, v_in, v_out_1b, v_out_2b, 16);
    }
    if (ret == 0) {
        if (memcmp(v_out_1a, v_out_1b, 16) != 0) {
            ret = -1;
        }
        else if (memcmp(v_out_2a, v_out_2b, 16) != 0) {
            ret = -1;
        }
    }
    /* decryption test */
    if (ret == 0) {
        ret = cipher_trial(cipher, key, iv, 0, v_out_2a, v_out_1d, v_out_2d, 16);
    }
    if (ret == 0) {
        if (memcmp(v_out_1a, v_out_1d, 16) != 0) {
            ret = -1;
        }
        else if (memcmp(v_out_2d, v_in, 16) != 0) {
            ret = -1;
        }
    }

    return ret;
}

static int label_test(ptls_hash_algorithm_t * hash, uint8_t * v_out, size_t o_len, const uint8_t * secret,
    char const * label, char const * label_prefix)
{
    uint8_t h_val_v[32];
    ptls_iovec_t h_val = { 0 };
    ptls_iovec_t s_vec = { 0 };
    s_vec.base = (uint8_t *)secret;
    s_vec.len = 32;
    h_val.base = h_val_v;
    h_val.len = 32;
    memset(h_val_v, 0, sizeof(h_val_v));

    ptls_hkdf_expand_label(hash, v_out, o_len, s_vec, label, h_val, label_prefix);
    return 0;
}

static int test_label(ptls_hash_algorithm_t* hash, ptls_hash_algorithm_t* ref)
{
    int ret = 0;
    uint8_t v_out[16], v_ref[16];
    uint8_t secret[32];
    char const* label = "label";
    char const* label_prefix = "label_prefix";
    memset(secret, 0x5e, sizeof(secret));

    ret = label_test(hash, v_out, 16, secret, label, label_prefix);

    if (ret == 0) {
        ret = label_test(ref, v_ref, 16, secret, label, label_prefix);
    }

    if (ret == 0 && memcmp(v_out, v_ref, 16) != 0) {
        ret = -1;
    }

    return ret;
}

static int aead_trial(ptls_aead_algorithm_t * algo, ptls_hash_algorithm_t * hash, const uint8_t * secret, int is_enc, 
    const uint8_t * v_in, size_t len, uint8_t * aad, size_t aad_len, uint64_t seq, uint8_t * v_out, size_t * o_len)
{
    int ret = 0;
    ptls_aead_context_t* aead = ptls_aead_new(algo, hash, is_enc, secret, "test_aead");

    if (aead == NULL) {
        ret = -1;
    }
    else{
        if (is_enc) {
            *o_len = ptls_aead_encrypt(aead, v_out, v_in, len, seq, aad, aad_len);
            if (*o_len != len + algo->tag_size) {
                ret = -1;
            }
        }
        else {
            *o_len = ptls_aead_decrypt(aead, v_out, v_in, len, seq, aad, aad_len);
            if (*o_len != len - algo->tag_size) {
                ret = -1;
            }
        }
        ptls_aead_free(aead);
    }
    return ret;
}

static int test_aead(ptls_aead_algorithm_t* algo, ptls_hash_algorithm_t* hash, ptls_aead_algorithm_t* ref, ptls_hash_algorithm_t* hash_ref)
{
    uint8_t secret[32];
    uint8_t v_in[1234];
    uint8_t aad[17];
    uint8_t v_out_a[1250], v_out_b[1250], v_out_r[1250];
    size_t olen_a, olen_b, olen_r;
    uint64_t seq = 12345;
    int ret = 0;

    memset(secret, 0x58, sizeof(secret));
    memset(v_in, 0x12, sizeof(v_in));
    memset(aad, 0xaa, sizeof(aad));

    ret = aead_trial(algo, hash, secret, 1, v_in, sizeof(v_in), aad, sizeof(aad), seq, v_out_a, &olen_a);
    if (ret == 0) {
        ret = aead_trial(ref, hash_ref, secret, 1, v_in, sizeof(v_in), aad, sizeof(aad), seq, v_out_b, &olen_b);
    }
    if (ret == 0 && (olen_a != olen_b || memcmp(v_out_a, v_out_b, olen_a) != 0)) {
        ret = -1;
    }
    if (ret == 0) {
        ret = aead_trial(ref, hash_ref, secret, 0, v_out_a, olen_a, aad, sizeof(aad), seq, v_out_r, &olen_r);
    }
    if (ret == 0 && (olen_r != sizeof(v_in) || memcmp(v_in, v_out_r, sizeof(v_in)) != 0)) {
        ret = -1;
    }
    return ret;
}

/* Test key exchanges. We copy paste the code from "test.h" in picotls.
* if intergarted with picotls, we should reuse this code.
*/

static int test_key_exchange(ptls_key_exchange_algorithm_t *client, ptls_key_exchange_algorithm_t *server)
{
    ptls_key_exchange_context_t *ctx;
    ptls_iovec_t client_secret, server_pubkey, server_secret;
    int f_ret;
    int ret = 0;

    /* fail */
    if ((f_ret = server->exchange(server, &server_pubkey, &server_secret, (ptls_iovec_t) { NULL })) == 0) {
        ret = -1;
    }
    if (ret == 0) {
        /* perform ecdh */
        ret = client->create(client, &ctx);
        if (ret == 0) {
            ret = server->exchange(server, &server_pubkey, &server_secret, ctx->pubkey);
        }
        if (ret == 0) {
            ret = ctx->on_exchange(&ctx, 1, &client_secret, server_pubkey);
        }
        if (ret == 0) {
            if (client_secret.len != server_secret.len ||
                memcmp(client_secret.base, server_secret.base, client_secret.len) != 0) {
                ret = -1;
            }
        }
    }

    free(client_secret.base);
    free(server_pubkey.base);
    free(server_secret.base);

    if (ret == 0) {
        /* client abort */
        ret = client->create(client, &ctx);
        if (ret == 0) {
            ret = ctx->on_exchange(&ctx, 1, NULL, ptls_iovec_init(NULL, 0));
        }
        if (ctx != NULL) {
            ret = -1;
        }
    }

    return ret;
}


/*
Series of tests for loading a key and using it to build
a signature. Verification of the signature will be done
in the "verify" tests.
*/
#ifdef _WINDOWS
#ifdef _WINDOWS64
#define ASSET_DIR ..\\..\\data
#define ASSET_RSA_KEY "..\\..\\certs\\rsa\\key.pem"
#define ASSET_RSA_PKCS8_KEY "..\\..\\certs\\rsa-pkcs8\\key.pem"
#define ASSET_SECP256R1_KEY "..\\..\\certs\\secp256r1\\key.pem"
#define ASSET_SECP384R1_KEY "..\\..\\certs\\secp384r1\\key.pem"
#define ASSET_SECP521R1_KEY "..\\..\\certs\\secp521r1\\key.pem"
#define ASSET_SECP256R1_PKCS8_KEY "..\\..\\certs\\secp256r1-pkcs8\\key.pem"
#define ASSET_ED25519_KEY "..\\..\\certs\\ed25519\\key.pem"
#define ASSET_NO_SUCH_FILE "..\\..\\certs\\no_such_file.pem"
#define ASSET_NOT_A_PEM_FILE "..\\..\\certs\\not_a_valid_pem_file.pem"
#define ASSET_RSA_CERT "..\\..\\certs\\rsa/cert.pem"
#define ASSET_RSA_PKCS8_CERT "..\\..\\certs\\rsa-pkcs8\\cert.pem"
#define ASSET_SECP256R1_CERT "..\\..\\certs\\secp256r1\\cert.pem"
#define ASSET_SECP384R1_CERT "..\\..\\certs\\secp384r1\\cert.pem"
#define ASSET_SECP521R1_CERT "..\\..\\certs\\secp521r1\\cert.pem"
#define ASSET_SECP256R1_PKCS8_CERT "..\\..\\certs\\secp256r1-pkcs8/cert.pem"
#define ASSET_ED25519_CERT "..\\..\\certs\\ed25519\\cert.pem"

#define ASSET_TEST_CA "..\\..\\certs\\test-ca.crt"
#else
#define ASSET_DIR ..\\data
#define ASSET_RSA_KEY "..\\certs\\rsa\\key.pem"
#define ASSET_RSA_PKCS8_KEY "..\\certs\\rsa-pkcs8\\key.pem"
#define ASSET_SECP256R1_KEY "..\\certs\\secp256r1\\key.pem"
#define ASSET_SECP384R1_KEY "..\\certs\\secp384r1\\key.pem"
#define ASSET_SECP521R1_KEY "..\\certs\\secp521r1\\key.pem"
#define ASSET_SECP256R1_PKCS8_KEY "..\\certs\\secp256r1-pkcs8\\key.pem"
#define ASSET_ED25519_KEY "..\\certs\\ed25519\\key.pem"
#define ASSET_NO_SUCH_FILE "..\\certs\\no_such_file.pem"
#define ASSET_NOT_A_PEM_FILE "..\\certs\\not_a_valid_pem_file.pem"
#define ASSET_RSA_CERT "..\\certs\\rsa/cert.pem"
#define ASSET_RSA_PKCS8_CERT "..\\certs\\rsa-pkcs8\\cert.pem"
#define ASSET_SECP256R1_CERT "..\\certs\\secp256r1\\cert.pem"
#define ASSET_SECP384R1_CERT "..\\certs\\secp384r1\\cert.pem"
#define ASSET_SECP521R1_CERT "..\\certs\\secp521r1\\cert.pem"
#define ASSET_SECP256R1_PKCS8_CERT "..\\certs\\secp256r1-pkcs8/cert.pem"
#define ASSET_ED25519_CERT "..\\certs\\ed25519\\cert.pem"

#define ASSET_TEST_CA "data\\test-ca.crt"
#endif
#else
#define ASSET_DIR data
#define ASSET_RSA_KEY "certs/rsa/key.pem"
#define ASSET_RSA_PKCS8_KEY "certs/rsa-pkcs8/key.pem"
#define ASSET_SECP256R1_KEY "certs/secp256r1/key.pem"
#define ASSET_SECP384R1_KEY "certs/secp384r1/key.pem"
#define ASSET_SECP521R1_KEY "certs/secp521r1/key.pem"
#define ASSET_SECP256R1_PKCS8_KEY "certs/secp256r1-pkcs8/key.pem"
#define ASSET_ED25519_KEY "certs/ed25519/key.pem"
#define ASSET_NO_SUCH_FILE "certs/no_such_file.pem"
#define ASSET_NOT_A_PEM_FILE "certs/not_a_valid_pem_file.pem"
#define ASSET_RSA_CERT "certs/rsa/cert.pem"
#define ASSET_RSA_PKCS8_CERT "certs/rsa-pkcs8/cert.pem"
#define ASSET_SECP256R1_CERT "certs/secp256r1/cert.pem"
#define ASSET_SECP384R1_CERT "certs/secp384r1/cert.pem"
#define ASSET_SECP521R1_CERT "certs/secp521r1/cert.pem"
#define ASSET_SECP256R1_PKCS8_CERT "certs/secp256r1-pkcs8/cert.pem"
#define ASSET_ED25519_CERT "certs/ed25519/cert.pem"

#define ASSET_TEST_CA "certs/test-ca.crt"
#endif

#define ASSET_RSA_NAME "rsa.test.example.com"
#define ASSET_RSA_PKCS8_NAME "rsa.test.example.com"
#define ASSET_SECP256R1_NAME "test.example.com"
#define ASSET_SECP384R1_NAME "secp384r1.test.example.com"
#define ASSET_SECP521R1_NAME "secp521r1.test.example.com"
#define ASSET_SECP256R1_PKCS8_NAME "test.example.com"

static int mbedtls_test_load_one_der_key(char const* path_ref)
{
    int ret = -1;
    unsigned char hash[32];
    const unsigned char h0[32] = {
        1, 2, 3, 4, 5, 6, 7, 8,
        9, 10, 11, 12, 13, 14, 15, 16,
        17, 18, 19, 20, 21, 22, 23, 24,
        25, 26, 27, 28, 29, 30, 31, 32
    };
    ptls_context_t ctx = { 0 };

    char path[512];

    if ((ret = picoquic_get_input_path(path, sizeof(path), picoquic_solution_dir, path_ref)) != 0) {
        DBG_PRINTF("Cannot build path from %s", path_ref);
    }
    else {
        ret = ptls_mbedtls_load_private_key(path, &ctx);
        if (ret != 0) {
            DBG_PRINTF("Cannot create sign_certificate from: %s\n", path);
        }
        else if (ctx.sign_certificate == NULL) {
            DBG_PRINTF("Sign_certificate not set in ptls context for: %s\n", path);
            ret = -1;
        }
        else {
            /* Try to sign something */
            int ret;
            ptls_mbedtls_sign_certificate_t* signer = (ptls_mbedtls_sign_certificate_t*)
                (((unsigned char*)ctx.sign_certificate) - offsetof(struct st_ptls_mbedtls_sign_certificate_t, super));
            ptls_buffer_t outbuf;
            uint8_t outbuf_smallbuf[256];
            ptls_iovec_t input = { hash, sizeof(hash) };
            uint16_t selected_algorithm = 0;
            int num_algorithms = 0;
            uint16_t algorithms[16];
            memcpy(hash, h0, 32);
            while (signer->schemes[num_algorithms].scheme_id != UINT16_MAX && num_algorithms < 16) {
                algorithms[num_algorithms] = signer->schemes[num_algorithms].scheme_id;
                num_algorithms++;
            }

            ptls_buffer_init(&outbuf, outbuf_smallbuf, sizeof(outbuf_smallbuf));

            ret = ptls_mbedtls_sign_certificate(ctx.sign_certificate, NULL, NULL, &selected_algorithm,
                &outbuf, input, algorithms, num_algorithms);
            if (ret == 0) {
                DBG_PRINTF("Signed a message, key: %s, scheme: %x, signature size: %zu\n", path, selected_algorithm, outbuf.off);
            }
            else {
                DBG_PRINTF("Sign failed, key: %s, scheme: %x, signature size: %zu\n", path, selected_algorithm, outbuf.off);
            }
            ptls_buffer_dispose(&outbuf);
            ptls_mbedtls_dispose_sign_certificate(&signer->super);
        }
    }

    return ret;
}

int mbedtls_load_key_test()
{
    int ret = 0;


    /* Initialize the PSA crypto library. */
    if ((ret = ptls_mbedtls_init()) != 0) {
        DBG_PRINTF("%s", "psa_crypto_init fails.");
    }
    else {
        if (ret == 0) {
            ret = mbedtls_test_load_one_der_key(ASSET_RSA_KEY);
        }

        if (ret == 0) {
            ret = mbedtls_test_load_one_der_key(ASSET_SECP256R1_KEY);
        }

        if (ret == 0) {
            ret = mbedtls_test_load_one_der_key(ASSET_SECP384R1_KEY);
        }

        if (ret == 0) {
            ret = mbedtls_test_load_one_der_key(ASSET_SECP521R1_KEY);
        }

        if (ret == 0) {
            ret = mbedtls_test_load_one_der_key(ASSET_SECP256R1_PKCS8_KEY);
        }

        if (ret == 0) {
            ret = mbedtls_test_load_one_der_key(ASSET_RSA_PKCS8_KEY);
        }
#if 0
        /* Commenting out ED25519 for now, probably not supported yet in MBEDTLS/PSA */
        if (ret == 0) {
            ret = mbedtls_test_load_one_der_key(ASSET_ED25519_KEY);
        }
#endif
        /* Deinitialize the PSA crypto library. */
        ptls_mbedtls_free();
    }

    return ret;
}

/*
* Testing of failure modes.
* 
* Testing the various reasons why loading of key should fail:
* - key file does not exist
* - key file is empty, no PEM keyword
* - key file does not contain a key (we use a cert file for that)
* - key file is for ED25559, which is not supported
*/
int mbedtls_load_key_fail_test()
{
    int ret = 0;


    if ((ret = ptls_mbedtls_init()) != 0) {
        DBG_PRINTF("%s", "psa_crypto_init fails.");
    }
    else {
        if (ret == 0 && mbedtls_test_load_one_der_key(ASSET_NO_SUCH_FILE) == 0)
        {
            ret = -1;
        }

        if (ret == 0 && mbedtls_test_load_one_der_key(ASSET_NOT_A_PEM_FILE) == 0)
        {
            ret = -1;
        }

        if (ret == 0 && mbedtls_test_load_one_der_key(ASSET_RSA_CERT) == 0)
        {
            ret = -1;
        }

        if (ret == 0 && mbedtls_test_load_one_der_key(ASSET_ED25519_KEY) == 0)
        {
            ret = -1;
        }

        /* Deinitialize the PSA crypto library. */
        ptls_mbedtls_free();
    }

    return ret;
}


/* testing of public key export.
* The API to export a public key directly from the certificate is not present
* in older versions of MbedTLS, which might be installed by default in
* old versions of operating systems. Instead, we develop a robust way to
* export the key bits from the "raw public key" bytes in the certificate.
* But we need to test that this work properly, and we do that by
* comparing to the export of key bits from the private key, because for
* these tests we know the private key.
*/
int ptls_mbedtls_get_public_key_info(const unsigned char* pk_raw, size_t pk_raw_len,
    psa_key_attributes_t* attributes,
    size_t* key_index, size_t* key_length);

static int test_retrieve_pubkey_one(char const* key_path_ref, char const* cert_path_ref)
{
    int ret = 0;
    ptls_context_t ctx = { 0 };
    mbedtls_x509_crt* chain_head = (mbedtls_x509_crt*)malloc(sizeof(mbedtls_x509_crt));
    uint8_t pubkey_ref[1024];
    size_t pubkey_ref_len = 0;
    char cert_path[512];
    char key_path[512];

    if ((ret = picoquic_get_input_path(cert_path, sizeof(cert_path), picoquic_solution_dir, cert_path_ref)) != 0 ||
        (ret = picoquic_get_input_path(key_path, sizeof(key_path), picoquic_solution_dir, key_path_ref)) != 0) {
        DBG_PRINTF("Cannot build path from %s or %s", cert_path_ref, key_path_ref);
    }
    else {
        /* Preparation: load the certificate and the private key */
        if (chain_head == NULL) {
            ret = PTLS_ERROR_NO_MEMORY;
        }
        if (ret == 0) {
            mbedtls_x509_crt_init(chain_head);

            if (mbedtls_x509_crt_parse_file(chain_head, cert_path) != 0) {
                ret = -1;
            }
        }
        if (ret == 0) {
            ret = ptls_mbedtls_load_private_key(key_path, &ctx);
            if (ret != 0) {
                DBG_PRINTF("Cannot create load private key from: %s, ret = %d (0x%x, -0x%x)", key_path, ret, ret, (int16_t)-ret);
            }
        }
        /* Export the pubkey bits from the private key, for reference */
        if (ret == 0) {
            ptls_mbedtls_sign_certificate_t* signer = (ptls_mbedtls_sign_certificate_t*)
                (((unsigned char*)ctx.sign_certificate) - offsetof(struct st_ptls_mbedtls_sign_certificate_t, super));
            if (psa_export_public_key(signer->key_id, pubkey_ref, sizeof(pubkey_ref), &pubkey_ref_len) != 0) {
                ret = -1;
            }
        }
        /* Obtain the key bits from the certificate */
        if (ret == 0) {
            uint8_t* pk_raw = chain_head->pk_raw.p;
            size_t pk_raw_len = chain_head->pk_raw.len;
            size_t key_index;
            size_t key_length;
            psa_key_attributes_t attributes = psa_key_attributes_init();

            ret = ptls_mbedtls_get_public_key_info(pk_raw, pk_raw_len,
                &attributes, &key_index, &key_length);

            if (ret == 0) {
                /* Compare key bits */
                if (pubkey_ref_len != key_length ||
                    memcmp(pubkey_ref, chain_head->pk_raw.p + key_index, key_length) != 0) {
                    ret = -1;
                    DBG_PRINTF("%s", "Fail, retrieved key does not match public key.");
                }
            }
            else {
                DBG_PRINTF("%s", "Fail");
            }
        }
        /* Clean up */
        if (ctx.sign_certificate != NULL) {
            ptls_mbedtls_dispose_sign_certificate(ctx.sign_certificate);
        }
        if (chain_head != NULL) {
            mbedtls_x509_crt_free(chain_head);
        }
    }
    return ret;
}

int mbedtls_retrieve_pubkey_test()
{
    int ret = 0;
    if ((ret = ptls_mbedtls_init()) != 0) {
        DBG_PRINTF("%s", "psa_crypto_init fails.");
    }
    else {
        if (ret == 0) {
            ret = test_retrieve_pubkey_one(ASSET_RSA_KEY, ASSET_RSA_CERT);
        }

        if (ret == 0) {
            ret = test_retrieve_pubkey_one(ASSET_SECP256R1_KEY, ASSET_SECP256R1_CERT);
        }

        if (ret == 0) {
            ret = test_retrieve_pubkey_one(ASSET_SECP384R1_KEY, ASSET_SECP384R1_CERT);
        }

        if (ret == 0) {
            ret = test_retrieve_pubkey_one(ASSET_SECP521R1_KEY, ASSET_SECP521R1_CERT);
        }

        /* Deinitialize the PSA crypto library. */
        ptls_mbedtls_free();
    }

    return ret;
}


/*
* End to end testing of signature and verifiers:
* The general scenario is:
* - prepare a signature of a test string using a simulated
*   server programmed with a private key and a certificate
*   list.
* - verify the signature in a simulated client programmed
*   with a list of trusted certificates.
* 
* The test is configured with the file names for the key,
* certificate list, and trusted certificates. 
* 
* Ideally, we should be able to run the test by mixing and 
* matching mbedtls server or clients with other backends.
* However, using openssl will require some plumbing,
* which will be done when integrating this code in 
* picotls. For now, we will only do self tests, and test with
* minicrypto if the key is supported.
*/

const unsigned char test_sign_verify_message[] = {
    0,  1,  2,  3,  4,  5,  6,  7,  8,  9 , 10, 11, 12, 13, 14, 15, 16, 17, 18, 19,
    20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39,
    40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59,
    60, 61, 62, 63, 64
};
const size_t test_sign_verify_message_size = sizeof(test_sign_verify_message);

uint16_t test_sign_signature_algorithms[] = {
    0x0401, 0x0403, 0x501, 0x0503, 0x0601, 0x0603,
    0x0804, 0x0805, 0x0806, 0x0807, 0x0808
};

size_t num_test_sign_signature_algorithms = sizeof(test_sign_signature_algorithms) / sizeof(uint16_t);

static int test_sign_init_server_mbedtls(ptls_context_t* ctx, char const* key_path, char const* cert_path)
{
    int ret = ptls_mbedtls_load_private_key(key_path, ctx);
    if (ret == 0 &&
        (ctx->certificates.list = picoquic_mbedtls_get_certs_from_file(cert_path, &ctx->certificates.count)) == NULL){
        ret = -1;
    }
    return ret;
}

static int test_sign_init_server_minicrypto(ptls_context_t* ctx, char const* key_path, char const* cert_path)
{
    int ret = ptls_minicrypto_load_private_key(ctx, key_path);
    if (ret == 0) {
        ret = ptls_load_certificates(ctx, cert_path);
    }
    return ret;
}

static void test_sign_free_certificates(ptls_context_t* ctx)
{
    if (ctx->certificates.list != NULL) {
        for (int i = 0; i < ctx->certificates.count; i++) {
            free(ctx->certificates.list[i].base);
        }
        free(ctx->certificates.list);
    }
    ctx->certificates.list = NULL;
    ctx->certificates.count = 0;
}

static void test_sign_free_context(ptls_context_t* ctx, int config)
{
    /* Free the server context */
    if (ctx == NULL) {
        return;
    }
    test_sign_free_certificates(ctx);
    if (ctx->sign_certificate != NULL) {
        switch (config) {
        case 0:
            ptls_mbedtls_dispose_sign_certificate(ctx->sign_certificate);
            break;
        case 1:
        default:
            free(ctx->sign_certificate);
            ctx->sign_certificate = NULL;
        }
    }

    if (ctx->verify_certificate != NULL) {
        switch (config) {
        case 0:
            ptls_mbedtls_dispose_verify_certificate(ctx->verify_certificate);
            ctx->verify_certificate = NULL;
            break;
        default:
            break;
        }
    }

    free(ctx);
}

static ptls_context_t* test_sign_set_ptls_context(char const* key_path, char const* cert_path, char const* trusted_path, int is_server, int config)
{
    int ret = 0;
    ptls_context_t* ctx = (ptls_context_t*)malloc(sizeof(ptls_context_t));

    if (ctx == NULL) {
        return NULL;
    }

    memset(ctx, 0, sizeof(ptls_context_t));
    ctx->get_time = &ptls_get_time;

    switch (config) {
    case 0:
        ctx->random_bytes = ptls_mbedtls_random_bytes;
    case 1:
    default:
        break;
    }

    if (is_server) {
        /* First, create the "signer" plug-in */
        switch (config) {
        case 0: /* MbedTLS */
            ret = test_sign_init_server_mbedtls(ctx, key_path, cert_path);
            break;
        case 1: /* Minicrypto */
            ret = test_sign_init_server_minicrypto(ctx, key_path, cert_path);
            break;
        default:
            ret = -1;
            break;
        }
    }
    else {
        /* Initialize the client verify context */
        unsigned int is_cert_store_not_empty = 0;
        switch (config) {
        case 0: /* MbedTLS */
            ctx->verify_certificate = ptls_mbedtls_get_certificate_verifier(trusted_path,
                &is_cert_store_not_empty);
            break;
        default:
            ret = -1;
            break;
        }
    }

    if (ret != 0) {
        /* Release and return NULL */
        test_sign_free_context(ctx, config);
        ctx = NULL;
    }
    return ctx;
}

static int test_sign_verify_one(char const* key_path_ref, char const * cert_path_ref, char const * trusted_path_ref,
    char const * server_name, int server_config, int client_config)
{
    int ret = 0;
    char cert_path[512];
    char key_path[512];
    char trusted_path[512];

    if ((ret = picoquic_get_input_path(cert_path, sizeof(cert_path), picoquic_solution_dir, cert_path_ref)) != 0 ||
        (ret = picoquic_get_input_path(key_path, sizeof(key_path), picoquic_solution_dir, key_path_ref)) != 0 ||
        (ret = picoquic_get_input_path(trusted_path, sizeof(trusted_path), picoquic_solution_dir, trusted_path_ref)) != 0) {
        DBG_PRINTF("Cannot build path from %s, %s or %s", cert_path_ref, key_path_ref, trusted_path_ref);
    }
    else {
        ptls_context_t* server_ctx = test_sign_set_ptls_context(key_path, cert_path, trusted_path, 1, server_config); 
        ptls_context_t* client_ctx = test_sign_set_ptls_context(key_path, cert_path, trusted_path, 0, client_config);
        ptls_t* client_tls = NULL;
        ptls_t* server_tls = NULL;
        uint16_t selected_algorithm = 0;
        uint8_t signature_smallbuf[256];
        ptls_buffer_t signature;
        struct {
            int (*cb)(void *verify_ctx, uint16_t algo, ptls_iovec_t data, ptls_iovec_t signature);
            void *verify_ctx;
        } certificate_verify;
        ptls_iovec_t input;

        input.base = (uint8_t*)test_sign_verify_message;
        input.len = test_sign_verify_message_size;

        ptls_buffer_init(&signature, signature_smallbuf, sizeof(signature_smallbuf));

        if (server_ctx == NULL || client_ctx == NULL) {
            ret = -1;
        }

        if (ret == 0) {
            /* Then, create a tls context for the server. */
            server_tls = ptls_new(server_ctx, 1);
            if (server_tls == NULL) {
                DBG_PRINTF("ptls_new (server, %s) returns NULL", key_path);
                ret = -1;
            }
        }

        if (ret == 0) {
            /* Then, create the signature messages */
            ret = server_ctx->sign_certificate->cb(server_ctx->sign_certificate, server_tls, NULL,
                &selected_algorithm, &signature, input,
                test_sign_signature_algorithms, num_test_sign_signature_algorithms);
            if (ret != 0) {
                DBG_PRINTF("sign_certificate (%s) returns 0x%x (%d)", key_path, ret, ret);
            }
        }

        if (ret == 0) {
            /* Then, create a tls context for the client. */
            client_tls = ptls_new(client_ctx, 0);
            if (client_tls == NULL) {
                    DBG_PRINTF("ptls_new (client, %s) returns NULL", key_path);
                ret = -1;
            }
        }

        if (ret == 0) {
            /* verify the certificates */
            ret = client_ctx->verify_certificate->cb(client_ctx->verify_certificate, client_tls, server_name,
                &certificate_verify.cb, &certificate_verify.verify_ctx,
                server_ctx->certificates.list, server_ctx->certificates.count);
            if (ret == 0) {
                /* verify the signature */
                ptls_iovec_t sig;
                sig.base = signature.base;
                sig.len = signature.off;

                ret = certificate_verify.cb(certificate_verify.verify_ctx, selected_algorithm, input, sig);
                if (ret != 0) {
                    DBG_PRINTF("verify_signature (%s) returns 0x%x (%d)", key_path, ret, ret);
                    ret = -1;
                }
            } 
            else if (certificate_verify.cb != NULL) {
                /* In case of failure, call with null args to free memory. */
                DBG_PRINTF("verify_certificate (%s) returns 0x%x (%d)", cert_path, ret, ret);
                ptls_iovec_t empty;
                empty.base = NULL;
                empty.len = 0;
                (void)certificate_verify.cb(certificate_verify.verify_ctx, 0, empty, empty);
            }
        }
        if (ret == 0) {
            DBG_PRINTF("verify_signature (%s) and cert (%s) succeeds.", key_path, cert_path);
        }

        ptls_buffer_dispose(&signature);

        if (client_tls != NULL) {
            ptls_free(client_tls);
        }
        if (server_tls != NULL) {
            ptls_free(server_tls);
        }

        test_sign_free_context(server_ctx, server_config);
        test_sign_free_context(client_ctx, client_config);
    }
    return ret;
}

int mbedtls_sign_verify_test()
{
    int ret = 0;

    if ((ret = ptls_mbedtls_init()) != 0) {
        DBG_PRINTF("%s", "psa_crypto_init fails.");
    }
    else {
        if (ret == 0) {
            ret = test_sign_verify_one(ASSET_RSA_KEY, ASSET_RSA_CERT, ASSET_TEST_CA, ASSET_RSA_NAME, 0, 0);
        }

        if (ret == 0) {
            ret = test_sign_verify_one(ASSET_SECP256R1_KEY, ASSET_SECP256R1_CERT, ASSET_TEST_CA, ASSET_SECP256R1_NAME, 0, 0);
        }

        if (ret == 0) {
            ret = test_sign_verify_one(ASSET_SECP384R1_KEY, ASSET_SECP384R1_CERT, ASSET_TEST_CA, ASSET_SECP384R1_NAME, 0, 0);
        }

        if (ret == 0) {
            ret = test_sign_verify_one(ASSET_SECP521R1_KEY, ASSET_SECP521R1_CERT, ASSET_TEST_CA, ASSET_SECP521R1_NAME, 0, 0);
        }

        if (ret == 0) {
            ret = test_sign_verify_one(ASSET_SECP256R1_PKCS8_KEY, ASSET_SECP256R1_PKCS8_CERT, ASSET_TEST_CA, ASSET_SECP256R1_PKCS8_NAME, 0, 0);
        }

        /* Deinitialize the PSA crypto library. */
        ptls_mbedtls_free();
    }
    return ret;
}

int mbedtls_configure_test()
{
    int ret = 0;
    int cipher_suite_match_low = 0;
    int cipher_suite_match_high = 0;
    int key_exchange_max = 0;
    ptls_cipher_suite_t* targets[3] = {
        &ptls_mbedtls_aes128gcmsha256,
        &ptls_mbedtls_aes256gcmsha384,
        &ptls_mbedtls_chacha20poly1305sha256
    };
    ptls_key_exchange_algorithm_t* exchange[3] = {
        &ptls_mbedtls_secp256r1, &ptls_mbedtls_x25519 };

    /* Cleanup previous initiation of the TLS API and do it cleanly. */
    picoquic_tls_api_reset(TLS_API_INIT_FLAGS_NO_OPENSSL |
        TLS_API_INIT_FLAGS_NO_FUSION);
    /* Verify that the negotiated parameters have the expected value */
    for (int i = 0; i < PICOQUIC_CIPHER_SUITES_NB_MAX; i++) {
        for (int j = 0; j < 3; j++) {
            if (targets[j] == picoquic_cipher_suites[i].high_memory_suite) {
                cipher_suite_match_high |= (1 << j);
            }
            if (targets[j] == picoquic_cipher_suites[i].low_memory_suite) {
                cipher_suite_match_low |= (1 << j);
            }
        }
        if (cipher_suite_match_low == 0x7 && cipher_suite_match_high == 0x7) {
            break;
        }
    }
    if (cipher_suite_match_low != 0x7 || cipher_suite_match_high != 0x7) {
        DBG_PRINTF("Suites registration test fails, expected 0x%x, 0x%x, got 0x%x, 0x%x",
            7, 7, cipher_suite_match_low, cipher_suite_match_high);
        ret = -1;
    }

    if (picoquic_key_exchange_secp256r1[0] != &ptls_mbedtls_secp256r1) {
        DBG_PRINTF("%s", "key_exchange_secp256r1 does not match");
        ret = -1;
    }

    for (int i = 0; i < PICOQUIC_KEY_EXCHANGES_NB_MAX; i++) {
        for (int j = 0; j < 2; j++) {
            if (exchange[j] == picoquic_key_exchanges[i]) {
                key_exchange_max |= (1 << j);
            }
            if (key_exchange_max == 0x3) {
                break;
            }
        }
    }

    if (key_exchange_max != 0x3) {
        DBG_PRINTF("Exchange registration test fails, expected 0x%x, got 0x%x",
            7, key_exchange_max);
        ret = -1;
    }

    if (picoquic_set_private_key_from_file_fn != ptls_mbedtls_load_private_key ||
        picoquic_dispose_sign_certificate_fn != ptls_mbedtls_dispose_sign_certificate ||
        picoquic_get_certs_from_file_fn != picoquic_mbedtls_get_certs_from_file) {
        DBG_PRINTF("%s", "At least one private key function does not match mbedtls");
        ret = -1;
    }

    if (picoquic_get_certificate_verifier_fn != picoquic_mbedtls_get_certificate_verifier ||
        picoquic_dispose_certificate_verifier_fn != ptls_mbedtls_dispose_verify_certificate) {
        DBG_PRINTF("%s", "At least one verify certs function does not match mbedtls");
        ret = -1;
    }

    if (picoquic_crypto_random_provider_fn != ptls_mbedtls_random_bytes) {
        DBG_PRINTF("%s", "Crypto random provider does not match mbedtls");
        ret = -1;
    }

    /* Reset configuration to default after test */
    picoquic_tls_api_reset(0);

    return ret;
}


#endif
