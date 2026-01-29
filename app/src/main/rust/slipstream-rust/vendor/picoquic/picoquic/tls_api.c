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


/* The tls_api.c file provides the glue between the QUIC protocol code and the
 * implementation of TLS 1.3 in picotls. That glue code has two main components:
 *
 * - matching TLS concepts such as handshake events with QUIC protocol events.
 * - providing implementation of cryptographic algorithms.
 *
 * The bulk of the code corresponds to the first objective, the implementation
 * of generic interactions with picotls. But this implementation relies on
 * implementation of cryptographic primitives. The initial version of
 * picoquic relies on OpenSSL for the implementation of these primitives,
 * which limits portability of Picoquic to platforms that support OpenSSL.
 *
 * Picotls includes API for providing a variety of implementations of the
 * cryptographic algorithms, linking with external libraries like OpenSSL or
 * minimal implementations like "minicrypto". Our goal there is to provide a
 * "crypto-provider" API so that applications can decide which provider they
 * prefer.
 *
 * As an intermediate state towards that goal, we isolate the dependencies on
 * OpenSSL in a small set of function calls.
 */

#ifdef _WINDOWS
#include "wincompat.h"
#ifndef PTLS_WITHOUT_FUSION
/* temporary disabling of PTLS_FUSION until memory alignment issues are fixed*/
#define PTLS_WITHOUT_FUSION
#endif
#endif

#include <stddef.h>
#include <stdlib.h>
#include "picotls.h"
#include "picoquic_internal.h"
#ifndef PTLS_WITHOUT_OPENSSL
#include "picotls/openssl.h"
#endif
#include "tls_api.h"
#include "picoquic_crypto_provider_api.h"
#include <stdio.h>
#include <string.h>
#include "picoquic_unified_log.h"

#define container_of(ptr, type, member) ((type *)((char *)(ptr) - offsetof(type, member)))

#ifndef UNREFERENCED_PARAMETER
#define UNREFERENCED_PARAMETER(x) (void)(x)
#endif

#define PICOQUIC_TRANSPORT_PARAMETERS_TLS_EXTENSION_DRAFT 0xFFA5
#define PICOQUIC_TRANSPORT_PARAMETERS_TLS_EXTENSION_V1 0x39
#define PICOQUIC_TRANSPORT_PARAMETERS_MAX_SIZE 2048

typedef struct st_picoquic_tls_ctx_t {
    ptls_t* tls;
    picoquic_cnx_t* cnx;
    int client_mode;
    ptls_raw_extension_t ext[2];
    ptls_handshake_properties_t handshake_properties;
    ptls_iovec_t* alpn_vec;
    size_t alpn_vec_size;
    size_t alpn_count;
    uint8_t* ext_data;
    size_t ext_data_size;
    uint8_t app_secret_enc[PTLS_MAX_DIGEST_SIZE];
    uint8_t app_secret_dec[PTLS_MAX_DIGEST_SIZE];
} picoquic_tls_ctx_t;

struct st_picoquic_log_event_t {
    ptls_log_event_t super;
    FILE* fp;
};


/* This first part of this file provides a set of function for accessing
 * the cryptographic libraries.
 */
#define CRYPTO_PROVIDERS_REGION 1

#ifdef CRYPTO_PROVIDERS_REGION

struct st_picoquic_cipher_suites_t picoquic_cipher_suites[PICOQUIC_CIPHER_SUITES_NB_MAX + 1];

#define PICOQUIC_KEY_EXCHANGES_NB_MAX 4
ptls_key_exchange_algorithm_t* picoquic_key_exchanges[PICOQUIC_KEY_EXCHANGES_NB_MAX + 1];
ptls_key_exchange_algorithm_t* picoquic_key_exchange_secp256r1[2];
picoquic_set_private_key_from_file_t picoquic_set_private_key_from_file_fn = NULL;
picoquic_dispose_sign_certificate_t picoquic_dispose_sign_certificate_fn = NULL;
picoquic_get_certs_from_file_t picoquic_get_certs_from_file_fn = NULL;
picoquic_get_certificate_verifier_t picoquic_get_certificate_verifier_fn = NULL;
picoquic_dispose_certificate_verifier_t picoquic_dispose_certificate_verifier_fn = NULL;
picoquic_set_tls_root_certificates_t picoquic_set_tls_root_certificates_fn = NULL;
picoquic_explain_crypto_error_t picoquic_explain_crypto_error_fn = NULL;
picoquic_clear_crypto_errors_t picoquic_clear_crypto_errors_fn = NULL;
picoquic_crypto_random_provider_t picoquic_crypto_random_provider_fn = NULL;

/* Initialization of the cryptographic tables and functions
 * 
 * The code calls a series of potential crypto providers. 
 * The personalization relies on compile mode parameters
 * such as "ifdef" and real time flags assessed in each
 * per provider module.
 */
#ifdef PICOQUIC_WITH_MBEDTLS
void picoquic_mbedtls_load(int unload);
#endif
#if (!defined(_WINDOWS) || defined(_WINDOWS64)) && !defined(PTLS_WITHOUT_FUSION)
void picoquic_ptls_fusion_load(int unload);
#endif
/* void picoquic_bcrypt_load(int unload); */
#ifndef PTLS_WITHOUT_OPENSSL
void picoquic_ptls_openssl_load(int unload);
#endif
void picoquic_ptls_minicrypto_load(int unload);

/* Flags controlling which providers will be launched.
 * This is means to be used mostly in tests. In production,
 * it is better to just use compile options.
 */
static uint64_t tls_api_init_flags = 0;
static int tls_api_is_init = 0;

/* Initialization of providers. The latest registration wins.
* This implies an initialization order from least desirable
* to most desirable.
 */
void picoquic_tls_api_init_providers(int unload)
{
    if ((tls_api_init_flags & TLS_API_INIT_FLAGS_NO_MINICRYPTO) == 0) {
        DBG_PRINTF("%s minicrypto", (unload)?"Unloading":"Loading");
        picoquic_ptls_minicrypto_load(unload);
    }
#ifndef PTLS_WITHOUT_OPENSSL
    if ((tls_api_init_flags & TLS_API_INIT_FLAGS_NO_OPENSSL) == 0) {
        DBG_PRINTF("%s openssl", (unload)?"Unloading":"Loading");
        picoquic_ptls_openssl_load(unload);
    }
#else
    if (unload == 0 && tls_api_is_init == 0) {
        DBG_PRINTF("%s", "Picoquic was compiled without OpenSSL");
    }
#endif
    // picoquic_bcrypt_load(unload);
#if (!defined(_WINDOWS) || defined(_WINDOWS64)) && !defined(PTLS_WITHOUT_FUSION)
    if ((tls_api_init_flags & TLS_API_INIT_FLAGS_NO_FUSION) == 0) {
        DBG_PRINTF("%s fusion", (unload)?"Unloading":"Loading");
        picoquic_ptls_fusion_load(unload);
    }
#else
    if (unload == 0 && tls_api_is_init == 0) {
        DBG_PRINTF("%s", "Picoquic was compiled without Fusion");
    }
#endif

#ifdef PICOQUIC_WITH_MBEDTLS
    if ((tls_api_init_flags & TLS_API_INIT_FLAGS_NO_MBEDTLS) == 0) {
        DBG_PRINTF("%s MbedTLS", (unload)?"Unloading":"Loading");
        picoquic_mbedtls_load(unload);
    }
#endif
}

static void picoquic_tls_api_zero()
{
    memset(picoquic_cipher_suites, 0, sizeof(picoquic_cipher_suites));
    memset((void*)picoquic_key_exchanges, 0, sizeof(picoquic_key_exchanges));
    memset((void*)picoquic_key_exchange_secp256r1, 0, sizeof(picoquic_key_exchange_secp256r1));

    picoquic_set_private_key_from_file_fn = NULL;
    picoquic_dispose_sign_certificate_fn = NULL;
    picoquic_get_certs_from_file_fn = NULL;

    picoquic_get_certificate_verifier_fn = NULL;
    picoquic_dispose_certificate_verifier_fn = NULL;
    picoquic_set_tls_root_certificates_fn = NULL;

    picoquic_explain_crypto_error_fn = NULL;
    picoquic_clear_crypto_errors_fn = NULL;
 
    picoquic_crypto_random_provider_fn = NULL;
}

void picoquic_tls_api_init()
{
    if (!tls_api_is_init) {
        picoquic_tls_api_zero();
        picoquic_tls_api_init_providers(0);
        tls_api_is_init = 1;
    }
}

void picoquic_tls_api_unload()
{
    if (tls_api_is_init) {
        picoquic_tls_api_init_providers(1);
        picoquic_tls_api_zero();
        tls_api_is_init = 0;
    }
}

void picoquic_tls_api_reset(uint64_t init_flags)
{
    if (tls_api_is_init) {
        tls_api_is_init = 0;
        picoquic_tls_api_init_providers(2);
        picoquic_tls_api_zero();
    }
    tls_api_init_flags = init_flags;
    picoquic_tls_api_init_providers(0);
    tls_api_is_init = 1;
}
/* Registration of ciphersuites.
 * This API is called by crypto providers to register available cipher suites.
 */
void picoquic_register_ciphersuite(ptls_cipher_suite_t* suite, int is_low_memory)
{
    for (int i = 0; i < PICOQUIC_CIPHER_SUITES_NB_MAX; i++) {
        if (picoquic_cipher_suites[i].high_memory_suite == NULL ||
            picoquic_cipher_suites[i].high_memory_suite->id == suite->id) {
            /* Replace the lower priority provider if present! */
            picoquic_cipher_suites[i].high_memory_suite = suite;
            if (is_low_memory) {
                picoquic_cipher_suites[i].low_memory_suite = suite;
            }
            break;
        }
    }
}

/* Registration of key exchange algorithms */
void picoquic_register_key_exchange_algorithm(ptls_key_exchange_algorithm_t* key_exchange)
{
    for (int i = 0; i < PICOQUIC_KEY_EXCHANGES_NB_MAX; i++) {
        if (picoquic_key_exchanges[i] == NULL ||
            picoquic_key_exchanges[i]->id == key_exchange->id) {
            /* Replace the lower priority provider if present! */
            picoquic_key_exchanges[i] = key_exchange;
            break;
        }
    }

    if (key_exchange->id == PICOQUIC_GROUP_SECP256R1) {
        /* Replace the lower priority provider if present! */
        picoquic_key_exchange_secp256r1[0] = key_exchange;
    }
}

void picoquic_register_tls_key_provider_fn(
    picoquic_set_private_key_from_file_t set_key_from_key_file_fn,
    picoquic_dispose_sign_certificate_t dispose_sign_certificate_fn,
    picoquic_get_certs_from_file_t get_certs_from_file_fn)
{
    DBG_PRINTF("%s", "Loading set key functions.");
    picoquic_set_private_key_from_file_fn = set_key_from_key_file_fn;
    picoquic_dispose_sign_certificate_fn = dispose_sign_certificate_fn;
    picoquic_get_certs_from_file_fn = get_certs_from_file_fn;
}

void picoquic_register_verify_certificate_fn(picoquic_get_certificate_verifier_t certificate_verifier_fn,
    picoquic_dispose_certificate_verifier_t dispose_certificate_verifier_fn,
    picoquic_set_tls_root_certificates_t set_tls_root_certificates_fn)
{
    picoquic_get_certificate_verifier_fn = certificate_verifier_fn;
    picoquic_dispose_certificate_verifier_fn = dispose_certificate_verifier_fn;
    picoquic_set_tls_root_certificates_fn = set_tls_root_certificates_fn;
}

void picoquic_register_explain_crypto_error_fn(picoquic_explain_crypto_error_t explain_crypto_error_fn,
    picoquic_clear_crypto_errors_t clear_crypto_errors_fn)
{
    picoquic_explain_crypto_error_fn = explain_crypto_error_fn;
    picoquic_clear_crypto_errors_fn = clear_crypto_errors_fn;
}

void picoquic_register_crypto_random_provider_fn(picoquic_crypto_random_provider_t crypto_random_provider_fn)
{
    picoquic_crypto_random_provider_fn = crypto_random_provider_fn;
}

/* List of cipher suites that are suitable for this context */
static int picoquic_set_cipher_suite_list(ptls_cipher_suite_t** selected_suites, int cipher_suite_id, int use_low_memory)
{
    int nb_suites = 0;

    for (int i = 0; i < PICOQUIC_CIPHER_SUITES_NB_MAX && nb_suites < 4; i++) {
        if (picoquic_cipher_suites[i].high_memory_suite == NULL) {
            break;
        }
        if (cipher_suite_id == 0 || cipher_suite_id == picoquic_cipher_suites[i].high_memory_suite->id) {
            if (use_low_memory) {
                if (picoquic_cipher_suites[i].low_memory_suite != NULL) {
                    selected_suites[nb_suites++] = picoquic_cipher_suites[i].low_memory_suite;
                }
            }
            else {
                selected_suites[nb_suites++] = picoquic_cipher_suites[i].high_memory_suite;
            }
        }
    }

    return nb_suites;
}

/* Set the cipher suites */
static int picoquic_set_cipher_suite_in_ctx(ptls_context_t* ctx, int cipher_suite_id, int use_low_memory)
{
    ptls_cipher_suite_t** selected_suites = (ptls_cipher_suite_t**)malloc(sizeof(ptls_cipher_suite_t*) * 4);
    int nb_suites = 0;
    int ret = 0;

    /* Remove previous suites (if any) */
    if (ctx->cipher_suites != NULL) {
        free((void*)ctx->cipher_suites);
    }

    if (ctx == NULL || selected_suites == NULL) {
        ret = -1;
    }
    else {
        nb_suites = picoquic_set_cipher_suite_list(selected_suites, cipher_suite_id, use_low_memory);

        if (nb_suites == 0) {
            ctx->cipher_suites = NULL;
            ret = -1;
        }
        else {
            while (nb_suites < 4) {
                selected_suites[nb_suites++] = NULL;
            }
            ctx->cipher_suites = selected_suites;
        }
    }

    if (ret != 0 && selected_suites != NULL) {
        free((void*)selected_suites);
    }
    return ret;
}

int picoquic_set_cipher_suite(picoquic_quic_t* quic, int cipher_suite_id)
{
    ptls_context_t* ctx = (ptls_context_t*)quic->tls_master_ctx;
    return (picoquic_set_cipher_suite_in_ctx(ctx, cipher_suite_id, quic->use_low_memory));
}

/* Obtain AES128GCM SHA256, AES256GCM_SHA384 or CHACHA20 suite according to current provider */
ptls_cipher_suite_t* picoquic_get_selected_cipher_suite_by_id(int cipher_suite_id, int use_low_memory)
{
    ptls_cipher_suite_t* selected_suites[4];
    ptls_cipher_suite_t* cipher;
    int nb_suites = picoquic_set_cipher_suite_list(selected_suites, cipher_suite_id, use_low_memory);
    if (nb_suites <= 0) {
        cipher = NULL;
    }
    else {
        cipher = selected_suites[0];
    }
    
    return cipher;
}

static ptls_cipher_suite_t* picoquic_get_cipher_suite_by_id(int cipher_suite_id, int use_low_memory)
{
    return picoquic_get_selected_cipher_suite_by_id(cipher_suite_id, use_low_memory);
}

static ptls_cipher_algorithm_t* picoquic_get_ecb_cipher_by_id(const char* ecb_cipher_name)
{
    ptls_cipher_algorithm_t* ecb_cipher = NULL;

    for (int j = 0; j < 2 && ecb_cipher == NULL; j++) {
        for (int i = 0; i < PICOQUIC_CIPHER_SUITES_NB_MAX && ecb_cipher == NULL; i++) {
            ptls_cipher_suite_t* suite = (j == 0) ?
                picoquic_cipher_suites[i].high_memory_suite :
                picoquic_cipher_suites[i].low_memory_suite;

            if (suite != NULL && suite->aead != NULL && suite->aead->ecb_cipher != NULL &&
                strcmp(suite->aead->ecb_cipher->name, ecb_cipher_name) == 0){
                ecb_cipher = suite->aead->ecb_cipher;
                break;
            }
        }
    }
    return ecb_cipher;
}

/* Obtain an AES128 ECB cipher, which is required for CID encryption
* according to the CID for load balancer specification.
* TODO: rewrite this as a call to the generic "get cipher suite" API,
* then derive the ECB function from the selection of the AEAD function.
* This will obviate the need of providing a specific API.
*/
void* picoquic_aes128_ecb_create(int is_enc, const void* ecb_key)
{
    void* created = NULL;
    ptls_cipher_algorithm_t* ecb_cipher = picoquic_get_ecb_cipher_by_id("AES128-ECB");

    if (ecb_cipher != NULL) {
        created = (void*)ptls_cipher_new(ecb_cipher, is_enc, ecb_key);
    }
    
    return created;
}

/* Obtain a hash algorithm from the table of supported cipher suites.*/
ptls_hash_algorithm_t* picoquic_get_hash_algorithm_by_name(const char* hash_algorithm_name)
{
    ptls_hash_algorithm_t* hash = NULL;

    for (int i = 0; i < PICOQUIC_CIPHER_SUITES_NB_MAX && hash == NULL; i++) {
        if (picoquic_cipher_suites[i].high_memory_suite == NULL) {
            break;
        }
        if (strcmp(picoquic_cipher_suites[i].high_memory_suite->hash->name, hash_algorithm_name) == 0) {
            hash = picoquic_cipher_suites[i].high_memory_suite->hash;
            break;
        }
    }
    return hash;
}

/* Obtain the SHA256 hash, used to derive some secrets
*/
ptls_hash_algorithm_t* picoquic_get_sha256()
{
    return picoquic_get_hash_algorithm_by_name("sha256");
}

void* picoquic_get_sha256_v()
{
    return (void*)picoquic_get_sha256();
}

/* Export hash functions so applications do not need to access picotls.
* It is not clear that these functions are actually used by applications.
*/

void* picoquic_hash_create(char const* algorithm_name) {
    ptls_hash_context_t* ctx = NULL;
    ptls_hash_algorithm_t*hash = picoquic_get_hash_algorithm_by_name(algorithm_name);

    if (hash != NULL) {
        ctx = hash->create();
    }

    return (void*)ctx;
}

size_t picoquic_hash_get_length(char const* algorithm_name) {
    size_t len = 0;
    ptls_hash_algorithm_t*hash = picoquic_get_hash_algorithm_by_name(algorithm_name);

    if (hash != NULL) {
        len = hash->digest_size;
    }

    return len;
}

/* Set the supported key exchange in the TLS context
* Supported algorithms are defined by keyexchange_id
* - 0: set all supported algorithms
* - PICOQUIC_GROUP_SECP256R1: secp256r1
*/

static int picoquic_set_key_exchange_in_ctx(ptls_context_t* ctx, int key_exchange_id)
{
    int ret = 0;

    switch (key_exchange_id) {
    case 0:
        ctx->key_exchanges = picoquic_key_exchanges;
        break;
    case PICOQUIC_GROUP_SECP256R1:
        if (picoquic_key_exchange_secp256r1[0] == NULL) {
            ret = -1;
        }
        else {
            ctx->key_exchanges = picoquic_key_exchange_secp256r1;
        }
        break;
    default:
        ret = -1;
        break;
    }

    return ret;
}

int picoquic_set_key_exchange(picoquic_quic_t* quic, int key_exchange_id)
{
    int ret = 0;
    ptls_context_t* ctx = (ptls_context_t*)quic->tls_master_ctx;

    ret = picoquic_set_key_exchange_in_ctx(ctx, key_exchange_id);
    return ret;
}

#endif /* CRYPTO_PROVIDERS_REGION */

#define CRYPTO_PROVIDERS_API_REGION 1

#ifdef CRYPTO_PROVIDERS_API_REGION
/* Implementation of generic setup functions using the default present
 * in this file. These functions may be declared in tls_api.h.
 */


/* Set the cryptographic random provider */
static void picoquic_set_random_provider_in_ctx(ptls_context_t* ctx)
{
    ctx->random_bytes = picoquic_crypto_random_provider_fn;
}

/* Set the certificate signing function in the context */
static int set_private_key_from_file(char const* keypem, ptls_context_t* ctx)
{
    if (picoquic_set_private_key_from_file_fn == NULL) {
        return -1;
    }
    else {
        return picoquic_set_private_key_from_file_fn(keypem, ctx);
    }
}

int picoquic_set_private_key_from_file(picoquic_quic_t* quic, char const* file_name)
{
    return set_private_key_from_file(file_name, quic->tls_master_ctx);
}

/* Clear certificate objects allocated by the crypto stack for a certficate
*/
void picoquic_dispose_sign_certificate(ptls_context_t* ctx)
{
    if (ctx->sign_certificate != NULL) {
        if (picoquic_dispose_sign_certificate_fn != NULL) {
            /* we expect the dispose function to free dependencies,
             * but not the certificate itself. */
            picoquic_dispose_sign_certificate_fn(ctx->sign_certificate);
        }
        free(ctx->sign_certificate);
        ctx->sign_certificate = NULL;
    }
}

/* Read certificates from a file
 */
ptls_iovec_t* picoquic_get_certs_from_file(char const* file_name, size_t * count)
{
    if (picoquic_get_certs_from_file_fn == NULL) {
        return NULL;
    }
    else {
        return picoquic_get_certs_from_file_fn(file_name, count);
    }
}

/* Return the certificate verifier callback provided by the crypto stack */
ptls_verify_certificate_t* picoquic_get_certificate_verifier(char const* cert_root_file_name,
    unsigned int* is_cert_store_not_empty, picoquic_free_verify_certificate_ctx * p_free_certificate_verifier_fn)
{
    if (picoquic_get_certificate_verifier_fn == NULL) {
        return NULL;
    }
    else {
        return picoquic_get_certificate_verifier_fn(cert_root_file_name, is_cert_store_not_empty,
            p_free_certificate_verifier_fn);
    }
}

/* Release a verify certificate callback function.
 * TODO: there should be a delete function documented at the same time the
 * callback is installed, to allow replacing one type of callback by another.
 */
void picoquic_dispose_certificate_verifier(ptls_verify_certificate_t* verifier) {
    if (picoquic_dispose_certificate_verifier_fn != NULL) {
        picoquic_dispose_certificate_verifier_fn(verifier);
    }
}

/* Set the list of root certificates used by the client. */
int picoquic_set_tls_root_certificates(picoquic_quic_t* quic, ptls_iovec_t* certs, size_t count)
{
    int ret = -1;

    if (picoquic_set_tls_root_certificates_fn != NULL) {
        if ((ret = picoquic_set_tls_root_certificates_fn(quic->tls_master_ctx, certs, count)) == 0){
            quic->is_cert_store_not_empty = 1;
        }
    }
    return ret;
}
/* Provide a crypto provider independent interface to crypto errors.
 * Can be called repeatedly until no error needs to be signalled. 
 */
int picoquic_explain_crypto_error(char const** err_file, int* err_line)
{
    int ret = 0;
    if (picoquic_explain_crypto_error_fn != NULL) {
        ret = picoquic_explain_crypto_error_fn(err_file, err_line);
    }
    return ret;
}

/* Clear the recorded errors in the crypto stack, e.g. before
 * processing a new message.
 */
void picoquic_clear_crypto_errors()
{
    if (picoquic_clear_crypto_errors_fn != NULL) {
        picoquic_clear_crypto_errors_fn();
    }
}

#endif /* CRYPTO_PROVIDERS_API_REGION */

#define CRYPTO_PROVIDERS_GENERIC_REGION 1

#ifdef CRYPTO_PROVIDERS_GENERIC_REGION
/* Generic APIs, derived from the APi to crypto providers */


/* Get the AES128GCM+SHA256 cipher suite required for Initial packets */
static ptls_cipher_suite_t* picoquic_get_aes128gcm_sha256(int use_low_memory)
{
    return picoquic_get_cipher_suite_by_id(PICOQUIC_AES_128_GCM_SHA256, use_low_memory);
}

void* picoquic_get_aes128gcm_sha256_v(int use_low_memory)
{
    return (void*)picoquic_get_aes128gcm_sha256(use_low_memory);
}

void* picoquic_get_aes128gcm_v(int use_low_memory)
{
    void* aead = NULL;
    ptls_cipher_suite_t* cipher = picoquic_get_aes128gcm_sha256(use_low_memory);

    if (cipher != NULL) {
        aead = (void*)(cipher->aead);
    }
    return aead;
}

void* picoquic_get_cipher_suite_by_id_v(int cipher_suite_id, int use_low_memory)
{
    return (void*)picoquic_get_cipher_suite_by_id(cipher_suite_id, use_low_memory);
}

void picoquic_hash_update(uint8_t* input, size_t input_length, void* hash_context) {
    ((ptls_hash_context_t*)hash_context)->update((ptls_hash_context_t*)hash_context, input, input_length);
}

void picoquic_hash_finalize(uint8_t* output, void* hash_context) {
    ((ptls_hash_context_t*)hash_context)->final((ptls_hash_context_t*)hash_context, output, PTLS_HASH_FINAL_MODE_FREE);
}

#endif /* CRYPTO_PROVIDERS_GENERIC_REGION */

static void picoquic_setup_cleartext_aead_salt(size_t version_index, ptls_iovec_t* salt);

static void picoquic_free_log_event(picoquic_quic_t* quic);

void picoquic_log_crypto_errors(picoquic_cnx_t* cnx, int ret)
{
    unsigned long crypto_err;
    char const* err_file = NULL;
    int err_line = 0;

    while ((crypto_err = picoquic_explain_crypto_error(&err_file, &err_line)) != 0) {
        picoquic_log_app_message(cnx, "Crypto SSL error: %lu, file %s, line %d", crypto_err,
            (err_file == NULL) ? "?" : err_file, err_line);
    }

    picoquic_log_app_message(cnx, "Picotls returns error: %d (0x%x)", ret, ret);
}


int picoquic_server_setup_ticket_aead_contexts(picoquic_quic_t* quic,
    ptls_context_t* tls_ctx,
    const uint8_t* secret, size_t secret_length);

/* Crypto random number generator */

void picoquic_crypto_random(picoquic_quic_t* quic, void* buf, size_t len)
{
    ptls_context_t* ctx = (ptls_context_t*)quic->tls_master_ctx;

    ctx->random_bytes(buf, len);
}

uint64_t picoquic_crypto_uniform_random(picoquic_quic_t* quic, uint64_t rnd_max)
{
    uint64_t rnd;
    uint64_t rnd_min = UINT64_MAX % rnd_max;

    do {
        picoquic_crypto_random(quic, &rnd, sizeof(rnd));
    } while (rnd < rnd_min);

    return rnd % rnd_max;
}

/*
 * Non crypto public random generator. This is meant to provide good enough randomness
 * without disclosing the state of the crypto random number generator. This is
 * adequate for non critical random numbers, such as sequence numbers or padding.
 *
 * The following is an implementation of xorshift1024* suggested by Sebastiano Vigna,
 * following the general xorshift design by George Marsaglia.
 * The state must be seeded so that it is not everywhere zero.
 *
 * The seed operation gets 64 bits from the crypto random generator. We then run the
 * generator 16 times to mix that input into the 1024 bits of seed[16].
 *
 * In order to provide a minimum of protection against casual analysis, we run
 * an obfuscation step before providing the result. The obfuscation involves 
 * multiply by a constant modulo, then XOR the result with obfuscator again.
 * The obfuscator changes each time the random generator is seeded.
 *
 * If we were really paranoid, we would want to break possible discovery by passing
 * the seeding bits from the crypto random generator through SHA256 or something
 * similar, so there would be really no way to get at the state of crypto random
 * generator. The 16 rounds of the xorshift process give a pretty good hash, but
 * that can probably be broken by linear analysis. Or at least we have no proof
 * that it cannot be broken.
 */

static uint64_t public_random_seed[16] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
static int public_random_index = 0;
static const uint64_t public_random_multiplier = 1181783497276652981ull;
static uint64_t public_random_obfuscator = 0x5555555555555555ull;

static uint64_t picoquic_public_random_step(void)
{
    uint64_t s1;
    const uint64_t s0 = public_random_seed[public_random_index++];
    public_random_index &= 15;
    s1 = public_random_seed[public_random_index];
    s1 ^= (s1 << 31); // a
    s1 ^= (s1 >> 11); // b
    s1 ^= (s0 ^ (s0 >> 30)); // c
    public_random_seed[public_random_index] = s1;
    return s1;
}

uint64_t picoquic_public_random_64(void)
{
    uint64_t s1 = picoquic_public_random_step();
    s1 *= public_random_multiplier;
    s1 ^= public_random_obfuscator;
    return s1;
}

void picoquic_public_random_seed_64(uint64_t seed, int reset)
{
    if (reset) {
        public_random_index = 0;
        for (uint64_t i = 0; i < 16; i++) {
            public_random_seed[i] = i + 1u;
        }
        public_random_obfuscator = 0x5555555555555555ull;
    }

    public_random_seed[public_random_index] ^= seed;

    for (int i = 0; i < 16; i++) {
        (void)picoquic_public_random_step();
    }
}


void picoquic_public_random_seed(picoquic_quic_t* quic)
{
    uint64_t seed[3];
    picoquic_crypto_random(quic, &seed, sizeof(seed));

    picoquic_public_random_seed_64(seed[0], 0);
    public_random_obfuscator = seed[1];
}

void picoquic_public_random(void* buf, size_t len)
{
    uint8_t* x = buf;

    while (len > 0) {
        uint64_t y = picoquic_public_random_64();
        for (int i = 0; i < 8 && len > 0; i++) {
            *x++ = (uint8_t)(y & 255);
            y >>= 8;
            len--;
        }
    }
}

uint64_t picoquic_public_uniform_random(uint64_t rnd_max)
{
    uint64_t rnd;
    uint64_t rnd_min = UINT64_MAX % rnd_max;

    do {
        rnd = picoquic_public_random_64();
    } while (rnd < rnd_min);

    return rnd % rnd_max;
}

/* For an interim period, we are still supporting versions of QUIC that
 * use the old version extension identifier, so we need a function to
 * predict the extension ID from the QUIc version */
uint16_t picoquic_tls_get_quic_extension_id(picoquic_cnx_t* cnx)
{
    int v = picoquic_supported_versions[cnx->version_index].version;
    uint16_t quic_ext_id = PICOQUIC_TRANSPORT_PARAMETERS_TLS_EXTENSION_V1;

    /* Manage exception for old versions, that were using the
     * provisional code for the transport parameters */
    
    if (v == PICOQUIC_SEVENTEENTH_INTEROP_VERSION ||
        v == PICOQUIC_EIGHTEENTH_INTEROP_VERSION ||
        v == PICOQUIC_NINETEENTH_INTEROP_VERSION ||
        v == PICOQUIC_NINETEENTH_BIS_INTEROP_VERSION ||
        v == PICOQUIC_TWENTIETH_PRE_INTEROP_VERSION ||
        v == PICOQUIC_TWENTIETH_INTEROP_VERSION ||
        v == PICOQUIC_INTERNAL_TEST_VERSION_1 ||
        v == PICOQUIC_INTERNAL_TEST_VERSION_2) {
        quic_ext_id = PICOQUIC_TRANSPORT_PARAMETERS_TLS_EXTENSION_DRAFT;
    }

    return quic_ext_id;
}
            
/*
 * The collect extensions call back is called by the picotls stack upon
 * reception of a handshake message containing extensions. It should return true (1)
 * if the stack can process the extension, false (0) otherwise.
 */

int picoquic_tls_collect_extensions_cb(ptls_t* tls, struct st_ptls_handshake_properties_t* properties, uint16_t type)
{
#ifdef _WINDOWS
    UNREFERENCED_PARAMETER(tls);
    UNREFERENCED_PARAMETER(properties);
#endif
    /* Find the context from the TLS context */
    picoquic_tls_ctx_t* ctx =
        (picoquic_tls_ctx_t*)((char*)properties - offsetof(struct st_picoquic_tls_ctx_t, handshake_properties));

    return picoquic_tls_get_quic_extension_id(ctx->cnx);
}

void picoquic_tls_set_extensions(picoquic_cnx_t* cnx, picoquic_tls_ctx_t* tls_ctx)
{
    size_t consumed = 0;
    int ret = -1;
    
    if (tls_ctx->ext_data != NULL) {
        ret = picoquic_prepare_transport_extensions(cnx, (tls_ctx->client_mode) ? 0 : 1,
            tls_ctx->ext_data, tls_ctx->ext_data_size, &consumed);
    }

    if (ret == 0) {
        tls_ctx->ext[0].type = picoquic_tls_get_quic_extension_id(cnx);
        tls_ctx->ext[0].data.base = tls_ctx->ext_data;
        tls_ctx->ext[0].data.len = consumed;
        tls_ctx->ext[1].type = 0xFFFF;
        tls_ctx->ext[1].data.base = NULL;
        tls_ctx->ext[1].data.len = 0;
    } else {
        tls_ctx->ext[0].type = 0xFFFF;
        tls_ctx->ext[0].data.base = NULL;
        tls_ctx->ext[0].data.len = 0;
    }

    tls_ctx->handshake_properties.additional_extensions = tls_ctx->ext;
}

/*
 * The collected extensions call back is called by the stack upon
 * reception of a handshake message containing supported extensions.
 */

int picoquic_tls_collected_extensions_cb(ptls_t* tls, ptls_handshake_properties_t* properties,
    ptls_raw_extension_t* slots)
{
#ifdef _WINDOWS
    UNREFERENCED_PARAMETER(tls);
#endif
    int ret = 0;
    size_t consumed = 0;
    /* Find the context from the TLS context */
    picoquic_tls_ctx_t* ctx = (picoquic_tls_ctx_t*)((char*)properties - offsetof(struct st_picoquic_tls_ctx_t, handshake_properties));

    for (int i_slot = 0; slots[i_slot].type != 0xFFFF; i_slot++) {
        if (slots[i_slot].type == picoquic_tls_get_quic_extension_id(ctx->cnx)) {
            /* Retrieve the transport parameters */
            ret = picoquic_receive_transport_extensions(ctx->cnx, (ctx->client_mode) ? 1 : 0,
                slots[i_slot].data.base, slots[i_slot].data.len, &consumed);
            /* For now, override the value in case of default */
            ret = 0;

            /* In server mode, only compose the extensions if properly received from client */
            if (ctx->client_mode == 0) {
                picoquic_tls_set_extensions(ctx->cnx, ctx);
            }
        }
    }

    return ret;
}

/*
 * The Hello Call Back is called on the server side upon reception of the 
 * Client Hello. The picotls code will parse the client hello and retrieve
 * parameters such as SNI and proposed ALPN.
 * TODO: check the SNI in case several are supported.
 * TODO: check the ALPN in case several are supported.
 */

int picoquic_client_hello_call_back(ptls_on_client_hello_t* on_hello_cb_ctx,
    ptls_t* tls, ptls_on_client_hello_parameters_t *params)
{
    const uint8_t * alpn_found = 0;
    size_t alpn_found_length = 0;
    int ret = 0;
    picoquic_quic_t** ppquic = (picoquic_quic_t**)(((char*)on_hello_cb_ctx) + sizeof(ptls_on_client_hello_t));
    picoquic_quic_t* quic = *ppquic;

    /* Save the server name */
    ptls_set_server_name(tls, (const char *)params->server_name.base, params->server_name.len);

    /* Check if the client is proposing the expected ALPN */
    if (quic->default_alpn != NULL) {
        size_t len = strlen(quic->default_alpn);

        for (size_t i = 0; i < params->negotiated_protocols.count; i++) {
            if (params->negotiated_protocols.list[i].len == len && memcmp(params->negotiated_protocols.list[i].base, quic->default_alpn, len) == 0) {
                if (quic->cnx_in_progress != NULL) {
                    picoquic_log_app_message(quic->cnx_in_progress, "ALPN[%d] matches default alpn (%s)", (int)i, quic->default_alpn);
                }
                alpn_found = (const uint8_t *)quic->default_alpn;
                alpn_found_length = len;
                ptls_set_negotiated_protocol(tls, quic->default_alpn, len);
                break;
            }
        }
    }
    else if (quic->alpn_select_fn != NULL) {
        size_t selected = quic->alpn_select_fn(quic, params->negotiated_protocols.list, params->negotiated_protocols.count);

        if (selected < params->negotiated_protocols.count) {
            alpn_found = params->negotiated_protocols.list[selected].base;
            alpn_found_length = params->negotiated_protocols.list[selected].len;
            ptls_set_negotiated_protocol(tls, (const char *)params->negotiated_protocols.list[selected].base, params->negotiated_protocols.list[selected].len);
        }
    }

    if (quic->cnx_in_progress != NULL) {
        if (quic->cnx_in_progress->alpn == NULL && alpn_found_length > 0) {
            quic->cnx_in_progress->alpn = picoquic_string_create((const char *)alpn_found, alpn_found_length);
        }
        picoquic_log_negotiated_alpn(quic->cnx_in_progress,
            0, params->server_name.base, params->server_name.len, alpn_found, alpn_found_length,
            params->negotiated_protocols.list, params->negotiated_protocols.count);
    }

    /* ALPN is mandatory in Quic. Return an error if no match found. */
    if (alpn_found == NULL) {
        ret = PTLS_ALERT_NO_APPLICATION_PROTOCOL;
    }

    if (ret != 0 && quic->cnx_in_progress != NULL) {
        picoquic_log_app_message(quic->cnx_in_progress, "Client Hello call back returns %d (0x%x)", ret, ret);
    }

    return ret;
}

/*
 * The server will generate session tickets if some parameters are set in the server
 * TLS context, including:
 *  - the session ticket encryption callback, defined per the "encrypt_ticket" member of the context.
 *  - the session ticket lifetime, defined per the "ticket_life_time" member of the context.
 * The encrypt call back is called on the server side when a session resume ticket is ready.
 * The call is:
 * cb(tls->ctx->encrypt_ticket, tls, 1, sendbuf,
 *    ptls_iovec_init(session_id.base, session_id.off))
 * The call to decrypt is:
 * tls->ctx->encrypt_ticket->cb(tls->ctx->encrypt_ticket, tls, 0, &decbuf, identity->identity)
 * Should return 0 if the ticket is good, etc.
 */

int picoquic_server_encrypt_ticket_call_back(ptls_encrypt_ticket_t* encrypt_ticket_ctx,
    ptls_t* tls, int is_encrypt, ptls_buffer_t* dst, ptls_iovec_t src)
{
#ifdef _WINDOWS
    UNREFERENCED_PARAMETER(tls);
#endif

    /* Assume that the keys are in the quic context 
     * The tickets are composed of a 64 bit "sequence number" 
     * followed by the result of the clear text encryption.
     */
    int ret = 0;
    picoquic_quic_t** ppquic = (picoquic_quic_t**)(((char*)encrypt_ticket_ctx) + sizeof(ptls_encrypt_ticket_t));
    picoquic_quic_t* quic = *ppquic;

    if (is_encrypt != 0) {
        ptls_aead_context_t* aead_enc = (ptls_aead_context_t*)quic->aead_encrypt_ticket_ctx;
        /* Encoding*/
        if (aead_enc == NULL) {
            ret = -1;
        } else if ((ret = ptls_buffer_reserve(dst, 8 + 4 + src.len + aead_enc->algo->tag_size)) == 0) {
            /* Create and store the ticket sequence number */
            uint32_t version_number = picoquic_supported_versions[quic->cnx_in_progress->version_index].version;
            uint64_t seq_num = picoquic_public_random_64();
            size_t start_off;
            size_t data_length;

            picoformat_64(dst->base + dst->off, seq_num);
            dst->off += 8;
            start_off = dst->off;
            /* Copy initial ticket to dst field before encryption. */
            memcpy(dst->base + dst->off, src.base, src.len);
            data_length = src.len;
            /* Add the version number */
            picoformat_32(dst->base + dst->off + data_length, version_number);
            data_length += 4;
            /* Run AEAD encryption */
            dst->off += ptls_aead_encrypt(aead_enc, dst->base + dst->off,
                dst->base + start_off, data_length, seq_num, NULL, 0);
            /* Remember issued ticket ID in connection context */
            quic->cnx_in_progress->issued_ticket_id = seq_num;
        }
    } else {
        ptls_aead_context_t* aead_dec = (ptls_aead_context_t*)quic->aead_decrypt_ticket_ctx;
        /* Decoding*/
        if (aead_dec == NULL) {
            ret = -1;
        } else if (src.len < 8 + 4 + aead_dec->algo->tag_size) {
            ret = -1;
        } else if ((ret = ptls_buffer_reserve(dst, src.len)) == 0) {
            /* Decode the ticket sequence number */
            uint64_t seq_num = PICOPARSE_64(src.base);
            /* Decrypt */
            size_t decrypted = ptls_aead_decrypt(aead_dec, dst->base + dst->off,
                src.base + 8, src.len - 8, seq_num, NULL, 0);

            if (decrypted > src.len - 8) {
                /* decryption error */
                ret = -1;
                picoquic_log_app_message(quic->cnx_in_progress, "%s",
                    "Session ticket could not be decrypted");
            } else {
                /* decode and verify the version number */
                uint32_t version_number = PICOPARSE_32(dst->base + dst->off + decrypted - 4);
                if (version_number != picoquic_supported_versions[quic->cnx_in_progress->version_index].version) {
                    /* wrong version error */
                    ret = -1;
                    picoquic_log_app_message(quic->cnx_in_progress, "Ticket version mismatch, expected 0x%x, got 0x%x",
                        picoquic_supported_versions[quic->cnx_in_progress->version_index].version, version_number);
                }
                else {
                    picoquic_issued_ticket_t* server_ticket;
                    dst->off += decrypted - 4;
                    picoquic_log_app_message(quic->cnx_in_progress, "%s",
                        "Session ticket properly decrypted");
                    /* Remember resumed ticket ID in connection context */
                    quic->cnx_in_progress->resumed_ticket_id = seq_num;
                    /* Remember rtt and cwin from ticket */
                    server_ticket = picoquic_retrieve_issued_ticket(quic, seq_num);
                    if (server_ticket != NULL && server_ticket->cwin > 0) {
                        picoquic_seed_bandwidth(
                            quic->cnx_in_progress,
                            server_ticket->rtt,
                            server_ticket->cwin,
                            server_ticket->ip_addr,
                            server_ticket->ip_addr_length);
                    }
                }
            }
        }
    }

    return ret;
}

/*
 * The client signals its willingness to receive session resume tickets by providing
 * the "save ticket" callback in the client's quic context.
 */

int picoquic_client_save_ticket_call_back(ptls_save_ticket_t* save_ticket_ctx,
    ptls_t* tls, ptls_iovec_t input)
{
    int ret = 0;
    picoquic_quic_t* quic = *((picoquic_quic_t**)(((char*)save_ticket_ctx) + sizeof(ptls_save_ticket_t)));
    const char* sni = ptls_get_server_name(tls);
    const char* alpn = ptls_get_negotiated_protocol(tls);
    picoquic_cnx_t * cnx = (picoquic_cnx_t *)*ptls_get_data_ptr(tls);
    uint32_t version = picoquic_supported_versions[cnx->version_index].version;

    if (alpn == NULL && quic != NULL) {
        alpn = quic->default_alpn;
    }

    if (sni != NULL && alpn != NULL) {
        /* TODO: SHOULD STORE IP ADDRESSES? */
        ret = picoquic_store_ticket(quic, sni, (uint16_t)strlen(sni),
            alpn, (uint16_t)strlen(alpn), version, NULL, 0, NULL, 0,
            input.base, (uint16_t)input.len, &cnx->remote_parameters);
        /* Set first 8 bytes of ticket as identifier */
        if (input.len > 8) {
            cnx->issued_ticket_id = PICOPARSE_64(input.base);
        }
    } else {
        picoquic_log_app_message(cnx, 
            "Received incorrect session resume ticket, sni = %s, alpn = %s, length = %d\n",
            (sni == NULL) ? "NULL" : sni, (alpn == NULL) ? "NULL" : alpn, (int)input.len);
    }

    return ret;
}

/*
 * Time get callback
 */
uint64_t picoquic_get_simulated_time_cb(ptls_get_time_t* self)
{
    uint64_t** pp_simulated_time = (uint64_t**)(((char*)self) + sizeof(ptls_get_time_t));
    return ((**pp_simulated_time) / 1000);
}

/*
 * Verify certificate
 */

int picoquic_enable_custom_verify_certificate_callback(picoquic_quic_t* quic) {
    ptls_context_t* ctx = (ptls_context_t*)quic->tls_master_ctx;

    ctx->verify_certificate = quic->verify_certificate_callback;
    quic->is_cert_store_not_empty = 1;
    return 0;
}

void picoquic_dispose_verify_certificate_callback(picoquic_quic_t* quic) {
    ptls_context_t* ctx = (ptls_context_t*)quic->tls_master_ctx;

    if (ctx->verify_certificate != NULL) {
        if (quic->free_verify_certificate_callback_fn != NULL) {
            picoquic_dispose_certificate_verifier_t disposer =
                (picoquic_dispose_certificate_verifier_t)quic->free_verify_certificate_callback_fn;
            disposer(ctx->verify_certificate);
            quic->free_verify_certificate_callback_fn = NULL;
        }
        /*
        free(ctx->verify_certificate);
        */
        ctx->verify_certificate = NULL;
    }

    ctx->verify_certificate = NULL;
}

void picoquic_tls_set_verify_certificate_callback(picoquic_quic_t* quic,
    struct st_ptls_verify_certificate_t* cb, picoquic_free_verify_certificate_ctx free_fn)
{
    ptls_context_t* ctx = (ptls_context_t*)quic->tls_master_ctx;

    picoquic_dispose_verify_certificate_callback(quic);

    ctx->verify_certificate = cb;
    quic->is_cert_store_not_empty = 1;
    quic->free_verify_certificate_callback_fn = free_fn;
}

/* set key from secret: this is used to create AEAD contexts and PN encoding contexts
 * after a key update callback, and also to create the initial keys from a locally
 * computed secret
 */

static int picoquic_set_aead_from_secret(void ** v_aead,ptls_cipher_suite_t * cipher, int is_enc, const void *secret, const char *prefix_label)
{
    int ret = 0;

    if (*v_aead != NULL) {
        ptls_aead_free((ptls_aead_context_t*)*v_aead);
    }

    if ((*v_aead = ptls_aead_new(cipher->aead, cipher->hash, is_enc, secret, prefix_label)) == NULL) {
        ret = PTLS_ERROR_NO_MEMORY;
    }

    return ret;
}

static int picoquic_set_pn_enc_from_secret(void ** v_pn_enc, ptls_cipher_suite_t * cipher, int is_enc, const void *secret, const char *prefix_label)
{
    uint8_t pnekey[PTLS_MAX_SECRET_SIZE];
    int ret;

    if (*v_pn_enc != NULL) {
        ptls_cipher_free((ptls_cipher_context_t *)*v_pn_enc);
        *v_pn_enc = NULL;
    }

    if ((ret = ptls_hkdf_expand_label(cipher->hash, pnekey, 
        cipher->aead->ctr_cipher->key_size, ptls_iovec_init(secret, cipher->hash->digest_size), 
        PICOQUIC_LABEL_HP, ptls_iovec_init(NULL, 0), prefix_label)) == 0) {
        if ((*v_pn_enc = ptls_cipher_new(cipher->aead->ctr_cipher, is_enc, pnekey)) == NULL) {
            ret = PTLS_ERROR_NO_MEMORY;
        }
    }
    
    return ret;
}

void picoquic_aes128_ecb_free(void * v_aesecb)
{
    ptls_cipher_free((ptls_cipher_context_t *)v_aesecb);
}

void picoquic_aes128_ecb_encrypt(void* v_aesecb, uint8_t * output, const uint8_t * input, size_t len)
{
    ptls_cipher_encrypt((ptls_cipher_context_t*)v_aesecb, output, input, len);
}

static int picoquic_set_key_from_secret(ptls_cipher_suite_t * cipher, int is_enc, int is_rotation, picoquic_crypto_context_t * ctx, const void *secret, const char *prefix_label)
{
    int ret = 0;

    if (is_enc != 0) {
        ret = picoquic_set_aead_from_secret(&ctx->aead_encrypt, cipher, is_enc, secret, prefix_label);
        
        if (ret == 0 && !is_rotation) {
            ret = picoquic_set_pn_enc_from_secret(&ctx->pn_enc, cipher, is_enc, secret, prefix_label);
        }
    } else {
        ret = picoquic_set_aead_from_secret(&ctx->aead_decrypt, cipher, is_enc, secret, prefix_label);
        
        if (ret == 0 && !is_rotation) {
            ret = picoquic_set_pn_enc_from_secret(&ctx->pn_dec, cipher, is_enc, secret, prefix_label);
        }
    }

    return ret;
}


/* Key update callback: this is called by TLS whenever the session key has changed,
 * from the function "setup_traffic_protection" in picotls.c.
 *
 * The macro generated callback struct is:
 *     typedef struct st_ptls_update_traffic_key_t {
 *      ret (*cb)(struct st_ptls_update_traffic_key_t * self, ptls_t *tls, int is_enc, size_t epoch, const void *secret);
 *  } ptls_update_traffic_key_t;
 *
 * The parameters are defined as:
 *  - self    -- classic callback structure in picotls, can be remapped to hold additional arguments.
 *  - tls     -- the tls context of the connection
 *  - is_enc  -- 0: decryption key, 1: decryption key
 *  - epoch   -- 1: "c e traffic"
 *            -- 2: "s hs traffic"
 *            -- 2: "c hs traffic"
 *            -- 3: "s ap traffic"
 *            -- 3: "c ap traffic"
 *  - secret  -- the expansion of the master secret with the label specific to the key epoch
 *               and client or server mode.
 */

typedef struct st_picoquic_update_traffic_key_t {
    int(*cb)(struct st_ptls_update_traffic_key_t * self, ptls_t *tls, int is_enc, size_t epoch, const void *secret);
    picoquic_cnx_t *cnx;
} picoquic_update_traffic_key_t;

static int picoquic_update_traffic_key_callback(ptls_update_traffic_key_t * self, ptls_t *tls, int is_enc, size_t epoch, const void *secret)
{
    picoquic_cnx_t* cnx = (picoquic_cnx_t*)*ptls_get_data_ptr(tls);
    picoquic_tls_ctx_t * tls_ctx = (picoquic_tls_ctx_t *)cnx->tls_ctx;
    ptls_context_t* ctx = (ptls_context_t*)cnx->quic->tls_master_ctx;
    ptls_cipher_suite_t * cipher = ptls_get_cipher(tls);
    UNREFERENCED_PARAMETER(self);
    const char *prefix_label = picoquic_supported_versions[cnx->version_index].tls_prefix_label;

    int ret = picoquic_set_key_from_secret(cipher, is_enc, 0, &cnx->crypto_context[epoch], secret, prefix_label);
    if (cnx->cnx_state < picoquic_state_ready) {
        cnx->recycle_sooner_needed = 1;
    }

    if (ret == 0 && epoch == 3) {
        memcpy((is_enc) ? tls_ctx->app_secret_enc : tls_ctx->app_secret_dec, secret, cipher->hash->digest_size);
    }

    if (ctx->log_event != NULL) {
        char hexbuf[PTLS_MAX_DIGEST_SIZE * 2 + 1];
        static const char *log_labels[2][4] = {
            {NULL, "CLIENT_EARLY_TRAFFIC_SECRET", "CLIENT_HANDSHAKE_TRAFFIC_SECRET", "CLIENT_TRAFFIC_SECRET_0"},
            {NULL, NULL, "SERVER_HANDSHAKE_TRAFFIC_SECRET", "SERVER_TRAFFIC_SECRET_0"}};
        const char *secret_label = log_labels[ptls_is_server(tls) == is_enc][epoch];
        ptls_hexdump(hexbuf, secret, cipher->hash->digest_size);
        ctx->log_event->cb(ctx->log_event, tls, secret_label, "%s", hexbuf);
    }

    return ret;
}

ptls_update_traffic_key_t * picoquic_set_update_traffic_key_callback() {
    ptls_update_traffic_key_t * cb_st = (ptls_update_traffic_key_t *)malloc(sizeof(ptls_update_traffic_key_t));

    if (cb_st != NULL) {
        memset(cb_st, 0, sizeof(ptls_update_traffic_key_t));
        cb_st->cb = picoquic_update_traffic_key_callback;
    }

    return cb_st;
}

int picoquic_setup_initial_master_secret(
    ptls_cipher_suite_t * cipher,
    ptls_iovec_t salt,
    picoquic_connection_id_t initial_cnxid,
    uint8_t * master_secret)
{
    int ret = 0;
    ptls_iovec_t ikm;
    uint8_t cnx_id_serialized[PICOQUIC_CONNECTION_ID_MAX_SIZE];

    ikm.len = picoquic_format_connection_id(cnx_id_serialized, PICOQUIC_CONNECTION_ID_MAX_SIZE,
        initial_cnxid);
    ikm.base = cnx_id_serialized;

    /* Extract the master key -- key length will be 32 per SHA256 */
    ret = ptls_hkdf_extract(cipher->hash, master_secret, salt, ikm);

    return ret;
}

int picoquic_setup_initial_secrets(
    ptls_cipher_suite_t * cipher,
    uint8_t * master_secret,
    uint8_t * client_secret,
    uint8_t * server_secret)
{
    int ret = 0;
    ptls_iovec_t prk;

    prk.base = master_secret;
    prk.len = cipher->hash->digest_size;

    /* Get the client secret */
    ret = ptls_hkdf_expand_label(cipher->hash, client_secret, cipher->hash->digest_size,
        prk, PICOQUIC_LABEL_INITIAL_CLIENT, ptls_iovec_init(NULL, 0), NULL);

    if (ret == 0) {
        /* Get the server secret */
        ret = ptls_hkdf_expand_label(cipher->hash, server_secret, cipher->hash->digest_size,
            prk, PICOQUIC_LABEL_INITIAL_SERVER, ptls_iovec_init(NULL, 0), NULL);
    }

    return ret;
}

static int picoquic_compute_initial_secrets(picoquic_quic_t * quic, int version_index, picoquic_connection_id_t *initial_cnxid,
    ptls_cipher_suite_t * *cipher, uint8_t *client_secret, uint8_t *server_secret)
{
    int ret = 0;
    ptls_iovec_t salt;
    uint8_t master_secret[256]; /* secret_max */
    *cipher = picoquic_get_aes128gcm_sha256(quic->use_low_memory);
    if (*cipher == NULL) {
        ret = -1;
    }
    else {
        picoquic_setup_cleartext_aead_salt(version_index, &salt);

        /* Extract the master key -- key length will be 32 per SHA256 */
        ret = picoquic_setup_initial_master_secret(*cipher, salt, *initial_cnxid, master_secret);
        if (ret == 0) {
            ret = picoquic_setup_initial_secrets(*cipher, master_secret, client_secret, server_secret);
        }
    }
    return ret;
}

int picoquic_setup_initial_traffic_keys(picoquic_cnx_t* cnx)
{
    int ret = 0;
    const char *prefix_label = picoquic_supported_versions[cnx->version_index].tls_prefix_label;
    ptls_cipher_suite_t* cipher = NULL;
    uint8_t client_secret[256];
    uint8_t server_secret[256];
    uint8_t *secret1, *secret2;

    ret = picoquic_compute_initial_secrets(cnx->quic, cnx->version_index, &cnx->initial_cnxid, &cipher, client_secret, server_secret);

    /* derive the initial keys */
    if (ret == 0) {
        if (!cnx->client_mode) {
            secret1 = server_secret;
            secret2 = client_secret;
        }
        else {
            secret1 = client_secret;
            secret2 = server_secret;
        }
        
        ret = picoquic_set_key_from_secret(cipher, 1, 0, &cnx->crypto_context[0], secret1, prefix_label);

        if (ret == 0) {
            ret = picoquic_set_key_from_secret(cipher, 0, 0, &cnx->crypto_context[0], secret2, prefix_label);
        }
    }

    return ret;
}

int picoquic_get_initial_aead_context(picoquic_quic_t * quic, int version_index, picoquic_connection_id_t *initial_cnxid,
    int is_client, int is_enc, void** aead_ctx, void ** pn_enc_ctx)
{
    int ret = 0;
    ptls_cipher_suite_t* cipher = NULL;
    uint8_t client_secret[256];
    uint8_t server_secret[256];
    const char *prefix_label = picoquic_supported_versions[version_index].tls_prefix_label;

    *aead_ctx = NULL;
    *pn_enc_ctx = NULL;

    ret = picoquic_compute_initial_secrets(quic, version_index, initial_cnxid, &cipher, client_secret, server_secret);

    if (ret == 0) {
        uint8_t* selected_secret;

        if (!is_client) {
            selected_secret = (is_enc) ? server_secret : client_secret;
        }
        else {
            selected_secret = (is_enc) ? client_secret : server_secret;
        }

        ret = picoquic_set_aead_from_secret(aead_ctx, cipher, is_enc, selected_secret, prefix_label);
        if (ret == 0) {
            ret = picoquic_set_pn_enc_from_secret(pn_enc_ctx, cipher, is_enc, selected_secret, prefix_label);
        }
    }
    return ret;
}

/*
 * Key rotation.
 *
 * The old keys get moved to the old crypto context.
 * The secrets are rotated.
 * The new context gets informed.
 *
 * The key update is defined in RFC 8446 section 7.2 as:
 * application_traffic_secret_N+1 =
 *         HKDF-Expand-Label(application_traffic_secret_N,
 *                            "quic ku", "", Hash.length)
  * Label: PICOQUIC_LABEL_TRAFFIC_UPDATE
 */
int picoquic_rotate_app_secret(ptls_cipher_suite_t * cipher, uint8_t * secret, const char *traffic_update_label)
{
    int ret = 0;
    uint8_t new_secret[PTLS_MAX_DIGEST_SIZE];

    ret = ptls_hkdf_expand_label(cipher->hash, new_secret,
        cipher->hash->digest_size, ptls_iovec_init(secret, cipher->hash->digest_size), traffic_update_label,
        ptls_iovec_init(NULL, 0), PICOQUIC_LABEL_QUIC_BASE);
    if (ret == 0) {
        memcpy(secret, new_secret, cipher->hash->digest_size);
    }

    return ret;
}


uint8_t * picoquic_get_app_secret(picoquic_cnx_t* cnx, int is_enc)
{
    picoquic_tls_ctx_t * tls_ctx = (picoquic_tls_ctx_t *)cnx->tls_ctx;

    return (is_enc) ?tls_ctx->app_secret_enc:tls_ctx->app_secret_dec;
}

size_t picoquic_get_app_secret_size(picoquic_cnx_t* cnx)
{
    picoquic_tls_ctx_t * tls_ctx = (picoquic_tls_ctx_t *)cnx->tls_ctx;

    ptls_cipher_suite_t * cipher = ptls_get_cipher(tls_ctx->tls);

    return (cipher->hash->digest_size);
}

int picoquic_compute_new_rotated_keys(picoquic_cnx_t * cnx)
{
    int ret = 0;
    picoquic_tls_ctx_t * tls_ctx = (picoquic_tls_ctx_t *)cnx->tls_ctx;
    ptls_cipher_suite_t * cipher = ptls_get_cipher(tls_ctx->tls);
    const char *prefix_label = picoquic_supported_versions[cnx->version_index].tls_prefix_label;
    const char *traffic_update_label = picoquic_supported_versions[cnx->version_index].tls_traffic_update_label;

    /* Verify that the previous transition is complete */
    if (cnx->crypto_context_new.aead_decrypt != NULL ||
        cnx->crypto_context_new.aead_encrypt != NULL) {
        if (cnx->crypto_context_new.aead_decrypt == NULL ||
            cnx->crypto_context_new.aead_encrypt == NULL) {
            ret = PICOQUIC_ERROR_CANNOT_COMPUTE_KEY;
        }
        else {
            /* already computed */
            return 0;
        }
    }

    /* Recompute the secrets */
    if (ret == 0) {
        ret = picoquic_rotate_app_secret(cipher, tls_ctx->app_secret_enc, traffic_update_label);
#ifdef _DEBUG
        if (ret == 0) {
            DBG_PRINTF("Rotated Encryption Secret (%d):\n", (int)cipher->hash->digest_size);
            debug_dump(tls_ctx->app_secret_enc, (int)cipher->hash->digest_size);
        }
        else {
            DBG_PRINTF("Encryption secret rotation fails, ret=%x\n", ret);
        }
#endif
    }

    if (ret == 0) {
        ret = picoquic_set_key_from_secret(cipher, 1, 1, &cnx->crypto_context_new, tls_ctx->app_secret_enc, prefix_label);
    }

    if (ret == 0) {
        ret = picoquic_rotate_app_secret(cipher, tls_ctx->app_secret_dec, traffic_update_label);
#ifdef _DEBUG
        if (ret == 0) {
            DBG_PRINTF("Rotated Decryption Secret (%d):\n", (int)cipher->hash->digest_size);
            debug_dump(tls_ctx->app_secret_dec, (int)cipher->hash->digest_size);
        }
        else {
            DBG_PRINTF("Decryption secret rotation fails, ret=%x\n", ret);
        }
#endif

    }

    if (ret == 0) {
        ret = picoquic_set_key_from_secret(cipher, 0, 1, &cnx->crypto_context_new, tls_ctx->app_secret_dec, prefix_label);
    }

    return (ret == 0)?0: PICOQUIC_ERROR_CANNOT_COMPUTE_KEY;
}

void picoquic_apply_rotated_keys(picoquic_cnx_t * cnx, int is_enc)
{
    if (is_enc) {
        if (cnx->crypto_context[3].aead_encrypt != NULL) {
            ptls_aead_free((ptls_aead_context_t *)cnx->crypto_context[3].aead_encrypt);
        }

        cnx->crypto_context[3].aead_encrypt = cnx->crypto_context_new.aead_encrypt;
        cnx->crypto_context_new.aead_encrypt = NULL;

        cnx->key_phase_enc ^= 1;
        picoquic_log_pn_dec_trial(cnx);
    }
    else {
        if (cnx->crypto_context_old.aead_decrypt != NULL) {
            ptls_aead_free((ptls_aead_context_t *)cnx->crypto_context_old.aead_decrypt);
        }

        cnx->crypto_context_old.aead_decrypt = cnx->crypto_context[3].aead_decrypt;
        cnx->crypto_context[3].aead_decrypt = cnx->crypto_context_new.aead_decrypt;
        cnx->crypto_context_new.aead_decrypt = NULL;

        cnx->key_phase_dec ^= 1;
    }
}

/*
 * Release the crypto context, and the associated keys.
 */

void picoquic_crypto_context_free(picoquic_crypto_context_t * ctx)
{
    if (ctx->aead_encrypt != NULL) {
        ptls_aead_free((ptls_aead_context_t *)ctx->aead_encrypt);
        ctx->aead_encrypt = NULL;
    }

    if (ctx->aead_decrypt != NULL) {
        ptls_aead_free((ptls_aead_context_t *)ctx->aead_decrypt);
        ctx->aead_decrypt = NULL;
    }

    if (ctx->pn_enc != NULL) {
        ptls_cipher_free((ptls_cipher_context_t *)ctx->pn_enc);
        ctx->pn_enc = NULL;
    }

    if (ctx->pn_dec != NULL) {
        ptls_cipher_free((ptls_cipher_context_t *)ctx->pn_dec);
        ctx->pn_dec = NULL;
    }
}

/*
 * Setting the master TLS context.
 * On servers, this implies setting the "on hello" call back
 */

int picoquic_master_tlscontext(picoquic_quic_t* quic,
    char const* cert_file_name, char const* key_file_name, const char * cert_root_file_name,
    const uint8_t* ticket_key, size_t ticket_key_length)
{
    /* Create a client context or a server context */
    int ret = 0;
    ptls_context_t* ctx;
    ptls_on_client_hello_t* och = NULL;
    ptls_encrypt_ticket_t* encrypt_ticket = NULL;
    ptls_save_ticket_t* save_ticket = NULL;
    unsigned int is_cert_store_not_empty = 0;

    picoquic_tls_api_init(); /* For example, init openSSL if in use. */

    ctx = (ptls_context_t*)malloc(sizeof(ptls_context_t));

    if (ctx == NULL) {
        ret = -1;
    }
    else {
        memset(ctx, 0, sizeof(ptls_context_t));
        picoquic_set_random_provider_in_ctx(ctx);
        
        ret = picoquic_set_key_exchange_in_ctx(ctx, 0); /* was: ctx->key_exchanges = picoquic_key_exchanges; */

        if (ret == 0) {
            ret = picoquic_set_cipher_suite_in_ctx(ctx, 0, quic->use_low_memory); /* was: ptls_openssl_cipher_suites; */
        }

        if (ret == 0) {
            ctx->send_change_cipher_spec = 0;

            ctx->hkdf_label_prefix__obsolete = NULL;
            ctx->update_traffic_key = picoquic_set_update_traffic_key_callback();

            if (quic->p_simulated_time == NULL) {
                ctx->get_time = &ptls_get_time;
            }
            else {
                ptls_get_time_t* time_getter = (ptls_get_time_t*)malloc(sizeof(ptls_get_time_t) + sizeof(uint64_t*));
                if (time_getter == NULL) {
                    ret = PICOQUIC_ERROR_MEMORY;
                }
                else {
                    uint64_t** pp_simulated_time = (uint64_t**)(((char*)time_getter) + sizeof(ptls_get_time_t));

                    time_getter->cb = picoquic_get_simulated_time_cb;
                    *pp_simulated_time = quic->p_simulated_time;
                    ctx->get_time = time_getter;
                }
            }

            if (cert_file_name != NULL && key_file_name != NULL) {
                /* Read the certificate file */
                if (ptls_load_certificates(ctx, (char*)cert_file_name) != 0) {
                    DBG_PRINTF("Cannot load certificate: %s", cert_file_name);
                    ret = -1;
                }
                else {
                    ret = set_private_key_from_file(key_file_name, ctx);
                    if (ret != 0){
                        DBG_PRINTF("Cannot load key: %s, ret = 0x%x", key_file_name, ret);
                    }
                }
            }
        }

        if (ret == 0) {
            och = (ptls_on_client_hello_t*)malloc(sizeof(ptls_on_client_hello_t) + sizeof(picoquic_quic_t*));
            if (och != NULL) {
                picoquic_quic_t** ppquic = (picoquic_quic_t**)(((char*)och) + sizeof(ptls_on_client_hello_t));

                och->cb = picoquic_client_hello_call_back;
                ctx->on_client_hello = och;
                *ppquic = quic;
            } else {
                ret = PICOQUIC_ERROR_MEMORY;
            }
        }

        if (ret == 0) {
            ret = picoquic_server_setup_ticket_aead_contexts(quic, ctx, ticket_key, ticket_key_length);
        }

        if (ret == 0) {
            encrypt_ticket = (ptls_encrypt_ticket_t*)malloc(sizeof(ptls_encrypt_ticket_t) + sizeof(picoquic_quic_t*));
            if (encrypt_ticket == NULL) {
                ret = PICOQUIC_ERROR_MEMORY;
            } else {
                picoquic_quic_t** ppquic = (picoquic_quic_t**)(((char*)encrypt_ticket) + sizeof(ptls_encrypt_ticket_t));

                encrypt_ticket->cb = picoquic_server_encrypt_ticket_call_back;
                *ppquic = quic;

                ctx->encrypt_ticket = encrypt_ticket;
                ctx->ticket_lifetime = 100000; /* 100,000 seconds, a bit more than one day */
                ctx->require_dhe_on_psk = 1;
                ctx->max_early_data_size = 0xFFFFFFFF;
            }
        }

        if (ret == 0) {
            ctx->verify_certificate = picoquic_get_certificate_verifier(cert_root_file_name,
                &is_cert_store_not_empty, (picoquic_free_verify_certificate_ctx*)
                &quic->free_verify_certificate_callback_fn);
            quic->is_cert_store_not_empty = is_cert_store_not_empty;
        }

        if (ret == 0 && quic->ticket_file_name != NULL) {
            save_ticket = (ptls_save_ticket_t*)malloc(sizeof(ptls_save_ticket_t) + sizeof(picoquic_quic_t*));
            if (save_ticket != NULL) {
                picoquic_quic_t** ppquic = (picoquic_quic_t**)(((char*)save_ticket) + sizeof(ptls_save_ticket_t));

                save_ticket->cb = picoquic_client_save_ticket_call_back;
                ctx->save_ticket = save_ticket;
                *ppquic = quic;
            }
        }

        if (ret == 0) {
            /* Tell Picotls to not require EOED messages during handshake */
            ctx->omit_end_of_early_data = 1;
        }

        if (ret == 0) {
            quic->tls_master_ctx = ctx;
            picoquic_public_random_seed(quic);
        } else {
            quic->tls_master_ctx = ctx;
            picoquic_master_tlscontext_free(quic);
            quic->tls_master_ctx = NULL;
            free(ctx);
        }
    }

    return ret;
}

static void free_certificates_list(ptls_iovec_t* certs, size_t len) {
    if (certs == NULL) {
        return;
    }

    for (size_t i = 0; i < len; ++i) {
        free(certs[i].base);
    }
    free(certs);
}

void picoquic_master_tlscontext_free(picoquic_quic_t* quic)
{
    if (quic->tls_master_ctx != NULL) {
        ptls_context_t* ctx = (ptls_context_t*)quic->tls_master_ctx;

        if (quic->p_simulated_time != NULL && ctx->get_time != NULL) {
            free(ctx->get_time);
            ctx->get_time = NULL;
        }

        free_certificates_list(ctx->certificates.list, ctx->certificates.count);

        picoquic_dispose_sign_certificate(ctx);

        picoquic_dispose_verify_certificate_callback(quic);

        if (ctx->on_client_hello != NULL) {
            free(ctx->on_client_hello);
        }

        if (ctx->encrypt_ticket != NULL) {
            free(ctx->encrypt_ticket);
        }

        if (ctx->update_traffic_key != NULL) {
            free(ctx->update_traffic_key);
        }

        /* Need to be tested */
        if (ctx->save_ticket != NULL) {
            free(ctx->save_ticket);
        }

        if (ctx->cipher_suites != NULL) {
            free((void*)ctx->cipher_suites);
        }

        picoquic_free_log_event(quic);
    }
}

/* Return the virtual time seen by tls */
uint64_t picoquic_get_tls_time(picoquic_quic_t* quic)
{
    ptls_context_t* ctx = (ptls_context_t*)quic->tls_master_ctx;
    uint64_t now = ctx->get_time->cb(ctx->get_time)*1000;

    return now;
}

/*
 * Creation of a TLS context.
 * This includes setting the handshake properties that will later be
 * used during the TLS handshake.
 */
int picoquic_tlscontext_create(picoquic_quic_t* quic, picoquic_cnx_t* cnx, uint64_t current_time)
{
    int ret = 0;
    /* allocate a context structure */
    picoquic_tls_ctx_t* ctx = (picoquic_tls_ctx_t*)malloc(sizeof(picoquic_tls_ctx_t));

    /* Create the TLS context */
    if (ctx == NULL) {
        ret = -1;
    } else {
        memset(ctx, 0, sizeof(picoquic_tls_ctx_t));
        ctx->ext_data_size = PICOQUIC_TRANSPORT_PARAMETERS_MAX_SIZE;
        if (!cnx->client_mode && quic->test_large_server_flight) {
            ctx->ext_data_size += 4096;
        }
        ctx->ext_data = (uint8_t*)malloc(ctx->ext_data_size);
        ctx->alpn_vec = (ptls_iovec_t*)malloc(sizeof(ptls_iovec_t) * PICOQUIC_ALPN_NUMBER_MAX);
        if (ctx->ext_data == NULL || ctx->alpn_vec == NULL) {
            ret = -1;
        }
        else {
            ctx->alpn_vec_size = PICOQUIC_ALPN_NUMBER_MAX;
            ctx->cnx = cnx;

            ctx->handshake_properties.collect_extension = picoquic_tls_collect_extensions_cb;
            ctx->handshake_properties.collected_extensions = picoquic_tls_collected_extensions_cb;
            ctx->client_mode = cnx->client_mode;

            ctx->tls = ptls_new((ptls_context_t*)quic->tls_master_ctx,
                (ctx->client_mode) ? 0 : 1);
            *ptls_get_data_ptr(ctx->tls) = cnx;

            if (ctx->tls == NULL) {
                free(ctx);
                ctx = NULL;
                ret = -1;
            }
            else if (!ctx->client_mode) {
                /* A server side connection, but no cert/key where given for the master context */
                if (((ptls_context_t*)quic->tls_master_ctx)->encrypt_ticket == NULL) {
                    ret = PICOQUIC_ERROR_TLS_SERVER_CON_WITHOUT_CERT;
                    picoquic_tlscontext_free(ctx);
                    ctx = NULL;
                }

                if (ctx != NULL) {
                    /* The server should never attempt a stateless retry */
                    ctx->handshake_properties.server.enforce_retry = 0;
                    ctx->handshake_properties.server.retry_uses_cookie = 0;
                    ctx->handshake_properties.server.cookie.key = NULL;
                    ctx->handshake_properties.server.cookie.additional_data.base = NULL;
                    ctx->handshake_properties.server.cookie.additional_data.len = 0;
                }
            }
        }
    }
    
    if (cnx->tls_ctx != NULL) {
        picoquic_tlscontext_free(cnx->tls_ctx);
    }

    cnx->tls_ctx = (void*)ctx;

    return ret;
}

/* Set the log event to record keys for use by Wireshark.
 */

static void picoquic_log_event_call_back(ptls_log_event_t *_self, ptls_t *tls, const char *type, const char *fmt, ...)
{
    struct st_picoquic_log_event_t *self = (struct st_picoquic_log_event_t*)_self;
    char randomhex[PTLS_HELLO_RANDOM_SIZE * 2 + 1];
    va_list args;

    if (self->fp != NULL) {
        ptls_hexdump(randomhex, ptls_get_client_random(tls).base, PTLS_HELLO_RANDOM_SIZE);
            fprintf(self->fp, "%s %s ", type, randomhex);

            va_start(args, fmt);
            vfprintf(self->fp, fmt, args);
            va_end(args);

            fprintf(self->fp, "\n");
            fflush(self->fp);
    }
}

/**
 * Free the log-event call back, either when the TLS master context is freed,
 * or when the key log file is reset.
 */
static void picoquic_free_log_event(picoquic_quic_t* quic)
{
    ptls_context_t* ctx = (ptls_context_t*)quic->tls_master_ctx;

    if (ctx->log_event != NULL) {
        struct st_picoquic_log_event_t* picoquic_log_event = (struct st_picoquic_log_event_t*)ctx->log_event;
        if (picoquic_log_event != NULL && picoquic_log_event->fp != NULL) {
            picoquic_file_close(picoquic_log_event->fp);
        }
        free(ctx->log_event);
        ctx->log_event = NULL;
    }
}


/**
 * Sets the output file handle for writing traffic secrets in a format that can
 * be recognized by Wireshark.
 */
void picoquic_set_key_log_file(picoquic_quic_t *quic, char const * keylog_filename)
{
    ptls_context_t* ctx = (ptls_context_t*)quic->tls_master_ctx;
    struct st_picoquic_log_event_t* log_event = (struct st_picoquic_log_event_t*)ctx->log_event;

    if (log_event == NULL) {
        log_event = (struct st_picoquic_log_event_t*)malloc(sizeof(struct st_picoquic_log_event_t));
        if (log_event != NULL) {
            log_event->super.cb = picoquic_log_event_call_back;
        }
    }
    else {
        if (log_event->fp != NULL) {
            picoquic_file_close(log_event->fp);
            log_event->fp = NULL;
        }
    }

    if (log_event != NULL) {
        log_event->fp = picoquic_file_open(keylog_filename, "a");
        log_event->super.cb = picoquic_log_event_call_back;
        ctx->log_event = (ptls_log_event_t*)log_event;
    }

    ctx->log_event = (ptls_log_event_t*)log_event;
}

/*
Check whether the ticket that was received, or used, authorizes 0-RTT data.

From TLS 1.3 spec:
struct {
uint32 ticket_lifetime;
uint32 ticket_age_add;
opaque ticket_nonce<0..255>;
opaque ticket<1..2^16-1>;
Extension extensions<0..2^16-2>;
} NewSessionTicket;

struct {
ExtensionType extension_type;
opaque extension_data<0..2^16-1>;
} Extension;
*/

int picoquic_does_tls_ticket_allow_early_data(uint8_t* ticket, uint16_t ticket_length)
{
    uint8_t nonce_length = 0;
    uint16_t ticket_val_length = 0;
    uint16_t extension_length = 0;
    uint8_t* extension_ptr = NULL;
    uint16_t byte_index = 0;
    uint16_t min_length = 4 + 4 + 1 + 2 + 2;
    int ret = 0;

    if (ticket_length >= min_length) {
        byte_index += 4; /* Skip lifetime */
        byte_index += 4; /* Skip age add */
        nonce_length = ticket[byte_index++];
        min_length += nonce_length;
        if (ticket_length >= min_length) {
            byte_index += nonce_length;

            ticket_val_length = PICOPARSE_16(ticket + byte_index);
            byte_index += 2;
            min_length += ticket_val_length;
            if (ticket_length >= min_length) {
                byte_index += ticket_val_length;

                extension_length = PICOPARSE_16(ticket + byte_index);
                byte_index += 2;
                min_length += extension_length;
                if (ticket_length >= min_length) {
                    extension_ptr = &ticket[byte_index];
                }
            }
        }
    }

    if (extension_ptr != NULL) {
        uint16_t x_index = 0;

        while (x_index + 4 < extension_length) {
            uint16_t x_type = PICOPARSE_16(extension_ptr + x_index);
            uint16_t x_len = PICOPARSE_16(extension_ptr + x_index + 2);
            x_index += 4 + x_len;

            if (x_type == 42 && x_len == 4) {
                uint32_t ed_len = PICOPARSE_32(extension_ptr + x_index - 4);
                if (ed_len == 0xFFFFFFFF) {
                    ret = 1;
                }
                break;
            }
        }
    }

    return ret;
}

/*
* Creation of a TLS context.
* This includes setting the handshake properties that will later be
* used during the TLS handshake.
*/
void picoquic_tlscontext_remove_ticket(picoquic_cnx_t* cnx)
{
    /* allocate a context structure */
    picoquic_tls_ctx_t* ctx = (picoquic_tls_ctx_t*)(cnx->tls_ctx);

    ctx->handshake_properties.client.session_ticket.base = NULL;
    ctx->handshake_properties.client.session_ticket.len = 0;
}

void picoquic_tlscontext_free(void* vctx)
{
    picoquic_tls_ctx_t* ctx = (picoquic_tls_ctx_t*)vctx;

    if (ctx->ext_data != NULL) {
        free(ctx->ext_data);
    }

    if (ctx->alpn_vec != NULL) {
        free(ctx->alpn_vec);
    }

    if (ctx->tls != NULL) {
        ptls_free((ptls_t*)ctx->tls);
        ctx->tls = NULL;
    }
    free(ctx);
}


void picoquic_tlscontext_trim_after_handshake(picoquic_cnx_t * cnx)
{
    picoquic_tls_ctx_t* ctx = (picoquic_tls_ctx_t*)cnx->tls_ctx;

    if (ctx->ext_data != NULL) {
        free(ctx->ext_data);
        ctx->ext_data = NULL;
        ctx->ext_data_size = 0;
    }

    if (ctx->alpn_vec != NULL) {
        free(ctx->alpn_vec);
        ctx->alpn_vec = NULL;
        ctx->alpn_vec_size = 0;
    }
}

char const* picoquic_tls_get_negotiated_alpn(picoquic_cnx_t* cnx)
{
    picoquic_tls_ctx_t* ctx = (picoquic_tls_ctx_t*)cnx->tls_ctx;

    return ptls_get_negotiated_protocol(ctx->tls);
}

char const* picoquic_tls_get_sni(picoquic_cnx_t* cnx)
{
    picoquic_tls_ctx_t* ctx = (picoquic_tls_ctx_t*)cnx->tls_ctx;

    return ptls_get_server_name(ctx->tls);
}

int picoquic_tls_is_psk_handshake(picoquic_cnx_t* cnx)
{
    /* int ret = cnx->is_psk_handshake; */
    int ret = ptls_is_psk_handshake(((picoquic_tls_ctx_t*)(cnx->tls_ctx))->tls);
    return ret;
}


/*
* Sending data on the crypto stream.
*/

static int picoquic_add_to_tls_stream(picoquic_cnx_t* cnx, const uint8_t* data, size_t length, int epoch)
{
    int ret = 0;
    picoquic_stream_head_t* stream = &cnx->tls_stream[epoch];

    if (length > 0) {
        picoquic_stream_queue_node_t* stream_data = (picoquic_stream_queue_node_t*)
            malloc(sizeof(picoquic_stream_queue_node_t));
        if (stream_data == 0) {
            ret = -1;
        }
        else {
            stream_data->bytes = (uint8_t*)malloc(length);

            if (stream_data->bytes == NULL) {
                free(stream_data);
                stream_data = NULL;
                ret = -1;
            }
            else {
                picoquic_stream_queue_node_t** pprevious = &stream->send_queue;
                picoquic_stream_queue_node_t* next = stream->send_queue;

                memcpy(stream_data->bytes, data, length);
                stream_data->length = length;
                stream_data->offset = 0;
                stream_data->next_stream_data = NULL;

                while (next != NULL) {
                    pprevious = &next->next_stream_data;
                    next = next->next_stream_data;
                }

                *pprevious = stream_data;
            }
        }
    }

    return ret;
}

/* Add a supported ALPN context */
int picoquic_add_proposed_alpn(void* tls_context, const char* alpn)
{
    int ret = 0;
    picoquic_tls_ctx_t* ctx = (picoquic_tls_ctx_t*)tls_context;
    if (ctx == NULL) {
        ret = PICOQUIC_ERROR_UNEXPECTED_ERROR;
    }
    else if (ctx->alpn_count >= ctx->alpn_vec_size) {
        ret = PICOQUIC_ERROR_SEND_BUFFER_TOO_SMALL;
    } else {
        ctx->alpn_vec[ctx->alpn_count].base = (uint8_t*)alpn;
        ctx->alpn_vec[ctx->alpn_count].len = strlen(alpn);
        ctx->alpn_count++;
    }

    return ret;
}

/* Prepare the initial message when starting a connection.
 */

int picoquic_initialize_tls_stream(picoquic_cnx_t* cnx, uint64_t current_time)
{
    int ret = 0;
    struct st_ptls_buffer_t sendbuf;
    picoquic_tls_ctx_t* ctx = (picoquic_tls_ctx_t*)cnx->tls_ctx;
    size_t epoch_offsets[PICOQUIC_NUMBER_OF_EPOCH_OFFSETS] = { 0, 0, 0, 0, 0 };

    if (cnx->sni != NULL) {
        ptls_set_server_name(ctx->tls, cnx->sni, strlen(cnx->sni));
    }

    if (cnx->alpn != NULL) {
        ctx->alpn_vec[0].base = (uint8_t*)cnx->alpn;
        ctx->alpn_vec[0].len = strlen(cnx->alpn);
        ctx->handshake_properties.client.negotiated_protocols.count = 1;
        ctx->handshake_properties.client.negotiated_protocols.list = ctx->alpn_vec;
    }
    else if (cnx->callback_fn != NULL) {
        /* Get the default ALPN list for the callback function */
        ret = cnx->callback_fn(cnx, 0, (uint8_t*)ctx, 0, picoquic_callback_request_alpn_list, cnx->callback_ctx, NULL);

        ctx->handshake_properties.client.negotiated_protocols.count = ctx->alpn_count;
        ctx->handshake_properties.client.negotiated_protocols.list = ctx->alpn_vec;

        if (ret != 0) {
            DBG_PRINTF("ALPN list callback returns 0x%x", ret);
        }
    }

    /* ALPN is mandatory, there should be at least one */
    if (ret == 0 && ctx->handshake_properties.client.negotiated_protocols.count == 0) {
        ret = PICOQUIC_ERROR_NO_ALPN_PROVIDED;
        DBG_PRINTF("No ALPN provided, error 0x%x", ret);
    }

    picoquic_log_negotiated_alpn(cnx,
            1, (const uint8_t *)cnx->sni, (cnx->sni == NULL)?0:strlen(cnx->sni), NULL, 0,
            ctx->handshake_properties.client.negotiated_protocols.list, 
            ctx->handshake_properties.client.negotiated_protocols.count);

    /* No resumption if no alpn specified upfront, because it would make the negotiation and
     * the handling of 0-RTT way too messy */
    if (cnx->sni != NULL && cnx->alpn != NULL && !cnx->quic->client_zero_share) {
        picoquic_stored_ticket_t* stored_ticket = picoquic_get_stored_ticket(cnx->quic, 
            cnx->sni, (uint16_t)strlen(cnx->sni), cnx->alpn, (uint16_t)strlen(cnx->alpn),
            picoquic_supported_versions[cnx->version_index].version, 1, 0);
        if (stored_ticket != NULL) {
            ctx->handshake_properties.client.session_ticket.base = stored_ticket->ticket;
            ctx->handshake_properties.client.session_ticket.len = stored_ticket->ticket_length;
            ctx->handshake_properties.client.max_early_data_size = &cnx->max_early_data_size;
            /* Remember first 8 bytes of ticket as ticket ID, and set psk suite from ticket */
            cnx->resumed_ticket_id = PICOPARSE_64(stored_ticket->ticket);
            cnx->psk_cipher_suite_id = PICOPARSE_16(stored_ticket->ticket + 8);
            /* Set initial transport parameters from stored values */
            cnx->remote_parameters.initial_max_data = stored_ticket->tp_0rtt[picoquic_tp_0rtt_max_data];
            cnx->remote_parameters.initial_max_stream_data_bidi_local = stored_ticket->tp_0rtt[picoquic_tp_0rtt_max_stream_data_bidi_local];
            cnx->remote_parameters.initial_max_stream_data_bidi_remote = stored_ticket->tp_0rtt[picoquic_tp_0rtt_max_stream_data_bidi_remote];
            cnx->remote_parameters.initial_max_stream_data_uni = stored_ticket->tp_0rtt[picoquic_tp_0rtt_max_stream_data_uni];
            cnx->remote_parameters.initial_max_stream_id_bidir = stored_ticket->tp_0rtt[picoquic_tp_0rtt_max_streams_id_bidir];
            cnx->remote_parameters.initial_max_stream_id_unidir = stored_ticket->tp_0rtt[picoquic_tp_0rtt_max_streams_id_unidir];

            if (stored_ticket->time_valid_until > current_time) {
                /* Seed connection with remembered data */
                picoquic_seed_bandwidth(cnx, stored_ticket->tp_0rtt[picoquic_tp_0rtt_rtt_local],
                    stored_ticket->tp_0rtt[picoquic_tp_0rtt_cwin_local],
                    stored_ticket->ip_addr, stored_ticket->ip_addr_length);
            }
        }
    }

    if (cnx->quic->client_zero_share &&
        cnx->cnx_state == picoquic_state_client_init)
    {
        ctx->handshake_properties.client.negotiate_before_key_exchange = 1;
    }
    else
    {
        ctx->handshake_properties.client.negotiate_before_key_exchange = 0;
    }

    if (ret != 0) {
        DBG_PRINTF("Could not set up TLS parameters, error 0x%x, abandoning connection", ret);
        picoquic_connection_disconnect(cnx);
    } else {
        picoquic_tls_set_extensions(cnx, ctx);

        ptls_buffer_init(&sendbuf, "", 0);

        /* Clearing the global error state of the crypto provider before calling handle message.
         * This allows detection of errors during processing. */
        picoquic_clear_crypto_errors();
        ret = ptls_handle_message(ctx->tls, &sendbuf, epoch_offsets, 0, NULL, 0, &ctx->handshake_properties);

        /* assume that all the data goes to epoch 0, initial */
        if ((ret == 0 || ret == PTLS_ERROR_IN_PROGRESS)) {
            if (sendbuf.off > 0) {
                ret = picoquic_add_to_tls_stream(cnx, sendbuf.base, sendbuf.off, 0);
            }
            else {
                ret = 0;
            }
        }
        else {
            picoquic_log_crypto_errors(cnx, ret);
            ret = -1;
        }
        ptls_buffer_dispose(&sendbuf);
    }

    return ret;
}

/*
 * Packet number encryption and decryption utilities
 */

void * picoquic_pn_enc_create_for_test(const uint8_t * secret, const char *prefix_label)
{
    ptls_cipher_suite_t *cipher = picoquic_get_aes128gcm_sha256(1);
    void *v_pn_enc = NULL;
    
    (void)picoquic_set_pn_enc_from_secret(&v_pn_enc, cipher, 1, secret, prefix_label);

    return v_pn_enc;
}

size_t picoquic_pn_iv_size(void *pn_enc)
{
    return ((ptls_cipher_context_t *)pn_enc)->algo->iv_size;
}

void picoquic_pn_encrypt(void *pn_enc, const void * iv, void *output, const void *input, size_t len)
{
    ptls_cipher_init((ptls_cipher_context_t *) pn_enc, iv);
    ptls_cipher_encrypt((ptls_cipher_context_t *) pn_enc, output, input, len);
}

/* Utility functions, so applications do not have to load picotls.h */

void picoquic_aead_free(void* aead_context)
{
    ptls_aead_free((ptls_aead_context_t*)aead_context);
}

void picoquic_cipher_free(void* cipher_context)
{
    ptls_cipher_free((ptls_cipher_context_t*)cipher_context);
}


size_t picoquic_aead_get_checksum_length(void* aead_context)
{
    size_t tag_size = ((ptls_aead_context_t*)aead_context)->algo->tag_size;
    /* TODO: remove this temporary fix to deal with Feb 2019 change in picotls */
    if (tag_size > 16) {
        tag_size = 16;
    }
    return tag_size;
}

/* Setting of encryption contexts for test */
void * picoquic_setup_test_aead_context(int is_encrypt, const uint8_t * secret, const char *prefix_label)
{
    void * v_aead = NULL;
    ptls_cipher_suite_t* cipher = picoquic_get_aes128gcm_sha256(1);

    (void)picoquic_set_aead_from_secret(&v_aead, cipher, is_encrypt, secret, prefix_label);

    return v_aead;
}

int picoquic_server_setup_ticket_aead_contexts(picoquic_quic_t* quic,
    ptls_context_t* tls_ctx,
    const uint8_t* secret, size_t secret_length)
{
    int ret = 0;
    uint8_t temp_secret[256]; /* secret_max */
    ptls_cipher_suite_t *cipher = picoquic_get_aes128gcm_sha256(0);

    if (cipher->hash->digest_size > sizeof(temp_secret)) {
        ret = PICOQUIC_ERROR_UNEXPECTED_ERROR;
    } else {
        if (secret != NULL && secret_length > 0) {
            memset(temp_secret, 0, cipher->hash->digest_size);
            memcpy(temp_secret, secret, (secret_length > cipher->hash->digest_size) ? cipher->hash->digest_size : secret_length);
        } else {
            tls_ctx->random_bytes(temp_secret, cipher->hash->digest_size);
        }

        /* Create the AEAD contexts */
        ret = picoquic_set_aead_from_secret(&quic->aead_encrypt_ticket_ctx, cipher, 1, temp_secret, "random label");
        if (ret == 0) {
            ret = picoquic_set_aead_from_secret(&quic->aead_decrypt_ticket_ctx, cipher, 0, temp_secret, "random label");
        }

        /* erase the temporary secret */
        ptls_clear_memory(temp_secret, cipher->hash->digest_size);
    }
    return ret;
}

/* Access integrity limit for AEAD */
uint64_t picoquic_aead_integrity_limit(void* aead_ctx)
{
    return ((ptls_aead_context_t*)aead_ctx)->algo->integrity_limit;
}

/* Access confidentiality limit for AEAD */
uint64_t picoquic_aead_confidentiality_limit(void* aead_ctx)
{
    return ((ptls_aead_context_t*)aead_ctx)->algo->confidentiality_limit;
}

/* AEAD encrypt/decrypt routines */
size_t picoquic_aead_decrypt_generic(uint8_t* output, const uint8_t* input, size_t input_length,
    uint64_t seq_num, const uint8_t* auth_data, size_t auth_data_length, void* aead_ctx)
{
    size_t decrypted = 0;

    if (aead_ctx == NULL) {
        decrypted = SIZE_MAX;
    } else {
        decrypted = ptls_aead_decrypt((ptls_aead_context_t*)aead_ctx,
            (void*)output, (const void*)input, input_length, seq_num,
            (void*)auth_data, auth_data_length);
    }

    return decrypted;
}

size_t picoquic_aead_encrypt_generic(uint8_t* output, const uint8_t* input, size_t input_length,
    uint64_t seq_num, const uint8_t* auth_data, size_t auth_data_length, void* aead_context)
{
    size_t encrypted = 0;

    encrypted = ptls_aead_encrypt((ptls_aead_context_t*)aead_context,
        (void*)output, (const void*)input, input_length, seq_num,
        (void*)auth_data, auth_data_length);

    return encrypted;
}

size_t picoquic_aead_decrypt_mp(uint8_t* output, const uint8_t* input, size_t input_length,
    uint64_t path_id, uint64_t seq_num, const uint8_t* auth_data, size_t auth_data_length, void* aead_context)
{
    size_t decrypted = 0;

    if (aead_context == NULL) {
        decrypted = SIZE_MAX;
    }
    else {
        uint8_t seq32[4];

        picoformat_32(seq32, (uint32_t)path_id);
        ptls_aead_xor_iv((ptls_aead_context_t*)aead_context, seq32, sizeof(seq32));
        decrypted = ptls_aead_decrypt((ptls_aead_context_t*)aead_context,
            (void*)output, (const void*)input, input_length, seq_num,
            (void*)auth_data, auth_data_length);
        ptls_aead_xor_iv((ptls_aead_context_t*)aead_context, seq32, sizeof(seq32));
    }

    return decrypted;
}

size_t picoquic_aead_encrypt_mp(uint8_t* output, const uint8_t* input, size_t input_length,
    uint64_t path_id, uint64_t seq_num, const uint8_t* auth_data, size_t auth_data_length, void* aead_context)
{
    size_t encrypted = 0;
    uint8_t seq32[4];

    picoformat_32(seq32, (uint32_t)path_id);
    ptls_aead_xor_iv((ptls_aead_context_t*)aead_context, seq32, sizeof(seq32));
    encrypted = ptls_aead_encrypt((ptls_aead_context_t*)aead_context,
        (void*)output, (const void*)input, input_length, seq_num,
        (void*)auth_data, auth_data_length);
    ptls_aead_xor_iv((ptls_aead_context_t*)aead_context, seq32, sizeof(seq32));

    return encrypted;
}

/* management of version specific salt, for initial packet encryption.
 */

uint8_t picoquic_cleartext_null_salt[] = {
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0
};

static void picoquic_setup_cleartext_aead_salt(size_t version_index, ptls_iovec_t* salt)
{
    if (picoquic_supported_versions[version_index].version_aead_key != NULL && picoquic_supported_versions[version_index].version_aead_key_length > 0) {
        salt->base = picoquic_supported_versions[version_index].version_aead_key;
        salt->len = picoquic_supported_versions[version_index].version_aead_key_length;
    } else {
        salt->base = picoquic_cleartext_null_salt;
        salt->len = sizeof(picoquic_cleartext_null_salt);
    }
}

/* Input stream zero data to TLS context.
 *
 * Processing  depends on the "epoch" in which packets have been received. That
 * epoch is be passed through the ptls_handle_message() API.
 * The API has an "epoch offset" parameter that documents how many bytes of the
 * should be sent at each epoch.
 */

int picoquic_tls_stream_process(picoquic_cnx_t* cnx, int * data_consumed, uint64_t current_time)
{
    int ret = 0;
    picoquic_tls_ctx_t* ctx = (picoquic_tls_ctx_t*)cnx->tls_ctx;
    size_t next_epoch = 0;

    /* Provide indication of current connection for later callbacks */
    cnx->quic->cnx_in_progress = cnx;

    for (size_t epoch = 0; epoch < PICOQUIC_NUMBER_OF_EPOCHS && ret == 0; epoch++) {
        picoquic_stream_head_t* stream = &cnx->tls_stream[epoch];
        picoquic_stream_data_node_t* data = (picoquic_stream_data_node_t*)picosplay_first(&stream->stream_data_tree);
        size_t processed = 0;
        int data_pushed = 0;

        next_epoch = ptls_get_read_epoch(ctx->tls);

        if (epoch != next_epoch) {
            if (epoch > next_epoch) {
                break;
            } else {
                if (data != NULL && data->offset > stream->consumed_offset) {
                    /* Protocol error: data received that could not be read */
#ifdef _DEBUG
                    DBG_PRINTF("Connection error - TLS data at epoch %d, expected %d.\n",
                        epoch, next_epoch);
#endif
                    ret = picoquic_connection_error(cnx,
                        PICOQUIC_TRANSPORT_PROTOCOL_VIOLATION, 0);
                }
                continue;
            }
        }

        while ((ret == 0 || ret == PTLS_ERROR_IN_PROGRESS) &&
            data != NULL && data->offset <= stream->consumed_offset) {
            struct st_ptls_buffer_t sendbuf;
            size_t start = (size_t)(stream->consumed_offset - data->offset);
            size_t epoch_data = data->length - start;
            size_t send_offset[PICOQUIC_NUMBER_OF_EPOCH_OFFSETS] = { 0, 0, 0, 0, 0 };

            if (data_consumed != NULL) {
                *data_consumed = 1;
            }

            ptls_buffer_init(&sendbuf, "", 0);

            /* Clearing the global error state of the crypto provider before calling handle message.
             * This allows detection of errors during processing. */
            picoquic_clear_crypto_errors();

            ret = ptls_handle_message(ctx->tls, &sendbuf, send_offset, epoch,
                data->bytes + start, epoch_data, &ctx->handshake_properties);

            if ((ret == 0 || ret == PTLS_ERROR_IN_PROGRESS ||
                ret == PTLS_ERROR_STATELESS_RETRY)) {
                for (int i = 0; i < PICOQUIC_NUMBER_OF_EPOCHS; i++) {
                    if (send_offset[i] < send_offset[i + 1]) {
                        data_pushed = 1;
                        ret = picoquic_add_to_tls_stream(cnx,
                            sendbuf.base + send_offset[i], send_offset[i + 1] - send_offset[i], i);
                    }
                }
                if (cnx->client_mode) {
                    if (cnx->alpn == NULL) {
                        const char* alpn = ptls_get_negotiated_protocol(ctx->tls);

                        if (alpn != NULL){
                            cnx->alpn = picoquic_string_duplicate(alpn);

                            picoquic_log_negotiated_alpn(cnx, 0, NULL, 0, (const uint8_t*)alpn, strlen(alpn), NULL, 0);

                            if (cnx->callback_fn != NULL) {
                                cnx->callback_fn(cnx, 0, (uint8_t*)alpn, 0, picoquic_callback_set_alpn, cnx->callback_ctx, NULL);
                            }
                            else {
                                DBG_PRINTF("Negotiated ALPN: %s", alpn);
                            }
                        }
                    }
                    switch (ctx->handshake_properties.client.early_data_acceptance) {
                    case PTLS_EARLY_DATA_REJECTED:
                        cnx->zero_rtt_data_accepted = 0;
                        break;
                    case PTLS_EARLY_DATA_ACCEPTED:
                        cnx->zero_rtt_data_accepted = 1;
                        break;
                    default:
                        break;
                    }
                }
            }
            else {
                picoquic_log_crypto_errors(cnx, ret);
            }

            stream->consumed_offset += epoch_data;
            processed += epoch_data;

            if (start + epoch_data >= data->length) {
                picosplay_delete_hint(&cnx->tls_stream[epoch].stream_data_tree, &data->stream_data_node);
                data = (picoquic_stream_data_node_t*)picosplay_first(&cnx->tls_stream[epoch].stream_data_tree);
            }

            ptls_buffer_dispose(&sendbuf);
        }

        if (processed > 0) {
            if (ret == 0) {
                switch (cnx->cnx_state) {
                case picoquic_state_client_retry_received:
                    /* This is not supposed to happen -- HRR should generate "error in progress" */
                    break;
                case picoquic_state_client_init:
                case picoquic_state_client_init_sent:
                case picoquic_state_client_renegotiate:
                case picoquic_state_client_init_resent:
                case picoquic_state_client_handshake_start:
                    if (ptls_handshake_is_complete(ctx->tls)) {
                        if (cnx->remote_parameters_received == 0) {

#ifdef _DEBUG
                            DBG_PRINTF("%s", "Connection error - no transport parameter received.\n");
#endif
                            ret = picoquic_connection_error(cnx,
                                PICOQUIC_TRANSPORT_PARAMETER_ERROR, 0);
                        }
                        else {
                            if (cnx->crypto_context[3].aead_encrypt != NULL) {
                                picoquic_client_almost_ready_transition(cnx);
                            }
                        }
                    }
                    break;
                case picoquic_state_server_init:
                case picoquic_state_server_handshake:
                    /* If client authentication is activated, the client sends the certificates with its `Finished` packet.
                       The server does not send any further packets, so, we can switch into false start state here.
                    */
                    if (data_pushed == 0 && ((ptls_context_t*)cnx->quic->tls_master_ctx)->require_client_authentication == 1) {
                        picoquic_false_start_transition(cnx, current_time);
                    }
                    else {
                        if (cnx->crypto_context[3].aead_encrypt != NULL) {
                            cnx->cnx_state = picoquic_state_server_almost_ready;
                        }
                    }
                    break;
                case picoquic_state_client_almost_ready:
                case picoquic_state_handshake_failure:
                case picoquic_state_handshake_failure_resend:
                case picoquic_state_client_ready_start:
                case picoquic_state_server_almost_ready:
                case picoquic_state_server_false_start:
                case picoquic_state_ready:
                case picoquic_state_disconnecting:
                case picoquic_state_closing_received:
                case picoquic_state_closing:
                case picoquic_state_draining:
                case picoquic_state_disconnected:
                    break;
                default:
                    DBG_PRINTF("Unexpected connection state: %d\n", cnx->cnx_state);
                    break;
                }
            }
            else if (ret == PTLS_ERROR_IN_PROGRESS && (cnx->cnx_state == picoquic_state_client_init || cnx->cnx_state == picoquic_state_client_init_sent || cnx->cnx_state == picoquic_state_client_init_resent)) {
                /* Extract and install the client 0-RTT key */
#ifdef _DEBUG
                DBG_PRINTF("%s", "Handshake not yet complete.\n");
#endif
            }
            else if (ret == PTLS_ERROR_IN_PROGRESS &&
                (cnx->cnx_state == picoquic_state_server_init ||
                    cnx->cnx_state == picoquic_state_server_handshake))
            {
                if (ptls_handshake_is_complete(ctx->tls))
                {
                    cnx->cnx_state = picoquic_state_server_almost_ready;
                }
            }

            if ((ret == 0 || ret == PTLS_ERROR_IN_PROGRESS || ret == PTLS_ERROR_STATELESS_RETRY)) {
                ret = 0;
            }
            else {
                uint16_t error_code = PICOQUIC_TRANSPORT_INTERNAL_ERROR;

                if (PTLS_ERROR_GET_CLASS(ret) == PTLS_ERROR_CLASS_SELF_ALERT) {
                    error_code = PICOQUIC_TRANSPORT_CRYPTO_ERROR(ret);
                }
#ifdef _DEBUG
                DBG_PRINTF("Handshake failed, ret = 0x%x.\n", ret);
#endif
                (void)picoquic_connection_error(cnx, error_code, 0);
                ret = 0;
            }
        }
    }

    /* Reset indication of current connection */
    cnx->quic->cnx_in_progress = NULL;

    return ret;
}

/*
 * Test whether the TLS handshake is complete according to TLS stack
 */
int picoquic_is_tls_complete(picoquic_cnx_t* cnx)
{
    picoquic_tls_ctx_t* ctx = (picoquic_tls_ctx_t*)cnx->tls_ctx;
    return ptls_handshake_is_complete(ctx->tls);
}

/*
 * Compute the 16 byte reset secret associated with a connection ID.
 * We implement it as the hash of a secret seed maintained per QUIC context
 * and the 8 bytes connection ID.
 * This is written portable hash APIs.
 */

int picoquic_create_cnxid_reset_secret(picoquic_quic_t* quic, picoquic_connection_id_t * cnx_id,
    uint8_t reset_secret[PICOQUIC_RESET_SECRET_SIZE])
{
    int ret = 0;
    ptls_hash_algorithm_t* algo = picoquic_get_sha256();

    if (algo == NULL) {
        ret = -1;
    }
    else {
        ptls_hash_context_t* hash_ctx = algo->create();
        uint8_t final_hash[PTLS_MAX_DIGEST_SIZE];

        if (hash_ctx == NULL) {
            ret = -1;
            memset(reset_secret, 0, PICOQUIC_RESET_SECRET_SIZE);
        }
        else {
            hash_ctx->update(hash_ctx, quic->reset_seed, sizeof(quic->reset_seed));
            hash_ctx->update(hash_ctx, cnx_id, sizeof(picoquic_connection_id_t));
            hash_ctx->final(hash_ctx, final_hash, PTLS_HASH_FINAL_MODE_FREE);
            memcpy(reset_secret, final_hash, PICOQUIC_RESET_SECRET_SIZE);
        }
    }

    return (ret);
}

void picoquic_set_tls_certificate_chain(picoquic_quic_t* quic, ptls_iovec_t* certs, size_t count)
{
    ptls_context_t* ctx = (ptls_context_t*)quic->tls_master_ctx;

    free_certificates_list(ctx->certificates.list, ctx->certificates.count);

    ctx->certificates.list = certs;
    ctx->certificates.count = count;
}

void picoquic_tls_set_client_authentication(picoquic_quic_t* quic, int client_authentication) {
    ((ptls_context_t*)quic->tls_master_ctx)->require_client_authentication = client_authentication;
}

int picoquic_tls_client_authentication_activated(picoquic_quic_t* quic) {
    return ((ptls_context_t*)quic->tls_master_ctx)->require_client_authentication;
}

/* 
 * Create or verify a token. Tokens are tied to an IP address and a time of
 * issue, and come in two variations:
 * - specific tokens are tied to an Original DCID.
 * - generic tokens work with a zero length DCID.
 * The structure of the token is:
 * - time valid until: uint64_t
 * - ODCID length, one byte
 * - ODCID, length bytes
 * This is encrypted using the same AEAD contexts as the encryption of session tickets.
 * The encrypted structure is:
 * - 64 bit random sequence number.
 * - Encrypted value of the token.
 * - AEAD checksum.
 * The most significant bit of the random number is set to 1 (0x80) for a "new token",
 * and to zero for a "retry token".
 * When invoking AEAD, the sequence number is used to update the IV, and the IP address
 * is passed as "authenticated" data. The 64 bit random number alleviates the concern of
 * reusing the same AEAD key twice. The authenticated data ensures that if the token is
 * used from a different address, the decryption will fail.
 */

static int picoquic_server_encrypt_retry_token(picoquic_quic_t * quic, const struct sockaddr * addr_peer,
    int is_new_token,
    uint8_t * token, size_t * token_length, size_t token_max, const uint8_t * text, size_t text_length)
{
    int ret = 0;
    uint64_t sequence;
    uint8_t* auth_data;
    size_t auth_data_length;

    if (text_length + 1u + 16u > token_max) {
        ret = -1;
        *token_length = 0;
    }
    else {

        if (addr_peer->sa_family == AF_INET) {
            auth_data = (uint8_t*)&((struct sockaddr_in*)addr_peer)->sin_addr;
            auth_data_length = 4;
        }
        else {
            auth_data = (uint8_t*)&((struct sockaddr_in6*)addr_peer)->sin6_addr;
            auth_data_length = 16;
        }
        picoquic_crypto_random(quic, token, 8);
        if (is_new_token) {
            token[0] |= 0x80;
        }
        else {
            token[0] &= 0x7F;
        }
        sequence = PICOPARSE_64(token);

        *token_length = (size_t)8u + picoquic_aead_encrypt_generic(token + 8, text, text_length,
            sequence, auth_data, auth_data_length, quic->aead_encrypt_ticket_ctx);
    }

    return ret;
}

int picoquic_server_decrypt_retry_token(picoquic_quic_t* quic, const struct sockaddr * addr_peer,
    int * is_new_token, const uint8_t * token, size_t token_length, uint8_t * text, size_t *text_length)
{
    int ret = 0;
    uint64_t sequence;
    uint8_t* auth_data;
    size_t auth_data_length;

    if (addr_peer->sa_family == AF_INET) {
        auth_data = (uint8_t*)&((struct sockaddr_in *)addr_peer)->sin_addr;
        auth_data_length = 4;
    }
    else {
        auth_data = (uint8_t*)&((struct sockaddr_in6 *)addr_peer)->sin6_addr;
        auth_data_length = 16;
    }

    if (token_length < 8) {
        *is_new_token = 0;
        ret = -1;
    }
    else {
        *is_new_token = ((token[0] & 0x80) == 0) ? 0: 1;
        sequence = PICOPARSE_64(token);

        *text_length = picoquic_aead_decrypt_generic(text, token+8, token_length-8,
            sequence, auth_data, auth_data_length, quic->aead_decrypt_ticket_ctx);
        if (*text_length >= token_length - 8) {
            ret = -1;
        }
    }

    return ret;
}

int picoquic_prepare_retry_token(picoquic_quic_t* quic, const struct sockaddr* addr_peer,
    uint64_t current_time, const picoquic_connection_id_t* odcid, const picoquic_connection_id_t* rcid,
    uint32_t initial_pn,
    uint8_t* token, size_t token_max, size_t* token_size)
{
    int ret = 0;
    uint8_t text[128];
    uint64_t token_time = current_time;
    uint8_t* bytes = text;
    uint8_t* bytes_max = text + sizeof(text);

    /* set a short life time for short lived tokens, 24 hours otherwise */
    if (odcid->id_len == 0) {
        token_time += 24ull * 3600ull * 1000000ull;
    }
    else {
        token_time += 4000000ull;
    }
    /* serialize the token components */
    if ((bytes = picoquic_frames_uint64_encode(bytes, bytes_max, token_time)) != NULL &&
        (bytes = picoquic_frames_cid_encode(bytes, bytes_max, odcid)) != NULL &&
        (bytes = picoquic_frames_cid_encode(bytes, bytes_max, rcid)) != NULL &&
        (bytes = picoquic_frames_varint_encode(bytes, bytes_max, initial_pn)) != NULL) {
        /* Pad to min token size */
        while (bytes < text + PICOQUIC_RETRY_TOKEN_PAD_SIZE) {
            *bytes++ = 0;
        }
        /* Encode the clear text components */
        ret = picoquic_server_encrypt_retry_token(quic, addr_peer, odcid->id_len == 0,
            token, token_size, token_max, text, bytes - text);
    }
    else {
        ret = -1;
    }

    return ret;
}

int picoquic_verify_retry_token(picoquic_quic_t* quic, const struct sockaddr * addr_peer,
    uint64_t current_time, int * is_new_token, picoquic_connection_id_t * odcid, const picoquic_connection_id_t* rcid,
    uint32_t initial_pn,
    const uint8_t * token, size_t token_size, int check_reuse)
{
    int ret = 0;
    uint8_t text[128];
    size_t text_len = 0;
    picoquic_connection_id_t cid;
    uint64_t token_pn;

    odcid->id_len = 0;

    /* decode the encrypted token */
    if (token_size > sizeof(text)) {
        /* regular tokens produced by picoquic are always short, and a short decoding
        * buffer should be sufficient. If this text fires, it probably because of
        * an attack, or buggy code at the peer. */
        ret = -1;
    }
    else {
        ret = picoquic_server_decrypt_retry_token(quic, addr_peer, is_new_token, token, token_size,
            text, &text_len);
    }

    if (ret == 0) {
        /* Decode the clear text components */
        const uint8_t* bytes = text;
        const uint8_t* bytes_max = text + text_len;
        uint64_t token_time = PICOPARSE_64(text);

        if ((bytes = picoquic_frames_uint64_decode(bytes, bytes_max, &token_time)) != NULL &&
            (bytes = picoquic_frames_cid_decode(bytes, bytes_max, odcid)) != NULL &&
            (bytes = picoquic_frames_cid_decode(bytes, bytes_max, &cid)) != NULL &&
            (bytes = picoquic_frames_varint_decode(bytes, bytes_max, &token_pn)) != NULL) {
            if (token_time < current_time) {
                /* Invalid token, too old */
                ret = -1;
            }
            /* If the PN value is not yet decrypted, setting it to UINT32_MAX
             * bypasses the verification */
            else if (initial_pn != UINT32_MAX && odcid->id_len > 0 && token_pn >= initial_pn) {
                /* Invalid PN number */
                ret = -1;
            }
            else {
                /* Remove old tickets before testing this one. */
                picoquic_registered_token_clear(quic, current_time);
                if (check_reuse && (ret = picoquic_registered_token_check_reuse(quic, token, token_size, token_time)) != 0) {
                    picoquic_log_context_free_app_message(quic, rcid, "Duplicate token test returns %d", ret);
                }
                else if (odcid->id_len > 0 &&
                    picoquic_compare_connection_id(rcid, &cid) != 0) {
                    /* Invalid token, bad rcid */
                    ret = -1;
                }
            }
        }
        else {
            *odcid = picoquic_null_connection_id;
        }
    }

    return ret;
}

/*
 * Encryption functions for CID encryption
 */

void picoquic_cid_free_under_mask_ctx(void * v_cid_enc)
{
    if (v_cid_enc != NULL) {
        ptls_cipher_free((ptls_cipher_context_t *)v_cid_enc);
    }
}

int picoquic_cid_get_under_mask_ctx(void ** v_cid_enc, const void *secret, const char *prefix_label)
{
    uint8_t cidkey[PTLS_MAX_SECRET_SIZE];
    uint8_t long_secret[PTLS_MAX_DIGEST_SIZE];
    ptls_cipher_suite_t * cipher = picoquic_get_aes128gcm_sha256(1);
    int ret;

    picoquic_cid_free_under_mask_ctx(*v_cid_enc);
    *v_cid_enc = NULL;
    /* Secret is only guaranteed to be 16 bytes long. Avoid excess length issues */
    memset(long_secret, 0, sizeof(long_secret));
    memcpy(long_secret, secret, 16);

    if ((ret = ptls_hkdf_expand_label(cipher->hash, cidkey,
        cipher->aead->ctr_cipher->key_size, ptls_iovec_init(long_secret, cipher->hash->digest_size),
        PICOQUIC_LABEL_CID, ptls_iovec_init(NULL, 0), prefix_label)) == 0) {
#ifdef _DEBUG
        DBG_PRINTF("CID Encryption key (%d):\n", (int)cipher->aead->ctr_cipher->key_size);
        debug_dump(cidkey, (int)cipher->aead->ctr_cipher->key_size);
#endif
        if ((*v_cid_enc = ptls_cipher_new(cipher->aead->ctr_cipher, 1, cidkey)) == NULL) {
            ret = PTLS_ERROR_NO_MEMORY;
        }
    }

    return ret;
}

void picoquic_cid_encrypt_under_mask(void *cid_enc, const picoquic_connection_id_t * cid_in, const picoquic_connection_id_t * mask,
    picoquic_connection_id_t * cid_out)
{
    uint8_t unmasked[18];
    uint8_t val[18];

    memset(unmasked, 0, 18);
    memset(val, 0, 18);

    for (uint8_t i = 0; i < cid_in->id_len; i++) {
        /* retain only the random bits */
        unmasked[i] = cid_in->id[i] & mask->id[i];
    }

    ptls_cipher_init((ptls_cipher_context_t *)cid_enc, unmasked);
    ptls_cipher_encrypt((ptls_cipher_context_t *)cid_enc, val, val, cid_in->id_len);

    for (uint8_t i = 0; i < cid_in->id_len; i++) {
        /* randomize the unmasked bits */
        cid_out->id[i] = cid_in->id[i]^(val[i] & ~mask->id[i]);
    }
    cid_out->id_len = cid_in->id_len;
    if (cid_out->id_len < 18) {
        memset(cid_out->id + cid_out->id_len, 0, 18 - cid_out->id_len);
    }
}

void picoquic_cid_decrypt_under_mask(void *cid_enc, const picoquic_connection_id_t * cid_in, const picoquic_connection_id_t * mask,
    picoquic_connection_id_t * cid_out)
{
    picoquic_cid_encrypt_under_mask(cid_enc, cid_in, mask, cid_out);
}

/* Retry Packet Protection.
 * This is done by applying AES-GCM128 with a constant key and a NULL nonce,
 * using an extension of the retry packet as authenticated data and a zero
 * length content, computing a 16 bytes checksum. Or verifying it in the
 * other direction.
 *
 * The retry protection key is stored in the Quic context. It is created on
 * first use, and deleted when the context is deleted.
 */

void * picoquic_create_retry_protection_context(int is_enc, uint8_t * key, const char *prefix_label)
{
    return (void *)picoquic_setup_test_aead_context(is_enc, key, prefix_label);
}

void * picoquic_find_retry_protection_context(picoquic_quic_t * quic, int version_index, int sending)
{
    void * aead_ctx = NULL;
    void ** aead_vector = (sending) ? quic->retry_integrity_sign_ctx : quic->retry_integrity_verify_ctx;

    if (picoquic_supported_versions[version_index].version_retry_key != NULL) {
        if (aead_vector == NULL) {
            if (sending) {
                quic->retry_integrity_sign_ctx = (void**)malloc(sizeof(void*)*picoquic_nb_supported_versions);
                aead_vector = quic->retry_integrity_sign_ctx;
            }
            else {
                quic->retry_integrity_verify_ctx = (void**)malloc(sizeof(void*)*picoquic_nb_supported_versions);
                aead_vector = quic->retry_integrity_verify_ctx;
            }
            if (aead_vector != NULL) {
                memset(aead_vector, 0, sizeof(void*)*picoquic_nb_supported_versions);
            }
        }

        if (aead_vector != NULL) {
            aead_ctx = aead_vector[version_index];
            if (aead_ctx == NULL) {
                aead_ctx = picoquic_create_retry_protection_context(sending, picoquic_supported_versions[version_index].version_retry_key,
                                                                    picoquic_supported_versions[version_index].tls_prefix_label);
                aead_vector[version_index] = aead_ctx;
            }
        }
    }

    return aead_ctx;
}

static void ** picoquic_delete_one_retry_protection_context(void ** ctx)
{
    if (ctx != NULL) {
        for (size_t i = 0; i < picoquic_nb_supported_versions; i++) {
            if (ctx[i] != NULL) {
                picoquic_aead_free(ctx[i]);
            }
        }
        free(ctx);
    }
    return NULL;
}

void picoquic_delete_retry_protection_contexts(picoquic_quic_t * quic)
{
    quic->retry_integrity_sign_ctx = picoquic_delete_one_retry_protection_context(quic->retry_integrity_sign_ctx);
    quic->retry_integrity_verify_ctx = picoquic_delete_one_retry_protection_context(quic->retry_integrity_verify_ctx);
}

static size_t picoquic_format_retry_protection_pseudo_packet(uint8_t * pseudo_packet, uint8_t * bytes, size_t byte_index, const picoquic_connection_id_t * odcid)
{
    size_t pseudo_index = 0;

    if (byte_index + odcid->id_len + 1 < PICOQUIC_MAX_PACKET_SIZE) {
        pseudo_packet[pseudo_index++] = odcid->id_len;
        memcpy(&pseudo_packet[pseudo_index], odcid->id, odcid->id_len);
        pseudo_index += odcid->id_len;
        memcpy(&pseudo_packet[pseudo_index], bytes, byte_index);
        pseudo_index += byte_index;
    }

    return pseudo_index;
}

size_t picoquic_encode_retry_protection(void * integrity_aead, uint8_t * bytes, size_t bytes_max, size_t byte_index, const picoquic_connection_id_t * odcid)
{
    size_t pseudo_index;
    uint8_t pseudo_packet[PICOQUIC_MAX_PACKET_SIZE];

    if (integrity_aead != NULL && byte_index + picoquic_aead_get_checksum_length(integrity_aead) < bytes_max &&
        (pseudo_index = picoquic_format_retry_protection_pseudo_packet(pseudo_packet, bytes, byte_index, odcid)) > 0){
        byte_index += picoquic_aead_encrypt_generic(bytes+byte_index, bytes+byte_index, 0, 0, pseudo_packet, pseudo_index, integrity_aead);
    }

    return byte_index;
}

int picoquic_verify_retry_protection(void * integrity_aead, uint8_t * bytes, size_t * length, size_t byte_index, const picoquic_connection_id_t * odcid)
{
    int ret = PICOQUIC_ERROR_AEAD_CHECK;
    size_t pseudo_index;
    uint8_t pseudo_packet[PICOQUIC_MAX_PACKET_SIZE];
    uint8_t decoded[PICOQUIC_MAX_PACKET_SIZE];
    size_t checksum_length = picoquic_aead_get_checksum_length(integrity_aead);

    if (byte_index + checksum_length < *length) {
        *length -= checksum_length;
        if ((pseudo_index = picoquic_format_retry_protection_pseudo_packet(pseudo_packet, bytes, *length, odcid)) > 0 &&
            picoquic_aead_decrypt_generic(decoded, bytes + *length, checksum_length, 0, pseudo_packet, pseudo_index, integrity_aead) == 0) {
            ret = 0;
        }
    }

    return ret;
}
