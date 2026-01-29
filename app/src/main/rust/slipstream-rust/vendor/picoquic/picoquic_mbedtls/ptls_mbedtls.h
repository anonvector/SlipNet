/*
* Copyright (c) 2023, Christian Huitema
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
#ifndef picotls_mbedtls_h
#define picotls_mbedtls_h

#ifdef __cplusplus
extern "C" {
#endif
#include "picotls.h"
#include "psa/crypto.h"
#include "mbedtls/x509_crt.h"

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

typedef struct st_ptls_mbedtls_signature_scheme_t {
    uint16_t scheme_id;
    psa_algorithm_t hash_algo;
} ptls_mbedtls_signature_scheme_t;

typedef struct st_ptls_mbedtls_sign_certificate_t {
    ptls_sign_certificate_t super;
    mbedtls_svc_key_id_t key_id;
    psa_key_attributes_t attributes;
    const ptls_mbedtls_signature_scheme_t * schemes;
} ptls_mbedtls_sign_certificate_t;

typedef struct st_ptls_mbedtls_certificate_t {
    ptls_verify_certificate_t super;
    mbedtls_x509_crt *trust_ca;
    mbedtls_x509_crl *trust_crl;
    int (*f_vrfy)(void*, mbedtls_x509_crt*, int, uint32_t*);
    void* p_vrfy;
} ptls_mbedtls_verify_certificate_t;

typedef struct st_mbedtls_message_verify_ctx_t {
    psa_key_id_t key_id;
} mbedtls_message_verify_ctx_t;

int ptls_mbedtls_load_private_key(char const* pem_fname, ptls_context_t* ctx);
void ptls_mbedtls_dispose_sign_certificate(ptls_sign_certificate_t* _self);
int ptls_mbedtls_sign_certificate(ptls_sign_certificate_t* _self, ptls_t* tls, ptls_async_job_t** async,
    uint16_t* selected_algorithm, ptls_buffer_t* outbuf, ptls_iovec_t input,
    const uint16_t* algorithms, size_t num_algorithms);

ptls_iovec_t* picoquic_mbedtls_get_certs_from_file(char const* pem_fname, size_t* count);
int ptls_mbedtls_load_certificates(ptls_context_t* ctx, char const* cert_pem_file);

ptls_verify_certificate_t* ptls_mbedtls_get_certificate_verifier(char const* pem_fname,
    unsigned int* is_cert_store_not_empty);
void ptls_mbedtls_dispose_verify_certificate(ptls_verify_certificate_t* v);

int ptls_mbedtls_load_file(char const* file_name, unsigned char** buf, size_t* n);

#ifdef __cplusplus
}
#endif
#endif /* picotls_mbedtls_h */
