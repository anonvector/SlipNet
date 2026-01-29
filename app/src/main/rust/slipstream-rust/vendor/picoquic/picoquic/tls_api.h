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

#ifndef TLS_API_H
#define TLS_API_H
#include "picoquic.h"
#include "picoquic_internal.h"

#define PICOQUIC_LABEL_INITIAL_CLIENT "client in"
#define PICOQUIC_LABEL_INITIAL_SERVER "server in"

#define PICOQUIC_LABEL_V1_TRAFFIC_UPDATE "quic ku"
#define PICOQUIC_LABEL_V2_TRAFFIC_UPDATE "quicv2 ku"

#define PICOQUIC_LABEL_KEY "key"
#define PICOQUIC_LABEL_IV "iv"
#define PICOQUIC_LABEL_HP "hp"
#define PICOQUIC_LABEL_CID "cid"
#define PICOQUIC_LABEL_CID_GLOBAL "cid global"
#define PICOQUIC_LABEL_CID_GLOBAL_ROUNDS 4

#define PICOQUIC_LABEL_QUIC_BASE NULL
#define PICOQUIC_LABEL_QUIC_V1_KEY_BASE "tls13 quic "
#define PICOQUIC_LABEL_QUIC_V2_KEY_BASE "tls13 quicv2 "

#ifdef __cplusplus
extern "C" {
#endif

int picoquic_master_tlscontext(picoquic_quic_t* quic, char const* cert_file_name, char const* key_file_name,
    char const * cert_root_file_name, const uint8_t* ticket_key, size_t ticket_key_length);

void picoquic_master_tlscontext_free(picoquic_quic_t* quic);

int picoquic_tlscontext_create(picoquic_quic_t* quic, picoquic_cnx_t* cnx, uint64_t current_time);

void picoquic_tlscontext_free(void* ctx);

void picoquic_tlscontext_trim_after_handshake(picoquic_cnx_t* cnx);

void picoquic_tlscontext_remove_ticket(picoquic_cnx_t* cnx);

int picoquic_tls_stream_process(picoquic_cnx_t* cnx, int* data_consumed, uint64_t current_time);
int picoquic_is_tls_complete(picoquic_cnx_t* cnx);

int picoquic_initialize_tls_stream(picoquic_cnx_t* cnx, uint64_t current_time);

uint64_t picoquic_get_tls_time(picoquic_quic_t* quic);

void picoquic_crypto_random(picoquic_quic_t* quic, void* buf, size_t len);
uint64_t picoquic_crypto_uniform_random(picoquic_quic_t* quic, uint64_t rnd_max);

uint64_t picoquic_public_random_64(void);
void picoquic_public_random_seed_64(uint64_t seed, int reset);
void picoquic_public_random_seed(picoquic_quic_t* quic);
void picoquic_public_random(void* buf, size_t len);
uint64_t picoquic_public_uniform_random(uint64_t rnd_max);

size_t picoquic_aead_get_checksum_length(void* aead_context);

size_t picoquic_aead_encrypt_generic(uint8_t* output, const uint8_t* input, size_t input_length,
    uint64_t seq_num, const uint8_t* auth_data, size_t auth_data_length, void* aead_context);
size_t picoquic_aead_decrypt_generic(uint8_t* output, const uint8_t* input, size_t input_length,
    uint64_t seq_num, const uint8_t* auth_data, size_t auth_data_length, void* aead_ctx);

size_t picoquic_aead_decrypt_mp(uint8_t* output, const uint8_t* input, size_t input_length, uint64_t path_id,
    uint64_t seq_num, const uint8_t* auth_data, size_t auth_data_length, void* aead_context);
size_t picoquic_aead_encrypt_mp(uint8_t* output, const uint8_t* input, size_t input_length, uint64_t path_id,
    uint64_t seq_num, const uint8_t* auth_data, size_t auth_data_length, void* aead_context);

uint64_t picoquic_aead_integrity_limit(void* aead_ctx);
uint64_t picoquic_aead_confidentiality_limit(void* aead_ctx);

void picoquic_aead_free(void* aead_context);
void picoquic_cipher_free(void* cipher_context);

size_t picoquic_pn_iv_size(void *pn_enc);

void picoquic_pn_encrypt(void *pn_enc, const void * iv, void *output, const void *input, size_t len);

typedef const struct st_ptls_cipher_suite_t ptls_cipher_suite_t;

int picoquic_setup_initial_master_secret(
    ptls_cipher_suite_t * cipher,
    ptls_iovec_t salt,
    picoquic_connection_id_t initial_cnxid,
    uint8_t * master_secret);

int picoquic_setup_initial_secrets(
    ptls_cipher_suite_t * cipher,
    uint8_t * master_secret,
    uint8_t * client_secret,
    uint8_t * server_secret);

int picoquic_setup_initial_traffic_keys(picoquic_cnx_t* cnx);

int picoquic_get_initial_aead_context(picoquic_quic_t* quic, int version_index, picoquic_connection_id_t* initial_cnxid,
    int is_client, int is_enc, void** aead_ctx, void** pn_enc_ctx);

uint8_t * picoquic_get_app_secret(picoquic_cnx_t* cnx, int is_enc);
size_t picoquic_get_app_secret_size(picoquic_cnx_t* cnx);
int picoquic_compute_new_rotated_keys(picoquic_cnx_t * cnx);
void picoquic_apply_rotated_keys(picoquic_cnx_t * cnx, int is_enc);
int picoquic_rotate_app_secret(ptls_cipher_suite_t * cipher, uint8_t * secret, const char *traffic_update_label);

void picoquic_crypto_context_free(picoquic_crypto_context_t * ctx);

void * picoquic_setup_test_aead_context(int is_encrypt, const uint8_t * secret, const char *prefix_label);
void * picoquic_pn_enc_create_for_test(const uint8_t * secret, const char *prefix_label);

int picoquic_create_cnxid_reset_secret(picoquic_quic_t* quic, picoquic_connection_id_t * cnx_id,
    uint8_t reset_secret[PICOQUIC_RESET_SECRET_SIZE]);

char const* picoquic_tls_get_negotiated_alpn(picoquic_cnx_t* cnx);
char const* picoquic_tls_get_sni(picoquic_cnx_t* cnx);

void picoquic_tls_set_verify_certificate_callback(picoquic_quic_t* quic,
    struct st_ptls_verify_certificate_t* cb, picoquic_free_verify_certificate_ctx free_fn);

void picoquic_dispose_verify_certificate_callback(picoquic_quic_t* quic);

void picoquic_tls_set_client_authentication(picoquic_quic_t* quic, int client_authentication);

int picoquic_tls_client_authentication_activated(picoquic_quic_t* quic);

int picoquic_server_decrypt_retry_token(picoquic_quic_t* quic, const struct sockaddr* addr_peer, 
    int * is_new_token, const uint8_t* token, size_t token_length, uint8_t* text, size_t* text_length);

int picoquic_prepare_retry_token(picoquic_quic_t* quic, const struct sockaddr * addr_peer,
    uint64_t current_time, const picoquic_connection_id_t * odcid, const picoquic_connection_id_t* rcid,
    uint32_t initial_pn,
    uint8_t * token, size_t token_max, size_t * token_size);

int picoquic_verify_retry_token(picoquic_quic_t* quic, const struct sockaddr * addr_peer,
    uint64_t current_time, int * is_new_token, picoquic_connection_id_t * odcid, 
    const picoquic_connection_id_t* rcid, uint32_t initial_pn,
    const uint8_t * token, size_t token_size, int check_reuse);

void picoquic_cid_free_under_mask_ctx(void * v_pn_enc);
int picoquic_cid_get_under_mask_ctx(void ** v_pn_enc, const void * secret, const char *prefix_label);
void picoquic_cid_encrypt_under_mask(void * cid_enc, const picoquic_connection_id_t * cid_in, const picoquic_connection_id_t * mask, picoquic_connection_id_t * cid_out);
void picoquic_cid_decrypt_under_mask(void * cid_enc, const picoquic_connection_id_t * cid_in, const picoquic_connection_id_t * mask, picoquic_connection_id_t * cid_out);

void picoquic_cid_free_encrypt_global_ctx(void ** v_cid_enc);

/* Define hash functions here so applications don't need to directly interface picotls */
#define PICOQUIC_HASH_SIZE_MAX 64
void * picoquic_hash_create(char const * algorithm_name);
#if 0
size_t picoquic_hash_get_length(char const* algorithm_name);
#endif
void picoquic_hash_update(uint8_t* input, size_t input_length, void* hash_context);
void picoquic_hash_finalize(uint8_t* output, void* hash_context);

#if 0
uint8_t* picoquic_get_private_key_from_file(char const* file_name, int* key_length);
#endif
int picoquic_set_private_key_from_file(picoquic_quic_t* quic, char const* file_name);
ptls_iovec_t* picoquic_get_certs_from_file(char const* file_name, size_t * count);


/* Special AEAD context definition functions used for stateless retry integrity protection */
void * picoquic_create_retry_protection_context(int is_enc, uint8_t * key, const char *prefix_label);
void * picoquic_find_retry_protection_context(picoquic_quic_t * quic, int version_index, int sending);
void picoquic_delete_retry_protection_contexts(picoquic_quic_t * quic);
size_t picoquic_encode_retry_protection(void * integrity_aead, uint8_t * bytes, size_t bytes_max, size_t byte_index, const picoquic_connection_id_t * odcid);
int picoquic_verify_retry_protection(void * integrity_aead, uint8_t * bytes, size_t * length, size_t byte_index, const picoquic_connection_id_t * odcid);

/* Exportable definition of ciphersuites */
void* picoquic_get_cipher_suite_by_id_v(int cipher_suite_id, int use_low_memory);

/* Exportable version of ciphersuite definition for AES128GCM SHA256 ciphersuite */
void* picoquic_get_aes128gcm_sha256_v(int use_low_memory);

void* picoquic_get_aes128gcm_v(int use_low_memory);

/* AES ECB function used for CID encryption */
void* picoquic_aes128_ecb_create(int is_enc, const void* ecb_key);

void picoquic_aes128_ecb_free(void* v_aesecb);

void picoquic_aes128_ecb_encrypt(void* v_aesecb, uint8_t* output, const uint8_t* input, size_t len);

void picoquic_tls_api_init();
void picoquic_tls_api_unload();
void picoquic_tls_api_reset(uint64_t init_flags);

#ifdef __cplusplus
}
#endif
#endif /* TLS_API_H */
