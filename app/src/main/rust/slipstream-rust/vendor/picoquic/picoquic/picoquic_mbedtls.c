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

/* This module interfaces with the minicrypto libraries. It loads the
* required variables and function pointers so they can be used by picoquic.
*/

#include "picotls.h"
#ifndef PICOQUIC_WITH_MBEDTLS
void picoquic_mbedtls_load(int unload)
{
#ifdef _WINDOWS
    UNREFERENCED_PARAMETER(unload);
#endif
    /* Nothing to do, as the module is not loaded. */
}
#else
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <picotls.h>
#include "mbedtls/mbedtls_config.h"
#include "mbedtls/build_info.h"
#include "psa/crypto.h"
#include "psa/crypto_struct.h"
#include "psa/crypto_values.h"
#include "picotls.h"
#include "ptls_mbedtls.h"
#include "picoquic_crypto_provider_api.h"
#include "picoquic_utils.h"
#include "mbedtls/chacha20.h"
#include "mbedtls/ecdh.h"

#include "picoquic_crypto_provider_api.h"


/* Set the certificate signature function and context using MbedSSL
*/

ptls_verify_certificate_t* picoquic_mbedtls_get_certificate_verifier(char const* cert_root_file_name,
    unsigned int* is_cert_store_not_empty, picoquic_dispose_certificate_verifier_t * free_certificate_verifier_fn)
{
    ptls_verify_certificate_t* verifier = ptls_mbedtls_get_certificate_verifier(cert_root_file_name,
        is_cert_store_not_empty);

    if (verifier == NULL) {
        free_certificate_verifier_fn = NULL;
        *is_cert_store_not_empty = 0;
    }
    else {
        *free_certificate_verifier_fn = ptls_mbedtls_dispose_verify_certificate;
    }
    return verifier;
}

/* Register the mbedtls functions
*/
void picoquic_mbedtls_load(int unload)
{
    int ret = 0;
    if (unload) {
        ptls_mbedtls_free();
    }
    else if ((ret = ptls_mbedtls_init()) == 0){

        picoquic_register_ciphersuite(&ptls_mbedtls_aes128gcmsha256, 1);
        picoquic_register_ciphersuite(&ptls_mbedtls_aes256gcmsha384, 1);
        picoquic_register_ciphersuite(&ptls_mbedtls_chacha20poly1305sha256, 1);
        picoquic_register_key_exchange_algorithm(&ptls_mbedtls_secp256r1);
        picoquic_register_key_exchange_algorithm(&ptls_mbedtls_x25519);

        picoquic_register_tls_key_provider_fn(
            ptls_mbedtls_load_private_key,
            ptls_mbedtls_dispose_sign_certificate,
            picoquic_mbedtls_get_certs_from_file);

        picoquic_register_verify_certificate_fn(
            picoquic_mbedtls_get_certificate_verifier,
            ptls_mbedtls_dispose_verify_certificate,
            NULL);
        /*
        picoquic_register_explain_crypto_error_fn(picoquic_open_ssl_explain_crypto_error,
            picoquic_openssl_clear_crypto_errors);
            */

        picoquic_register_crypto_random_provider_fn(ptls_mbedtls_random_bytes);
    }
    else {
        DBG_PRINTF("Error: ptls_mbedtls_init returns %d", ret);
    }
}
#endif
