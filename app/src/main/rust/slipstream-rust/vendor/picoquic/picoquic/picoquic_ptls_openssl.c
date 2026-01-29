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

/* This module interfaces with the openssl libraries. It loads the
 * required variables and function pointers so they can be used by picoquic.
 */

#include "picotls.h"
#include "picoquic.h"
#include "picoquic_crypto_provider_api.h"

#ifdef PTLS_WITHOUT_OPENSSL
void picoquic_openssl_load(int unload)
{
    /* Nothing to do, as the module is not loaded. */
}
#else
#include "picotls/openssl.h"
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/engine.h>
#include <openssl/conf.h>
#include <openssl/ssl.h>
#if !defined(LIBRESSL_VERSION_NUMBER) && OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/provider.h>
#endif
/*
* Make sure that openssl is properly initialized.
*
* The OpenSSL resources are allocated on first use, and not released until the end of the
* process. The only problem is when use memory leak tracers such as valgrind. The OpenSSL
* allocations will create a large number of issues, which may hide the actual leaks that
* should be fixed. To alleviate that, the application may use an explicit call to
* a global destructor like OPENSSL_cleanup(), but normally the OpenSSL stack does it
* during the process exit.
*/
static int openssl_is_init = 0;
#if !defined(LIBRESSL_VERSION_NUMBER) && OPENSSL_VERSION_NUMBER >= 0x30000000L
static OSSL_PROVIDER* openssl_default_provider = NULL;
#endif

static void picoquic_init_openssl()
{
    if (openssl_is_init == 0) {
        openssl_is_init = 1;
        OpenSSL_add_all_algorithms();
#if !defined(LIBRESSL_VERSION_NUMBER) && OPENSSL_VERSION_NUMBER >= 0x30000000L
        openssl_default_provider = OSSL_PROVIDER_load(NULL, "default");
#else
        ERR_load_crypto_strings();
#if !defined(OPENSSL_NO_ENGINE)
        /* Load all compiled-in ENGINEs */
        ENGINE_load_builtin_engines();
        ENGINE_register_all_ciphers();
        ENGINE_register_all_digests();
#endif
#endif
    }
}

static void picoquic_clear_openssl()
{
    if (openssl_is_init) {
#if !defined(LIBRESSL_VERSION_NUMBER) && OPENSSL_VERSION_NUMBER >= 0x30000000L
        if (openssl_default_provider != NULL) {
            (void)OSSL_PROVIDER_unload(openssl_default_provider);
            openssl_default_provider = NULL;
        }
#else
#if !defined(OPENSSL_NO_ENGINE)
        /* Free allocations from engines ENGINEs */
        ENGINE_cleanup();
#endif
        ERR_free_strings();
#endif
        EVP_cleanup();
        openssl_is_init = 0;
    }
}

/* Provide a certificate signature function, based on the implementation in openssl.
*/
static int set_openssl_sign_certificate_from_key(EVP_PKEY* pkey, ptls_context_t* ctx)
{
    int ret = 0;
    ptls_openssl_sign_certificate_t* signer;

    signer = (ptls_openssl_sign_certificate_t*)malloc(sizeof(ptls_openssl_sign_certificate_t));

    if (signer == NULL || pkey == NULL) {
        ret = -1;
    }
    else {
        ret = ptls_openssl_init_sign_certificate(signer, pkey);
        ctx->sign_certificate = &signer->super;
    }

    if (pkey != NULL) {
        EVP_PKEY_free(pkey);
    }

    if (ret != 0 && signer != NULL) {
        free(signer);
    }

    return ret;
}

/* Set the certificate signature function and context using openSSL
*/

static int set_openssl_private_key_from_key_file(char const* keypem, ptls_context_t* ctx)
{
    int ret = 0;
    BIO* bio = BIO_new_file(keypem, "rb");
    if (bio == NULL) {
        ret = -1;
    }
    else {
        EVP_PKEY* pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
        if (pkey == NULL) {
            ret = -1;
        }
        else {
            ret = set_openssl_sign_certificate_from_key(pkey, ctx);
        }
        BIO_free(bio);
    }
    return ret;
}

/* Clear certificate objects allocated via openssl for a certificate
*/
static void picoquic_openssl_dispose_sign_certificate(ptls_sign_certificate_t* cert)
{
    ptls_openssl_dispose_sign_certificate((ptls_openssl_sign_certificate_t*)cert);
}


/* Read certificates from a file using openSSL functions
* TODO: what if we need to read multiple certificates for the chain?
*/
ptls_iovec_t* picoquic_openssl_get_certs_from_file(char const * file_name, size_t * count)
{
    BIO* bio_key = BIO_new_file(file_name, "rb");
    size_t const max_count = 16;
    ptls_iovec_t* chain = malloc(sizeof(ptls_iovec_t) * max_count);
    *count = 0;
    if (chain != NULL) {
        X509* cert = NULL;
        memset(chain, 0, sizeof(ptls_iovec_t) * max_count);
        /* Load cert and convert to DER */
        while (*count < max_count && (cert = PEM_read_bio_X509(bio_key, NULL, NULL, NULL)) != NULL) {
            int length = i2d_X509(cert, NULL);
            unsigned char* cert_der = (unsigned char*)malloc(length);
            unsigned char* tmp = cert_der;
            i2d_X509(cert, &tmp);
            X509_free(cert);
            chain[*count] = ptls_iovec_init(cert_der, length);
            *count += 1;
        }
    }
    BIO_free(bio_key);
    return chain;
}

/* Use openssl functions to create a certficate verifier */
ptls_openssl_verify_certificate_t* picoquic_openssl_get_openssl_certificate_verifier(char const * cert_root_file_name,
    unsigned int * is_cert_store_not_empty)
{
    ptls_openssl_verify_certificate_t * verifier = (ptls_openssl_verify_certificate_t*)malloc(sizeof(ptls_openssl_verify_certificate_t));
    if (verifier != NULL) {
        X509_STORE* store = X509_STORE_new();

        if (cert_root_file_name != NULL && store != NULL) {
            int file_ret = 0;
            X509_LOOKUP* lookup = X509_STORE_add_lookup(store, X509_LOOKUP_file());
            if ((file_ret = X509_LOOKUP_load_file(lookup, cert_root_file_name, X509_FILETYPE_PEM)) == 1) {
                *is_cert_store_not_empty = 1;
            }
        }
#ifdef PTLS_OPENSSL_VERIFY_CERTIFICATE_ENABLE_OVERRIDE
        ptls_openssl_init_verify_certificate(verifier, store, NULL);
#else
        ptls_openssl_init_verify_certificate(verifier, store);
#endif

        // If we created an instance of the store, release our reference after giving it to the verify_certificate callback.
        // The callback internally increased the reference counter by one.
#if OPENSSL_VERSION_NUMBER > 0x10100000L
        if (store != NULL) {
            X509_STORE_free(store);
        }
#endif
    }
    return verifier;
}

void picoquic_openssl_dispose_certificate_verifier(ptls_verify_certificate_t* verifier) {
    ptls_openssl_dispose_verify_certificate((ptls_openssl_verify_certificate_t*)verifier);
    /* The ptls_openssl call does not free the verifier context.
     * We free it here, in order to match the programming pattern of picoquic.
     */
    free(verifier);
}

ptls_verify_certificate_t* picoquic_openssl_get_certificate_verifier(char const* cert_root_file_name,
    unsigned int* is_cert_store_not_empty, picoquic_free_verify_certificate_ctx * free_certificate_verifier_fn)
{
    ptls_verify_certificate_t* verify_cert = NULL;
    ptls_openssl_verify_certificate_t* verifier = picoquic_openssl_get_openssl_certificate_verifier(cert_root_file_name,
        is_cert_store_not_empty);

    if (verifier == NULL) {
        free_certificate_verifier_fn = NULL;
    }
    else {
        verify_cert = &verifier->super;
        *free_certificate_verifier_fn = picoquic_openssl_dispose_certificate_verifier;
    }
    return verify_cert;
}

/* Set the list of root certificates used by the client.
* This implementation is specific to OpenSSL, because it is tied to the 
* implementation of the verify certificate function. */

int picoquic_openssl_set_tls_root_certificates(ptls_context_t* ctx, ptls_iovec_t* certs, size_t count)
{
    ptls_openssl_verify_certificate_t* verify_ctx = (ptls_openssl_verify_certificate_t*)ctx->verify_certificate;

    for (size_t i = 0; i < count; ++i) {
        uint8_t* cert_i_base = certs[i].base;
        X509* cert = d2i_X509(NULL, (const uint8_t**)&cert_i_base, (long)certs[i].len);

        if (cert == NULL) {
            return -1;
        }

        if (X509_STORE_add_cert(verify_ctx->cert_store, cert) == 0) {
            X509_free(cert);
            return -2;
        }

        X509_free(cert);
    }

    return 0;
}

/* Explain OPENSSL errors */
int picoquic_open_ssl_explain_crypto_error(char const** err_file, int* err_line)
{
#if !defined(LIBRESSL_VERSION_NUMBER) && OPENSSL_VERSION_NUMBER >= 0x30000000L
    const char *func = NULL;
    const char *data = NULL;
    int flags=0;
    return (int)ERR_get_error_all(err_file, err_line, &func, &data, &flags);
#else
    return ERR_get_error_line(err_file, err_line);
#endif
}

/* Clear the recorded errors in the crypto stack, e.g. before
* processing a new message.
*/
void picoquic_openssl_clear_crypto_errors()
{
    ERR_clear_error();
}

/* Register the openssl functions
 */
void picoquic_ptls_openssl_load(int unload)
{
    if (unload) {
        if (unload == 1) {
            picoquic_clear_openssl();
        }
    }
    else {
        picoquic_init_openssl();

        picoquic_register_ciphersuite(&ptls_openssl_aes128gcmsha256, 1);
        picoquic_register_ciphersuite(&ptls_openssl_aes256gcmsha384, 1);
        picoquic_register_key_exchange_algorithm(&ptls_openssl_secp256r1);
#ifdef PTLS_OPENSSL_HAVE_CHACHA20_POLY1305
        picoquic_register_ciphersuite(&ptls_openssl_chacha20poly1305sha256, 1);
        picoquic_register_key_exchange_algorithm(&ptls_openssl_x25519);
#endif
        picoquic_register_tls_key_provider_fn(
            set_openssl_private_key_from_key_file,
            picoquic_openssl_dispose_sign_certificate,
            picoquic_openssl_get_certs_from_file);
        picoquic_register_verify_certificate_fn(picoquic_openssl_get_certificate_verifier,
            picoquic_openssl_dispose_certificate_verifier,
            picoquic_openssl_set_tls_root_certificates);
        picoquic_register_explain_crypto_error_fn(picoquic_open_ssl_explain_crypto_error,
            picoquic_openssl_clear_crypto_errors);
        picoquic_register_crypto_random_provider_fn(ptls_openssl_random_bytes);
    }
}
#endif