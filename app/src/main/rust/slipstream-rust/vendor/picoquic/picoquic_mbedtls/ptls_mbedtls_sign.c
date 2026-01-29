/*
* Copyright (c) 2023, Christian Huitema
*
* Permission is hereby granted, free of charge, to any person obtaining a copy
* of this software and associated documentation files (the "Software"), to
* deal in the Software without restriction, including without limitation the
* rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
* sell copies of the Software, and to permit persons to whom the Software is
* furnished to do so, subject to the following conditions:
*
* The above copyright notice and this permission notice shall be included in
* all copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
* IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
* AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
* LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
* FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
* IN THE SOFTWARE.
*/

#ifdef _WINDOWS
#include "wincompat.h"
#endif

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <picotls.h>
#include <mbedtls/mbedtls_config.h>
#include <mbedtls/build_info.h>
#include <mbedtls/pk.h>
#include <mbedtls/pem.h>
#include <mbedtls/error.h>
#include <mbedtls/x509_crt.h>
#include <psa/crypto.h>
#include <psa/crypto_struct.h>
#include <psa/crypto_values.h>
#include "ptls_mbedtls.h"

static const unsigned char ptls_mbedtls_oid_ec_key[] = {0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01};
static const unsigned char ptls_mbedtls_oid_rsa_key[] = {0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01};
#if 0
/* Commented out for now, as EDDSA is not yet supported by MbedTLS */
static const unsigned char ptls_mbedtls_oid_ed25519[] = {0x2b, 0x65, 0x70};
#endif

static const ptls_mbedtls_signature_scheme_t rsa_signature_schemes[] = {
    {PTLS_SIGNATURE_RSA_PKCS1_SHA256, PSA_ALG_SHA_256},
    {PTLS_SIGNATURE_RSA_PSS_RSAE_SHA256, PSA_ALG_SHA_256},
    {PTLS_SIGNATURE_RSA_PSS_RSAE_SHA384, PSA_ALG_SHA_384},
    {PTLS_SIGNATURE_RSA_PSS_RSAE_SHA512, PSA_ALG_SHA_512},
    {PTLS_SIGNATURE_RSA_PKCS1_SHA1, PSA_ALG_SHA_1},
    {UINT16_MAX, PSA_ALG_NONE}
};

static const ptls_mbedtls_signature_scheme_t secp256r1_signature_schemes[] = {
    {PTLS_SIGNATURE_ECDSA_SECP256R1_SHA256, PSA_ALG_SHA_256}, {UINT16_MAX, PSA_ALG_NONE}};
static const ptls_mbedtls_signature_scheme_t secp384r1_signature_schemes[] = {
    {PTLS_SIGNATURE_ECDSA_SECP384R1_SHA384, PSA_ALG_SHA_384}, {UINT16_MAX, PSA_ALG_NONE}};
static const ptls_mbedtls_signature_scheme_t secp521r1_signature_schemes[] = {
    {PTLS_SIGNATURE_ECDSA_SECP521R1_SHA512, PSA_ALG_SHA_512}, {UINT16_MAX, PSA_ALG_NONE}};
#if 0
/* Commented out for now, as EDDSA is not yet supported by MbedTLS */
static const ptls_mbedtls_signature_scheme_t ed25519_signature_schemes[] = {{PTLS_SIGNATURE_ED25519, PSA_ALG_NONE},
    {UINT16_MAX, PSA_ALG_NONE}};
#endif

#if defined(MBEDTLS_PEM_PARSE_C)

/* Mapping of MBEDTLS APIs to Picotls */

static int ptls_mbedtls_parse_der_length(const unsigned char *pem_buf, size_t pem_len, size_t *px, size_t *pl)
{
    int ret = 0;
    size_t x = *px;
    size_t l = pem_buf[x++];

    if (l > 128) {
        size_t ll = l & 0x7F;
        l = 0;
        while (ll > 0 && x + l < pem_len) {
            l *= 256;
            l += pem_buf[x++];
            ll--;
        }
    }

    *pl = l;
    *px = x;

    return ret;
}

static int ptls_mbedtls_parse_ecdsa_field(const unsigned char *pem_buf, size_t pem_len, size_t *key_index, size_t *key_length)
{
    int ret = 0;
    size_t x = 0;

    // const unsigned char head = { 0x30, l-2, 0x02, 0x01, 0x01, 0x04 }
    if (pem_len < 16 || pem_buf[x++] != 0x30 /* type = sequence */) {
        ret = -1;
    } else {
        size_t l = 0;
        ret = ptls_mbedtls_parse_der_length(pem_buf, pem_len, &x, &l);

        if (x + l != pem_len) {
            ret = -1;
        }
    }
    if (ret == 0) {
        if (pem_buf[x++] != 0x02 /* type = int */ || pem_buf[x++] != 0x01 /* length of int = 1 */ ||
            pem_buf[x++] != 0x01 /* version = 1 */ || pem_buf[x++] != 0x04 /*octet string */ || pem_buf[x] + x >= pem_len) {
            ret = -1;
        } else {
            *key_index = x + 1;
            *key_length = pem_buf[x];
            x += 1 + pem_buf[x];

            if (x < pem_len && pem_buf[x] == 0xa0) {
                /* decode the EC parameters, identify the curve */
                x++;
                if (x + pem_buf[x] >= pem_len) {
                    /* EC parameters extend beyond buffer */
                    ret = -1;
                } else {
                    x += pem_buf[x] + 1;
                }
            }

            if (ret == 0 && x < pem_len) {
                /* skip the public key parameter */
                if (pem_buf[x++] != 0xa1 || x >= pem_len) {
                    ret = -1;
                } else {
                    size_t l = 0;
                    ret = ptls_mbedtls_parse_der_length(pem_buf, pem_len, &x, &l);
                    x += l;
                }
            }

            if (x != pem_len) {
                ret = -1;
            }
        }
    }
    return ret;
}

#if 0
/* Code commented out for now, as EDDSA is not supported yet in MbedTLS */

/* On input, key_index points at the "key information" in a
* "private key" message. For EDDSA, this contains an
* octet string carrying the key itself. On return, key index
* and key length are updated to point at the key field.
*/
static int ptls_mbedtls_parse_eddsa_key(const unsigned char *pem_buf, size_t pem_len, size_t *key_index, size_t *key_length)
{
    int ret = 0;
    size_t x = *key_index;
    size_t l_key = 0;

    if (*key_length < 2 || pem_buf[x++] != 0x04) {
        ret = -1;
    } else {
        ret = ptls_mbedtls_parse_der_length(pem_buf, pem_len, &x, &l_key);
        if (x + l_key != *key_index + *key_length) {
            ret = -1;
        } else {

            *key_index = x;
            *key_length = l_key;
        }
    }
    return ret;
}
#endif

/* If using PKCS8 encoding, the "private key" field contains the
* same "ecdsa field" found in PEM "EC PRIVATE KEY" files. We
* use the same parser, but we need to reset indices so they
* reflect the unwrapped key.
*/
int ptls_mbedtls_parse_ec_private_key(const unsigned char *pem_buf, size_t pem_len, size_t *key_index, size_t *key_length)
{
    size_t x_offset = 0;
    size_t x_len = 0;
    int ret = ptls_mbedtls_parse_ecdsa_field(pem_buf + *key_index, *key_length, &x_offset, &x_len);

    if (ret == 0) {
        *key_index += x_offset;
        *key_length = x_len;
    }
    return ret;
}

/* Parsing the private key field in a PEM key object.
* The syntax is similar to the "public key info", but there
* are differences, such as encoding the key as an octet
* string instead of a bit field.
* TODO: look at unifying the common parts for making the
* code a bit smaller.
*/
int ptls_parse_private_key_field(const unsigned char *pem_buf, size_t pem_len, size_t *oid_index, size_t *oid_length,
    size_t *key_index, size_t *key_length)
{
    int ret = 0;
    size_t l_oid = 0;
    size_t x_oid = 0;
    size_t l_key = 0;
    size_t x_key = 0;

    size_t x = 0;
    /*  const unsigned char head = {0x30, l - 2, 0x02, 0x01, 0x00} */
    if (pem_len < 16 || pem_buf[x++] != 0x30 /* type = sequence */) {
        ret = -1;
    } else {
        size_t l = 0;
        ret = ptls_mbedtls_parse_der_length(pem_buf, pem_len, &x, &l);

        if (x + l != pem_len) {
            ret = -1;
        }
    }
    if (ret == 0) {
        if (pem_buf[x++] != 0x02 /* type = int */ || pem_buf[x++] != 0x01 /* length of int = 1 */ ||
            pem_buf[x++] != 0x00 /* version = 0 */ || pem_buf[x++] != 0x30 /* sequence */) {
            ret = -1;
        } else {
            /* the sequence contains the OID and optional key attributes,
            * which we ignore for now.
            */
            size_t l_seq = 0;
            size_t x_seq;
            ret = ptls_mbedtls_parse_der_length(pem_buf, pem_len, &x, &l_seq);
            x_seq = x;
            if (x + l_seq >= pem_len || pem_buf[x++] != 0x06) {
                ret = -1;
            } else {
                l_oid = pem_buf[x++];
                x_oid = x;
                if (x + l_oid > x_seq + l_seq) {
                    ret = -1;
                } else {
                    x = x_seq + l_seq;
                }
            }
        }
    }
    if (ret == 0) {
        /* At that point the oid has been identified.
        * The next parameter is an octet string containing the key info.
        */
        if (x + 2 > pem_len || pem_buf[x++] != 0x04) {
            ret = -1;
        } else {
            ret = ptls_mbedtls_parse_der_length(pem_buf, pem_len, &x, &l_key);
            x_key = x;
            x += l_key;
            if (x > pem_len) {
                ret = -1;
            }
        }
    }
    *oid_index = x_oid;
    *oid_length = l_oid;
    *key_index = x_key;
    *key_length = l_key;

    return ret;
}

int ptls_mbedtls_get_der_key(mbedtls_pem_context *pem, mbedtls_pk_type_t *pk_type, const unsigned char *key, size_t keylen,
    const unsigned char *pwd, size_t pwdlen, int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
#if defined(MBEDTLS_PEM_PARSE_C)
    size_t len;
#endif

    if (keylen == 0) {
        return MBEDTLS_ERR_PK_KEY_INVALID_FORMAT;
    }

    mbedtls_pem_init(pem);

#if defined(MBEDTLS_RSA_C)
    /* Avoid calling mbedtls_pem_read_buffer() on non-null-terminated string */
    if (key[keylen] != '\0') {
        ret = MBEDTLS_ERR_PEM_NO_HEADER_FOOTER_PRESENT;
    } else {
        ret = mbedtls_pem_read_buffer(pem, "-----BEGIN RSA PRIVATE KEY-----", "-----END RSA PRIVATE KEY-----", key, pwd, pwdlen,
            &len);
    }

    if (ret == 0) {
        *pk_type = MBEDTLS_PK_RSA;
        return ret;
    } else if (ret == MBEDTLS_ERR_PEM_PASSWORD_MISMATCH) {
        return MBEDTLS_ERR_PK_PASSWORD_MISMATCH;
    } else if (ret == MBEDTLS_ERR_PEM_PASSWORD_REQUIRED) {
        return MBEDTLS_ERR_PK_PASSWORD_REQUIRED;
    } else if (ret != MBEDTLS_ERR_PEM_NO_HEADER_FOOTER_PRESENT) {
        return ret;
    }
#endif /* MBEDTLS_RSA_C */

#if defined(MBEDTLS_PK_HAVE_ECC_KEYS)
    /* Avoid calling mbedtls_pem_read_buffer() on non-null-terminated string */
    if (key[keylen] != '\0') {
        ret = MBEDTLS_ERR_PEM_NO_HEADER_FOOTER_PRESENT;
    } else {
        ret =
            mbedtls_pem_read_buffer(pem, "-----BEGIN EC PRIVATE KEY-----", "-----END EC PRIVATE KEY-----", key, pwd, pwdlen, &len);
    }
    if (ret == 0) {
        *pk_type = MBEDTLS_PK_ECKEY;
        return ret;
    } else if (ret == MBEDTLS_ERR_PEM_PASSWORD_MISMATCH) {
        return MBEDTLS_ERR_PK_PASSWORD_MISMATCH;
    } else if (ret == MBEDTLS_ERR_PEM_PASSWORD_REQUIRED) {
        return MBEDTLS_ERR_PK_PASSWORD_REQUIRED;
    } else if (ret != MBEDTLS_ERR_PEM_NO_HEADER_FOOTER_PRESENT) {
        return ret;
    }
#endif /* MBEDTLS_PK_HAVE_ECC_KEYS */

    /* Avoid calling mbedtls_pem_read_buffer() on non-null-terminated string */
    if (key[keylen] != '\0') {
        ret = MBEDTLS_ERR_PEM_NO_HEADER_FOOTER_PRESENT;
    } else {
        ret = mbedtls_pem_read_buffer(pem, "-----BEGIN PRIVATE KEY-----", "-----END PRIVATE KEY-----", key, NULL, 0, &len);
        if (ret == 0) {
            /* info is unknown */
            return ret;
        } else if (ret != MBEDTLS_ERR_PEM_NO_HEADER_FOOTER_PRESENT) {
            return ret;
        }
    }

#if defined(MBEDTLS_PKCS12_C) || defined(MBEDTLS_PKCS5_C)
    /* Avoid calling mbedtls_pem_read_buffer() on non-null-terminated string */
    if (key[keylen] != '\0') {
        ret = MBEDTLS_ERR_PEM_NO_HEADER_FOOTER_PRESENT;
    } else {
        ret = mbedtls_pem_read_buffer(pem, "-----BEGIN ENCRYPTED PRIVATE KEY-----", "-----END ENCRYPTED PRIVATE KEY-----", key,
            NULL, 0, &len);
    }
    if (ret == 0) {
        /* infor is unknown */
        return ret;
    } else if (ret != MBEDTLS_ERR_PEM_NO_HEADER_FOOTER_PRESENT) {
        return ret;
    }
#endif /* MBEDTLS_PKCS12_C || MBEDTLS_PKCS5_C */
    return MBEDTLS_ERR_PK_KEY_INVALID_FORMAT;
}
#endif

/* When finding public keys in a certificate, we expect the syntax to be:
* SubjectPublicKeyInfo  ::=  SEQUENCE  {
*       algorithm         AlgorithmIdentifier,
*       subjectPublicKey  BIT STRING
* }
* AlgorithmIdentifier  ::=  SEQUENCE  {
*        algorithm   OBJECT IDENTIFIER,
*        parameters  ANY DEFINED BY algorithm OPTIONAL
* }
*/
static int ptls_mbedtls_parse_public_key_info(const unsigned char *pem_buf, size_t pem_len,
    size_t *oid_index, size_t *oid_length,
    size_t *param_index, size_t *param_length,
    size_t *key_index, size_t *key_length)
{
    int ret = 0;
    size_t x = 0;

    if (ret == 0) {
        if (pem_buf[x++] != 0x30 /* sequence */) {
            ret = PTLS_ERROR_INCORRECT_ASN1_SYNTAX;
        }
        else {
            size_t l_seq1 = 0;

            ret = ptls_mbedtls_parse_der_length(pem_buf, pem_len, &x, &l_seq1);
            if (x + l_seq1 > pem_len || pem_buf[x++] != 0x30) {
                ret = PTLS_ERROR_INCORRECT_ASN1_SYNTAX;
            }
            else {
                size_t l_seq = 0;
                size_t x_seq;
                ret = ptls_mbedtls_parse_der_length(pem_buf, pem_len, &x, &l_seq);
                x_seq = x;
                if (x + l_seq > pem_len || pem_buf[x++] != 0x06) {
                    ret = PTLS_ERROR_INCORRECT_ASN1_SYNTAX;
                }
                else {
                    /* Sequence contains the OID and optional key attributes */
                    *oid_length = pem_buf[x++];
                    *oid_index = x;
                    *param_index = x + *oid_length;
                    x = x_seq + l_seq;
                    if (*param_index > x) {
                        ret = PTLS_ERROR_INCORRECT_ASN1_SYNTAX;
                    }
                    else {
                        *param_length = x - *param_index;
                    }
                }
            }

            if (ret == 0) {
                /* At that point the oid has been identified.
                * The next parameter is an octet string containing the key info.
                */
                if (x + 2 > pem_len || pem_buf[x++] != 0x03) {
                    ret = PTLS_ERROR_INCORRECT_ASN1_SYNTAX;
                }
                else {
                    ret = ptls_mbedtls_parse_der_length(pem_buf, pem_len, &x, key_length);
                    *key_index = x;
                    x += *key_length;
                    if (x > pem_len) {
                        ret = PTLS_ERROR_INCORRECT_ASN1_SYNTAX;
                    }
                }
            }
        }
    }

    return ret;
}

/* Obtain the public key bits and the public key attributes from the
* subject public key info in a certificate.
 */
int ptls_mbedtls_get_public_key_info(const unsigned char* pk_raw, size_t pk_raw_len,
    psa_key_attributes_t* attributes,
    size_t* key_index, size_t* key_length)
{
    size_t oid_index, oid_length, param_index, param_length;
    int ret = ptls_mbedtls_parse_public_key_info(pk_raw, pk_raw_len,
        &oid_index, &oid_length, &param_index, &param_length, key_index, key_length);

    if (ret == 0) {
        /* find the key type from the OID. Use key type to derive
        * further attributes from parameter, or update the value
        * of the key index to skip unused version field, etc.
        */
        if (oid_length == sizeof(ptls_mbedtls_oid_rsa_key) &&
            memcmp(pk_raw + oid_index, ptls_mbedtls_oid_rsa_key, sizeof(ptls_mbedtls_oid_rsa_key)) == 0) {
            /* We recognized RSA */
            psa_set_key_type(attributes, PSA_KEY_TYPE_RSA_PUBLIC_KEY);
            if (*key_length > 0 && pk_raw[*key_index] == 0) {
                (*key_index)++;
                (*key_length)--;
            }
        }
        else if (oid_length == sizeof(ptls_mbedtls_oid_ec_key) &&
            memcmp(pk_raw + oid_index, ptls_mbedtls_oid_ec_key, sizeof(ptls_mbedtls_oid_ec_key)) == 0) {
            /* We recognized ECDSA */
            psa_set_key_type(attributes, PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1));
            if (*key_length > 0 && pk_raw[*key_index] == 0) {
                (*key_index)++;
                (*key_length)--;
            }
        } else {
            ret = PTLS_ERROR_NOT_AVAILABLE;
        }
    }
    return ret;
}


const ptls_mbedtls_signature_scheme_t *ptls_mbedtls_select_signature_scheme(const ptls_mbedtls_signature_scheme_t *available,
    const uint16_t *algorithms, size_t num_algorithms, uint16_t * selected_algorithm)
{
    const ptls_mbedtls_signature_scheme_t *scheme;

    /* select the algorithm, driven by server-isde preference of `available` */
    for (scheme = available; scheme->scheme_id != UINT16_MAX; ++scheme) {
        for (size_t i = 0; i != num_algorithms; ++i) {
            if (algorithms[i] == scheme->scheme_id) {
                *selected_algorithm = scheme->scheme_id;
                return scheme;
            }
        }
    }
    return NULL;
}

/* Find whether the signature scheme is supported */
int ptls_mbedtls_set_schemes_from_key_params(psa_algorithm_t key_algo, size_t key_nb_bits, const ptls_mbedtls_signature_scheme_t** schemes)
{
    int ret = 0;

    switch (key_algo) {
    case PSA_ALG_RSA_PKCS1V15_SIGN_RAW:
        *schemes = rsa_signature_schemes;
        break;
    case PSA_ALG_DETERMINISTIC_ECDSA(PSA_ALG_SHA_256):
        *schemes = secp256r1_signature_schemes;
        break;
    case PSA_ALG_DETERMINISTIC_ECDSA(PSA_ALG_SHA_384):
        *schemes = secp384r1_signature_schemes;
        break;
    case PSA_ALG_DETERMINISTIC_ECDSA(PSA_ALG_SHA_512):
        *schemes = secp521r1_signature_schemes;
        break;
    case PSA_ALG_ECDSA_BASE:
        switch (key_nb_bits) {
        case 521:
            *schemes = secp521r1_signature_schemes;
            break;
        case 384:
            *schemes = secp384r1_signature_schemes;
            break;
        case 256:
            *schemes = secp256r1_signature_schemes;
            break;
        default:
            *schemes = secp256r1_signature_schemes;
            ret = -1;
            break;
        }
        break;
#if 0
    case PSA_ALG_ED25519PH:
        *schemes = ed25519_signature_schemes;
        break;
#endif
    default:
        /* printf("Unknown algo: %x\n", key_algo); */
        ret = -1;
    }

    return ret;
}

int ptls_mbedtls_set_available_schemes(ptls_mbedtls_sign_certificate_t *signer)
{
    int ret = 0;
    psa_algorithm_t algo = psa_get_key_algorithm(&signer->attributes);
    size_t nb_bits = psa_get_key_bits(&signer->attributes);

    ret = ptls_mbedtls_set_schemes_from_key_params(algo, nb_bits, &signer->schemes);

    return ret;
}


/*
* Sign a certificate
* - step1, selected a signature algorithm compatible with the public key algorithm
*   and with the list specified by the application.
* - step2, compute the hash with the specified algorithm.
* - step3, compute the signature of the hash using psa_sign_hash.
*
* In the case of RSA, we use the algorithm PSA_ALG_RSA_PKCS1V15_SIGN_RAW, which
* pads the hash according to PKCS1V15 before doing the private key operation.
* The implementation of RSA/PKCS1V15 also includes a verification step to protect
* against key attacks through partial faults.
*
* MBEDTLS has a "psa_sign_message" that combines step2 and step3. However, it
* requires specifying an algorithm type that exactly specifies the signature
* algorithm, such as "RSA with SHA384". This is not compatible with the
* "RSA sign raw" algorithm. Instead, we decompose the operation in two steps.
* There is no performance penalty doing so, as "psa_sign_message" is only
* a convenience API.
*/

int ptls_mbedtls_sign_certificate(ptls_sign_certificate_t *_self, ptls_t *tls, ptls_async_job_t **async,
    uint16_t *selected_algorithm, ptls_buffer_t *outbuf, ptls_iovec_t input,
    const uint16_t *algorithms, size_t num_algorithms)
{
    int ret = 0;
    ptls_mbedtls_sign_certificate_t *self =
        (ptls_mbedtls_sign_certificate_t *)(((unsigned char *)_self) - offsetof(struct st_ptls_mbedtls_sign_certificate_t, super));
    /* First, find the set of compatible algorithms */
    const ptls_mbedtls_signature_scheme_t *scheme = ptls_mbedtls_select_signature_scheme(self->schemes, algorithms, num_algorithms, selected_algorithm);

    if (scheme == NULL) {
        ret = PTLS_ERROR_INCOMPATIBLE_KEY;
    } else {
        /* First prepare the hash */
        unsigned char hash_buffer[PTLS_MAX_DIGEST_SIZE];
        unsigned char *hash_value = NULL;

        size_t hash_length = 0;

        if (scheme->hash_algo == PSA_ALG_NONE) {
            hash_value = input.base;
            hash_length = input.len;
        } else {
            if (psa_hash_compute(scheme->hash_algo, input.base, input.len, hash_buffer, PTLS_MAX_DIGEST_SIZE, &hash_length) !=
                PSA_SUCCESS) {
                ret = PTLS_ERROR_NOT_AVAILABLE;
            } else {
                hash_value = hash_buffer;
            }
        }
        if (ret == 0) {
            psa_algorithm_t sign_algo = psa_get_key_algorithm(&self->attributes);
            size_t nb_bits = psa_get_key_bits(&self->attributes);
            size_t nb_bytes = (nb_bits + 7) / 8;
            if (nb_bits == 0) {
                if (sign_algo == PSA_ALG_RSA_PKCS1V15_SIGN_RAW) {
                    /* assume at most 4096 bit key */
                    nb_bytes = 512;
                } else {
                    /* Max size assumed, secp521r1 */
                    nb_bytes = 124;
                }
            } else if (sign_algo != PSA_ALG_RSA_PKCS1V15_SIGN_RAW) {
                nb_bytes *= 2;
            }
            if ((ret = ptls_buffer_reserve(outbuf, nb_bytes)) == 0) {
                size_t signature_length = 0;
                if (psa_sign_hash(self->key_id, sign_algo, hash_value, hash_length, outbuf->base + outbuf->off, nb_bytes,
                    &signature_length) != 0) {
                    ret = PTLS_ERROR_INCOMPATIBLE_KEY;
                } else {
                    outbuf->off += signature_length;
                }
            }
        }
    }
    return ret;
}

void ptls_mbedtls_dispose_sign_certificate(ptls_sign_certificate_t *_self)
{
    if (_self != NULL) {
        ptls_mbedtls_sign_certificate_t *self =
            (ptls_mbedtls_sign_certificate_t *)(((unsigned char *)_self) -
                offsetof(struct st_ptls_mbedtls_sign_certificate_t, super));
        /* Destroy the key */
        psa_destroy_key(self->key_id);
        psa_reset_key_attributes(&self->attributes);
        memset(self, 0, sizeof(ptls_mbedtls_sign_certificate_t));
    }
}
/*
* An RSa key is encoded in DER as:
* RSAPrivateKey ::= SEQUENCE {
*   version             INTEGER,  -- must be 0
*   modulus             INTEGER,  -- n
*   publicExponent      INTEGER,  -- e
*   privateExponent     INTEGER,  -- d
*   prime1              INTEGER,  -- p
*   prime2              INTEGER,  -- q
*   exponent1           INTEGER,  -- d mod (p-1)
*   exponent2           INTEGER,  -- d mod (q-1)
*   coefficient         INTEGER,  -- (inverse of q) mod p
* }
*
* The number of key bits is the size in bits of the integer N.
* We must decode the length in octets of the integer representation,
* then subtract the number of zeros at the beginning of the data.
*/
int ptls_mbedtls_rsa_get_key_bits(const unsigned char *key_value, size_t key_length, size_t *p_nb_bits)
{
    int ret = 0;
    size_t nb_bytes = 0;
    size_t nb_bits = 0;
    size_t x = 0;

    if (key_length > 16 && key_value[x++] == 0x30) {
        /* get the length of the sequence. */
        size_t l = 0;
        ret = ptls_mbedtls_parse_der_length(key_value, key_length, &x, &l);

        if (x + l != key_length) {
            ret = -1;
        }
    }

    if (ret == 0 && key_value[x] == 0x02 && key_value[x + 1] == 0x01 && key_value[x + 2] == 0x00 && key_value[x + 3] == 0x02) {
        x += 4;
        ret = ptls_mbedtls_parse_der_length(key_value, key_length, &x, &nb_bytes);
    } else {
        ret = -1;
    }

    if (ret == 0) {
        unsigned char v = key_value[x];
        nb_bits = 8 * nb_bytes;

        if (v == 0) {
            nb_bits -= 8;
        } else {
            while ((v & 0x80) == 0) {
                nb_bits--;
                v <<= 1;
            }
        }
    }
    *p_nb_bits = nb_bits;
    return ret;
}

void ptls_mbedtls_set_rsa_key_attributes(ptls_mbedtls_sign_certificate_t *signer, const unsigned char *key_value, size_t key_length)
{
    size_t nb_bits = 0;
    psa_set_key_usage_flags(&signer->attributes, PSA_KEY_USAGE_SIGN_HASH);
    psa_set_key_algorithm(&signer->attributes, PSA_ALG_RSA_PKCS1V15_SIGN_RAW);
    psa_set_key_type(&signer->attributes, PSA_KEY_TYPE_RSA_KEY_PAIR);
    if (ptls_mbedtls_rsa_get_key_bits(key_value, key_length, &nb_bits) == 0) {
        psa_set_key_bits(&signer->attributes, nb_bits);
    }
}

int ptls_mbedtls_set_ec_key_attributes(ptls_mbedtls_sign_certificate_t *signer, size_t key_length)
{
    int ret = 0;

    psa_set_key_usage_flags(&signer->attributes, PSA_KEY_USAGE_SIGN_HASH);
    psa_set_key_algorithm(&signer->attributes, PSA_ALG_ECDSA_BASE);
    psa_set_key_type(&signer->attributes, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    if (key_length == 32) {
        psa_set_key_algorithm(&signer->attributes, PSA_ALG_DETERMINISTIC_ECDSA(PSA_ALG_SHA_256));
        psa_set_key_bits(&signer->attributes, 256);
    } else if (key_length == 48) {
        psa_set_key_algorithm(&signer->attributes, PSA_ALG_DETERMINISTIC_ECDSA(PSA_ALG_SHA_384));
        psa_set_key_bits(&signer->attributes, 384);
    } else if (key_length == 66) {
        psa_set_key_algorithm(&signer->attributes, PSA_ALG_DETERMINISTIC_ECDSA(PSA_ALG_SHA_512));
        psa_set_key_bits(&signer->attributes, 521);
    } else {
        ret = -1;
    }

    return ret;
}

int ptls_mbedtls_load_file(char const * file_name, unsigned char ** buf, size_t * n)
{
    int ret = 0;
    FILE* F = NULL;
    *buf = NULL;
    *n = 0;
#ifdef _WINDOWS
    errno_t err = fopen_s(&F, file_name, "rb");
    if (err != 0){
        if (F != NULL) {
            fclose(F);
            F = NULL;
        }
    }
#else
    F = fopen(file_name, "rb");
#endif

    if (F == NULL) {
        ret = PTLS_ERROR_NOT_AVAILABLE;
    } else {
        long sz;
        fseek(F, 0, SEEK_END);
        sz = ftell(F);

        if (sz > 0) {
            *buf = (unsigned char *)malloc(sz+1);
            if (*buf == NULL){
                ret = PTLS_ERROR_NO_MEMORY;
            }
            else {
                size_t nb_read = 0;
                fseek(F, 0, SEEK_SET);
                while(nb_read < (size_t)sz){
                    *n = sz;
                    size_t ret = fread((*buf) + nb_read, 1, sz - nb_read, F);
                    if (ret > 0){
                        nb_read += ret;
                        (*buf)[nb_read] = 0;
                    } else {
                        /* No need to check for EOF, since we know the length of the file */
                        ret = PTLS_ERROR_NOT_AVAILABLE;
                        free(*buf);
                        *buf = NULL;
                        *n = 0;
                        break;
                    }
                }
            }
            (void)fclose(F);
        }
    }
    return ret;
}

int ptls_mbedtls_load_private_key(char const *pem_fname, ptls_context_t *ctx)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t n;
    unsigned char *buf;
    mbedtls_pem_context pem = {0};
    mbedtls_pk_type_t pk_type = 0;
    /* mbedtls_svc_key_id_t key_id = 0; */
    size_t key_length = 0;
    size_t key_index = 0;
    ptls_mbedtls_sign_certificate_t *signer = (ptls_mbedtls_sign_certificate_t *)malloc(sizeof(ptls_mbedtls_sign_certificate_t));

    if (signer == NULL) {
        return (PTLS_ERROR_NO_MEMORY);
    }
    memset(signer, 0, sizeof(ptls_mbedtls_sign_certificate_t));
    signer->attributes = psa_key_attributes_init();

    if ((ret = ptls_mbedtls_load_file(pem_fname, &buf, &n)) != 0) {
        return ret;
    }
    ret = ptls_mbedtls_get_der_key(&pem, &pk_type, buf, n, NULL, 0, NULL, NULL);

    /* We cannot use the platform API:
    mbedtls_zeroize_and_free(buf, n);
    so we do our own thing.
    */
    memset(buf, 0, n);
    free(buf);

    if (ret == 0) {
        if (pk_type == MBEDTLS_PK_RSA) {
            key_length = pem.private_buflen;
            ptls_mbedtls_set_rsa_key_attributes(signer, pem.private_buf, key_length);
        } else if (pk_type == MBEDTLS_PK_ECKEY) {
            ret = ptls_mbedtls_parse_ecdsa_field(pem.private_buf, pem.private_buflen, &key_index, &key_length);
            if (ret == 0) {
                ret = ptls_mbedtls_set_ec_key_attributes(signer, key_length);
            }
        } else if (pk_type == MBEDTLS_PK_NONE) {
            size_t oid_index = 0;
            size_t oid_length = 0;

            psa_set_key_usage_flags(&signer->attributes, PSA_KEY_USAGE_SIGN_HASH);
            ret =
                ptls_parse_private_key_field(pem.private_buf, pem.private_buflen, &oid_index, &oid_length, &key_index, &key_length);
            if (ret == 0) {
                /* need to parse the OID in order to set the parameters */

                if (oid_length == sizeof(ptls_mbedtls_oid_ec_key) &&
                    memcmp(pem.private_buf + oid_index, ptls_mbedtls_oid_ec_key, sizeof(ptls_mbedtls_oid_ec_key)) == 0) {
                    ret = ptls_mbedtls_parse_ec_private_key(pem.private_buf, pem.private_buflen, &key_index, &key_length);
                    if (ret == 0) {
                        ret = ptls_mbedtls_set_ec_key_attributes(signer, key_length);
                    }
#if 0
                /* Commenting out as MbedTLS does not support 25519 yet */
                } else if (oid_length == sizeof(ptls_mbedtls_oid_ed25519) &&
                    memcmp(pem.private_buf + oid_index, ptls_mbedtls_oid_ed25519, sizeof(ptls_mbedtls_oid_ed25519)) == 0) {
                    /* This code looks correct, but EDDSA is not supported yet by MbedTLS,
                    * and attempts to import the key will result in an error, so commenting out for now. */
                    /* We recognized ED25519 -- PSA_ECC_FAMILY_TWISTED_EDWARDS -- PSA_ALG_ED25519PH */
                    psa_set_key_algorithm(&signer->attributes, PSA_ALG_ED25519PH);
                    psa_set_key_type(&signer->attributes, PSA_ECC_FAMILY_TWISTED_EDWARDS);
                    ret = ptls_mbedtls_parse_eddsa_key(pem.private_buf, pem.private_buflen, &key_index, &key_length);
                    psa_set_key_bits(&signer->attributes, 256);
#endif
                } else if (oid_length == sizeof(ptls_mbedtls_oid_rsa_key) &&
                    memcmp(pem.private_buf + oid_index, ptls_mbedtls_oid_rsa_key, sizeof(ptls_mbedtls_oid_rsa_key)) == 0) {
                    /* We recognized RSA */
                    ptls_mbedtls_set_rsa_key_attributes(signer, pem.private_buf + key_index, key_length);
                } else {
                    ret = PTLS_ERROR_NOT_AVAILABLE;
                }
            }
        } else {
            ret = -1;
        }

        if (ret == 0) {
            /* Now that we have the DER or bytes for the key, try import into PSA */
            psa_status_t status = psa_import_key(&signer->attributes, pem.private_buf + key_index, key_length, &signer->key_id);

            if (status != PSA_SUCCESS) {
                ret = -1;
            } else {
                ret = ptls_mbedtls_set_available_schemes(signer);
            }
        }
        /* Free the PEM buffer */
        mbedtls_pem_free(&pem);
    }
    if (ret == 0) {
        signer->super.cb = ptls_mbedtls_sign_certificate;
        ctx->sign_certificate = &signer->super;
    } else {
        /* Dispose of what we have allocated. */
        ptls_mbedtls_dispose_sign_certificate(&signer->super);
    }
    return ret;
}

/* Handling of certificates.
* Certificates in picotls are used both at the client and the server side.
* 
* The server is programmed with a copy of the certificate chain linking
* the local key and identity to a certificate authority. Picotls formats
* that key and sends it as part of the "server hello". It is signed with
* the server key.
* 
* The client is programmed with a list of trusted certificates. It should
* process the list received from the server and verifies that it does
* correctly link the server certificate to one of the certificates in the
* root list.
* 
* Mbedtls documents a series of certificate related API in `x509_crt.h`.
* 
* On the server side, we read the certificates from a PEM encoded
* file, and provide it to the server.
* 
* For verify certificate, picotls uses a two phase API:
* 
* - During initialization, prepare a "verify certificate callback"
* - During the handshake, picotls executes the callback.
* 
* Picotls verifies certificates using the "verify_certificate" callback.
* 
* if ((ret = tls->ctx->verify_certificate->cb(tls->ctx->verify_certificate,
*       tls, server_name, &tls->certificate_verify.cb,
*       &tls->certificate_verify.verify_ctx, certs, num_certs)) != 0)
*           goto Exit;
*
* This is implemented using the function mbedtls_verify_certificate,
* documented during the initialization of the "cb" structure,
* ptls_mbedtls_verify_certificate_t. The function pointer is
* the first member of that structure, followed by other arguments.
* The callback structure is passed as the first argument in the
* callback, with type "self".
* 
* The callback should return 0 if the certificate is good. The call may
* also set the value of tls->certificate_verify.cb and 
* tls->certificate_verify.verify_ctx. If these are set, picotls will
* then use tls->certificate_verify.cb to verify that the TLS messages
* are properly signed using that certificate.
*
* The function mbedtls_verify_certificate is implemented using the
* function "mbedtls_x509_crt_verify", which has the following arguments:
* 
* - A chain of certificates, starting from the server certificate and hopefully
*   going all the way to one of the root certificates. In our code, this
*   is obtained by parsing the "certs" argument provided by picotls, which
*   is an iovec vector of length numcerts, with one entry per certificate in
*   the CERTS parameter received from the server.
* - The chain of trusted certificate authorities. In our case, that list is
*   initialized during the call to `ptls_mbedssl_init_verify_certificate`,
*   loading certificates from a `root` file.
* - A certificate revocation list. We leave that parameter NULL for now.
* - The expected server name, a NULL terminated string.
* - A "verify" function pointer, and its argument.
* 
* The call returns 0 (and flags set to 0) if the chain was verified and valid,
* MBEDTLS_ERR_X509_CERT_VERIFY_FAILED if the chain was verified but found to
* be invalid, in which case *flags will have one or more MBEDTLS_X509_BADCERT_XXX
* or MBEDTLS_X509_BADCRL_XXX flags set, or another error
* (and flags set to 0xffffffff) in case of a fatal error encountered
* during the verification process. 
* 
* The verify callback is a user-supplied callback that can clear / modify / add
* flags for a certificate. If set, the verification callback is called for each
* certificate in the chain (from the trust-ca down to the presented crt).
* The parameters for the callback are: (void *parameter, mbedtls_x509_crt *crt,
* int certificate_depth, int *flags). With the flags representing current flags
* for that specific certificate and the certificate depth from the bottom
* (Peer cert depth = 0). Function pointer and parameters can be set in the call
* to `ptls_mbedssl_init_verify_certificate`.
* 
* If the certificate verification is successfull, the code sets the pointer
* and the context for the certificate_verify callback:
* 
* struct {
*    int (*cb)(void *verify_ctx, uint16_t algo, ptls_iovec_t data, ptls_iovec_t signature);
*    void *verify_ctx;
* } certificate_verify;
* 
* The structure "certificate_verify" is allocated as part of the PTLS context. We will
* allcoate a a "ptls_mbetls_certificate_verify_ctx_t" ctx as part of the
* 
* The verify callback is implemented using `psa_verify_message`, which takes the following
* arguments:
* 
* psa_status_t psa_verify_message(psa_key_id_t key,
*                                psa_algorithm_t alg,
*                                const uint8_t * input,
*                                size_t input_length,
*                                const uint8_t * signature,
*                                size_t signature_length);
*
* The public key ID will be set from the certificate proposed by the server. The
* input and length of the data to be signed are derived from the data parameter
* in the callback, and the signature and length from the signature parameter of
* the callback. The "alg" parameter of type "psa_algorithm_t" will have to
* be derived from the algo parameter of the callback, which is a 16 bit
* "signature scheme" (see
* https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-signaturescheme).
* 
* Picotls will use that callback exactly once, then reset the callback
* pointer to NULL. It does not reset of free the "verify_ctx" -- if necessary,
* the value there should be reset after the first call.
*/

uint16_t mbedtls_verify_sign_algos[] = {
    0x0201, 0x0203, 0x0401, 0x0403, 0x501, 0x0503, 0x0601, 0x0603,
    0x0804, 0x0805, 0x0806,
    0xFFFF
};

/* Find the psa_algorithm_t values corresponding to the 16 bit TLS signature scheme */
psa_algorithm_t mbedtls_get_psa_alg_from_tls_number(uint16_t tls_algo)
{
    psa_algorithm_t alg = PSA_ALG_NONE;
    switch (tls_algo) {
    case 0x0201: /* PTLS_SIGNATURE_RSA_PKCS1_SHA1 */
        alg = PSA_ALG_RSA_PKCS1V15_SIGN(PSA_ALG_SHA_1);
        break;
    case 0x0203: /*	ecdsa_sha1 */
        alg = PSA_ALG_ECDSA(PSA_ALG_SHA_1);
        break;
    case 0x401: /* PTLS_SIGNATURE_RSA_PKCS1_SHA256 */
        alg = PSA_ALG_RSA_PKCS1V15_SIGN(PSA_ALG_SHA_256);
        break;
    case 0x0403: /*  PTLS_SIGNATURE_ECDSA_SECP256R1_SHA256 */
        alg = PSA_ALG_ECDSA(PSA_ALG_SHA_256);
        break;
#if 0
        /* For further study. These two algorithms might be available in MbedTLS */
    case 0x0420: /* rsa_pkcs1_sha256_legacy */
        break;
    case 0x0520: /* rsa_pkcs1_sha384_legacy */
        break;
#endif
    case 0x501: /* rsa_pkcs1_sha384 */
        alg = PSA_ALG_RSA_PKCS1V15_SIGN(PSA_ALG_SHA_384);
        break;
    case 0x0503: /* PTLS_SIGNATURE_ECDSA_SECP384R1_SHA384 */
        alg = PSA_ALG_ECDSA(PSA_ALG_SHA_384);
        break;
    case 0x0601: /* rsa_pkcs1_sha512  */
        alg = PSA_ALG_RSA_PKCS1V15_SIGN(PSA_ALG_SHA_512);
        break;
    case 0x0603: /* PTLS_SIGNATURE_ECDSA_SECP521R1_SHA512 */
        alg = PSA_ALG_ECDSA(PSA_ALG_SHA_512);
        break;
    case 0x0804: /* PTLS_SIGNATURE_RSA_PSS_RSAE_SHA256 */
        alg = PSA_ALG_RSA_PSS(PSA_ALG_SHA_256);
        break;
    case 0x0805: /* PTLS_SIGNATURE_RSA_PSS_RSAE_SHA384 */
        alg = PSA_ALG_RSA_PSS(PSA_ALG_SHA_384);
        break;
    case 0x0806: /* PTLS_SIGNATURE_RSA_PSS_RSAE_SHA512 */
        alg = PSA_ALG_RSA_PSS(PSA_ALG_SHA_512);
        break;
#if 0
        /* Commented out, as EDDSA is not supported yet in MbedTLS*/
    case 0x0807: /* PTLS_SIGNATURE_ED25519 */
        alg = PSA_ALG_ED25519PH;
        break;
    case 0x0808: /* PTLS_SIGNATURE_ED448 */
        alg = PSA_ALG_ED448PH;
        break;
#endif
    default:
        break;
    }

    return alg;
}

int mbedtls_verify_sign(void *verify_ctx, uint16_t algo, ptls_iovec_t data, ptls_iovec_t signature)
{
    /* Obtain the key parameters, etc. */
    int ret = 0;
    psa_algorithm_t alg = PSA_ALG_NONE;
    mbedtls_message_verify_ctx_t * message_verify_ctx = (mbedtls_message_verify_ctx_t*)verify_ctx;

    if (message_verify_ctx == NULL) {
        ret = PTLS_ERROR_LIBRARY;
    }
    else if (data.base != NULL) {
        /* Picotls will call verify_sign with data.base == NULL when it
        * only wants to clear the memory. This is not an error condition. */

        /* Find the PSA_ALG for the signature scheme */
        alg = mbedtls_get_psa_alg_from_tls_number(algo);

        if (alg == PSA_ALG_NONE) {
            ret = PTLS_ALERT_ILLEGAL_PARAMETER;
        }
    }
    else {
        psa_status_t status = psa_verify_message(message_verify_ctx->key_id, alg, data.base, data.len, signature.base, signature.len);

        if (status != PSA_SUCCESS) {
            switch (status) {
            case PSA_ERROR_NOT_PERMITTED: /* The key does not have the PSA_KEY_USAGE_SIGN_MESSAGE flag, or it does not permit the requested algorithm. */
                ret = PTLS_ERROR_INCOMPATIBLE_KEY;
                break;
            case PSA_ERROR_INVALID_SIGNATURE: /* The calculation was performed successfully, but the passed signature is not a valid signature. */
                ret = PTLS_ALERT_DECRYPT_ERROR;
                break;
            case PSA_ERROR_NOT_SUPPORTED:
                ret = PTLS_ALERT_ILLEGAL_PARAMETER;
                break;
            case PSA_ERROR_INSUFFICIENT_MEMORY:
                ret = PTLS_ERROR_NO_MEMORY;
                break;
            default:
                ret = PTLS_ERROR_LIBRARY;
                break;
            }
        }
    }
    /* destroy the key because it is used only once. */
    if (message_verify_ctx != NULL) {
        psa_destroy_key(message_verify_ctx->key_id);
        free(message_verify_ctx);
    }
    return ret;
}

static int mbedtls_verify_certificate(ptls_verify_certificate_t *_self, ptls_t *tls, const char *server_name,
    int (**verifier)(void *, uint16_t, ptls_iovec_t, ptls_iovec_t), void **verify_data, ptls_iovec_t *certs,
    size_t num_certs)
{
    size_t i;
    int ret = 0;
    mbedtls_x509_crt* chain_head = (mbedtls_x509_crt*)malloc(sizeof(mbedtls_x509_crt));

    if (chain_head == NULL) {
        ret = PTLS_ERROR_NO_MEMORY;
    }
    else {
        ptls_mbedtls_verify_certificate_t* self = (ptls_mbedtls_verify_certificate_t*)_self;
        *verifier = NULL;
        *verify_data = NULL;
        mbedtls_x509_crt_init(chain_head);

        /* If any certs are given, convert them to MbedTLS representation, then verify the cert chain. If no certs are given, just give
        * the override_callback to see if we want to stay fail open. */
        if (num_certs == 0) {
            ret = PTLS_ALERT_CERTIFICATE_REQUIRED;
        }
        else {
            mbedtls_x509_crt* previous_chain = chain_head;
            mbedtls_x509_crt_init(chain_head);

            for (i = 0; i != num_certs; ++i) {
                ret = mbedtls_x509_crt_parse_der(previous_chain, certs[i].base, certs[i].len);
                if (i != 0) {
                    if (previous_chain->next == NULL) {
                        ret = PTLS_ALERT_BAD_CERTIFICATE;
                        break;
                    }
                    previous_chain = previous_chain->next;
                }
            }

            if (ret == 0) {
                uint32_t flags = 0;

                int verify_ret = mbedtls_x509_crt_verify(chain_head, self->trust_ca, self->trust_crl, server_name, &flags,
                    self->f_vrfy, self->p_vrfy);

                if (verify_ret != 0) {
                    switch (verify_ret) {
                    case MBEDTLS_ERR_X509_CERT_VERIFY_FAILED:
                        /* if the chain was verified but found to be invalid, in which case
                        * flags will have one or more MBEDTLS_X509_BADCERT_XXX
                        * or MBEDTLS_X509_BADCRL_XXX flags set, or another
                        * error(and flags set to 0xffffffff) in case of a fatal error
                        * encountered during the verification process. */
                        ret = PTLS_ALERT_BAD_CERTIFICATE;
                        break;
                    default:
                        ret = PTLS_ERROR_LIBRARY;
                        break;
                    }
                }
            }

            if (ret == 0) {
                mbedtls_message_verify_ctx_t* message_verify_ctx = (mbedtls_message_verify_ctx_t*)
                    malloc(sizeof(mbedtls_message_verify_ctx_t));
                if (message_verify_ctx == NULL) {
                    ret = PTLS_ERROR_NO_MEMORY;
                }
                else {
                    /* Obtain the key bits from the certificate */
                    size_t key_index;
                    size_t key_length;
                    psa_key_attributes_t attributes = psa_key_attributes_init();

                    ret = ptls_mbedtls_get_public_key_info(chain_head->pk_raw.p, chain_head->pk_raw.len,
                        &attributes, &key_index, &key_length);

                    if (ret == 0) {
                        if (psa_import_key(&attributes, chain_head->pk_raw.p + key_index, key_length, &message_verify_ctx->key_id) != 0) {
                            ret = PTLS_ERROR_LIBRARY;
                        }
                    }
                    if (ret != 0) {
                        free(message_verify_ctx);
                    }
                    else {
                        *verifier = mbedtls_verify_sign;
                        *verify_data = message_verify_ctx;
                    }
                }
            }
        }
    }

    if (chain_head != NULL) {
        mbedtls_x509_crt_free(chain_head);
    }
    return ret;
}

/* Read certificates from a file using MbedTLS functions.
* We only use the PEM function to parse PEM files, find
* up to 16 certificates, and convert the base64 encoded
* data to DER encoded binary. No attempt is made to verify
* that these actually are certificates.
* 
* Discuss: picotls has a built in function for this.
* Is it really necessary to program an alternative?
*/
 ptls_iovec_t * picoquic_mbedtls_get_certs_from_file(char const * pem_fname, size_t * count)
{
    int ret = 0;
    size_t const max_count = 16;
    ptls_iovec_t *pvec = (ptls_iovec_t*)malloc(sizeof(ptls_iovec_t) * max_count);

    *count = 0;
    if (pvec != NULL) {
        size_t buf_length;
        unsigned char* buf = NULL;
        /* The load file function simply loads the file content in memory */
        if (ptls_mbedtls_load_file(pem_fname, &buf, &buf_length) == 0) {
            size_t length_already_read = 0;

            while (ret == 0 && *count < 16 && length_already_read < (size_t)buf_length) {
                mbedtls_pem_context pem = { 0 };
                size_t length_read = 0;

                /* PEM context setup. */
                mbedtls_pem_init(&pem);
                /* Read a buffer for PEM information and store the resulting data into the specified context buffers. */
                ret = mbedtls_pem_read_buffer(&pem,
                    "-----BEGIN CERTIFICATE-----",
                    "-----END CERTIFICATE-----",
                    buf + length_already_read, NULL, 0, &length_read);
                if (ret == 0) {
                    /* Certificate was read successfully. PEM buffer contains the base64 value */
                    uint8_t* cert = (uint8_t*)malloc(pem.private_buflen);
                    if (cert == NULL) {
                        ret = PTLS_ERROR_NO_MEMORY;
                    }
                    else {
                        memcpy(cert, pem.private_buf, pem.private_buflen);
                        pvec[*count].base = cert;
                        pvec[*count].len = pem.private_buflen;
                        *count += 1;
                    }
                }
                mbedtls_pem_free(&pem);
                length_already_read += length_read;
            }

            free(buf);
        }
    }
    return pvec;
}

int ptls_mbedtls_load_certificates(ptls_context_t *ctx, char const *cert_pem_file)
{
    ctx->certificates.list = picoquic_mbedtls_get_certs_from_file(cert_pem_file, 
        &ctx->certificates.count);
    return((ctx->certificates.list == NULL) ? 0 : -1);
}

/* Creating the call back. This API is not described by picotls. The "backend"
* merely has to provide a "certicate verifier" callback. We consider two ways of
* providing this callback: an API very close to the details of the MBedTLS code,
* with a list of explicit parameters, and a "portable" API whose only
* parameter is a file name for the list of trusted certificates. 
*/

ptls_mbedtls_verify_certificate_t* ptls_mbedssl_init_verify_certificate_complete(
    mbedtls_x509_crt* trust_ca, mbedtls_x509_crl* trust_crl,
    int (*f_vrfy)(void*, mbedtls_x509_crt*, int, uint32_t*), void* p_vrfy)
{
    ptls_mbedtls_verify_certificate_t* verifier =
        (ptls_mbedtls_verify_certificate_t*)malloc(sizeof(ptls_mbedtls_verify_certificate_t));
    if (verifier != NULL) {
        memset(verifier, 0, sizeof(ptls_mbedtls_verify_certificate_t));
        verifier->super.cb = mbedtls_verify_certificate;
        verifier->super.algos = mbedtls_verify_sign_algos; /* list of supported algorithms, end with 0xFFFF */
        verifier->trust_ca = trust_ca;
        verifier->trust_crl = trust_crl;
        verifier->f_vrfy = f_vrfy;
        verifier->p_vrfy = p_vrfy;
    }
    return verifier;
}

ptls_verify_certificate_t* ptls_mbedtls_get_certificate_verifier(char const* pem_fname,
    unsigned int* is_cert_store_not_empty)
{
    ptls_mbedtls_verify_certificate_t* verifier = NULL;
    *is_cert_store_not_empty = 0;
    mbedtls_x509_crt* chain_head = (mbedtls_x509_crt*)malloc(sizeof(mbedtls_x509_crt));
    if (chain_head != NULL) {
        int psa_ret;
        mbedtls_x509_crt_init(chain_head);

        psa_ret = mbedtls_x509_crt_parse_file(chain_head, pem_fname);
        if (psa_ret == 0) {
            *is_cert_store_not_empty = 1;
            verifier = ptls_mbedssl_init_verify_certificate_complete(chain_head, NULL, NULL, NULL);
        }
        else {

            mbedtls_x509_crt_free(chain_head);
        }
    }
    return (verifier==NULL)?NULL:&verifier->super;
}

void ptls_mbedtls_dispose_verify_certificate(ptls_verify_certificate_t* v)
{
    ptls_mbedtls_verify_certificate_t* verifier =
        (ptls_mbedtls_verify_certificate_t*)v;
    if (verifier != NULL) {
        if (verifier->trust_ca != NULL) {
            mbedtls_x509_crt_free(verifier->trust_ca);
            verifier->trust_ca = NULL;
        }
        if (verifier->trust_crl != NULL) {
            mbedtls_x509_crl_free(verifier->trust_crl);
        }
        memset(verifier, 0, sizeof(ptls_mbedtls_verify_certificate_t));
        free(verifier);
    }
}
