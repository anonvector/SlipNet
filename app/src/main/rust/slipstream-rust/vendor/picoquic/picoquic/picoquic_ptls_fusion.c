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

/* This module interfaces with the PTLS "fusion" libraries. It loads the
 * required variables and function pointers so they can be used by picoquic.
 */

#include "picotls.h"
#include "picoquic_crypto_provider_api.h"

#ifdef _WINDOWS_TRY_AGAIN
#ifndef PTLS_WITHOUT_FUSION
 /* temporary disabling of PTLS_FUSION until memory alignment issues are fixed*/
#define PTLS_WITHOUT_FUSION
#endif
#endif

#if (!defined(_WINDOWS) || defined(_WINDOWS64)) && !defined(PTLS_WITHOUT_FUSION)
#ifdef _WINDOWS
#pragma warning(disable:4324)
#endif
#include "picotls/fusion.h"

/* Declaration of the function `picoquic_get_hash_algorithm_by_name`, which the code
* uses to complete the declaration of the cipher suites. This is a bit of a hack: it
* only works if `picoquic_ptls_fusion_load` is called after loading other providers
* like `openssl` or `minicrypto`, that will have registered ciphersuites for
* AES_128_GCM_SHA256 and AES_256_GCM_SHA384.
*/
ptls_hash_algorithm_t* picoquic_get_hash_algorithm_by_name(const char* hash_algorithm_name);

struct st_ptls_cipher_suite_t picoquic_fusion_aes128gcmsha256 = { PTLS_CIPHER_SUITE_AES_128_GCM_SHA256, &ptls_fusion_aes128gcm,
NULL };
struct st_ptls_cipher_suite_t picoquic_fusion_aes256gcmsha384 = { PTLS_CIPHER_SUITE_AES_256_GCM_SHA384, &ptls_fusion_aes256gcm,
NULL };

void picoquic_ptls_fusion_load(int unload)
{
    if (unload) {
        /* Nothing to do */
    }
    else {
        if (ptls_fusion_is_supported_by_cpu()) {
            if ((picoquic_fusion_aes128gcmsha256.hash = picoquic_get_hash_algorithm_by_name("SHA256")) != NULL) {
                picoquic_register_ciphersuite((ptls_cipher_suite_t*)&picoquic_fusion_aes128gcmsha256, 0);
            }
            if ((picoquic_fusion_aes256gcmsha384.hash = picoquic_get_hash_algorithm_by_name("SHA384")) != NULL) {
                picoquic_register_ciphersuite(&picoquic_fusion_aes256gcmsha384, 0);
            }
        }
    }
}
#else
void picoquic_ptls_fusion_load(int unload)
{
#ifdef _WINDOWS
    UNREFERENCED_PARAMETER(unload);
#endif
    /* Nothing to do, as the module is not loaded. */
}
#endif