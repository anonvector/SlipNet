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

#ifdef _WINDOWS
#include "wincompat.h"
#endif
#include "picoquic_internal.h"
#include "tls_api.h"
#include "picoquic_utils.h"
#include "picotls.h"
#include "picoquic_lb.h"
#include <string.h>
#include "picoquictest_internal.h"

static uint8_t const addr1[4] = { 10, 0, 0, 1 };
static uint8_t const addr2[4] = { 10, 0, 0, 2 };

void cleartext_aead_packet_init_header(picoquic_packet_header* ph,
    picoquic_connection_id_t cnx_id, uint32_t pn, uint32_t vn, picoquic_packet_type_enum ptype)
{
    memset(ph, 0, sizeof(picoquic_packet_header));
    ph->dest_cnx_id = cnx_id;
    ph->srce_cnx_id = picoquic_null_connection_id;
    ph->pn = pn;
    ph->pn64 = pn;
    ph->vn = vn;
    ph->ptype = ptype;
    ph->offset = 17;
    ph->pnmask = 0xFFFFFFFF00000000ull;
    ph->version_index = picoquic_get_version_index(ph->vn);
}

void cleartext_aead_init_packet(picoquic_packet_header* ph,
    uint8_t* cleartext, size_t target)
{
    size_t byte_index = 0;
    uint64_t seed = picoquic_val64_connection_id(ph->dest_cnx_id);

    seed ^= ph->pn;

    /* Serialize the header */
    cleartext[byte_index++] = 0x80 | ((uint8_t)ph->ptype);
    picoformat_32(&cleartext[byte_index], ph->vn);
    byte_index += 4;
    byte_index += picoquic_format_connection_id(&cleartext[byte_index], 1526 - byte_index, ph->dest_cnx_id);
    byte_index += picoquic_format_connection_id(&cleartext[byte_index], 1526 - byte_index, ph->srce_cnx_id);
    ph->pn_offset = (uint32_t)byte_index;
    picoformat_32(&cleartext[byte_index], ph->pn);
    byte_index += 4;
    /* Add some silly content */
    while (byte_index < target) {
        seed *= 101;
        cleartext[byte_index++] = (uint8_t)seed & 255;
    }
}

int cleartext_aead_test()
{
    int ret = 0;
    uint8_t clear_text[1536];
    uint8_t incoming[1536];
    uint32_t seqnum = 0xdeadbeef;
    size_t clear_length = 1200;
    size_t encoded_length;
    size_t decoded_length;
    picoquic_packet_header ph_init;
    struct sockaddr_in test_addr_c, test_addr_s;
    picoquic_cnx_t* cnx_client = NULL;
    picoquic_cnx_t* cnx_server = NULL;
    picoquic_quic_t* qclient = NULL;
    picoquic_quic_t* qserver = NULL;
    char test_server_cert_file[512];
    char test_server_key_file[512];
    char test_server_cert_store_file[512];

    ret = picoquic_get_input_path(test_server_cert_file, sizeof(test_server_cert_file), picoquic_solution_dir, PICOQUIC_TEST_FILE_SERVER_CERT);

    if (ret == 0) {
        ret = picoquic_get_input_path(test_server_key_file, sizeof(test_server_key_file), picoquic_solution_dir, PICOQUIC_TEST_FILE_SERVER_KEY);
    }

    if (ret == 0) {
        ret = picoquic_get_input_path(test_server_cert_store_file, sizeof(test_server_cert_store_file), picoquic_solution_dir, PICOQUIC_TEST_FILE_CERT_STORE);
    }

    if (ret != 0) {
        DBG_PRINTF("%s", "Cannot set the cert, key or store file names.\n");
    }
    else {

        qclient = picoquic_create(8, NULL, NULL, NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, 0, NULL, NULL, NULL, 0);
        qserver = picoquic_create(8,
            test_server_cert_file, test_server_key_file, test_server_cert_store_file,
            "test", NULL, NULL, NULL, NULL, NULL, 0, NULL, NULL, NULL, 0);

        if (qclient == NULL || qserver == NULL) {
            DBG_PRINTF("%s", "Could not create Quic contexts.\n");
            ret = -1;
        }
    }

    if (ret == 0) {
        memset(&test_addr_c, 0, sizeof(struct sockaddr_in));
        test_addr_c.sin_family = AF_INET;
        memcpy(&test_addr_c.sin_addr, addr1, 4);
        test_addr_c.sin_port = 12345;

        cnx_client = picoquic_create_cnx(qclient, picoquic_null_connection_id, picoquic_null_connection_id,
            (struct sockaddr*)&test_addr_c, 0, 0, NULL, NULL, 1);
        if (cnx_client == NULL) {
            DBG_PRINTF("%s", "Could not create client connection context.\n");
            ret = -1;
        }
    }

    if (ret == 0) {

        memset(&test_addr_s, 0, sizeof(struct sockaddr_in));
        test_addr_s.sin_family = AF_INET;
        memcpy(&test_addr_s.sin_addr, addr2, 4);
        test_addr_s.sin_port = 4433;

        cnx_server = picoquic_create_cnx(qserver, cnx_client->initial_cnxid, cnx_client->initial_cnxid,
            (struct sockaddr*)&test_addr_s, 0,
            cnx_client->proposed_version, NULL, NULL, 0);

        if (cnx_server == NULL) {
            DBG_PRINTF("%s", "Could not create server connection context.\n");
            ret = -1;
        } else if (picoquic_compare_connection_id(&cnx_client->initial_cnxid, &cnx_server->initial_cnxid) != 0) {
            DBG_PRINTF("Server Cnx-ID= %llx, differs from Client Cnx-ID = %llx\n",
                (unsigned long long) picoquic_val64_connection_id(cnx_client->initial_cnxid),
                (unsigned long long) picoquic_val64_connection_id(cnx_server->initial_cnxid));
            ret = -1;
        }
#if 0
        /* TODO: find replacement for this test */
        else if (picoquic_compare_cleartext_aead_contexts(cnx_client, cnx_server) != 0 ||
            picoquic_compare_cleartext_aead_contexts(cnx_server, cnx_client) != 0) {
            DBG_PRINTF("%s", "Cleartext encryption contexts no not match.\n");
            ret = -1;
        }
#endif
    }

    /* Create a packet from client to server, encrypt, decrypt */
    if (ret == 0) {
        cleartext_aead_packet_init_header(&ph_init,
            cnx_client->initial_cnxid, seqnum, cnx_client->proposed_version,
            picoquic_packet_initial);
        cleartext_aead_init_packet(&ph_init, clear_text, clear_length);

        /* AEAD Encrypt, to the send buffer */
        memcpy(incoming, clear_text, ph_init.offset);
        encoded_length = picoquic_aead_encrypt_generic(incoming + ph_init.offset,
            clear_text + ph_init.offset, clear_length - ph_init.offset,
            seqnum, incoming, ph_init.offset, cnx_client->crypto_context[0].aead_encrypt);
        encoded_length += ph_init.offset;

        /* AEAD Decrypt */
        decoded_length = picoquic_aead_decrypt_generic(incoming + ph_init.offset,
            incoming + ph_init.offset, encoded_length - ph_init.offset, seqnum,
            incoming, ph_init.offset, cnx_server->crypto_context[0].aead_decrypt);
        decoded_length += ph_init.offset;

        if (decoded_length != clear_length) {
            DBG_PRINTF("Decoded length (%d) does not match clear lenth (%d).\n", (int)decoded_length, (int)clear_length);
            ret = -1;
        } else if (memcmp(incoming, clear_text, clear_length) != 0) {
            DBG_PRINTF("%s", "Decoded message not match clear length.\n");
            ret = 1;
        }
    }

    if (cnx_client != NULL) {
        picoquic_delete_cnx(cnx_client);
    }

    if (cnx_server != NULL) {
        picoquic_delete_cnx(cnx_server);
    }

    if (qclient != NULL) {
        picoquic_free(qclient);
    }

    if (qserver != NULL) {
        picoquic_free(qserver);
    }

    return ret;
}

static int cleartext_iv_cmp(void * void_aead, uint8_t * ref_iv, size_t iv_length)
{
#if 0
    ptls_aead_context_t* aead = (ptls_aead_context_t*)void_aead;

    return memcmp(aead->static_iv, ref_iv, iv_length);
#else
#ifdef _WINDOWS
    UNREFERENCED_PARAMETER(void_aead);
    UNREFERENCED_PARAMETER(ref_iv);
    UNREFERENCED_PARAMETER(iv_length);
#endif
    return 0;
#endif
}

int cleartext_aead_vector_test_one(picoquic_connection_id_t test_id, uint32_t test_vn,
    uint8_t * client_iv, size_t client_iv_length,
    uint8_t * server_iv, size_t server_iv_length, char const * test_name)
{
    int ret = 0;
    struct sockaddr_in test_addr_c;
    picoquic_cnx_t* cnx_client = NULL;
    picoquic_quic_t* qclient = picoquic_create(8, NULL, NULL, NULL, NULL, NULL, NULL,
        NULL, NULL, NULL, 0, NULL, NULL, NULL, 0);
    if (qclient == NULL) {
        DBG_PRINTF("%s: Could not create Quic context.\n", test_name);
        ret = -1;
    }

    if (ret == 0) {
        memset(&test_addr_c, 0, sizeof(struct sockaddr_in));
        test_addr_c.sin_family = AF_INET;
        memcpy(&test_addr_c.sin_addr, addr1, 4);
        test_addr_c.sin_port = 12345;

        cnx_client = picoquic_create_cnx(qclient, test_id, picoquic_null_connection_id,
            (struct sockaddr*)&test_addr_c, 0, test_vn, NULL, NULL, 1);

        if (cnx_client == NULL) {
            DBG_PRINTF("%s: Could not create client connection context.\n", test_name);
            ret = -1;
        }
        else {
            ret = picoquic_start_client_cnx(cnx_client);

            if (ret == 0) {
                /* Compare client key to expected value */
                if (cnx_client->crypto_context[0].aead_encrypt == NULL)
                {
                    DBG_PRINTF("%s: Could not create clear text AEAD encryption context.\n", test_name);
                    ret = -1;
                }
                else if (0 != cleartext_iv_cmp(cnx_client->crypto_context[0].aead_encrypt,
                    client_iv, client_iv_length)) {
                    DBG_PRINTF("%s: Clear text AEAD encryption IV does not match expected value.\n", test_name);
                    ret = -1;
                }
                else if (cnx_client->crypto_context[0].aead_decrypt == NULL) {
                    DBG_PRINTF("%s: Could not create clear text AEAD decryption context.\n", test_name);
                    ret = -1;
                }
                else if (0 != cleartext_iv_cmp(cnx_client->crypto_context[0].aead_decrypt,
                    server_iv, server_iv_length)) {
                    DBG_PRINTF("%s: Clear text AEAD decryption IV does not match expected value.\n", test_name);
                    ret = -1;
                }
            }
        }
    }

    if (cnx_client != NULL) {
        picoquic_delete_cnx(cnx_client);
    }

    if (qclient != NULL) {
        picoquic_free(qclient);
    }

    return ret;
}

/*
 * Test the CTR primitives used for PN encryption
 */

int pn_ctr_test()
{
    int ret = 0;

    static const uint8_t key[] = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
    static const uint8_t iv[] = {
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
        0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a };
    static const uint8_t expected[] = { 
        0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60,
        0xa8, 0x9e, 0xca, 0xf3, 0x24, 0x66, 0xef, 0x97 };
    static const uint8_t packet_clear_pn[] = {
        0x5D,
        0xba, 0xba, 0xc0, 0x01,
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
        0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
        0x20, 0x3f, 0xbe, 0x2e, 0x32, 0x17, 0xfc, 0x5b, 
        0x88, 0x55
    };
    static const uint8_t packet_encrypted_pn[] = {
        0x5d,
        0x80, 0x6d, 0xbb, 0xb5,
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
        0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
        0x20, 0x3f, 0xbe, 0x2e, 0x32, 0x17, 0xfc, 0x5b,
        0x88, 0x55
    };

    uint8_t in_bytes[16];
    uint8_t out_bytes[16];
    uint8_t decoded[16];

    picoquic_tls_api_init();

    ptls_aead_algorithm_t* aead = (ptls_aead_algorithm_t*)picoquic_get_aes128gcm_v(0);
    ptls_cipher_context_t *pn_enc = (aead == NULL)?NULL:ptls_cipher_new(aead->ctr_cipher, 1, key);

    if (pn_enc == NULL) {
        ret = -1;
    } else {
        /* test against expected value, from PTLS test */
        ptls_cipher_init(pn_enc, iv);
        memset(in_bytes, 0, 16);
        ptls_cipher_encrypt(pn_enc, out_bytes, in_bytes, sizeof(in_bytes));
        if (memcmp(out_bytes, expected, 16) != 0) {
            ret = -1;
        }

        /* test for various values of the PN length */

        for (size_t i = 1; ret == 0 && i <= 16; i *= 2) {
            memset(in_bytes, (int)i, i);
            ptls_cipher_init(pn_enc, iv);
            ptls_cipher_encrypt(pn_enc, out_bytes, in_bytes, i);
            for (size_t j = 0; j < i; j++) {
                if (in_bytes[j] != (out_bytes[j] ^ expected[j])) {
                    ret = -1;
                    break;
                }
            }
            ptls_cipher_init(pn_enc, iv);
            ptls_cipher_encrypt(pn_enc, decoded, out_bytes, i);
            if (memcmp(in_bytes, decoded, i) != 0) {
                ret = -1;
            }

            ptls_cipher_init(pn_enc, iv);
            ptls_cipher_encrypt(pn_enc, out_bytes, out_bytes, i);
            if (memcmp(in_bytes, out_bytes, i) != 0) {
                ret = -1;
            }
        }

        /* Test with the encrypted value from the packet */
        if (ret == 0)
        {
            ptls_cipher_init(pn_enc, packet_clear_pn + 5);
            ptls_cipher_encrypt(pn_enc, out_bytes, packet_clear_pn + 1, 4);
            if (memcmp(out_bytes, packet_encrypted_pn + 1, 4) != 0)
            {
                ret = -1;
            } else {
                ptls_cipher_init(pn_enc, packet_encrypted_pn + 5);
                ptls_cipher_encrypt(pn_enc, out_bytes, packet_encrypted_pn + 1, 4);
                if (memcmp(out_bytes, packet_clear_pn + 1, 4) != 0)
                {
                    ret = -1;
                }
            }
        }
        // cleanup
        ptls_cipher_free(pn_enc);
    }

    return ret;
}

/*
* Test that the generated encryption and decryption produce
* the same results.
*/

int test_one_pn_enc_pair(uint8_t * seqnum, size_t seqnum_len, void * pn_enc, void * pn_dec, uint8_t * sample)
{
    int ret = 0;
    uint8_t encoded[32];
    uint8_t decoded[32];

    ptls_cipher_init((ptls_cipher_context_t *)pn_enc, sample);
    ptls_cipher_encrypt((ptls_cipher_context_t *)pn_enc, encoded, seqnum, seqnum_len);

    ptls_cipher_init((ptls_cipher_context_t *)pn_dec, sample);
    ptls_cipher_encrypt((ptls_cipher_context_t *)pn_dec, decoded, encoded, seqnum_len);

    if (memcmp(seqnum, decoded, seqnum_len) != 0)
    {
        ret = -1;
    }

    return ret;
}

/*
 * Test that the key generated for cleartext PN encryption on
 * client and server produce the correct results.
 */

int cleartext_pn_enc_test()
{
    int ret = 0;
    struct sockaddr_in test_addr_c, test_addr_s;
    picoquic_cnx_t* cnx_client = NULL;
    picoquic_cnx_t* cnx_server = NULL;
    picoquic_quic_t* qclient = NULL;
    picoquic_quic_t* qserver = NULL;
    char test_server_cert_file[512];
    char test_server_key_file[512];

    ret = picoquic_get_input_path(test_server_cert_file, sizeof(test_server_cert_file), picoquic_solution_dir, PICOQUIC_TEST_FILE_SERVER_CERT);

    if (ret == 0) {
        ret = picoquic_get_input_path(test_server_key_file, sizeof(test_server_key_file), picoquic_solution_dir, PICOQUIC_TEST_FILE_SERVER_KEY);
    }

    if (ret != 0) {
        DBG_PRINTF("%s", "Cannot set the cert or key file names.\n");
    }
    else {
        qclient = picoquic_create(8, NULL, NULL, NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, 0, NULL, NULL, NULL, 0);
        qserver = picoquic_create(8, test_server_cert_file, test_server_key_file,
            NULL, PICOQUIC_TEST_ALPN, NULL, NULL, NULL, NULL, NULL, 0, NULL, NULL, NULL, 0);
        if (qclient == NULL || qserver == NULL) {
            DBG_PRINTF("%s", "Could not create Quic contexts.\n");
            ret = -1;
        }
    }

    if (ret == 0) {
        memset(&test_addr_c, 0, sizeof(struct sockaddr_in));
        test_addr_c.sin_family = AF_INET;
        memcpy(&test_addr_c.sin_addr, addr1, 4);
        test_addr_c.sin_port = 12345;

        cnx_client = picoquic_create_cnx(qclient, picoquic_null_connection_id, picoquic_null_connection_id,
            (struct sockaddr*)&test_addr_c, 0, 0, NULL, PICOQUIC_TEST_ALPN, 1);
        if (cnx_client == NULL) {
            DBG_PRINTF("%s", "Could not create client connection context.\n");
            ret = -1;
        } else {
            ret = picoquic_start_client_cnx(cnx_client);
        }
    }

    if (ret == 0) {

        memset(&test_addr_s, 0, sizeof(struct sockaddr_in));
        test_addr_s.sin_family = AF_INET;
        memcpy(&test_addr_s.sin_addr, addr2, 4);
        test_addr_s.sin_port = 4433;

        cnx_server = picoquic_create_cnx(qserver, cnx_client->initial_cnxid, cnx_client->path[0]->p_local_cnxid->cnx_id,
            (struct sockaddr*)&test_addr_s, 0,
            cnx_client->proposed_version, NULL, NULL, 0);

        if (cnx_server == NULL) {
            DBG_PRINTF("%s", "Could not create server connection context.\n");
            ret = -1;
        }
    }

    /* Try to encrypt a sequence number */
    if (ret == 0) {
        uint8_t seq_num_1[4] = { 0xde, 0xad, 0xbe, 0xef };
        uint8_t sample_1[16] = {
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
            0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a };
        uint8_t seq_num_2[4] = { 0xba, 0xba, 0xc0, 0x0l };
        uint8_t sample_2[16] = {
            0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96};

        ret = test_one_pn_enc_pair(seq_num_1, 4, 
            cnx_client->crypto_context[0].pn_enc, cnx_server->crypto_context[0].pn_dec, sample_1);

        if (ret != 0) {
            DBG_PRINTF("%s", "Test of encoding PN sample 1 failed.\n");
        } else {
            ret = test_one_pn_enc_pair(seq_num_2, 4, cnx_server->crypto_context[0].pn_enc, 
                cnx_client->crypto_context[0].pn_dec, sample_2);
            if (ret != 0) {
                DBG_PRINTF("%s", "Test of encoding PN sample 2 failed.\n");
            }
        }
    }

    if (cnx_client != NULL) {
        picoquic_delete_cnx(cnx_client);
    }

    if (cnx_server != NULL) {
        picoquic_delete_cnx(cnx_server);
    }

    if (qclient != NULL) {
        picoquic_free(qclient);
    }

    if (qserver != NULL) {
        picoquic_free(qserver);
    }

    return ret;
}

/* Test vector copied from Kazuho Ohu's test code in quicly -- then changed */

int cleartext_pn_vector_test()
{
    int ret = 0;
#if 0
    static const uint8_t cid[] = { 0x77, 0x0d, 0xc2, 0x6c, 0x17, 0x50, 0x9b, 0x35 };
    static const uint8_t sample[] = { 0x05, 0x80, 0x24, 0xa9, 0x72, 0x75, 0xf0, 0x1d, 0x2a, 0x1e, 0xc9, 0x1f, 0xd1, 0xc2, 0x65, 0xbb };
    static const uint8_t encrypted_pn[] = { 0x02, 0x6c, 0xe6, 0xde };
    static const uint8_t expected_pn[] = { 0xc0, 0x00, 0x00, 0x00 };

    struct sockaddr_in test_addr_s;
    picoquic_connection_id_t initial_cnxid;
    picoquic_cnx_t* cnx_server = NULL;
    picoquic_quic_t* qserver = NULL;
    char test_server_cert_file[512];
    char test_server_key_file[512];

    ret = picoquic_get_input_path(test_server_cert_file, sizeof(test_server_cert_file), picoquic_solution_dir, PICOQUIC_TEST_FILE_SERVER_CERT);

    if (ret == 0) {
        ret = picoquic_get_input_path(test_server_key_file, sizeof(test_server_key_file), picoquic_solution_dir, PICOQUIC_TEST_FILE_SERVER_KEY);
    }

    if (ret != 0) {
        DBG_PRINTF("%s", "Cannot set the cert or key file names.\n");
    }
    else {
        qserver = picoquic_create(8, test_server_cert_file, test_server_key_file,
            NULL, "test", NULL, NULL, NULL, NULL, NULL, 0, NULL, NULL, NULL, 0);
        if (qserver == NULL) {
            DBG_PRINTF("%s", "Could not create Quic contexts.\n");
            ret = -1;
        }
    }

    if (ret == 0 && picoquic_parse_connection_id(cid, sizeof(cid), &initial_cnxid) != sizeof(cid)) {
        ret = -1;
    }


    if (ret == 0) {

        memset(&test_addr_s, 0, sizeof(struct sockaddr_in));
        test_addr_s.sin_family = AF_INET;
        memcpy(&test_addr_s.sin_addr, addr2, 4);
        test_addr_s.sin_port = 4433;

        cnx_server = picoquic_create_cnx(qserver, initial_cnxid, initial_cnxid,
            (struct sockaddr*)&test_addr_s, 0, PICOQUIC_NINTH_INTEROP_VERSION, NULL, NULL, 0);

        if (cnx_server == NULL) {
            DBG_PRINTF("%s", "Could not create server connection context.\n");
            ret = -1;
        }
    }

    /* Try to decrypt the test vector */
    if (ret == 0) {
        uint8_t decrypted[8];

        memset(decrypted, 0, sizeof(decrypted));

        picoquic_pn_encrypt(cnx_server->crypto_context[0].pn_dec, sample, decrypted, encrypted_pn, sizeof(encrypted_pn));

        if (memcmp(decrypted, expected_pn, sizeof(expected_pn)) != 0)
        {
            DBG_PRINTF("%s", "Test of encoding PN vector failed.\n");
            ret = -1;
        }
    }

    if (cnx_server != NULL) {
        picoquic_delete_cnx(cnx_server);
    }

    if (qserver != NULL) {
        picoquic_free(qserver);
    }
#endif
    return ret;
}

/*
 * draft-17 vectors copied from Tatsuhiro's data. We do not have a complete message.
 */
#if 0
static uint8_t draft15_test_input_packet[] = {
    0xff, 0xff, 0x00, 0x00, 0x0f, 0x50, 0x06, 0xb8, 0x58, 0xec,
    0x6f, 0x80, 0x45, 0x2b, 0x00, 0x40, 0x44, 0xef, 0xa5, 0xd8, 0xd3,
    0x07, 0xc2, 0x97, 0x3f, 0xa0, 0xd6, 0x3f, 0xd9, 0xb0, 0x3a,
    0x4e, 0x16, 0x3b, 0x99, 0x0d, 0xd7, 0x78, 0x89, 0x4a, 0x9e,
    0xdc, 0x8e, 0xac, 0xfb, 0xe4, 0xaa, 0x6f, 0xbf, 0x4a, 0x22,
    0xec, 0x7f, 0x90, 0x6b, 0x5e, 0x8b, 0x8a, 0xe1, 0x2e, 0x5f,
    0xcc, 0x79, 0x24, 0xdf, 0xee, 0xe8, 0x13, 0x84, 0x2b, 0xb2,
    0x14, 0x9b, 0x80, 0x5e, 0x55, 0x89, 0x50, 0x84, 0xe8, 0x39,
    0x32, 0x00, 0xbb, 0x3f, 0xc6, 0x18, 0xaf, 0x7d, 0x08, 0x28,
    0x14, 0x85, 0xd9, 0x14, 0xce, 0x42, 0x30, 0x3f, 0x5d, 0x77,
    0x2b, 0x20, 0x05, 0x08, 0xa0, 0xc0, 0x02, 0x53, 0xe3, 0x32,
    0xe3, 0x6a, 0x84, 0xf6, 0x57, 0x32, 0x1a, 0xc4, 0xc8, 0xe2,
    0xcc, 0x8a, 0x11, 0x7e, 0x95, 0x87, 0x1f, 0x12, 0xb1, 0xf3,
    0x6b, 0xe8, 0xc4, 0xb7, 0x6f, 0xa4, 0x33, 0xdc, 0x4d, 0x31,
    0x42, 0xe6, 0x54, 0x7f, 0x45, 0x98, 0xbf, 0x4b, 0x19, 0x21,
    0x30, 0xae, 0xa6, 0xfc, 0x20, 0xda, 0x51, 0x58, 0xb2, 0x16,
    0x2b, 0x5a, 0x89, 0x99, 0x57, 0xda, 0x05, 0xde, 0xd5, 0xc7,
    0x09, 0x07, 0x29, 0x8f, 0xd8, 0x85, 0x84, 0x7f, 0x22, 0xa1,
    0xec, 0xb0, 0xa8, 0x14, 0xfe, 0x01, 0x70, 0xe2, 0x3c, 0xad,
    0x20, 0xaf, 0x64, 0xf0, 0x5c, 0xc1, 0x3c, 0x74, 0xe9, 0x18,
    0x24, 0x10, 0x1a, 0xfd, 0xcf, 0x5f, 0x15, 0x32, 0xfc, 0x2f,
    0xde, 0x93, 0x6a, 0x3a, 0x15, 0x9f, 0x76, 0x28, 0x3a, 0x26,
    0xc7, 0x38, 0xf7, 0x78, 0xc7, 0x6e, 0x6c, 0xa4, 0x1f, 0xa7,
    0xf1, 0x34, 0x40, 0x1d, 0x39, 0x02, 0x7f, 0xd8, 0x1d, 0xe1,
    0x7a, 0x80, 0x21, 0xa9, 0xc0, 0xaa, 0xa9, 0xb4, 0x47, 0x8f,
    0xe5, 0xc0, 0x64, 0x79, 0x41, 0x61, 0x8f, 0x3b, 0xee, 0x41,
    0x0c, 0xaf, 0x94, 0xc2, 0x48, 0xd2, 0xa6, 0x4b, 0x5e, 0x45,
    0x84, 0x5c, 0xd7, 0x7d, 0xe1, 0x3a, 0x5e, 0xd9, 0x40, 0x34,
    0xd2, 0xbc, 0x5f, 0x45, 0x78, 0x87, 0x35, 0x19, 0x93, 0xc1,
    0xec, 0xfa, 0x34, 0xfd, 0x0c, 0x65, 0x8f, 0xea, 0x3f, 0x80,
    0x86, 0xd2, 0x68, 0x08, 0xee, 0xf9, 0x76, 0x26, 0x2e, 0xcf,
    0x0a, 0xd6, 0x46, 0xb6, 0x27, 0x94, 0x55, 0x11, 0xdd, 0xe8,
    0x3e, 0x26, 0x60, 0x9c, 0xd5, 0xcf, 0xd7, 0xed, 0x9f, 0x62,
    0x07, 0xd7, 0x66, 0x18, 0xb4, 0x4c, 0x48, 0xbf, 0x62, 0x3b,
    0xf4, 0x20, 0xdc, 0x7c, 0x12, 0x7e, 0x5d, 0x5f, 0x52, 0x9f,
    0x08, 0x3b, 0x71, 0xa1, 0x7b, 0x17, 0xda, 0x32, 0x9b, 0xfc,
    0x38, 0xa7, 0x4b, 0xf8, 0xcf, 0xcf, 0x31, 0x5c, 0x7c, 0x07,
    0x0b, 0x71, 0xeb, 0xfa, 0xe3, 0xab, 0x35, 0x13, 0x41, 0xa7,
    0x67, 0xad, 0xfd, 0xd9, 0xe5, 0x7c, 0x73, 0x8f, 0x5d, 0xe9,
    0xda, 0x53, 0x71, 0x1e, 0x88, 0x6d, 0x14, 0x72, 0x31, 0x0b,
    0x91, 0x7a, 0x1c, 0x97, 0x98, 0xe3, 0xe9, 0xb1, 0x3c, 0x7c,
    0x74, 0xbe, 0xb8, 0xd1, 0xb8, 0x23, 0x45, 0xbe, 0xa1, 0x34,
    0x94, 0x15, 0x67, 0x9a, 0x9c, 0x64, 0xb0, 0x43, 0x3b, 0x68,
    0xc8, 0x71, 0xae, 0x08, 0x09, 0x2a, 0x1f, 0x61, 0x06, 0xbc,
    0x06, 0x33, 0x7c, 0xd3, 0x43, 0x86, 0x6e, 0xe8, 0x18, 0x5c,
    0x03, 0xfc, 0xf3, 0xbb, 0x06, 0x66, 0x45, 0x3f, 0x84, 0x79,
    0x05, 0x54, 0x71, 0x99, 0x41, 0x4c, 0x1e, 0x57, 0x53, 0x57,
    0x47, 0xbe, 0x61, 0xcd, 0xf6, 0x77, 0x83, 0x78, 0xf1, 0x21,
    0xd6, 0x8d, 0xf0, 0x18, 0x1e, 0xe9, 0xe8, 0xd9, 0x93, 0x2c,
    0x1c, 0x59, 0x3c, 0x0f, 0x8c, 0x0a, 0x1a, 0xf0, 0xf5, 0x26,
    0x2b, 0x86, 0x20, 0x50, 0x02, 0xdc, 0xed, 0x9e, 0xcd, 0xae,
    0xe2, 0xd0, 0xaa, 0x07, 0xdd, 0x4c, 0x14, 0xf9, 0x85, 0x71,
    0xe4, 0xbe, 0xa7, 0x2f, 0x84, 0x74, 0xf6, 0x36, 0x97, 0x04,
    0x3e, 0x93, 0x6e, 0xbb, 0x2b, 0xf9, 0x71, 0x6e, 0xd0, 0xef,
    0xbd, 0xc1, 0x30, 0x05, 0xa7, 0x5c, 0xee, 0x3a, 0x49, 0xba,
    0xbc, 0x61, 0xb9, 0x67, 0x77, 0x64, 0x51, 0x0e, 0xb1, 0x98,
    0x28, 0xdf, 0x4e, 0x10, 0xfb, 0x38, 0xb7, 0x9a, 0x1e, 0xfb,
    0xf0, 0x4c, 0xc2, 0xd5, 0x71, 0x94, 0x9d, 0x54, 0x03, 0xf7,
    0x97, 0x36, 0x17, 0x43, 0xdc, 0xc5, 0xe3, 0xbf, 0x3b, 0x43,
    0x96, 0xf7, 0xae, 0x1a, 0x3a, 0xff, 0xbc, 0x9f, 0x72, 0xe5,
    0x40, 0xd9, 0x20, 0x36, 0x39, 0x70, 0x30, 0x7e, 0x07, 0x25,
    0xfa, 0x83, 0x8d, 0x61, 0x18, 0x03, 0x25, 0x1a, 0x4a, 0x08,
    0xcc, 0xca, 0x19, 0x83, 0xd5, 0xb2, 0x9a, 0x58, 0x37, 0x58,
    0xbe, 0x63, 0x34, 0x3e, 0x88, 0xf5, 0x59, 0x1d, 0x88, 0x5b,
    0x8a, 0xf6, 0x95, 0xf3, 0x3a, 0xdb, 0xdd, 0x0d, 0x94, 0x1d,
    0x26, 0x02, 0x87, 0xe3, 0x2e, 0xf5, 0xa9, 0x8f, 0xd5, 0x5a,
    0xc1, 0x37, 0x21, 0x10, 0x21, 0xfd, 0xc2, 0x3b, 0x5d, 0x7a,
    0x54, 0x69, 0xf5, 0x78, 0xbf, 0x7a, 0xff, 0x65, 0x29, 0x11,
    0x79, 0x96, 0xf9, 0xeb, 0xab, 0x5e, 0x6d, 0xc7, 0xb0, 0x47,
    0xb3, 0x56, 0x33, 0x2f, 0xea, 0x82, 0xfd, 0xd6, 0x20, 0xeb,
    0x86, 0xf3, 0xc1, 0xd3, 0x85, 0x5c, 0x8b, 0x80, 0x75, 0xda,
    0x59, 0xa7, 0x66, 0x2f, 0x4a, 0x11, 0xb9, 0x77, 0xd9, 0x96,
    0xb8, 0xb3, 0xc7, 0x65, 0x7a, 0xd4, 0xa8, 0x2a, 0x20, 0xa7,
    0xf7, 0x6c, 0xe3, 0x76, 0xc0, 0x32, 0x00, 0x86, 0xed, 0x02,
    0x9d, 0xd6, 0x15, 0x39, 0x93, 0x07, 0x98, 0x31, 0x13, 0xcc,
    0x0a, 0xa9, 0x73, 0xec, 0xba, 0x69, 0x1e, 0x7e, 0x4c, 0xdc,
    0x80, 0xae, 0xfa, 0x7e, 0x8c, 0x83, 0x47, 0xba, 0xba, 0x05,
    0x0e, 0xac, 0xa7, 0xdc, 0x35, 0xa2, 0x1a, 0xa8, 0x54, 0xe5,
    0x31, 0xdc, 0x77, 0x58, 0xd7, 0xd1, 0x0b, 0x8c, 0x8e, 0x42,
    0xc1, 0xbe, 0x3b, 0xbf, 0x26, 0x6d, 0x05, 0x5a, 0xc2, 0x5c,
    0x37, 0x27, 0x9e, 0xbe, 0xfa, 0x28, 0xbb, 0xe8, 0x9a, 0x34,
    0xad, 0x1a, 0xb3, 0xd2, 0x3d, 0x7a, 0x66, 0xd1, 0xc2, 0x16,
    0xa5, 0x76, 0x50, 0xe6, 0xec, 0x9f, 0xc8, 0xba, 0x7a, 0xdf,
    0xb3, 0x8e, 0x57, 0xf2, 0x0c, 0x46, 0x71, 0x66, 0xc8, 0xfe,
    0x79, 0x44, 0xe6, 0x7f, 0x82, 0x13, 0x81, 0x60, 0x00, 0x20,
    0x04, 0x81, 0x2c, 0x78, 0xba, 0x4b, 0x5f, 0x0d, 0xa9, 0x17,
    0xda, 0x4c, 0xc1, 0x4c, 0xf8, 0xfc, 0x10, 0xdb, 0xa3, 0xf5,
    0x33, 0xfa, 0xcb, 0x11, 0xef, 0x06, 0xd8, 0xb8, 0xf1, 0x78,
    0xea, 0x9c, 0x5e, 0x8a, 0xcb, 0xbc, 0xa7, 0xb7, 0xf0, 0xe1,
    0xf6, 0xb7, 0xa7, 0x0e, 0xc2, 0xd5, 0x10, 0x8c, 0xc4, 0x11,
    0x78, 0x05, 0x62, 0x95, 0x79, 0x3b, 0xed, 0x35, 0x7a, 0xcc,
    0xbb, 0x03, 0xc0, 0x58, 0x2d, 0xc6, 0x9b, 0xc7, 0x7a, 0x34,
    0x03, 0x0f, 0x38, 0xcc, 0xe2, 0x56, 0xc5, 0xa9, 0xce, 0xc6,
    0xe8, 0x62, 0x14, 0x6e, 0x3f, 0x04, 0x63, 0xf1, 0x0d, 0xd5,
    0x83, 0x32, 0x57, 0xd0, 0xa0, 0x35, 0x91, 0x66, 0xa7, 0xe2,
    0x02, 0x7d, 0x98, 0xea, 0xf2, 0x6c, 0xf0, 0xd5, 0xa4, 0xa0,
    0x5f, 0x6e, 0xf8, 0xb7, 0x42, 0xf5, 0xd3, 0x14, 0xa3, 0x1d,
    0xee, 0xea, 0xbe, 0x4e, 0xbc, 0x31, 0x06, 0x54, 0x7e, 0x79,
    0xc6, 0xcb, 0x93, 0x31, 0x05, 0xd9, 0x07, 0xb4, 0xc8, 0xc6,
    0x04, 0x43, 0xe9, 0x7a, 0x15, 0x46, 0x94, 0xba, 0xb5, 0xed,
    0xfc, 0x78, 0x1a, 0x43, 0x86, 0x75, 0xb9, 0xde, 0x6e, 0xd0,
    0x3c, 0x77, 0xf5, 0x14, 0x58, 0xea, 0xb6, 0x1c, 0xa2, 0xe8,
    0x0a, 0xc0, 0x2c, 0xc8, 0xc0, 0x37, 0xd8, 0xfb, 0x3c, 0xf1,
    0x29, 0xd7, 0x10, 0x7f, 0x61, 0x8d, 0x66, 0x03, 0x2c, 0xc0,
    0x22, 0x38, 0xa2, 0x11, 0xf7, 0x8b, 0xfa, 0x44, 0xe7, 0xc1,
    0xbb, 0xcf, 0xcc, 0x62, 0x77, 0x71, 0xc1, 0x88, 0xd1, 0xb3,
    0x71, 0x3c, 0xe5, 0xe7, 0x5c, 0xd2, 0x32, 0x5a, 0x0a, 0x2b,
    0xa0, 0x82, 0x68, 0xca, 0xd1, 0x3b, 0x27, 0xd9, 0x76, 0x96,
    0xef, 0x67, 0x8b, 0x59, 0x2d, 0x0a, 0xc8, 0x0a, 0xd1, 0xba,
    0xcb, 0x4a, 0x1b, 0xa7, 0x5b, 0xea, 0x8c, 0x47, 0x7f, 0x39,
    0xfc, 0x32, 0xc2, 0xaa, 0x20, 0xf3, 0x52, 0xbb, 0x0d, 0xa1,
    0xc4, 0x9b, 0x7d, 0x39, 0x27, 0xbc, 0xd9, 0xdf, 0xaf, 0x22,
    0x92, 0x37, 0x08, 0x1d, 0x5f, 0xa0, 0x89, 0x24, 0xfe, 0xfd,
    0x92, 0x3f, 0xf0, 0xac, 0x6b, 0xaa, 0xd6, 0x86, 0x4b, 0x7c,
    0x10, 0xdc, 0x73, 0x37, 0x9a, 0x5e, 0xbd, 0x9e, 0x46, 0x78,
    0xa0, 0xc2, 0x65, 0x17, 0x65, 0x6e, 0x8e, 0x51, 0xfc, 0xa2,
    0xa5, 0x1a, 0x33, 0xfb, 0x2c, 0xdd, 0x5d, 0x76, 0xd1, 0x26,
    0x74, 0xc2, 0x40, 0xba, 0x9a, 0x48, 0x93, 0xc1, 0xaf, 0x69,
    0xb8, 0xf2, 0xc4, 0xad, 0xf3, 0x7c, 0x4a, 0x47, 0x55, 0x1e,
    0xb2, 0x00, 0x6a, 0x73, 0x2f, 0x6b, 0x3b, 0x2f, 0x33, 0x8c,
    0x07, 0x8e, 0xde, 0x33, 0x94, 0x6d, 0xfe, 0x4a, 0x55, 0xbf,
    0x64, 0x4d, 0x3b, 0x98, 0x84, 0x86, 0x93, 0xad, 0xa1, 0xfc,
    0xb6, 0xfc, 0x16, 0xca, 0xc3, 0x39, 0xee, 0x65, 0xc2, 0x4d,
    0xc6, 0x4b, 0x0a, 0xe9, 0x20, 0x05, 0x35, 0x4a, 0xf0, 0x0a,
    0xde, 0x71, 0xe6, 0xc5, 0xe2, 0xef, 0xd8, 0x5c, 0x46, 0x13,
    0x1d, 0x94, 0x8f, 0xf1, 0x40, 0x96, 0xb0, 0xf0, 0x6a, 0x41,
    0xd8, 0x3c, 0x85, 0x22, 0xf3, 0x0b, 0xeb, 0x4e, 0xaa, 0xf4,
    0xa6, 0xf9, 0x08, 0xfe, 0x2a, 0x6e, 0xe7, 0x54, 0xc8, 0x96
};
#endif

static uint32_t draft17_test_vn = PICOQUIC_INTEROP_VERSION_LATEST;

static picoquic_connection_id_t draft17_test_cnx_id = { 
    { 0x7d, 0xdc, 0x42, 0x90, 0xc4, 0xe7, 0xd2, 0x04 }, 8 };

static uint8_t draft17_test_salt[] = {
     0xef, 0x4f, 0xb0, 0xab, 0xb4, 0x74, 0x70, 0xc4,
     0x1b, 0xef, 0xcf, 0x80, 0x31, 0x33, 0x4f, 0xae,
     0x48, 0x5e, 0x09, 0xa0
};

/* initial_secret = e56c751dbc9ab8e79f616142c0c07ab830eb25968faeb7404da69a80f75f1c7c */
static uint8_t draft17_test_initial_secret[] = {
    0xe5, 0x6c, 0x75, 0x1d, 0xbc, 0x9a, 0xb8, 0xe7, 
    0x9f, 0x61, 0x61, 0x42, 0xc0, 0xc0, 0x7a, 0xb8, 
    0x30, 0xeb, 0x25, 0x96, 0x8f, 0xae, 0xb7, 0x40, 
    0x4d, 0xa6, 0x9a, 0x80, 0xf7, 0x5f, 0x1c, 0x7c
};

/* server_in_secret=5eac7474 7872fe6d 9ecbac75 df87abc4 bb4374c8 e6636549 da718b9f 722f0d6a */
static uint8_t draft17_test_server_initial_secret[] = {
    0x5e, 0xac, 0x74, 0x74, 0x78, 0x72, 0xfe, 0x6d,
    0x9e, 0xcb, 0xac, 0x75, 0xdf, 0x87, 0xab, 0xc4,
    0xbb, 0x43, 0x74, 0xc8, 0xe6, 0x63, 0x65, 0x49,
    0xda, 0x71, 0x8b, 0x9f, 0x72, 0x2f, 0x0d, 0x6a
};

/*  server_pp_key=f367a4c1 2f7726d9 2ccea21b 9339a871 */
static uint8_t draft17_test_server_key[] = {
    0xf3, 0x67, 0xa4, 0xc1, 0x2f, 0x77, 0x26, 0xd9,
    0x2c, 0xce, 0xa2, 0x1b, 0x93, 0x39, 0xa8, 0x71
};

/* server_pp_iv = 448214c966314d8f540b7b43 */
static uint8_t draft17_test_server_iv[] = {
    0x44, 0x82, 0x14, 0xc9, 0x66, 0x31, 0x4d, 0x8f, 0x54, 0x0b, 0x7b, 0x43
};

/* server_pp_hp = 922b113f1b2a815f084254f981a0b097 */
static uint8_t draft17_test_server_pn[] = {
    0x92, 0x2b, 0x11, 0x3f, 0x1b, 0x2a, 0x81, 0x5f,
    0x08, 0x42, 0x54, 0xf9, 0x81, 0xa0, 0xb0, 0x97
};

/* client_in_secret = f88616781056a6ac007087d121ce158ea8c770a1e62899616cde507bb6d60e08 */
static uint8_t draft17_test_client_initial_secret[] = {
    0xf8, 0x86, 0x16, 0x78, 0x10, 0x56, 0xa6, 0xac, 
    0x00, 0x70, 0x87, 0xd1, 0x21, 0xce, 0x15, 0x8e,
    0xa8, 0xc7, 0x70, 0xa1, 0xe6, 0x28, 0x99, 0x61,
    0x6c, 0xde, 0x50, 0x7b, 0xb6, 0xd6, 0x0e, 0x08
};

/* client_pp_key = 1b7e2858101833ce989a77254f3faa62 */
static uint8_t draft17_test_client_key[] = {
    0x1b, 0x7e, 0x28, 0x58, 0x10, 0x18, 0x33, 0xce,
    0x98, 0x9a, 0x77, 0x25, 0x4f, 0x3f, 0xaa, 0x62
};

/* client_pp_iv = 01a41aa73c43298dcb38bcb6 */

static uint8_t draft17_test_client_iv[] = {
    0x01, 0xa4, 0x1a, 0xa7, 0x3c, 0x43, 0x29, 0x8d, 0xcb, 0x38, 0xbc, 0xb6
};

/* client_pp_hp = 9a8542ef399038aba66ef1333809fc5b */

static uint8_t draft17_test_client_pn[] = {
    0x9a, 0x85, 0x42, 0xef, 0x39, 0x90, 0x38, 0xab,
    0xa6, 0x6e, 0xf1, 0x33, 0x38, 0x09, 0xfc, 0x5b
};


#if 0
/* TODO: reset this test when draft-17 vector is available */
static uint64_t draft17_test_decoded_pn = 0;
#endif

static int draft17_label_expansion_test(ptls_cipher_suite_t * cipher, char const * label, char const * base_label,
    uint8_t * secret, size_t secret_length, uint8_t const * key_ref, size_t key_ref_len)
{
    int ret = 0;
    uint8_t key_out[256];

    if ((ret = ptls_hkdf_expand_label(cipher->hash, key_out, key_ref_len, ptls_iovec_init(secret, secret_length),
        label, ptls_iovec_init(NULL, 0), base_label)) != 0) {
        DBG_PRINTF("Cannot expand label <%s>, ret = %x\n", label, ret);
    }
    else if (memcmp(key_out, key_ref, key_ref_len) != 0) {
        DBG_PRINTF("Expanded key for label <%s> does not match\n", label);
        ret = -1;
    }

    return ret;
}

#if 0
/* TODO: restore this test once we have a valid incoming message for draft-17 */
static int draft31_incoming_initial_test()
{
    int ret = 0;
    /* Create a server context */
    picoquic_quic_t* qserver = picoquic_create(8,
        PICOQUIC_TEST_SERVER_CERT, PICOQUIC_TEST_SERVER_KEY, PICOQUIC_TEST_CERT_STORE,
        "test", NULL, NULL, NULL, NULL, NULL, 0, NULL, NULL, NULL, 0);
    if (qserver == NULL) {
        DBG_PRINTF("%s", "Could not create Quic server context.\n");
        ret = -1;
    }

    if (ret == 0) {
        /* Simulate arrival of an initial packet in the server context */
        picoquic_cnx_t* cnx = NULL;
        picoquic_packet_header ph;
        uint32_t length = (uint32_t) sizeof(draft15_test_input_packet);
        uint64_t current_time = 0;
        uint32_t consumed = 0;
        struct sockaddr_in test_addr_c;
        int new_context_created = 0;

        memset(&test_addr_c, 0, sizeof(struct sockaddr_in));
        test_addr_c.sin_family = AF_INET;
        memcpy(&test_addr_c.sin_addr, addr1, 4);
        test_addr_c.sin_port = 12345;

        /* Parse the header and decrypt the packet */
        ret = picoquic_parse_header_and_decrypt(qserver, draft15_test_input_packet, length, length,
            (struct sockaddr *)&test_addr_c, current_time, &ph, &cnx, &consumed, &new_context_created);

        if (ret != 0) {
            DBG_PRINTF("Cannot parse or decrypt incoming packet, ret = %x\n", ret);
        }
        else if (ph.ptype != picoquic_packet_initial) {
            DBG_PRINTF("Incoming packet type %d instead of initial\n", ph.ptype);
            ret = -1;
        }
        else if (ph.pn != draft17_test_decoded_pn) {
            DBG_PRINTF("Incoming packet sequence %d instead of %d\n", ph.pn, draft17_test_decoded_pn);
            ret = -1;
        }
        else if (consumed != length) {
            DBG_PRINTF("Incoming packet length %d instead of %d\n", consumed, length);
            ret = -1;
        }

        if (cnx != NULL) {
            picoquic_delete_cnx(cnx);
        }

        picoquic_free(qserver);
    }

    return ret;
}
#endif


int draft17_vector_test()
{
    int ret = 0;
    int version_index = 0;
    ptls_iovec_t salt;
    uint8_t master_secret[256];
    uint8_t client_secret[256];
    uint8_t server_secret[256];
    ptls_cipher_suite_t* cipher = (ptls_cipher_suite_t*)picoquic_get_aes128gcm_sha256_v(0);

    if (cipher == NULL) {
        DBG_PRINTF("%s", "Could not find the default cipher suite.");
        ret = -1;
    }
    else {
        /* Check the label expansions */
        ret = draft17_label_expansion_test(cipher, PICOQUIC_LABEL_KEY, PICOQUIC_LABEL_QUIC_V1_KEY_BASE,
            draft17_test_server_initial_secret, sizeof(draft17_test_server_initial_secret),
            draft17_test_server_key, sizeof(draft17_test_server_key));
    }

    if (ret == 0) {
        ret = draft17_label_expansion_test(cipher, PICOQUIC_LABEL_IV, PICOQUIC_LABEL_QUIC_V1_KEY_BASE,
            draft17_test_server_initial_secret, sizeof(draft17_test_server_initial_secret),
            draft17_test_server_iv, sizeof(draft17_test_server_iv));
    }

    if (ret == 0) {
        ret = draft17_label_expansion_test(cipher, PICOQUIC_LABEL_HP, PICOQUIC_LABEL_QUIC_V1_KEY_BASE,
            draft17_test_server_initial_secret, sizeof(draft17_test_server_initial_secret),
            draft17_test_server_pn, sizeof(draft17_test_server_pn));
    }

    if (ret == 0) {
        ret = draft17_label_expansion_test(cipher, PICOQUIC_LABEL_KEY, PICOQUIC_LABEL_QUIC_V1_KEY_BASE,
            draft17_test_client_initial_secret, sizeof(draft17_test_client_initial_secret),
            draft17_test_client_key, sizeof(draft17_test_client_key));
    }

    if (ret == 0) {
        ret = draft17_label_expansion_test(cipher, PICOQUIC_LABEL_IV, PICOQUIC_LABEL_QUIC_V1_KEY_BASE,
            draft17_test_client_initial_secret, sizeof(draft17_test_client_initial_secret),
            draft17_test_client_iv, sizeof(draft17_test_client_iv));
    }

    if (ret == 0) {
        ret = draft17_label_expansion_test(cipher, PICOQUIC_LABEL_HP, PICOQUIC_LABEL_QUIC_V1_KEY_BASE,
            draft17_test_client_initial_secret, sizeof(draft17_test_client_initial_secret),
            draft17_test_client_pn, sizeof(draft17_test_client_pn));
    }

    /* Check the salt */
    version_index = picoquic_get_version_index(draft17_test_vn);
    if (version_index < 0) {
        DBG_PRINTF("Test version (%x) is not supported.\n", draft17_test_vn);
        ret = -1;
    }
    else if (picoquic_supported_versions[version_index].version_aead_key == NULL) {
        DBG_PRINTF("Test version (%x) has no salt.\n", draft17_test_vn);
        ret = -1;
    }
    else if (picoquic_supported_versions[version_index].version_aead_key_length != sizeof(draft17_test_salt))
    {
        DBG_PRINTF("Test version (%x) has no salt[%d], expected [%d].\n", draft17_test_vn,
            (int)picoquic_supported_versions[version_index].version_aead_key_length, (int) sizeof(draft17_test_salt));
        ret = -1;
    }
    else if (memcmp(picoquic_supported_versions[version_index].version_aead_key, draft17_test_salt, sizeof(draft17_test_salt)) != 0) {
        /* TODO: this test means that the reminder of the code will not be executed for new versions */
        DBG_PRINTF("Test version (%x) does not have matching salt.\n", draft17_test_vn);
    }
    else {

        /* Check the master secret and then client and server secret */
        if (ret == 0) {
            salt.base = draft17_test_salt;
            salt.len = sizeof(draft17_test_salt);

            ret = picoquic_setup_initial_master_secret(cipher, salt, draft17_test_cnx_id, master_secret);

            if (ret != 0) {
                DBG_PRINTF("Cannot compute master secret, ret = %x\n", ret);
            }
            else {
                if (memcmp(master_secret, draft17_test_initial_secret, sizeof(draft17_test_initial_secret)) != 0) {
                    DBG_PRINTF("%s", "Initial master secret does not match expected value");
                    ret = -1;
                }
            }

            if (ret == 0) {
                ret = picoquic_setup_initial_secrets(cipher, master_secret, client_secret, server_secret);

                if (ret != 0) {
                    DBG_PRINTF("Cannot derive client and server secrets, ret = %x\n", ret);
                }
                else {
                    if (memcmp(client_secret, draft17_test_client_initial_secret, sizeof(draft17_test_client_initial_secret)) != 0) {
                        DBG_PRINTF("%s", "Initial client secret does not match expected value");
                        ret = -1;
                    }

                    if (memcmp(server_secret, draft17_test_server_initial_secret, sizeof(draft17_test_server_initial_secret)) != 0) {
                        DBG_PRINTF("%s", "Initial server secret does not match expected value");
                        ret = -1;
                    }
                }
            }
        }

        /* First integration test: verify that the aead keys are as expected */
        if (ret == 0) {
            ret = cleartext_aead_vector_test_one(draft17_test_cnx_id, draft17_test_vn,
                draft17_test_client_iv, sizeof(draft17_test_client_iv),
                draft17_test_server_iv, sizeof(draft17_test_server_iv), "draft17_vector");
        }

#if 0
        /* TODO: reset this test once we have draft-17 samples. */
        /* Final integration test: verify that the incoming packet can be decrypted */
        if (ret == 0) {
            ret = draft31_incoming_initial_test();
        }
#endif
    }
    return ret;
}

/*
 * Test key rotation
 */
static const uint8_t key_rotation_test_init[PTLS_MAX_DIGEST_SIZE] = {
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
    17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
    33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48,
    49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64};

static const uint8_t key_rotation_test_target_sha384[] = {
    0xa1, 0xb5, 0xbd, 0xa2, 0x55, 0xf0, 0x7b, 0x68,
    0xdb, 0xe0, 0xa0, 0x39, 0x86, 0x94, 0xd9, 0x0d, 
    0xe1, 0xf9, 0x46, 0xe4, 0x68, 0xf6, 0x87, 0xeb,
    0x19, 0x22, 0x5c, 0x92, 0x45, 0xe1, 0xf4, 0xe4,
    0x17, 0x73, 0xf6, 0x46, 0x5c, 0xb2, 0x24, 0xe0,
    0x5d, 0xb0, 0x40, 0x7a, 0x9b, 0x67, 0x47, 0xd1};

static const uint8_t key_rotation_test_target_sha256[] = { 
    0x00, 0x70, 0x0d, 0x33, 0x5b, 0x1c, 0x49, 0xd1,
    0xe6, 0x37, 0x1e, 0x22, 0xd4, 0xa0, 0x17, 0x6d,
    0x0e, 0x34, 0x09, 0x19, 0x1b, 0x28, 0x46, 0x3c,
    0x38, 0xaf, 0x43, 0x34, 0x99, 0x43, 0x72, 0x57 };

static const uint8_t key_rotation_test_target_poly[] = {
    0x00, 0x70, 0x0d, 0x33, 0x5b, 0x1c, 0x49, 0xd1,
    0xe6, 0x37, 0x1e, 0x22, 0xd4, 0xa0, 0x17, 0x6d,
    0x0e, 0x34, 0x09, 0x19, 0x1b, 0x28, 0x46, 0x3c,
    0x38, 0xaf, 0x43, 0x34, 0x99, 0x43, 0x72, 0x57 };

static const uint8_t * key_rotation_test_target[] = {
    key_rotation_test_target_sha384, key_rotation_test_target_sha256,
    key_rotation_test_target_poly,
    NULL };

static const size_t key_rotation_test_target_size[] = {
    sizeof(key_rotation_test_target_sha384), sizeof(key_rotation_test_target_sha256),
    sizeof(key_rotation_test_target_poly),
    0 };

int key_rotation_vector_test()
{
    int ret = 0;
    ptls_cipher_suite_t* key_rotation_test_suites[4] = {
        NULL, NULL, NULL, NULL };
    uint8_t new_secret[PTLS_MAX_DIGEST_SIZE];

    key_rotation_test_suites[0] = (ptls_cipher_suite_t*)picoquic_get_cipher_suite_by_id_v(PICOQUIC_AES_256_GCM_SHA384, 0);
    key_rotation_test_suites[1] = (ptls_cipher_suite_t*)picoquic_get_cipher_suite_by_id_v(PICOQUIC_AES_128_GCM_SHA256, 0);
    key_rotation_test_suites[2] = (ptls_cipher_suite_t*)picoquic_get_cipher_suite_by_id_v(PICOQUIC_CHACHA20_POLY1305_SHA256, 0);
    key_rotation_test_suites[3] = NULL;

    memcpy(new_secret, key_rotation_test_init, PTLS_MAX_DIGEST_SIZE);

    for (int i = 0; ret == 0 && key_rotation_test_suites[i] != NULL; i++) {
        memset(new_secret, 0, sizeof(new_secret));
        memcpy(new_secret, key_rotation_test_init, key_rotation_test_suites[i]->hash->digest_size);
        /* TODO: update to use the test vector of draft 25 and up */
        ret = picoquic_rotate_app_secret(key_rotation_test_suites[i], new_secret, PICOQUIC_LABEL_V1_TRAFFIC_UPDATE);
        if (ret != 0) {
            DBG_PRINTF("Cannot rotate secret[%d], ret=%x\n", i, ret);
        }
        else if (key_rotation_test_suites[i]->hash->digest_size != key_rotation_test_target_size[i]) {
            DBG_PRINTF("Wrong size for secret[%d], %d vs %d\n", i, (int) key_rotation_test_suites[i]->hash->digest_size, 
                (int) key_rotation_test_target_size[i]);
            ret = -1;
        }
        else if (memcmp(new_secret, key_rotation_test_target[i], key_rotation_test_target_size[i]) != 0) {
            DBG_PRINTF("Values don't match for secret[%d]\n", i);
            ret = -1;
        }
    }

    return ret;
}

/* Retry protection test vector */

#define RETRY_PROTECTION_FIRST_BYTE 0xF5
#define RETRY_PROTECTION_VERSION 0xFF,0,0,25
#define RETRY_PROTECTION_TEST_ODCID_LENGTH 8
#define RETRY_PROTECTION_TEST_ODCID_BYTES 81,82,83,84,85,86,87,88
#define RETRY_PROTECTION_TEST_DCID_LENGTH 6
#define RETRY_PROTECTION_TEST_DCID_BYTES 61,62,63,64,65,66
#define RETRY_PROTECTION_TEST_SCID_LENGTH 4
#define RETRY_PROTECTION_TEST_SCID_BYTES 44,45,46,47
#define RETRY_PROTECTION_TEST_RETRY_TOKEN_LENGTH 24
#define RETRY_PROTECTION_TEST_RETRY_TOKEN 101,102,103,104,105,106,107,108,109,110,111,112,113,114,115,116,117,118,119,120,121,122,123,124

static uint8_t retry_protection_test_input[] = {
    RETRY_PROTECTION_FIRST_BYTE,
    RETRY_PROTECTION_VERSION,
    RETRY_PROTECTION_TEST_DCID_LENGTH,
    RETRY_PROTECTION_TEST_DCID_BYTES,
    RETRY_PROTECTION_TEST_SCID_LENGTH,
    RETRY_PROTECTION_TEST_SCID_BYTES,
    RETRY_PROTECTION_TEST_RETRY_TOKEN
};

static picoquic_connection_id_t retry_protection_test_odcid = { {RETRY_PROTECTION_TEST_ODCID_BYTES}, RETRY_PROTECTION_TEST_ODCID_LENGTH };

static uint8_t retry_protection_pseudo_packet[] = {
    RETRY_PROTECTION_TEST_ODCID_LENGTH,
    RETRY_PROTECTION_TEST_ODCID_BYTES,
    RETRY_PROTECTION_FIRST_BYTE,
    RETRY_PROTECTION_VERSION,
    RETRY_PROTECTION_TEST_DCID_LENGTH,
    RETRY_PROTECTION_TEST_DCID_BYTES,
    RETRY_PROTECTION_TEST_SCID_LENGTH,
    RETRY_PROTECTION_TEST_SCID_BYTES,
    RETRY_PROTECTION_TEST_RETRY_TOKEN
};
static uint8_t retry_protection_test_iv[12] = {
    0x4d, 0x16, 0x11, 0xd0, 0x55, 0x13, 0xa5, 0x52, 0xc5, 0x87, 0xd5, 0x75
};

static uint8_t retry_protection_test_checksum[16] = {
    0xf9, 0x50, 0xf8, 0x85, 0x71, 0x4b, 0xae, 0x7a, 0xf1, 0xe2, 0x86, 0x7d, 0xd8, 0xf7, 0x83, 0x92 };


static picoquic_connection_id_t retry_protection_odcid_draft25 = {
    { 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 }, 8 };

static uint8_t retry_protection_packet_draft25[36] = {
    0xff, 0xff, 0x00, 0x00, 0x19, 0x00, 0x08, 0xf0, 0x67, 0xa5, 0x50, 0x2a, 0x42, 0x62, 0xb5, 0x74, 
    0x6f, 0x6b, 0x65, 0x6e, 0x1e, 0x5e, 0xc5, 0xb0, 0x14, 0xcb, 0xb1, 0xf0, 0xfd, 0x93, 0xdf, 0x40,
    0x48, 0xc4, 0x46, 0xa6
};


extern uint8_t picoquic_retry_protection_key_25[16];

int retry_protection_vector_test()
{
    /* First, create a protection context to test the basic mechanisms */
    int ret = 0;
    void* protection_ctx = picoquic_create_retry_protection_context(1, picoquic_retry_protection_key_25, PICOQUIC_LABEL_QUIC_V1_KEY_BASE);

    if (protection_ctx == NULL) {
        DBG_PRINTF("%s", "Cannot create protection context!");
        ret = -1;
    }
    else if (0 != cleartext_iv_cmp(protection_ctx, retry_protection_test_iv, sizeof(retry_protection_test_iv))) {
        DBG_PRINTF("%s", "Clear protection IV does not match expected value.\n");
            ret = -1;
    } 
    else {
        uint8_t encoded[256];
        size_t encoded_length = picoquic_aead_encrypt_generic(encoded, encoded, 0, 0, retry_protection_pseudo_packet, sizeof(retry_protection_pseudo_packet), protection_ctx);

        if (encoded_length != 16) {
            DBG_PRINTF("Encoded length = %d instead of 16", (int)encoded_length);
            ret = -1;
        }
        else if (memcmp(encoded, retry_protection_test_checksum, 16) != 0) {
            DBG_PRINTF("%s", "Test vector does not match!");
            ret = -1;
        }

        picoquic_aead_free(protection_ctx);

        if (ret == 0) {
            void* verification_ctx = picoquic_create_retry_protection_context(0, picoquic_retry_protection_key_25, PICOQUIC_LABEL_QUIC_V1_KEY_BASE);
            if (verification_ctx == NULL) {
                DBG_PRINTF("%s", "Cannot create verification context!");
                ret = -1;
            }
            else if (0 != cleartext_iv_cmp(verification_ctx, retry_protection_test_iv, sizeof(retry_protection_test_iv))) {
                DBG_PRINTF("%s", "Clear verification IV does not match expected value.\n");
                    ret = -1;
            }
            else {
                uint8_t decoded[256];
                size_t decoded_length = picoquic_aead_decrypt_generic(decoded, encoded, encoded_length, 0, retry_protection_pseudo_packet, sizeof(retry_protection_pseudo_packet), verification_ctx);

                if (decoded_length != 0) {
                    DBG_PRINTF("Decoded length = %d instead of 0", (int)decoded_length);
                    ret = -1;
                }
                else {
                    /* Positive test succeeded, now do a negative test */
                    encoded[0] ^= 1;
                    decoded_length = picoquic_aead_decrypt_generic(decoded, encoded, encoded_length, 0, retry_protection_pseudo_packet, sizeof(retry_protection_pseudo_packet), verification_ctx);
                    if (decoded_length == 0) {
                        DBG_PRINTF("Decoded length = 0 instead of expected error", (int)decoded_length);
                        ret = -1;
                    }
                }

                picoquic_aead_free(verification_ctx);
            }
        }
    }

    if (ret == 0) {
        /* Test the verification functions */
        void* protection_ctx = picoquic_create_retry_protection_context(1, picoquic_retry_protection_key_25, PICOQUIC_LABEL_QUIC_V1_KEY_BASE);
        uint8_t packet[PICOQUIC_MAX_PACKET_SIZE];
        size_t packet_index = sizeof(retry_protection_test_input);

        if (protection_ctx == NULL) {
            DBG_PRINTF("%s", "Cannot create protection context!");
            ret = -1;
        }
        else {
            size_t length;
            memcpy(packet, retry_protection_test_input, packet_index);

            length = picoquic_encode_retry_protection(protection_ctx, packet, PICOQUIC_MAX_PACKET_SIZE, packet_index, &retry_protection_test_odcid);

            if (length != packet_index + sizeof(retry_protection_test_checksum)) {
                DBG_PRINTF("Packet length = %d instead of %d+16", (int)length, (int)packet_index);
                ret = -1;
            }
            else if (memcmp(packet + packet_index, retry_protection_test_checksum, sizeof(retry_protection_test_checksum)) != 0) {
                DBG_PRINTF("%s", "Packet checksum does not match!");
                ret = -1;
            }
            
            picoquic_aead_free(protection_ctx);

            if (ret == 0) {
                void* verification_ctx = picoquic_create_retry_protection_context(0, picoquic_retry_protection_key_25, PICOQUIC_LABEL_QUIC_V1_KEY_BASE);
                if (verification_ctx == NULL) {
                    DBG_PRINTF("%s", "Cannot create verification context!");
                    ret = -1;
                }
                else {
                    size_t data_length = length;
                    size_t bytes_index = sizeof(retry_protection_test_input) - RETRY_PROTECTION_TEST_RETRY_TOKEN_LENGTH;

                    ret = picoquic_verify_retry_protection(verification_ctx, packet, &data_length, bytes_index, &retry_protection_test_odcid);

                    if (ret != 0) {
                        DBG_PRINTF("Verification returns %d (0x%d)!", ret, ret);
                    }
                    else if (data_length != sizeof(retry_protection_test_input)) {
                        DBG_PRINTF("Verification returns length %d instead of %d!", (int)data_length, (int)sizeof(retry_protection_test_input));
                        ret = -1;
                    }

                    if (ret == 0) {
                        /* Try verification with a different odcid. It should fail */
                        picoquic_connection_id_t bad_odcid = retry_protection_test_odcid;
                        bad_odcid.id[0] ^= 1;
                        data_length = length;
                        if (picoquic_verify_retry_protection(verification_ctx, packet, &data_length, bytes_index, &bad_odcid) == 0) {
                            DBG_PRINTF("%s", "Bad odcid not detected!");
                            ret = -1;
                        }
                    }


                    if (ret == 0) {
                        /* Verify that the draft 25 vector passes */
                        data_length = sizeof(retry_protection_packet_draft25);
                        memcpy(packet, retry_protection_packet_draft25, data_length);
                        bytes_index = data_length - RETRY_PROTECTION_TEST_RETRY_TOKEN_LENGTH;

                        ret = picoquic_verify_retry_protection(verification_ctx, packet, &data_length, bytes_index, &retry_protection_odcid_draft25);

                        if (ret != 0) {
                            DBG_PRINTF("Testing vector in draft 25 returns %d (0x%x)!", ret, ret);
                        }
                    }

                    picoquic_aead_free(verification_ctx);
                }
            }
        }
    }

    return ret;
}

/* Implement test vector for retry protection V2 */
const picoquic_connection_id_t v2_sample_odcid = {
    { 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 }, 8 };
const uint8_t v2_sample_retry[] = {
    0xcf, 0x6b, 0x33, 0x43, 0xcf, 0x00, 0x08, 0xf0,
    0x67, 0xa5, 0x50, 0x2a, 0x42, 0x62, 0xb5, 0x74,
    0x6f, 0x6b, 0x65, 0x6e, 0xc8, 0x64, 0x6c, 0xe8,
    0xbf, 0xe3, 0x39, 0x52, 0xd9, 0x55, 0x54, 0x36,
    0x65, 0xdc, 0xc7, 0xb6};

int retry_protection_v2_test()
{
    int ret = 0;
    void* protection_ctx_v2 = NULL;

    /* Create a simple protection context from the V2 parameters */
    for (size_t i = 0; i < picoquic_nb_supported_versions; i++) {
        if (picoquic_supported_versions[i].version == PICOQUIC_V2_VERSION) {
            protection_ctx_v2 = picoquic_create_retry_protection_context(1,
                picoquic_supported_versions[i].version_retry_key,
                picoquic_supported_versions[i].tls_prefix_label);
            break;
        }
    }

    if (protection_ctx_v2 == NULL) {
        DBG_PRINTF("%s", "Cannot create protection context!");
        ret = -1;
    }
    else{ 
        uint8_t bytes[PICOQUIC_MAX_PACKET_SIZE] = { 0 };
        size_t byte_index = sizeof(v2_sample_retry) - 16;
        /* Copy the first bytes of the retry sample to the buffer */
        memcpy(bytes, v2_sample_retry, byte_index);
        /* Generate the signature */
        byte_index = picoquic_encode_retry_protection(protection_ctx_v2, bytes, PICOQUIC_MAX_PACKET_SIZE, byte_index, &v2_sample_odcid);
        /* Compare result and expectation */
        if (byte_index != sizeof(v2_sample_retry)) {
            DBG_PRINTF("Wrong retry packet size, expected %zu, got %zu", sizeof(v2_sample_retry), byte_index);
            ret = -1;
        }
        else if (memcmp(bytes, v2_sample_retry, byte_index) != 0) {
            DBG_PRINTF("%s", "Wrong retry packet value");
            ret = -1;
        }

        picoquic_aead_free(protection_ctx_v2);
    }

    return ret;
}