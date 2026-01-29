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

/* Test of the CID generation function.
 */
#define CID_ENCRYPTION_KEY 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16

#define NB_LB_CONFIG_TEST 58

picoquic_load_balancer_config_t cid_for_lb_test_config[NB_LB_CONFIG_TEST] = {
    {
        picoquic_load_balancer_cid_clear,
        0,
        0,
        3,
        0,
        8,
        0x0123,
        { 0 }
    },
    {
        picoquic_load_balancer_cid_stream_cipher,
        2,
        0,
        4,
        8,
        13,
        0x2345,
        { CID_ENCRYPTION_KEY }
    },
    {
        picoquic_load_balancer_cid_block_cipher,
        2,
        0,
        2,
        0,
        17,
        0x3456,
        { CID_ENCRYPTION_KEY }
    },
    // LB configuration : cr_bits 0x0 length_self_encoding : y sid_len 1
    {
        /* cid 01be sid be su */
        picoquic_load_balancer_cid_clear,
        0,
        1,
        1,
        0,
        2,
        0xbe,
        { 0 }
    },
    {
        /* cid 0221b7 sid 21 su b7 */
        picoquic_load_balancer_cid_clear,
        0,
        1,
        1,
        0,
        3,
        0x21,
        { 0 }
    },
    {
        /* cid 03cadfd8 sid ca su dfd8 */
        picoquic_load_balancer_cid_clear,
        0,
        1,
        1,
        0,
        4,
        0xca,
        { 0 }
    },
    {
        /* cid 041e0c9328 sid 1e su 0c9328 */
        picoquic_load_balancer_cid_clear,
        0,
        1,
        1,
        0,
        5,
        0x1e,
        { 0 }
    },
    {
        /* cid 050c8f6d9129 sid 0c su 8f6d9129 */
        picoquic_load_balancer_cid_clear,
        0,
        1,
        1,
        0,
        6,
        0x0c,
        { 0 }
    },
    /* LB configuration : cr_bits 0x0 length_self_encoding : n sid_len 2 */
    {
        /* cid 02aab0 sid aab0 su */
        picoquic_load_balancer_cid_clear,
        0,
        0,
        2,
        0,
        3,
        0xaab0,
        { 0 }
    },
    {
        /* cid 3ac4b106 sid c4b1 su 06 */
        picoquic_load_balancer_cid_clear,
        0,
        0,
        2,
        0,
        4,
        0xc4b1,
        { 0 }
    },
    {
        /* cid 08bd3cf4a0 sid bd3c su f4a0 */
        picoquic_load_balancer_cid_clear,
        0,
        0,
        2,
        0,
        5,
        0xbd3c,
        { 0 }
    },
    {
        /* cid 3771d59502d6 sid 71d5 su 9502d6 */
        picoquic_load_balancer_cid_clear,
        0,
        0,
        2,
        0,
        6,
        0x71d5,
        { 0 }
    },
    {
        /* cid 1d57dee8b888f3 sid 57de su e8b888f3 */
        picoquic_load_balancer_cid_clear,
        0,
        0,
        2,
        0,
        7,
        0x57de,
        { 0 }
    },
    /* LB configuration : cr_bits 0x0 length_self_encoding : y sid_len 3 */
    {
        /* cid 0336c976 sid 36c976 su */
        picoquic_load_balancer_cid_clear,
        0,
        1,
        3,
        0,
        4,
        0x36c976,
        { 0 }
    },
    {
        /* cid 04aa291806 sid aa2918 su 06 */
        picoquic_load_balancer_cid_clear,
        0,
        1,
        3,
        0,
        5,
        0xaa2918,
        { 0 }
    },
    {
        /* cid 0586897bd8b6 sid 86897b su d8b6 */
        picoquic_load_balancer_cid_clear,
        0,
        1,
        3,
        0,
        6,
        0x86897b,
        { 0 }
    },
    {
        /* cid 063625bcae4de0 sid 3625bc su ae4de0 */
        picoquic_load_balancer_cid_clear,
        0,
        1,
        3,
        0,
        7,
        0x3625bc,
        { 0 }
    },
    {
        /* cid 07966fb1f3cb535f sid 966fb1 su f3cb535f */
        picoquic_load_balancer_cid_clear,
        0,
        1,
        3,
        0,
        8,
        0x966fb1,
        { 0 }
    },
    /* LB configuration : cr_bits 0x0 length_self_encoding : n sid_len 4 */
    {
        /* cid 185172fab8 sid 5172fab8 su */
        picoquic_load_balancer_cid_clear,
        0,
        0,
        4,
        0,
        5,
        0x5172fab8,
        { 0 }
    },
    {
        /* cid 2eb7ff2c9297 sid b7ff2c92 su 97 */
        picoquic_load_balancer_cid_clear,
        0,
        0,
        4,
        0,
        6,
        0xb7ff2c92,
        { 0 }
    },
    {
        /* cid 14f3eb3dd3edbe sid f3eb3dd3 su edbe */
        picoquic_load_balancer_cid_clear,
        0,
        0,
        4,
        0,
        7,
        0xf3eb3dd3,
        { 0 }
    },
    {
        /* cid 3feb31cece744b74 sid eb31cece su 744b74 */
        picoquic_load_balancer_cid_clear,
        0,
        0,
        4,
        0,
        8,
        0xeb31cece,
        { 0 }
    },
    {
        /* cid 06b9f34c353ce23bb5 sid b9f34c35 su 3ce23bb5 */
        picoquic_load_balancer_cid_clear,
        0,
        0,
        4,
        0,
        9,
        0xb9f34c35,
        { 0 }
    },
    /* LB configuration : cr_bits 0x0 length_self_encoding : y sid_len 5 */
    {
        /* cid 05bdcd8d0b1d sid bdcd8d0b1d su */
        picoquic_load_balancer_cid_clear,
        0,
        1,
        5,
        0,
        6,
        0xbdcd8d0b1d,
        { 0 }
    },
    {
        /* cid 06aee673725a63 sid aee673725a su 63 */
        picoquic_load_balancer_cid_clear,
        0,
        1,
        5,
        0,
        7,
        0xaee673725a,
        { 0 }
    },
    {
        /* cid 07bbf338ddbf37f4 sid bbf338ddbf su 37f4 */
        picoquic_load_balancer_cid_clear,
        0,
        1,
        5,
        0,
        8,
        0xbbf338ddbf,
        { 0 }
    },
    {
        /* cid 08fbbca64c26756840 sid fbbca64c26 su 756840 */
        picoquic_load_balancer_cid_clear,
        0,
        1,
        5,
        0,
        9,
        0xfbbca64c26,
        { 0 }
    },
    {
        /* cid 09e7737c495b93894e34 sid e7737c495b su 93894e34 */
        picoquic_load_balancer_cid_clear,
        0,
        1,
        5,
        0,
        10,
        0xe7737c495b,
        { 0 }
    },
    /* Test vectors, stream cipher */
    /* LB configuration : cr_bits 0x0 length_self_encoding : y nonce_len 12 sid_len 1
       key 4d9d0fd25a25e7f321ef464e13f9fa3d */
    {
        /* cid 0d69fe8ab8293680395ae256e89c sid c5 su */
        picoquic_load_balancer_cid_stream_cipher,
        0,
        1,
        1,
        12,
        14,
        0xc5,
        { 0x4d, 0x9d, 0x0f, 0xd2, 0x5a, 0x25, 0xe7, 0xf3, 0x21, 0xef, 0x46, 0x4e, 0x13, 0xf9, 0xfa, 0x3d }
    },
    {
        /* cid 0e420d74ed99b985e10f5073f43027 sid d5 su 27 */
        picoquic_load_balancer_cid_stream_cipher,
        0,
        1,
        1,
        12,
        15,
        0xd5,
        { 0x4d, 0x9d, 0x0f, 0xd2, 0x5a, 0x25, 0xe7, 0xf3, 0x21, 0xef, 0x46, 0x4e, 0x13, 0xf9, 0xfa, 0x3d }
    },
    {
        /* cid 0f380f440c6eefd3142ee776f6c16027 sid 10 su 6027 */
        picoquic_load_balancer_cid_stream_cipher,
        0,
        1,
        1,
        12,
        16,
        0x10,
        { 0x4d, 0x9d, 0x0f, 0xd2, 0x5a, 0x25, 0xe7, 0xf3, 0x21, 0xef, 0x46, 0x4e, 0x13, 0xf9, 0xfa, 0x3d }
    },
    {
        /* cid 1020607efbe82049ddbf3a7c3d9d32604d sid 3c su 32604d */
        picoquic_load_balancer_cid_stream_cipher,
        0,
        1,
        1,
        12,
        17,
        0x3c,
        { 0x4d, 0x9d, 0x0f, 0xd2, 0x5a, 0x25, 0xe7, 0xf3, 0x21, 0xef, 0x46, 0x4e, 0x13, 0xf9, 0xfa, 0x3d }
    },
    {
        /* cid 11e132d12606a1bb0fa17e1caef00ec54c10 sid e3 su 0ec54c10 */
        picoquic_load_balancer_cid_stream_cipher,
        0,
        1,
        1,
        12,
        18,
        0xe3,
        { 0x4d, 0x9d, 0x0f, 0xd2, 0x5a, 0x25, 0xe7, 0xf3, 0x21, 0xef, 0x46, 0x4e, 0x13, 0xf9, 0xfa, 0x3d }
    },
    
    /* LB configuration : cr_bits 0x0 length_self_encoding : n nonce_len 12 sid_len 2
    key 49e1cec7fd264b1f4af37413baf8ada9 */

    /* cid 3d3a5e1126414271cc8dc2ec7c8c15 sid f7fe su */
    /* cid 007042539e7c5f139ac2adfbf54ba748 sid eaf4 su 48 */
    /* cid 2bc125dd2aed2aafacf59855d99e029217 sid e880 su 9217 */
    /* cid 3be6728dc082802d9862c6c8e4dda3d984d8 sid 62c6 su d984d8 */
    /* cid 1afe9c6259ad350fc7bad28e0aeb2e8d4d4742 sid 8502 su 8d4d4742 */

    /* LB configuration : cr_bits 0x0 length_self_encoding : y nonce_len 14 sid_len 3
    key 2c70df0b399bd33a7335523dcdb884ad */

    /* cid 11d62e8670565cd30b552edff6782ff5a740 sid d794bb su */
    /* cid 12c70e481f49363cabd9370d1fd5012c12bca5 sid 2cbd5d su a5 */
    /* cid 133b95dfd8ad93566782f8424df82458069fc9e9 sid d126cd su c9e9 */
    /* cid 13ac6ffcd635532ab60370306c7ee572d6b6e795 sid 539e42 su e795 */
    /* cid 1383ed07a9700777ff450bb39bb9c1981266805c sid 9094dd su 805c */

    /* LB configuration : cr_bits 0x0 length_self_encoding : n nonce_len 12 sid_len 4
    key 2297b8a95c776cf9c048b76d9dc27019 */

    /* cid 32873890c3059ca62628089439c44c1f84 sid 7398d8ca su */
    /* cid 1ff7c7d7b9823954b178636c99a7dc93ac83 sid 9655f091 su 83 */
    /* cid 31044000a5ebb3bf2fa7629a17f2c78b077c17 sid 8b035fc6 su 7c17 */
    /* cid 1791bd28c66721e8fea0c6f34fd2d8e663a6ef70 sid 6672e0e2 su a6ef70 */
    /* cid 3df1d90ad5ccd5f8f475f040e90aeca09ec9839d sid b98b1fff su c9839d */

    /* LB configuration : cr_bits 0x0 length_self_encoding : y nonce_len 8 sid_len 5
    key 484b2ed942d9f4765e45035da3340423 */

    /* cid 0da995b7537db605bfd3a38881ae sid 391a7840dc su */
    /* cid 0ed8d02d55b91d06443540d1bf6e98 sid 10f7f7b284 su 98 */
    /* cid 0f3f74be6d46a84ccb1fd1ee92cdeaf2 sid 0606918fc0 su eaf2 */
    /* cid 1045626dbf20e03050837633cc5650f97c sid e505eea637 su 50f97c */
    /* cid 11bb9a17f691ab446a938427febbeb593eaa sid 99343a2a96 su eb593eaa */

    /* Test vectors, block cipher */
    /* LB configuration: cr_bits 0x0 length_self_encoding: y sid_len 1
    key 411592e4160268398386af84ea7505d4 */
    {
        /* cid 10564f7c0df399f6d93bdddb1a03886f25 sid 23 su 05231748a80884ed58007847eb9fd0 */
        picoquic_load_balancer_cid_block_cipher,
        0,
        1,
        1,
        0,
        17,
        0x23,
        { 0x41, 0x15, 0x92, 0xe4, 0x16, 0x02, 0x68, 0x39, 0x83, 0x86, 0xaf, 0x84, 0xea, 0x75, 0x05, 0xd4 }
    },
    {
        /* cid 10d5c03f9dd765d73b3d8610b244f74d02 sid 15 su 76cd6b6f0d3f0b20fc8e633e3a05f3 */
        picoquic_load_balancer_cid_block_cipher,
        0,
        1,
        1,
        0,
        17,
        0x15,
        { 0x41, 0x15, 0x92, 0xe4, 0x16, 0x02, 0x68, 0x39, 0x83, 0x86, 0xaf, 0x84, 0xea, 0x75, 0x05, 0xd4 }
    },
    {
        /* cid 108ca55228ab23b92845341344a2f956f2 sid 64 su 65c0ce170a9548717498b537cb8790 */
        picoquic_load_balancer_cid_block_cipher,
        0,
        1,
        1,
        0,
        17,
        0x64,
        { 0x41, 0x15, 0x92, 0xe4, 0x16, 0x02, 0x68, 0x39, 0x83, 0x86, 0xaf, 0x84, 0xea, 0x75, 0x05, 0xd4 }
    },
    {
        /* cid 10e73f3d034aef2f6f501e3a7693d6270a sid 07 su f9ad10c84cc1e89a2492221d74e707 */
        picoquic_load_balancer_cid_block_cipher,
        0,
        1,
        1,
        0,
        17,
        0x07,
        { 0x41, 0x15, 0x92, 0xe4, 0x16, 0x02, 0x68, 0x39, 0x83, 0x86, 0xaf, 0x84, 0xea, 0x75, 0x05, 0xd4 }
    },
    {
        /* cid 101a6ce13d48b14a77ecfd365595ad2582 sid 6c su 76ce4689b0745b956ef71c2608045d */
        picoquic_load_balancer_cid_block_cipher,
        0,
        1,
        1,
        0,
        17,
        0x6c,
        { 0x41, 0x15, 0x92, 0xe4, 0x16, 0x02, 0x68, 0x39, 0x83, 0x86, 0xaf, 0x84, 0xea, 0x75, 0x05, 0xd4 }
    },
    /* LB configuration: cr_bits 0x0 length_self_encoding: n sid_len 2
    key 92ce44aecd636aeeff78da691ef48f77 */
    {
        /* cid 20aa09bc65ed52b1ccd29feb7ef995d318 sid a52f su 99278b92a86694ff0ecd64bc2f73 */
        picoquic_load_balancer_cid_block_cipher,
        0,
        0,
        2,
        0,
        17,
        0xa52f,
        { 0x92, 0xce, 0x44, 0xae, 0xcd, 0x63, 0x6a, 0xee, 0xff, 0x78, 0xda, 0x69, 0x1e, 0xf4, 0x8f, 0x77 }
    },
    {
        /* cid 30b8dbef657bd78a2f870e93f9485d5211 sid 6c49 su 7381c8657a388b4e9594297afe96 */
        picoquic_load_balancer_cid_block_cipher,
        0,
        0,
        2,
        0,
        17,
        0x6c49,
        { 0x92, 0xce, 0x44, 0xae, 0xcd, 0x63, 0x6a, 0xee, 0xff, 0x78, 0xda, 0x69, 0x1e, 0xf4, 0x8f, 0x77 }
    },
    {
        /* cid 043a8137331eacd2e78383279b202b9a6d sid 4188 su 5ac4b0e0b95f4e7473b49ee2d0dd */
        picoquic_load_balancer_cid_block_cipher,
        0,
        0,
        2,
        0,
        17,
        0x4188,
        { 0x92, 0xce, 0x44, 0xae, 0xcd, 0x63, 0x6a, 0xee, 0xff, 0x78, 0xda, 0x69, 0x1e, 0xf4, 0x8f, 0x77 }
    },
    {
        /* cid 3ba71ea2bcf0ab95719ab59d3d7fde770d sid 8ccc su 08728807605db25f2ca88be08e0f */
        picoquic_load_balancer_cid_block_cipher,
        0,
        0,
        2,
        0,
        17,
        0x8ccc,
        { 0x92, 0xce, 0x44, 0xae, 0xcd, 0x63, 0x6a, 0xee, 0xff, 0x78, 0xda, 0x69, 0x1e, 0xf4, 0x8f, 0x77 }
    },
    {
        /* cid 37ef1956b4ec354f40dc68336a23d42b31 sid c89d su 5a3ccd1471caa0de221ad6c185c0 */
        picoquic_load_balancer_cid_block_cipher,
        0,
        0,
        2,
        0,
        17,
        0xc89d,
        { 0x92, 0xce, 0x44, 0xae, 0xcd, 0x63, 0x6a, 0xee, 0xff, 0x78, 0xda, 0x69, 0x1e, 0xf4, 0x8f, 0x77 }
    },
    /* LB configuration: cr_bits 0x0 length_self_encoding: y sid_len 3
       key 5c49cb9265efe8ae7b1d3886948b0a34 */
    {
        /* cid 10efcffc161d232d113998a49b1dbc4aa0 sid 0690b3 su 958fc9f38fe61b83881b2c5780 */
        picoquic_load_balancer_cid_block_cipher,
        0,
        1,
        3,
        0,
        17,
        0x0690b3,
        { 0x5c, 0x49, 0xcb, 0x92, 0x65, 0xef, 0xe8, 0xae, 0x7b, 0x1d, 0x38, 0x86, 0x94, 0x8b, 0x0a, 0x34 }
    },
    {
        /* cid 10fc13bdbcb414ba90e391833400c19505 sid 031ac3 su 9a55e1e1904e780346fcc32c3c */
        picoquic_load_balancer_cid_block_cipher,
        0,
        1,
        3,
        0,
        17,
        0x031ac3,
        { 0x5c, 0x49, 0xcb, 0x92, 0x65, 0xef, 0xe8, 0xae, 0x7b, 0x1d, 0x38, 0x86, 0x94, 0x8b, 0x0a, 0x34 }
    },
    {
        /* cid 10d3cc1efaf5dc52c7a0f6da2746a8c714 sid 572d3a su ff2ec9712664e7174dc03ca3f8 */
        picoquic_load_balancer_cid_block_cipher,
        0,
        1,
        3,
        0,
        17,
        0x572d3a,
        { 0x5c, 0x49, 0xcb, 0x92, 0x65, 0xef, 0xe8, 0xae, 0x7b, 0x1d, 0x38, 0x86, 0x94, 0x8b, 0x0a, 0x34 }
    },
    {
        /* cid 107edf37f6788e33c0ec7758a485215f2b sid 562c25 su 02c5a5dcbea629c3840da5f567 */
        picoquic_load_balancer_cid_block_cipher,
        0,
        1,
        3,
        0,
        17,
        0x562c25,
        { 0x5c, 0x49, 0xcb, 0x92, 0x65, 0xef, 0xe8, 0xae, 0x7b, 0x1d, 0x38, 0x86, 0x94, 0x8b, 0x0a, 0x34 }
    },
    {
        /* cid 10bc28da122582b7312e65aa096e9724fc sid 2fa4f0 su 8ae8c666bfc0fc364ebfd06b9a */
        picoquic_load_balancer_cid_block_cipher,
        0,
        1,
        3,
        0,
        17,
        0x2fa4f0,
        { 0x5c, 0x49, 0xcb, 0x92, 0x65, 0xef, 0xe8, 0xae, 0x7b, 0x1d, 0x38, 0x86, 0x94, 0x8b, 0x0a, 0x34 }
    },
    /* LB configuration: cr_bits 0x0 length_self_encoding: n sid_len 4
        key e787a3a491551fb2b4901a3fa15974f3 */
    {
        /* cid 26125351da12435615e3be6b16fad35560 sid 0cb227d3 su 65b40b1ab54e05bff55db046 */
        picoquic_load_balancer_cid_block_cipher,
        0,
        0,
        4,
        0,
        17,
        0x0cb227d3,
        { 0xe7, 0x87, 0xa3, 0xa4, 0x91, 0x55, 0x1f, 0xb2, 0xb4, 0x90, 0x1a, 0x3f, 0xa1, 0x59, 0x74, 0xf3 }
    },
    {
        /* cid 14de05fc84e41b611dfbe99ed5b1c9d563 sid 6a0f23ad su d73bee2f3a7e72b3ffea52d9 */
        picoquic_load_balancer_cid_block_cipher,
        0,
        0,
        4,
        0,
        17,
        0x6a0f23ad,
        { 0xe7, 0x87, 0xa3, 0xa4, 0x91, 0x55, 0x1f, 0xb2, 0xb4, 0x90, 0x1a, 0x3f, 0xa1, 0x59, 0x74, 0xf3 }
    },
    {
        /* cid 1306052c3f973db87de6d7904914840ff1 sid ca21402d su 5829465f7418b56ee6ada431 */
        picoquic_load_balancer_cid_block_cipher,
        0,
        0,
        4,
        0,
        17,
        0xca21402d,
        { 0xe7, 0x87, 0xa3, 0xa4, 0x91, 0x55, 0x1f, 0xb2, 0xb4, 0x90, 0x1a, 0x3f, 0xa1, 0x59, 0x74, 0xf3 }
    },
    {
        /* cid 1d202b5811af3e1dba9ea2950d27879a92 sid b14e1307 su 4902aba8b23a5f24616df3cf */
        picoquic_load_balancer_cid_block_cipher,
        0,
        0,
        4,
        0,
        17,
        0xb14e1307,
        { 0xe7, 0x87, 0xa3, 0xa4, 0x91, 0x55, 0x1f, 0xb2, 0xb4, 0x90, 0x1a, 0x3f, 0xa1, 0x59, 0x74, 0xf3 }
    },
    {
        /* cid 26538b78efc2d418539ad1de13ab73e477 sid a75e0148 su 0040323f1854e75aeb449b9f */
        picoquic_load_balancer_cid_block_cipher,
        0,
        0,
        4,
        0,
        17,
        0xa75e0148,
        { 0xe7, 0x87, 0xa3, 0xa4, 0x91, 0x55, 0x1f, 0xb2, 0xb4, 0x90, 0x1a, 0x3f, 0xa1, 0x59, 0x74, 0xf3 }
    },
    /* LB configuration: cr_bits 0x0 length_self_encoding: y sid_len 5
        key d5a6d7824336fbe0f25d28487cdda57c */
    {
        /* cid 10a2794871aadb20ddf274a95249e57fde sid 82d3b0b1a1 su 0935471478c2edb8120e60 */
        picoquic_load_balancer_cid_block_cipher,
        0,
        1,
        5,
        0,
        17,
        0x82d3b0b1a1,
        { 0xd5, 0xa6, 0xd7, 0x82, 0x43, 0x36, 0xfb, 0xe0, 0xf2, 0x5d, 0x28, 0x48, 0x7c, 0xdd, 0xa5, 0x7c }
    },
    {
        /* cid 108122fe80a6e546a285c475a3b8613ec9 sid fbcc902c9d su 59c47946882a9a93981c15 */
        picoquic_load_balancer_cid_block_cipher,
        0,
        1,
        5,
        0,
        17,
        0xfbcc902c9d,
        { 0xd5, 0xa6, 0xd7, 0x82, 0x43, 0x36, 0xfb, 0xe0, 0xf2, 0x5d, 0x28, 0x48, 0x7c, 0xdd, 0xa5, 0x7c }
    },
    {
        /* cid 104d227ad9dd0fef4c8cb6eb75887b6ccc sid 2808e22642 su 2a7ef40e2c7e17ae40b3fb */
        picoquic_load_balancer_cid_block_cipher,
        0,
        1,
        5,
        0,
        17,
        0x2808e22642,
        { 0xd5, 0xa6, 0xd7, 0x82, 0x43, 0x36, 0xfb, 0xe0, 0xf2, 0x5d, 0x28, 0x48, 0x7c, 0xdd, 0xa5, 0x7c }
    },
    {
        /* cid 10b3f367d8627b36990a28d67f50b97846 sid 5e018f0197 su 2289cae06a566e5cb6cfa4 */
        picoquic_load_balancer_cid_block_cipher,
        0,
        1,
        5,
        0,
        17,
        0x5e018f0197,
        { 0xd5, 0xa6, 0xd7, 0x82, 0x43, 0x36, 0xfb, 0xe0, 0xf2, 0x5d, 0x28, 0x48, 0x7c, 0xdd, 0xa5, 0x7c }
    },
    {
        /* cid 1024412bfe25f4547510204bdda6143814 sid 8a8dd3d036 su 4b12933a135e5eaaebc6fd */
        picoquic_load_balancer_cid_block_cipher,
        0,
        1,
        5,
        0,
        17,
        0x8a8dd3d036,
        { 0xd5, 0xa6, 0xd7, 0x82, 0x43, 0x36, 0xfb, 0xe0, 0xf2, 0x5d, 0x28, 0x48, 0x7c, 0xdd, 0xa5, 0x7c }
    },
};

picoquic_connection_id_t cid_for_lb_test_init[NB_LB_CONFIG_TEST] = {
    { { 0xC8, 0x00, 0x00, 0x00, 0x84, 0x85, 0x86, 0x87 }, 8 },
    { { 0x8b, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c }, 13},
    { { 0x57, 0x81, 0x82, 0x00, 0x00, 0x00, 0x00, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f, 0x90 }, 17 },
    /* Test vectors, clear text */
    { { 0 }, 2 }, /* cid 01be sid be su */
    { { 0 , 0, 0xb7}, 3 }, /* cid 0221b7 sid 21 su b7 */
    { { 0, 0, 0xdf, 0xd8}, 4 }, /* cid 03cadfd8 sid ca su dfd8 */
    { { 0, 0, 0x0c, 0x93, 0x28 }, 5 }, /* cid 041e0c9328 sid 1e su 0c9328 */
    { { 0, 0, 0x8f, 0x6d, 0x91, 0x29  }, 6 }, /* cid 050c8f6d9129 sid 0c su 8f6d9129 */
    { { 0x02, 0, 0}, 3 }, /* cid 02aab0 sid aab0 su */
    { { 0x3a, 0, 0, 0x06}, 4 }, /* cid 3ac4b106 sid c4b1 su 06 */
    { { 0x08, 0, 0, 0xf4, 0xa0}, 5 }, /* cid 08bd3cf4a0 sid bd3c su f4a0 */
    { { 0x37, 0, 0, 0x95, 0x02, 0xd6}, 6 }, /* cid 3771d59502d6 sid 71d5 su 9502d6  */
    { { 0x1d, 0, 0, 0xe8, 0xb8, 0x88, 0xf3}, 7 }, /* cid 1d57dee8b888f3 sid 57de su e8b888f3 */
    { { 0, 0, 0, 0}, 4 }, /* cid 0336c976 sid 36c976 su */
    { { 0, 0, 0, 0, 0x06}, 5 }, /* cid 04aa291806 sid aa2918 su 06 */
    { { 0, 0, 0, 0, 0xd8, 0xb6}, 6 }, /* cid 0586897bd8b6 sid 86897b su d8b6 */
    { { 0, 0, 0, 0, 0xae, 0x4d, 0xe0}, 7 }, /* cid 063625bcae4de0 sid 3625bc su ae4de0 */
    { { 0, 0, 0, 0, 0xf3, 0xcb, 0x53, 0x5f}, 8 }, /* cid 07966fb1f3cb535f sid 966fb1 su f3cb535f */
    { { 0x18, 0, 0, 0, 0}, 5 }, /* cid 185172fab8 sid 5172fab8 su */
    { { 0x2e, 0, 0, 0, 0, 0x97}, 6 }, /* cid 2eb7ff2c9297 sid b7ff2c92 su 97 */
    { { 0x14, 0, 0, 0, 0, 0xed, 0xbe}, 7 }, /* cid 14f3eb3dd3edbe sid f3eb3dd3 su edbe */
    { { 0x3f, 0, 0, 0, 0, 0x74, 0x4b, 0x74}, 8 }, /* cid 3feb31cece744b74 sid eb31cece su 744b74 */
    { { 0x06, 0, 0, 0, 0, 0x3c, 0xe2, 0x3b, 0xb5}, 9 }, /* cid 06b9f34c353ce23bb5 sid b9f34c35 su 3ce23bb5 */
    { { 0x3f, 0, 0, 0, 0, 0}, 6 }, /* cid 05bdcd8d0b1d sid bdcd8d0b1d su */
    { { 0, 0, 0, 0, 0, 0, 0x63}, 7 }, /* cid 06aee673725a63 sid aee673725a su 63 */
    { { 0, 0, 0, 0, 0, 0, 0x37, 0xf4}, 8 }, /* cid 07bbf338ddbf37f4 sid bbf338ddbf su 37f4 */
    { { 0, 0, 0, 0, 0, 0, 0x75, 0x68, 0x40}, 9 }, /* cid 08fbbca64c26756840 sid fbbca64c26 su 756840 */
    { { 0, 0, 0, 0, 0, 0, 0x93, 0x89, 0x4e, 0x34}, 10 }, /* cid 09e7737c495b93894e34 sid e7737c495b su 93894e34 */
    /* Test vectors, stream cipher */
    /* cid 0d69fe8ab8293680395ae256e89c sid c5 su */
    { { 0x0d, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, 14 },
    /* cid 0e420d74ed99b985e10f5073f43027 sid d5 su 27 */
    { { 0x0e, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x27}, 15 },
    /* cid 0f380f440c6eefd3142ee776f6c16027 sid 10 su 6027 */
    { { 0x0f, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x60, 0x27}, 16 },
    /* cid 1020607efbe82049ddbf3a7c3d9d32604d sid 3c su 32604d */
    { { 0x10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x32, 0x60, 0x4d}, 17 },
    /* cid 11e132d12606a1bb0fa17e1caef00ec54c10 sid e3 su 0ec54c10 */
    { { 0x11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x0e, 0xc5, 0x4c, 0x10}, 18 },
    
    /* Test vectors, block cipher */
    /* cid 10564f7c0df399f6d93bdddb1a03886f25 sid 23 su 05231748a80884ed58007847eb9fd0 */
    { { 0, 0, 0x05, 0x23, 0x17, 0x48, 0xa8, 0x08, 0x84, 0xed, 0x58, 0x00, 0x78, 0x47, 0xeb, 0x9f, 0xd0}, 17 },
    /* cid 10d5c03f9dd765d73b3d8610b244f74d02 sid 15 su 76cd6b6f0d3f0b20fc8e633e3a05f3 */
    { { 0, 0, 0x76, 0xcd, 0x6b, 0x6f, 0x0d, 0x3f, 0x0b, 0x20, 0xfc, 0x8e, 0x63, 0x3e, 0x3a, 0x05, 0xf3}, 17 },
    /* cid 108ca55228ab23b92845341344a2f956f2 sid 64 su 65c0ce170a9548717498b537cb8790 */
    { { 0, 0, 0x65, 0xc0, 0xce, 0x17, 0x0a, 0x95, 0x48, 0x71, 0x74, 0x98, 0xb5, 0x37, 0xcb, 0x87, 0x90}, 17 },
    /* cid 10e73f3d034aef2f6f501e3a7693d6270a sid 07 su f9ad10c84cc1e89a2492221d74e707 */
    { { 0, 0, 0xf9, 0xad, 0x10, 0xc8, 0x4c, 0xc1, 0xe8, 0x9a, 0x24, 0x92, 0x22, 0x1d, 0x74, 0xe7, 0x07}, 17 },
    /* cid 101a6ce13d48b14a77ecfd365595ad2582 sid 6c su 76ce4689b0745b956ef71c2608045d */
    { { 0, 0, 0x76, 0xce, 0x46, 0x89, 0xb0, 0x74, 0x5b, 0x95, 0x6e, 0xf7, 0x1c, 0x26, 0x08, 0x04, 0x5d}, 17 },
    /* cid 20aa09bc65ed52b1ccd29feb7ef995d318 sid a52f su 99278b92a86694ff0ecd64bc2f73 */
    { { 0x20, 0, 0, 0x99, 0x27, 0x8b, 0x92, 0xa8, 0x66, 0x94, 0xff, 0x0e, 0xcd, 0x64, 0xbc, 0x2f, 0x73}, 17 },
    /* cid 30b8dbef657bd78a2f870e93f9485d5211 sid 6c49 su 7381c8657a388b4e9594297afe96 */
    { { 0x30, 0, 0, 0x73, 0x81, 0xc8, 0x65, 0x7a, 0x38, 0x8b, 0x4e, 0x95, 0x94, 0x29, 0x7a, 0xfe, 0x96}, 17 },
    /* cid 043a8137331eacd2e78383279b202b9a6d sid 4188 su 5ac4b0e0b95f4e7473b49ee2d0dd */
    { { 0x04, 0, 0, 0x5a, 0xc4, 0xb0, 0xe0, 0xb9, 0x5f, 0x4e, 0x74, 0x73, 0xb4, 0x9e, 0xe2, 0xd0, 0xdd}, 17 },
    /* cid 3ba71ea2bcf0ab95719ab59d3d7fde770d sid 8ccc su 08728807605db25f2ca88be08e0f */
    { { 0x3b, 0, 0, 0x08, 0x72, 0x88, 0x07, 0x60, 0x5d, 0xb2, 0x5f, 0x2c, 0xa8, 0x8b, 0xe0, 0x8e, 0x0f}, 17 },
    /* cid 37ef1956b4ec354f40dc68336a23d42b31 sid c89d su 5a3ccd1471caa0de221ad6c185c0 */
    { { 0x37, 0, 0, 0x5a, 0x3c, 0xcd, 0x14, 0x71, 0xca, 0xa0, 0xde, 0x22, 0x1a, 0xd6, 0xc1, 0x85, 0xc0}, 17 },
    /* cid 10efcffc161d232d113998a49b1dbc4aa0 sid 0690b3 su 958fc9f38fe61b83881b2c5780 */
    { { 0, 0, 0, 0, 0x95, 0x8f, 0xc9, 0xf3, 0x8f, 0xe6, 0x1b, 0x83, 0x88, 0x1b, 0x2c, 0x57, 0x80}, 17 },
    /* cid 10fc13bdbcb414ba90e391833400c19505 sid 031ac3 su 9a55e1e1904e780346fcc32c3c */
    { { 0, 0, 0, 0, 0x9a, 0x55, 0xe1, 0xe1, 0x90, 0x4e, 0x78, 0x03, 0x46, 0xfc, 0xc3, 0x2c, 0x3c}, 17 },
    /* cid 10d3cc1efaf5dc52c7a0f6da2746a8c714 sid 572d3a su ff2ec9712664e7174dc03ca3f8 */
    { { 0, 0, 0, 0, 0xff, 0x2e, 0xc9, 0x71, 0x26, 0x64, 0xe7, 0x17, 0x4d, 0xc0, 0x3c, 0xa3, 0xf8}, 17 },
    /* cid 107edf37f6788e33c0ec7758a485215f2b sid 562c25 su 02c5a5dcbea629c3840da5f567 */
    { { 0, 0, 0, 0, 0x02, 0xc5, 0xa5, 0xdc, 0xbe, 0xa6, 0x29, 0xc3, 0x84, 0x0d, 0xa5, 0xf5, 0x67}, 17 },
    /* cid 10bc28da122582b7312e65aa096e9724fc sid 2fa4f0 su 8ae8c666bfc0fc364ebfd06b9a */
    { { 0, 0, 0, 0, 0x8a, 0xe8, 0xc6, 0x66, 0xbf, 0xc0, 0xfc, 0x36, 0x4e, 0xbf, 0xd0, 0x6b, 0x9a}, 17 },
    /* cid 26125351da12435615e3be6b16fad35560 sid 0cb227d3 su 65b40b1ab54e05bff55db046 */
    { { 0x26, 0, 0, 0, 0, 0x65, 0xb4, 0x0b, 0x1a, 0xb5, 0x4e, 0x05, 0xbf, 0xf5, 0x5d, 0xb0, 0x46}, 17 },
    /* cid 14de05fc84e41b611dfbe99ed5b1c9d563 sid 6a0f23ad su d73bee2f3a7e72b3ffea52d9 */
    { { 0x14, 0, 0, 0, 0, 0xd7, 0x3b, 0xee, 0x2f, 0x3a, 0x7e, 0x72, 0xb3, 0xff, 0xea, 0x52, 0xd9}, 17 },
    /* cid 1306052c3f973db87de6d7904914840ff1 sid ca21402d su 5829465f7418b56ee6ada431 */
    { { 0x13, 0, 0, 0, 0, 0x58, 0x29, 0x46, 0x5f, 0x74, 0x18, 0xb5, 0x6e, 0xe6, 0xad, 0xa4, 0x31}, 17 },
    /* cid 1d202b5811af3e1dba9ea2950d27879a92 sid b14e1307 su 4902aba8b23a5f24616df3cf */
    { { 0x1d, 0, 0, 0, 0, 0x49, 0x02, 0xab, 0xa8, 0xb2, 0x3a, 0x5f, 0x24, 0x61, 0x6d, 0xf3, 0xcf}, 17 },
    /* cid 26538b78efc2d418539ad1de13ab73e477 sid a75e0148 su 0040323f1854e75aeb449b9f */
    { { 0x26, 0, 0, 0, 0, 0x00, 0x40, 0x32, 0x3f, 0x18, 0x54, 0xe7, 0x5a, 0xeb, 0x44, 0x9b, 0x9f}, 17 },
    /* cid 10a2794871aadb20ddf274a95249e57fde sid 82d3b0b1a1 su 0935471478c2edb8120e60 */
    { { 0, 0, 0, 0, 0, 0, 0x09, 0x35, 0x47, 0x14, 0x78, 0xc2, 0xed, 0xb8, 0x12, 0x0e, 0x60}, 17 },
    /* cid 108122fe80a6e546a285c475a3b8613ec9 sid fbcc902c9d su 59c47946882a9a93981c15 */
    { { 0, 0, 0, 0, 0, 0, 0x59, 0xc4, 0x79, 0x46, 0x88, 0x2a, 0x9a, 0x93, 0x98, 0x1c, 0x15}, 17 },
    /* cid 104d227ad9dd0fef4c8cb6eb75887b6ccc sid 2808e22642 su 2a7ef40e2c7e17ae40b3fb */
    { { 0, 0, 0, 0, 0, 0, 0x2a, 0x7e, 0xf4, 0x0e, 0x2c, 0x7e, 0x17, 0xae, 0x40, 0xb3, 0xfb}, 17 },
    /* cid 10b3f367d8627b36990a28d67f50b97846 sid 5e018f0197 su 2289cae06a566e5cb6cfa4 */
    { { 0, 0, 0, 0, 0, 0, 0x22, 0x89, 0xca, 0xe0, 0x6a, 0x56, 0x6e, 0x5c, 0xb6, 0xcf, 0xa4}, 17 },
    /* cid 1024412bfe25f4547510204bdda6143814 sid 8a8dd3d036 su 4b12933a135e5eaaebc6fd */
    { { 0, 0, 0, 0, 0, 0, 0x4b, 0x12, 0x93, 0x3a, 0x13, 0x5e, 0x5e, 0xaa, 0xeb, 0xc6, 0xfd}, 17 },
};

picoquic_connection_id_t cid_for_lb_test_ref[NB_LB_CONFIG_TEST] = {
    { { 0x08, 0x00, 0x01, 0x23, 0x84, 0x85, 0x86, 0x87 }, 8 },
    { { 0x8b, 0x7b, 0x37, 0xbe, 0x1c, 0x7c, 0xe2, 0x62, 0x28, 0x66, 0xd9, 0xf1, 0x7a }, 13},
    { { 0x97, 0x42, 0xa4, 0x35, 0x97, 0x2b, 0xfc, 0x60, 0x51, 0x69, 0x1d, 0x28, 0x1a, 0x65, 0x13, 0xcf, 0x4a }, 17 },
    /* Test vectors, clear text */
    { { 0x01, 0xbe}, 2 }, /* cid 01be sid be su */
    { { 0x02, 0x21, 0xb7}, 3 }, /* cid 0221b7 sid 21 su b7 */
    { { 0x03, 0xca, 0xdf, 0xd8}, 4 }, /* cid 03cadfd8 sid ca su dfd8 */
    { { 0x04, 0x1e, 0x0c, 0x93, 0x28 }, 5 }, /* cid 041e0c9328 sid 1e su 0c9328 */
    { { 0x05, 0x0c, 0x8f, 0x6d, 0x91, 0x29  }, 6 }, /* cid 050c8f6d9129 sid 0c su 8f6d9129 */
    { { 0x02, 0xaa, 0xb0}, 3 }, /* cid 02aab0 sid aab0 su */
    { { 0x3a, 0xc4, 0xb1, 0x06}, 4 }, /* cid 3ac4b106 sid c4b1 su 06 */
    { { 0x08, 0xbd, 0x3c, 0xf4, 0xa0}, 5 }, /* cid 08bd3cf4a0 sid bd3c su f4a0 */
    { { 0x37, 0x71, 0xd5, 0x95, 0x02, 0xd6}, 6 }, /* cid 3771d59502d6 sid 71d5 su 9502d6  */
    { { 0x1d, 0x57, 0xde, 0xe8, 0xb8, 0x88, 0xf3}, 7 }, /* cid 1d57dee8b888f3 sid 57de su e8b888f3 */
    { { 0x03, 0x36, 0xc9, 0x76}, 4 }, /* cid 0336c976 sid 36c976 su */
    { { 0x04, 0xaa, 0x29, 0x18, 0x06}, 5 }, /* cid 04aa291806 sid aa2918 su 06 */
    { { 0x05, 0x86, 0x89, 0x7b, 0xd8, 0xb6}, 6 }, /* cid 0586897bd8b6 sid 86897b su d8b6 */
    { { 0x06, 0x36, 0x25, 0xbc, 0xae, 0x4d, 0xe0}, 7 }, /* cid 063625bcae4de0 sid 3625bc su ae4de0 */
    { { 0x07, 0x96, 0x6f, 0xb1, 0xf3, 0xcb, 0x53, 0x5f}, 8 }, /* cid 07966fb1f3cb535f sid 966fb1 su f3cb535f */
    { { 0x18, 0x51, 0x72, 0xfa, 0xb8}, 5 }, /* cid 185172fab8 sid 5172fab8 su */
    { { 0x2e, 0xb7, 0xff, 0x2c, 0x92, 0x97}, 6 }, /* cid 2eb7ff2c9297 sid b7ff2c92 su 97 */
    { { 0x14, 0xf3, 0xeb, 0x3d, 0xd3, 0xed, 0xbe}, 7 }, /* cid 14f3eb3dd3edbe sid f3eb3dd3 su edbe */
    { { 0x3f, 0xeb, 0x31, 0xce, 0xce, 0x74, 0x4b, 0x74}, 8 }, /* cid 3feb31cece744b74 sid eb31cece su 744b74 */
    { { 0x06, 0xb9, 0xf3, 0x4c, 0x35, 0x3c, 0xe2, 0x3b, 0xb5}, 9 }, /* cid 06b9f34c353ce23bb5 sid b9f34c35 su 3ce23bb5 */
    { { 0x05, 0xbd, 0xcd, 0x8d, 0x0b, 0x1d}, 6 }, /* cid 05bdcd8d0b1d sid bdcd8d0b1d su */
    { { 0x06, 0xae, 0xe6, 0x73, 0x72, 0x5a, 0x63}, 7 }, /* cid 06aee673725a63 sid aee673725a su 63 */
    { { 0x07, 0xbb, 0xf3, 0x38, 0xdd, 0xbf, 0x37, 0xf4}, 8 }, /* cid 07bbf338ddbf37f4 sid bbf338ddbf su 37f4 */
    { { 0x08, 0xfb, 0xbc, 0xa6, 0x4c, 0x26, 0x75, 0x68, 0x40}, 9 }, /* cid 08fbbca64c26756840 sid fbbca64c26 su 756840 */
    { { 0x09, 0xe7, 0x73, 0x7c, 0x49, 0x5b, 0x93, 0x89, 0x4e, 0x34}, 10 }, /* cid 09e7737c495b93894e34 sid e7737c495b su 93894e34 */
    /* Test vectors, stream cipher */
    /* cid 0d69fe8ab8293680395ae256e89c sid c5 su */
    { { 0x0d, 0x69, 0xfe, 0x8a, 0xb8, 0x29, 0x36, 0x80, 0x39, 0x5a, 0xe2, 0x56, 0xe8, 0x9c}, 14 },
    /* cid 0e420d74ed99b985e10f5073f43027 sid d5 su 27 */
    { { 0x0e, 0x42, 0x0d, 0x74, 0xed, 0x99, 0xb9, 0x85, 0xe1, 0x0f, 0x50, 0x73, 0xf4, 0x30, 0x27}, 15 },
    /* cid 0f380f440c6eefd3142ee776f6c16027 sid 10 su 6027 */
    { { 0x0f, 0x38, 0x0f, 0x44, 0x0c, 0x6e, 0xef, 0xd3, 0x14, 0x2e, 0xe7, 0x76, 0xf6, 0xc1, 0x60, 0x27}, 16 },
    /* cid 1020607efbe82049ddbf3a7c3d9d32604d sid 3c su 32604d */
    { { 0x10, 0x20, 0x60, 0x7e, 0xfb, 0xe8, 0x20, 0x49, 0xdd, 0xbf, 0x3a, 0x7c, 0x3d, 0x9d, 0x32, 0x60, 0x4d}, 17 },
    /* cid 11e132d12606a1bb0fa17e1caef00ec54c10 sid e3 su 0ec54c10 */
    { { 0x11, 0xe1, 0x32, 0xd1, 0x26, 0x06, 0xa1, 0xbb, 0x0f, 0xa1, 0x7e, 0x1c, 0xae, 0xf0, 0x0e, 0xc5, 0x4c, 0x10}, 18 },

    /* Test vectors, block cipher */
    /* cid 10564f7c0df399f6d93bdddb1a03886f25 sid 23 su 05231748a80884ed58007847eb9fd0 */
    { { 0x10, 0x56, 0x4f, 0x7c, 0x0d, 0xf3, 0x99, 0xf6, 0xd9, 0x3b, 0xdd, 0xdb, 0x1a, 0x03, 0x88, 0x6f, 0x25}, 17 },
    /* cid 10d5c03f9dd765d73b3d8610b244f74d02 sid 15 su 76cd6b6f0d3f0b20fc8e633e3a05f3 */
    { { 0x10, 0xd5, 0xc0, 0x3f, 0x9d, 0xd7, 0x65, 0xd7, 0x3b, 0x3d, 0x86, 0x10, 0xb2, 0x44, 0xf7, 0x4d, 0x02}, 17 },
    /* cid 108ca55228ab23b92845341344a2f956f2 sid 64 su 65c0ce170a9548717498b537cb8790 */
    { { 0x10, 0x8c, 0xa5, 0x52, 0x28, 0xab, 0x23, 0xb9, 0x28, 0x45, 0x34, 0x13, 0x44, 0xa2, 0xf9, 0x56, 0xf2}, 17 },
    /* cid 10e73f3d034aef2f6f501e3a7693d6270a sid 07 su f9ad10c84cc1e89a2492221d74e707 */
    { { 0x10, 0xe7, 0x3f, 0x3d, 0x03, 0x4a, 0xef, 0x2f, 0x6f, 0x50, 0x1e, 0x3a, 0x76, 0x93, 0xd6, 0x27, 0x0a}, 17 },
    /* cid 101a6ce13d48b14a77ecfd365595ad2582 sid 6c su 76ce4689b0745b956ef71c2608045d */
    { { 0x10, 0x1a, 0x6c, 0xe1, 0x3d, 0x48, 0xb1, 0x4a, 0x77, 0xec, 0xfd, 0x36, 0x55, 0x95, 0xad, 0x25, 0x82}, 17 },
    /* cid 20aa09bc65ed52b1ccd29feb7ef995d318 sid a52f su 99278b92a86694ff0ecd64bc2f73 */
    { { 0x20, 0xaa, 0x09, 0xbc, 0x65, 0xed, 0x52, 0xb1, 0xcc, 0xd2, 0x9f, 0xeb, 0x7e, 0xf9, 0x95, 0xd3, 0x18}, 17 },
    /* cid 30b8dbef657bd78a2f870e93f9485d5211 sid 6c49 su 7381c8657a388b4e9594297afe96 */
    { { 0x30, 0xb8, 0xdb, 0xef, 0x65, 0x7b, 0xd7, 0x8a, 0x2f, 0x87, 0x0e, 0x93, 0xf9, 0x48, 0x5d, 0x52, 0x11}, 17 },
    /* cid 043a8137331eacd2e78383279b202b9a6d sid 4188 su 5ac4b0e0b95f4e7473b49ee2d0dd */
    { { 0x04, 0x3a, 0x81, 0x37, 0x33, 0x1e, 0xac, 0xd2, 0xe7, 0x83, 0x83, 0x27, 0x9b, 0x20, 0x2b, 0x9a, 0x6d}, 17 },
    /* cid 3ba71ea2bcf0ab95719ab59d3d7fde770d sid 8ccc su 08728807605db25f2ca88be08e0f */
    { { 0x3b, 0xa7, 0x1e, 0xa2, 0xbc, 0xf0, 0xab, 0x95, 0x71, 0x9a, 0xb5, 0x9d, 0x3d, 0x7f, 0xde, 0x77, 0x0d}, 17 },
    /* cid 37ef1956b4ec354f40dc68336a23d42b31 sid c89d su 5a3ccd1471caa0de221ad6c185c0 */
    { { 0x37, 0xef, 0x19, 0x56, 0xb4, 0xec, 0x35, 0x4f, 0x40, 0xdc, 0x68, 0x33, 0x6a, 0x23, 0xd4, 0x2b, 0x31}, 17 },
    /* cid 10efcffc161d232d113998a49b1dbc4aa0 sid 0690b3 su 958fc9f38fe61b83881b2c5780 */
    { { 0x10, 0xef, 0xcf, 0xfc, 0x16, 0x1d, 0x23, 0x2d, 0x11, 0x39, 0x98, 0xa4, 0x9b, 0x1d, 0xbc, 0x4a, 0xa0}, 17 },
    /* cid 10fc13bdbcb414ba90e391833400c19505 sid 031ac3 su 9a55e1e1904e780346fcc32c3c */
    { { 0x10, 0xfc, 0x13, 0xbd, 0xbc, 0xb4, 0x14, 0xba, 0x90, 0xe3, 0x91, 0x83, 0x34, 0x00, 0xc1, 0x95, 0x05}, 17 },
    /* cid 10d3cc1efaf5dc52c7a0f6da2746a8c714 sid 572d3a su ff2ec9712664e7174dc03ca3f8 */
    { { 0x10, 0xd3, 0xcc, 0x1e, 0xfa, 0xf5, 0xdc, 0x52, 0xc7, 0xa0, 0xf6, 0xda, 0x27, 0x46, 0xa8, 0xc7, 0x14}, 17 },
    /* cid 107edf37f6788e33c0ec7758a485215f2b sid 562c25 su 02c5a5dcbea629c3840da5f567 */
    { { 0x10, 0x7e, 0xdf, 0x37, 0xf6, 0x78, 0x8e, 0x33, 0xc0, 0xec, 0x77, 0x58, 0xa4, 0x85, 0x21, 0x5f, 0x2b}, 17 },
    /* cid 10bc28da122582b7312e65aa096e9724fc sid 2fa4f0 su 8ae8c666bfc0fc364ebfd06b9a */
    { { 0x10, 0xbc, 0x28, 0xda, 0x12, 0x25, 0x82, 0xb7, 0x31, 0x2e, 0x65, 0xaa, 0x09, 0x6e, 0x97, 0x24, 0xfc}, 17 },
    /* cid 26125351da12435615e3be6b16fad35560 sid 0cb227d3 su 65b40b1ab54e05bff55db046 */
    { { 0x26, 0x12, 0x53, 0x51, 0xda, 0x12, 0x43, 0x56, 0x15, 0xe3, 0xbe, 0x6b, 0x16, 0xfa, 0xd3, 0x55, 0x60}, 17 },
    /* cid 14de05fc84e41b611dfbe99ed5b1c9d563 sid 6a0f23ad su d73bee2f3a7e72b3ffea52d9 */
    { { 0x14, 0xde, 0x05, 0xfc, 0x84, 0xe4, 0x1b, 0x61, 0x1d, 0xfb, 0xe9, 0x9e, 0xd5, 0xb1, 0xc9, 0xd5, 0x63}, 17 },
    /* cid 1306052c3f973db87de6d7904914840ff1 sid ca21402d su 5829465f7418b56ee6ada431 */
    { { 0x13, 0x06, 0x05, 0x2c, 0x3f, 0x97, 0x3d, 0xb8, 0x7d, 0xe6, 0xd7, 0x90, 0x49, 0x14, 0x84, 0x0f, 0xf1}, 17 },
    /* cid 1d202b5811af3e1dba9ea2950d27879a92 sid b14e1307 su 4902aba8b23a5f24616df3cf */
    { { 0x1d, 0x20, 0x2b, 0x58, 0x11, 0xaf, 0x3e, 0x1d, 0xba, 0x9e, 0xa2, 0x95, 0x0d, 0x27, 0x87, 0x9a, 0x92}, 17 },
    /* cid 26538b78efc2d418539ad1de13ab73e477 sid a75e0148 su 0040323f1854e75aeb449b9f */
    { { 0x26, 0x53, 0x8b, 0x78, 0xef, 0xc2, 0xd4, 0x18, 0x53, 0x9a, 0xd1, 0xde, 0x13, 0xab, 0x73, 0xe4, 0x77}, 17 },
    /* cid 10a2794871aadb20ddf274a95249e57fde sid 82d3b0b1a1 su 0935471478c2edb8120e60 */
    { { 0x10, 0xa2, 0x79, 0x48, 0x71, 0xaa, 0xdb, 0x20, 0xdd, 0xf2, 0x74, 0xa9, 0x52, 0x49, 0xe5, 0x7f, 0xde}, 17 },
    /* cid 108122fe80a6e546a285c475a3b8613ec9 sid fbcc902c9d su 59c47946882a9a93981c15 */
    { { 0x10, 0x81, 0x22, 0xfe, 0x80, 0xa6, 0xe5, 0x46, 0xa2, 0x85, 0xc4, 0x75, 0xa3, 0xb8, 0x61, 0x3e, 0xc9}, 17 },
    /* cid 104d227ad9dd0fef4c8cb6eb75887b6ccc sid 2808e22642 su 2a7ef40e2c7e17ae40b3fb */
    { { 0x10, 0x4d, 0x22, 0x7a, 0xd9, 0xdd, 0x0f, 0xef, 0x4c, 0x8c, 0xb6, 0xeb, 0x75, 0x88, 0x7b, 0x6c, 0xcc}, 17 },
    /* cid 10b3f367d8627b36990a28d67f50b97846 sid 5e018f0197 su 2289cae06a566e5cb6cfa4 */
    { { 0x10, 0xb3, 0xf3, 0x67, 0xd8, 0x62, 0x7b, 0x36, 0x99, 0x0a, 0x28, 0xd6, 0x7f, 0x50, 0xb9, 0x78, 0x46}, 17 },
    /* cid 1024412bfe25f4547510204bdda6143814 sid 8a8dd3d036 su 4b12933a135e5eaaebc6fd */
    { { 0x10, 0x24, 0x41, 0x2b, 0xfe, 0x25, 0xf4, 0x54, 0x75, 0x10, 0x20, 0x4b, 0xdd, 0xa6, 0x14, 0x38, 0x14}, 17 },
};

int cid_for_lb_test_one(picoquic_quic_t* quic, int test_id, picoquic_load_balancer_config_t* config,
    picoquic_connection_id_t* init_cid, picoquic_connection_id_t* target_cid)
{
    int ret = 0;
    picoquic_connection_id_t result;

    /* Configure the policy */
    ret = picoquic_lb_compat_cid_config(quic, config);

    if (ret != 0) {
        DBG_PRINTF("CID test #%d fails, could not configure the context.\n", test_id);
    }
    else {
        /* Create a CID. */
        result = *init_cid;

        if (quic->cnx_id_callback_fn) {
            quic->cnx_id_callback_fn(quic, picoquic_null_connection_id, picoquic_null_connection_id,
                quic->cnx_id_callback_ctx, &result);
        }

        if (picoquic_compare_connection_id(&result, target_cid) != 0) {
            DBG_PRINTF("CID test #%d fails, result does not match.\n", test_id);
            ret = -1;
        }
        else {
            uint64_t server_id64 = picoquic_lb_compat_cid_verify(quic, quic->cnx_id_callback_ctx, &result);

            if (server_id64 != config->server_id64) {
                DBG_PRINTF("CID test #%d fails, server id decode to %" PRIu64 " instead of %" PRIu64,
                    test_id, server_id64, config->server_id64);
                ret = -1;
            }
        }
    }

    /* Free the configured policy */
    picoquic_lb_compat_cid_config_free(quic);

    return ret;
}


int cid_for_lb_test()
{
    int ret = 0;
    uint64_t simulated_time = 0;
    picoquic_quic_t* quic = picoquic_create(8, NULL, NULL, NULL, NULL, NULL,
        NULL, NULL, NULL, NULL, simulated_time,
        &simulated_time, NULL, NULL, 0);

    if (quic == NULL) {
        DBG_PRINTF("%s", "Could not create the quic context.");
    }
    else {
        for (int i = 0; i < NB_LB_CONFIG_TEST && ret == 0; i++) {
            ret = cid_for_lb_test_one(quic, i, &cid_for_lb_test_config[i], &cid_for_lb_test_init[i], &cid_for_lb_test_ref[i]);
        }

        if (quic != NULL) {
            picoquic_free(quic);
        }
    }
    return ret;
}

/* CID for LG Tests.
 * The CLI parameter takes as input a text string that can be parsed as a LB "config" struct.
 * The test starts with a set of "Good" configurations and the corresponding value,
 * then a set of erroneous configuration, then a fuzz test to check that parsing works even in
 * presence of unsuspected errors.
 */

static picoquic_load_balancer_config_t cid_for_lb_cli_test_config[] = {
    {
        picoquic_load_balancer_cid_clear,
        0,
        0,
        3,
        0,
        8,
        0x0123,
        { 0 }
    },
    {
        picoquic_load_balancer_cid_stream_cipher,
        2,
        0,
        4,
        8,
        13,
        0x2345,
        { CID_ENCRYPTION_KEY }
    },
    {
        picoquic_load_balancer_cid_block_cipher,
        2,
        0,
        2,
        0,
        17,
        0x3456,
        { CID_ENCRYPTION_KEY }
    },
    // LB configuration : cr_bits 0x0 length_self_encoding : y sid_len 1
    {
        /* cid 01be sid be su */
        picoquic_load_balancer_cid_clear,
        0,
        1,
        1,
        0,
        2,
        0xbe,
        { 0 }
    },
    /* LB configuration : cr_bits 0x0 length_self_encoding : n sid_len 4 */
    {
        /* cid 09e7737c495b93894e34 sid e7737c495b su 93894e34 */
        picoquic_load_balancer_cid_clear,
        0,
        1,
        5,
        0,
        10,
        0xe7737c495b,
        { 0 }
    },
    /* Test vectors, stream cipher */
    /* LB configuration : cr_bits 0x0 length_self_encoding : y nonce_len 12 sid_len 1
       key 4d9d0fd25a25e7f321ef464e13f9fa3d */
    {
        /* cid 11e132d12606a1bb0fa17e1caef00ec54c10 sid e3 su 0ec54c10 */
        picoquic_load_balancer_cid_stream_cipher,
        0,
        1,
        1,
        12,
        18,
        0xe3,
        { 0x4d, 0x9d, 0x0f, 0xd2, 0x5a, 0x25, 0xe7, 0xf3, 0x21, 0xef, 0x46, 0x4e, 0x13, 0xf9, 0xfa, 0x3d }
    },
    {
        /* cid 10564f7c0df399f6d93bdddb1a03886f25 sid 23 su 05231748a80884ed58007847eb9fd0 */
        picoquic_load_balancer_cid_block_cipher,
        0,
        1,
        1,
        0,
        17,
        0x23,
        { 0x41, 0x15, 0x92, 0xe4, 0x16, 0x02, 0x68, 0x39, 0x83, 0x86, 0xaf, 0x84, 0xea, 0x75, 0x05, 0xd4 }
    },
    /* LB configuration: cr_bits 0x0 length_self_encoding: y sid_len 3
       key 5c49cb9265efe8ae7b1d3886948b0a34 */
    {
        /* cid 10d3cc1efaf5dc52c7a0f6da2746a8c714 sid 572d3a su ff2ec9712664e7174dc03ca3f8 */
        picoquic_load_balancer_cid_block_cipher,
        0,
        1,
        3,
        0,
        17,
        0x572d3a,
        { 0x5c, 0x49, 0xcb, 0x92, 0x65, 0xef, 0xe8, 0xae, 0x7b, 0x1d, 0x38, 0x86, 0x94, 0x8b, 0x0a, 0x34 }
    },
    /* LB configuration: cr_bits 0x0 length_self_encoding: y sid_len 5
        key d5a6d7824336fbe0f25d28487cdda57c */
    {
        /* cid 1024412bfe25f4547510204bdda6143814 sid 8a8dd3d036 su 4b12933a135e5eaaebc6fd */
        picoquic_load_balancer_cid_block_cipher,
        0,
        1,
        5,
        0,
        17,
        0x8a8dd3d036,
        { 0xd5, 0xa6, 0xd7, 0x82, 0x43, 0x36, 0xfb, 0xe0, 0xf2, 0x5d, 0x28, 0x48, 0x7c, 0xdd, 0xa5, 0x7c }
    },
};

static size_t nb_cid_for_lb_cli_test_config = sizeof(cid_for_lb_cli_test_config) / sizeof(picoquic_load_balancer_config_t);

static char const * cid_for_lb_test_txt[] = {
    "0N8C-000123",
    "2N13S8-00002345-0102030405060708090A0B0C0D0E0F10",
    "2n17B-3456-0102030405060708090A0B0C0D0E0F10",
    "0y2c-be",
    "0y10c-e7737c495b",
    "0Y18s12-e3-4d9d0fd25a25e7f321ef464e13f9fa3d",
    "0y17b-23-411592e4160268398386af84ea7505d4",
    "0Y17B-572d3a-5c49cb9265efe8ae7b1d3886948b0a34",
    "0Y17B-8a8dd3d036-d5a6d7824336fbe0f25d28487cdda57c"
};

static size_t nb_cid_for_lb_test_txt = sizeof(cid_for_lb_test_txt) / sizeof(char const*);

static char const* cid_for_lb_bad_txt[] = {
    "5N8C-000123",
    "2M13S8-00002345-0102030405060708090A0B0C0D0E0F10",
    "2n257b-3456-0102030405060708090A0B0C0D0E0F10",
    "0y2d-be1",
    "0y10c*e7737c495b",
    "0Y18s257-e3-4d9d0fd25a25e7f321ef464e13f9fa3d",
    "0y17b-23-411592e4160268398386af84ea7505",
    "0Y17B-572d3a-5c49cb9265efe8ae7b1d3886948b0a3",
    "0Y17B-8a8dd3d036-d5a6d7824336fbe0f25d28487cdda57cab"
};

static size_t nb_cid_for_lb_bad_txt = sizeof(cid_for_lb_bad_txt) / sizeof(char const*);

static char fuzz_c[] = { 0, 0xff, '0', '9', 'a', 'z', '-' };
static size_t nb_fuzz_c = sizeof(fuzz_c) / sizeof(char);

int cid_for_lb_cli_test()
{
    int ret = 0;
    picoquic_load_balancer_config_t config;
    char buf[256];
    size_t fuzz_res[3] = { 0, 0, 0 };

    /* Parse each of the test strings and compare to corresponding config */
    if (nb_cid_for_lb_cli_test_config != nb_cid_for_lb_test_txt) {
        ret = -1;
    }
    for (size_t i = 0; ret == 0 &&  i < nb_cid_for_lb_cli_test_config; i++) {
        size_t txt_length = strlen(cid_for_lb_test_txt[i]);
        if (picoquic_lb_compat_cid_config_parse(&config, cid_for_lb_test_txt[i], txt_length) != 0) {
            ret = -1;
        }
        else if (config.method != cid_for_lb_cli_test_config[i].method) {
            ret = -1;
        }
        else if (config.rotation_bits != cid_for_lb_cli_test_config[i].rotation_bits) {
            ret = -1;
        }
        else if (config.first_byte_encodes_length != cid_for_lb_cli_test_config[i].first_byte_encodes_length) {
            ret = -1;
        }
        else if (config.server_id_length != cid_for_lb_cli_test_config[i].server_id_length) {
            ret = -1;
        }
        else if (config.nonce_length != cid_for_lb_cli_test_config[i].nonce_length) {
            ret = -1;
        }
        else if (config.connection_id_length != cid_for_lb_cli_test_config[i].connection_id_length) {
            ret = -1;
        }
        else if (config.server_id64 != cid_for_lb_cli_test_config[i].server_id64) {
            ret = -1;
        }
        else if (memcmp(config.cid_encryption_key, cid_for_lb_cli_test_config[i].cid_encryption_key, 16) != 0){
            ret = -1;
        }
    }
    /* Parse each of the bad strings and verify an error is returned */
    for (size_t i = 0; ret == 0 && i < nb_cid_for_lb_bad_txt; i++) {
        size_t txt_length = strlen(cid_for_lb_bad_txt[i]);
        if (picoquic_lb_compat_cid_config_parse(&config, cid_for_lb_bad_txt[i], txt_length) == 0) {
            ret = -1;
        }
    }
    /* Fuzz test */
    for (size_t i = 0; ret == 0 && i < nb_cid_for_lb_cli_test_config; i++) {
        size_t txt_length = strlen(cid_for_lb_test_txt[i]);
        if (txt_length < 255) {
            fuzz_res[0] += txt_length * nb_fuzz_c;
            for (size_t f = 0; f < txt_length; f++) {
                for (size_t fu = 0; fu < nb_fuzz_c; fu++) {
                    memcpy(buf, cid_for_lb_test_txt[i], txt_length);
                    buf[txt_length] = 0;
                    buf[f] = fuzz_c[fu];

                    if (picoquic_lb_compat_cid_config_parse(&config, buf, strlen(buf)) == 0) {
                        fuzz_res[1] += 1;
                    }
                    else {
                        fuzz_res[2] += 1;
                    }
                }
            }
        }
    }
    if (ret == 0 && fuzz_res[2] == 0) {
        ret = -1;
    }
    if (ret == 0 && fuzz_res[0] != fuzz_res[1] + fuzz_res[2]) {
        ret = -1;
    }
    /* Done */
    return ret;
}