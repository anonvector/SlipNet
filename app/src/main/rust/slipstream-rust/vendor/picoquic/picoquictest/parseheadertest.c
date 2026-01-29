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

#include <stdlib.h>
#include <string.h>
#include "tls_api.h"
#include "picoquic_internal.h"
#include "picoquictest_internal.h"

/* test vectors and corresponding structure */
#define TEST_CNXID_LEN_BYTE 0x51
#define TEST_CNXID_LEN_INI 8
#define TEST_CNXID_LEN_REM 4
#define TEST_CNXID_INI_BYTES 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07
#define TEST_CNXID_INI_BYTES_ZERO 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
#define TEST_CNXID_INI_VAL {{TEST_CNXID_INI_BYTES, TEST_CNXID_INI_BYTES_ZERO}, 8}
#define TEST_CNXID_REM_BYTES 0x04, 0x05, 0x06, 0x07
#define TEST_CNXID_REM_BYTES_ZERO 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
#define TEST_CNXID_REM_VAL {{TEST_CNXID_REM_BYTES, TEST_CNXID_REM_BYTES_ZERO}, 4}
#define TEST_CNXID_NULL_VAL {{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, 0}
#define TEST_CNXID_LOCAL_BYTE 0x55
#define TEST_CNXID_LEN_LOCAL 8
#define TEST_CNXID_LOCAL_BYTES 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08
#define TEST_CNXID_LOCAL_VAL {{TEST_CNXID_LOCAL_BYTES, TEST_CNXID_INI_BYTES_ZERO}, 8}
/*
 * New definitions
 */
#define TEST_CNXID_LEN_10 8
#define TEST_CNXID_10_BYTES 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09
#define TEST_CNXID_10_VAL { { TEST_CNXID_10_BYTES, TEST_CNXID_INI_BYTES_ZERO }, 8 }

static picoquic_connection_id_t test_cnxid_ini = TEST_CNXID_INI_VAL;
static picoquic_connection_id_t test_cnxid_rem = TEST_CNXID_REM_VAL;
static picoquic_connection_id_t test_cnxid_local = TEST_CNXID_LOCAL_VAL;
static picoquic_connection_id_t test_cnxid_r10 = TEST_CNXID_10_VAL;

static uint8_t pinitial10[] = {
    0xC3,
    0x50, 0x43, 0x51, 0x30,
    TEST_CNXID_LEN_INI,
    TEST_CNXID_INI_BYTES,
    TEST_CNXID_LEN_REM,
    TEST_CNXID_REM_BYTES,
    0x00,
    0x44, 00,
    0xDE, 0xAD, 0xBE, 0xEF
};

static picoquic_packet_header hinitial10 = {
    TEST_CNXID_INI_VAL,
    TEST_CNXID_REM_VAL,
    0xDEADBEEF,
    0x50435130,
    22,
    22,
    picoquic_packet_initial,
    0xFFFFFFFF00000000ull,
    0, 
    0x400,
    0,
    0,
    picoquic_packet_context_initial,
    0,
    0,
    0,
    0,
    0,
    0,
    0
};

static uint8_t pinitial10_l[] = {
    0xC3,
    0x50, 0x43, 0x51, 0x30,
    TEST_CNXID_LEN_INI,
    TEST_CNXID_INI_BYTES,
    TEST_CNXID_LEN_LOCAL,
    TEST_CNXID_LOCAL_BYTES,
    0,
    0x44, 00,
    0xDE, 0xAD, 0xBE, 0xEF
};

static picoquic_packet_header hinitial10_l = {
    TEST_CNXID_INI_VAL,
    TEST_CNXID_LOCAL_VAL,
    0xDEADBEEF,
    0x50435130,
    26,
    26,
    picoquic_packet_initial,
    0xFFFFFFFF00000000ull,
    0,
    0x400,
    0,
    0,
    picoquic_packet_context_initial,
    0,
    0,
    0,
    0,
    0,
    0,
    0
};

static uint8_t pvnego10[] = {
    0xFF,
    0, 0, 0, 0,
    TEST_CNXID_LEN_10,
    TEST_CNXID_10_BYTES,
    TEST_CNXID_LEN_REM,
    TEST_CNXID_REM_BYTES,
    0x50, 0x43, 0x51, 0x30,
    0xFF, 0, 0, 7
};

static uint8_t pvnegobis10[] = {
    0xAA,
    0, 0, 0, 0,
    TEST_CNXID_LEN_10,
    TEST_CNXID_10_BYTES,
    TEST_CNXID_LEN_REM,
    TEST_CNXID_REM_BYTES,
    0x50, 0x43, 0x51, 0x30,
    0xFF, 0, 0, 7
};

static picoquic_packet_header hvnego10 = {
    TEST_CNXID_10_VAL,
    TEST_CNXID_REM_VAL,
    0,
    0,
    19,
    0,
    picoquic_packet_version_negotiation,
    0,
    0,
    PICOQUIC_MAX_PACKET_SIZE - 19,
    0,
    0,
    picoquic_packet_context_initial,
    0,
    0,
    0,
    0,
    0,
    0,
    0
};

static uint8_t phandshake[] = {
    0xE3,
    0x50, 0x43, 0x51, 0x30,
    TEST_CNXID_LEN_LOCAL,
    TEST_CNXID_LOCAL_BYTES,
    TEST_CNXID_LEN_REM,
    TEST_CNXID_REM_BYTES,
    0x44, 00,
    0xDE, 0xAD, 0xBE, 0xEF
};

static picoquic_packet_header hhandshake = {
    TEST_CNXID_LOCAL_VAL,
    TEST_CNXID_REM_VAL,
    0xDEADBEEF,
    0x50435130,
    21,
    21,
    picoquic_packet_handshake,
    0xFFFFFFFF00000000ull,
    0,
    0x400,
    0,
    2,
    picoquic_packet_context_handshake,
    0,
    0,
    0,
    0,
    0,
    0,
    0
};

static uint8_t packet_short_phi0_c_32[] = {
    0x43,
    TEST_CNXID_10_BYTES,
    0xDE, 0xAD, 0xBE, 0xEF
};

static picoquic_packet_header hphi0_c_32 = {
    TEST_CNXID_10_VAL,
    TEST_CNXID_NULL_VAL,
    0xDEADBEEF,
    0,
    9,
    9,
    picoquic_packet_1rtt_protected,
    0xFFFFFFFF00000000ull,
    0,
    PICOQUIC_MAX_PACKET_SIZE - 9,
    0,
    3,
    picoquic_packet_context_application,
    0,
    0,
    0,
    0,
    1,
    0,
    0
};

static uint8_t packet_short_phi0_c_32_spin[] = {
    0x63, /* Setting the spin bit */
    TEST_CNXID_10_BYTES,
    0xDE, 0xAD, 0xBE, 0xEF
};

static picoquic_packet_header hphi0_c_32_spin = {
    TEST_CNXID_10_VAL,
    TEST_CNXID_NULL_VAL,
    0xDEADBEEF,
    0,
    9,
    9,
    picoquic_packet_1rtt_protected,
    0xFFFFFFFF00000000ull,
    0,
    PICOQUIC_MAX_PACKET_SIZE - 9, 
    0,
    3,
    picoquic_packet_context_application,
    0,
    1,
    0,
    1,
    0,
    0,
    0
};

static uint8_t packet_short_phi1_noc_32[] = {
    0x47,
    0xDE, 0xAD, 0xBE, 0xEF,
};

static picoquic_packet_header hphi1_noc_32 = { 
    TEST_CNXID_NULL_VAL,
    TEST_CNXID_NULL_VAL,
    0xDEADBEEF,
    0,
    1,
    1,
    picoquic_packet_1rtt_protected,
    0xFFFFFFFF00000000ull,
    0,
    PICOQUIC_MAX_PACKET_SIZE - 1,
    0,
    3,
    picoquic_packet_context_application,
    1,
    0,
    0,
    0,
    0,
    0,
    0
};

static uint8_t packet_intel_bug[] = {
    0xc4,0x00,0x00,0x00,0x01,0x08,0xbb,0xba,0xda,0x0e,0xf9,0x26,0x00,0xc8,0x00,0x00,
    0x44,0x9e,0x19,0x55,0xc0,0x25,0x6e,0x96,0xd8,0x1d,0x8d,0x85,0xed,0xe9,0x3e,0x4b,
    0x01,0xfa,0x6b,0xc1,0xf3,0x5a,0x67,0xf3,0xbf,0xc5,0x92,0x21,0xc4,0xce,0x1d,0x46,
    0x63,0x5c,0x36,0xff,0x59,0x15,0x06,0xd0,0x8f,0xe1,0xd6,0x7c,0x15,0x9d,0x7e,0xe9,
    0x20,0xed,0xca,0x35,0x83,0x7c,0x22,0xa7,0xd6,0x5b,0x2e,0x5b,0x52,0x9d,0xe3,0xf2,
    0x7f,0x72,0xc4,0x57,0xc5,0xc3,0x3c,0x09,0x03,0x47,0x95,0xe7,0x12,0x59,0x9c,0xa5,
    0x0b,0xeb,0xd6,0x7c,0x1a,0xf4,0xfa,0x58,0x67,0x3f,0xb2,0x2e,0x8a,0xde,0xce,0x28,
    0xea,0x1f,0x44,0x4d,0x4e,0xda,0xfb,0x98,0xf8,0x3a,0x1d,0x7c,0x02,0x05,0x70,0xfe,
    0xc5,0x97,0x97,0x9d,0x7e,0x7f,0xea,0x9a,0x03,0x5e,0x6a,0x7b,0xa6,0x2c,0x16,0xd7,
    0xf9,0xef,0x98,0x75,0x05,0xaa,0xf6,0x9e,0xf7,0x43,0x4b,0xd9,0x0e,0xd0,0x5a,0x6d,
    0x7e,0x0c,0xe2,0xb9,0x7c,0x48,0x3d,0x00,0xe8,0xc6,0x3f,0x93,0xb7,0xc2,0x44,0xbf,
    0x44,0xc3,0x2c,0x51,0xef,0x99,0xaa,0x10,0x25,0x42,0xa3,0x53,0x88,0xa7,0x86,0x39,
    0x7f,0x1f,0x62,0x6c,0x31,0xb7,0xca,0xa9,0x6a,0x8b,0x44,0x31,0x58,0x2c,0x20,0x6c,
    0x94,0xa9,0x6b,0x4e,0x45,0x38,0xfb,0xc0,0x96,0xbd,0x06,0x52,0x71,0x5a,0x05,0x88,
    0x3c,0x96,0x6f,0x72,0x79,0x08,0x05,0xd9,0xab,0xb7,0xcd,0xe6,0x70,0xf7,0x95,0xd1,
    0x5d,0x9b,0x86,0xc6,0xc0,0x4b,0x89,0x47,0x15,0x30,0xb2,0x6b,0xab,0x38,0x6b,0x60,
    0x6c,0x19,0x4d,0xaa,0x28,0x6d,0xf7,0xf9,0x17,0x4a,0xc7,0x29,0xbd,0x85,0x33,0xc3,
    0xce,0x38,0x2f,0x0a,0x0f,0x11,0x9f,0x60,0x3d,0xbd,0x33,0x0c,0xcc,0xf2,0x9b,0x3c,
    0x88,0x77,0x43,0x20,0x6c,0xe5,0xcb,0x81,0x4a,0x50,0x2d,0x22,0x00,0x9c,0xa1,0x75,
    0xa8,0xc9,0x86,0x5a,0x2c,0xea,0x90,0x90,0xeb,0x70,0x0a,0x82,0x90,0x4c,0xd4,0x12,
    0x2a,0x97,0x21,0x1b,0x7e,0x46,0x56,0x5e,0x5f,0x0f,0x23,0xf0,0x50,0x18,0x11,0xcf,
    0xaf,0x7b,0x80,0xe8,0x31,0x1f,0x0c,0x13,0x66,0x97,0x1b,0x41,0x79,0x53,0x53,0xd9,
    0xb9,0xba,0xcc,0x0f,0xcd,0x31,0x76,0x7e,0x48,0x09,0x1f,0x94,0xa2,0x4e,0x59,0xe0,
    0x91,0x40,0xf2,0x01,0x97,0x08,0x07,0xcf,0x77,0x3c,0x3a,0x7c,0x7a,0xf2,0x12,0xda,
    0x8a,0x5c,0xf3,0xae,0xf5,0x4c,0x2a,0x92,0x24,0xe9,0x06,0x8d,0x7b,0x25,0x69,0xd0,
    0xa6,0xd6,0xf8,0xa2,0x1c,0xcb,0x2c,0xa9,0xa6,0xc8,0xa2,0x95,0xac,0x07,0x93,0xf7,
    0x1b,0x0e,0x08,0x5c,0x8a,0xd0,0xeb,0x59,0x10,0x5f,0x15,0xca,0xed,0x16,0xf7,0xb5,
    0x17,0x1f,0x42,0x6e,0x9b,0xe6,0x25,0x38,0xa2,0xcd,0xf0,0x32,0x56,0x53,0x48,0xe9,
    0x77,0xe2,0xd1,0xdf,0x25,0x03,0xb0,0x53,0x72,0xc8,0x77,0x85,0x1f,0xa1,0x8f,0x60,
    0x20,0x42,0xc7,0xe1,0x51,0x57,0x1e,0x5f,0xa7,0xdc,0xa4,0xb7,0xc1,0xb8,0x2e,0x90,
    0x15,0xea,0x8b,0x3c,0x91,0x44,0x3a,0x4d,0x7d,0x0c,0xc2,0x43,0x54,0x05,0xfc,0xff,
    0xbe,0x66,0x83,0xfc,0x5d,0xf3,0xf3,0x92,0xe7,0xab,0xf6,0x6a,0x5c,0xb0,0x93,0x0a,
    0xe7,0x81,0x24,0x5a,0xed,0x37,0x69,0xcf,0x5a,0xfe,0x06,0x12,0xb7,0x00,0x0f,0x56,
    0x71,0xe5,0xac,0x54,0x86,0x3e,0xfb,0x48,0x00,0x84,0x3b,0x53,0x10,0xcd,0x05,0x92,
    0x03,0xc0,0x79,0xc5,0x59,0x9f,0xed,0x3e,0xa6,0x7c,0xfb,0x60,0xf3,0xed,0x7d,0x1f,
    0x47,0xa4,0x38,0x2f,0x6d,0xc5,0x62,0x26,0x8d,0x9e,0x50,0x38,0xc6,0x5c,0x83,0x22,
    0x19,0xfb,0x64,0xff,0x48,0x55,0x86,0x84,0xc8,0x53,0xaa,0xaf,0x7b,0x9c,0x6c,0xb0,
    0xca,0x60,0xf2,0xb8,0x76,0xeb,0x68,0x41,0x94,0x8c,0x46,0x55,0x02,0x16,0xdb,0xae,
    0xc7,0x44,0xd2,0x37,0xa0,0xa3,0x1d,0x27,0x37,0xb8,0xc7,0x01,0xe0,0x21,0x33,0xf3,
    0xca,0xe6,0x8f,0xb5,0x49,0x4b,0x4a,0xf5,0x95,0x54,0x0b,0xcb,0x6b,0x7f,0xfa,0x2a,
    0xc5,0x11,0xa8,0x72,0x2d,0x58,0x6c,0x15,0x11,0xab,0x8b,0xd2,0xb4,0x59,0x75,0xa5,
    0xe8,0x74,0x9f,0x58,0x7a,0x97,0x57,0x73,0xb6,0xb1,0x34,0x30,0xfe,0x6f,0x70,0x1d,
    0xf7,0x0b,0x67,0x6b,0x93,0x6d,0x9b,0x5e,0xc6,0x64,0xa3,0xae,0xe2,0x54,0x18,0x34,
    0xda,0xde,0x09,0xab,0x2f,0x64,0xd4,0xf2,0xa0,0x09,0x81,0xaa,0x52,0x2e,0xba,0x87,
    0xcf,0x35,0x36,0x49,0x57,0x22,0x95,0x5b,0x86,0x2b,0x07,0xa0,0x31,0x08,0xfe,0x56,
    0x5f,0x9a,0x19,0x63,0xc6,0x01,0x63,0x25,0xc1,0xf8,0xd1,0x1c,0xbd,0xd9,0xf4,0x5e,
    0x12,0x79,0xef,0xaa,0x1e,0xca,0xea,0xb8,0x25,0xf1,0x26,0x12,0x6a,0x12,0x44,0xb7,
    0x1d,0xcb,0x45,0xa6,0x8c,0xe6,0x1e,0x38,0x77,0x0b,0x02,0x03,0x4d,0xcc,0x38,0x17,
    0x58,0x21,0xd5,0xd7,0x00,0x9c,0x58,0xea,0xa7,0x4f,0xa6,0xc0,0xe7,0x50,0xc8,0xdd,
    0xa9,0x47,0xf2,0x56,0x56,0xaa,0x9e,0x91,0x75,0x61,0xb0,0x60,0x1f,0x2a,0x2d,0xd8,
    0x81,0xcc,0x22,0x82,0xc3,0xf6,0x14,0xa1,0xa4,0xa5,0x89,0x89,0xe1,0xa3,0x57,0xe3,
    0xec,0x38,0xe4,0x9a,0x51,0x00,0xe7,0xbf,0x86,0xe3,0x46,0x7d,0x65,0x81,0xba,0x40,
    0x54,0xdc,0xd8,0xc3,0x26,0x86,0xe3,0x89,0xb7,0x05,0x61,0xd4,0xa9,0xed,0x78,0x26,
    0xd3,0x8c,0xa2,0xc2,0x5a,0xd6,0xc5,0xc1,0xb3,0x47,0x1c,0xd8,0x93,0xa8,0x02,0xc6,
    0x87,0xb2,0x87,0x60,0x39,0x63,0xf6,0x88,0xc8,0xf4,0x62,0xfc,0x17,0xc8,0x0f,0xbc,
    0x00,0x8d,0x98,0x08,0x6f,0xb8,0x9a,0x88,0x05,0xb1,0xd8,0x55,0x26,0xd5,0x14,0xfb,
    0xef,0x59,0x29,0x9e,0x20,0x87,0x28,0xcc,0x29,0x48,0xd2,0x95,0x38,0x66,0xcb,0xb2,
    0x92,0x50,0x84,0xab,0xd4,0x6f,0x91,0x67,0x70,0x80,0x2b,0x5f,0xab,0x9a,0xda,0xad,
    0xe8,0xd0,0x62,0x0f,0xec,0x34,0x1a,0x64,0xc0,0x5d,0xe3,0xa5,0x2f,0xef,0x6f,0x97,
    0x94,0x43,0xba,0x69,0x8c,0x15,0x73,0x5c,0x0b,0x4c,0x0f,0xc1,0x69,0xcc,0x11,0x5c,
    0xcc,0x43,0x37,0xff,0x1a,0x5d,0xbf,0x5c,0xb1,0x05,0x2d,0xee,0x81,0xf1,0x22,0x5c,
    0x82,0xdd,0xed,0x65,0x95,0xbe,0xa8,0x8b,0x64,0xdb,0xbb,0x82,0xf2,0x01,0xeb,0xcb,
    0xb1,0x31,0x59,0x2c,0x1e,0x53,0xc7,0x22,0x5e,0x1c,0x82,0xfd,0x8f,0xe2,0x74,0xc4,
    0x54,0xf4,0x3e,0x72,0xbe,0x93,0x1b,0x17,0x90,0xc8,0x61,0xa5,0xbb,0x97,0xf6,0x85,
    0xf3,0x88,0x1b,0xa2,0xbf,0xe3,0x2b,0x5c,0x47,0x28,0xbd,0x0f,0xad,0x27,0x4f,0xe2,
    0x89,0x8d,0x1b,0xaa,0x23,0x5c,0x03,0xa3,0xd8,0x82,0x5c,0x6c,0x2d,0xfd,0x76,0xf4,
    0xe8,0xdc,0xc6,0xdc,0x1f,0x32,0x94,0x9e,0x9d,0x6e,0x28,0xbd,0x48,0xa3,0x18,0x03,
    0x66,0x61,0x03,0x9f,0x40,0x44,0x69,0xa0,0x4e,0x2d,0xea,0x96,0xc3,0xb1,0x23,0x11,
    0xdc,0xf0,0xe2,0xde,0x4e,0xfd,0x18,0xbf,0xdb,0x86,0x4c,0xae,0xd5,0xaa,0x17,0x13,
    0x0c,0x0a,0xce,0x61,0xee,0x9d,0x75,0xfa,0xc9,0x58,0xa5,0xa7,0x14,0x8c,0x4e,0x94,
    0xc2,0xb0,0xc8,0x4e,0x8d,0x58,0xc9,0xe6,0x2c,0x9f,0x37,0x12,0x6f,0xd3,0x68,0x8c,
    0xbe,0xdb,0x83,0x11,0x14,0xcd,0x44,0xeb,0x84,0xb3,0xce,0x36,0x6e,0xa1,0x70,0x42,
    0x7e,0xb0,0x90,0x94,0x56,0x45,0x06,0x8d,0x62,0x76,0x65,0x59,0xa9,0x46,0xef,0xde,
    0xa3,0xb8,0x2f,0x33,0x01,0x1d,0xd7,0x4a,0xb9,0x25,0xae,0xe9,0x5e,0x40,0xf9,0xf7,
    0x1e,0x64,0x40,0xbe,0x66,0xbf,0xb9,0xfb,0xe8,0x25,0x5b,0x36,0x3f,0x05,0x0a,0x57
};


#define TEST_CNXID_INTEL_BUG {{ 187, 186, 218, 14, 249, 38, 0, 200}, 8 }

static picoquic_packet_header h_intel_bug = {
    TEST_CNXID_INTEL_BUG,
    TEST_CNXID_NULL_VAL,
    0,
    1,
    18,
    18,
    picoquic_packet_initial,
    0xFFFFFFFFFFFFFF00ull,
    0,
    1182,
    0,
    0,
    picoquic_packet_context_initial,
    0,
    0,
    0,
    0,
    0,
    0,
    0
};

struct _test_entry {
    uint8_t* packet;
    size_t length;
    picoquic_packet_header* ph;
    int decode_test_only;
    uint8_t local_cid_length;
};

static struct _test_entry test_entries[] = {
    { pinitial10, sizeof(pinitial10), &hinitial10, 1, 8 },
    { pinitial10_l, sizeof(pinitial10_l), &hinitial10_l, 0, 8 },
    { pvnego10, sizeof(pvnego10), &hvnego10, 1, 8 },
    { pvnegobis10, sizeof(pvnegobis10), &hvnego10, 1, 8 },
    { phandshake, sizeof(phandshake), &hhandshake, 1, 8 },
    { packet_short_phi0_c_32, sizeof(packet_short_phi0_c_32), &hphi0_c_32, 0, 8 },
    { packet_short_phi0_c_32_spin, sizeof(packet_short_phi0_c_32_spin), &hphi0_c_32_spin, 1, 8 },
    { packet_short_phi1_noc_32, sizeof(packet_short_phi1_noc_32), &hphi1_noc_32, 1, 0 },
    { packet_intel_bug, sizeof(packet_intel_bug), &h_intel_bug, 1, 8 }
};

static const size_t nb_test_entries = sizeof(test_entries) / sizeof(struct _test_entry);

int parseheadertest()
{
    int ret = 0;
    picoquic_packet_header ph;
    picoquic_quic_t* quic = NULL;
    picoquic_cnx_t* cnx_10 = NULL;
    struct sockaddr_in addr_10;
    picoquic_cnx_t* pcnx;
    uint8_t packet[PICOQUIC_MAX_PACKET_SIZE];

    /* Initialize the quic context and the connection contexts */
    memset(&addr_10, 0, sizeof(struct sockaddr_in));
    addr_10.sin_family = AF_INET;
#ifdef _WINDOWS
    addr_10.sin_addr.S_un.S_addr = 0x0A000002;
#else
    addr_10.sin_addr.s_addr = 0x0A000002;
#endif
    // addr_07.sin_port = 4433;
    addr_10.sin_port = 4434;

    quic = picoquic_create(8, NULL, NULL, NULL, NULL, NULL,
        NULL, NULL, NULL, NULL, 0, NULL, NULL, NULL, 0);
    if (quic == NULL) {
        ret = -1;
    } else {
        cnx_10 = picoquic_create_cnx(quic, test_cnxid_ini, test_cnxid_rem, (struct sockaddr*)&addr_10,
            0, PICOQUIC_INTERNAL_TEST_VERSION_1, NULL, NULL, 1);

        if (cnx_10 == NULL || cnx_10->first_local_cnxid_list == NULL) {
            ret = -1;
        }
        else {
            /* Remove old local CID from table and avoid leak. */
            picoquic_local_cnxid_list_t* local_cnxid_list = cnx_10->first_local_cnxid_list;

            picoquic_delete_local_cnxid(cnx_10, cnx_10->path[0]->p_local_cnxid);
            if (local_cnxid_list->nb_local_cnxid != 0) {
                DBG_PRINTF("Expected 0 cnxid left, got %d", local_cnxid_list->nb_local_cnxid);
            }
            else {
                /* Update the local cnx_id so it be predictable in tests */
                picoquic_local_cnxid_t* local_cnxid0 = picoquic_create_local_cnxid(cnx_10, 0, &test_cnxid_local, 0);
                if (local_cnxid0 == NULL) {
                    DBG_PRINTF("%s", "Cannot create the new CNX_ID");
                    ret = -1;
                }
                else {
                    cnx_10->path[0]->p_local_cnxid = local_cnxid0;
                }
            }
        }
    }

    for (size_t i = 0; ret == 0 && i < nb_test_entries; i++) {
        pcnx = (i < 3) ? NULL : cnx_10;
        quic->local_cnxid_length = test_entries[i].local_cid_length;
        memset(packet, 0xcc, sizeof(packet));
        memcpy(packet, test_entries[i].packet, (uint32_t)test_entries[i].length);

        if (picoquic_parse_packet_header(quic, packet, sizeof(packet),
                (struct sockaddr*)&addr_10, &ph, &pcnx, 1)
            != 0) {
            ret = -1;
        } else if (picoquic_compare_connection_id(&ph.dest_cnx_id, &test_entries[i].ph->dest_cnx_id) != 0) {
            ret = -1;
        } else if (picoquic_compare_connection_id(&ph.srce_cnx_id, &test_entries[i].ph->srce_cnx_id) != 0) {
            ret = -1;
        } else if (ph.vn != test_entries[i].ph->vn) {
            ret = -1;
        } else if (ph.offset != test_entries[i].ph->offset) {
            ret = -1;
        } else if (ph.pn_offset != test_entries[i].ph->pn_offset) {
            ret = -1;
        } else if (ph.payload_length != test_entries[i].ph->payload_length) {
            ret = -1;
        } else if (ph.ptype != test_entries[i].ph->ptype) {
            ret = -1;
        } else if (ph.spin != test_entries[i].ph->spin) {
            ret = -1;
        } else if (ph.epoch != test_entries[i].ph->epoch) {
            ret = -1;
        } else if (ph.pc != test_entries[i].ph->pc) {
            ret = -1;
        } else if (ph.key_phase != test_entries[i].ph->key_phase) {
            ret = -1;
        }
    }

    if (ret == 0) {
        quic->local_cnxid_length = 8;
    }

    for (size_t i = 0; ret == 0 && i < nb_test_entries; i++) {
        size_t header_length;
        size_t pn_offset;
        size_t pn_length;

        if (test_entries[i].decode_test_only) {
            continue;
        }

        pcnx = (i < 3) ? NULL : cnx_10;
        memset(packet, 0xcc, sizeof(packet));
        /* Prepare the header inside the packet */
        if (i < 2) {
            cnx_10->path[0]->p_remote_cnxid->cnx_id = picoquic_null_connection_id;
        }
        else {
            cnx_10->path[0]->p_remote_cnxid->cnx_id = test_cnxid_r10;
        }
        header_length = picoquic_create_packet_header(cnx_10, test_entries[i].ph->ptype,
            test_entries[i].ph->pn, cnx_10->path[0], 0, packet, &pn_offset, &pn_length);
        picoquic_update_payload_length(packet, pn_offset, pn_offset, pn_offset +
            test_entries[i].ph->payload_length);
        
        if ( pn_offset != test_entries[i].ph->pn_offset) {
           ret = -1;
        }
        
        if (memcmp(packet, test_entries[i].packet, header_length) != 0)
        {
            ret = -1;
        }
    }

    if (quic != NULL) {
        picoquic_free(quic);
    }

    return ret;
}


/* Test a range of variations of packet encryption and decryption */
int test_packet_decrypt_one(
    picoquic_quic_t* q_server,
    uint8_t * send_buffer,
    size_t send_length,
    size_t packet_length,
    struct sockaddr * addr_from,
    picoquic_cnx_t* cnx_target,
    picoquic_packet_header * expected_ph,
    int expected_return
)
{
    int ret = 0;
    int decoding_return;
    uint64_t current_time = 0;
    picoquic_packet_header received_ph;
    picoquic_cnx_t* server_cnx = NULL;
    size_t consumed = 0;
    int new_context_created = 0;
    uint64_t simulated_time = 0;
    picoquic_stream_data_node_t* decrypted_data = NULL;
    picoquic_quic_t* quic = picoquic_create(8, NULL, NULL, NULL, NULL, NULL,
        NULL, NULL, NULL, NULL, simulated_time,
        &simulated_time, NULL, NULL, 0);

    if (quic == NULL) {
        ret = -1;
    }
    else {
        decrypted_data = picoquic_stream_data_node_alloc(quic);
        if (decrypted_data == NULL) {
            ret = -1;
        }
    }

    /* Decrypt the packet */
    decoding_return = picoquic_parse_header_and_decrypt(q_server,
        send_buffer, send_length, packet_length,
        addr_from,
        current_time,
        decrypted_data,
        &received_ph, &server_cnx,
        &consumed, &new_context_created);

    /* verify that decryption matches original value */
    if (decoding_return != expected_return) {
        DBG_PRINTF("Return %x instead of %x.\n", decoding_return, expected_return);
        ret = -1;
    } else if (cnx_target != NULL && server_cnx != cnx_target) {
        DBG_PRINTF("%s", "Could not retrieve the connection\n");
        ret = -1;
    }
    else if (received_ph.ptype != expected_ph->ptype) {
        DBG_PRINTF("PTYPE %x instead of %x.\n", received_ph.ptype, expected_ph->ptype);
        ret = -1;
    }
    else if (received_ph.offset != expected_ph->offset) {
        DBG_PRINTF("Offset %x instead of %x.\n", received_ph.offset, expected_ph->offset);
        ret = -1;
    }
    else if (received_ph.vn != expected_ph->vn) {
        DBG_PRINTF("Version %x instead of %x.\n", received_ph.vn, expected_ph->vn);
        ret = -1;
    }
    else if (received_ph.pn64 != expected_ph->pn64) {
        DBG_PRINTF("PN64 %llx instead of %llx.\n", (unsigned long long)received_ph.pn64, (unsigned long long)expected_ph->pn64);
        ret = -1;
    }
    else if (received_ph.payload_length != expected_ph->payload_length) {
        DBG_PRINTF("Payload length %x instead of %x.\n", received_ph.payload_length, expected_ph->payload_length);
        ret = -1;
    }
    else if (picoquic_compare_connection_id(&received_ph.dest_cnx_id, &expected_ph->dest_cnx_id) != 0) {
        DBG_PRINTF("%s", "Dest CNXID does not match.\n");
        ret = -1;
    }
    else if (picoquic_compare_connection_id(&received_ph.srce_cnx_id, &expected_ph->srce_cnx_id) != 0) {
        DBG_PRINTF("%s", "Srce CNXID does not match.\n");
        ret = -1;
    }

    if (decrypted_data != NULL) {
        picoquic_stream_data_node_recycle(decrypted_data);
    }
    if (quic != NULL) {
        picoquic_free(quic);
    }

    return ret;
}

int test_packet_encrypt_one(
    struct sockaddr * addr_from,
    picoquic_cnx_t* cnx_client,
    picoquic_quic_t* q_server,
    picoquic_cnx_t* server_cnx,
    picoquic_packet_type_enum ptype,
    uint32_t length
)
{
    int ret = 0;
    size_t header_length = 0;
    size_t checksum_overhead = 0;
    size_t send_length = 0;
    uint8_t send_buffer[PICOQUIC_MAX_PACKET_SIZE];
    picoquic_path_t * path_x = cnx_client->path[0];
    uint64_t current_time = 0;
    picoquic_packet_header expected_header;
    picoquic_packet_t * packet = (picoquic_packet_t *) malloc(sizeof(picoquic_packet_t));
    picoquic_packet_context_enum pc = 0;
    picoquic_packet_context_t* pkt_ctx;

    if (packet == NULL) {
        DBG_PRINTF("%s", "Out of memory\n");
        ret = -1;
    }
    else {
        pkt_ctx = (ptype == picoquic_packet_1rtt_protected && cnx_client->is_multipath_enabled) ?
            &path_x->pkt_ctx : &cnx_client->pkt_ctx[pc];
        memset(packet, 0, sizeof(picoquic_packet_t));
        memset(packet->bytes, 0xbb, length);
        header_length = picoquic_predict_packet_header_length(cnx_client, ptype, pkt_ctx);
        packet->ptype = ptype;
        packet->offset = header_length;
        packet->length = length;
        packet->sequence_number = pkt_ctx->send_sequence;
        packet->send_path = cnx_client->path[0];

        /* Create a packet with specified parameters */
        picoquic_finalize_and_protect_packet(cnx_client, packet,
            ret, length, header_length, checksum_overhead,
            &send_length, send_buffer, PICOQUIC_MAX_PACKET_SIZE,
            path_x, current_time);

        expected_header.ptype = packet->ptype;
        expected_header.offset = packet->offset;
        expected_header.pn64 = packet->sequence_number;
        expected_header.vn = picoquic_supported_versions[cnx_client->version_index].version;
        expected_header.payload_length = packet->length - packet->offset;

        if (packet->ptype == picoquic_packet_0rtt_protected ||
            packet->ptype == picoquic_packet_initial) {
            expected_header.dest_cnx_id = cnx_client->initial_cnxid;
        }
        else {
            expected_header.dest_cnx_id = cnx_client->path[0]->p_remote_cnxid->cnx_id;
        }

        if (packet->ptype == picoquic_packet_1rtt_protected) {
            expected_header.vn = 0;
            expected_header.srce_cnx_id = picoquic_null_connection_id;
        }
        else {
            expected_header.vn = picoquic_supported_versions[cnx_client->version_index].version;
            expected_header.srce_cnx_id = cnx_client->path[0]->p_local_cnxid->cnx_id;
        }

        /* Decrypt the packet */
        ret = test_packet_decrypt_one(q_server,
            send_buffer, send_length, send_length,
            addr_from, server_cnx, &expected_header, 0);
    }
    return ret;
}

static const uint8_t test_0rtt_secret[] = {
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
    0, 1
};

static const uint8_t test_handshake_secret[] = {
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
    0, 1,
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10
};

static const uint8_t test_1rtt_secret[] = {
    0, 1,
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10
};

static uint8_t const addr1[4] = { 10, 0, 0, 1 };

int packet_enc_dec_test()
{
    int ret = 0;
    struct sockaddr_in test_addr_c;
    picoquic_cnx_t* cnx_client = NULL;
    picoquic_cnx_t* cnx_server = NULL;
    picoquic_quic_t* qclient = NULL;
    picoquic_quic_t* qserver = NULL;
    char test_server_cert_file[512];
    char test_server_key_file[512];
    char test_server_cert_store_file[512];
    const char *prefix_label;

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
            (struct sockaddr*)&test_addr_c, 0, 0, NULL, PICOQUIC_TEST_ALPN, 1);
        if (cnx_client == NULL) {
            DBG_PRINTF("%s", "Could not create client connection context.\n");
            ret = -1;
        }
        else {
            ret = picoquic_start_client_cnx(cnx_client);
        }
    }

    /* Test with a series of packets */
    /* First, client initial */
    if (ret == 0) {
        ret = test_packet_encrypt_one(
            (struct sockaddr *) &test_addr_c,
            cnx_client, qserver, NULL, picoquic_packet_initial, 1256);
    }
    /* If that work, update the connection context */
    if (ret == 0) {
        cnx_server = qserver->cnx_list;
        if (cnx_server == NULL) {
            DBG_PRINTF("%s", "Did not create the server connection context.\n");
            ret = -1;
        } else {
            /* Set the remote context ID for the client */
            cnx_client->path[0]->p_remote_cnxid->cnx_id = cnx_server->path[0]->p_local_cnxid->cnx_id;
        }
    }

    prefix_label = picoquic_supported_versions[cnx_client->version_index].tls_prefix_label;

    /* Try handshake packet from client */
    if (ret == 0) {
        cnx_client->crypto_context[2].aead_encrypt = picoquic_setup_test_aead_context(1, test_handshake_secret, prefix_label);
        cnx_server->crypto_context[2].aead_decrypt = picoquic_setup_test_aead_context(0, test_handshake_secret, prefix_label);
        cnx_client->crypto_context[2].pn_enc = picoquic_pn_enc_create_for_test(test_handshake_secret, prefix_label);
        cnx_server->crypto_context[2].pn_dec = picoquic_pn_enc_create_for_test(test_handshake_secret, prefix_label);
        ret = test_packet_encrypt_one(
            (struct sockaddr *) &test_addr_c,
            cnx_client, qserver, cnx_server, picoquic_packet_handshake, 1256);
    }

    /* Now try a zero RTT packet */
    if (ret == 0) {
        cnx_client->crypto_context[1].aead_encrypt = picoquic_setup_test_aead_context(1, test_0rtt_secret, prefix_label);
        cnx_server->crypto_context[1].aead_decrypt = picoquic_setup_test_aead_context(0, test_0rtt_secret, prefix_label);
        cnx_client->crypto_context[1].pn_enc = picoquic_pn_enc_create_for_test(test_0rtt_secret, prefix_label);
        cnx_server->crypto_context[1].pn_dec = picoquic_pn_enc_create_for_test(test_0rtt_secret, prefix_label);

        /* Use a null connection ID to trigger use of initial ID */
        cnx_client->path[0]->p_remote_cnxid->cnx_id = picoquic_null_connection_id;

        ret = test_packet_encrypt_one(
            (struct sockaddr *) &test_addr_c,
            cnx_client, qserver, cnx_server, picoquic_packet_0rtt_protected, 256);


        /* Set the remote context ID for the next test  */
        cnx_client->path[0]->p_remote_cnxid->cnx_id = cnx_server->path[0]->p_local_cnxid->cnx_id;
    }

    /* And try a 1 RTT packet */
    if (ret == 0) {
        cnx_client->crypto_context[3].aead_encrypt = picoquic_setup_test_aead_context(1, test_1rtt_secret, prefix_label);
        cnx_server->crypto_context[3].aead_decrypt = picoquic_setup_test_aead_context(0, test_1rtt_secret, prefix_label);
        cnx_client->crypto_context[3].pn_enc = picoquic_pn_enc_create_for_test(test_1rtt_secret, prefix_label);
        cnx_server->crypto_context[3].pn_dec = picoquic_pn_enc_create_for_test(test_1rtt_secret, prefix_label);

        ret = test_packet_encrypt_one(
            (struct sockaddr *) &test_addr_c,
            cnx_client, qserver, cnx_server, picoquic_packet_1rtt_protected, 1024);
    }

    if (cnx_client != NULL) {
        picoquic_delete_cnx(cnx_client);
    }

    if (qclient != NULL) {
        picoquic_free(qclient);
    }

    if (qserver != NULL) {
        picoquic_free(qserver);
    }

    return ret;
}

/* Tests of potentially challenging initial packets. 
 * The test passes if the packet is accepted and the
 * connection is created.
 */

int packet_initial_dec_one(
    uint8_t* bytes,
    size_t packet_length,
    char const * alpn)
{
    int ret = 0;
    struct sockaddr_in test_addr_c;
    struct sockaddr_in test_addr_s;
    picoquic_quic_t* qserver = NULL;
    picoquic_cnx_t* new_cnx = NULL;
    int path_id = -1;
    char test_server_cert_file[512];
    char test_server_key_file[512];
    char test_server_cert_store_file[512];

    picoquic_set_test_address(&test_addr_c, 0xabcd, 12345);
    picoquic_set_test_address(&test_addr_s, 0xa001, 443);

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
        qserver = picoquic_create(8,
            test_server_cert_file, test_server_key_file, test_server_cert_store_file,
            "h3", NULL, NULL, NULL, NULL, NULL, 0, NULL, NULL, NULL, 0);
        if (qserver == NULL) {
            DBG_PRINTF("%s", "Could not create Quic context.\n");
            ret = -1;
        }
    }

    if (ret == 0) {
        ret = picoquic_incoming_packet_ex(qserver, bytes, packet_length,
            (struct sockaddr*)&test_addr_c, (struct sockaddr*)&test_addr_s, 0,
            0, &new_cnx, &path_id, 0);
        if (ret != 0) {
            DBG_PRINTF("Incoming returns ret=0x%x", ret);
        }
        else if (new_cnx == NULL) {
            ret = -1;
            DBG_PRINTF("No connection created ret=0x%x", ret);
        }
    }

    if (qserver != NULL) {
        picoquic_free(qserver);
    }

    return ret;
}

int incoming_initial_test()
{
    int ret = packet_initial_dec_one(packet_intel_bug, sizeof(packet_intel_bug), "h3");

    return ret;
}

/* Header length test. verify that the header length prediction
 * matches the actual length of the encoding.
 * Loop through a set of variables: state of connection, type of packet,
 * sequence number, last packet not acknowledged.
 */

typedef struct st_header_length_case_t {
    int is_client;
    int i_cid_length;
    int local_cid_length;
    int remote_cid_length;
    picoquic_packet_type_enum ptype;
    uint64_t sequence;
    uint64_t sequence_unack;
    uint64_t sequence_unack_after;
} header_length_case_t;

static header_length_case_t header_length_case[] = {
    { 0, 8, 8, 8, picoquic_packet_initial, 0, UINT64_MAX, UINT64_MAX },
    { 0, 8, 8, 16, picoquic_packet_initial, 0, UINT64_MAX, UINT64_MAX },
    { 0, 16, 8, 4, picoquic_packet_initial, 0, UINT64_MAX, UINT64_MAX },
    { 0, 16, 8, 0, picoquic_packet_initial, 0, UINT64_MAX, UINT64_MAX },
    { 0, 16, 0, 0, picoquic_packet_initial, 0, UINT64_MAX, UINT64_MAX },
    { 0, 8, 8, 8, picoquic_packet_handshake, 0, UINT64_MAX, UINT64_MAX },
    { 0, 8, 8, 16, picoquic_packet_handshake, 0, UINT64_MAX, UINT64_MAX },
    { 0, 16, 8, 4, picoquic_packet_handshake, 0, UINT64_MAX, UINT64_MAX },
    { 0, 16, 8, 0, picoquic_packet_handshake, 0, UINT64_MAX, UINT64_MAX },
    { 0, 16, 0, 0, picoquic_packet_handshake, 0, UINT64_MAX, UINT64_MAX },
    { 0, 8, 8, 8, picoquic_packet_1rtt_protected, 0, UINT64_MAX, UINT64_MAX },
    { 0, 8, 8, 16, picoquic_packet_1rtt_protected, 0, UINT64_MAX, UINT64_MAX },
    { 0, 16, 8, 4, picoquic_packet_1rtt_protected, 0, UINT64_MAX, UINT64_MAX },
    { 0, 16, 8, 0, picoquic_packet_1rtt_protected, 0, UINT64_MAX, UINT64_MAX },
    { 0, 16, 0, 0, picoquic_packet_1rtt_protected, 0, UINT64_MAX, UINT64_MAX },
    { 0, 8, 0, 0, picoquic_packet_1rtt_protected, 0, UINT64_MAX, UINT64_MAX },
    { 0, 16, 8, 4, picoquic_packet_1rtt_protected, 63, UINT64_MAX, UINT64_MAX },
    { 0, 16, 8, 4, picoquic_packet_1rtt_protected, 64, UINT64_MAX, UINT64_MAX },
    { 0, 16, 8, 4, picoquic_packet_1rtt_protected, 255, UINT64_MAX, UINT64_MAX },
    { 0, 16, 8, 4, picoquic_packet_1rtt_protected, 0xffff, UINT64_MAX, UINT64_MAX },
    { 0, 16, 8, 4, picoquic_packet_1rtt_protected, 0xffffff, UINT64_MAX, UINT64_MAX },
    { 0, 16, 8, 4, picoquic_packet_1rtt_protected, 0xffffffff, UINT64_MAX, UINT64_MAX },
    { 0, 16, 8, 4, picoquic_packet_1rtt_protected, 0xffffffffffull, UINT64_MAX, UINT64_MAX },
    { 0, 16, 8, 4, picoquic_packet_1rtt_protected, 0xffffffff, 0xffffff00, 0xfffffffe },
    { 0, 16, 8, 4, picoquic_packet_1rtt_protected, 0xffffffff, 0xffffff00, UINT64_MAX },
    { 0, 16, 8, 4, picoquic_packet_handshake, 0xffffffff, 0xffffff00, 0xfffffffe },
    { 0, 16, 8, 4, picoquic_packet_handshake, 0xffffffff, 0xffffff00, UINT64_MAX },
    { 0, 16, 8, 4, picoquic_packet_initial, 0xffffffff, 0xffffff00, 0xfffffffe },
    { 0, 16, 8, 4, picoquic_packet_initial, 0xffffffff, 0xffffff00, UINT64_MAX },
    { 1, 8, 8, 8, picoquic_packet_initial, 0, UINT64_MAX, UINT64_MAX },
    { 1, 8, 8, 16, picoquic_packet_initial, 0, UINT64_MAX, UINT64_MAX },
    { 1, 16, 8, 4, picoquic_packet_initial, 0, UINT64_MAX, UINT64_MAX },
    { 1, 16, 8, 0, picoquic_packet_initial, 0, UINT64_MAX, UINT64_MAX },
    { 1, 16, 0, 0, picoquic_packet_initial, 0, UINT64_MAX, UINT64_MAX },
    { 1, 8, 8, 8, picoquic_packet_0rtt_protected, 0, UINT64_MAX, UINT64_MAX },
    { 1, 8, 8, 16, picoquic_packet_0rtt_protected, 0, UINT64_MAX, UINT64_MAX },
    { 1, 16, 8, 4, picoquic_packet_0rtt_protected, 0, UINT64_MAX, UINT64_MAX },
    { 1, 16, 8, 0, picoquic_packet_0rtt_protected, 0, UINT64_MAX, UINT64_MAX },
    { 1, 16, 0, 0, picoquic_packet_0rtt_protected, 0, UINT64_MAX, UINT64_MAX },
    { 1, 8, 8, 8, picoquic_packet_handshake, 0, UINT64_MAX, UINT64_MAX },
    { 1, 8, 8, 16, picoquic_packet_handshake, 0, UINT64_MAX, UINT64_MAX },
    { 1, 16, 8, 4, picoquic_packet_handshake, 0, UINT64_MAX, UINT64_MAX },
    { 1, 16, 8, 0, picoquic_packet_handshake, 0, UINT64_MAX, UINT64_MAX },
    { 1, 16, 0, 0, picoquic_packet_handshake, 0, UINT64_MAX, UINT64_MAX },
    { 1, 16, 8, 4, picoquic_packet_handshake, 0xffffffff, 0xffffff00, 0xfffffffe },
    { 1, 16, 8, 4, picoquic_packet_handshake, 0xffffffff, 0xffffff00, UINT64_MAX },
    { 1, 16, 8, 4, picoquic_packet_initial, 0xffffffff, 0xffffff00, 0xfffffffe },
    { 1, 16, 8, 4, picoquic_packet_initial, 0xffffffff, 0xffffff00, UINT64_MAX },
    { 1, 8, 8, 8, picoquic_packet_1rtt_protected, 0, UINT64_MAX, UINT64_MAX },
    { 1, 16, 8, 4, picoquic_packet_1rtt_protected, 255, UINT64_MAX, UINT64_MAX },
    { 1, 16, 8, 4, picoquic_packet_1rtt_protected, 0xffff, UINT64_MAX, UINT64_MAX },
    { 1, 16, 8, 4, picoquic_packet_1rtt_protected, 0xffffff, UINT64_MAX, UINT64_MAX },
    { 1, 16, 8, 4, picoquic_packet_1rtt_protected, 0xffffffff, UINT64_MAX, UINT64_MAX },
    { 1, 16, 8, 4, picoquic_packet_1rtt_protected, 0xffffffffffull, UINT64_MAX, UINT64_MAX },
    { 1, 16, 8, 4, picoquic_packet_1rtt_protected, 0xffffffff, 0xffffff00, 0xfffffffe },
    { 1, 16, 8, 4, picoquic_packet_1rtt_protected, 0xffffffff, 0xffffff00, UINT64_MAX }
};

static size_t nb_header_length_cases = sizeof(header_length_case) / sizeof(header_length_case_t);

static int header_length_test_set_queue(picoquic_cnx_t* cnx, header_length_case_t* hlc,
    uint64_t unack, picoquic_packet_context_enum pc, picoquic_packet_context_t* pkt_ctx, uint64_t simulated_time)
{
    int ret = 0;
    pkt_ctx->send_sequence = hlc->sequence;

    if (unack != UINT64_MAX) {
        picoquic_packet_t* packet = picoquic_create_packet(cnx->quic);
        if (packet == NULL) {
            ret = -1;
        }
        else {
            packet->ptype = hlc->ptype;
            packet->sequence_number = unack;
            packet->length = PICOQUIC_MAX_PACKET_SIZE;
            packet->pc = pc;
            picoquic_queue_for_retransmit(cnx, cnx->path[0], packet, packet->length, simulated_time);
        }
    }
    return ret;
}

static int header_length_test_one(header_length_case_t * hlc)
{
    int ret = 0;
    char test_server_cert_file[512];
    char test_server_key_file[512];
    char test_server_cert_store_file[512];
    uint64_t simulated_time = 0;
    picoquic_quic_t* quic = NULL;
    picoquic_cnx_t* cnx = NULL;
    picoquic_connection_id_t i_cid;
    picoquic_connection_id_t r_cid;
    struct sockaddr_in addr_to;
    picoquic_packet_context_enum pc = 0;
    picoquic_packet_context_t* pkt_ctx = NULL;
    size_t predicted_length = 0;
    size_t header_length = 0;
    size_t pn_offset;
    size_t pn_length;
    uint8_t buffer[PICOQUIC_MAX_PACKET_SIZE];

    /* Create the remote address */
    picoquic_set_test_address(&addr_to, 0xabcd, 12345);
    /* Set cid to required value */
    memset(i_cid.id, 0x11, 20);
    memset(r_cid.id, 0xdd, 20);
    i_cid.id_len = hlc->i_cid_length;
    r_cid.id_len = hlc->remote_cid_length;

    /* Create the quic context */
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
        quic = picoquic_create(8,
            test_server_cert_file, test_server_key_file, test_server_cert_store_file,
            "h3", NULL, NULL, NULL, NULL, NULL, 0, &simulated_time, NULL, NULL, 0);
        if (quic == NULL) {
            DBG_PRINTF("%s", "Could not create Quic context.\n");
            ret = -1;
        }
        else {
            quic->local_cnxid_length = hlc->local_cid_length;
        }
    }

    /* Create a connection with desired characteristics */
    if (ret == 0) {
        cnx = picoquic_create_cnx(quic, i_cid, r_cid, (struct sockaddr*)&addr_to, 0, 0, "test", "h3", hlc->is_client);
        if (cnx == NULL) {
            ret = -1;
        }
        else {
            /* Find the required packet context and initialize the sequence and retransmit or retransmitted queue */
            /* TODO: add option for trying packet type retry */
            if (hlc->ptype == picoquic_packet_initial) {
                pc = picoquic_packet_context_initial;
                pkt_ctx = &cnx->pkt_ctx[picoquic_packet_context_initial];
            }
            else if (hlc->ptype == picoquic_packet_handshake) {
                pc = picoquic_packet_context_handshake;
                pkt_ctx = &cnx->pkt_ctx[picoquic_packet_context_handshake];
            }
            else if (hlc->ptype == picoquic_packet_0rtt_protected || hlc->ptype == picoquic_packet_1rtt_protected) {
                pc = picoquic_packet_context_application;
                pkt_ctx = &cnx->pkt_ctx[picoquic_packet_context_application];
            }
            if (pkt_ctx != NULL) {
                pkt_ctx->send_sequence = hlc->sequence;

                if (hlc->sequence_unack != UINT64_MAX) {
                    ret = header_length_test_set_queue(cnx, hlc, hlc->sequence_unack, pc, pkt_ctx, simulated_time);
                }
            }
        }
    }

    if (ret == 0) {
        /* Compute the predicted length */
        predicted_length = picoquic_predict_packet_header_length(cnx, hlc->ptype, pkt_ctx);
        /* Reset the retransmit queue to simulate unack */
        if (hlc->sequence_unack != hlc->sequence_unack_after) {
            if (hlc->sequence_unack != UINT64_MAX) {
                picoquic_dequeue_retransmit_packet(cnx, pkt_ctx, pkt_ctx->pending_first, 1, 0);
            }
            if (hlc->sequence_unack_after != UINT64_MAX) {
                ret = header_length_test_set_queue(cnx, hlc, hlc->sequence_unack_after, pc, pkt_ctx, simulated_time);
            }
        }
    }
    if (ret == 0) {
        /* Compute the header length */
        header_length = picoquic_create_packet_header(cnx, hlc->ptype,
            hlc->sequence, cnx->path[0], predicted_length, buffer, &pn_offset, &pn_length);
        /* Check the results */
        if (header_length != predicted_length) {
            DBG_PRINTF("Error, predicted header length %zu, actual %zu", header_length, predicted_length);
            ret = -1;
        }
        else if (pn_length == 0 || pn_length > 4) {
            DBG_PRINTF("Error, invalid PN length %zu", pn_length);
            ret = -1;
        }
        else if (pn_length + pn_offset != header_length) {
            DBG_PRINTF("Error, PN offset %zu + %zu != header_length %zu", pn_offset, pn_length, header_length);
            ret = -1;
        }
    }


    if (quic != NULL) {
        picoquic_free(quic);
    }

    return ret;
}

int header_length_test()
{
    int ret = 0;
    for (size_t i = 0; i < nb_header_length_cases; i++) {
        ret = header_length_test_one(&header_length_case[i]);
        if (ret != 0) {
            DBG_PRINTF("Header length test %zu fails", i);
            break;
        }
    }
    return ret;
}