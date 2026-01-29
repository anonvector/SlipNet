/*
* Author: Christian Huitema
* Copyright (c) 2019, Private Octopus, Inc.
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

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "picoquic_internal.h"
#include "picoquic_utils.h"
#include "picoquictest_internal.h"
#include "tls_api.h"
#include "h3zero.h"
#include "h3zero_common.h"
#include "democlient.h"
#include "demoserver.h"
#ifdef _WINDOWS
#include "wincompat.h"
#include <direct.h>
#else
#include <sys/stat.h>
#include <sys/types.h>
#endif
#if 0
/* Include picotls.h in order to support tests of ESNI */
#include "picotls.h"
#include "tls_api.h"
#endif
#include "autoqlog.h"
#include "picoquic_binlog.h"
#include "picoquic_utils.h"

/*
 * Test of the prefixed integer encoding
 */

static uint8_t h3zero_pref31_val10[] = { 0xCA }; 
static uint8_t h3zero_pref31_val31[] = { 0xDF, 0 };
static uint8_t h3zero_pref31_val1337[] = { 0xDF, 0x9A, 0x0A };
static uint8_t h3zero_pref127_val0[] = { 0x80 };
static uint8_t h3zero_pref127_valmax[] = { 
    0xFF, 0x80, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x3F };
static uint8_t h3zero_pref7_err1[] = { 0x07 };
static uint8_t h3zero_pref7_err2[] = { 0x07, 0xFF, 0xFF, 0x80, 0x80, 0x80 };
static uint8_t h3zero_pref127_val255[] = { 0x7F, 0x80, 0x01 };

typedef struct st_h3zero_test_integer_case_t {
    uint64_t test_value;
    uint8_t mask;
    uint8_t * encoding;
    size_t encoding_length;
} h3zero_test_integer_case_t;

static h3zero_test_integer_case_t h3zero_int_case[] = {
    { 10, 0x1F, h3zero_pref31_val10, sizeof(h3zero_pref31_val10)},
    { 31, 0x1F, h3zero_pref31_val31, sizeof(h3zero_pref31_val31)},
    { 1337, 0x1F, h3zero_pref31_val1337, sizeof(h3zero_pref31_val1337)},
    { 0, 0x7F, h3zero_pref127_val0, sizeof(h3zero_pref127_val0)},
    { 0x3FFFFFFFFFFFFFFFull, 0x7F, h3zero_pref127_valmax, sizeof(h3zero_pref127_valmax)},
    { 0xFFFFFFFFFFFFFFFFull, 0x07, h3zero_pref7_err1, sizeof(h3zero_pref7_err1)},
    { 0xFFFFFFFFFFFFFFFFull, 0x07, h3zero_pref7_err2, sizeof(h3zero_pref7_err2)},
    { 0xFF, 0x7F, h3zero_pref127_val255, sizeof(h3zero_pref127_val255)}
};

static size_t nb_h3zero_int_case = sizeof(h3zero_int_case) / sizeof(h3zero_test_integer_case_t);

int h3zero_integer_test() 
{
    int ret = 0;
    for (size_t i = 0; ret == 0 && i < nb_h3zero_int_case; i++) {
        uint64_t val;
        uint8_t * bytes;

        bytes = h3zero_qpack_int_decode(
            h3zero_int_case[i].encoding,
            h3zero_int_case[i].encoding + h3zero_int_case[i].encoding_length,
            h3zero_int_case[i].mask,
            &val);

        if (h3zero_int_case[i].test_value == 0xFFFFFFFFFFFFFFFFull) {
            /* verify that error is properly detected */
            if (bytes != NULL) {
                DBG_PRINTF("Failed to detect error case %d\n", (int)i);
                ret = -1;
            }
        }
        else {
            if (bytes == NULL) {
                DBG_PRINTF("Failed to decode case %d\n", (int)i);
                ret = -1;
            }
            else if ((bytes - h3zero_int_case[i].encoding) != h3zero_int_case[i].encoding_length) {
                DBG_PRINTF("Bad decoding length case %d\n", (int)i);
                ret = -1;
            }
            else if (val != h3zero_int_case[i].test_value) {
                DBG_PRINTF("Bad decoded value case %d\n", (int)i);
                ret = -1;
            }
            else {
                uint8_t target[16];

                memset(target, 0x55, sizeof(target));
                target[0] = h3zero_int_case[i].encoding[0] & ~h3zero_int_case[i].mask;

                bytes = h3zero_qpack_int_encode(target, target + sizeof(target),
                    h3zero_int_case[i].mask, h3zero_int_case[i].test_value);

                if (bytes == NULL) {
                    DBG_PRINTF("Failed to encode case %d\n", (int)i);
                    ret = -1;
                }
                else if ((bytes - target) != h3zero_int_case[i].encoding_length) {
                    DBG_PRINTF("Bad encoding length case %d\n", (int)i);
                    ret = -1;
                }
                else if (memcmp(target, h3zero_int_case[i].encoding,
                    h3zero_int_case[i].encoding_length) != 0) {
                    DBG_PRINTF("Bad encoding case %d\n", (int)i);
                    ret = -1;
                }
            }
        }
    }

    return ret;
}

/* Test of QPACK Huffman decoding */
static uint8_t qpack_huffman_test_1[] = { 0xce, 0x64, 0x97, 0x75, 0x65, 0x2c, 0x9f };
static uint8_t qpack_huffman_test_2[] = { 0x1d, 0x75, 0xd0, 0x62, 0x0d, 0x26, 0x3d, 0x4c, 0x4e, 0x9a, 0x68 };
static uint8_t qpack_huffman_test_3[] = { 0x7c, 0x40 };
static uint8_t qpack_huffman_test_4[] = { 0x60, 0x22, 0x65, 0xaf };
static uint8_t qpack_huffman_data_1[] = { 'L', 'i', 't', 'e', 'S', 'p', 'e', 'e', 'd' };
static uint8_t qpack_huffman_data_2[] = { 'a', 'p', 'p', 'l', 'i', 'c', 'a', 't', 'i', 'o', 'n', '/', 'h', 't', 'm', 'l' };
static uint8_t qpack_huffman_data_3[] = { '9', '2', '0' };
static uint8_t qpack_huffman_data_4[] = { '/', '1', '2', '3', '4' };

typedef struct st_qpack_huffman_test_case_t {
    uint8_t * test;
    size_t test_size;
    uint8_t * result;
    size_t result_size;
} qpack_huffman_test_case_t;

static qpack_huffman_test_case_t qpack_huffman_test_case[] = {
    { qpack_huffman_test_1, sizeof(qpack_huffman_test_1),
    qpack_huffman_data_1, sizeof(qpack_huffman_data_1)},
    { qpack_huffman_test_2, sizeof(qpack_huffman_test_2),
    qpack_huffman_data_2, sizeof(qpack_huffman_data_2)},
    { qpack_huffman_test_3, sizeof(qpack_huffman_test_3),
    qpack_huffman_data_3, sizeof(qpack_huffman_data_3)},
    { qpack_huffman_test_4, sizeof(qpack_huffman_test_4),
    qpack_huffman_data_4, sizeof(qpack_huffman_data_4)}
};

static size_t nb_qpack_huffman_test_case = sizeof(qpack_huffman_test_case) / sizeof(qpack_huffman_test_case_t);

int qpack_huffman_test()
{
    int ret = 0;
    uint8_t data[256];
    size_t nb_data;

    for (size_t i = 0; ret == 0 && i < nb_qpack_huffman_test_case; i++) {
        ret = hzero_qpack_huffman_decode(
            qpack_huffman_test_case[i].test,
            qpack_huffman_test_case[i].test + qpack_huffman_test_case[i].test_size,
            data, sizeof(data), &nb_data);
        if (ret == 0) {
            if (nb_data != qpack_huffman_test_case[i].result_size) {
                DBG_PRINTF("Huffman test %d bad length (%d vs %d)\n", (int)i,
                    (int)nb_data, (int)qpack_huffman_test_case[i].result_size);
                ret = -1;
            }
            else if (memcmp(qpack_huffman_test_case[i].result, data, nb_data) != 0) {
                DBG_PRINTF("Huffman test %d does not match \n", (int)i);
                ret = -1;
            }
        }
        else {
            DBG_PRINTF("Huffman cannot decode test %d\n", (int)i);
        }
    }

    return ret;
}

typedef struct st_h3zero_qpack_huffman_base_t {
    uint64_t right_shift_hex;
    int nb_bits;
    int code;
} h3zero_qpack_huffman_base_t;

static h3zero_qpack_huffman_base_t h3zero_qpack_huffman_base[] = {
    { 0x0 , 5 , 48 }, /* index:  0   |00000  */
    { 0x1 , 5 , 49 }, /* index:  1   |00001  */
    { 0x2 , 5 , 50 }, /* index:  2   |00010  */
    { 0x3 , 5 , 97 }, /* index:  3   |00011  */
    { 0x4 , 5 , 99 }, /* index:  4   |00100  */
    { 0x5 , 5 , 101 }, /* index:  5   |00101  */
    { 0x6 , 5 , 105 }, /* index:  6   |00110  */
    { 0x7 , 5 , 111 }, /* index:  7   |00111  */
    { 0x8 , 5 , 115 }, /* index:  8   |01000  */
    { 0x9 , 5 , 116 }, /* index:  9   |01001  */
    { 0x14 , 6 , 32 }, /* index:  10   |010100  */
    { 0x15 , 6 , 37 }, /* index:  11   |010101  */
    { 0x16 , 6 , 45 }, /* index:  12   |010110  */
    { 0x17 , 6 , 46 }, /* index:  13   |010111  */
    { 0x18 , 6 , 47 }, /* index:  14   |011000  */
    { 0x19 , 6 , 51 }, /* index:  15   |011001  */
    { 0x1a , 6 , 52 }, /* index:  16   |011010  */
    { 0x1b , 6 , 53 }, /* index:  17   |011011  */
    { 0x1c , 6 , 54 }, /* index:  18   |011100  */
    { 0x1d , 6 , 55 }, /* index:  19   |011101  */
    { 0x1e , 6 , 56 }, /* index:  20   |011110  */
    { 0x1f , 6 , 57 }, /* index:  21   |011111  */
    { 0x20 , 6 , 61 }, /* index:  22   |100000  */
    { 0x21 , 6 , 65 }, /* index:  23   |100001  */
    { 0x22 , 6 , 95 }, /* index:  24   |100010  */
    { 0x23 , 6 , 98 }, /* index:  25   |100011  */
    { 0x24 , 6 , 100 }, /* index:  26   |100100  */
    { 0x25 , 6 , 102 }, /* index:  27   |100101  */
    { 0x26 , 6 , 103 }, /* index:  28   |100110  */
    { 0x27 , 6 , 104 }, /* index:  29   |100111  */
    { 0x28 , 6 , 108 }, /* index:  30   |101000  */
    { 0x29 , 6 , 109 }, /* index:  31   |101001  */
    { 0x2a , 6 , 110 }, /* index:  32   |101010  */
    { 0x2b , 6 , 112 }, /* index:  33   |101011  */
    { 0x2c , 6 , 114 }, /* index:  34   |101100  */
    { 0x2d , 6 , 117 }, /* index:  35   |101101  */
    { 0x5c , 7 , 58 }, /* index:  36   |1011100  */
    { 0x5d , 7 , 66 }, /* index:  37   |1011101  */
    { 0x5e , 7 , 67 }, /* index:  38   |1011110  */
    { 0x5f , 7 , 68 }, /* index:  39   |1011111  */
    { 0x60 , 7 , 69 }, /* index:  40   |1100000  */
    { 0x61 , 7 , 70 }, /* index:  41   |1100001  */
    { 0x62 , 7 , 71 }, /* index:  42   |1100010  */
    { 0x63 , 7 , 72 }, /* index:  43   |1100011  */
    { 0x64 , 7 , 73 }, /* index:  44   |1100100  */
    { 0x65 , 7 , 74 }, /* index:  45   |1100101  */
    { 0x66 , 7 , 75 }, /* index:  46   |1100110  */
    { 0x67 , 7 , 76 }, /* index:  47   |1100111  */
    { 0x68 , 7 , 77 }, /* index:  48   |1101000  */
    { 0x69 , 7 , 78 }, /* index:  49   |1101001  */
    { 0x6a , 7 , 79 }, /* index:  50   |1101010  */
    { 0x6b , 7 , 80 }, /* index:  51   |1101011  */
    { 0x6c , 7 , 81 }, /* index:  52   |1101100  */
    { 0x6d , 7 , 82 }, /* index:  53   |1101101  */
    { 0x6e , 7 , 83 }, /* index:  54   |1101110  */
    { 0x6f , 7 , 84 }, /* index:  55   |1101111  */
    { 0x70 , 7 , 85 }, /* index:  56   |1110000  */
    { 0x71 , 7 , 86 }, /* index:  57   |1110001  */
    { 0x72 , 7 , 87 }, /* index:  58   |1110010  */
    { 0x73 , 7 , 89 }, /* index:  59   |1110011  */
    { 0x74 , 7 , 106 }, /* index:  60   |1110100  */
    { 0x75 , 7 , 107 }, /* index:  61   |1110101  */
    { 0x76 , 7 , 113 }, /* index:  62   |1110110  */
    { 0x77 , 7 , 118 }, /* index:  63   |1110111  */
    { 0x78 , 7 , 119 }, /* index:  64   |1111000  */
    { 0x79 , 7 , 120 }, /* index:  65   |1111001  */
    { 0x7a , 7 , 121 }, /* index:  66   |1111010  */
    { 0x7b , 7 , 122 }, /* index:  67   |1111011  */
    { 0xf8 , 8 , 38 }, /* index:  68   |11111000  */
    { 0xf9 , 8 , 42 }, /* index:  69   |11111001  */
    { 0xfa , 8 , 44 }, /* index:  70   |11111010  */
    { 0xfb , 8 , 59 }, /* index:  71   |11111011  */
    { 0xfc , 8 , 88 }, /* index:  72   |11111100  */
    { 0xfd , 8 , 90 }, /* index:  73   |11111101  */
    { 0x3f8 , 10 , 33 }, /* index:  74   |11111110|00  */
    { 0x3f9 , 10 , 34 }, /* index:  75   |11111110|01  */
    { 0x3fa , 10 , 40 }, /* index:  76   |11111110|10  */
    { 0x3fb , 10 , 41 }, /* index:  77   |11111110|11  */
    { 0x3fc , 10 , 63 }, /* index:  78   |11111111|00  */
    { 0x7fa , 11 , 39 }, /* index:  79   |11111111|010  */
    { 0x7fb , 11 , 43 }, /* index:  80   |11111111|011  */
    { 0x7fc , 11 , 124 }, /* index:  81   |11111111|100  */
    { 0xffa , 12 , 35 }, /* index:  82   |11111111|1010  */
    { 0xffb , 12 , 62 }, /* index:  83   |11111111|1011  */
    { 0x1ff8 , 13 , 0 }, /* index:  84   |11111111|11000  */
    { 0x1ff9 , 13 , 36 }, /* index:  85   |11111111|11001  */
    { 0x1ffa , 13 , 64 }, /* index:  86   |11111111|11010  */
    { 0x1ffb , 13 , 91 }, /* index:  87   |11111111|11011  */
    { 0x1ffc , 13 , 93 }, /* index:  88   |11111111|11100  */
    { 0x1ffd , 13 , 126 }, /* index:  89   |11111111|11101  */
    { 0x3ffc , 14 , 94 }, /* index:  90   |11111111|111100  */
    { 0x3ffd , 14 , 125 }, /* index:  91   |11111111|111101  */
    { 0x7ffc , 15 , 60 }, /* index:  92   |11111111|1111100  */
    { 0x7ffd , 15 , 96 }, /* index:  93   |11111111|1111101  */
    { 0x7ffe , 15 , 123 }, /* index:  94   |11111111|1111110  */
    { 0x7fff0 , 19 , 92 }, /* index:  95   |11111111|11111110|000  */
    { 0x7fff1 , 19 , 195 }, /* index:  96   |11111111|11111110|001  */
    { 0x7fff2 , 19 , 208 }, /* index:  97   |11111111|11111110|010  */
    { 0xfffe6 , 20 , 128 }, /* index:  98   |11111111|11111110|0110  */
    { 0xfffe7 , 20 , 130 }, /* index:  99   |11111111|11111110|0111  */
    { 0xfffe8 , 20 , 131 }, /* index:  100   |11111111|11111110|1000  */
    { 0xfffe9 , 20 , 162 }, /* index:  101   |11111111|11111110|1001  */
    { 0xfffea , 20 , 184 }, /* index:  102   |11111111|11111110|1010  */
    { 0xfffeb , 20 , 194 }, /* index:  103   |11111111|11111110|1011  */
    { 0xfffec , 20 , 224 }, /* index:  104   |11111111|11111110|1100  */
    { 0xfffed , 20 , 226 }, /* index:  105   |11111111|11111110|1101  */
    { 0x1fffdc , 21 , 153 }, /* index:  106   |11111111|11111110|11100  */
    { 0x1fffdd , 21 , 161 }, /* index:  107   |11111111|11111110|11101  */
    { 0x1fffde , 21 , 167 }, /* index:  108   |11111111|11111110|11110  */
    { 0x1fffdf , 21 , 172 }, /* index:  109   |11111111|11111110|11111  */
    { 0x1fffe0 , 21 , 176 }, /* index:  110   |11111111|11111111|00000  */
    { 0x1fffe1 , 21 , 177 }, /* index:  111   |11111111|11111111|00001  */
    { 0x1fffe2 , 21 , 179 }, /* index:  112   |11111111|11111111|00010  */
    { 0x1fffe3 , 21 , 209 }, /* index:  113   |11111111|11111111|00011  */
    { 0x1fffe4 , 21 , 216 }, /* index:  114   |11111111|11111111|00100  */
    { 0x1fffe5 , 21 , 217 }, /* index:  115   |11111111|11111111|00101  */
    { 0x1fffe6 , 21 , 227 }, /* index:  116   |11111111|11111111|00110  */
    { 0x1fffe7 , 21 , 229 }, /* index:  117   |11111111|11111111|00111  */
    { 0x1fffe8 , 21 , 230 }, /* index:  118   |11111111|11111111|01000  */
    { 0x3fffd2 , 22 , 129 }, /* index:  119   |11111111|11111111|010010  */
    { 0x3fffd3 , 22 , 132 }, /* index:  120   |11111111|11111111|010011  */
    { 0x3fffd4 , 22 , 133 }, /* index:  121   |11111111|11111111|010100  */
    { 0x3fffd5 , 22 , 134 }, /* index:  122   |11111111|11111111|010101  */
    { 0x3fffd6 , 22 , 136 }, /* index:  123   |11111111|11111111|010110  */
    { 0x3fffd7 , 22 , 146 }, /* index:  124   |11111111|11111111|010111  */
    { 0x3fffd8 , 22 , 154 }, /* index:  125   |11111111|11111111|011000  */
    { 0x3fffd9 , 22 , 156 }, /* index:  126   |11111111|11111111|011001  */
    { 0x3fffda , 22 , 160 }, /* index:  127   |11111111|11111111|011010  */
    { 0x3fffdb , 22 , 163 }, /* index:  128   |11111111|11111111|011011  */
    { 0x3fffdc , 22 , 164 }, /* index:  129   |11111111|11111111|011100  */
    { 0x3fffdd , 22 , 169 }, /* index:  130   |11111111|11111111|011101  */
    { 0x3fffde , 22 , 170 }, /* index:  131   |11111111|11111111|011110  */
    { 0x3fffdf , 22 , 173 }, /* index:  132   |11111111|11111111|011111  */
    { 0x3fffe0 , 22 , 178 }, /* index:  133   |11111111|11111111|100000  */
    { 0x3fffe1 , 22 , 181 }, /* index:  134   |11111111|11111111|100001  */
    { 0x3fffe2 , 22 , 185 }, /* index:  135   |11111111|11111111|100010  */
    { 0x3fffe3 , 22 , 186 }, /* index:  136   |11111111|11111111|100011  */
    { 0x3fffe4 , 22 , 187 }, /* index:  137   |11111111|11111111|100100  */
    { 0x3fffe5 , 22 , 189 }, /* index:  138   |11111111|11111111|100101  */
    { 0x3fffe6 , 22 , 190 }, /* index:  139   |11111111|11111111|100110  */
    { 0x3fffe7 , 22 , 196 }, /* index:  140   |11111111|11111111|100111  */
    { 0x3fffe8 , 22 , 198 }, /* index:  141   |11111111|11111111|101000  */
    { 0x3fffe9 , 22 , 228 }, /* index:  142   |11111111|11111111|101001  */
    { 0x3fffea , 22 , 232 }, /* index:  143   |11111111|11111111|101010  */
    { 0x3fffeb , 22 , 233 }, /* index:  144   |11111111|11111111|101011  */
    { 0x7fffd8 , 23 , 1 }, /* index:  145   |11111111|11111111|1011000  */
    { 0x7fffd9 , 23 , 135 }, /* index:  146   |11111111|11111111|1011001  */
    { 0x7fffda , 23 , 137 }, /* index:  147   |11111111|11111111|1011010  */
    { 0x7fffdb , 23 , 138 }, /* index:  148   |11111111|11111111|1011011  */
    { 0x7fffdc , 23 , 139 }, /* index:  149   |11111111|11111111|1011100  */
    { 0x7fffdd , 23 , 140 }, /* index:  150   |11111111|11111111|1011101  */
    { 0x7fffde , 23 , 141 }, /* index:  151   |11111111|11111111|1011110  */
    { 0x7fffdf , 23 , 143 }, /* index:  152   |11111111|11111111|1011111  */
    { 0x7fffe0 , 23 , 147 }, /* index:  153   |11111111|11111111|1100000  */
    { 0x7fffe1 , 23 , 149 }, /* index:  154   |11111111|11111111|1100001  */
    { 0x7fffe2 , 23 , 150 }, /* index:  155   |11111111|11111111|1100010  */
    { 0x7fffe3 , 23 , 151 }, /* index:  156   |11111111|11111111|1100011  */
    { 0x7fffe4 , 23 , 152 }, /* index:  157   |11111111|11111111|1100100  */
    { 0x7fffe5 , 23 , 155 }, /* index:  158   |11111111|11111111|1100101  */
    { 0x7fffe6 , 23 , 157 }, /* index:  159   |11111111|11111111|1100110  */
    { 0x7fffe7 , 23 , 158 }, /* index:  160   |11111111|11111111|1100111  */
    { 0x7fffe8 , 23 , 165 }, /* index:  161   |11111111|11111111|1101000  */
    { 0x7fffe9 , 23 , 166 }, /* index:  162   |11111111|11111111|1101001  */
    { 0x7fffea , 23 , 168 }, /* index:  163   |11111111|11111111|1101010  */
    { 0x7fffeb , 23 , 174 }, /* index:  164   |11111111|11111111|1101011  */
    { 0x7fffec , 23 , 175 }, /* index:  165   |11111111|11111111|1101100  */
    { 0x7fffed , 23 , 180 }, /* index:  166   |11111111|11111111|1101101  */
    { 0x7fffee , 23 , 182 }, /* index:  167   |11111111|11111111|1101110  */
    { 0x7fffef , 23 , 183 }, /* index:  168   |11111111|11111111|1101111  */
    { 0x7ffff0 , 23 , 188 }, /* index:  169   |11111111|11111111|1110000  */
    { 0x7ffff1 , 23 , 191 }, /* index:  170   |11111111|11111111|1110001  */
    { 0x7ffff2 , 23 , 197 }, /* index:  171   |11111111|11111111|1110010  */
    { 0x7ffff3 , 23 , 231 }, /* index:  172   |11111111|11111111|1110011  */
    { 0x7ffff4 , 23 , 239 }, /* index:  173   |11111111|11111111|1110100  */
    { 0xffffea , 24 , 9 }, /* index:  174   |11111111|11111111|11101010  */
    { 0xffffeb , 24 , 142 }, /* index:  175   |11111111|11111111|11101011  */
    { 0xffffec , 24 , 144 }, /* index:  176   |11111111|11111111|11101100  */
    { 0xffffed , 24 , 145 }, /* index:  177   |11111111|11111111|11101101  */
    { 0xffffee , 24 , 148 }, /* index:  178   |11111111|11111111|11101110  */
    { 0xffffef , 24 , 159 }, /* index:  179   |11111111|11111111|11101111  */
    { 0xfffff0 , 24 , 171 }, /* index:  180   |11111111|11111111|11110000  */
    { 0xfffff1 , 24 , 206 }, /* index:  181   |11111111|11111111|11110001  */
    { 0xfffff2 , 24 , 215 }, /* index:  182   |11111111|11111111|11110010  */
    { 0xfffff3 , 24 , 225 }, /* index:  183   |11111111|11111111|11110011  */
    { 0xfffff4 , 24 , 236 }, /* index:  184   |11111111|11111111|11110100  */
    { 0xfffff5 , 24 , 237 }, /* index:  185   |11111111|11111111|11110101  */
    { 0x1ffffec , 25 , 199 }, /* index:  186   |11111111|11111111|11110110|0  */
    { 0x1ffffed , 25 , 207 }, /* index:  187   |11111111|11111111|11110110|1  */
    { 0x1ffffee , 25 , 234 }, /* index:  188   |11111111|11111111|11110111|0  */
    { 0x1ffffef , 25 , 235 }, /* index:  189   |11111111|11111111|11110111|1  */
    { 0x3ffffe0 , 26 , 192 }, /* index:  190   |11111111|11111111|11111000|00  */
    { 0x3ffffe1 , 26 , 193 }, /* index:  191   |11111111|11111111|11111000|01  */
    { 0x3ffffe2 , 26 , 200 }, /* index:  192   |11111111|11111111|11111000|10  */
    { 0x3ffffe3 , 26 , 201 }, /* index:  193   |11111111|11111111|11111000|11  */
    { 0x3ffffe4 , 26 , 202 }, /* index:  194   |11111111|11111111|11111001|00  */
    { 0x3ffffe5 , 26 , 205 }, /* index:  195   |11111111|11111111|11111001|01  */
    { 0x3ffffe6 , 26 , 210 }, /* index:  196   |11111111|11111111|11111001|10  */
    { 0x3ffffe7 , 26 , 213 }, /* index:  197   |11111111|11111111|11111001|11  */
    { 0x3ffffe8 , 26 , 218 }, /* index:  198   |11111111|11111111|11111010|00  */
    { 0x3ffffe9 , 26 , 219 }, /* index:  199   |11111111|11111111|11111010|01  */
    { 0x3ffffea , 26 , 238 }, /* index:  200   |11111111|11111111|11111010|10  */
    { 0x3ffffeb , 26 , 240 }, /* index:  201   |11111111|11111111|11111010|11  */
    { 0x3ffffec , 26 , 242 }, /* index:  202   |11111111|11111111|11111011|00  */
    { 0x3ffffed , 26 , 243 }, /* index:  203   |11111111|11111111|11111011|01  */
    { 0x3ffffee , 26 , 255 }, /* index:  204   |11111111|11111111|11111011|10  */
    { 0x7ffffde , 27 , 203 }, /* index:  205   |11111111|11111111|11111011|110  */
    { 0x7ffffdf , 27 , 204 }, /* index:  206   |11111111|11111111|11111011|111  */
    { 0x7ffffe0 , 27 , 211 }, /* index:  207   |11111111|11111111|11111100|000  */
    { 0x7ffffe1 , 27 , 212 }, /* index:  208   |11111111|11111111|11111100|001  */
    { 0x7ffffe2 , 27 , 214 }, /* index:  209   |11111111|11111111|11111100|010  */
    { 0x7ffffe3 , 27 , 221 }, /* index:  210   |11111111|11111111|11111100|011  */
    { 0x7ffffe4 , 27 , 222 }, /* index:  211   |11111111|11111111|11111100|100  */
    { 0x7ffffe5 , 27 , 223 }, /* index:  212   |11111111|11111111|11111100|101  */
    { 0x7ffffe6 , 27 , 241 }, /* index:  213   |11111111|11111111|11111100|110  */
    { 0x7ffffe7 , 27 , 244 }, /* index:  214   |11111111|11111111|11111100|111  */
    { 0x7ffffe8 , 27 , 245 }, /* index:  215   |11111111|11111111|11111101|000  */
    { 0x7ffffe9 , 27 , 246 }, /* index:  216   |11111111|11111111|11111101|001  */
    { 0x7ffffea , 27 , 247 }, /* index:  217   |11111111|11111111|11111101|010  */
    { 0x7ffffeb , 27 , 248 }, /* index:  218   |11111111|11111111|11111101|011  */
    { 0x7ffffec , 27 , 250 }, /* index:  219   |11111111|11111111|11111101|100  */
    { 0x7ffffed , 27 , 251 }, /* index:  220   |11111111|11111111|11111101|101  */
    { 0x7ffffee , 27 , 252 }, /* index:  221   |11111111|11111111|11111101|110  */
    { 0x7ffffef , 27 , 253 }, /* index:  222   |11111111|11111111|11111101|111  */
    { 0x7fffff0 , 27 , 254 }, /* index:  223   |11111111|11111111|11111110|000  */
    { 0xfffffe2 , 28 , 2 }, /* index:  224   |11111111|11111111|11111110|0010  */
    { 0xfffffe3 , 28 , 3 }, /* index:  225   |11111111|11111111|11111110|0011  */
    { 0xfffffe4 , 28 , 4 }, /* index:  226   |11111111|11111111|11111110|0100  */
    { 0xfffffe5 , 28 , 5 }, /* index:  227   |11111111|11111111|11111110|0101  */
    { 0xfffffe6 , 28 , 6 }, /* index:  228   |11111111|11111111|11111110|0110  */
    { 0xfffffe7 , 28 , 7 }, /* index:  229   |11111111|11111111|11111110|0111  */
    { 0xfffffe8 , 28 , 8 }, /* index:  230   |11111111|11111111|11111110|1000  */
    { 0xfffffe9 , 28 , 11 }, /* index:  231   |11111111|11111111|11111110|1001  */
    { 0xfffffea , 28 , 12 }, /* index:  232   |11111111|11111111|11111110|1010  */
    { 0xfffffeb , 28 , 14 }, /* index:  233   |11111111|11111111|11111110|1011  */
    { 0xfffffec , 28 , 15 }, /* index:  234   |11111111|11111111|11111110|1100  */
    { 0xfffffed , 28 , 16 }, /* index:  235   |11111111|11111111|11111110|1101  */
    { 0xfffffee , 28 , 17 }, /* index:  236   |11111111|11111111|11111110|1110  */
    { 0xfffffef , 28 , 18 }, /* index:  237   |11111111|11111111|11111110|1111  */
    { 0xffffff0 , 28 , 19 }, /* index:  238   |11111111|11111111|11111111|0000  */
    { 0xffffff1 , 28 , 20 }, /* index:  239   |11111111|11111111|11111111|0001  */
    { 0xffffff2 , 28 , 21 }, /* index:  240   |11111111|11111111|11111111|0010  */
    { 0xffffff3 , 28 , 23 }, /* index:  241   |11111111|11111111|11111111|0011  */
    { 0xffffff4 , 28 , 24 }, /* index:  242   |11111111|11111111|11111111|0100  */
    { 0xffffff5 , 28 , 25 }, /* index:  243   |11111111|11111111|11111111|0101  */
    { 0xffffff6 , 28 , 26 }, /* index:  244   |11111111|11111111|11111111|0110  */
    { 0xffffff7 , 28 , 27 }, /* index:  245   |11111111|11111111|11111111|0111  */
    { 0xffffff8 , 28 , 28 }, /* index:  246   |11111111|11111111|11111111|1000  */
    { 0xffffff9 , 28 , 29 }, /* index:  247   |11111111|11111111|11111111|1001  */
    { 0xffffffa , 28 , 30 }, /* index:  248   |11111111|11111111|11111111|1010  */
    { 0xffffffb , 28 , 31 }, /* index:  249   |11111111|11111111|11111111|1011  */
    { 0xffffffc , 28 , 127 }, /* index:  250   |11111111|11111111|11111111|1100  */
    { 0xffffffd , 28 , 220 }, /* index:  251   |11111111|11111111|11111111|1101  */
    { 0xffffffe , 28 , 249 }, /* index:  252   |11111111|11111111|11111111|1110  */
    { 0x3ffffffc , 30 , 10 }, /* index:  253   |11111111|11111111|11111111|111100  */
    { 0x3ffffffd , 30 , 13 }, /* index:  254   |11111111|11111111|11111111|111101  */
    { 0x3ffffffe , 30 , 22 }, /* index:  255   |11111111|11111111|11111111|111110  */
    { 0x3fffffff , 30 , 256 }, /* index:  256   |11111111|11111111|11111111|111111  */
};

static size_t nb_h3zero_qpack_huffman_base = sizeof(h3zero_qpack_huffman_base) / sizeof(h3zero_qpack_huffman_base_t);

int qpack_huffman_base_test()
{
    int ret = 0;
    uint8_t data[256];
    uint8_t input[256];
    size_t input_length;
    size_t nb_data;

    /* First, test all the valid values */
    for (size_t i = 0; ret == 0 && i < (nb_h3zero_qpack_huffman_base - 1); i++) {
        uint64_t val = h3zero_qpack_huffman_base[i].right_shift_hex << (64 - h3zero_qpack_huffman_base[i].nb_bits);
        uint64_t mask = UINT64_MAX >> h3zero_qpack_huffman_base[i].nb_bits;
        uint64_t val_in = val | mask;
        
        input_length = 0;
        for (int l = 0; 8 * l < h3zero_qpack_huffman_base[i].nb_bits; l++) {
            input[input_length++] = (uint8_t)(val_in >> 56);
            val_in <<= 8;
        }

        ret = hzero_qpack_huffman_decode(
            input,
            input + input_length,
            data, sizeof(data), &nb_data);
        if (ret == 0) {
            if (nb_data != 1) {
                DBG_PRINTF("Huffman base test %d bad length (%d vs %d)\n", (int)i,
                    (int)nb_data, 1);
                ret = -1;
            }
            else if (data[0] != h3zero_qpack_huffman_base[i].code) {
                DBG_PRINTF("Huffman base test %d does not match, %d instead of %d \n", (int)i,
                    data[0], h3zero_qpack_huffman_base[i].code);
                ret = -1;
            }
        }
        else {
            DBG_PRINTF("Huffman cannot decode base test %d\n", (int)i);
        }
    }

    /* Second, test a set of valid terminators */
    for (size_t i = 1; ret == 0 && i < 4; i++) {
        input_length = 0;
        for (size_t l = 0; l < i; l++) {
            input[input_length++] = 0xFF;
        }

        ret = hzero_qpack_huffman_decode(
            input,
            input + input_length,
            data, sizeof(data), &nb_data);
        if (ret == 0) {
            if (nb_data != 0) {
                DBG_PRINTF("Huffman eof test %d bad length (%d vs %d)\n", (int)i,
                    (int)nb_data, 0);
                ret = -1;
            }
        }
        else {
            DBG_PRINTF("Huffman cannot decode eof test %d\n", (int)i);
        }
    }
    return ret;
}


#define QPACK_HUFFMAN_TXT "qpack_huffman.txt"

/* Test decoding of basic QPACK messages */

#define QPACK_TEST_HEADER_BLOCK_PREFIX 0,0
#define QPACK_TEST_HEADER_BLOCK_PREFIX2 0,0x7F,0x18
#define QPACK_TEST_HEADER_INDEX_HTML 'i', 'n', 'd', 'e', 'x', '.', 'h', 't', 'm', 'l'
#define QPACK_TEST_HEADER_INDEX_HTML_LEN 10
#define QPACK_TEST_HEADER_PATH ':', 'p', 'a', 't', 'h'
#define QPACK_TEST_HEADER_PATH_LEN 5
#define QPACK_TEST_HEADER_RANGE 'r', 'a', 'n', 'g', 'e'
#define QPACK_TEST_HEADER_RANGE_LEN 5
#define QPACK_TEST_HEADER_STATUS ':', 's', 't', 'a', 't', 'u', 's'
#define QPACK_TEST_HEADER_STATUS_LEN 7
#define QPACK_TEST_HEADER_QPACK_PATH 0xFD, 0xFD, 0xFD 
#define QPACK_TEST_HEADER_DEQPACK_PATH 'Z', 'Z', 'Z'
#define QPACK_TEST_HEADER_HOST 0x50, 0x0b, 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm'
#define QPACK_TEST_HEADER_ALLOW_GET_POST 
#define QPACK_TEST_ALLOWED_METHODS 'G', 'E', 'T', ',', ' ', 'P', 'O', 'S', 'T', ',', ' ', 'C', 'O', 'N', 'N', 'E', 'C', 'T'
#define QPACK_TEST_ALLOWED_METHODS_LEN 18
#define QPACK_TEST_VALUE_RANGE10 'b', 'y', 't', 'e', 's', '=', '1', '-', '1', '0'
#define QPACK_TEST_VALUE_RANGE10_LEN 10
static uint8_t qpack_test_get_slash[] = {
    QPACK_TEST_HEADER_BLOCK_PREFIX, 0xC0|17, 0xC0 | 1 };

static uint8_t qpack_test_get_slash_null[] = {
    QPACK_TEST_HEADER_BLOCK_PREFIX, 0xC0 | 17, 0xC0 | 23,
    0x51, 1, '/',
    QPACK_TEST_HEADER_HOST
};

static uint8_t qpack_test_get_slash_prefix[] = {
    QPACK_TEST_HEADER_BLOCK_PREFIX2, 0xC0 | 17, 0xC0 | 1 };
static uint8_t qpack_test_get_index_html[] = {
    QPACK_TEST_HEADER_BLOCK_PREFIX, 0xC0 | 17, 0x50 | 1,
    QPACK_TEST_HEADER_INDEX_HTML_LEN, QPACK_TEST_HEADER_INDEX_HTML };
static uint8_t qpack_test_get_index_html_long[] = {
    QPACK_TEST_HEADER_BLOCK_PREFIX, 0xC0 | 17, 
    0x20 | QPACK_TEST_HEADER_PATH_LEN, QPACK_TEST_HEADER_PATH,
    QPACK_TEST_HEADER_INDEX_HTML_LEN, QPACK_TEST_HEADER_INDEX_HTML };
static uint8_t qpack_test_status_404[] = {
    QPACK_TEST_HEADER_BLOCK_PREFIX, 0xC0 | 27 };
static uint8_t qpack_test_status_404_code[] = {
    QPACK_TEST_HEADER_BLOCK_PREFIX, 0x50 | 0x0F, 13, 3, '4', '0', '4' };
static uint8_t qpack_test_status_404_long[] = {
    QPACK_TEST_HEADER_BLOCK_PREFIX, 0x20|0x07, 
    QPACK_TEST_HEADER_STATUS_LEN - 7, QPACK_TEST_HEADER_STATUS,
    3, '4', '0', '4' };
static uint8_t qpack_test_response_html[] = {
    QPACK_TEST_HEADER_BLOCK_PREFIX, 0xC0 | 25, 0xC0 | 52 };
static uint8_t qpack_test_status_405_code[] = {
    QPACK_TEST_HEADER_BLOCK_PREFIX, 0x50 | 0x0F, 13, 3, '4', '0', '5',
    0xFF, (uint8_t)(H3ZERO_QPACK_ALLOW_GET - 63)};
static uint8_t qpack_test_status_405_null[] = {
    QPACK_TEST_HEADER_BLOCK_PREFIX, 0x50 | 0x0F,  H3ZERO_QPACK_CODE_404 - 0x0F, 3, '4', '0', '5',
    0x50 | 0x0F, H3ZERO_QPACK_ALLOW_GET - 0x0F,
    QPACK_TEST_ALLOWED_METHODS_LEN, QPACK_TEST_ALLOWED_METHODS };

static uint8_t qpack_test_get_zzz[] = {
    QPACK_TEST_HEADER_BLOCK_PREFIX, 0xC0 | 17, 0x50 | 1,
    0x80 | 3, QPACK_TEST_HEADER_QPACK_PATH };

static uint8_t qpack_test_get_1234[] = {
    0x00, 0x00, 0xd1, 0xd7, 0x51, 0x84, 0x60, 0x22,
    0x65, 0xaf, 0x50, 0x94, 0x49, 0x50, 0x95, 0xeb,
    0xb0, 0xdd, 0xc6, 0x92, 0x9c, 0x89, 0x3d, 0x76,
    0xa1, 0x72, 0x1e, 0x9b, 0x8d, 0x34, 0xcb, 0x3f
};

static uint8_t qpack_test_get_ats[] = {
    0x00, 0x00, 0x50, 0x8a, 0xed, 0x69, 0x88, 0xb9,
    0xe6, 0xb0, 0xab, 0x90, 0xf4, 0xff, 0xd1, 0xc1,
    0xd7
};

static uint8_t qpack_test_get_ats2[] = {
    0x00, 0x00, 0x50, 0x90, 0x49, 0x50, 0x95, 0xeb,
    0xb0, 0xdd, 0xc6, 0x92, 0x9c, 0x89, 0x3d, 0x76,
    0xa1, 0x72, 0x1e, 0x9f, 0xd1, 0xc1, 0xd7
};

static uint8_t qpack_test_post_zzz[] = {
    QPACK_TEST_HEADER_BLOCK_PREFIX, 0xC0 | 20, 0xC0 | 23,
    0x50 | 1, 0x80 | 3, QPACK_TEST_HEADER_QPACK_PATH, 0xF5
};

static uint8_t qpack_test_post_zzz_null[] = {
    QPACK_TEST_HEADER_BLOCK_PREFIX, 0xC0 | 20, 0xC0 | 23,
    0x50 | 1, 3, QPACK_TEST_HEADER_DEQPACK_PATH,
    QPACK_TEST_HEADER_HOST, 0xF5
};

static uint8_t qpack_status200_akamai[] = {
    0x00, 0x00, 0xd9, 0x54, 0x84, 0x08, 0x04, 0xd0,
    0x3f, 0x5f, 0x1d, 0x90, 0x1d, 0x75, 0xd0, 0x62,
    0x0d, 0x26, 0x3d, 0x4c, 0x1c, 0x89, 0x2a, 0x56,
    0x42, 0x6c, 0x28, 0xe9, 0xe3
};

static uint8_t qpack_test_get_slash_range[] = {
    QPACK_TEST_HEADER_BLOCK_PREFIX, 0xC0 | 17, 0xC0 | 1,
    0x5f, 0x28, QPACK_TEST_VALUE_RANGE10_LEN, QPACK_TEST_VALUE_RANGE10
};

static uint8_t qpack_test_get_slash_range_long[] = {
    QPACK_TEST_HEADER_BLOCK_PREFIX, 0xC0 | 17, 0xC0 | 1,
    0x20 | QPACK_TEST_HEADER_RANGE_LEN, QPACK_TEST_HEADER_RANGE,
    QPACK_TEST_VALUE_RANGE10_LEN, QPACK_TEST_VALUE_RANGE10
};

#define FILE_10Z '0', '0', '0', '0', '0', '0', '0', '0', '0', '0'
#define FILE_50Z FILE_10Z , FILE_10Z , FILE_10Z , FILE_10Z , FILE_10Z
#define FILE_100Z  FILE_50Z , FILE_50Z
#define FILE_NAME_LONG FILE_100Z , FILE_100Z , FILE_50Z , '0', '0', '3', '2'

static uint8_t qpack_get_long_file_name[] = {
     0x00, 0x00, 0xd1, 0xd7, 0x51, 0x7f, 0x80, 0x01,
     '/', FILE_NAME_LONG,
     0x50, 0x10, 0x74, 0x65, 0x73, 0x74, 0x2e, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d
};

/* 
* From RFC 8441 and draft-ietf-webtrans-http3-01.html :
*   HEADERS + END_HEADERS
*   :method = CONNECT
*   : protocol = webtransport
*   : scheme = https
*   : path = /wtp
*   : authority = example.com
*   origin = http ://www.example.com
*/

#define CONNECT_TEST_PROTOCOL_PATH '/', 'w', 't', 'p'
#define CONNECT_TEST_PROTOCOL_PATH_LEN 4
#define CONNECT_TEST_PROTOCOL_PSH ':', 'p', 'r', 'o', 't', 'o', 'c', 'o', 'l'
#define CONNECT_TEST_PROTOCOL_PSH_LEN 9
#define CONNECT_TEST_PROTOCOL_WTP 'w', 'e', 'b', 't', 'r', 'a', 'n', 's', 'p', 'o', 'r', 't'
#define CONNECT_TEST_PROTOCOL_WTP_LEN 12
#define CONNECT_TEST_AUTHORITY 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm'
#define CONNECT_TEST_AUTHORITY_LEN 11
#define CONNECT_TEST_ORIGIN 'h', 't', 't', 'p', 's', ':', '/', '/', CONNECT_TEST_AUTHORITY
#define CONNECT_TEST_ORIGIN_LEN (8 + CONNECT_TEST_AUTHORITY_LEN)

char const web_transport_str[] = { CONNECT_TEST_PROTOCOL_WTP, 0 };

static uint8_t qpack_connect_webtransport[] = {
    QPACK_TEST_HEADER_BLOCK_PREFIX, 
    0xC0 | 15, 
    0x50 | 1,
    CONNECT_TEST_PROTOCOL_PATH_LEN, CONNECT_TEST_PROTOCOL_PATH,
    0x27, CONNECT_TEST_PROTOCOL_PSH_LEN - 7, CONNECT_TEST_PROTOCOL_PSH,
    CONNECT_TEST_PROTOCOL_WTP_LEN, CONNECT_TEST_PROTOCOL_WTP,
    0xC0 | 23, /* Scheme HTTPs, QPACK: 23 */
    0x50 | 0, /* Header: authority */
    CONNECT_TEST_AUTHORITY_LEN, CONNECT_TEST_AUTHORITY,
    0x50 | 0x0F, 90 - 0x0F, /* header: origin */
    CONNECT_TEST_ORIGIN_LEN, CONNECT_TEST_ORIGIN
};

static uint8_t qpack_test_string_index_html[] = { QPACK_TEST_HEADER_INDEX_HTML };
static uint8_t qpack_test_string_slash[] = { '/' };
static uint8_t qpack_test_string_zzz[] = { 'Z', 'Z', 'Z' };
static uint8_t qpack_test_string_1234[] = { '/', '1', '2', '3', '4' };
static uint8_t qpack_test_string_long[] = { '/', FILE_NAME_LONG };
static uint8_t qpack_test_string_wtp[] = { CONNECT_TEST_PROTOCOL_PATH };
static uint8_t qpack_test_range_text[] = { 'b', 'y', 't', 'e', 's', '=', '1', '-', '1', '0' };

typedef struct st_qpack_test_case_t {
    uint8_t * bytes;
    size_t bytes_length;
    h3zero_header_parts_t parts;
} qpack_test_case_t;

static qpack_test_case_t qpack_test_case[] = {
    {
        qpack_test_get_slash, sizeof(qpack_test_get_slash),
        { h3zero_method_get, qpack_test_string_slash, 1, NULL, 0, 0, 0, NULL, 0}
    },
    {
        qpack_test_get_slash_null, sizeof(qpack_test_get_slash_null),
        { h3zero_method_get, qpack_test_string_slash, 1, NULL, 0, 0, 0, NULL, 0}
    },
    {
        qpack_test_get_slash_prefix, sizeof(qpack_test_get_slash_prefix),
        { h3zero_method_get, qpack_test_string_slash, 1, NULL, 0, 0, 0, NULL, 0}
    },
    {
        qpack_test_get_index_html, sizeof(qpack_test_get_index_html),
        { h3zero_method_get, qpack_test_string_index_html, QPACK_TEST_HEADER_INDEX_HTML_LEN, NULL, 0, 0, 0, NULL, 0}
    },
    {
        qpack_test_get_index_html_long, sizeof(qpack_test_get_index_html_long),
        { h3zero_method_get, qpack_test_string_index_html, QPACK_TEST_HEADER_INDEX_HTML_LEN, NULL, 0, 0, 0, NULL, 0}
    },
    {
        qpack_test_status_404, sizeof(qpack_test_status_404),
        { 0, NULL, 0, NULL, 0, 404, 0, NULL, 0}
    },
    {
        qpack_test_status_404_code, sizeof(qpack_test_status_404_code),
        { 0, NULL, 0, NULL, 0, 404, 0, NULL, 0}
    },
    {
        qpack_test_status_404_long, sizeof(qpack_test_status_404_long),
        { 0, NULL, 0, NULL, 0, 404, 0, NULL, 0}
    },
    {
        qpack_test_response_html, sizeof(qpack_test_response_html),
        { 0, NULL, 0, NULL, 0, 200, h3zero_content_type_text_html, NULL, 0}
    },
    {
        qpack_test_status_405_code, sizeof(qpack_test_status_405_code),
        { 0, NULL, 0, NULL, 0, 405, 0, NULL, 0}
    },
    {
        qpack_test_status_405_null, sizeof(qpack_test_status_405_null),
        { 0, NULL, 0, NULL, 0, 405, 0, NULL, 0}
    },
    {
        qpack_test_get_zzz, sizeof(qpack_test_get_zzz),
        { h3zero_method_get, qpack_test_string_zzz, sizeof(qpack_test_string_zzz), NULL, 0, 0, 0, NULL, 0}
    },
    {
        qpack_test_get_1234, sizeof(qpack_test_get_1234),
        { h3zero_method_get, qpack_test_string_1234, sizeof(qpack_test_string_1234), NULL, 0, 0, 0, NULL, 0}
    },
    {
        qpack_test_get_ats, sizeof(qpack_test_get_ats),
        { h3zero_method_get, qpack_test_string_slash, sizeof(qpack_test_string_slash), NULL, 0, 0, 0, NULL, 0}
    },
    {
        qpack_test_get_ats2, sizeof(qpack_test_get_ats2),
        { h3zero_method_get, qpack_test_string_slash, sizeof(qpack_test_string_slash), NULL, 0, 0, 0, NULL, 0}
    },
    {
        qpack_test_post_zzz, sizeof(qpack_test_post_zzz),
        { h3zero_method_post, qpack_test_string_zzz, sizeof(qpack_test_string_zzz), NULL, 0, 0, h3zero_content_type_text_plain, NULL, 0}
    },
    {
        qpack_test_post_zzz_null, sizeof(qpack_test_post_zzz_null),
        { h3zero_method_post, qpack_test_string_zzz, sizeof(qpack_test_string_zzz), NULL, 0, 0, h3zero_content_type_text_plain, NULL, 0}
    },
    {
        qpack_status200_akamai, sizeof(qpack_status200_akamai),
        { h3zero_method_none, NULL, 0, NULL, 0, 200, h3zero_content_type_not_supported, NULL, 0}
    },
    {
        qpack_get_long_file_name, sizeof(qpack_get_long_file_name),
        { h3zero_method_get, qpack_test_string_long, sizeof(qpack_test_string_long), NULL, 0, 0, 0, NULL, 0}
    },
    {
        qpack_connect_webtransport, sizeof(qpack_connect_webtransport),
        { h3zero_method_connect, qpack_test_string_wtp, sizeof(qpack_test_string_wtp), NULL, 0, 0, 0,
        (uint8_t *)web_transport_str, CONNECT_TEST_PROTOCOL_WTP_LEN}
    },
    {
        qpack_test_get_slash_range, sizeof(qpack_test_get_slash_range),
        { h3zero_method_get, qpack_test_string_slash, 1,
        qpack_test_range_text, sizeof(qpack_test_range_text),
        0, 0, NULL, 0}
    },
    {
        qpack_test_get_slash_range_long, sizeof(qpack_test_get_slash_range_long),
        { h3zero_method_get, qpack_test_string_slash, 1,
        qpack_test_range_text, sizeof(qpack_test_range_text),
        0, 0, NULL, 0}
    }
};

static size_t nb_qpack_test_case = sizeof(qpack_test_case) / sizeof(qpack_test_case_t);

static int h3zero_parse_qpack_test_one(size_t i, uint8_t * data, size_t data_length)
{
    int ret = 0;
    uint8_t * bytes;
    h3zero_header_parts_t parts;

    bytes = h3zero_parse_qpack_header_frame(data, data + data_length, &parts);

    if (bytes == 0) {
        DBG_PRINTF("Qpack case %d cannot be parsed", i);
        ret = -1;
    }
    else if ((bytes - data) != data_length) {
        DBG_PRINTF("Qpack case %d parse wrong length", i);
        ret = -1;
    }
    else if (parts.method != qpack_test_case[i].parts.method) {
        DBG_PRINTF("Qpack case %d parse wrong method", i);
        ret = -1;
    }
    else if (parts.path_length != qpack_test_case[i].parts.path_length) {
        DBG_PRINTF("Qpack case %d parse wrong path length", i);
        ret = -1;
    }
    else if (parts.path == NULL && qpack_test_case[i].parts.path != NULL) {
        DBG_PRINTF("Qpack case %d parse path not null", i);
        ret = -1;
    }
    else if (parts.path != NULL && qpack_test_case[i].parts.path == NULL) {
        DBG_PRINTF("Qpack case %d parse null path", i);
        ret = -1;
    }
    else if (parts.path != NULL && parts.path_length > 0 &&
        memcmp(parts.path, qpack_test_case[i].parts.path, parts.path_length) != 0) {
        DBG_PRINTF("Qpack case %d parse wrong path", i);
        ret = -1;
    } else if (parts.range_length != qpack_test_case[i].parts.range_length) {
        DBG_PRINTF("Qpack case %d parse wrong range length", i);
        ret = -1;
    }
    else if (parts.range == NULL && qpack_test_case[i].parts.range_length > 0) {
        DBG_PRINTF("Qpack case %d parse range not null", i);
        ret = -1;
    }
    else if (parts.range_length > 0 &&
        memcmp(parts.range, qpack_test_case[i].parts.range, parts.range_length) != 0) {
        DBG_PRINTF("Qpack case %d parse wrong range", i);
        ret = -1;
    }
    else if (parts.status != qpack_test_case[i].parts.status) {
        DBG_PRINTF("Qpack case %d parse wrong status", i);
        ret = -1;
    }
    else if (parts.content_type != qpack_test_case[i].parts.content_type) {
        DBG_PRINTF("Qpack case %d parse wrong content_type", i);
        ret = -1;
    }
    else if (parts.protocol_length != qpack_test_case[i].parts.protocol_length) {
        DBG_PRINTF("Qpack case %d parse wrong protocol length", i);
        ret = -1;
    }
    else if (parts.protocol == NULL && qpack_test_case[i].parts.protocol != NULL) {
        DBG_PRINTF("Qpack case %d parse path not null", i);
        ret = -1;
    }
    else if (parts.protocol != NULL && parts.protocol_length > 0 &&
        memcmp(parts.protocol, qpack_test_case[i].parts.protocol, parts.protocol_length) != 0) {
        DBG_PRINTF("Qpack case %d parse wrong path", i);
        ret = -1;
    }

    h3zero_release_header_parts(&parts);

    return ret;
}

int h3zero_parse_qpack_test()
{
    int ret = 0;

    for (size_t i = 0; ret == 0 && i < nb_qpack_test_case; i++) {
        ret = h3zero_parse_qpack_test_one(i,
            qpack_test_case[i].bytes, qpack_test_case[i].bytes_length);
        if (ret != 0) {
            DBG_PRINTF("Parse QPACK test %d fails.\n", i);
        }
    }

    return ret;
}

/*
 * Prepare frames of the different supported types, and 
 * verify that they can be decoded as expected
 */
int h3zero_prepare_qpack_test()
{
    int ret = 0;
    int qpack_compare_test[] = { 0, 2, 4, 7, 8, 13, 20, -1 };
    
    for (int i = 0; ret == 0 && qpack_compare_test[i] >= 0; i++) {
        uint8_t buffer[256];
        uint8_t * bytes_max = &buffer[0] + sizeof(buffer);
        uint8_t * bytes = NULL;
        int j = qpack_compare_test[i];

        if (qpack_test_case[j].parts.path != NULL) {
            if (qpack_test_case[j].parts.method == h3zero_method_get)
            {
                /* Create a request header */
                bytes = h3zero_create_request_header_frame_ex(buffer, bytes_max,
                    qpack_test_case[j].parts.path, qpack_test_case[j].parts.path_length,
                    qpack_test_case[j].parts.range, qpack_test_case[j].parts.range_length,
                    "example.com", NULL);
            }
            else  if (qpack_test_case[j].parts.method == h3zero_method_post)
            {
                /* Create a post header */
                bytes = h3zero_create_post_header_frame(buffer, bytes_max,
                    qpack_test_case[j].parts.path, qpack_test_case[j].parts.path_length, "example.com", h3zero_content_type_text_plain);
            }
            else {
                DBG_PRINTF("Case %d, unexpected method: %d\n", j, qpack_test_case[j].parts.method);
                ret = -1;
                break;
            }
        }
        else if (qpack_test_case[j].parts.content_type != 0) {
            bytes = h3zero_create_response_header_frame(buffer, bytes_max,
                qpack_test_case[j].parts.content_type);
        } else if (qpack_test_case[j].parts.status == 404) {
            bytes = h3zero_create_not_found_header_frame(buffer, bytes_max);
        } else if (qpack_test_case[j].parts.status == 405) {
            bytes = h3zero_create_bad_method_header_frame(buffer, bytes_max);
        }

        if (bytes == NULL) {
            DBG_PRINTF("Prepare qpack test %d failed\n", j);
            ret = -1;
        }
        else {
            ret = h3zero_parse_qpack_test_one((size_t)j, buffer, bytes - buffer);
        }
    }

    return ret;
}

/* Check that the user agent string is correctly set.
 */

#define QPACK_TEST_UA_STRING 'H', '3', 'Z', 'e', 'r', 'o', '/', '1', '.', '0'
#define QPACK_TEST_UA_STRING_LEN 10
#define QPACK_TEST_UA_STRING_TEST 'T', 'e', 's', 't', '/', '1', '.', '0'
#define QPACK_TEST_UA_STRING_TEST_LEN 8
char const h3zero_test_ua_string[] = { QPACK_TEST_UA_STRING_TEST, 0 };
char const h3zero_test_ua_post_path[] = { QPACK_TEST_HEADER_DEQPACK_PATH, 0 };

static uint8_t qpack_test_get_slash_ua[] = {
    QPACK_TEST_HEADER_BLOCK_PREFIX, 0xC0 | 17, 0xC0 | 23,
    0x51, 1, '/',
    QPACK_TEST_HEADER_HOST,
    0x5f, 95 - 0x0f, QPACK_TEST_UA_STRING_LEN, QPACK_TEST_UA_STRING
};
static uint8_t qpack_test_post_zzz_ua[] = {
    QPACK_TEST_HEADER_BLOCK_PREFIX, 0xC0 | 20, 0xC0 | 23,
    0x50 | 1, 3, QPACK_TEST_HEADER_DEQPACK_PATH,
    QPACK_TEST_HEADER_HOST,
    0x5f, 95 - 0x0f, QPACK_TEST_UA_STRING_LEN, QPACK_TEST_UA_STRING, 0xF5
};
static uint8_t qpack_test_status_404_srv[] = {
    QPACK_TEST_HEADER_BLOCK_PREFIX, 0xC0 | 27,
    0x5f, 92 - 0x0f, QPACK_TEST_UA_STRING_LEN, QPACK_TEST_UA_STRING
};
static uint8_t qpack_test_status_405_srv[] = {
    QPACK_TEST_HEADER_BLOCK_PREFIX, 0x50 | 0x0F,  H3ZERO_QPACK_CODE_404 - 0x0F, 3, '4', '0', '5',
    0x5f, 92 - 0x0f, QPACK_TEST_UA_STRING_LEN, QPACK_TEST_UA_STRING,
    0x50 | 0x0F, H3ZERO_QPACK_ALLOW_GET - 0x0F,
    QPACK_TEST_ALLOWED_METHODS_LEN, QPACK_TEST_ALLOWED_METHODS };
static uint8_t qpack_test_get_slash_ua2[] = {
    QPACK_TEST_HEADER_BLOCK_PREFIX, 0xC0 | 17, 0xC0 | 23,
    0x51, 1, '/',
    QPACK_TEST_HEADER_HOST,
    0x5f, 95 - 0x0f, QPACK_TEST_UA_STRING_TEST_LEN, QPACK_TEST_UA_STRING_TEST
};
static uint8_t qpack_test_post_zzz_ua2[] = {
    QPACK_TEST_HEADER_BLOCK_PREFIX, 0xC0 | 20, 0xC0 | 23,
    0x50 | 1, 3, QPACK_TEST_HEADER_DEQPACK_PATH,
    QPACK_TEST_HEADER_HOST,
    0x5f, 95 - 0x0f, QPACK_TEST_UA_STRING_TEST_LEN, QPACK_TEST_UA_STRING_TEST, 0xF5
};
static uint8_t qpack_test_status_404_srv2[] = {
    QPACK_TEST_HEADER_BLOCK_PREFIX, 0xC0 | 27,
    0x5f, 92 - 0x0f, QPACK_TEST_UA_STRING_TEST_LEN, QPACK_TEST_UA_STRING_TEST
};
static uint8_t qpack_test_status_405_srv2[] = {
    QPACK_TEST_HEADER_BLOCK_PREFIX, 0x50 | 0x0F, H3ZERO_QPACK_CODE_404 - 0x0F, 3, '4', '0', '5',
    0x5f, 92 - 0x0f, QPACK_TEST_UA_STRING_TEST_LEN, QPACK_TEST_UA_STRING_TEST,
    0x50 | 0x0F, H3ZERO_QPACK_ALLOW_GET - 0x0F,
    QPACK_TEST_ALLOWED_METHODS_LEN, QPACK_TEST_ALLOWED_METHODS };

typedef struct st_h3zero_user_agent_case_t {
    uint8_t* data;
    size_t data_length;
} h3zero_user_agent_case_t;

h3zero_user_agent_case_t h3zero_user_agent_case_null[4] = {
    { qpack_test_get_slash_null, sizeof(qpack_test_get_slash_null)},
    { qpack_test_post_zzz_null, sizeof(qpack_test_post_zzz_null)},
    { qpack_test_status_404, sizeof(qpack_test_status_404)},
    { qpack_test_status_405_null, sizeof(qpack_test_status_405_null)}
};

h3zero_user_agent_case_t h3zero_user_agent_case_default[4] = {
    { qpack_test_get_slash_ua, sizeof(qpack_test_get_slash_ua)},
    { qpack_test_post_zzz_ua, sizeof(qpack_test_post_zzz_ua)},
    { qpack_test_status_404_srv, sizeof(qpack_test_status_404_srv)},
    { qpack_test_status_405_srv, sizeof(qpack_test_status_405_srv)}
};

h3zero_user_agent_case_t h3zero_user_agent_case_test[4] = {
    { qpack_test_get_slash_ua2, sizeof(qpack_test_get_slash_ua2)},
    { qpack_test_post_zzz_ua2, sizeof(qpack_test_post_zzz_ua2)},
    { qpack_test_status_404_srv2, sizeof(qpack_test_status_404_srv2)},
    { qpack_test_status_405_srv2, sizeof(qpack_test_status_405_srv2)}
};

h3zero_user_agent_case_t* h3zero_user_agent_test_list[3] = {
    h3zero_user_agent_case_null,
    h3zero_user_agent_case_default,
    h3zero_user_agent_case_test
};

int h3zero_user_agent_test_one(int test_mode, char const * ua_string, uint8_t * target, size_t target_length)
{
    int ret = 0;
    uint8_t buffer[256];
    uint8_t* bytes_max = &buffer[0] + sizeof(buffer);
    uint8_t* bytes = NULL;
    size_t length = 0;

    switch (test_mode) {
    case 0:
        bytes = h3zero_create_request_header_frame_ex(buffer, bytes_max,
            (uint8_t*)"/", 1, NULL, 0, "example.com", ua_string);
        break;
    case 1:
        bytes = h3zero_create_post_header_frame_ex(buffer, bytes_max,
            (uint8_t *)h3zero_test_ua_post_path, strlen(h3zero_test_ua_post_path),
            NULL, 0, "example.com", h3zero_content_type_text_plain, ua_string);
        break;
    case 2:
        bytes = h3zero_create_not_found_header_frame_ex(buffer, bytes_max, ua_string);
        break;
    case 3:
        bytes = h3zero_create_bad_method_header_frame_ex(buffer, bytes_max, ua_string);
        break;
    default:
        DBG_PRINTF("Unexpected test mode: %d", test_mode);
        ret = -1;
        break;
    }
    if (ret == 0 && bytes == NULL) {
        DBG_PRINTF("Encoding fails test mode: %d, ua string %s", test_mode, (ua_string == NULL)?"NULL":ua_string);
        ret = -1;
    }
    if (ret == 0) {
        length = (bytes - buffer);
        if (length != target_length) {
            DBG_PRINTF("Bad length (%d vs %d), test mode: %d, ua string %s", length, target_length, test_mode, (ua_string == NULL) ? "NULL" : ua_string);
            ret = -1;
        } else if (memcmp(buffer, target, target_length) != 0) {
            DBG_PRINTF("Content does not match, test mode : %d, ua string %s", test_mode, (ua_string == NULL) ? "NULL" : ua_string);
            ret = -1;
        }
    }
    return ret;
}

int h3zero_user_agent_test()
{
    int ret = 0;
    char const* ua_string[3] = { NULL, H3ZERO_USER_AGENT_STRING, h3zero_test_ua_string };

    for (int ua_x = 0; ret == 0 && ua_x < 3; ua_x++) {
        h3zero_user_agent_case_t* test_list = h3zero_user_agent_test_list[ua_x];
        for (int test_mode = 0; ret == 0 && test_mode < 4; test_mode++) {
            ret = h3zero_user_agent_test_one(test_mode, ua_string[ua_x], test_list[test_mode].data, test_list[test_mode].data_length);
            if (ret != 0) {
                DBG_PRINTF("Test fails, test mode : %d, ua_x : %d", test_mode,ua_x);
            }
        }
    }

    return ret;
}

int h3zero_null_sni_test()
{
    int ret = 0;
    int hret;
    uint8_t buffer[256];
    size_t consumed = 0;
    
    hret = h3zero_client_create_stream_request(buffer, 256,
        (uint8_t const *)"/", 1, 0, NULL, &consumed);
    if (hret == 0) {
        DBG_PRINTF("%s", "Unexpected success, create request header with NULL host");
            ret = -1;
    }
    else {
        hret = h3zero_client_create_stream_request(buffer, 256,
            (uint8_t const*)"/", 1, 0, NULL, &consumed);
        if (hret == 0) {
            DBG_PRINTF("%s", "Unexpected success, create post header with NULL host");
            ret = -1;
        }
    }
    return ret;
}

/* Fuzz test of the qpack parser.
 * Start from valid frames, stick several of them in a buffer,
 * and then perform random changes in the packet.
 * Verify that the parser does not crash or loop.
 */

int h3zero_qpack_fuzz_test()
{
    uint8_t* bytes = malloc(PICOQUIC_MAX_PACKET_SIZE);
    size_t length = 0;
    uint64_t random_context = 0x123456789ABCDEF0;
    int ret = (bytes == NULL) ? -1 : 0;
    int n_good = 0;
    int n_trials = 0;

    for (size_t x = 0; ret == 0 && x < nb_qpack_test_case; x++) {
        for (length = 0; length < qpack_test_case[x].bytes_length - 1; length++) {
            h3zero_header_parts_t parts = { 0 };
            uint8_t* parsed = NULL;

            memcpy(bytes, qpack_test_case[x].bytes, length);
            if (length < sizeof(bytes)) {
                memset(bytes + length, 0, sizeof(bytes) - length);
            }

            parsed = h3zero_parse_qpack_header_frame(bytes, bytes + length, &parts);
            h3zero_release_header_parts(&parts);
            n_good += (parsed != NULL) ? 1 : 0;
            n_trials++;
        }
    }

    for (int i = 0; ret == 0 && i < 512; i++) {
        size_t x = (size_t)picoquic_test_uniform_random(&random_context, nb_qpack_test_case);

        memcpy(bytes, qpack_test_case[x].bytes, qpack_test_case[x].bytes_length);
        length = qpack_test_case[x].bytes_length;

        for (x = 0; x < length; x++) {
            h3zero_header_parts_t parts;
            uint8_t* parsed = bytes;
            uint8_t* bytes_max = bytes + length;
            size_t y = (size_t)picoquic_test_uniform_random(&random_context, length);
            size_t m = (size_t)picoquic_test_uniform_random(&random_context, 8);
            bytes[y] ^= (uint8_t)(1 << m);

            while (parsed != NULL && parsed < bytes_max) {
                /* Attempt to parse the next header.
                 * the test succeeds if that does not cause a crash */
                memset(&parts, 0, sizeof(parts));
                parsed = h3zero_parse_qpack_header_frame(parsed, bytes_max, &parts);
                h3zero_release_header_parts(&parts);
                n_good += (parsed != NULL) ? 1 : 0;
                n_trials++;
            }
        }
    }
    if (ret == 0) {
        DBG_PRINTF("qpack_fuzz: %d goods out of %d trials", n_good, n_trials);
    }

    if (bytes != NULL) {
        free(bytes);
    }

    return ret;
}


/*
 * Test of the stream decoding filter
 */

static uint8_t h3zero_stream_test1[] = {
    h3zero_frame_header, 4,
    QPACK_TEST_HEADER_BLOCK_PREFIX, 0xC0 | 17, 0xC0 | 1 };

#define H3ZERO_STREAM_TEST2_DATA 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l'

static uint8_t h3zero_stream_test2_data[] = { H3ZERO_STREAM_TEST2_DATA };

static uint8_t h3zero_stream_test2[] = {
    h3zero_frame_header, 4,
    QPACK_TEST_HEADER_BLOCK_PREFIX, 0xC0 | 25, 0xC0 | 52,
    h3zero_frame_data, 12,
    H3ZERO_STREAM_TEST2_DATA };

static uint8_t h3zero_stream_test3[] = {
    h3zero_frame_header, 0x40, 4,
    QPACK_TEST_HEADER_BLOCK_PREFIX, 0xC0 | 25, 0xC0 | 52,
    h3zero_frame_data, 12,
    H3ZERO_STREAM_TEST2_DATA,
    h3zero_frame_header, 8,
    QPACK_TEST_HEADER_BLOCK_PREFIX, 0x50 | 0x0F, 13, 3, '4', '0', '4'
};

static uint8_t h3zero_stream_test_grease[] = {
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 
    0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xfe, 0x12, 0x47, 0x52, 0x45, 0x41, 0x53, 0x45,
    0x20, 0x69, 0x73, 0x20, 0x74, 0x68, 0x65, 0x20,
    0x77, 0x6f, 0x72, 0x64, 0x01, 0x1f, 0x00, 0x00,
    0xd1, 0xd7, 0x50, 0x90, 0x49, 0x50, 0x95, 0xeb,
    0xb0, 0xdd, 0xc6, 0x92, 0x9c, 0x89, 0x3d, 0x76,
    0xa1, 0x72, 0x1e, 0x9f, 0xc1, 0x5f, 0x50, 0x85,
    0xed, 0x69, 0x89, 0x39, 0x7f
};

static uint8_t h3zero_stream_test_split3[] = {
    0x01, 0x40, 0x04, 0x00, 0x00, 0xd9, 0xf5, 0x00, 0x20,
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
    17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32 };

int h3zero_stream_test_one_split(uint8_t * bytes, size_t nb_bytes, 
    uint8_t ** bmax, int nb_splits,
    uint8_t * data_ref, size_t data_len, int has_trailer)
{
    int ret = 0;
    h3zero_data_stream_state_t stream_state;
    size_t nb_data = 0;
    uint8_t data[64];
    uint8_t packet_buffer[256];
    size_t available_data;
    uint64_t error_found;

    memset(&stream_state, 0, sizeof(h3zero_data_stream_state_t));

    for (int i = 0; ret == 0 && i < nb_splits && bytes != NULL; i++) {
        uint8_t* p = packet_buffer;
        uint8_t* p_max;
        size_t p_len = bmax[i] - bytes;
        memset(p, 0, sizeof(packet_buffer));
        memcpy(p, bytes, p_len);
        p_max = packet_buffer + p_len;
        while (p != NULL && p < p_max) {
            p = h3zero_parse_data_stream(p, p_max, &stream_state, &available_data, &error_found);
            if (p != NULL && available_data > 0) {
                if (nb_data + available_data > 64) {
                    ret = -1;
                }
                else {
                    memcpy(&data[nb_data], p, available_data);
                    p += available_data;
                    nb_data += available_data;
                }
            }
        }
        bytes = (p == NULL) ? NULL : bytes + (p - packet_buffer);
    }

    if (ret == 0) {
        if (bytes != bmax[nb_splits - 1]) {
            DBG_PRINTF("%s", "did not parse to the end!\n");
            ret = -1;
        }
        else if (stream_state.frame_header_parsed) {
            DBG_PRINTF("%s", "stopped with frame not parsed\n");
            ret = -1;
        }
        else if (!stream_state.header_found) {
            DBG_PRINTF("%s", "did not parse the first header\n");
            ret = -1;
        }
        else if (nb_data != data_len) {
            DBG_PRINTF("%s", "did not get right amount of data (%d vs %d)\n",
                (int)nb_data, (int)data_len);
            ret = -1;
        }
        else if (nb_data != 0 && memcmp(data, data_ref, nb_data) != 0) {
            DBG_PRINTF("%s", "did not get right amount of data (%d vs %d)\n",
                (int)nb_data, (int)data_len);
            ret = -1;
        }
        else if (has_trailer && !stream_state.trailer_found) {
            DBG_PRINTF("%s", "did not parse the trailer\n");
            ret = -1;
        }
        else if (!has_trailer && stream_state.trailer_found) {
            DBG_PRINTF("%s", "found an extra trailer\n");
            ret = -1;
        }
    }

    h3zero_delete_data_stream_state(&stream_state);
    return ret;
}

int h3zero_stream_test_one(uint8_t * bytes, size_t nb_bytes,
    uint8_t * data_ref, size_t data_len, int has_trailer)
{
    int ret = 0;

    for (size_t split = 0; ret == 0 && split < data_len; split++) {
        uint8_t* bmax[2] = { bytes + split, bytes + nb_bytes };
        ret = h3zero_stream_test_one_split(bytes, nb_bytes, bmax, 2, data_ref, data_len, has_trailer);
    }

    return ret;
}

int h3zero_stream_test()
{
    int ret = h3zero_stream_test_one(h3zero_stream_test1, sizeof(h3zero_stream_test1), NULL, 0, 0);

    if (ret == 0) {
        ret = h3zero_stream_test_one(h3zero_stream_test2, sizeof(h3zero_stream_test2), 
            h3zero_stream_test2_data, sizeof(h3zero_stream_test2_data), 0);
    }

    if (ret == 0) {
        ret = h3zero_stream_test_one(h3zero_stream_test3, sizeof(h3zero_stream_test3),
            h3zero_stream_test2_data, sizeof(h3zero_stream_test2_data), 1);
    }

    if (ret == 0) {
        ret = h3zero_stream_test_one(h3zero_stream_test_grease, sizeof(h3zero_stream_test_grease),
            NULL, 0, 0);
    }

    if (ret == 0) {
        uint8_t* bytes = h3zero_stream_test_split3;
        size_t nb_bytes = sizeof(h3zero_stream_test_split3);
        size_t split_max = 9;

        for (size_t split = 1; ret == 0 && split < split_max; split++) {
            uint8_t* bmax[3] = { bytes + split, bytes + split_max, bytes + nb_bytes };

            ret = h3zero_stream_test_one_split(bytes, nb_bytes, bmax, 3, bytes + split_max, nb_bytes - split_max, 0);

            if (ret != 0) {
                DBG_PRINTF("Stream reassembly fails for split: %d - %d - %d\n", (int)split, (int)split_max, (int)nb_bytes);
            }
        }
    }

    return ret;
}

/* H3Zero stream fuzz test
 */

uint8_t more_value_1[] = { 0x1f };
uint8_t more_value_8[] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, };
uint8_t push_id[] = { 0x1f };

#define FUZZ_MORE(more_type, more_value) { more_type, more_value, sizeof(more_value) }
#define FUZZ_HEADER(test_header) { h3zero_frame_header, test_header, sizeof(test_header) }
typedef struct st_fuzz_header_t {
    size_t header_type;
    const uint8_t* header;
    size_t header_length;
} fuzz_header_t;
fuzz_header_t fuzz_headers[] = {
    FUZZ_HEADER(qpack_test_get_slash_prefix),
    FUZZ_HEADER(qpack_test_get_index_html),
    FUZZ_HEADER(qpack_test_get_index_html_long),
    FUZZ_HEADER(qpack_test_status_404),
    FUZZ_HEADER(qpack_test_status_404_code),
    FUZZ_HEADER(qpack_test_status_404_long),
    FUZZ_HEADER(qpack_test_response_html),
    FUZZ_HEADER(qpack_test_status_405_code),
    FUZZ_HEADER(qpack_test_status_405_null),
    FUZZ_HEADER(qpack_test_get_zzz),
    FUZZ_HEADER(qpack_test_get_1234),
    FUZZ_HEADER(qpack_test_get_ats),
    FUZZ_HEADER(qpack_test_get_ats2),
    FUZZ_HEADER(qpack_test_post_zzz),
    FUZZ_HEADER(qpack_test_post_zzz_null),
    FUZZ_HEADER(qpack_status200_akamai),
    FUZZ_HEADER(qpack_test_get_slash_range),
    FUZZ_HEADER(qpack_test_get_slash_range_long),
    FUZZ_HEADER(qpack_get_long_file_name),
    FUZZ_MORE(0xabcd, more_value_1),
    FUZZ_MORE(0xabcd, more_value_8),
    FUZZ_MORE(0, more_value_1),
    FUZZ_MORE(0, more_value_8),
    FUZZ_MORE(h3zero_frame_cancel_push, push_id),
    FUZZ_MORE(h3zero_frame_max_push_id, push_id),
    FUZZ_MORE(h3zero_frame_goaway, push_id),
    { 0, more_value_1, 0 },
};

const size_t nb_fuzz_headers = sizeof(fuzz_headers) / sizeof(fuzz_header_t);

typedef enum {
    stream_fuzz_l0 = 0,
    stream_fuzz_l1,
    stream_fuzz_l2,
    stream_fuzz_l3,
    stream_fuzz_ln1,
    stream_fuzz_lt,
    stream_fuzz_max
} stream_fuzz_enum;

/* fuzzing a T-L-V frame */
uint8_t* h3zero_stream_fuzz_tlv(uint8_t* bytes, const uint8_t* bytes_max, uint64_t frame_type, size_t frame_length, const uint8_t * frame_value,
    size_t fuzz_index, int * errored)
{
    *errored = 0;
    uint8_t* byte0 = bytes;
    size_t coded_length = frame_length;
    switch (fuzz_index) {
    case stream_fuzz_l0:
        coded_length = 0;
        break;
    case stream_fuzz_l1:
        coded_length = 1;
        break;
    case stream_fuzz_l2:
        coded_length = 2;
        break;
    case stream_fuzz_l3:
        coded_length = 3;
        break;
    case stream_fuzz_ln1:
        coded_length = frame_length - 1;
        break;
    case stream_fuzz_max:
        break;
    default:
        break;
    }
    if (coded_length > frame_length) {
        coded_length = frame_length;
    }
    else if (coded_length != frame_length) {
        *errored = 1;
    }
    if (fuzz_index == stream_fuzz_lt) {
        if (bytes + 8 >= bytes_max) {
            bytes = NULL;
        }
        else {
            *bytes++ = (uint8_t)(((frame_type >> 56) & 0x3f) + 0xc0);
            *bytes++ = (uint8_t)((frame_type >> 48) & 0xff);
            *bytes++ = (uint8_t)((frame_type >> 40) & 0xff);
            *bytes++ = (uint8_t)((frame_type >> 32) & 0xff);
            *bytes++ = (uint8_t)((frame_type >> 24) & 0xff);
            *bytes++ = (uint8_t)((frame_type >> 16) & 0xff);
            *bytes++ = (uint8_t)((frame_type >> 8) & 0xff);
            *bytes++ = (uint8_t)(frame_type & 0xff);
        }
    }
    else {
        bytes = picoquic_frames_varint_encode(bytes, bytes_max, frame_type);
    }
    if (bytes  != NULL &&
        (bytes = picoquic_frames_varint_encode(bytes, bytes_max, coded_length)) != NULL &&
        bytes + frame_length <= bytes_max) {
        memcpy(bytes, frame_value, frame_length);
        bytes += frame_length;
    } else {
        bytes = byte0;
    }
    return bytes;
}

size_t h3zero_stream_fuzz_message(uint8_t* buffer, size_t buffer_size, size_t trial_rank)
{
    /* Pick a series of frames until one is fuzzed */
    uint8_t* bytes = buffer;
    uint8_t* bytes_max = buffer + buffer_size;
    size_t message_size = 0;
    size_t header_index;
    size_t fuzz_index;
    int errored = 0;
    uint8_t* bytes_0 = bytes;

    header_index = trial_rank % nb_fuzz_headers;
    trial_rank /= nb_fuzz_headers;
    fuzz_index = trial_rank % (size_t)2 * stream_fuzz_max;
    trial_rank /= (size_t)2 * stream_fuzz_max;

    if (fuzz_index < stream_fuzz_max) {
        fuzz_index = stream_fuzz_max;
    }
    else {
        fuzz_index -= stream_fuzz_max;
    }

    bytes = h3zero_stream_fuzz_tlv(bytes, bytes_max,
        fuzz_headers[header_index].header_type, fuzz_headers[header_index].header_length,
        fuzz_headers[header_index].header, fuzz_index, &errored);

    if (bytes == NULL) {
        bytes = bytes_0;
    }

    message_size = bytes - buffer;
    
    if (message_size > 0 && trial_rank > 0) {
        size_t nb_fuzz_bytes = trial_rank % 15;
        trial_rank >>= 4;
        if (nb_fuzz_bytes > 0 && nb_fuzz_bytes < 5) {
            uint8_t* fuzzed_byte = bytes_0 + (trial_rank % message_size);
            trial_rank /= message_size;

            while (message_size > 0 && trial_rank > 0) {
                fuzzed_byte++;
                if (fuzzed_byte >= buffer + message_size) {
                    fuzzed_byte = buffer;
                }
                *fuzzed_byte ^= (uint8_t)(trial_rank ^ 0xff);
                trial_rank >>= 8;
            }
        }
    }
    return message_size;
}

int h3zero_stream_fuzz_test()
{
    int ret = 0;
    size_t buffer_size = 0x10000;
    uint8_t* packet_buffer = malloc(buffer_size);
    int nb_good = 0;
    int nb_bad = 0;
    size_t nb_trials = 2048;
    int errors_found[6] = { 0, 0, 0, 0, 0, 0 };
    char const * errors_names[6] = {
        "error no error",
        "frame unexpected",
        "internal error",
        "general protocol error",
        "frame error",
        "other errors" };

    if (packet_buffer == NULL) {
        ret = -1;
    }
    else {
        uint64_t error_found = 0;
        uint8_t* p = packet_buffer;
        uint64_t trial_random_ctx = 0xdeadbeef;
        size_t p_len = 0;
        uint8_t* p_max;

        for (size_t trial_rank = 0; ret == 0 && trial_rank < nb_trials; trial_rank++) {
            h3zero_data_stream_state_t stream_state = { 0 };
            for (int i = 0; i < 32; i++) {
                size_t trial_random = (size_t)picoquic_test_uniform_random(&trial_random_ctx, SIZE_MAX);
                size_t available_data;
                if (trial_rank < 128 && i == 0) {
                    trial_random = trial_rank;
                }
                p_len = h3zero_stream_fuzz_message(packet_buffer, buffer_size, trial_random);
                p_max = packet_buffer + p_len;
                p = packet_buffer;
                while (p != NULL && p < p_max) {
                    available_data = 0;
                    p = h3zero_parse_data_stream(p, p_max, &stream_state, &available_data, &error_found);
                    p += available_data;
                }
                if (p == NULL) {
                    break;
                }
            }
            if (p == NULL) {
                nb_bad++;
                switch(error_found){
                case 0:
                    errors_found[0]++;
                    break;
                case H3ZERO_FRAME_UNEXPECTED:
                    errors_found[1]++;
                    break;
                case H3ZERO_INTERNAL_ERROR:
                    errors_found[2]++;
                    break;
                case H3ZERO_GENERAL_PROTOCOL_ERROR:
                    errors_found[3]++;
                    break;
                case H3ZERO_FRAME_ERROR:
                    errors_found[4]++;
                    break;
                default:
                    errors_found[5]++;
                    break;
                }
            }
            else {
                nb_good++;
            }
            h3zero_delete_data_stream_state(&stream_state);
        }
        if (nb_good + nb_bad != nb_trials) {
            ret = -1;
        }
        for (int i = 0; i < 6; i++) {
            DBG_PRINTF("%s: %d", errors_names[i], errors_found[i]);
        }
        free(packet_buffer);
    }
    return ret;
}

/*
 * Test the scenario parsing function
 */

static picoquic_demo_stream_desc_t const parse_demo_scenario_desc1[] = {
    { 0, 0, PICOQUIC_DEMO_STREAM_ID_INITIAL, "/", "_", 0, NULL},
    { 0, 4, 0, "test.html", "test.html", 0, NULL },
    { 0, 8, 0, "main.jpg", "main.jpg", 0, NULL },
    { 0, 12, 0, "/bla/bla/", "_bla_bla_", 0, NULL }
};

static picoquic_demo_stream_desc_t const parse_demo_scenario_desc2[] = {
    { 0, 0, PICOQUIC_DEMO_STREAM_ID_INITIAL, "/", "_", 0, NULL },
    { 0, 4, 0, "main.jpg", "main.jpg", 0, NULL },
    { 0, 8, 4, "test.html", "test.html", 0, NULL }
};

static picoquic_demo_stream_desc_t const parse_demo_scenario_desc3[] = {
    { 1000, 0, PICOQUIC_DEMO_STREAM_ID_INITIAL, "/", "_", 0, NULL }
};

static picoquic_demo_stream_desc_t const parse_demo_scenario_desc4[] = {
    { 0, 0, PICOQUIC_DEMO_STREAM_ID_INITIAL, "/cgi-sink", "_cgi-sink", 1000000, NULL },
    { 0, 4, 0, "/", "_", 0, NULL }
};

static picoquic_demo_stream_desc_t const parse_demo_scenario_desc5[] = {
    { 0, 0, PICOQUIC_DEMO_STREAM_ID_INITIAL, "/32", "_32", 0, NULL },
    { 0, 4, PICOQUIC_DEMO_STREAM_ID_INITIAL, "/33", "_33", 0, NULL }
};

static picoquic_demo_stream_desc_t const parse_demo_scenario_desc6[] = {
    { 0, 0, PICOQUIC_DEMO_STREAM_ID_INITIAL, "/200000000000", "_200000000000", 0, NULL }
};

static picoquic_demo_stream_desc_t const parse_demo_scenario_desc7[] = {
    { 0, 0, PICOQUIC_DEMO_STREAM_ID_INITIAL, "/cgi-sink", "_cgi-sink", 100000000000, NULL }
};

static picoquic_demo_stream_desc_t const parse_demo_scenario_desc8[] = {
    { 0, 0, PICOQUIC_DEMO_STREAM_ID_INITIAL, "test.html", "test.html", 0, "bytes=80-800"},
    { 0, 4, 0, "/cgi-sink", "_cgi-sink", 10000, "bytes=100-1000" }
};


typedef struct st_demo_scenario_test_case_t {
    char const* text;
    const picoquic_demo_stream_desc_t* desc;
    size_t nb_streams;
} demo_scenario_test_case_t;

static const demo_scenario_test_case_t demo_scenario_test_cases[] = {
    { "/;test.html;8:0:main.jpg;12:0:/bla/bla/", parse_demo_scenario_desc1, sizeof(parse_demo_scenario_desc1) / sizeof(picoquic_demo_stream_desc_t) },
    { "/;main.jpg;test.html;", parse_demo_scenario_desc2, sizeof(parse_demo_scenario_desc2) / sizeof(picoquic_demo_stream_desc_t) },
    { "*1000:/", parse_demo_scenario_desc3, sizeof(parse_demo_scenario_desc3) / sizeof(picoquic_demo_stream_desc_t) },
    { "/cgi-sink:1000000;4:/", parse_demo_scenario_desc4, sizeof(parse_demo_scenario_desc4) / sizeof(picoquic_demo_stream_desc_t) },
    { "-:/32;-:/33", parse_demo_scenario_desc5, sizeof(parse_demo_scenario_desc5) / sizeof(picoquic_demo_stream_desc_t) },
    { "-:/200000000000", parse_demo_scenario_desc6, sizeof(parse_demo_scenario_desc6) / sizeof(picoquic_demo_stream_desc_t) },
    { "/cgi-sink:100000000000", parse_demo_scenario_desc7, sizeof(parse_demo_scenario_desc7) / sizeof(picoquic_demo_stream_desc_t) },
    { "test.html:#bytes=80-800;/cgi-sink:10000:#bytes=100-1000;", parse_demo_scenario_desc8, sizeof(parse_demo_scenario_desc8) / sizeof(picoquic_demo_stream_desc_t) }
};

static size_t nb_demo_scenario_test_cases = sizeof(demo_scenario_test_cases) / sizeof(demo_scenario_test_case_t);


int parse_demo_scenario_test_one(const char * text, picoquic_demo_stream_desc_t const * desc_ref, size_t nb_streams_ref)
{
    size_t nb_streams = 0;
    picoquic_demo_stream_desc_t * desc = NULL;
    int ret = demo_client_parse_scenario_desc(text, &nb_streams, &desc);

    if (ret == 0) {
        if (nb_streams != nb_streams_ref) {
            ret = -1;
        }
        else {
            for (size_t i = 0; ret == 0 && i < nb_streams; i++) {
                if (desc[i].stream_id != desc_ref[i].stream_id) {
                    ret = -1;
                }
                else if (desc[i].previous_stream_id != desc_ref[i].previous_stream_id) {
                    ret = -1;
                }
                else if (strcmp(desc[i].doc_name, desc_ref[i].doc_name) != 0) {
                    ret = -1;
                }
                else if (strcmp(desc[i].f_name, desc_ref[i].f_name) != 0) {
                    ret = -1;
                }
                else if (desc[i].post_size !=  desc_ref[i].post_size) {
                    ret = -1;
                }
                else if (desc[i].range == NULL &&
                    desc_ref[i].range != NULL) {
                    ret = -1;
                }
                else if (desc[i].range != NULL &&
                    desc_ref[i].range == NULL) {
                    ret = -1;
                }
                else if (desc[i].range != NULL &&
                    strcmp(desc[i].range, desc_ref[i].range) != 0) {
                    ret = -1;
                }
            }
        }
    }
    else {
        ret = -1;
    }

    if (desc != NULL) {
        demo_client_delete_scenario_desc(nb_streams, desc);
    }

    return ret;
}

int parse_demo_scenario_test()
{
    int ret = 0;

    for (size_t i = 0; ret == 0 && i < nb_demo_scenario_test_cases; i++) {
        ret = parse_demo_scenario_test_one(demo_scenario_test_cases[i].text, demo_scenario_test_cases[i].desc, demo_scenario_test_cases[i].nb_streams);
        if (ret != 0) {
            DBG_PRINTF("Could not parse scenario %d: %s", i, demo_scenario_test_cases[i].text);
        }
    }

    return ret;
}

/*
 * Set a connection between an H3 client and an H3 server over
 * network simulation.
 */
static const picoquic_demo_stream_desc_t demo_test_scenario[] = {
    { 0, 0, PICOQUIC_DEMO_STREAM_ID_INITIAL, "/", "root.html", 0 },
    { 0, 4, 0, "12345", "doc-12345.txt", 0 },
    { 0, 8, 4, "post-test", "post-test.html", 12345 }
};

static size_t const nb_demo_test_scenario = sizeof(demo_test_scenario) / sizeof(picoquic_demo_stream_desc_t);

static size_t const demo_test_stream_length[] = {
    128,
    12345,
    190
};

static int demo_server_test(char const * alpn, picoquic_stream_data_cb_fn server_callback_fn, void * server_param,
    const picoquic_demo_stream_desc_t * demo_scenario, size_t nb_scenario, size_t const * demo_length,
    int do_sat, uint64_t do_losses, uint64_t completion_target, int delay_fin, const char * out_dir, const char * client_bin,
    const char * server_bin, int do_preemptive_repeat)
{
    uint64_t simulated_time = 0;
    uint64_t loss_mask = do_losses;
    uint64_t time_out;
    int nb_trials = 0;
    int was_active = 0;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    picoquic_demo_callback_ctx_t callback_ctx;
    int ret;
    picoquic_tp_t client_parameters;
    picoquic_connection_id_t initial_cid = { {0xde, 0xc1, 3, 4, 5, 6, 7, 8}, 8 };

    ret = picoquic_demo_client_initialize_context(&callback_ctx, demo_scenario, nb_scenario, alpn, 0, delay_fin);
    callback_ctx.out_dir = out_dir;
    callback_ctx.no_print = 1;

    if (ret == 0) {
        ret = tls_api_init_ctx_ex(&test_ctx,
            PICOQUIC_INTERNAL_TEST_VERSION_1,
            PICOQUIC_TEST_SNI, alpn, &simulated_time, NULL, NULL, 0, 1, 0, &initial_cid);

        if (ret == 0 && server_bin != NULL) {
            picoquic_set_binlog(test_ctx->qserver, ".");
            test_ctx->qserver->use_long_log = 1;
        }

        if (ret == 0 && client_bin != NULL) {
            picoquic_set_binlog(test_ctx->qclient, ".");
        }

        if (ret == 0 && do_sat) {
            /* For the satellite test, set long delays, 10 Mbps one way, 1 Mbps the other way */
            const uint64_t satellite_latency = 300000;
            test_ctx->c_to_s_link->microsec_latency = satellite_latency;
            test_ctx->c_to_s_link->picosec_per_byte = 8000000;
            test_ctx->s_to_c_link->microsec_latency = satellite_latency;
            test_ctx->s_to_c_link->picosec_per_byte = 800000;
            picoquic_set_default_congestion_algorithm(test_ctx->qserver, picoquic_bbr_algorithm);
            picoquic_set_congestion_algorithm(test_ctx->cnx_client, picoquic_bbr_algorithm);

            memset(&client_parameters, 0, sizeof(picoquic_tp_t));
            picoquic_init_transport_parameters(&client_parameters, 1);
            client_parameters.enable_time_stamp = 1;
            picoquic_set_transport_parameters(test_ctx->cnx_client, &client_parameters);
        }

        if (ret == 0 && do_preemptive_repeat) {
            picoquic_set_preemptive_repeat_policy(test_ctx->qserver, 1);
            picoquic_set_preemptive_repeat_per_cnx(test_ctx->cnx_client, 1);
        }
    }

    if (ret != 0) {
        DBG_PRINTF("Could not create the QUIC test contexts for V=%x\n", PICOQUIC_INTERNAL_TEST_VERSION_1);
    }
    else if (test_ctx == NULL || test_ctx->cnx_client == NULL || test_ctx->qserver == NULL) {
        DBG_PRINTF("%s", "Connections where not properly created!\n");
        ret = -1;
    }

    /* The default procedure creates connections using the test callback.
     * We want to replace that by the demo client callback */

    if (ret == 0) {
        picoquic_set_alpn_select_fn(test_ctx->qserver, picoquic_demo_server_callback_select_alpn);
        picoquic_set_default_callback(test_ctx->qserver, server_callback_fn, server_param);
        picoquic_set_callback(test_ctx->cnx_client, picoquic_demo_client_callback, &callback_ctx);
        if (ret == 0) {
            ret = picoquic_start_client_cnx(test_ctx->cnx_client);
        }
    }

    if (ret == 0) {
        ret = tls_api_connection_loop(test_ctx, &loss_mask, 0, &simulated_time);
    }

    if (ret == 0) {
        ret = picoquic_demo_client_start_streams(test_ctx->cnx_client, &callback_ctx, PICOQUIC_DEMO_STREAM_ID_INITIAL);
    }

    if (delay_fin) {
        /* Trigger sending the first stream requests, then send a separate FIN on stream 0 */
        int is_sent = 0;
        time_out = simulated_time + 3000000;
        while (ret == 0 && simulated_time < time_out) {
            ret = tls_api_one_sim_round(test_ctx, &simulated_time, time_out, &was_active);
            if (!is_sent && test_ctx->cnx_client->data_sent > 0) {
                is_sent = 1;
                time_out = simulated_time + 250;
            }
        }
        if (ret == 0) {
            picoquic_add_to_stream_with_ctx(test_ctx->cnx_client, 0, NULL, 0, 1, callback_ctx.first_stream);
        }
    }

    /* Simulate the connection from the client side. */
    time_out = simulated_time + 30000000;
    while (ret == 0 && picoquic_get_cnx_state(test_ctx->cnx_client) != picoquic_state_disconnected) {
        ret = tls_api_one_sim_round(test_ctx, &simulated_time, time_out, &was_active);

        if (ret == -1) {
            break;
        }

        if (picoquic_is_cnx_backlog_empty(test_ctx->cnx_client)) {
            if (callback_ctx.nb_open_streams == 0) {
                ret = picoquic_close(test_ctx->cnx_client, 0);
            }
            else if (simulated_time > callback_ctx.last_interaction_time &&
                simulated_time - callback_ctx.last_interaction_time > 10000000ull) {
                (void)picoquic_close(test_ctx->cnx_client, 0);
                ret = -1;
            }
        }
        if (++nb_trials > 100000) {
            ret = -1;
            break;
        }
    }

    /* Verify that the data was properly received. */
    for (size_t i = 0; ret == 0 && i < nb_scenario; i++) {
        picoquic_demo_client_stream_ctx_t* stream = callback_ctx.first_stream;

        while (stream != NULL && stream->stream_id != demo_scenario[i].stream_id) {
            stream = stream->next_stream;
        }

        if (stream == NULL) {
            DBG_PRINTF("Scenario stream %d is missing\n", (int)i);
            ret = -1;
        }
        else if (stream->F != NULL) {
            DBG_PRINTF("Scenario stream %d, file was not closed\n", (int)i);
            ret = -1;
        }
        else if (stream->received_length < demo_length[i]) {
            DBG_PRINTF("Scenario stream %d, only %d bytes received\n", 
                (int)i, (int)stream->received_length);
            ret = -1;
        }
        else if (stream->post_sent < demo_scenario[i].post_size) {
            DBG_PRINTF("Scenario stream %d, only %d bytes sent\n",
                (int)i, (int)stream->post_sent);
            ret = -1;
        }
    }

    if (ret == 0 && completion_target != 0) {
        if (simulated_time > completion_target) {
            DBG_PRINTF("Test uses %llu microsec instead of %llu", simulated_time, completion_target);
            ret = -1;
        }
    }

    if (ret == 0 && test_ctx->qclient->nb_data_nodes_allocated > test_ctx->qclient->nb_data_nodes_in_pool) {
        ret = -1;
    }
    else if (ret == 0 && test_ctx->qserver->nb_data_nodes_allocated > test_ctx->qserver->nb_data_nodes_in_pool) {
        ret = -1;
    }

    picoquic_demo_client_delete_context(&callback_ctx);

    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }
    
    return ret;
}

int h3zero_server_test()
{
    return demo_server_test(PICOHTTP_ALPN_H3_LATEST, h3zero_callback, NULL, 
        demo_test_scenario, nb_demo_test_scenario, demo_test_stream_length,
        0, 0, 0, 0, NULL, ".", ".", 0);
}

int h09_server_test()
{
    return demo_server_test(PICOHTTP_ALPN_HQ_LATEST, picoquic_h09_server_callback, NULL,
        demo_test_scenario, nb_demo_test_scenario, demo_test_stream_length,
        0, 0, 0, 0, NULL, NULL, NULL, 0);
}

/* Unit test of H09 header parsing. 
 * test a variety of headers
 */

typedef struct st_h09_header_test_data_t {
    char const* test_header;
    size_t expected_parsed;
    picohttp_server_stream_status_t expected_status;
    int expected_method;
    int expected_proto;
    char const* expected_path;
    size_t expected_command_length;
    
} h09_header_test_data_t;

static h09_header_test_data_t h09_header_data_test_case[] = {
    { "GET /\r\n\r\n", 9, picohttp_server_stream_status_receiving, 0, 0, "/", 5 },
    { "GET /\n", 6, picohttp_server_stream_status_crlf, 0, 0, "/", 5 },
    { "GET /\r", 6, picohttp_server_stream_status_none, 0, 0, "/", 5 },
    { "GET /", 5, picohttp_server_stream_status_none, 0, 0, "/", 5 },
    { "POST /bla\r\n\r\nBlablablablablablabla\nblabla\n", 
    13, picohttp_server_stream_status_receiving, 1, 0, "/bla", 9 },
    { "GET /hello.txt HTTP/1.1\n\
User - Agent: curl / 7.16.3 libcurl / 7.16.3 OpenSSL / 0.9.7l zlib / 1.2.3\n\
Host : www.example.com\n\
Accept - Language : en, mi",
    148, picohttp_server_stream_status_header, 0, 1, "/hello.txt", 23 },
    { "Abracadabra", 0, picohttp_server_stream_status_none, -1, 0, "", 0 }
};

static size_t nb_h09_header_data_test_cases = sizeof(h09_header_data_test_case) / sizeof(h09_header_test_data_t);

int h09_header_split_test(const uint8_t* bytes, size_t length, size_t split, h09_header_test_data_t* expected)
{
    int ret = 0;
    h3zero_stream_ctx_t* stream_ctx;
    size_t total_processed = 0;

    /* Create stream context */
    stream_ctx = (h3zero_stream_ctx_t*)
        malloc(sizeof(h3zero_stream_ctx_t));
    if (stream_ctx == NULL) {
        DBG_PRINTF("%s", "Cannot allocate stream context");
        ret = -1;
    }
    else {
        memset(stream_ctx, 0, sizeof(h3zero_stream_ctx_t));
        stream_ctx->is_h3 = 0; /* This is http... */
    }

    for (size_t l = 0; ret == 0 && l < length; l += split) {
        picoquic_call_back_event_t fin_or_event = picoquic_callback_stream_fin;
        size_t available = length - l;
        size_t processed = 0;

        if (available > split) {
            available = split;
            fin_or_event = picoquic_callback_stream_data;
        }

        ret = picoquic_h09_server_process_data_header(bytes + l, available, fin_or_event,
            stream_ctx, &processed);

        total_processed += processed;
        if (processed < available) {
            break;
        }
    }

    /* Check status */
    if (ret == 0){
        if (expected->expected_method < 0) {
            DBG_PRINTF("Unexpected success, method = %d, ret = %d", expected->expected_method, ret);
            ret = -1;
        }
        else {
            if (total_processed != expected->expected_parsed) {
                DBG_PRINTF("Expected parsed %zu, processed %zu", expected->expected_parsed, total_processed);
                ret = -1;
            }
            else if (stream_ctx->ps.hq.status != expected->expected_status) {
                DBG_PRINTF("Expected status %d, got %d", expected->expected_status, stream_ctx->ps.hq.status);
                ret = -1;
            }
            else if (stream_ctx->ps.hq.method != expected->expected_method) {
                DBG_PRINTF("Expected method %d, got %d", expected->expected_method, stream_ctx->ps.hq.method);
                ret = -1;
            }
            else if (stream_ctx->ps.hq.proto != expected->expected_proto) {
                DBG_PRINTF("Expected proto %d, got %d", expected->expected_proto, stream_ctx->ps.hq.proto);
                ret = -1;
            }
            else if (stream_ctx->ps.hq.command_length != expected->expected_command_length) {
                DBG_PRINTF("Expected command length %zu, got %zu", expected->expected_command_length, stream_ctx->ps.hq.command_length);
                ret = -1;
            }
            else
            {   
                if (expected->expected_path == NULL) {
                    if (stream_ctx->ps.hq.path_length > 0) {
                        DBG_PRINTF("Expected empty, result path length %d", stream_ctx->ps.hq.path_length);
                        ret = -1;
                    }
                }
                else if (stream_ctx->ps.hq.path_length != strlen(expected->expected_path)) {
                    DBG_PRINTF("Expected path <%s>, result path length %d", 
                        expected->expected_path, stream_ctx->ps.hq.path_length);
                    ret = -1;
                }
                else if (stream_ctx->ps.hq.path_length > 0) {
                    if (stream_ctx->ps.hq.path == NULL) {
                        DBG_PRINTF("Result path is NULL, length %d", stream_ctx->ps.hq.path_length);
                        ret = -1;
                    }
                    else if (memcmp(expected->expected_path, stream_ctx->ps.hq.path, stream_ctx->ps.hq.path_length) != 0) {
                        DBG_PRINTF("Result path differs from expected path <%s>", expected->expected_path);
                        ret = -1;
                    }
                }
            }
        }
    }
    else {
        /* The parsing failed. If this was expected, then not an error. */
        if (expected->expected_method < 0) {
            ret = 0;
        }
        else {
            DBG_PRINTF("Unexpected parsing error, method = %d, ret = %d", expected->expected_method, ret);
        }
    }

    if (stream_ctx != NULL) {
        if (stream_ctx->ps.hq.path != NULL) {
            free(stream_ctx->ps.hq.path);
        }
        free(stream_ctx);
    }

    return ret;
}

int h09_header_test()
{
    int ret = 0;
    const size_t split_test[4] = { 1024, 7, 3, 1 };

    for (size_t i = 0; ret == 0 && i < nb_h09_header_data_test_cases; i++)
    {

        /* Simulate data arrival */
        for (int j = 0; ret == 0 && j < 4; j++) {
            ret = h09_header_split_test(
                (const uint8_t*) h09_header_data_test_case[i].test_header,
                strlen(h09_header_data_test_case[i].test_header),
                split_test[j], &h09_header_data_test_case[i]);
            if (ret < 0) {
                DBG_PRINTF("H09 header test %zu fails, split = %zu, ret = %d",
                    i, split_test[j], ret);
            }
        }
    }
    /* If success so far, try a buffer overflow scenario */
    if (ret == 0) {
        h09_header_test_data_t overflow_case;
        size_t overflow_size = 0x10000;
        uint8_t* overflow_bytes = (uint8_t*)malloc(overflow_size);
        
        if (overflow_bytes == NULL) {
            DBG_PRINTF("%s", "Cannot malloc overflow bytes.");
            ret = -1;
        }
        else {
            memset(&overflow_case, 0, sizeof(h09_header_test_data_t));
            overflow_case.expected_method = -1;
            memset(overflow_bytes, 'x', overflow_size);
            overflow_bytes[0] = 'G';
            overflow_bytes[1] = 'E';
            overflow_bytes[2] = 'T';
            overflow_bytes[3] = ' ';
            overflow_bytes[overflow_size - 1] = (uint8_t)'\n';
            overflow_bytes[overflow_size - 2] = (uint8_t)'\n';

            ret = h09_header_split_test(overflow_bytes, overflow_size, 1024, &overflow_case);
            if (ret < 0) {
                DBG_PRINTF("H09 header overflow fails, split = %d, ret = %d",
                    1024, ret);
            }

            free(overflow_bytes);
        }
    }


    return ret;
}


int generic_server_test()
{
    char const* alpn_09 = PICOHTTP_ALPN_HQ_LATEST;
    char const* alpn_3 = PICOHTTP_ALPN_H3_LATEST;
    int ret = demo_server_test(alpn_09, picoquic_demo_server_callback, NULL, demo_test_scenario,
        nb_demo_test_scenario, demo_test_stream_length, 0, 0, 0, 0, NULL, NULL, NULL, 0);

    if (ret != 0) {
        DBG_PRINTF("Generic server test fails for %s\n", alpn_09);
    }
    else {
        ret = demo_server_test(alpn_3, picoquic_demo_server_callback, NULL, demo_test_scenario,
            nb_demo_test_scenario, demo_test_stream_length, 0, 0, 0, 0, NULL, NULL, NULL, 0);

        if (ret != 0) {
            DBG_PRINTF("Generic server test fails for %s\n", alpn_3);
        }
        else {
            ret = demo_server_test(NULL, picoquic_demo_server_callback, NULL, demo_test_scenario,
                nb_demo_test_scenario, demo_test_stream_length, 0, 0, 0, 0, NULL, NULL, NULL, 0);

            if (ret != 0) {
                DBG_PRINTF("Generic server test fails for %s\n", alpn_3);
            }
        }
    }

    return ret;
}

/* Test the server side post API */

/* Sample callback used for demonstrating the callback API.
 * The transaction returns the MD5 of the posted data */

#define PICOQUIC_ECHO_SIZE_MAX 8192

typedef struct st_hzero_post_echo_ctx_t {
    size_t nb_received;
    size_t nb_echo;
    size_t nb_sent;
    uint8_t buf[PICOQUIC_ECHO_SIZE_MAX];
} hzero_post_echo_ctx_t;

int h3zero_test_ping_callback(picoquic_cnx_t* cnx,
    uint8_t* bytes, size_t length,
    picohttp_call_back_event_t event, h3zero_stream_ctx_t* stream_ctx,
    void * callback_ctx)
{
    int ret = 0;
    hzero_post_echo_ctx_t* ctx = (hzero_post_echo_ctx_t*)stream_ctx->path_callback_ctx;

    switch (event) {
    case picohttp_callback_get: /* Received a get command */
        break;
    case picohttp_callback_post: /* Received a post command */
        if (ctx == NULL) {
            ctx = (hzero_post_echo_ctx_t*)malloc(sizeof(hzero_post_echo_ctx_t));
            if (ctx == NULL) {
                /* cannot handle the stream -- TODO: reset stream? */
                return -1;
            }
            else {
                memset(ctx, 0, sizeof(hzero_post_echo_ctx_t));
                stream_ctx->path_callback_ctx = (void *) ctx;
            }
        }
        else {
            /* unexpected. Should not have a context here */
            return -1;
        }
        break;
    case picohttp_callback_post_data: /* Data received from peer on stream N */
    case picohttp_callback_post_fin: /* All posted data have been received, prepare the response now. */
        /* Add data to echo size */
        if (ctx == NULL) {
            ret = -1;
        }
        else { 
            if (ctx->nb_received < PICOQUIC_ECHO_SIZE_MAX) {
                size_t available = PICOQUIC_ECHO_SIZE_MAX - ctx->nb_received;
                size_t copied = (available > length) ? length : available;
                memcpy(ctx->buf + ctx->nb_received, bytes, copied);
                ctx->nb_echo += copied;
            }
            ctx->nb_received += length;
        }
        if (event == picohttp_callback_post_fin) {
            if (ctx != NULL) {
                ret = (int)ctx->nb_echo;
            }
            else {
                ret = -1;
            }
        }
        break;
    case picohttp_callback_provide_data:
        if (ctx == NULL || ctx->nb_sent > ctx->nb_echo) {
            ret = -1;
        }
        else
        {
            /* Provide data. */
            uint8_t* buffer;
            size_t available = ctx->nb_echo - ctx->nb_sent;
            int is_fin = 1;

            if (available > length) {
                available = length;
                is_fin = 0;
            }

            buffer = picoquic_provide_stream_data_buffer(bytes, available, is_fin, !is_fin);
            if (buffer != NULL) {
                memcpy(buffer, ctx->buf + ctx->nb_sent, available);
                ctx->nb_sent += available;
                ret = 0;
            }
            else {
                ret = -1;
            }
        }
        break;
    case picohttp_callback_free: /* stream is abandoned */
        stream_ctx->path_callback = NULL;
        stream_ctx->path_callback_ctx = NULL;
       
        if (ctx != NULL) {
            free(ctx);
        }
        break;
    default:
        ret = -1;
        break;
    }

    return ret;
}

static const picoquic_demo_stream_desc_t post_test_scenario[] = {
    { 0, 0, PICOQUIC_DEMO_STREAM_ID_INITIAL, "/ping", "ping-test.html", 2345 }
};

picohttp_server_path_item_t ping_test_item = {
    "/ping",
    5,
    h3zero_test_ping_callback,
    NULL
};

picohttp_server_parameters_t ping_test_param = {
    NULL,
    &ping_test_item,
    1
};


static size_t const nb_post_test_scenario = sizeof(post_test_scenario) / sizeof(picoquic_demo_stream_desc_t);

static size_t const post_test_stream_length[] = { 2345 };

int h3zero_post_test()
{
    return demo_server_test(PICOHTTP_ALPN_H3_LATEST, h3zero_callback, (void*)&ping_test_param, post_test_scenario, nb_post_test_scenario,
        post_test_stream_length, 0, 0, 0, 0, NULL, NULL, NULL, 0);
}

int h09_post_test()
{
    return demo_server_test(PICOHTTP_ALPN_HQ_LATEST, picoquic_h09_server_callback, (void*)&ping_test_param, post_test_scenario, nb_post_test_scenario, 
        post_test_stream_length, 0, 0, 0, 0, NULL, NULL, NULL, 0);
}

int demo_file_sanitize_test()
{
    int ret = 0;
    char const* good[] = {
        "/index.html", "/example.com.txt", "/5000000", "/123_45.png", "/a-b-C-Z", "/dir/index.html"
    };
    size_t nb_good = sizeof(good) / sizeof(char const*);
    char const* bad[] = {
        "/../index.html", "example.com.txt", "/5000000/", "/.123_45.png", "/a-b-C-Z\\..\\password.txt", "//remote-server/example"
    };
    size_t nb_bad = sizeof(bad) / sizeof(char const*);

    for (size_t i = 0; ret == 0 && i < nb_good; i++) {
        if (demo_server_is_path_sane((uint8_t*)good[i], strlen(good[i])) != 0) {
            DBG_PRINTF("Found good frame not good: %s\n", good[i]);
            ret = -1;
        }
    }

    for (size_t i = 0; ret == 0 && i < nb_bad; i++) {
        if (demo_server_is_path_sane((uint8_t*)bad[i], strlen(bad[i])) == 0) {
            DBG_PRINTF("Found bad frame not bad: %s\n", bad[i]);
            ret = -1;
        }
    }

    return ret;
}

int demo_file_access_test()
{
    int ret = 0;
#ifdef _WINDOWS
    char const* folder = ".\\";
#else
    char const* folder = "./";
#endif
    char const* path = "/x1234x5678.zzz";
    char const* bad_path = "/../etc/passwd";
    size_t f_size = 0;
    uint64_t echo_size = 0;
    char buf[128];
    char* file_path;
    const int nb_blocks = 16;
    int file_error = 0;

    FILE* F = picoquic_file_open(path + 1, "wb");

    if (F == NULL) {
        DBG_PRINTF("Cannot create file: %s", path + 1);
        ret = -1;
    }
    else {
        for (int i = 0; i < nb_blocks; i++) {
            memset(buf, i, sizeof(buf));
            fwrite(buf, 1, sizeof(buf), F);
            f_size += sizeof(buf);
        }
        F = picoquic_file_close(F);
    }

    if (ret == 0) {
        ret = demo_server_try_file_path((uint8_t*)path, strlen(path), &echo_size,
            &file_path, folder, &file_error);
        if (ret != 0) {
            DBG_PRINTF("Could not try file path <%s> <%s>, ret = %d, err = 0x%x", folder, path, ret, file_error);
        }
        else if (echo_size != f_size) {
            DBG_PRINTF("Found size = %d instead of %d", (int)echo_size, (int)f_size);
            ret = -1;
        }
        else {
            F = picoquic_file_open(file_path, "rb");
            if (F == NULL) {
                DBG_PRINTF("Could not open file path: <%s>", file_path);
                ret = -1;
            }
            else {
                for (int i = 0; ret == 0 && i < nb_blocks; i++) {
                    int nb_read = (int)fread(buf, 1, sizeof(buf), F);
                    if (nb_read != (int)sizeof(buf)) {
                        ret = -1;
                    }
                    else {
                        for (size_t j = 0; j < sizeof(buf); j++) {
                            if (buf[j] != i) {
                                ret = -1;
                                break;
                            }
                        }
                    }
                }
            }
        }

        if (F != NULL) {
            F = picoquic_file_close(F);
        }
        if (file_path != NULL) {
            free(file_path);
            file_path = NULL;
        }
    }

    if (ret == 0) {
        ret = remove(path + 1);
        if (ret != 0) {
            DBG_PRINTF("Could not remove %s", path + 1);
        }
    }

    if (ret == 0) {
        if (demo_server_try_file_path((uint8_t*)path, strlen(path), &echo_size, &file_path, folder, &file_error) == 0) {
            DBG_PRINTF("Could open deleted file path <%s> <%s>", folder, path);
            ret = -1;
        }
        if (file_path != NULL) {
            free(file_path);
            file_path = NULL;
        }
    }

    if (ret == 0) {
        if (demo_server_try_file_path((uint8_t*)bad_path, strlen(bad_path), &echo_size,
            &file_path, folder, &file_error) == 0) {
            DBG_PRINTF("Could open bad path <%s> <%s>", folder, bad_path);
            ret = -1;
        }
        if (file_path != NULL) {
            free(file_path);
            file_path = NULL;
        }
    }

    return ret;
}


#define PICOQUIC_TEST_FILE_DEMO_FOLDER "picoquictest"

static const picoquic_demo_stream_desc_t file_test_scenario[] = {
    { 0, 0, PICOQUIC_DEMO_STREAM_ID_INITIAL, "/file_test_ref.txt", "file_test_ref.txt", 0 }
};

static size_t const demo_file_test_stream_length[] = {
    4499
};

static size_t nb_file_test_scenario = sizeof(file_test_scenario) / sizeof(picoquic_demo_stream_desc_t);

int serve_file_test_set_param(picohttp_server_parameters_t* file_param, char * buf, size_t buf_size)
{
    int ret = picoquic_get_input_path(buf, buf_size, picoquic_solution_dir, PICOQUIC_TEST_FILE_DEMO_FOLDER);

    memset(file_param, 0, sizeof(picohttp_server_parameters_t));
    file_param->web_folder = buf;

    return ret;
}

int file_test_compare(const picohttp_server_parameters_t * file_param, const picoquic_demo_stream_desc_t * file_test_scenario)
{
    /* Find the input file name */
    char test_input[1024];
    size_t l;
    int ret = picoquic_sprintf(test_input, sizeof(test_input), &l, "%s%s%s", file_param->web_folder, PICOQUIC_FILE_SEPARATOR, file_test_scenario->f_name);

    if (ret == 0) {
        ret = picoquic_test_compare_text_files(test_input, file_test_scenario->f_name);
    }

    return ret;
}

int demo_server_file_test()
{
    int ret = 0;
    char file_name_buffer[1024];
    picohttp_server_parameters_t file_param;

    ret = serve_file_test_set_param(&file_param, file_name_buffer, sizeof(file_name_buffer));

    if (ret == 0 && (ret = demo_server_test(PICOHTTP_ALPN_H3_LATEST, h3zero_callback, (void*)&file_param, 
        file_test_scenario, nb_file_test_scenario, demo_file_test_stream_length, 0, 0, 0, 0, NULL, NULL, NULL, 0)) != 0) {
        DBG_PRINTF("H3 server (%s) file test fails, ret = %d\n", PICOHTTP_ALPN_H3_LATEST, ret);
    }
    else if (ret == 0) {
        ret = file_test_compare(&file_param, &file_test_scenario[0]);
    }

    if (ret == 0 && (ret = demo_server_test(PICOHTTP_ALPN_HQ_LATEST, picoquic_h09_server_callback, (void*)&file_param,
        file_test_scenario, nb_file_test_scenario, demo_file_test_stream_length, 0, 0, 0, 0, NULL, NULL, NULL, 0)) != 0) {
        DBG_PRINTF("H09 server (%s) file test fails, ret = %d\n", PICOHTTP_ALPN_HQ_LATEST, ret);
    }
    else if (ret == 0) {
        ret = file_test_compare(&file_param, &file_test_scenario[0]);
    }

    if (ret == 0 && (ret = demo_server_test(PICOHTTP_ALPN_H3_LATEST, picoquic_demo_server_callback, (void*)&file_param,
        file_test_scenario, nb_file_test_scenario, demo_file_test_stream_length, 0, 0, 0, 0, NULL, NULL, NULL, 0)) != 0) {
        DBG_PRINTF("Demo server (%s) file test fails, ret = %d\n", PICOHTTP_ALPN_H3_LATEST, ret);
    }
    else if (ret == 0) {
        ret = file_test_compare(&file_param, &file_test_scenario[0]);
    }

    if (ret == 0 && (ret = demo_server_test(PICOHTTP_ALPN_HQ_LATEST, picoquic_demo_server_callback, (void*)&file_param,
        file_test_scenario, nb_file_test_scenario, demo_test_stream_length, 0, 0, 0, 0, NULL, NULL, NULL, 0)) != 0) {
        DBG_PRINTF("Demo server (%s) file test fails, ret = %d\n", PICOHTTP_ALPN_HQ_LATEST, ret);
    }
    else if (ret == 0) {
        ret = file_test_compare(&file_param, &file_test_scenario[0]);
    }

    return ret;
}

static const picoquic_demo_stream_desc_t satellite_test_scenario[] = {
    { 0, 0, PICOQUIC_DEMO_STREAM_ID_INITIAL, "/10000000", "bin10M.txt", 0 }
};

static const size_t nb_satellite_test_scenario = sizeof(satellite_test_scenario) / sizeof(picoquic_demo_stream_desc_t);

int h3zero_satellite_test()
{
    return demo_server_test(PICOHTTP_ALPN_H3_LATEST, h3zero_callback, NULL, satellite_test_scenario, nb_satellite_test_scenario,
        demo_test_stream_length, 1, 0, 10750000, 0, NULL, NULL, NULL, 0);
}

int h09_satellite_test()
{
    return demo_server_test(PICOHTTP_ALPN_HQ_LATEST, picoquic_h09_server_callback, NULL, satellite_test_scenario, nb_satellite_test_scenario, 
        demo_test_stream_length, 1, 0, 10750000, 0, NULL, NULL, NULL, 0);
}

int h09_lone_fin_test()
{
    int ret = 0;
    char file_name_buffer[1024];
    picohttp_server_parameters_t file_param;

    ret = serve_file_test_set_param(&file_param, file_name_buffer, sizeof(file_name_buffer));

    if (ret == 0 && (ret = demo_server_test(PICOHTTP_ALPN_HQ_LATEST, picoquic_h09_server_callback, (void*)&file_param, 
        file_test_scenario, nb_file_test_scenario, demo_file_test_stream_length, 0, 0, 0, 1, NULL, NULL, NULL, 0)) != 0) {
        DBG_PRINTF("H09 server (%s) file test fails, ret = %d\n", PICOHTTP_ALPN_HQ_LATEST, ret);
    }
    else if (ret == 0) {
        ret = file_test_compare(&file_param, &file_test_scenario[0]);
    }

    return ret;
}

#ifndef _WINDOWS
const char doc_name_long[] = { '/', FILE_NAME_LONG, 0};
const char file_name_long[] = { '.', '/', FILE_NAME_LONG, 0 };

static const picoquic_demo_stream_desc_t long_file_name_scenario[] = {
    { 0, 0, PICOQUIC_DEMO_STREAM_ID_INITIAL, doc_name_long, file_name_long, 0 }
};

static const size_t nb_long_file_name_scenario = sizeof(long_file_name_scenario) / sizeof(picoquic_demo_stream_desc_t);
#endif

static size_t const long_file_name_stream_length[] = {
    32
};

int h3_long_file_name_test()
{
    int ret = 0;
#ifdef _WINDOWS
    /* In contrast to Unix, the path size in Windows is limited to 260 bytes.
     * This means that the maximum path size depends on the size of the path
     * to the working directory. It has to be kept small enough! */
    DWORD current_directory_length = GetCurrentDirectory(0, NULL);
    picoquic_demo_stream_desc_t scenario_line;
    char file_name_var[MAX_PATH];
    char doc_name_var[MAX_PATH];
    size_t name_length = 0;
    size_t file_name_length = 0;
    size_t doc_name_length = 0;

    if (current_directory_length + 7 >= MAX_PATH) {
        DBG_PRINTF("Current Directory too long for test: %d chars", current_directory_length);
        ret = -1;
    }
    else {
        name_length = MAX_PATH - current_directory_length - 7;
        if (name_length > 253) {
            name_length = 253;
        }
        file_name_var[file_name_length++] = '.';
        file_name_var[file_name_length++] = '\\';
        doc_name_var[doc_name_length++] = '/';
        for (size_t i = 0; i < name_length; i++) {
            file_name_var[file_name_length++] = '0';
            doc_name_var[doc_name_length++] = '0';
        }
        file_name_var[file_name_length++] = '3';
        doc_name_var[doc_name_length++] = '3';
        file_name_var[file_name_length++] = '2';
        doc_name_var[doc_name_length++] = '2';
        file_name_var[file_name_length++] = 0;
        doc_name_var[doc_name_length++] = 0;
        scenario_line.repeat_count = 0;
        scenario_line.stream_id = 0;
        scenario_line.previous_stream_id = PICOQUIC_DEMO_STREAM_ID_INITIAL;
        scenario_line.doc_name = doc_name_var;
        scenario_line.f_name = file_name_var;
        scenario_line.post_size = 0;
        scenario_line.range = NULL;

        ret = demo_server_test(PICOHTTP_ALPN_H3_LATEST, h3zero_callback, NULL, &scenario_line, 1,
            long_file_name_stream_length, 0, 0, 400000, 0, NULL, NULL, NULL, 0);
    }
#else
    ret = demo_server_test(PICOHTTP_ALPN_H3_LATEST, h3zero_callback, NULL, 
        long_file_name_scenario, nb_long_file_name_scenario, 
        long_file_name_stream_length, 0, 0, 400000, 0, NULL, NULL, NULL, 0);
#endif
    return ret;
}

/* Multi-file test.
 * Create a list of file and their content in the folder "www" in current directory.
 * Create in memory a scenario with the list of files to download in parallel by the client.
 * Execute the scenario, downloading the file in the client scenario.
 * Verify that all the files have been properly received. */
static void demo_test_create_directory(char const* dir_path)
{
#ifdef _WINDOWS
    (void)_mkdir(dir_path);
#else
    (void)mkdir(dir_path, 0777);
#endif
}

static int demo_test_create_file(char const* dir_path, char const* file_name, size_t length, uint64_t* random_ctx)
{
    int ret = 0;
    char name[1024];
    FILE* F;
    size_t nb_sprintf;

    (void)picoquic_sprintf(name, sizeof(name), &nb_sprintf, "%s%s%s", dir_path, PICOQUIC_FILE_SEPARATOR, file_name);

    if ((F = picoquic_file_open(name, "wb")) == NULL) {
        ret = -1;
    }
    else {
        uint8_t data[128];
        size_t written = 0;

        while (written < length) {
            size_t nb = length - written;
            if (nb > sizeof(data)) {
                nb = sizeof(data);
            }
            picoquic_test_random_bytes(random_ctx, data, nb);
            if (fwrite(data, 1, nb, F) <= 0) {
                ret = -1;
                break;
            }
            written += length;
        }

        (void)picoquic_file_close(F);
    }

    return ret;
}

static void demo_test_delete_file(char const* dir_path, char const* file_name)
{
    char name[1024];
    size_t nb_sprintf;

    (void)picoquic_sprintf(name, sizeof(name), &nb_sprintf, "%s%s%s", dir_path, PICOQUIC_FILE_SEPARATOR, file_name);

#ifdef _WINDOWS
    (void)DeleteFileA(name);
#else
    (void)remove(name);
#endif
}

static char * demo_test_create_random_file_name(size_t name_length, uint64_t * random_ctx)
{
    size_t alloc_size = name_length + 1;
    char* file_name = NULL;
    if (name_length < alloc_size) {
        file_name = (char*)malloc(alloc_size);
        if (file_name != NULL) {
            for (size_t i = 0; i < name_length; i++) {
                file_name[i] = 'a' + (int)picoquic_test_uniform_random(random_ctx, 'z' - 'a' + 1);
            }
            file_name[name_length] = 0;
        }
    }
    return file_name;
}

static int demo_test_check_file(char const* www_path, char const* download_path, char const* file_name)
{
    int ret;
    char name1[1024];
    char name2[1024];
    size_t nb_written;

    (void)picoquic_sprintf(name1, sizeof(name1), &nb_written, "%s%s%s", www_path, PICOQUIC_FILE_SEPARATOR, file_name);
    (void)picoquic_sprintf(name2, sizeof(name2), &nb_written, "%s%s%s", download_path, PICOQUIC_FILE_SEPARATOR, file_name);

    if ((ret = picoquic_test_compare_binary_files(name1, name2)) != 0) {
        DBG_PRINTF("Files %s != %s", name1, name2);
    }
    return ret;
}

static int demo_test_multi_scenario_create(picoquic_demo_stream_desc_t** scenario, size_t** stream_length, uint64_t seed, size_t nb_files, size_t name_length, size_t length,
    char const* dir_www, char const* dir_download)
{
    uint64_t random_ctx = seed;
    int ret = 0;
    *scenario = NULL;
    *stream_length = NULL;
    demo_test_create_directory(dir_www);
    demo_test_create_directory(dir_download);

    if (ret == 0) {
        *scenario = (picoquic_demo_stream_desc_t*)malloc(sizeof(picoquic_demo_stream_desc_t) * nb_files);
        if (*scenario == NULL) {
            ret = -1;
        }
        else {
            memset(*scenario, 0, sizeof(picoquic_demo_stream_desc_t) * nb_files);
            *stream_length = (size_t*)malloc(sizeof(size_t) * nb_files);
            if (*stream_length == NULL) {
                ret = -1;
            }
            else {
                for (size_t i = 0; ret == 0 && i < nb_files; i++) {
                    char* file_name = demo_test_create_random_file_name(name_length, &random_ctx);
                    if (file_name == NULL) {
                        ret = -1;
                    } else {
                        ret = demo_test_create_file(dir_www, file_name, length, &random_ctx);
                    }
                    if (ret == 0) {
                        size_t f_name_size = strlen(dir_download) + strlen(PICOQUIC_FILE_SEPARATOR) + strlen(file_name) + 1;
                        char* fn_alloc = (char*)malloc(f_name_size);

                        demo_test_delete_file(dir_download, file_name);
                        (*scenario)[i].doc_name = file_name;
                        (*scenario)[i].previous_stream_id = UINT64_MAX;
                        (*scenario)[i].stream_id = ((uint64_t)4)*i;
                        (*scenario)[i].repeat_count = 0;
                        (*stream_length)[i] = length;
                        (*scenario)[i].f_name = fn_alloc;
                        if (fn_alloc == NULL) {
                            ret = -1;
                        }
                        else {
                            size_t nb_chars = 0;
                            (void)picoquic_sprintf(fn_alloc, f_name_size, &nb_chars, "%s%s%s",
                                dir_download, PICOQUIC_FILE_SEPARATOR, file_name);
                        }
                    }
                }
            }
        }
    }

    return ret;
}

static int demo_test_multi_scenario_check(picoquic_demo_stream_desc_t* scenario, size_t nb_files, char const* dir_www, char const* dir_download)
{
    int ret = 0;

    for (size_t i = 0; ret == 0 && i < nb_files; i++) {
        ret = demo_test_check_file(dir_www, dir_download, scenario[i].doc_name);
        if (ret != 0) {
            DBG_PRINTF("File #%d differs", i);
        }
    }

    return ret;
}

static void demo_test_multi_scenario_free(picoquic_demo_stream_desc_t** scenario, size_t** stream_length, size_t nb_files)
{
    if (*scenario != NULL) {
        for (size_t i = 0; i < nb_files; i++) {
            if ((*scenario)[i].doc_name != NULL) {
                free((char*)((*scenario)[i].doc_name));
                (*scenario)[i].doc_name = NULL;
            }
            if ((*scenario)[i].f_name != NULL) {
                free((char*)((*scenario)[i].f_name));
                (*scenario)[i].f_name = NULL;
            }
        }
        free(*scenario);
        *scenario = NULL;
    }

    if (*stream_length != NULL) {
        free(*stream_length);
        *stream_length = NULL;
    }
}

size_t picohttp_test_multifile_number = 1000;
#define MULTI_FILE_CLIENT_BIN "multi_file_client_trace.bin"
#define MULTI_FILE_SERVER_BIN "multi_file_server_trace.bin"

int http_multi_file_test_one(char const * alpn, picoquic_stream_data_cb_fn server_callback_fn,
    uint64_t do_loss, int do_preemptive_repeat)
{
    picoquic_demo_stream_desc_t* scenario = NULL;
    size_t* stream_length = NULL;
    char const* dir_www = "h3-m-www";
    char const* dir_download = "h3-m-download";
    size_t nb_files = picohttp_test_multifile_number;
    size_t const name_length = 10;
    size_t const file_length = 32;
    uint64_t const random_seed = 0xab8acadab8aull;
    picohttp_server_parameters_t file_param;

    memset(&file_param, 0, sizeof(picohttp_server_parameters_t));
    file_param.web_folder = dir_www;

    int ret = demo_test_multi_scenario_create(&scenario, &stream_length, random_seed, nb_files, name_length, file_length, dir_www, dir_download);

    if (ret == 0) {
        if (stream_length == NULL) {
            ret = -1;
        }
        else {
            ret = demo_server_test(alpn, server_callback_fn, (void*)&file_param, scenario, nb_files,
                stream_length, 0, do_loss, 5000000, 0, NULL, MULTI_FILE_CLIENT_BIN, MULTI_FILE_SERVER_BIN, do_preemptive_repeat);
        }
    }

    if (ret == 0) {
        ret = demo_test_multi_scenario_check(scenario, nb_files, dir_www, dir_download);
    }

    demo_test_multi_scenario_free(&scenario, &stream_length, nb_files);

    return ret;
}

int h3_multi_file_test()
{
    return http_multi_file_test_one(PICOHTTP_ALPN_H3_LATEST, h3zero_callback, 0, 0);
}

#define H3ZERO_MULTI_LOSS_PATTERN 0xa242EDB710000ull

int h3_multi_file_loss_test()
{
    uint64_t loss_pattern = H3ZERO_MULTI_LOSS_PATTERN;
    return http_multi_file_test_one(PICOHTTP_ALPN_H3_LATEST, h3zero_callback, loss_pattern, 0);
}

int h3_multi_file_preemptive_test()
{
    uint64_t loss_pattern = H3ZERO_MULTI_LOSS_PATTERN;
    return http_multi_file_test_one(PICOHTTP_ALPN_H3_LATEST, h3zero_callback, loss_pattern, 1);
}

int h09_multi_file_test()
{
    return http_multi_file_test_one(PICOHTTP_ALPN_HQ_LATEST, picoquic_h09_server_callback, 0, 0);
}

int h09_multi_file_loss_test()
{
    uint64_t loss_pattern = H3ZERO_MULTI_LOSS_PATTERN;
    return http_multi_file_test_one(PICOHTTP_ALPN_HQ_LATEST, picoquic_h09_server_callback, 
        loss_pattern, 0);
}

int h09_multi_file_preemptive_test()
{
    uint64_t loss_pattern = H3ZERO_MULTI_LOSS_PATTERN;
    return http_multi_file_test_one(PICOHTTP_ALPN_HQ_LATEST, picoquic_h09_server_callback,
        loss_pattern, 1);
}

/* HTTP Server stress.
 * Execute in parallel a series of connection requests to the HTTP server.
 * Verify that all requests are served.
 *
 * Requirement:
 *  - network connection to each client.
 *  - set of scenarios (pick prime number)
 *     - in scenario parsing, add a client number to each download file name.
 *  - choice of h09 or h3 for each scenario (alternate)
 *  - number of clients
 */


static const picoquic_demo_stream_desc_t http_stress_scenario_1[] = {
    { 0, 0, PICOQUIC_DEMO_STREAM_ID_INITIAL, "/", "_", 0},
    { 0, 4, 0, "test.html", "test.html", 0 },
    { 0, 8, 0, "main.jpg", "main.jpg", 0 },
    { 0, 12, 0, "/bla/bla/", "_bla_bla_", 0 }
};

static const picoquic_demo_stream_desc_t http_stress_scenario_2[] = {
    { 0, 0, PICOQUIC_DEMO_STREAM_ID_INITIAL, "/", "_", 0 },
    { 0, 4, 0, "main.jpg", "main.jpg", 0 },
    { 0, 8, 4, "test.html", "test.html", 0 }
};

static const picoquic_demo_stream_desc_t http_stress_scenario_3[] = {
    { 1000, 0, PICOQUIC_DEMO_STREAM_ID_INITIAL, "/", "_", 0 }
};

static const picoquic_demo_stream_desc_t http_stress_scenario_4[] = {
    { 0, 0, PICOQUIC_DEMO_STREAM_ID_INITIAL, "/cgi-sink", "_cgi-sink", 1000000 },
    { 0, 4, 0, "/", "_", 0 }
};

typedef struct st_http_stress_scenario_list_t {
    const picoquic_demo_stream_desc_t * sc;
    const size_t sc_nb;
} http_stress_scenario_list_t;

#define HTTP_TEST_SCENARIO(scenario) { scenario, sizeof(scenario)/sizeof(picoquic_demo_stream_desc_t) }

static const http_stress_scenario_list_t http_stress_scenario_list[] = {
    HTTP_TEST_SCENARIO(http_stress_scenario_1),
    HTTP_TEST_SCENARIO(http_stress_scenario_2),
    HTTP_TEST_SCENARIO(http_stress_scenario_3),
    HTTP_TEST_SCENARIO(http_stress_scenario_4)
};

static size_t nb_http_stress_scenario = sizeof(http_stress_scenario_list) / sizeof(http_stress_scenario_list_t);

typedef struct st_http_stress_client_context_t {
    picoquic_quic_t * qclient;
    picoquic_cnx_t * cnx_client;
    picoquic_demo_callback_ctx_t callback_ctx;
    struct sockaddr_storage client_address;
    uint64_t client_time;
    int is_dropped;
    int is_not_sending;
} http_stress_client_context_t;

http_stress_client_context_t* http_stress_client_delete(http_stress_client_context_t* ctx)
{
    picoquic_demo_client_delete_context(&ctx->callback_ctx);
    if (ctx->cnx_client != NULL) {
        ctx->cnx_client = NULL;
    }
    if (ctx->qclient != NULL) {
        picoquic_free(ctx->qclient);
        ctx->qclient = NULL;
    }
    free(ctx);
    return(NULL);
}

http_stress_client_context_t* http_stress_client_create(size_t client_id, uint64_t * simulated_time, 
    struct sockaddr* server_address, int initial_random)
{
    int ret = 0;
    http_stress_client_context_t* ctx = (http_stress_client_context_t*)malloc(sizeof(http_stress_client_context_t));

    if (ctx != NULL) {
        char const* alpn = NULL;

        memset(ctx, 0, sizeof(http_stress_client_context_t));

        /* alternate ALPN between H3, HQ and "server chooses" */
        switch (client_id % 3) {
        case 0:
            alpn = PICOHTTP_ALPN_H3_LATEST;
            break;
        case 1:
            alpn = PICOHTTP_ALPN_HQ_LATEST;
            break;
        default:
            break;
        }

        ctx->qclient = picoquic_create(8, NULL, NULL, NULL, alpn, NULL, NULL, NULL, NULL, NULL, *simulated_time, simulated_time, NULL, NULL, 0);

        if (ctx->qclient == NULL) {
            ret = -1;
        }
        else {
            /* Use predictable value for ICID */
            picoquic_connection_id_t i_cid = picoquic_null_connection_id;
            uint64_t id64 = 0xdeadbeefbabac001ull;

            picoquic_set_default_congestion_algorithm(ctx->qclient, picoquic_bbr_algorithm);
            picoquic_set_null_verifier(ctx->qclient);
            if (initial_random) {
                picoquic_set_random_initial(ctx->qclient, 1);
            }

            id64 ^= (uint64_t)client_id;
            for (int i = 0; i < 8; i++) {
                i_cid.id[i] = (uint8_t)id64;
                id64 >>= 8;
            }

            /* Use various values for local CID length*/
            ctx->qclient->local_cnxid_length = client_id % 9;

            /* Create a client connection */
            ctx->cnx_client = picoquic_create_cnx(ctx->qclient, i_cid, picoquic_null_connection_id, server_address, *simulated_time, 0, PICOQUIC_TEST_FILE_SERVER_CERT, alpn, 1);

            if (ctx->cnx_client == NULL) {
                ret = -1;
            }
            else {
                size_t scenario_id = client_id % nb_http_stress_scenario;

                ret = picoquic_demo_client_initialize_context(&ctx->callback_ctx, http_stress_scenario_list[scenario_id].sc, http_stress_scenario_list[scenario_id].sc_nb, alpn, 1 /* No disk!*/, 0);
                if (ret == 0) {
                    picoquic_set_callback(ctx->cnx_client, picoquic_demo_client_callback, &ctx->callback_ctx);
                    ctx->callback_ctx.no_print = 1;
                }
            }
        }

        if (ret == 0) {
            char test_addr[256];
            size_t nb_written = 0;

            if ((ret = picoquic_sprintf(test_addr, sizeof(test_addr), &nb_written, "2::%x:%x", (uint16_t)(client_id >> 16), (uint16_t)client_id & 0xFFFF)) == 0) {
                ret = picoquic_store_text_addr(&ctx->client_address, test_addr, 4443);
            }
        }
        
        if (ret == 0)
        {
            /* Requires TP grease, for interop tests */
            ctx->cnx_client->grease_transport_parameters = 1;
            ctx->cnx_client->local_parameters.enable_time_stamp = 3;
            ctx->client_time = *simulated_time;

            if (ret == 0) {
                ret = picoquic_start_client_cnx(ctx->cnx_client);
            }
        }

        if (ret == 0) {
            ret = picoquic_demo_client_start_streams(ctx->cnx_client, &ctx->callback_ctx, PICOQUIC_DEMO_STREAM_ID_INITIAL);
        }
    }

    if (ret != 0 && ctx != NULL) {
        /* TODO: delete context */
        ctx = http_stress_client_delete(ctx);
    }

    return ctx;
}

size_t picohttp_nb_stress_clients = 128;
uint64_t picohttp_random_stress_context = 0x12345678;

int http_stress_test_one(int do_corrupt, int do_drop, int initial_random)
{
    /* initialize the server, address 1::1 */
    /* Create QUIC context */
    int ret = 0;
    uint64_t simulated_time = 0;
    uint8_t reset_seed[PICOQUIC_RESET_SECRET_SIZE] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 , 13, 14, 15, 16 };
    char test_server_cert_file[512];
    char test_server_key_file[512];
    char file_name_buffer[1024];
    picohttp_server_parameters_t file_param;
    picoquic_quic_t* qserver = NULL;
    http_stress_client_context_t** ctx_client = NULL;
    picoquictest_sim_link_t* lan = NULL;
    struct sockaddr_storage server_address;
    uint64_t server_time = 0;
    uint64_t random_context = picohttp_random_stress_context;
    size_t nb_stress_clients = picohttp_nb_stress_clients;
    int nb_loops = 0;

    ret = picoquic_store_text_addr(&server_address, "1::1", 443);

    if (ret == 0) {
        ret = serve_file_test_set_param(&file_param, file_name_buffer, sizeof(file_name_buffer));
    }

    if (ret == 0) {
        ret = picoquic_get_input_path(test_server_cert_file, sizeof(test_server_cert_file), picoquic_solution_dir, PICOQUIC_TEST_FILE_SERVER_CERT);
    }

    if (ret == 0) {
        ret = picoquic_get_input_path(test_server_key_file, sizeof(test_server_key_file), picoquic_solution_dir, PICOQUIC_TEST_FILE_SERVER_KEY);
    }
    if (ret == 0) {
        /* Make sure that the server is configured to handle all required clients.
        */
        qserver = picoquic_create((uint32_t)nb_stress_clients, test_server_cert_file, test_server_key_file, NULL, NULL,
            picoquic_demo_server_callback, &file_param,
            NULL, NULL, reset_seed, simulated_time, &simulated_time, NULL, NULL, 0);
        if (qserver == NULL) {
            DBG_PRINTF("%s", "Cannot create http_stress server");
            ret = -1;
        }
        else {
            picoquic_set_alpn_select_fn(qserver, picoquic_demo_server_callback_select_alpn);
            if (initial_random) {
                picoquic_set_random_initial(qserver, 1);
            }
            if (random_context == 0) {
                picoquic_crypto_random(qserver, &random_context, sizeof(random_context));
            }
        }
    }

    if (ret == 0) {
        ctx_client = (http_stress_client_context_t**)malloc(sizeof(http_stress_client_context_t*) * nb_stress_clients);
        if (ctx_client == NULL) {
            ret = -1;
        }
        else {
            /* initialize each client, address 2::nnnn */
            memset(ctx_client, 0, sizeof(http_stress_client_context_t*) * nb_stress_clients);
            for (size_t i = 0; ret == 0 && i < nb_stress_clients; i++) {
                ctx_client[i] = http_stress_client_create(i, &simulated_time, (struct sockaddr*) & server_address, initial_random);
                if (ctx_client[i] == NULL) {
                    ret = -1;
                }
            }
        }
    }

    if (ret == 0)
    {
        /* simulate a local network linking every client and the server */
        lan = picoquictest_sim_link_create(1.0, 1000, NULL, 10000, simulated_time);
        if (lan == NULL) {
            ret = -1;
        }
    }

    /* run the simulation until all clients are served */
    while (ret == 0) {
        uint64_t next_time = UINT64_MAX;
        int is_lan_ready = lan->first_packet != NULL;
        size_t client_id = nb_stress_clients;
        picoquic_quic_t* qready = NULL;
        struct sockaddr* ready_from = NULL;

        nb_loops++;
        if (nb_loops > 10000000) {
            DBG_PRINTF("Loop detected after %d iterations", nb_loops);
            ret = -1;
            break;
        }

        if (is_lan_ready) {
            next_time = picoquictest_sim_link_next_arrival(lan, next_time);
        }

        if (lan->queue_time < simulated_time + lan->queue_delay_max) {
            /* Simulate contention on access to LAN, to avoid creating peak loads and huge queues */
            if (server_time < next_time) {
                qready = qserver;
                ready_from = (struct sockaddr*) & server_address;
                next_time = server_time;
            }

            for (size_t i = 0; ret == 0 && i < nb_stress_clients; i++) {
                if (ctx_client[i] != NULL && ctx_client[i]->client_time < next_time && !ctx_client[i]->is_not_sending) {
                    qready = ctx_client[i]->qclient;
                    ready_from = (struct sockaddr*) & ctx_client[i]->client_address;
                    next_time = ctx_client[i]->client_time;
                    client_id = i;
                }
            }
        }

        if (next_time > simulated_time) {
            if (next_time == UINT64_MAX) {
                DBG_PRINTF("%s", "end of simulation");
                break;
            }
            else {
                simulated_time = next_time;
            }
        }
        if (qready != NULL) {
            picoquictest_sim_packet_t* prepared = picoquictest_sim_link_create_packet();

            if (prepared == NULL) {
                ret = -1;
            }
            else {
                /* ask server to prepare next packet */
                int if_index = -1;

                ret = picoquic_prepare_next_packet(qready, simulated_time, prepared->bytes, sizeof(prepared->bytes),
                    &prepared->length, &prepared->addr_to, &prepared->addr_from, &if_index, NULL, NULL);

                if (prepared->length == 0) {
                    free(prepared);
                }
                else {
                    if (prepared->addr_from.ss_family == 0) {
                        picoquic_store_addr(&prepared->addr_from, ready_from);
                    }
                    picoquictest_sim_link_submit(lan, prepared, simulated_time);
                }
            }

            if (client_id < nb_stress_clients && ctx_client[client_id] != NULL) {
                if (ctx_client[client_id]->is_dropped) {
                    uint64_t should_not_send = picoquic_test_uniform_random(&random_context, 5);
                    ctx_client[client_id]->is_not_sending = should_not_send == 3;
                }
                if (!ctx_client[client_id]->is_not_sending) {
                    ctx_client[client_id]->client_time = picoquic_get_next_wake_time(ctx_client[client_id]->qclient, simulated_time);
                    if (ctx_client[client_id]->client_time == UINT64_MAX) {
                        DBG_PRINTF("End of client %d", (int)client_id);
                    }
                }
            }
            else {
                server_time = picoquic_get_next_wake_time(qserver, simulated_time);
                if (server_time == UINT64_MAX) {
                    DBG_PRINTF("End of server at %llu", (unsigned long long)simulated_time);
                }
            }
        }
        else if (is_lan_ready) {
            picoquictest_sim_packet_t* arrival = picoquictest_sim_link_dequeue(lan, simulated_time);

            if (arrival != NULL) {
                if (do_corrupt) {
                    /* simulate packet corruption in flight. But, in the case of server initial packets,
                     * corrupting the initial connection ID will result in the creation of extra initial
                     * contexts, which can cause the server to end up with too many connections. We 
                     * prevent that by doing a minimal parsing of the long-header packets, to avoid
                     * messing with CID values there.
                     */
                    uint64_t lost_byte = picoquic_test_uniform_random(&random_context,((uint64_t)4)* arrival->length);
                    uint64_t min_length = 0;

                    if ((arrival->bytes[0] & 0x80) == 0x80) {
                        uint64_t cid_length = 0;
                        min_length = 1 + 4; /* Skip first byte and version number */
                        if (min_length < arrival->length) {
                            cid_length = arrival->bytes[min_length];
                            min_length += 1 + cid_length; /* skip destination CID */
                        }
                        if (min_length < arrival->length) {
                            cid_length = arrival->bytes[min_length];
                            min_length += 1 + cid_length; /* skip source CID */
                        }
                    }

                    if (lost_byte < arrival->length && lost_byte > min_length) {
                        arrival->bytes[lost_byte] ^= 0xFF;
                    }
                }
                if (picoquic_compare_addr((struct sockaddr*) & arrival->addr_to, (struct sockaddr*) & server_address) == 0) {
                    /* submit to server */
                    ret = picoquic_incoming_packet(qserver, arrival->bytes, arrival->length,
                        (struct sockaddr*) & arrival->addr_from, (struct sockaddr*) & arrival->addr_to, 0, 0, simulated_time);
                    server_time = picoquic_get_next_wake_time(qserver, simulated_time);
                }
                else {
                    int is_matched = 0;
                    for (size_t i = 0; ret == 0 && i < nb_stress_clients; i++) {
                        if (ctx_client[i] != NULL && !ctx_client[i]->is_dropped &&
                            picoquic_compare_addr((struct sockaddr*) & arrival->addr_to, (struct sockaddr*) & ctx_client[i]->client_address) == 0) {
                            /* submit to client */
                            ret = picoquic_incoming_packet(ctx_client[i]->qclient, arrival->bytes, arrival->length,
                                (struct sockaddr*) & arrival->addr_from, (struct sockaddr*) & arrival->addr_to, 0, 0, simulated_time);
                            ctx_client[i]->client_time = picoquic_get_next_wake_time(ctx_client[i]->qclient, simulated_time);
                            is_matched = 1;

                            if (do_drop && ctx_client[i]->qclient->cnx_list != NULL) {
                                uint64_t should_drop = picoquic_test_uniform_random(&random_context, 11);
                                ctx_client[i]->is_dropped = should_drop == 3;
                            }
                        }
                    }
                    if (!is_matched) {
                        DBG_PRINTF("%s", "Packet cannot be delivered");
                    }
                }

                free(arrival);
            }
        }
        else {
            /* end of simulation. */
            break;
        }
    }

    if (!do_corrupt && !do_drop) {
        /* verify that each client scenario is properly completed */
        for (size_t i = 0; ret == 0 && i < nb_stress_clients; i++) {
            if (ctx_client[i] != NULL) {
                if (!ctx_client[i]->callback_ctx.connection_ready) {
                    DBG_PRINTF("Connection #%d failed", (int)i);
                    ret = -1;
                }
                else if (!ctx_client[i]->callback_ctx.connection_closed) {
                    DBG_PRINTF("Connection #%d not closed", (int)i);
                    ret = -1;
                }
            }
        }
    }

    if (!do_corrupt) {
        /* verify that the global execution time makes sense,
        * but only if we are not fuzzing, since fuzzing likely
        * will cause instances of idle timers on clients or
        * servers. */
        if (ret == 0 && simulated_time > 240000000ull + 1000000ull * nb_stress_clients) {
            DBG_PRINTF("Taking %llu microseconds for %d clients!", (unsigned long long)simulated_time, (int)nb_stress_clients);
            ret = -1;
        }
    }

    /* clean up */
    if (lan != NULL) {
        picoquictest_sim_link_delete(lan);
        lan = NULL;
    }

    if (ctx_client != NULL) {
        for (size_t i = 0; i < nb_stress_clients; i++) {
            if (ctx_client[i] != NULL) {
                (void)http_stress_client_delete(ctx_client[i]);
            }
        }
        free(ctx_client);
    }

    if (qserver != NULL) {
        picoquic_free(qserver);
    }

    return ret;
}

int http_stress_test()
{
    return http_stress_test_one(0, 0, 0);
}

int http_corrupt_test()
{
    return http_stress_test_one(1, 0, 0);
}

int http_drop_test()
{
    return http_stress_test_one(0, 1, 0);
}

int http_corrupt_rdpn_test()
{
    return http_stress_test_one(1, 0, 1);
}

/* Test the selection of ALPN
 */
char const* alpn_good_list[] = {
    "h3-34", "hq-34", "h3-29", "hq-29", "h3", "hq-interop", "perf", NULL };
picoquic_alpn_enum alpn_proto_list[] = {
    picoquic_alpn_http_3, picoquic_alpn_http_0_9, picoquic_alpn_http_3, picoquic_alpn_http_0_9,
    picoquic_alpn_http_3, picoquic_alpn_http_0_9,
    picoquic_alpn_quicperf };
char const* alpn_bad_list[] = {
    "h3-00", "hq", "hq-interop-00", "", "unknown", NULL };

int demo_alpn_test()
{
    int ret = 0;
    /* Try the list of correct and incorrect values */
    for (int i = 0; ret == 0 && alpn_good_list[i] != NULL; i++) {
        picoquic_alpn_enum x = picoquic_parse_alpn_nz(alpn_good_list[i], strlen(alpn_good_list[i]));
        if (x != alpn_proto_list[i]) {
            DBG_PRINTF("For ALPN = \"%s\", got proto %d instead of %d", alpn_good_list[i], x, alpn_proto_list[i]);
            ret = -1;
            break;
        }
    }

    for (int i = 0; ret == 0 && alpn_bad_list[i] != NULL; i++) {
        picoquic_alpn_enum x = picoquic_parse_alpn_nz(alpn_bad_list[i], strlen(alpn_bad_list[i]));
        if (x != picoquic_alpn_undef) {
            DBG_PRINTF("For ALPN = \"%s\", got proto %d instead of %d", alpn_bad_list[i], x, picoquic_alpn_undef);
            ret = -1;
            break;
        }
    }

    /* Try the list of correct values with extra zero */
    for (int i = 0; ret == 0 && alpn_good_list[i] != NULL; i++) {
        char buf[256];
        picoquic_alpn_enum x;
        size_t len = strlen(alpn_good_list[i]);

        memset(buf, 0, sizeof(buf));
        memcpy(buf, alpn_good_list[i], len);
        x = picoquic_parse_alpn_nz(buf, len+1);
        if (x != picoquic_alpn_undef) {
            DBG_PRINTF("For ALPN = \"%s\\0...\", got proto %d instead of %d",
                alpn_good_list[i], x, picoquic_alpn_undef);
            ret = -1;
            break;
        }
    }

    /* Same test, but with large buffer */
    for (int i = 0; ret == 0 && alpn_good_list[i] != NULL; i++) {
        char buf[256];
        picoquic_alpn_enum x;

        memset(buf, 'a', sizeof(buf));
        memcpy(buf, alpn_good_list[i], strlen(alpn_good_list[i]));
        x = picoquic_parse_alpn_nz(buf, sizeof(buf));
        if (x != picoquic_alpn_undef) {
            DBG_PRINTF("For ALPN = \"%saaaaaaaaaaaaaa...\", got proto %d instead of %d", 
                alpn_good_list[i], x, picoquic_alpn_undef);
            ret = -1;
            break;
        }
    }

    return ret;
}

/* Test encode and decode of settings frame
 */

int h3zero_settings_encode_test(const uint8_t* ref, size_t ref_length, h3zero_settings_t* test)
{
    int ret = -1;
    uint8_t buffer[1024];
    uint8_t* bytes = buffer;
    uint8_t* bytes_max = buffer + sizeof(buffer);

    if ((bytes = h3zero_settings_encode(bytes, bytes_max, test)) != NULL &&
        (bytes - buffer) == ref_length &&
        memcmp(buffer, ref, ref_length) == 0) {
        ret = 0;
    }
    return ret;
}

int h3zero_settings_decode_test(const uint8_t* bytes, size_t length, h3zero_settings_t* ref, int check_length)
{
    int ret = 0;
    h3zero_settings_t decoded;
    const uint8_t * bytes_max = bytes + length;

    bytes = h3zero_settings_decode(bytes, bytes_max, &decoded);
    if (bytes == NULL) {
        ret = -1;
    }
    else if (check_length && bytes != bytes_max) {
        ret = -1;
    }
    else if (decoded.table_size != ref->table_size) {
        ret = -1;
    }
    else if (decoded.blocked_streams != ref->blocked_streams) {
        ret = -1;
    }
    else if (decoded.enable_connect_protocol != ref->enable_connect_protocol){
        ret = -1;
    }
    else if (decoded.h3_datagram != ref->h3_datagram){
        ret = -1;
    }
    else if (decoded.webtransport_max_sessions != ref->webtransport_max_sessions) {
        ret = -1;
    }
    return ret;
}

h3zero_settings_t default_setting_expected = {
    1, 0, 0, 0, 1, 1, 0
};

int h3zero_settings_test()
{
    int ret = h3zero_settings_decode_test(h3zero_default_setting_frame + 1, h3zero_default_setting_frame_size - 1, &default_setting_expected, 1);

    if (ret == 0) {
        ret = h3zero_settings_encode_test(h3zero_default_setting_frame + 1, h3zero_default_setting_frame_size - 1, &default_setting_expected);
    }

    return ret;
}

            /*
            * h3zero_content_type_none = 0,
            * h3zero_content_type_not_supported,
            * h3zero_content_type_text_html,
            * h3zero_content_type_text_plain,
            * h3zero_content_type_image_gif,
            * h3zero_content_type_image_jpeg,
            * h3zero_content_type_image_png,
            * h3zero_content_type_dns_message,
            * h3zero_content_type_javascript,
            * h3zero_content_type_json,
            * h3zero_content_type_www_form_urlencoded,
            * h3zero_content_type_text_css
            */

typedef struct st_h3zero_string_content_type_compar_list_t {
    const char *path;
    const h3zero_content_type_enum content_type;
} h3zero_string_content_type_compare_list_t;

char const root_path_str[] = { '/' , 0 };
char const no_ext_path_str[] = { '/', 'n', 'o', 'e', 'x', 't' , 0 };
char const htm_path_str[] = { '/', 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'h', 't', 'm', 0 };
char const html_path_str[] = { '/', 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'h', 't', 'm', 'l', 0 };
char const txt_path_str[] = { '/', 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 't', 'x', 't', 0 };
char const gif_path_str[] = { '/', 'i', 'm', 'g', '.', 'g', 'i', 'f', 0 };
char const jpg_path_str[] = { '/', 'i', 'm', 'g', '.', 'j', 'p', 'g', 0 };
char const jpeg_path_str[] = { '/', 'i', 'm', 'g', '.', 'j', 'p', 'e', 'g', 0 };
char const png_path_str[] = { '/', 'i', 'm', 'g', '.', 'p', 'n', 'g', 0 };
char const js_path_str[] = { '/', 's', 'c', 'r', 'i', 'p', 't', '.', 'j', 's', 0 };
char const json_path_str[] = { '/', 'd', 'a', 't', 'a', '.', 'j', 's', 'o', 'n', 0 };
char const css_path_str[] = { '/', 's', 't', 'y', 'l', 'e', '.', 'c', 's', 's', 0 };

char const double_dot_path_str[] = { '/', 's', 't', 'y', 'l', 'e', '.', 'e', 'x', 't', '.', 'h', 't', 'm', 'l', 0 };

static const h3zero_string_content_type_compare_list_t h3zero_string_content_type_compare_list[] = {
    /* Invalid paths and paths without extensions. */
    { NULL, h3zero_content_type_text_plain },
    { root_path_str, h3zero_content_type_text_plain },
    { no_ext_path_str, h3zero_content_type_text_plain },
    { txt_path_str, h3zero_content_type_text_plain },

    /* Valid paths with extensions. */
    { htm_path_str, h3zero_content_type_text_html },
    { html_path_str, h3zero_content_type_text_html },
    { gif_path_str, h3zero_content_type_image_gif },
    { jpg_path_str, h3zero_content_type_image_jpeg },
    { jpeg_path_str, h3zero_content_type_image_jpeg },
    { png_path_str, h3zero_content_type_image_png },
    { js_path_str, h3zero_content_type_javascript },
    { json_path_str, h3zero_content_type_json },
    { css_path_str, h3zero_content_type_text_css },

    /* Special cases but valid. */
    { double_dot_path_str, h3zero_content_type_text_html }
    /* TODO Add more test cases.
     * e.g. query string?
     */
};

static size_t nb_h3zero_string_content_type_compare = sizeof(h3zero_string_content_type_compare_list) / sizeof(h3zero_string_content_type_compare_list_t);

int h3zero_get_content_type_by_path_test() {
    int ret = 0;

    for (size_t i = 0; i < nb_h3zero_string_content_type_compare; i++) {
        h3zero_string_content_type_compare_list_t item = h3zero_string_content_type_compare_list[i];

        h3zero_content_type_enum ct_res;
        if ((ct_res = h3zero_get_content_type_by_path(item.path)) != item.content_type) {
            fprintf(stdout, "Path %s expects content type %d, but got %d. \n", item.path, item.content_type, ct_res);
            ret = -1;
            break;
        }
    }

    return ret;
}

/* Test support for H3 greasing of stream types.
* This is a test of the handling of unidirectional streams of unknown types. The
* desired handling is specified in
* https://datatracker.ietf.org/doc/html/rfc9114#name-unidirectional-streams
* If the stream header indicates a stream type that is not supported by the recipient,
* the remainder of the stream cannot be consumed as the semantics are unknown.
* Recipients of unknown stream types MUST either abort reading of the stream or
* discard incoming data without further processing. If reading is aborted,
* the recipient SHOULD use the H3_STREAM_CREATION_ERROR error code or a
* reserved error code (Section 8.1). The recipient MUST NOT consider unknown
* stream types to be a connection error of any kind.
* This can be tested with stream types reserved for Grease, as specified in
* https://datatracker.ietf.org/doc/html/rfc9114#name-reserved-stream-types,
* which reserves codes of the form 0x1f * N + 0x21.
* 
* We want the tests in two directions: server and client.
 */

static int h3_grease_test_one(int server_test)
{
    uint64_t simulated_time = 0;
    uint64_t loss_mask = 0;
    uint64_t time_out;
    int nb_trials = 0;
    int was_active = 0;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    picoquic_demo_callback_ctx_t callback_ctx;
    int ret;
    void* server_param = NULL;
    picoquic_connection_id_t initial_cid = { {0x68, 0xea, 0x5e, 0, 0, 0, 0, 0}, 8 };
    initial_cid.id[3] = (uint8_t)server_test;

    ret = picoquic_demo_client_initialize_context(&callback_ctx, demo_test_scenario, nb_demo_test_scenario, PICOHTTP_ALPN_H3_LATEST, 0, 0);
    callback_ctx.out_dir = NULL;
    callback_ctx.no_print = 1;

    if (ret == 0) {
        ret = tls_api_init_ctx_ex(&test_ctx,
            PICOQUIC_INTERNAL_TEST_VERSION_1,
            PICOQUIC_TEST_SNI, PICOHTTP_ALPN_H3_LATEST, &simulated_time, NULL, NULL, 0, 1, 0, &initial_cid);

        if (ret == 0) {
            picoquic_set_binlog(test_ctx->qserver, ".");
            test_ctx->qserver->use_long_log = 1;
        }

        if (ret == 0) {
            picoquic_set_binlog(test_ctx->qclient, ".");
        }

        /* Question: is there a need to change the server params? */
    }

    if (ret != 0) {
        DBG_PRINTF("Could not create the QUIC test contexts for V=%x\n", PICOQUIC_INTERNAL_TEST_VERSION_1);
    }
    else if (test_ctx == NULL || test_ctx->cnx_client == NULL || test_ctx->qserver == NULL) {
        DBG_PRINTF("%s", "Connections where not properly created!\n");
        ret = -1;
    }

    /* The default procedure creates connections using the test callback.
    * We want to replace that by the demo client callback */

    if (ret == 0) {
        picoquic_set_alpn_select_fn(test_ctx->qserver, picoquic_demo_server_callback_select_alpn);
        picoquic_set_default_callback(test_ctx->qserver, h3zero_callback, server_param);
        picoquic_set_callback(test_ctx->cnx_client, picoquic_demo_client_callback, &callback_ctx);
        if (ret == 0) {
            ret = picoquic_start_client_cnx(test_ctx->cnx_client);
        }
    }

    if (ret == 0) {
        ret = tls_api_connection_loop(test_ctx, &loss_mask, 0, &simulated_time);
    }

    if (ret == 0) {
        ret = picoquic_demo_client_start_streams(test_ctx->cnx_client, &callback_ctx, PICOQUIC_DEMO_STREAM_ID_INITIAL);
    }

    if (ret == 0) {
        /* start a unidir stream for greasing.
         * grease_stream_type = 0x1f * 4 + 0x21 = 0x9d
         * encodes as varint= 0x409d
        */
        uint8_t grease_data[] = { 0x40, 0x9d, 0xba, 0xad, 0xc0, 0xff, 0xee, 0x00, 0x00, 0x00, 0x00 };
        picoquic_cnx_t* grease_cnx = (server_test) ? test_ctx->cnx_client: test_ctx->cnx_server;
        uint64_t grease_stream_id = picoquic_get_next_local_stream_id(grease_cnx, 1);
        ret = picoquic_add_to_stream(grease_cnx, grease_stream_id, grease_data, sizeof(grease_data), 1);
        if (ret != 0) {
            DBG_PRINTF("Cannot send grease data, ret=%d(0x%d)", ret, ret);
        }
    }

    /* Simulate the connection from the client side. */
    time_out = simulated_time + 30000000;
    while (ret == 0 && picoquic_get_cnx_state(test_ctx->cnx_client) != picoquic_state_disconnected) {
        ret = tls_api_one_sim_round(test_ctx, &simulated_time, time_out, &was_active);

        if (ret == -1) {
            break;
        }

        if (picoquic_is_cnx_backlog_empty(test_ctx->cnx_client)) {
            if (callback_ctx.nb_open_streams == 0) {
                ret = picoquic_close(test_ctx->cnx_client, 0);
            }
            else if (simulated_time > callback_ctx.last_interaction_time &&
                simulated_time - callback_ctx.last_interaction_time > 10000000ull) {
                (void)picoquic_close(test_ctx->cnx_client, 0);
                ret = -1;
            }
        }
        if (++nb_trials > 100000) {
            ret = -1;
            break;
        }
    }

    /* Minimal verification that the data was properly received. */
    for (size_t i = 0; ret == 0 && i < nb_demo_test_scenario; i++) {
        picoquic_demo_client_stream_ctx_t* stream = callback_ctx.first_stream;

        while (stream != NULL && stream->stream_id != demo_test_scenario[i].stream_id) {
            stream = stream->next_stream;
        }

        if (stream == NULL) {
            DBG_PRINTF("Scenario stream %d is missing\n", (int)i);
            ret = -1;
        }
        else if (stream->F != NULL) {
            DBG_PRINTF("Scenario stream %d, file was not closed\n", (int)i);
            ret = -1;
        }
        else if (stream->post_sent < demo_test_scenario[i].post_size) {
            DBG_PRINTF("Scenario stream %d, only %d bytes sent\n",
                (int)i, (int)stream->post_sent);
            ret = -1;
        }
    }

    if (ret == 0 && test_ctx->qclient->nb_data_nodes_allocated > test_ctx->qclient->nb_data_nodes_in_pool) {
        ret = -1;
    }
    else if (ret == 0 && test_ctx->qserver->nb_data_nodes_allocated > test_ctx->qserver->nb_data_nodes_in_pool) {
        ret = -1;
    }

    picoquic_demo_client_delete_context(&callback_ctx);

    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }

    return ret;
}

int h3_grease_client_test()
{
    int ret = h3_grease_test_one(0);

    return ret;
}

int h3_grease_server_test()
{
    int ret = h3_grease_test_one(1);

    return ret;
}