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

#include <string.h>
#include <stdlib.h>
#include "picoquic.h"
#include "picoquic_utils.h"
#include "h3zero_uri.h"

#define abempty_one_char '/'
#define abempty_one_name '/','e','x','a','m','p','l','e'
#define abempty_two_names abempty_one_name,abempty_one_name
#define i_val_1 '1'
#define i_val_n '1','2','3','4','5','6','7','8','9'
#define i_val_nx '1','%','3','2','3','4','5','6','7','8','9'
#define i_val_bad '1','%','a','b','3','4','5','6','7','8','9'
#define i_val_overflow i_val_n , i_val_n , i_val_n
#define i_val_bad2 '1','2','3','4','5','6','7','%','9'
#define i_val_bad3 '1','2','3','4','5','6','7','%'
#define s_val_1 'a'
#define s_val_8 'a','b','c','d','e','f','g','0'
#define s_val_x 'a','b','c','d','e','f','g','%','3','0'
#define s_val_bad 'a','b','c','d','e','f','g','%','3'
#define s_val_too_long s_val_8,'x'
#define name_int 'i','n','t'
#define name_txt 't','x','t'
#define name_other 'o','t','h','e','r'

char const str_1[] = { s_val_1 };
char const str_8[] = { s_val_8 };

char const param_int[] = { name_int };
char const param_txt[] = { name_txt };

char const path01[] = { abempty_one_char };
char const path02[] = { abempty_one_char, '?' };
char const path03[] = { abempty_one_char, '?', name_int, '=', i_val_1 };
char const path04[] = { abempty_one_char, '?', name_txt, '=', s_val_1 };
char const path05[] = { abempty_one_char, '?', name_txt, '=', s_val_1, '&', name_int, '=', i_val_1};
char const path06[] = { abempty_one_char, '?', name_int, '=', i_val_1, '&', name_txt, '=', s_val_1 };
char const path07[] = { abempty_one_char, '?', name_int, '=', i_val_n, '&', name_txt, '=', s_val_8 };
char const path08[] = { abempty_one_char, '?', name_int, '=', i_val_nx, '&', name_txt, '=', s_val_x };
char const path09[] = { abempty_one_char, '?', name_int, '=', i_val_1, '&', name_txt, '=', s_val_bad };
char const path10[] = { abempty_one_char, '?', name_int, '=', i_val_1, '&', name_txt, '=', s_val_too_long };
char const path11[] = { abempty_one_char, '?', name_int, '=', i_val_bad, '&', name_txt, '=', s_val_1 };
char const path12[] = { abempty_one_char, '?', name_int, '=', i_val_bad2, '&', name_txt, '=', s_val_1 };
char const path13[] = { abempty_one_char, '?', name_int, '=', i_val_bad3, '&', name_txt, '=', s_val_1 };
char const path14[] = { abempty_one_char, '?', name_int, '=', i_val_overflow, '&', name_txt, '=', s_val_1 };
char const path15[] = { abempty_one_name, '?', name_int, '=', i_val_1, '&', name_txt, '=', s_val_1 };
char const path16[] = { abempty_two_names, '?', name_int, '=', i_val_1, '&',  name_txt, '=', s_val_1 };
char const path17[] = { abempty_two_names, '?', name_int, '=', i_val_1, '&', name_other, '=', i_val_1, '&', name_txt, '=', s_val_1 };
char const path18[] = { abempty_two_names, '?', name_int, '=', i_val_1, '&', name_other, '&', name_txt, '=', s_val_1 };

typedef struct st_h3zero_uri_path_test_case_t {
    const uint8_t* path;
    size_t path_length;
    uint64_t val_int;
    const uint8_t * text;
    size_t text_len;
    int ret;
} h3zero_uri_path_test_case_t;

#define URI_PATH_TEST(p, i, t, r) { (const uint8_t*)p, sizeof(p), i, (const uint8_t *)t, sizeof(t), r }

h3zero_uri_path_test_case_t uri_test_cases[] = {
    { NULL, 0, 0, NULL, 0 },
    { (const uint8_t*)path01, sizeof(path01), 0, NULL, 0, 0 },
    { (const uint8_t*)path02, sizeof(path02), 0, NULL, 0, 0 },
    { (const uint8_t*)path03, sizeof(path03), 1, NULL, 0, 0 },
    URI_PATH_TEST(path04, 0, str_1, 0),
    URI_PATH_TEST(path05, 1, str_1, 0),
    URI_PATH_TEST(path06, 1, str_1, 0),
    URI_PATH_TEST(path07, 123456789, str_8, 0),
    URI_PATH_TEST(path08, 123456789, str_8, 0),
    URI_PATH_TEST(path09, 1, str_8, -1),
    URI_PATH_TEST(path10, 1, str_8, -1),
    URI_PATH_TEST(path11, 0, str_1, -1),
    URI_PATH_TEST(path12, 0, str_1, -1),
    URI_PATH_TEST(path13, 0, str_1, -1),
    URI_PATH_TEST(path14, 0, str_1, -1),
    URI_PATH_TEST(path15, 1, str_1, 0),
    URI_PATH_TEST(path16, 1, str_1, 0),
    URI_PATH_TEST(path17, 1, str_1, 0),
    URI_PATH_TEST(path18, 1, str_1, 0)
};

size_t nb_test_cases = sizeof(uri_test_cases) / sizeof(h3zero_uri_path_test_case_t);

int h3zero_uri_test_one(h3zero_uri_path_test_case_t* test_case)
{
    int ret = 0;
    int t_ret = 0;
    uint64_t val_int = 0;
    uint8_t text[8] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
    size_t text_len = 0;
    size_t query_offset = h3zero_query_offset(test_case->path, test_case->path_length);
    if (query_offset < test_case->path_length) {
        const uint8_t* queries = test_case->path + query_offset;
        size_t queries_length = test_case->path_length - query_offset;

        t_ret = h3zero_query_parameter_number(queries, queries_length, param_int, sizeof(param_int), &val_int, 0);
        if (t_ret == 0){
            t_ret = h3zero_query_parameter_string(queries, queries_length, param_txt, sizeof(param_txt), text, sizeof(text), &text_len);
        }
    }

    if (t_ret != test_case->ret) {
        DBG_PRINTF("Return: %d vs %d", t_ret, test_case->ret);
        ret = -1;
    }
    else if (t_ret == 0) {
        if (val_int != test_case->val_int) {
            DBG_PRINTF("val_int: %" PRIu64 " vs %" PRIu64, val_int, test_case->val_int);
            ret = -1;
        }
        else if (text_len != test_case->text_len) {
            DBG_PRINTF("text_len: %zu vs %zu", text_len, test_case->text_len);
            ret = -1;
        }
        else if (text_len > 0 && memcmp(text, test_case->text, text_len) != 0) {
            DBG_PRINTF("text_value length %zu do not match", text_len);
            ret = -1;
        }
    }
    return ret;
}

int h3zero_uri_test()
{
    int ret = 0;
    for (size_t i = 0; i < nb_test_cases; i++) {
        if ((ret = h3zero_uri_test_one(&uri_test_cases[i])) != 0) {
            DBG_PRINTF("Failure for uri test case %zu", i);
            break;
        }
    }
    return ret;
}