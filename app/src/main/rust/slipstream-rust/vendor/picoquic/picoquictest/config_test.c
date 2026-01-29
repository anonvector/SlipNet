/*
* Author: Christian Huitema
* Copyright (c) 2020, Private Octopus, Inc.
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

#include "picoquic.h"
#include "picoquic_internal.h"
#include "picoquic_utils.h"
#include "picoquic_config.h"
#include "picoquictest_internal.h"

#ifdef PICOQUIC_WITHOUT_SSLKEYLOG
static char* ref_option_text = "c:k:p:v:o:w:x:rR:s:XS:G:P:O:Me:C:i:l:Lb:q:m:n:a:t:zI:d:DQT:N:B:F:VU:0j:W:J:h";
#else
static char* ref_option_text = "c:k:p:v:o:w:x:rR:s:XS:G:P:O:Me:C:i:l:Lb:q:m:n:a:t:zI:d:DQT:N:B:F:VU:0j:W:8J:h";
#endif
int config_option_letters_test()
{
    char option_text[256];
    int ret = picoquic_config_option_letters(option_text, sizeof(option_text), NULL);

    if (ret != 0) {
        DBG_PRINTF("picoquic_config_option_letters returns %d", ret);
    }
    else if (strcmp(option_text, ref_option_text) != 0) {
        DBG_PRINTF("picoquic_config_option_letters returns %s", option_text);
        ret = -1;
    }

    return ret;
}

const uint8_t null_key[16] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

static picoquic_quic_config_t param1 = {
    1024, /*uint32_t nb_connections; */
    "/data/github/picoquic", /* char const* solution_dir; */
    "/data/certs/cert.pem", /* char const* server_cert_file; */
    "/data/certs/key.pem", /* char const* server_key_file; */
    "/data/log.txt", /* char const* log_file; */
    "/data/log/", /* char const* bin_dir; */
    "/data/qlog/", /* char const* qlog_dir; */
    "/data/performance_log.csv", /* char const* performance_log; */
    4433, /* int server_port; */
    1, /* int dest_if; */
    1536, /* int mtu_max; */
    0, /* int initial_send_mtu_ipv4; */
    0, /* int initial_send_mtu_ipv6; */
    -1, /* int cnx_id_length; */
    0, /* int idle_timeout */
    655360, /* Socket buffer size */
    "cubic", /* const picoquic_congestion_algorithm_t* cc_algorithm; */
    "0N8C-000123", /* char const* cnx_id_cbdata; */
    3, /* spin bit policy */
    2, /* loss bit policy */
    1, /* multipath option */
    "127.0.0.1",
    1,
    UINT64_MAX, /* Do not limit CWIN */
    3, /* Address discovery mode = 3 (cli param -J 2)*/
    /* Common flags */
    1, /* unsigned int initial_random : 1; */
    1, /* unsigned int use_long_log : 1; */
    1, /* unsigned int do_preemptive_repeat : 1; */
    1, /* unsigned int do_not_use_gso : 1 */
    0, /* disable port blocking */
#ifndef PICOQUIC_WITHOUT_SSLKEYLOG
    0,
#endif
    /* Server only */
    "/data/www/", /* char const* www_dir; */
    { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
      0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10}, /* uint8_t reset_seed[16]; */
    null_key, /* const uint8_t* ticket_encryption_key; */
    0, /* size_t ticket_encryption_key_length; */
    /* Server flags */
    1, /* unsigned int do_retry : 1; */
    1, /* unsigned int has_reset_seed : 1;*/
    /* Client only */
    NULL, /* char const* ticket_file_name; */
    NULL, /* char const* token_file_name; */
    NULL, /* char const* sni; */
    NULL, /* char const* alpn; */
    NULL, /* char const* out_dir; */
    NULL, /* char const* root_trust_file; */
    0, /* int cipher_suite_id; */
    0, /* uint32_t proposed_version; */
    0, /* uint32_t desired_version; */
    0, /* unsigned int force_zero_share : 1; */
    0, /* unsigned int no_disk : 1; */
    0, /* unsigned int large_client_hello : 1; */
};

static char const* config_argv1[] = {
    "-S", "/data/github/picoquic",
    "-c", "/data/certs/cert.pem",
    "-k", "/data/certs/key.pem",
    "-x", "1024",
    "-l", "/data/log.txt",
    "-b", "/data/log/",
    "-q", "/data/qlog/",
    "-p", "4433",
    "-e", "1",
    "-m", "1536",
    "-G", "cubic",
    "-P", "3",
    "-O", "2",
    "-M",
    "-R", "1",
    "-L",
    "-w", "/data/www/",
    "-r",
    "-s", "0123456789abcdeffedcba9876543210",
    "-B", "655360",
    "-F", "/data/performance_log.csv",
    "-V",
    "-j", "1",
    "-0",
    "-i", "0N8C-000123",
    "-J", "2",
    NULL
};

static picoquic_quic_config_t param2 = {
    256, /*uint32_t nb_connections; */
    NULL, /* char const* solution_dir; */
    NULL, /* char const* server_cert_file; */
    NULL, /* char const* server_key_file; */
    NULL, /* char const* log_file; */
    NULL, /* char const* bin_dir; */
    NULL, /* char const* qlog_dir; */
    NULL, /* char const* performance_log; */
    0, /* int server_port; */
    0, /* int dest_if; */
    0, /* int mtu_max; */
    0, /* int initial_send_mtu_ipv4; */
    0, /* int initial_send_mtu_ipv6; */
    5, /* int cnx_id_length; */
    1234567, /* int idle_timeout */
    0, /* socket_buffer_size */
    NULL, /* const picoquic_congestion_algorithm_t* cc_algorithm; */
    NULL, /* char const* cnx_id_cbdata; */
    0, /* spin bit policy */
    0, /* loss bit policy */
    0, /* multipath option */
    "127.0.0.1",
    0,
    1000000, /* Limit CWIN to 1 million bytes */
    0, /* Do not enable address discovery */
    /* Common flags */
    3, /* unsigned int initial_random : 1; */
    0, /* unsigned int use_long_log : 1; */
    0, /* unsigned int do_preemptive_repeat : 1; */
    0, /* unsigned int do_not_use_gso : 1 */
    1, /* disable port blocking */
#ifndef PICOQUIC_WITHOUT_SSLKEYLOG
    1,
#endif
    /* Server only */
    NULL, /* char const* www_dir; */
    { 0 }, /* Reset seed */
    NULL, /* const uint8_t* ticket_encryption_key; */
    0, /* size_t ticket_encryption_key_length; */
    /* Server flags */
    0, /* unsigned int do_retry : 1; */
    0, /* unsigned int  has reset seed : 1; */
    /* Client only */
    "/data/tickets.bin", /* char const* ticket_file_name; */
    "/data/tokens.bin", /* char const* token_file_name; */
    "test.example.com", /* char const* sni; */
    "test", /* char const* alpn; */
    "/data/w_out", /* char const* out_dir; */
    "data/certs/root.pem", /* char const* root_trust_file; */
    20, /* int cipher_suite_id; */
    0xff000020, /* uint32_t proposed_version; */
    0x00000002, /* uint32_t desired_version; */
    1,/* unsigned int force_zero_share : 1; */
    1, /* unsigned int no_disk : 1; */
    1 /* unsigned int large_client_hello : 1; */
};

static const char* config_argv2[] = {
    "-n", "test.example.com",
    "-a", "test",
    "-o", "/data/w_out",
    "-t", "data/certs/root.pem",
    "-C", "20",
    "-v", "fF000020",
    "-z",
    "-d", "1234567",
    "-D",
    "-Q",
    "-X",
#ifndef PICOQUIC_WITHOUT_SSLKEYLOG
    "-8",
#endif
    "-I", "5",
    "-T", "/data/tickets.bin",
    "-N", "/data/tokens.bin",
    "-U", "00000002",
    "-W", "1000000",
    NULL
};

static const char * config_two[] = {
    "--sni", "test.example.com",
    "--alpn", "test",
    "--outdir", "/data/w_out",
    "--root_trust_file", "data/certs/root.pem",
    "--cipher_suite", "20",
    "--proposed_version", "ff000020",
    "--force_zero_share",
    "--idle_timeout", "1234567",
    "--no_disk",
    "--large_client_hello",
    "--disable_block",
#ifndef PICOQUIC_WITHOUT_SSLKEYLOG
    "--sslkeylog",
#endif
    "--cnxid_length", "5",
    "--ticket_file", "/data/tickets.bin",
    "--token_file", "/data/tokens.bin",
    "--version_upgrade", "00000002",
    "--cwin_max", "1000000",
    NULL
};

typedef struct st_config_error_test_t {
    int nb_args;
    char const* err_args[2];
} config_error_test_t;

static config_error_test_t config_errors[] = {
    { 1, { "-A"}},
    { 1, { "-S" }},
    { 1, { "-c"}},
    { 1, { "-k"}},
    { 1, { "-x"}},
    { 2, { "-x", "nb_cnx"}},
    { 1, { "-l"}},
    { 1, { "-b"}},
    { 1, { "-q"}},
    { 2, { "-p", "port"}},
    { 1, { "-p" }},
    { 1, { "-e", }},
    { 2, { "-e", "a" }},
    { 1, { "-m" }},
    { 1, { "-m", "-1"}},
    { 2, { "-m", "15360"}},
    { 2, { "-P", "33"}},
    { 2, { "-O", "22"}},
    { 2, { "-R", "17"}},
    { 1, { "-w" }},
    { 2, { "-s", "0123456789abcdexyedcba9876543210"}},
    { 2, { "-s", "0123456789abcdeffedcba987654321"}},
    { 2, { "-s", "0123456789abcdeffedcba98765432"}},
    { 2, { "-B", "buffer"}},
    { 1, { "-F" }},
    { 2, { "-j", "3" }},
    { 1, { "-i" }},
    { 2, { "-I", "-1" }},
    { 2, { "-I", "255" }},
    { 2, { "-U", "XY000002" }},
    { 2, { "-W", "cwin" }},
    { 2, { "-d", "idle" }},
#ifdef PICOQUIC_WITHOUT_SSLKEYLOG
    { 1, {"-8"}},
#endif
};

static size_t nb_config_errors = sizeof(config_errors) / sizeof(config_error_test_t);

int config_test_compare_string(const char* title, const char* expected, const char* actual)
{
    int ret = 0;

    if (expected == NULL) {
        if (actual != NULL) {
            DBG_PRINTF("Expected %s = NULL, got %x", title, actual);
            ret = -1;
        }
    }
    else if (actual == NULL) {
        DBG_PRINTF("Expected %s = %s, got NULL", title, expected);
        ret = -1;
    }
    else if (strcmp(expected, actual) != 0) {
        DBG_PRINTF("Expected %s = %s, got %s", title, actual, expected);
        ret = -1;
    }
    return ret;
}

int config_test_compare_int(const char* title, int expected, int actual)
{
    int ret = 0;
    
    if (expected != actual) {
        DBG_PRINTF("Expected %s = %d, got %d", title, actual, expected);
        ret = -1;
    }
    return ret;
}

int config_test_compare_uint64(const char* title, uint64_t expected, uint64_t actual)
{
    int ret = 0;

    if (expected != actual) {
        DBG_PRINTF("Expected %s = %" PRIu64 ", got %" PRIu64, title, actual, expected);
        ret = -1;
    }
    return ret;
}

int config_test_compare_uint32(const char* title, uint32_t expected, uint32_t actual)
{
    int ret = 0;

    if (expected != actual) {
        DBG_PRINTF("Expected %s = 0x%" PRIx32 ", got 0x%" PRIx32, title, actual, expected);
        ret = -1;
    }
    return ret;
}

int config_test_compare(const picoquic_quic_config_t* expected, const picoquic_quic_config_t* actual)
{
    int ret = 0;

    ret |= config_test_compare_int("nb_connections", expected->nb_connections, actual->nb_connections);
    ret |= config_test_compare_string("solution_dir", expected->solution_dir, actual->solution_dir);
    ret |= config_test_compare_string("server_cert_file", expected->server_cert_file, actual->server_cert_file);
    ret |= config_test_compare_string("server_key_file", expected->server_key_file, actual->server_key_file);
    ret |= config_test_compare_string("log_file", expected->log_file, actual->log_file);
    ret |= config_test_compare_string("bin_dir", expected->bin_dir, actual->bin_dir);
    ret |= config_test_compare_string("qlog_dir", expected->qlog_dir, actual->qlog_dir);
    ret |= config_test_compare_string("performance_log", expected->performance_log, actual->performance_log);
    ret |= config_test_compare_int("port", expected->server_port, actual->server_port);
    ret |= config_test_compare_int("dest_if", expected->dest_if, actual->dest_if);
    ret |= config_test_compare_int("mtu_max", expected->mtu_max, actual->mtu_max);
    ret |= config_test_compare_int("socket_buffer_size", expected->socket_buffer_size, actual->socket_buffer_size);
    ret |= config_test_compare_string("cc_algo_id", expected->cc_algo_id, actual->cc_algo_id);
    ret |= config_test_compare_string("cnx_id_cbdata", expected->cnx_id_cbdata, actual->cnx_id_cbdata);
    ret |= config_test_compare_int("spinbit", expected->spinbit_policy, actual->spinbit_policy);
    ret |= config_test_compare_int("lossbit", expected->lossbit_policy, actual->lossbit_policy);
    ret |= config_test_compare_int("multipath", expected->multipath_option, actual->multipath_option);
    ret |= config_test_compare_int("initial_random", expected->initial_random, actual->initial_random);
    ret |= config_test_compare_int("use_long_log", expected->use_long_log, actual->use_long_log);
    ret |= config_test_compare_int("preemptive_repeat", expected->do_preemptive_repeat, actual->do_preemptive_repeat);
    ret |= config_test_compare_int("no_gso", expected->do_not_use_gso, actual->do_not_use_gso);
    ret |= config_test_compare_string("www_dir", expected->www_dir, actual->www_dir);
    ret |= config_test_compare_int("do_retry", expected->do_retry, actual->do_retry);
    /* TODO: reset_seed */
    ret |= config_test_compare_string("sni", expected->sni, actual->sni);
    ret |= config_test_compare_string("alpn", expected->alpn, actual->alpn);
    ret |= config_test_compare_string("out_dir", expected->out_dir, actual->out_dir);
    ret |= config_test_compare_string("root_trust_file", expected->root_trust_file, actual->root_trust_file);
    ret |= config_test_compare_string("root_trust_file", expected->root_trust_file, actual->root_trust_file);
    ret |= config_test_compare_int("cipher_suite_id", expected->cipher_suite_id, actual->cipher_suite_id);
    ret |= config_test_compare_uint32("proposed_version", expected->proposed_version, actual->proposed_version);
    ret |= config_test_compare_uint32("desired_version", expected->desired_version, actual->desired_version);
    ret |= config_test_compare_int("force_zero_share", expected->force_zero_share, actual->force_zero_share);
    ret |= config_test_compare_int("no_disk", expected->no_disk, actual->no_disk);
    ret |= config_test_compare_int("large_client_hello", expected->large_client_hello, actual->large_client_hello);
    ret |= config_test_compare_int("cnx_id_length", expected->cnx_id_length, actual->cnx_id_length);
    ret |= config_test_compare_int("bdp", expected->bdp_frame_option, actual->bdp_frame_option);
    ret |= config_test_compare_int("idle_timeout", expected->idle_timeout, actual->idle_timeout);
    ret |= config_test_compare_uint64("cwin_max", expected->cwin_max, actual->cwin_max);
#ifndef PICOQUIC_WITHOUT_SSLKEYLOG
    ret |= config_test_compare_int("sslkeylog", expected->enable_sslkeylog, actual->enable_sslkeylog);
#endif
    
    return ret;
}

static int config_parse_command_line(picoquic_quic_config_t* actual, const char** argv, int argc, int expect_error)
{
    int ret = 0;
    int opt_ind = 0;

    picoquic_config_init(actual);

    while (opt_ind < argc && ret == 0) {
        const char* x = argv[opt_ind];
        const char* optval = NULL;
        int opt;
        if (x == NULL) {
            /* could not parse to the end! */
            if (!expect_error) {
                DBG_PRINTF("Unexpected stop after %d arguments, expected %d", opt_ind, argc);
            }
            ret = -1;
            break;
        }
        else if (x[0] != '-' || x[1] == 0 || x[2] != 0) {
            /* Either next argument, or single "-", or more than one char ! */
            if (!expect_error) {
                DBG_PRINTF("Unexpected argument: %s", x);
            }
            ret = -1;
            break;
        }

        opt = x[1];
        opt_ind++;
        if (opt_ind < argc) {
            optval = argv[opt_ind];
            if (optval[0] == '-') {
                optval = NULL;
            }
            else {
                opt_ind++;
            }
        }

        ret = picoquic_config_command_line(opt, &opt_ind, argc, argv, optval, actual);
        if (ret != 0) {
            if (!expect_error) {
                DBG_PRINTF("Could not parse opt -%c", opt);
            }
        }
    }

    return (ret);
}


static int config_parse_command_line_test(const picoquic_quic_config_t* expected, const char** argv, int argc)
{
    int ret = 0;
    picoquic_quic_config_t actual;

    ret = config_parse_command_line(&actual, argv, argc, 0);

    if (ret == 0) {
        ret = config_test_compare(expected, &actual);
    }

    picoquic_config_clear(&actual);

    return (ret);
}

int config_test_parse_command_line_ex(const picoquic_quic_config_t* expected, const char** argv, int argc)
{
    int ret = 0;
    int opt_ind = 0;
    picoquic_quic_config_t actual;

    picoquic_config_init(&actual);

    while (opt_ind < argc && ret == 0) {
        const char* x = argv[opt_ind];
        const char* optval = NULL;

        if (x == NULL) {
            /* could not parse to the end! */
            DBG_PRINTF("Unexpected stop after %d arguments, expected %d", opt_ind, argc);
            ret = -1;
            break;
        }
        else if (x[0] != '-' || x[1] == 0 || 
            (x[2] != 0 && x[1] != '-')) {
            /* could not parse to the end! */
            DBG_PRINTF("Unexpected argument: %s", x);
            ret = -1;
            break;
        }
        opt_ind++;
        if (opt_ind < argc) {
            optval = argv[opt_ind];
            if (optval[0] == '-') {
                optval = NULL;
            }
            else {
                opt_ind++;
            }
        }
        ret = picoquic_config_command_line_ex(x, &opt_ind, argc, argv, optval, &actual);
        if (ret != 0) {
            DBG_PRINTF("Could not parse opt %s", x);
        }
    }

    if (ret == 0) {
        ret = config_test_compare(expected, &actual);
    }

    picoquic_config_clear(&actual);
  
    return (ret);
}

int config_set_option_test_one()
{
    int ret = 0;
    char const* ticket_store = "ticket_store.bin";
    char const* token_store = "ticket_store.bin";

    picoquic_quic_config_t config = { 0 };
    if (ret == 0 && config.ticket_file_name == NULL) {
        ret = picoquic_config_set_option(&config, picoquic_option_Ticket_File_Name, ticket_store);
    }
    if (ret == 0 && config.token_file_name == NULL) {
        ret = picoquic_config_set_option(&config, picoquic_option_Token_File_Name, token_store);
    }
    if (ret == 0 &&
        (config.ticket_file_name == NULL || strcmp(config.ticket_file_name, ticket_store) != 0)) {
        ret = -1;
    }
    if (ret == 0 &&
        (config.token_file_name == NULL || strcmp(config.token_file_name, token_store) != 0)) {
        ret = -1;
    }
    picoquic_config_clear(&config);

    return (ret);
}

int config_option_test()
{
    int ret = config_parse_command_line_test(&param1, config_argv1, (int)(sizeof(config_argv1) / sizeof(char const*)) - 1);
    if (ret != 0) {
        DBG_PRINTF("First config option test returns %d", ret);
    }
    if (ret == 0) {
        ret = config_parse_command_line_test(&param2, config_argv2, (int)(sizeof(config_argv2) / sizeof(char const*)) - 1);

        if (ret != 0) {
            DBG_PRINTF("Second config option test returns %d", ret);
        }
    }

    if (ret == 0) {
        ret = config_test_parse_command_line_ex(&param2, config_two, (int)(sizeof(config_two) / sizeof(char const*)) - 1);
        if (ret != 0) {
            DBG_PRINTF("Two dash config option test returns %d", ret);
        }
    }

    for (size_t i = 0; ret == 0 && i < nb_config_errors; i++) {
        picoquic_quic_config_t config = { 0 };
        if (config_parse_command_line(&config, config_errors[i].err_args,
            config_errors[i].nb_args, 1) == 0) {
            DBG_PRINTF("Did not detect config error %zu, %s", i, config_errors[i].err_args[0]);
            ret = -1;
        }
    }

    return ret;
}

int config_quic_test_one(picoquic_quic_config_t* config)
{
    int ret = 0;
    picoquic_quic_t * quic;
    uint64_t current_time = 0;

    char const* server_cert_file = NULL;
    char test_server_cert_file[512];
    char const* server_key_file = NULL;
    char test_server_key_file[512];
    char const* root_trust_file = NULL;
    char test_root_trust_file[512];

    if (ret == 0 && config->server_cert_file != NULL) {
        ret = picoquic_get_input_path(test_server_cert_file, sizeof(test_server_cert_file), picoquic_solution_dir,
            PICOQUIC_TEST_FILE_SERVER_CERT);
        if (ret == 0) {
            server_cert_file = config->server_cert_file;
            config->server_cert_file = test_server_cert_file;
        }
    }

    if (ret == 0 && config->server_key_file) {
        ret = picoquic_get_input_path(test_server_key_file, sizeof(test_server_key_file), picoquic_solution_dir,
            PICOQUIC_TEST_FILE_SERVER_KEY);
        if (ret == 0) {
            server_key_file = config->server_key_file;
            config->server_key_file = test_server_key_file;
        }
    }

    if (ret == 0 && config->root_trust_file) {
        ret = picoquic_get_input_path(test_root_trust_file, sizeof(test_root_trust_file), picoquic_solution_dir,
            PICOQUIC_TEST_FILE_CERT_STORE);
        if (ret == 0) {
            root_trust_file = config->root_trust_file;
            config->root_trust_file = root_trust_file;
        }
    }

    quic = picoquic_create_and_configure(config, NULL, NULL, current_time, NULL);
    if (quic == NULL) {
        ret = 1;
    }
    else {
        /* Check that at least some parameters are what we expect */
        if (config->nb_connections > 0 && config->nb_connections != quic->max_number_connections) {
            ret = -1;
        }
        if (config->alpn != NULL &&
            (quic->default_alpn == NULL || strcmp(quic->default_alpn, config->alpn) != 0)) {
            ret = -1;
        }
        if (config->has_reset_seed &&
            memcmp(quic->reset_seed, config->reset_seed, sizeof(config->reset_seed)) != 0) {
            ret = -1;
        }
        picoquic_free(quic);
    }

    if (server_key_file != NULL) {
        config->server_key_file = server_key_file;
    }
    if (server_cert_file != NULL) {
        config->server_cert_file = server_cert_file;
    }
    if (root_trust_file != NULL) {
        config->root_trust_file = root_trust_file;
    }

    return(ret);
}

int config_quic_test()
{
    int ret = 0;
    if (config_quic_test_one(&param1) != 0 ||
        config_quic_test_one(&param2) != 0) {
        ret = -1;
    }
    return ret;
}

#define CONFIG_USAGE_REF "picoquictest" PICOQUIC_FILE_SEPARATOR "config_usage_ref.txt"
#define CONFIG_USAGE_TXT "config_usage.txt"

int config_usage_test()
{

    FILE* F = NULL;
    char config_usage_ref[512];
    int ret = picoquic_get_input_path(config_usage_ref, sizeof(config_usage_ref), picoquic_solution_dir, CONFIG_USAGE_REF);

    if (ret == 0 && (F = picoquic_file_open(CONFIG_USAGE_TXT, "wt")) != NULL){
        picoquic_config_usage_file(F);
        F = picoquic_file_close(F);
    }

    if (ret == 0) {
        ret = picoquic_test_compare_text_files(CONFIG_USAGE_TXT, config_usage_ref);
    }

    return ret;
}