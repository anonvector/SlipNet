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

/* Manage the configuration options for the QUIC context
 * TODO: do not force linking of binlog, textlog, qlog
 * TODO: review of connection ID function API. Separate parameters?
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include "picoquic.h"
#include "picoquic_utils.h"
#include "picoquic_binlog.h"
#include "picoquic_logger.h"
#include "picoquic_unified_log.h"
#include "tls_api.h"
#include "picoquic_config.h"

typedef struct st_option_param_t {
    char const * param;
    size_t length;
} option_param_t;

typedef struct st_option_table_line_t {
    picoquic_option_enum_t option_num;
    char option_letter;
    char const* option_name;
    int nb_params_required;
    char const* param_sample;
    char const* option_help;
} option_table_line_t;

static option_table_line_t option_table[] = {
    { picoquic_option_CERT, 'c', "cert", 1, "file", "cert file" },
    { picoquic_option_KEY, 'k', "key", 1, "file", "key file" },
    { picoquic_option_SERVER_PORT, 'p', "port", 1, "number", "server port" },
    { picoquic_option_PROPOSED_VERSION, 'v', "proposed_version", 1, "", "Version proposed by client, e.g. -v ff000012" },
    { picoquic_option_OUTDIR, 'o', "outdir", 1, "folder", "Folder where client writes downloaded files, defaults to current directory." },
    { picoquic_option_WWWDIR, 'w', "wwwdir", 1, "folder", "Folder containing web pages served by server" },
    { picoquic_option_MAX_CONNECTIONS, 'x', "max_connections", 1, "number",
    "Maximum number of concurrent connections, default 256" },
    { picoquic_option_DO_RETRY, 'r', "do_retry", 0, "", "Do Retry Request" },
    { picoquic_option_INITIAL_RANDOM, 'R', "initial_random", 1, "option", "Randomize packet number spaces: none(0), initial(1, default), all(2)." },
    { picoquic_option_RESET_SEED, 's', "reset_seed", 1, "<32 hex chars>", "Reset seed" },
    { picoquic_option_DisablePortBlocking, 'X', "disable_block", 0, "", "Disable the check for blocked ports"},
    { picoquic_option_SOLUTION_DIR, 'S', "solution_dir", 1, "folder", "Set the path to the source files to find the default files" },
    { picoquic_option_CC_ALGO, 'G', "cc_algo", 1, "cc_algorithm",
    "Use the specified congestion control algorithm: reno, cubic, bbr or fast. Defaults to bbr." },
    { picoquic_option_SPINBIT, 'P', "spinbit", 1, "number", "Set the default spinbit policy" },
    { picoquic_option_LOSSBIT, 'O', "lossbit", 1, "number", "Set the default lossbit policy" },
    { picoquic_option_MULTIPATH, 'M', "multipath", 0, "", "Enable QUIC multipath extension" },
    { picoquic_option_DEST_IF, 'e', "dest_if", 1, "if", "Send on interface (default: -1)" },
    { picoquic_option_CIPHER_SUITE, 'C', "cipher_suite", 1, "cipher_suite_id", "specify cipher suite (e.g. -C 20 = chacha20)" },
    { picoquic_option_INIT_CNXID, 'i', "cnxid_params", 1, "per-text-lb-spec", "See documentation for LB compatible CID configuration" },
    { picoquic_option_LOG_FILE, 'l', "text_log", 1, "file", "Log file, Log to stdout if file = \"-\". No text logging if absent." },
    { picoquic_option_LONG_LOG, 'L', "long_log", 0, "", "Log all packets. If absent, log stops after 100 packets." },
    { picoquic_option_BINLOG_DIR, 'b', "binlog_dir", 1, "folder", "Binary logging to this directory. No binary logging if absent." },
    { picoquic_option_QLOG_DIR, 'q', "qlog_dir", 1, "folder", 
    "Qlog logging to this directory. No qlog logging if absent, but qlogs could be produced using picolog if binary logs are available." },
    { picoquic_option_MTU_MAX, 'm', "mtu_max", 1, "mtu_max", "Largest mtu value that can be tried for discovery." },
    { picoquic_option_SNI, 'n', "sni", 1, "sni", "sni (default: server name)" },
    { picoquic_option_ALPN, 'a', "alpn", 1, "alpn", "alpn (default function of version)" },
    { picoquic_option_ROOT_TRUST_FILE, 't', "root_trust_file", 1, "file", "root trust file" },
    { picoquic_option_FORCE_ZERO_SHARE, 'z', "force_zero_share", 0, "", "Set TLS zero share behavior on client, to force HRR" },
    { picoquic_option_CNXID_LENGTH, 'I', "cnxid_length", 1, "length", "Length of CNX_ID used by the client, default=8" },
    { picoquic_option_Idle_Timeout, 'd', "idle_timeout", 1, "ms", "Duration of idle timeout in milliseconds" },
    { picoquic_option_NO_DISK, 'D', "no_disk", 0, "", "no disk: do not save received files on disk" },
    { picoquic_option_LARGE_CLIENT_HELLO, 'Q', "large_client_hello", 0, "",
    "send a large client hello in order to test post quantum readiness" },
    { picoquic_option_Ticket_File_Name, 'T', "ticket_file", 1, "file", "File storing the session tickets" },
    { picoquic_option_Token_File_Name, 'N', "token_file", 1, "file", "File storing the new tokens" },
    { picoquic_option_Socket_buffer_size, 'B', "so_buf_size", 1, "number", "Set buffer size with SO_SNDBUF SO_RCVBUF" },
    { picoquic_option_Performance_Log, 'F', "log_file_name", 1, "file", "Append performance reports to performance log" },
    { picoquic_option_Preemptive_Repeat, 'V', "preemptive_repeat", 0, "", "enable preemptive repeat" },
    { picoquic_option_Version_Upgrade, 'U', "version_upgrade", 1, "", "Version upgrade if server agrees, e.g. -U 6b3343cf" },
    { picoquic_option_No_GSO, '0', "no_gso", 0, "", "Do not use UDP GSO or equivalent" },
    { picoquic_option_BDP_frame, 'j', "bdp", 1, "number", "use bdp extension frame(1) or don\'t (0). Default=0" },
    { picoquic_option_CWIN_MAX, 'W', "cwin_max", 1, "bytes", "Max value for CWIN. Default=UINT64_MAX"},
#ifndef PICOQUIC_WITHOUT_SSLKEYLOG
    { picoquic_option_SSLKEYLOG, '8', "sslkeylog", 0, "", "Enable SSLKEYLOG" },
#endif
    { picoquic_option_AddressDiscovery, 'J', "addr_disc", 1, "mode", "provider (0), receiver (1) or both (2)."},
    { picoquic_option_HELP, 'h', "help", 0, "", "This help message" }
};

static size_t option_table_size = sizeof(option_table) / sizeof(option_table_line_t);

static uint32_t config_parse_target_version(char const* v_arg)
{
    /* Expect the version to be encoded in base 16 */
    uint32_t v = 0;
    char const* x = v_arg;

    while (*x != 0) {
        int c = *x;

        if (c >= '0' && c <= '9') {
            c -= '0';
        }
        else if (c >= 'a' && c <= 'f') {
            c -= 'a';
            c += 10;
        }
        else if (c >= 'A' && c <= 'F') {
            c -= 'A';
            c += 10;
        }
        else {
            v = 0;
            break;
        }
        v *= 16;
        v += c;
        x++;
    }

    return v;
}

static int config_set_string_param(char const** v, const option_param_t* params, int nb_param, int x)
{
    int ret = 0;
    char* p_dup = NULL;

    if (*v != NULL) {
        free((void*)*v);
        *v = NULL;
    }

    if (params != NULL && x >= 0 && x < nb_param && params[x].param != NULL)
    {
        size_t alloc_length = params[x].length + 1;

        if (params[x].length > 0 && alloc_length > params[x].length) {
            p_dup = (char *)malloc(alloc_length);
        }
        if (p_dup != NULL) {
            memcpy(p_dup, params[x].param, params[x].length);
            p_dup[params[x].length] = 0;
            *v = (char const*)p_dup;
        }
        else {
            fprintf(stderr, "Cannot allocate %zu characters\n", params[x].length);
            ret = -1;
        }
    }
    else {
        ret = -1;
    }
    return ret;
}

static char* config_optval_string(char* buffer, size_t buffer_max, const char* p, size_t p_length)
{
    if (p_length + 1 > buffer_max) {
        p_length = buffer_max - 1;
    }
    memcpy(buffer, p, p_length);
    buffer[p_length] = 0;
    return buffer;
}

static char* config_optval_param_string(char* buffer, size_t buffer_max, const option_param_t* params, int nb_param, int x)
{
    if (params == NULL || x < 0 || x >= nb_param) {
        buffer[0] = 0;
        return buffer;
    }
    else {
        return config_optval_string(buffer, buffer_max, params[x].param, params[x].length);
    }
}

int config_atoi(const option_param_t* params, int nb_param, int x, int* ret)
{
    int v = 0;

    if (params == NULL || x < 0 || x >= nb_param) {
        *ret = -1;
    }
    else {
        for (size_t i = 0; i < params[x].length; i++) {
            int c = params[x].param[i] - '0';
            if (c < 0 || c > 9) {
                v = -1;
                *ret = -1;
                break;
            }
            else {
                v *= 10;
                v += c;
            }
        }
    }
    return v;
}

static int config_set_option(option_table_line_t* option_desc, option_param_t* params, int nb_params, picoquic_quic_config_t* config)
{
    int ret = 0;
    char opval_buffer[256];

    switch (option_desc->option_num) {
    case picoquic_option_CERT:
        ret = config_set_string_param(&config->server_cert_file, params, nb_params, 0);
        break;
    case picoquic_option_KEY:
        ret = config_set_string_param(&config->server_key_file, params, nb_params, 0);
        break;
    case picoquic_option_SERVER_PORT:
        config->server_port = config_atoi(params, nb_params, 0, &ret);
        if (ret != 0) {
            fprintf(stderr, "Invalid port: %s\n", config_optval_param_string(opval_buffer, 256, params, nb_params, 0));
        }
        break;
    case picoquic_option_PROPOSED_VERSION:
        if ((config->proposed_version = config_parse_target_version(config_optval_param_string(opval_buffer, 256, params, nb_params, 0))) <= 0) {
            fprintf(stderr, "Invalid version: %s\n", config_optval_param_string(opval_buffer, 256, params, nb_params, 0));
            ret = -1;
        }
        break;
    case picoquic_option_OUTDIR:
        ret = config_set_string_param(&config->out_dir, params, nb_params, 0);
        break;
    case picoquic_option_WWWDIR:
        ret = config_set_string_param(&config->www_dir, params, nb_params, 0);
        break;
    case picoquic_option_MAX_CONNECTIONS: {
        int v = config_atoi(params, nb_params, 0, &ret);
        if (ret != 0 || v <= 0 ) {
            fprintf(stderr, "Invalid max connections: %s\n", config_optval_param_string(opval_buffer, 256, params, nb_params, 0));
            ret = (ret == 0) ? -1 : ret;
        }
        else {
            config->nb_connections = (uint32_t)v;
        }
        break;
    }
    case picoquic_option_DO_RETRY:
        config->do_retry = 1;
        break;
    case picoquic_option_INITIAL_RANDOM: {
        int v = config_atoi(params, nb_params, 0, &ret);
        if (ret != 0 || v < 0 || v > 2) {
            fprintf(stderr, "Invalid initial random value: %s\n", config_optval_param_string(opval_buffer, 256, params, nb_params, 0));
            ret = (ret == 0) ? -1 : ret;
        }
        else {
            config->initial_random = v;
        }
        break;
    }
    case picoquic_option_RESET_SEED:
        config->has_reset_seed = 1;
        ret = (picoquic_parse_hexa(params[0].param, params[0].length, config->reset_seed, sizeof(config->reset_seed)) ==
            sizeof(config->reset_seed)) ? 0 : -1;
        if (ret != 0) {
            fprintf(stderr, "Invalid reset seed: %s\n", config_optval_param_string(opval_buffer, 256, params, nb_params, 0));
        }
        break;
    case picoquic_option_DisablePortBlocking:
        config->disable_port_blocking = 1;
        break;
#ifndef PICOQUIC_WITHOUT_SSLKEYLOG
    case picoquic_option_SSLKEYLOG:
        config->enable_sslkeylog = 1;
        break;
#endif
    case picoquic_option_SOLUTION_DIR:
        ret = config_set_string_param(&config->solution_dir, params, nb_params, 0);
        break;
    case picoquic_option_CC_ALGO:
        ret = config_set_string_param(&config->cc_algo_id, params, nb_params, 0);
        break;
    case picoquic_option_SPINBIT: {
        int v = config_atoi(params, nb_params, 0, &ret);
        if (ret != 0 || v < 0 || v > (int)picoquic_spinbit_on) {
            fprintf(stderr, "Invalid spinbit policy: %s\n", config_optval_param_string(opval_buffer, 256, params, nb_params, 0));
            ret = (ret == 0) ? -1 : ret;
        }
        else {
            config->spinbit_policy = (picoquic_spinbit_version_enum)v;
        }
        break;
    }
    case picoquic_option_LOSSBIT: {
        int v = config_atoi(params, nb_params, 0, &ret);
        if (ret != 0 || v < 0 || v >(int)picoquic_lossbit_send_receive) {
            fprintf(stderr, "Invalid lossbit policy: %s\n", config_optval_param_string(opval_buffer, 256, params, nb_params, 0));
            ret = (ret == 0) ? -1 : ret;
        }
        else {
            config->lossbit_policy = (picoquic_lossbit_version_enum)v;
        }
        break;
    }
    case picoquic_option_MULTIPATH: 
        config->multipath_option = 1;
        break;
    case picoquic_option_DEST_IF:
        config->dest_if = config_atoi(params, nb_params, 0, &ret);
        break;
    case picoquic_option_CIPHER_SUITE:
        config->cipher_suite_id = config_atoi(params, nb_params, 0, &ret);
        break;
    case picoquic_option_INIT_CNXID:
        ret = config_set_string_param(&config->cnx_id_cbdata, params, nb_params, 0);
        break;
    case picoquic_option_LOG_FILE:
        ret = config_set_string_param(&config->log_file, params, nb_params, 0);
        break;
    case picoquic_option_LONG_LOG:
        config->use_long_log = 1;
        break;
    case picoquic_option_BINLOG_DIR:
        ret = config_set_string_param(&config->bin_dir, params, nb_params, 0);
        break;
    case picoquic_option_QLOG_DIR:
        ret = config_set_string_param(&config->qlog_dir, params, nb_params, 0);
        break;
    case picoquic_option_MTU_MAX:
        config->mtu_max = config_atoi(params, nb_params, 0, &ret);
        if (config->mtu_max <= 0 || config->mtu_max > PICOQUIC_MAX_PACKET_SIZE) {
            fprintf(stderr, "Invalid max mtu: %s\n", config_optval_param_string(opval_buffer, 256, params, nb_params, 0));
            ret = -1;
        }
        break;
    case picoquic_option_INITIAL_SEND_MTU_IPV4:
        config->initial_send_mtu_ipv4 = config_atoi(params, nb_params, 0, &ret);
        if (config->initial_send_mtu_ipv4 <= 0 || config->initial_send_mtu_ipv4 > PICOQUIC_MAX_PACKET_SIZE) {
            fprintf(stderr, "Invalid initial send mtu ipv4: %s\n", config_optval_param_string(opval_buffer, 256, params, nb_params, 0));
            ret = -1;
        }
        break;
    case picoquic_option_INITIAL_SEND_MTU_IPV6:
        config->initial_send_mtu_ipv6 = config_atoi(params, nb_params, 0, &ret);
        if (config->initial_send_mtu_ipv6 <= 0 || config->initial_send_mtu_ipv6 > PICOQUIC_MAX_PACKET_SIZE) {
            fprintf(stderr, "Invalid initial send mtu ipv6: %s\n", config_optval_param_string(opval_buffer, 256, params, nb_params, 0));
            ret = -1;
        }
        break;
    case picoquic_option_SNI:
        ret = config_set_string_param(&config->sni, params, nb_params, 0);
        break;
    case picoquic_option_ALPN:
        ret = config_set_string_param(&config->alpn, params, nb_params, 0);
        break;
    case picoquic_option_ROOT_TRUST_FILE:
        ret = config_set_string_param(&config->root_trust_file, params, nb_params, 0);
        break;
    case picoquic_option_FORCE_ZERO_SHARE:
        config->force_zero_share = 1;
        break;
    case picoquic_option_CNXID_LENGTH:
        config->cnx_id_length = config_atoi(params, nb_params, 0, &ret);
        if (config->cnx_id_length < 0 || config->cnx_id_length > PICOQUIC_CONNECTION_ID_MAX_SIZE) {
            fprintf(stderr, "Invalid connection id length: %s\n", config_optval_param_string(opval_buffer, 256, params, nb_params, 0));
            ret = -1;
        }
        break;
    case picoquic_option_Idle_Timeout:
        config->idle_timeout = config_atoi(params, nb_params, 0, &ret);
        if (config->idle_timeout < 0) {
            fprintf(stderr, "Invalid idle timer: %s\n", config_optval_param_string(opval_buffer, 256, params, nb_params, 0));
            ret = -1;
        }
        break;
    case picoquic_option_NO_DISK:
        config->no_disk = 1;
        break;
    case picoquic_option_LARGE_CLIENT_HELLO:
        config->large_client_hello = 1;
        break;
    case picoquic_option_Ticket_File_Name:
        ret = config_set_string_param(&config->ticket_file_name, params, nb_params, 0);
        break;
    case picoquic_option_Token_File_Name:
        ret = config_set_string_param(&config->token_file_name, params, nb_params, 0);
        break;
    case picoquic_option_Socket_buffer_size:
        config->socket_buffer_size = config_atoi(params, nb_params, 0, &ret);
        if (config->socket_buffer_size < 0 ) {
            fprintf(stderr, "Invalid socket_buffer_size: %s\n", config_optval_param_string(opval_buffer, 256, params, nb_params, 0));
            ret = -1;
        }
        break;
    case picoquic_option_Performance_Log:
        ret = config_set_string_param(&config->performance_log, params, nb_params, 0);
        break;
    case picoquic_option_Preemptive_Repeat:
        config->do_preemptive_repeat = 1;
        break;
    case picoquic_option_Version_Upgrade:
        if ((config->desired_version = config_parse_target_version(config_optval_param_string(opval_buffer, 256, params, nb_params, 0))) <= 0) {
            fprintf(stderr, "Invalid version: %s\n", config_optval_param_string(opval_buffer, 256, params, nb_params, 0));
            ret = -1;
        }
        break;
    case picoquic_option_No_GSO:
        config->do_not_use_gso = 1;
        break;
    case picoquic_option_BDP_frame: {
        int v = config_atoi(params, nb_params, 0, &ret);
        if (ret != 0 || v < 0 || v > 1) {
            fprintf(stderr, "Invalid bdp option: %s\n", config_optval_param_string(opval_buffer, 256, params, nb_params, 0));
            ret = (ret == 0) ? -1 : ret;
        }
        else {
            config->bdp_frame_option = v;
        }
        break;
    }
    case picoquic_option_CWIN_MAX:{
        int v = config_atoi(params, nb_params, 0, &ret);
        if (ret != 0 || v < 0) {
            fprintf(stderr, "Invalid cwin max option: %s\n", config_optval_param_string(opval_buffer, 256, params, nb_params, 0));
            ret = (ret == 0) ? -1 : ret;
        }
        else {
            config->cwin_max = (v==0)?UINT64_MAX:v;
        }
        break;
    }
    case picoquic_option_AddressDiscovery: {
        int v = config_atoi(params, nb_params, 0, &ret);
        if (ret != 0 || v < 0 || v > 2) {
            fprintf(stderr, "Invalid address discovery option: %s\n", config_optval_param_string(opval_buffer, 256, params, nb_params, 0));
            ret = (ret == 0) ? -1 : ret;
        }
        else {
            config->address_discovery_mode = v + 1;
        }
        break;
    }
    case picoquic_option_HELP:
        ret = -1;
        break;
    default:
        ret = -1;
        break;
    }
    return ret;
}

int picoquic_config_option_letters(char* option_string, size_t string_max, size_t * string_length)
{
    size_t l = 0;
    int ret = 0;

    for (size_t i = 0; l + 1 < string_max && i < option_table_size; i++) {
        option_string[l++] = option_table[i].option_letter;
        if (option_table[i].nb_params_required > 0) {
            if (l + 1 < string_max) {
                option_string[l++] = ':';
            }
            else {
                l--;
                ret = -1;
                break;
            }
        }
    }
    option_string[l] = 0;
    if (string_length != NULL) {
        *string_length = l;
    }
    return ret;
}

void picoquic_config_usage_file(FILE* F)
{
    fprintf(F, "Picoquic options:\n");
    for (size_t i = 0; i < option_table_size; i++) {
        size_t spacer = strlen(option_table[i].param_sample);
        fprintf(F, "  -%c %s", option_table[i].option_letter, option_table[i].param_sample);
        while (spacer++ < 12) {
            putc(' ', F);
        }
        fprintf(F, " %s\n", option_table[i].option_help);
    }
}

void picoquic_config_usage()
{
    picoquic_config_usage_file(stderr);
}

int picoquic_config_set_option(picoquic_quic_config_t* config, picoquic_option_enum_t option_num, const char * opt_val)
{
    int ret = 0;
    option_table_line_t* option_desc = NULL;
    option_param_t params[1];
    int nb_params = 0;

    for (size_t i = 0; i < option_table_size; i++) {
        if (option_table[i].option_num == option_num) {
            option_desc = &option_table[i];
        }
    }
    if (option_desc == NULL) {
        fprintf(stderr, "Unknow option number: %d\n", option_num);
        ret = -1;
    }
    else{
        if (opt_val != NULL) {
            params[0].param = opt_val;
            params[0].length = strlen(opt_val);
            nb_params = 1;
        }
        ret = config_set_option(option_desc, params, nb_params, config);
    }
    return ret;
}

int picoquic_config_get_option_char_index(int opt)
{
    int option_index = -1;

    for (size_t i = 0; i < option_table_size; i++) {
        if (option_table[i].option_letter == opt) {
            option_index = (int)i;
            break;
        }
    }
    return option_index;
}

int picoquic_config_get_option_name_index(char const * s, size_t l)
{
    int option_index = -1;

    for (size_t i = 0; i < option_table_size; i++) {
        if (strncmp(s, option_table[i].option_name, l) == 0) {
            option_index = (int)i;
            break;
        }
    }
    return option_index;
}

int picoquic_config_get_command_line_option_index(char const* opt_string)
{
    int option_index = -1;

    if (opt_string[0] == '-' && opt_string[1] != 0) {
        if (opt_string[2] == 0) {
            option_index = picoquic_config_get_option_char_index(opt_string[1]);
        }
        else if (opt_string[1] == '-' && opt_string[2] != 0) {
            char const* opt_name = opt_string + 2;
            option_index = picoquic_config_get_option_name_index(opt_name, strlen(opt_name));
        }
    }
    return option_index;
}

int picoquic_get_command_line_option_value(int option_index, char const * opt_string, int* p_optind, const char** argv,
    int argc, char const* optarg, picoquic_quic_config_t* config)
{
    int ret = 0;
    option_param_t params[5];
    int nb_params = 0;

    if (option_table[option_index].nb_params_required > 0) {
        params[0].param = optarg;
        if (optarg == NULL) {
            fprintf(stderr, "option %s requires %d arguments\n", opt_string, option_table[option_index].nb_params_required);
            ret = -1;
        }
        else {
            params[0].length = strlen(optarg);
            nb_params++;
            while (nb_params < option_table[option_index].nb_params_required) {
                if (*p_optind + 1 > argc) {
                    fprintf(stderr, "option %s requires %d arguments\n", opt_string, option_table[option_index].nb_params_required);
                    ret = -1;
                    break;
                }
                else {
                    params[nb_params].param = argv[*p_optind];
                    params[nb_params].length = (int)strlen(argv[*p_optind]);
                    nb_params++;
                    *p_optind += 1;
                }
            }
        }
    }

    if (ret == 0) {
        ret = config_set_option(&option_table[option_index], params, nb_params, config);
    }

    return ret;
}

int picoquic_config_command_line(int opt, int * p_optind, int argc, char const ** argv, char const* optarg, picoquic_quic_config_t * config)
{
    int ret = 0;
    int option_index = -1;
    char opt_string[3] = { '-', 0, 0 };

    opt_string[1] = (char)opt;
    option_index = picoquic_config_get_option_char_index(opt);

    if (option_index == -1) {
        fprintf(stderr, "Unknown option: -%c\n", opt);
        ret = -1;
    }
    else {
        ret = picoquic_get_command_line_option_value(option_index, opt_string, p_optind,
            argv, argc, optarg, config);
    }
    return ret;
}

int picoquic_config_command_line_ex(char const * opt_string, int* p_optind, int argc, char const** argv, char const* optarg, picoquic_quic_config_t* config)
{
    int ret = 0;
    int option_index = -1;

    option_index = picoquic_config_get_command_line_option_index(opt_string);

    if (option_index == -1) {
        fprintf(stderr, "Unknown option: %s\n", opt_string);
    }
    else {
        ret = picoquic_get_command_line_option_value(option_index, opt_string, p_optind,
            argv, argc, optarg, config);
    }
    return ret;
}

#if 0
/* Reading parameters from a file instead of the command line.
* Apparently never used, also not tested.
 */
int picoquic_config_file(char const* file_name, picoquic_quic_config_t* config)
{
    int ret = 0;
    FILE* F = picoquic_file_open(file_name, "r");
    if (F == NULL) {
        DBG_PRINTF("Could not open configuration file: %s", file_name);
        ret = -1;
    }
    else {
        char line[1024];
        int line_number = 0;

        while (fgets(line, sizeof(line), F) != NULL && ret == 0) {
            /* Parse the line. Expect format: <arg_id>":" spaces* argv1 [space ^spaces argvn]* */
            int offset = skip_spaces(line, 0);
            int name_offset;
            int name_length;
            option_param_t params[5];
            int nb_params;
            int option_index = -1;

            line_number++;
            name_offset = offset;
            offset = skip_name(line, name_offset);
            if (offset <= name_offset) {
                /* Empty line */
            }
            else {
                name_length = offset - name_offset;
                /* Parse the option parameters, up to 5 of them */
                offset = parse_line_params(line, offset, params, 5, &nb_params);
                /* Recognize the option and apply the parameters  */
                for (size_t i = 0; i < option_table_size; i++) {
                    if (compare_option_name(line, name_offset, (size_t)name_length, option_table[i].option_name) == 0) {
                        option_index = (int)i;
                        break;
                    }
                }

                if (option_index == -1) {
                    char buffer[256];
                    fprintf(stderr, "Line %d, unknown option: -%s\n", line_number,
                        config_optval_string(buffer, 256, line + name_offset, name_length));
                    ret = -1;
                }
                else {
                    if (option_table[option_index].nb_params_required != nb_params) {
                        fprintf(stderr, "Line %d, option %s requires %d arguments, %d present\n",
                            line_number,
                            option_table[option_index].option_name,
                            option_table[option_index].nb_params_required,
                            nb_params);
                        ret = -1;
                    }
                }

                if (ret == 0) {
                    offset = skip_name(line, offset);
                    if (line[offset] != 0 && line[offset] != '#') {
                        fprintf(stderr, "Line %d, unexpected character at position %d\n", line_number, offset);
                    }
                }

                if (ret == 0) {
                    ret = config_set_option(&option_table[option_index], params, nb_params, config);
                }


            }
        }
        picoquic_file_close(F);
    }

    return ret;
}
#endif

/* Create a QUIC Context based on configuration data.
 * Arguments from configuration:
 * - uint32_t nb_connections,
 * - char const* cert_file_name,
 * - char const* key_file_name,
 * - char const * cert_root_file_name,
 * - char const* default_alpn,
 * - picoquic_connection_id_cb_fn cnx_id_callback,
 * - void* cnx_id_callback_data,
 * - uint8_t reset_seed[PICOQUIC_RESET_SECRET_SIZE],
 * - char const* ticket_file_name,
 * - const uint8_t* ticket_encryption_key,
 * - size_t ticket_encryption_key_length
 * Arguments from program:
 * - picoquic_stream_data_cb_fn default_callback_fn,
 * - void* default_callback_ctx,
 * - uint64_t current_time,
 * - uint64_t* p_simulated_time,
 */

picoquic_quic_t* picoquic_create_and_configure(picoquic_quic_config_t* config,
    picoquic_stream_data_cb_fn default_callback_fn,
    void* default_callback_ctx,
    uint64_t current_time,
    uint64_t* p_simulated_time)
{
    /* Create context */
    /* TODO: padding policy
     * TODO: mtu max accessor
     * TODO: set supported CC without linking every option
     * TODO: set logging option without linking every option
     * TODO: set key log file option
     */
    picoquic_quic_t* quic = picoquic_create(
        config->nb_connections,
        config->server_cert_file,
        config->server_key_file,
        config->root_trust_file,
        config->alpn,
        default_callback_fn,
        default_callback_ctx,
        NULL,
        NULL,
        (config->has_reset_seed)?(uint8_t*)config->reset_seed : NULL,
        current_time,
        p_simulated_time,
        config->ticket_file_name,
        config->ticket_encryption_key,
        config->ticket_encryption_key_length);

    if (quic != NULL) {
        int ret = 0;
        picoquic_congestion_algorithm_t const* cc_algo = NULL;

        /* Additional configuration options */
        /* picoquic_set_alpn_select_fn(qserver, picoquic_demo_server_callback_select_alpn); */
        if (config->do_retry) {
            picoquic_set_cookie_mode(quic, 1);
        }
        else {
            /* TODO: option to provide cookie by default or not */
            picoquic_set_cookie_mode(quic, 2);
        }

        if (config->cc_algo_id != NULL) {
            cc_algo = picoquic_get_congestion_algorithm(config->cc_algo_id);
            if (cc_algo == NULL) {
                fprintf(stderr, "Unrecognized congestion algorithm: %s. Using BBR isntead.\n", config->cc_algo_id);
            }
        }
        if (cc_algo == NULL) {
            cc_algo = picoquic_bbr_algorithm;
        }

        picoquic_set_default_congestion_algorithm(quic, cc_algo);

        picoquic_set_default_spinbit_policy(quic, config->spinbit_policy);
        picoquic_set_default_lossbit_policy(quic, config->lossbit_policy);

        picoquic_set_default_multipath_option(quic, config->multipath_option);
        picoquic_set_default_idle_timeout(quic, (uint64_t)config->idle_timeout);

        picoquic_set_cwin_max(quic, config->cwin_max);
        picoquic_set_default_address_discovery_mode(quic, config->address_discovery_mode);

        if (config->token_file_name) {
            if (picoquic_load_retry_tokens(quic, config->token_file_name) != 0) {
                fprintf(stderr, "No token file present. Will create one as <%s>.\n", config->token_file_name);
            }
        }

        if (config->force_zero_share) {
            quic->client_zero_share = 1;
        }

        if (config->mtu_max > 0) {
            picoquic_set_mtu_max(quic, config->mtu_max);
        }

        if (config->initial_send_mtu_ipv4 > 0 || config->initial_send_mtu_ipv6 > 0) {
            picoquic_set_initial_send_mtu(quic, config->initial_send_mtu_ipv4, config->initial_send_mtu_ipv6);
        }

        if (config->cnx_id_length != -1) {
            if (picoquic_set_default_connection_id_length(quic, (uint8_t)config->cnx_id_length) != 0) {
                fprintf(stderr, "Could not set CNX-ID length #%d.\n", config->cnx_id_length);
            }
        }

        /* Cannot set the cnx_id callback here, because it requires libraries
         * that are not linked by default */

         /* TODO: parameters to define padding policy */
        picoquic_set_padding_policy(quic, 39, 128);

        picoquic_set_binlog(quic, config->bin_dir);

        /* We cannot set qlog here, because of the dependency on libraries
         * that are not linked with picoquic by default. The application
         * will have to call:
         *    picoquic_set_qlog(quic, config->qlog_dir);
         */

        picoquic_set_textlog(quic, config->log_file);

        picoquic_set_log_level(quic, config->use_long_log);

        picoquic_set_preemptive_repeat_policy(quic, config->do_preemptive_repeat);

        picoquic_disable_port_blocking(quic, config->disable_port_blocking);

#ifndef PICOQUIC_WITHOUT_SSLKEYLOG
        picoquic_enable_sslkeylog(quic, config->enable_sslkeylog);
#endif

        if (config->initial_random >= 0 && config->initial_random <= 2) {
            picoquic_set_random_initial(quic, config->initial_random);
        }

        if (config->cipher_suite_id != 0) {
            int iana_cipher_suite_code = config->cipher_suite_id;
            if (config->cipher_suite_id == 20) {
                iana_cipher_suite_code = PICOQUIC_CHACHA20_POLY1305_SHA256;
            }
            else if (config->cipher_suite_id == 128) {
                iana_cipher_suite_code = PICOQUIC_AES_128_GCM_SHA256;
            }
            else if (config->cipher_suite_id == 256) {
                iana_cipher_suite_code = PICOQUIC_AES_256_GCM_SHA384;
            }
            if (picoquic_set_cipher_suite(quic, iana_cipher_suite_code) != 0) {
                fprintf(stderr, "Could not set cipher suite #%d.\n", config->cipher_suite_id);
            }
        }

        if (config->do_retry != 0) {
            picoquic_set_cookie_mode(quic, 1);
        }
        else {
            picoquic_set_cookie_mode(quic, 2);
        }
        /* TODO: control whether to */
        /* picoquic_set_key_log_file_from_env(quic); */

        picoquic_set_default_bdp_frame_option(quic, config->bdp_frame_option);

        if (ret != 0) {
            /* Something went wrong */
            DBG_PRINTF("QUIC configuration fails, ret = %d (0x%x)", ret, ret);
            picoquic_free(quic);
            quic = NULL;
        }
    }

    return quic;
}

void picoquic_config_init(picoquic_quic_config_t* config)
{
    memset(config, 0, sizeof(picoquic_quic_config_t));
    config->cnx_id_length = -1;
    config->nb_connections = 256;
    config->initial_random = 3;
    config->cwin_max = UINT64_MAX;
}

void picoquic_config_clear(picoquic_quic_config_t* config)
{
    if (config->solution_dir != NULL)
    {
        free((void*)config->solution_dir);
    }
    if (config->server_cert_file != NULL)
    {
        free((void*)config->server_cert_file);
    }
    if (config->server_key_file != NULL)
    {
        free((void*)config->server_key_file);
    }
    if (config->log_file != NULL)
    {
        free((void*)config->log_file);
    }
    if (config->bin_dir != NULL)
    {
        free((void*)config->bin_dir);
    }
    if (config->qlog_dir != NULL)
    {
        free((void*)config->qlog_dir);
    }
    if (config->performance_log != NULL)
    {
        free((void*)config->performance_log);
    }
    if (config->cc_algo_id != NULL)
    {
        free((void*)config->cc_algo_id);
    }
    if (config->cnx_id_cbdata != NULL)
    {
        free((void*)config->cnx_id_cbdata);
    }
    if (config->multipath_alt_config != NULL)
    {
        free((void*)config->multipath_alt_config);
    }
    if (config->www_dir != NULL)
    {
        free((void*)config->www_dir);
    }
    /* TODO:  const uint8_t* ticket_encryption_key; Or maybe consider this a PEM file */
    if (config->ticket_file_name != NULL)
    {
        free((void*)config->ticket_file_name);
    }
    if (config->token_file_name != NULL)
    {
        free((void*)config->token_file_name);
    }
    if (config->sni != NULL)
    {
        free((void*)config->sni);
    }
    if (config->alpn != NULL)
    {
        free((void*)config->alpn);
    }
    if (config->out_dir != NULL)
    {
        free((void*)config->out_dir);
    }
    if (config->root_trust_file != NULL)
    {
        free((void*)config->root_trust_file);
    }
    picoquic_config_init(config);
}
