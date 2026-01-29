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
#include "getopt.h"
#endif
#include "picoquic.h"
#include "picoquic_utils.h"
#include "picoquictest.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

extern size_t picohttp_nb_stress_clients;
extern size_t picohttp_test_multifile_number;
extern uint64_t picohttp_random_stress_context;

typedef struct st_picoquic_test_def_t {
    char const* test_name;
    int (*test_fn)();
} picoquic_test_def_t;

typedef enum {
    test_not_run = 0,
    test_excluded,
    test_success,
    test_failed
} test_status_t;

static const picoquic_test_def_t test_table[] = {
    { "h3zero_integer", h3zero_integer_test },
    { "h3zero_varint_stream", h3zero_varint_stream_test },
    { "h3zero_incoming_unidir", h3zero_incoming_unidir_test },
    { "qpack_huffman", qpack_huffman_test },
    { "qpack_huffman_base", qpack_huffman_base_test},
    { "h3zero_parse_qpack", h3zero_parse_qpack_test },
    { "h3zero_prepare_qpack", h3zero_prepare_qpack_test },
    { "h3zero_user_agent", h3zero_user_agent_test },
    { "h3zero_uri", h3zero_uri_test },
    { "h3zero_null_sni", h3zero_null_sni_test },
    { "h3zero_qpack_fuzz", h3zero_qpack_fuzz_test },
    { "h3zero_stream_test", h3zero_stream_test },
    { "h3zero_stream_fuzz", h3zero_stream_fuzz_test },
    { "parse_demo_scenario", parse_demo_scenario_test },
    { "h3zero_server", h3zero_server_test },
    { "h09_server", h09_server_test },
    { "h09_header", h09_header_test },
    { "generic_server", generic_server_test},
    { "h3zero_post", h3zero_post_test},
    { "h09_post", h09_post_test},
    { "demo_alpn", demo_alpn_test},
    { "demo_file_sanitize", demo_file_sanitize_test },
    { "demo_file_access", demo_file_access_test },
    { "demo_server_file", demo_server_file_test },
    { "h3zero_satellite", h3zero_satellite_test },
    { "h09_satellite", h09_satellite_test },
    { "h09_lone_fin", h09_lone_fin_test },
    { "h3_grease_client", h3_grease_client_test },
    { "h3_grease_server", h3_grease_server_test },
    { "h3_long_file_name", h3_long_file_name_test },
    { "h3_multi_file", h3_multi_file_test },
    { "h3_multi_file_loss", h3_multi_file_loss_test },
    { "h3_multi_file_preemptive", h3_multi_file_preemptive_test },
    { "h09_multi_file", h09_multi_file_test },
    { "h09_multi_file_loss", h09_multi_file_loss_test },
    { "h09_multi_file_preemptive", h09_multi_file_preemptive_test },
    { "h3zero_settings", h3zero_settings_test },
    { "h3zero_get_content_type_by_path", h3zero_get_content_type_by_path_test },
    { "http_stress", http_stress_test },
    { "http_corrupt", http_corrupt_test},
    { "http_corrupt_rdpn", http_corrupt_rdpn_test},
    { "http_drop", http_drop_test},
    { "picowt_baton_basic", picowt_baton_basic_test },
    { "picowt_baton_error", picowt_baton_error_test },
    { "picowt_baton_long", picowt_baton_long_test },
    { "picowt_baton_multi", picowt_baton_multi_test },
    { "picowt_baton_random", picowt_baton_random_test },
    { "picowt_baton_uri", picowt_baton_uri_test },
    { "picowt_baton_wrong", picowt_baton_wrong_test },
    { "quicperf_parse", quicperf_parse_test },
    { "quicperf_batch", quicperf_batch_test },
    { "quicperf_datagram", quicperf_datagram_test },
    { "quicperf_media", quicperf_media_test },
    { "quicperf_multi", quicperf_multi_test },
    { "quicperf_overflow", quicperf_overflow_test },
};

static size_t const nb_tests = sizeof(test_table) / sizeof(picoquic_test_def_t);

static int do_one_test(size_t i, FILE* F)
{
    int ret = 0;

    if (i >= nb_tests) {
        fprintf(F, "Invalid test number %" PRIst "\n", i);
        ret = -1;
    } else {
        fprintf(F, "Starting test number %" PRIst ", %s\n", i, test_table[i].test_name);

        fflush(F);

        ret = test_table[i].test_fn();
        if (ret == 0) {
            fprintf(F, "    Success.\n");
        } else {
            fprintf(F, "    Fails, error: %d.\n", ret);
        }
    }

    fflush(F);

    return ret;
}

int usage(char const * argv0)
{
    fprintf(stderr, "PicoQUIC test execution\n");
    fprintf(stderr, "Usage: picoquic_ct [-x <excluded>] [<list of tests]\n");
    fprintf(stderr, "\nUsage: %s [test1 [test2 ..[testN]]]\n\n", argv0);
    fprintf(stderr, "   Or: %s [-x test]*", argv0);
    fprintf(stderr, "Valid test names are: \n");
    for (size_t x = 0; x < nb_tests; x++) {
        fprintf(stderr, "    ");

        for (int j = 0; j < 4 && x < nb_tests; j++, x++) {
            fprintf(stderr, "%s, ", test_table[x].test_name);
        }
        fprintf(stderr, "\n");
    }
    fprintf(stderr, "Options: \n");
    fprintf(stderr, "  -x test           Do not run the specified test.\n");
    fprintf(stderr, "  -s nnn            Set the number of stress clients to nnn.\n");
    fprintf(stderr, "  -R xxxxxxxx       Set seed for stress tests to xxxxxxxx.\n");
    fprintf(stderr, "  -m nnn            Set number of files in multi file tests to nnn.\n");
    fprintf(stderr, "  -n                Disable debug prints.\n");
    fprintf(stderr, "  -r                Retry failed tests with debug print enabled.\n");
    fprintf(stderr, "  -h                Print this help message\n");
    fprintf(stderr, "  -S solution_dir   Set the path to the source files to find the default files\n");
    fprintf(stderr, "\nThe list of tests include http_stress, http_drop, http_corrupt\n");
    fprintf(stderr, "and http_corrupt_rpdn, which are all variations of the stress\n");
    fprintf(stderr, "test. Their execution is controlled by a number of clients to\n");
    fprintf(stderr, "simulate, which can be set by the \"-s\" option (default: 128),\n");
    fprintf(stderr, "and by an initial random seed which can be set by the \"R\"\n");
    fprintf(stderr, "option (default: 305,419,896). If the random seed is set to 0,\n");
    fprintf(stderr, "tests will initailize a seed using the cryptographic random");
    fprintf(stderr, "number generator.\n");
    fprintf(stderr, "\nThere are multiple tests that try downloading a series of\n");
    fprintf(stderr, "files with HTTP3 or H09, with out extra loss, with loss, or\n");
    fprintf(stderr, "with loss and using preemptive repeat. For all these tests,\n");
    fprintf(stderr, "the number of files is controlled by the \"-m\" option\n");
    fprintf(stderr, "(default: 1000).\n");

    return -1;
}

int get_test_number(char const * test_name)
{
    int test_number = -1;

    for (size_t i = 0; i < nb_tests; i++) {
        if (strcmp(test_name, test_table[i].test_name) == 0) {
            test_number = (int)i;
        }
    }

    return test_number;
}

int main(int argc, char** argv)
{
    int ret = 0;
    int nb_test_tried = 0;
    int nb_test_failed = 0;
    int stress_clients = 0;
    test_status_t * test_status = (test_status_t *) calloc(nb_tests, sizeof(test_status_t));
    int opt;
    int random_seed = 0;
    int nb_multi_file = 0;
    int disable_debug = 0;
    int retry_failed_test = 0;

    if (test_status == NULL)
    {
        fprintf(stderr, "Could not allocate memory.\n");
        ret = -1;
    }
    else
    {
        while (ret == 0 && (opt = getopt(argc, argv, "R:s:m:S:x:nrh")) != -1) {
            switch (opt) {
            case 'x': {
                int test_number = get_test_number(optarg);

                if (test_number < 0) {
                    fprintf(stderr, "Incorrect test name: %s\n", optarg);
                    ret = usage(argv[0]);
                }
                else {
                    test_status[test_number] = test_excluded;
                }
                break;
            }
            case 'R':
                random_seed = atoi(optarg);
                if (random_seed < 0) {
                    fprintf(stderr, "Incorrect number of stress clients: %s\n", optarg);
                    ret = usage(argv[0]);
                }
                else {
                    picohttp_random_stress_context = (uint64_t)random_seed;
                }
                break;
            case 's':
                stress_clients = atoi(optarg);
                if (stress_clients <= 0) {
                    fprintf(stderr, "Incorrect number of stress clients: %s\n", optarg);
                    ret = usage(argv[0]);
                }
                else {
                    picohttp_nb_stress_clients = (size_t) stress_clients;
                }
                break;
            case 'm':
                nb_multi_file = atoi(optarg);
                if (nb_multi_file <= 0) {
                    fprintf(stderr, "Incorrect number of files for multi-file test: %s\n", optarg);
                    ret = usage(argv[0]);
                }
                else {
                    picohttp_test_multifile_number = (size_t)nb_multi_file;
                }
                break;
            case 'S':
                picoquic_set_solution_dir(optarg);
                break;
            case 'n':
                disable_debug = 1;
                break;
            case 'r':
                retry_failed_test = 1;
                break;
            case 'h':
                usage(argv[0]);
                exit(0);
                break;
            default:
                ret = usage(argv[0]);
                break;
            }
        }

        if (disable_debug) {
            debug_printf_suspend();
        }
        else {
            debug_printf_push_stream(stderr);
        }

        if (ret == 0)
        {
            if (optind >= argc) {
                for (size_t i = 0; i < nb_tests; i++) {
                    if (test_status[i] == test_not_run) {
                        nb_test_tried++;
                        if (do_one_test(i, stdout) != 0) {
                            test_status[i] = test_failed;
                            nb_test_failed++;
                            ret = -1;
                        }
                        else {
                            test_status[i] = test_success;
                        }
                    }
                    else if (stress_clients == 0) {
                        fprintf(stdout, "Test number %d (%s) is bypassed.\n", (int)i, test_table[i].test_name);
                    }
                }
            }
            else {
                for (int arg_num = optind; arg_num < argc; arg_num++) {
                    int test_number = get_test_number(argv[arg_num]);

                    if (test_number < 0) {
                        fprintf(stderr, "Incorrect test name: %s\n", argv[arg_num]);
                        ret = usage(argv[0]);
                    }
                    else {
                        nb_test_tried++;
                        if (do_one_test(test_number, stdout) != 0) {
                            test_status[test_number] = test_failed;
                            nb_test_failed++;
                            ret = -1;
                        }
                        else if (test_status[test_number] == test_not_run) {
                            test_status[test_number] = test_success;
                        }
                        break;
                    }
                }
            }
        }

        if (nb_test_tried > 1) {
            fprintf(stdout, "Tried %d tests, %d fail%s.\n", nb_test_tried,
                nb_test_failed, (nb_test_failed > 1) ? "" : "s");
        }

        if (nb_test_failed > 0) {
            fprintf(stdout, "Failed test(s): ");
            for (size_t i = 0; i < nb_tests; i++) {
                if (test_status[i] == test_failed) {
                    fprintf(stdout, "%s ", test_table[i].test_name);
                }
            }
            fprintf(stdout, "\n");

            if (disable_debug && retry_failed_test) {
                /* debug_printf_push_stream(stderr); */
                debug_printf_resume();
                ret = 0;
                for (size_t i = 0; i < nb_tests; i++) {
                    int is_stress = 0;
                    if (strcmp("http_stress", test_table[i].test_name) == 0) {
                        is_stress = 1;
                    }
                    if (test_status[i] == test_failed) {
                        fprintf(stdout, "Retrying %s:\n", test_table[i].test_name);
                        if (is_stress && !disable_debug) {
                            debug_printf_suspend();
                        }
                        if (do_one_test(i, stdout) != 0) {
                            test_status[i] = test_failed;
                            ret = -1;
                        }
                        else {
                            /* This was a Heisenbug.. */
                            test_status[i] = test_success;
                        }
                        if (is_stress && !disable_debug) {
                            debug_printf_resume();
                        }
                    }
                }
                if (ret == 0) {
                    fprintf(stdout, "All tests pass after second try.\n");
                }
                else {
                    fprintf(stdout, "Still failing: ");
                    for (size_t i = 0; i < nb_tests; i++) {
                        if (test_status[i] == test_failed) {
                            fprintf(stdout, "%s ", test_table[i].test_name);
                        }
                    }
                    fprintf(stdout, "\n");
                }
            }
        }

        free(test_status);
    }
    
    return (ret);
}
