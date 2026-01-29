#include "picoquic_internal.h"
/*
* Author: Christian Huitema
* Copyright (c) 2024, Private Octopus, Inc.
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
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include "picoquic.h"
#include "picoquic_internal.h"
#include "picoquic_utils.h"
#include "picoquic_binlog.h"
#include "picosplay.h"
#include "picoquictest_internal.h"
#include "quicperf.h"

#define qpstr_batch "256:12345;"
#define qpstr_batch100 "* 100:256 : 12345;"
#define qpstr_batch2 "= b1:256 : 12345; = b2:=b1: 256 : 12345;"
#define qpstr_video1 "= v1:s30:n300:12345;"
#define qpstr_video2 "=v2:s30:p4:C:n300:12345;"
#define qpstr_video3 "=v3 : s30: p4:S: n1800:12345:G150:I11111;"
#define qpstr_video4 "=v4 : s30:p4:S:  n1800:12345:G150:I11111:D1000;"
#define qpstr_audio "=a0:d50:p2:C:n500:40;"
#define qpstr_combo "=a1:d50:p2:S:n3000:80; \
= vlow:*3 : s30 :p4:S:n1800 : 3750 : G150 : I37500; \
= vmid:*3 : s30 :p6:S: n1800 : 6250 : G150 : I62500 : D1000; \
= vhi:*3 : s30 :p8:S: n1800 : 12500 : G150 : I125000 : D1000;"

const quicperf_stream_desc_t qpsc_batch[1] = {
    {
    { 0, 0 }, /* id */
    { 0, 0 }, /* previous id */
    1, /* repeat_count */
    quicperf_media_batch, /* media_type */
    0, /* frequency */
    256, /* post_size */
    12345, /* response_size */
    0, /* nb_frames */
    0, /* frame_size */
    0, /* group_size */
    0, /* first_frame_size */
    0, /* reset_delay */
    0, /* priority */
    0, /* is_infinite */
    0, /*  is_client_media */
} };

const quicperf_stream_desc_t qpsc_batch100[1] = { {
    { 0, 0 }, /* id */
    { 0, 0 }, /* previous id */
    100, /* repeat_count */
    quicperf_media_batch, /* media_type */
    0, /* frequency */
    256, /* post_size */
    12345, /* response_size */
    0, /* nb_frames */
    0, /* frame_size */
    0, /* group_size */
    0, /* first_frame_size */
    0, /* reset_delay */
    0, /* priority */
    0, /* is_infinite */
    0, /*  is_client_media */
}};

const quicperf_stream_desc_t qpsc_batch2[2] = {
    {
        { 'b', '1', 0 }, /* id */
        { 0, 0 }, /* previous id */
        1, /* repeat_count */
        quicperf_media_batch, /* media_type */
        0, /* frequency */
        256, /* post_size */
        12345, /* response_size */
        0, /* nb_frames */
        0, /* frame_size */
        0, /* group_size */
        0, /* first_frame_size */
        0, /* reset_delay */
        0, /* priority */
        0, /* is_infinite */
        0, /*  is_client_media */
    },
    {
        { 'b', '2', 0 }, /* id */
        { 'b', '1', 0 }, /* previous id */
        1, /* repeat_count */
        quicperf_media_batch, /* media_type */
        0, /* frequency */
        256, /* post_size */
        12345, /* response_size */
        0, /* nb_frames */
        0, /* frame_size */
        0, /* group_size */
        0, /* first_frame_size */
        0, /* reset_delay */
        0, /* priority */
        0, /* is_infinite */
        0, /*  is_client_media */
    }
};

const quicperf_stream_desc_t qpsc_video1[1] = {
    {
        { 'v', '1', 0 }, /* id */
        { 0, 0 }, /* previous id */
        1, /* repeat_count */
        quicperf_media_stream, /* media_type */
        30, /* frequency */
        0, /* post_size */
        0, /* response_size */
        300, /* nb_frames */
        12345, /* frame_size */
        0, /* group_size */
        0, /* first_frame_size */
        0, /* reset_delay */
        0, /* priority */
        0, /* is_infinite */
        0, /*  is_client_media */
    }
};

const quicperf_stream_desc_t qpsc_video2[1] = {
    {
        { 'v', '2', 0 }, /* id */
        { 0, 0 }, /* previous id */
        1, /* repeat_count */
        quicperf_media_stream, /* media_type */
        30, /* frequency */
        0, /* post_size */
        0, /* response_size */
        300, /* nb_frames */
        12345, /* frame_size */
        0, /* group_size */
        0, /* first_frame_size */
        0, /* reset_delay */
        4, /* priority */
        0, /* is_infinite */
        1, /*  is_client_media */
    }
};

const quicperf_stream_desc_t qpsc_video3[] = {
    {
        { 'v', '3', 0 }, /* id */
        { 0, 0 }, /* previous id */
        1, /* repeat_count */
        quicperf_media_stream, /* media_type */
        30, /* frequency */
        0, /* post_size */
        0, /* response_size */
        1800, /* nb_frames */
        12345, /* frame_size */
        150, /* group_size */
        11111, /* first_frame_size */
        0, /* reset_delay */
        4, /* priority */
        0, /* is_infinite */
        0, /*  is_client_media */
    }
};

const quicperf_stream_desc_t qpsc_video4[] = {
    {
        { 'v', '4', 0 }, /* id */
        { 0, 0 }, /* previous id */
        1, /* repeat_count */
        quicperf_media_stream, /* media_type */
        30, /* frequency */
        0, /* post_size */
        0, /* response_size */
        1800, /* nb_frames */
        12345, /* frame_size */
        150, /* group_size */
        11111, /* first_frame_size */
        1000, /* reset_delay */
        4, /* priority */
        0, /* is_infinite */
        0, /*  is_client_media */
    }
};

const quicperf_stream_desc_t qpsc_audio[1] = {
    {
        { 'a', '0', 0 }, /* id */
        { 0, 0 }, /* previous id */
        1, /* repeat_count */
        quicperf_media_datagram, /* media_type */
        50, /* frequency */
        0, /* post_size */
        0, /* response_size */
        500, /* nb_frames */
        40, /* frame_size */
        0, /* group_size */
        0, /* first_frame_size */
        0, /* reset_delay */
        2, /* priority */
        0, /* is_infinite */
        1, /*  is_client_media */
    }
};

const quicperf_stream_desc_t qpsc_combo[4] = {
    {
        { 'a', '1', 0 }, /* id */
        { 0, 0 }, /* previous id */
        1, /* repeat_count */
        quicperf_media_datagram, /* media_type */
        50, /* frequency */
        0, /* post_size */
        0, /* response_size */
        3000, /* nb_frames */
        80, /* frame_size */
        0, /* group_size */
        0, /* first_frame_size */
        0, /* reset_delay */
        2, /* priority */
        0, /* is_infinite */
        0, /*  is_client_media */
    },
    {
        { 'v', 'l', 'o', 'w',  0}, /* id */
        { 0, 0 }, /* previous id */
        3, /* repeat_count */
        quicperf_media_stream, /* media_type */
        30, /* frequency */
        0, /* post_size */
        0, /* response_size */
        1800, /* nb_frames */
        3750, /* frame_size */
        150, /* group_size */
        37500, /* first_frame_size */
        0, /* reset_delay */
        4, /* priority */
        0, /* is_infinite */
        0, /*  is_client_media */
    },
    {
        { 'v', 'm', 'i', 'd',  0}, /* id */
        { 0, 0 }, /* previous id */
        3, /* repeat_count */
        quicperf_media_stream, /* media_type */
        30, /* frequency */
        0, /* post_size */
        0, /* response_size */
        1800, /* nb_frames */
        6250, /* frame_size */
        150, /* group_size */
        62500, /* first_frame_size */
        1000, /* reset_delay */
        6, /* priority */
        0, /* is_infinite */
        0, /*  is_client_media */
    },
    {
        { 'v', 'h', 'i',  0}, /* id */
        { 0, 0 }, /* previous id */
        3, /* repeat_count */
        quicperf_media_stream, /* media_type */
        30, /* frequency */
        0, /* post_size */
        0, /* response_size */
        1800, /* nb_frames */
        12500, /* frame_size */
        150, /* group_size */
        125000, /* first_frame_size */
        1000, /* reset_delay */
        8, /* priority */
        0, /* is_infinite */
        0, /*  is_client_media */
    }
};

typedef struct st_quicperf_test_line_t {
    const quicperf_stream_desc_t* sc;
    size_t nb_sc;
    char const* str;
} quicperf_test_line_t;

const quicperf_test_line_t test_lines[] = {
    { qpsc_batch, 1, qpstr_batch },
    { qpsc_batch100, 1, qpstr_batch100 },
    { qpsc_batch2, 2, qpstr_batch2 },
    { qpsc_video1, 1, qpstr_video1 },
    { qpsc_video2, 1, qpstr_video2 },
    { qpsc_video3, 1, qpstr_video3 },
    { qpsc_video4, 1, qpstr_video4 },
    { qpsc_audio, 1, qpstr_audio },
    { qpsc_combo, 4, qpstr_combo }
};

const size_t nb_test_lines = sizeof(test_lines) / sizeof(quicperf_test_line_t);

int quicperf_compare_stream_desc(const quicperf_stream_desc_t* sc1, const quicperf_stream_desc_t* sc2)
{
    int ret = 0;
    char const* diff = NULL;

    if (strcmp(sc1->id, sc2->id) != 0) {
        diff = "id";
    }
    else if (strcmp(sc1->previous_id, sc2->previous_id) != 0) {
        diff = "previous_id";
    }
    else if (sc1->repeat_count != sc2->repeat_count) {
        diff = "repeat_count";
    }
    else if (sc1->media_type != sc2->media_type) {
        diff = "media_type";
    }
    else if (sc1->frequency != sc2->frequency) {
        diff = "frequency";
    }
    else if (sc1->post_size != sc2->post_size) {
        diff = "post_size";
    }
    else if (sc1->post_size != sc2->post_size) {
        diff = "post_size";
    }
    else if (sc1->response_size != sc2->response_size) {
        diff = "response_size";
    }
    else if (sc1->nb_frames != sc2->nb_frames) {
        diff = "nb_frames";
    }
    else if (sc1->frame_size != sc2->frame_size) {
        diff = "frame_size";
    }
    else if (sc1->group_size != sc2->group_size) {
        diff = "group_size";
    }
    else if (sc1->first_frame_size != sc2->first_frame_size) {
        diff = "first_frame_size";
    }
    else if (sc1->reset_delay != sc2->reset_delay) {
        diff = "reset_delay";
    }
    else if (sc1->priority != sc2->priority) {
        diff = "priority";
    }
    else if (sc1->is_infinite != sc2->is_infinite) {
        diff = "is_infinite";
    }
    else if (sc1->is_client_media != sc2->is_client_media) {
        diff = "is_client_media";
    }
    if (diff != NULL) {
        DBG_PRINTF("Values of %s do not match.\n", diff);
        ret = -1;
    }
    return ret;
}

int quicperf_parse_test_one(const quicperf_test_line_t* tl)
{
    int ret = 0;

    /* Parse the scenario */
    quicperf_ctx_t* ctx = quicperf_create_ctx(tl->str);
    if (ctx == NULL) {
        ret = -1;
    }
    else {
        /* Compare to the reference */
        if (ctx->nb_scenarios != tl->nb_sc) {
            DBG_PRINTF("Found %zu streams instead of %zu", ctx->nb_scenarios, tl->nb_sc);
            ret = -1;
        }
        else {
            for (size_t i = 0; ret == 0 && i < ctx->nb_scenarios; i++) {
                if (quicperf_compare_stream_desc(&ctx->scenarios[i], &tl->sc[i]) != 0) {
                    DBG_PRINTF("Stream descriptio %zu does not match", i);
                    ret = -1;
                }
            }
        }
        /* Free the scenario */
        quicperf_delete_ctx(ctx);
    }
    return ret;
}

int quicperf_parse_test()
{
    int ret = 0;
    for (size_t i = 0; ret == 0 && i < nb_test_lines; i++) {
        ret = quicperf_parse_test_one(&test_lines[i]);
        if (ret != 0) {
            DBG_PRINTF("Parse test fails for test_lines[%zu]", i);
        }
    }
    return ret;
}

typedef struct st_quicperf_test_target_t {
    uint64_t nb_frames_received_min;
    uint64_t nb_frames_received_max;
    uint64_t average_delay_min;
    uint64_t average_delay_max;
    uint64_t max_delay;
    uint64_t min_delay;
} quicperf_test_target_t;


int quicperf_e2e_test(uint8_t test_id, char const *scenario, uint64_t completion_target, size_t nb_targets, quicperf_test_target_t * targets)
{
    uint64_t simulated_time = 0;
    uint64_t loss_mask = 0;
    uint64_t time_out;
    int nb_trials = 0;
    int was_active = 0;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    quicperf_ctx_t  *quicperf_ctx;
    int ret = 0;
    picoquic_connection_id_t initial_cid = { {0x9e, 0x8f, 0, 0, 0, 0, 0, 0}, 8 };

    initial_cid.id[2] = test_id;

    quicperf_ctx = quicperf_create_ctx(scenario);
    if (quicperf_ctx == NULL) {
        DBG_PRINTF("Could not get ready to run QUICPERF(%s)\n", scenario);
        return -1;
    }

    if (ret == 0 && quicperf_ctx->nb_scenarios != nb_targets) {
        DBG_PRINTF("Expected %zu scenario items, got %zu\n", quicperf_ctx->nb_scenarios, nb_targets);
        return -1;
    }

    if (ret == 0) {
        ret = tls_api_init_ctx_ex(&test_ctx,
            PICOQUIC_INTERNAL_TEST_VERSION_1,
            PICOQUIC_TEST_SNI, "perf", &simulated_time, NULL, NULL, 0, 1, 0, &initial_cid);

        if (ret == 0) {
            picoquic_set_binlog(test_ctx->qserver, ".");
            test_ctx->qserver->use_long_log = 1;
        }

        if (ret == 0) {
            picoquic_set_binlog(test_ctx->qclient, ".");
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
     * We want to replace that by the quicperf callback */

    if (ret == 0) {
        test_ctx->qserver->default_tp.max_datagram_frame_size = PICOQUIC_MAX_PACKET_SIZE;
        test_ctx->cnx_client->local_parameters.max_datagram_frame_size = PICOQUIC_MAX_PACKET_SIZE;
        // picoquic_set_alpn_select_fn(test_ctx->qserver, picoquic_demo_server_callback_select_alpn);
        picoquic_set_default_callback(test_ctx->qserver, quicperf_callback, NULL);
        picoquic_set_callback(test_ctx->cnx_client, quicperf_callback, quicperf_ctx);
        if (ret == 0) {
            ret = picoquic_start_client_cnx(test_ctx->cnx_client);
        }
    }

    if (ret == 0) {
        ret = tls_api_connection_loop(test_ctx, &loss_mask, 0, &simulated_time);
    }

    /* Simulate the connection from the client side. */
    time_out = simulated_time + 30000000;
    while (ret == 0 && picoquic_get_cnx_state(test_ctx->cnx_client) != picoquic_state_disconnected) {
        ret = tls_api_one_sim_round(test_ctx, &simulated_time, time_out, &was_active);

        if (ret == -1) {
            break;
        }

        if (test_ctx->cnx_client->cnx_state == picoquic_state_ready &&
            picoquic_is_cnx_backlog_empty(test_ctx->cnx_client) &&
            quicperf_ctx->next_group_start_time < simulated_time) {
            if (quicperf_ctx->nb_open_streams == 0) {
                ret = picoquic_close(test_ctx->cnx_client, 0);
            }
            else if (simulated_time > quicperf_ctx->last_interaction_time &&
                simulated_time - quicperf_ctx->last_interaction_time > 10000000ull) {
                (void)picoquic_close(test_ctx->cnx_client, 0xdeadbeef);
                ret = -1;
            }
        }
        if (++nb_trials > 100000) {
            ret = -1;
            break;
        }
    }

    if (ret == 0 && test_ctx->qclient->nb_data_nodes_allocated > test_ctx->qclient->nb_data_nodes_in_pool) {
        ret = -1;
    }
    else if (ret == 0 && test_ctx->qserver->nb_data_nodes_allocated > test_ctx->qserver->nb_data_nodes_in_pool) {
        ret = -1;
    }

    if (ret == 0 && completion_target != 0) {
        if (simulated_time > completion_target) {
            DBG_PRINTF("Test uses %llu microsec instead of %llu", simulated_time, completion_target);
            ret = -1;
        }
    }

    for (size_t i = 0; ret == 0 && i < nb_targets; i++) {
        quicperf_test_target_t* target = &targets[i];
        quicperf_stream_report_t* report = &quicperf_ctx->reports[i];

        if (target->nb_frames_received_min != 0 &&
            report->nb_frames_received < target->nb_frames_received_min) {
            DBG_PRINTF("Scenario %zu, expected at least %" PRIu64 "frames, got % PRIu64", i, target->nb_frames_received_min, report->nb_frames_received);
            ret = -1;
        }
        else if (target->nb_frames_received_max != 0 &&
            report->nb_frames_received > target->nb_frames_received_max) {
            DBG_PRINTF("Scenario %zu, expected at most %" PRIu64 "frames, got % PRIu64", i, target->nb_frames_received_max, report->nb_frames_received);
            ret = -1;
        }
        else if (report->nb_frames_received > 0) {
            uint64_t average_delay = report->sum_delays / report->nb_frames_received;

            if (target->average_delay_min != 0 &&
                average_delay < target->average_delay_min) {
                DBG_PRINTF("Scenario %zu, expected average delay >= %" PRIu64 ", got % PRIu64", i, target->average_delay_min, average_delay);
                ret = -1;
            }
            else if (target->average_delay_max != 0 &&
                average_delay > target->average_delay_max) {
                DBG_PRINTF("Scenario %zu, expected average delay <= %" PRIu64 ", got % PRIu64", i, target->average_delay_max, average_delay);
                ret = -1;
            }
            else if (target->max_delay != 0 &&
                report->max_delays > target->max_delay) {
                DBG_PRINTF("Scenario %zu, expected max delay <= %" PRIu64 ", got % PRIu64", i, target->max_delay, report->max_delays);
                ret = -1;
            }
            else if (target->min_delay != 0 &&
                report->min_delays < target->min_delay) {
                DBG_PRINTF("Scenario %zu, expected min delay >= %" PRIu64 ", got % PRIu64", i, target->min_delay, report->min_delays);
                ret = -1;
            }
        }
    }

    quicperf_delete_ctx(quicperf_ctx);

    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }

    return ret;
}

int quicperf_batch_test()
{
    char const* batch_scenario = "=b1:*1:397:1000000;";
    quicperf_test_target_t batch_target = {
        0, /* nb_frames_received_min */
        0, /* nb_frames_received_max */
        0, /* average_delay_min */
        0, /* average_delay_max */
        0, /* max_delay */
        0, /* min_delay */
    };

    return quicperf_e2e_test(0xba, batch_scenario, 1200000, 1, &batch_target);
}

int quicperf_datagram_test()
{
    char const* datagram_scenario = "=a1:d50:n250:100;";
    quicperf_test_target_t datagram_target = {
        250, /* nb_frames_received_min */
        250, /* nb_frames_received_max */
        20000, /* average_delay_min */
        25000, /* average_delay_max */
        50000, /* max_delay */
        20000, /* min_delay */
    };

    return quicperf_e2e_test(0xda, datagram_scenario, 6000000, 1, &datagram_target);
}

int quicperf_media_test()
{
    char const* media_scenario = "=v1:s30:n150:2000:G30:I20000;";
    quicperf_test_target_t media_target = {
        150, /* nb_frames_received_min */
        150, /* nb_frames_received_max */
        20000, /* average_delay_min */
        25000, /* average_delay_max */
        50000, /* max_delay */
        20000, /* min_delay */
    };

    return quicperf_e2e_test(0x1a,media_scenario, 6000000, 1, &media_target);
}

int quicperf_multi_test()
{
    char const* multi_scenario = "=a1:d50:p2:S:n250:80; \
     = vlow: s30 :p4:S:n150 : 3750 : G30 : I37500; \
     = vmid: s30 :p6:S:n150 : 6250 : G30 : I62500 : D250000;";
    quicperf_test_target_t multi_target[] = {
        {
        250, /* nb_frames_received_min */
        250, /* nb_frames_received_max */
        20000, /* average_delay_min */
        26000, /* average_delay_max */
        100000, /* max_delay */
        20000, /* min_delay */
        },
        {
        150, /* nb_frames_received_min */
        150, /* nb_frames_received_max */
        20000, /* average_delay_min */
        40000, /* average_delay_max */
        66000, /* max_delay */
        20000, /* min_delay */
        },
        {
        150, /* nb_frames_received_min */
        150, /* nb_frames_received_max */
        20000, /* average_delay_min */
        40000, /* average_delay_max */
        133000, /* max_delay */
        20000, /* min_delay */
        }
    };

    return quicperf_e2e_test(0x17, multi_scenario, 6000000, 3, multi_target);
}

int quicperf_overflow_test()
{
    char const* overflow_scenario = "=a1:d50:p2:S:n250:80; \
     = vlow: s30 :p4:S:n150 : 3750 : G30 : I37500; \
     = vmid: s30 :p6:S:n150 : 6250 : G30 : I62500 : D300000; \
     = vhi:*3 : s30 :p8:S: n150 : 12500 : G150 : I125000 : D250000;";
    quicperf_test_target_t overflow_target[] = {
        {
        250, /* nb_frames_received_min */
        250, /* nb_frames_received_max */
        20000, /* average_delay_min */
        40000, /* average_delay_max */
        100000, /* max_delay */
        20000, /* min_delay */
        },
        {
        150, /* nb_frames_received_min */
        150, /* nb_frames_received_max */
        20000, /* average_delay_min */
        40000, /* average_delay_max */
        100000, /* max_delay */
        20000, /* min_delay */
        },
        {
        150, /* nb_frames_received_min */
        150, /* nb_frames_received_max */
        20000, /* average_delay_min */
        45000, /* average_delay_max */
        120000, /* max_delay */
        20000, /* min_delay */
        },
        {
        3, /* nb_frames_received_min */
        24, /* nb_frames_received_max */
        20000, /* average_delay_min */
        650000, /* average_delay_max */
        750000, /* max_delay */
        20000, /* min_delay */
        }
    };

    return quicperf_e2e_test(0xf1, overflow_scenario, 6000000, 4, overflow_target);
}
