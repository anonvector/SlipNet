#include <stdint.h>
#include <stdlib.h>

#include <picoquic_internal.h>

typedef enum {
    slipstream_server_cc_alg_none = 0,
} slipstream_server_cc_alg_state_t;

typedef struct st_slipstream_server_cc_t {
    slipstream_server_cc_alg_state_t state;
} slipstream_server_cc_t;

static void slipstream_server_cc_init(picoquic_cnx_t * cnx, picoquic_path_t* path_x, uint64_t current_time)
{
    (void)cnx;
    (void)current_time;
    slipstream_server_cc_t* state = (slipstream_server_cc_t*)malloc(sizeof(slipstream_server_cc_t));
    if (state != NULL) {
        state->state = slipstream_server_cc_alg_none;
    }
    path_x->congestion_alg_state = (void*)state;

    /* Disable congestion control/pacing limits for authoritative server mode. */
    /* Keep packet_time_* non-zero to avoid zero-interval pacing paths. */
    path_x->cwin = UINT64_MAX;
    path_x->pacing.rate = UINT64_MAX;
    path_x->pacing.packet_time_nanosec = 1;
    path_x->pacing.packet_time_microsec = 1;
    path_x->pacing.bucket_max = UINT64_MAX / 4;
    path_x->pacing.bucket_nanosec = UINT64_MAX / 4;
    path_x->is_cc_data_updated = 1;
}

static void slipstream_server_cc_notify(
    picoquic_cnx_t* cnx,
    picoquic_path_t* path_x,
    picoquic_congestion_notification_t notification,
    picoquic_per_ack_state_t * ack_state,
    uint64_t current_time)
{
    (void)cnx;
    (void)notification;
    (void)ack_state;
    (void)current_time;
    path_x->is_cc_data_updated = 1;
    path_x->cwin = UINT64_MAX;
}

static void slipstream_server_cc_delete(picoquic_path_t* path_x)
{
    if (path_x->congestion_alg_state != NULL) {
        free(path_x->congestion_alg_state);
        path_x->congestion_alg_state = NULL;
    }
}

static void slipstream_server_cc_observe(picoquic_path_t* path_x, uint64_t* cc_state, uint64_t* cc_param)
{
    slipstream_server_cc_t* state = (slipstream_server_cc_t*)path_x->congestion_alg_state;
    if (state == NULL) {
        *cc_state = (uint64_t)slipstream_server_cc_alg_none;
    } else {
        *cc_state = (uint64_t)state->state;
    }
    *cc_param = UINT64_MAX;
}

#define picoquic_slipstream_server_cc_ID "slipstream_server"
#define PICOQUIC_CC_ALGO_NUMBER_SLIPSTREAM_SERVER 10

picoquic_congestion_algorithm_t slipstream_server_cc_algorithm_struct = {
    picoquic_slipstream_server_cc_ID, PICOQUIC_CC_ALGO_NUMBER_SLIPSTREAM_SERVER,
    slipstream_server_cc_init,
    slipstream_server_cc_notify,
    slipstream_server_cc_delete,
    slipstream_server_cc_observe
};

picoquic_congestion_algorithm_t* slipstream_server_cc_algorithm = &slipstream_server_cc_algorithm_struct;
