#include <stdint.h>

#include <picoquic_internal.h>

typedef enum {
    slipstream_path_mode_unknown = 0,
    slipstream_path_mode_recursive = 1,
    slipstream_path_mode_authoritative = 2,
} slipstream_path_mode_t;

static slipstream_path_mode_t slipstream_default_path_mode = slipstream_path_mode_recursive;
static picoquic_congestion_algorithm_t const* slipstream_cc_override = NULL;

static slipstream_path_mode_t slipstream_normalize_mode(int mode)
{
    if (mode == slipstream_path_mode_authoritative || mode == slipstream_path_mode_recursive) {
        return (slipstream_path_mode_t)mode;
    }
    return slipstream_path_mode_recursive;
}

static slipstream_path_mode_t slipstream_resolve_mode(uint8_t mode)
{
    slipstream_path_mode_t resolved = (slipstream_path_mode_t)mode;
    if (resolved == slipstream_path_mode_unknown) {
        resolved = slipstream_default_path_mode;
    }
    return resolved;
}

static picoquic_congestion_algorithm_t const* slipstream_select_cc(picoquic_path_t* path_x)
{
    if (slipstream_cc_override != NULL) {
        return slipstream_cc_override;
    }
    slipstream_path_mode_t mode = slipstream_resolve_mode(path_x->slipstream_path_mode);
    if (mode == slipstream_path_mode_authoritative) {
        return picoquic_bbr_algorithm;
    }
    return picoquic_dcubic_algorithm;
}

static void slipstream_mixed_cc_init(picoquic_cnx_t* cnx, picoquic_path_t* path_x, uint64_t current_time)
{
    picoquic_congestion_algorithm_t const* alg = slipstream_select_cc(path_x);
    if (alg != NULL && alg->alg_init != NULL) {
        alg->alg_init(cnx, path_x, current_time);
    }
}

static void slipstream_mixed_cc_notify(
    picoquic_cnx_t* cnx,
    picoquic_path_t* path_x,
    picoquic_congestion_notification_t notification,
    picoquic_per_ack_state_t* ack_state,
    uint64_t current_time)
{
    picoquic_congestion_algorithm_t const* alg = slipstream_select_cc(path_x);
    if (alg != NULL && alg->alg_notify != NULL) {
        alg->alg_notify(cnx, path_x, notification, ack_state, current_time);
    }
}

static void slipstream_mixed_cc_delete(picoquic_path_t* path_x)
{
    picoquic_congestion_algorithm_t const* alg = slipstream_select_cc(path_x);
    if (alg != NULL && alg->alg_delete != NULL) {
        alg->alg_delete(path_x);
    }
}

static void slipstream_mixed_cc_observe(picoquic_path_t* path_x, uint64_t* cc_state, uint64_t* cc_param)
{
    picoquic_congestion_algorithm_t const* alg = slipstream_select_cc(path_x);
    if (alg != NULL && alg->alg_observe != NULL) {
        alg->alg_observe(path_x, cc_state, cc_param);
        return;
    }
    *cc_state = 0;
    *cc_param = 0;
}

#define picoquic_slipstream_mixed_cc_ID "slipstream_mixed"
#define PICOQUIC_CC_ALGO_NUMBER_SLIPSTREAM_MIXED 11

picoquic_congestion_algorithm_t slipstream_mixed_cc_algorithm_struct = {
    picoquic_slipstream_mixed_cc_ID, PICOQUIC_CC_ALGO_NUMBER_SLIPSTREAM_MIXED,
    slipstream_mixed_cc_init,
    slipstream_mixed_cc_notify,
    slipstream_mixed_cc_delete,
    slipstream_mixed_cc_observe
};

picoquic_congestion_algorithm_t* slipstream_mixed_cc_algorithm = &slipstream_mixed_cc_algorithm_struct;

void slipstream_set_cc_override(const char* alg_name)
{
    if (alg_name == NULL) {
        slipstream_cc_override = NULL;
        return;
    }
    picoquic_congestion_algorithm_t const* alg = picoquic_get_congestion_algorithm(alg_name);
    slipstream_cc_override = alg;
}

void slipstream_set_default_path_mode(int mode)
{
    slipstream_default_path_mode = slipstream_normalize_mode(mode);
}

void slipstream_set_path_mode(picoquic_cnx_t* cnx, int path_id, int mode)
{
    if (cnx == NULL || path_id < 0 || path_id >= cnx->nb_paths) {
        return;
    }
    picoquic_path_t* path_x = cnx->path[path_id];
    path_x->slipstream_path_mode = (uint8_t)slipstream_normalize_mode(mode);
}

void slipstream_set_path_ack_delay(picoquic_cnx_t* cnx, int path_id, int disable)
{
    if (cnx == NULL || path_id < 0 || path_id >= cnx->nb_paths) {
        return;
    }
    cnx->path[path_id]->slipstream_no_ack_delay = (disable != 0) ? 1 : 0;
}
