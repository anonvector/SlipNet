#include "picoquic_internal.h"

void slipstream_request_poll(picoquic_cnx_t *cnx) {
    if (cnx == NULL) {
        return;
    }
    cnx->is_poll_requested = 1;
}

int slipstream_is_flow_blocked(picoquic_cnx_t *cnx) {
    if (cnx == NULL) {
        return 0;
    }
    return (cnx->flow_blocked || cnx->stream_blocked) ? 1 : 0;
}

int slipstream_has_ready_stream(picoquic_cnx_t *cnx) {
    if (cnx == NULL) {
        return 0;
    }
    return picoquic_find_ready_stream(cnx) != NULL ? 1 : 0;
}

void slipstream_disable_ack_delay(picoquic_cnx_t *cnx) {
    if (cnx == NULL) {
        return;
    }
    cnx->no_ack_delay = 1;
}

int slipstream_find_path_id_by_addr(picoquic_cnx_t *cnx, const struct sockaddr* addr_peer) {
    if (cnx == NULL || addr_peer == NULL || addr_peer->sa_family == 0) {
        return -1;
    }

    for (int path_id = 0; path_id < cnx->nb_paths; path_id++) {
        picoquic_path_t* path_x = cnx->path[path_id];
        if (path_x == NULL) {
            continue;
        }
        if (path_x->path_is_demoted || path_x->path_abandon_received || path_x->path_abandon_sent) {
            continue;
        }
        if (picoquic_compare_addr((struct sockaddr*) &path_x->peer_addr, addr_peer) != 0) {
            continue;
        }
        return path_id;
    }

    return -1;
}

int slipstream_get_path_id_from_unique(picoquic_cnx_t *cnx, uint64_t unique_path_id) {
    if (cnx == NULL) {
        return -1;
    }
    int path_id = picoquic_get_path_id_from_unique(cnx, unique_path_id);
    if (path_id < 0 || path_id >= cnx->nb_paths) {
        return -1;
    }
    picoquic_path_t* path_x = cnx->path[path_id];
    if (path_x == NULL) {
        return -1;
    }
    if (path_x->path_is_demoted || path_x->path_abandon_received || path_x->path_abandon_sent) {
        return -1;
    }
    return path_id;
}

uint64_t slipstream_get_max_streams_bidir_remote(picoquic_cnx_t *cnx) {
    if (cnx == NULL || cnx->remote_parameters_received == 0) {
        return 0;
    }
    /* STREAM_RANK_FROM_ID is 1-based and returns stream count, not a zero-based index. */
    return STREAM_RANK_FROM_ID(cnx->max_stream_id_bidir_remote);
}
