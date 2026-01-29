#include "picoquic_internal.h"

uint64_t slipstream_test_get_max_data_limit(picoquic_quic_t *quic) {
    if (quic == NULL) {
        return 0;
    }
    return quic->max_data_limit;
}

int slipstream_test_get_defer_stream_data_consumption(picoquic_quic_t *quic) {
    if (quic == NULL) {
        return 0;
    }
    return quic->defer_stream_data_consumption ? 1 : 0;
}
