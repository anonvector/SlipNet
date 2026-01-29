#include <string.h>
#include <picoquic_internal.h>
#include <tls_api.h>

static int slipstream_cid_equal(const picoquic_connection_id_t* a,
                                const picoquic_connection_id_t* b) {
    if (a->id_len != b->id_len) {
        return 0;
    }
    if (a->id_len == 0) {
        return 1;
    }
    return memcmp(a->id, b->id, a->id_len) == 0;
}

static int slipstream_parse_packet_header(picoquic_quic_t* quic,
                                          const uint8_t* packet,
                                          size_t packet_len,
                                          picoquic_packet_header* ph) {
    picoquic_cnx_t* cnx = NULL;
    struct sockaddr_storage dummy_addr;
    memset(&dummy_addr, 0, sizeof(dummy_addr));
    return picoquic_parse_packet_header(
               quic, packet, packet_len, (struct sockaddr*)&dummy_addr, ph, &cnx, 1) == 0;
}

static int slipstream_stateless_reset_matches(picoquic_quic_t* quic,
                                              picoquic_stateless_packet_t* sp,
                                              const picoquic_connection_id_t* dest_cid) {
    if (sp->length < PICOQUIC_RESET_SECRET_SIZE) {
        return 0;
    }
    uint8_t reset_secret[PICOQUIC_RESET_SECRET_SIZE];
    picoquic_connection_id_t cid = *dest_cid;
    if (picoquic_create_cnxid_reset_secret(quic, &cid, reset_secret) != 0) {
        return 0;
    }
    return memcmp(sp->bytes + sp->length - PICOQUIC_RESET_SECRET_SIZE,
                  reset_secret,
                  PICOQUIC_RESET_SECRET_SIZE) == 0;
}

int slipstream_take_stateless_packet_for_cid(picoquic_quic_t* quic,
                                             const uint8_t* packet,
                                             size_t packet_len,
                                             uint8_t* out_bytes,
                                             size_t out_capacity,
                                             size_t* out_len) {
    /* NOTE: Long-header matching keys on the queued packet's DCID (client SCID). This is safe
     * for our current client SCID length (8 bytes) but can misroute if SCIDs are short, fixed,
     * or reused (including zero-length). If SCID length/policy changes, consider additional
     * disambiguation (e.g., original DCID tracking). */
    if (out_len == NULL || out_bytes == NULL || packet == NULL || quic == NULL) {
        return -1;
    }
    if (packet_len == 0) {
        return -1;
    }

    picoquic_packet_header ph;
    if (!slipstream_parse_packet_header(quic, packet, packet_len, &ph)) {
        return 0;
    }

    int incoming_is_long = (packet[0] & 0x80) != 0;
    picoquic_stateless_packet_t* prev = NULL;
    picoquic_stateless_packet_t* sp = quic->pending_stateless_packet;
    while (sp != NULL) {
        int matches = 0;
        if (sp->length > 0) {
            int sp_is_long = (sp->bytes[0] & 0x80) != 0;
            if (sp_is_long) {
                if (incoming_is_long) {
                    picoquic_packet_header sp_ph;
                    if (slipstream_parse_packet_header(quic, sp->bytes, sp->length, &sp_ph) &&
                        slipstream_cid_equal(&sp_ph.dest_cnx_id, &ph.srce_cnx_id)) {
                        matches = 1;
                    }
                }
            } else {
                if (!incoming_is_long) {
                    picoquic_packet_header sp_ph;
                    if (slipstream_parse_packet_header(quic, sp->bytes, sp->length, &sp_ph) &&
                        slipstream_cid_equal(&sp_ph.dest_cnx_id, &ph.dest_cnx_id)) {
                        matches = 1;
                    }
                    if (!matches &&
                        slipstream_stateless_reset_matches(quic, sp, &ph.dest_cnx_id)) {
                        matches = 1;
                    }
                }
            }
        }

        if (matches) {
            if (sp->length > out_capacity) {
                return -1;
            }
            memcpy(out_bytes, sp->bytes, sp->length);
            *out_len = sp->length;
            if (prev == NULL) {
                quic->pending_stateless_packet = sp->next_packet;
            } else {
                prev->next_packet = sp->next_packet;
            }
            picoquic_delete_stateless_packet(sp);
            return 1;
        }
        prev = sp;
        sp = sp->next_packet;
    }

    return 0;
}
