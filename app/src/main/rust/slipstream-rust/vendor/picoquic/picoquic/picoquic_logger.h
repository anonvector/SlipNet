/*
* Author: Christian Huitema
* Copyright (c) 2018, Private Octopus, Inc.
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

#ifndef PICOQUIC_LOGGER_H
#define PICOQUIC_LOGGER_H
#include <stdio.h>
#include "picoquic.h"
#include "picoquic_unified_log.h"

#ifdef __cplusplus
extern "C" {
#endif
/* Set the text log file and start tracing into it.
 * Set to NULL value to stop text log.
 */
int picoquic_set_textlog(picoquic_quic_t* quic, char const* textlog_file);

/* Close the text log, e.g., when closing the QUIC context */
void picoquic_textlog_close(picoquic_quic_t* quic);

/* Handling of packet logging */

void picoquic_log_prefix_initial_cid64(FILE* F, uint64_t log_cnxid64);

void picoquic_textlog_picotls_ticket(FILE* F, picoquic_connection_id_t cnx_id,
    uint8_t* ticket, uint16_t ticket_length);

const char* picoquic_log_fin_or_event_name(picoquic_call_back_event_t ev);
#ifdef __cplusplus
}
#endif
#endif /* PICOQUIC_LOGGER_H */