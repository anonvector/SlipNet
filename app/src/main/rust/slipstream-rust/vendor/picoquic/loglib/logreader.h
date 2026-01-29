/*
* Author: Christian Huitema
* Copyright (c) 2019, Private Octopus, Inc.
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

#ifndef LOGREADER_H
#define LOGREADER_H

#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include "picoquic_internal.h"
#include "bytestream.h"

#ifdef __cplusplus
extern "C" {
#endif

/*! \brief Read the contents of a binary log file and call the callback
 *         function for each event found in the file.
 *
 *  \param f_binlog The file handle of the opened binary log file.
 *  \param cb       The callback function which receives a bytestream of
 *                  the binary event blob.
 *  \param cbptr    A caller provided context pointer that is passed through
 *                  to the callback.
 */
int fileread_binlog(FILE * f_binlog, int (*cb)(bytestream*, void*), void * cbptr);

/*! \brief List of log events to be called back to the application when used with
 *         binlog_convert.
 */
typedef struct binlog_convert_cb_st {

    int (*connection_start)(uint64_t time, const picoquic_connection_id_t * cid, int client_mode,
        uint32_t proposed_version, const picoquic_connection_id_t * remote_cnxid, void * cbptr);
    int(*alpn_update)(uint64_t time, bytestream* s, void* ptr);
    int(*param_update)(uint64_t time, bytestream* s, void* ptr);
    int (*pdu)(uint64_t time, int rxtx, bytestream* s, void * ptr);
    int (*packet_start)(uint64_t time, uint64_t path_id, uint64_t size, const picoquic_packet_header * ph, int rxtx, void * ptr);
    int (*packet_frame)(bytestream * s, void * ptr);
    int (*packet_end)(void * ptr);
    int (*packet_lost)(uint64_t time, uint64_t path_id, bytestream* s, void* ptr);
    int (*packet_dropped)(uint64_t time, uint64_t path_id, bytestream* s, void* ptr);
    int (*packet_buffered)(uint64_t time, uint64_t path_id, bytestream* s, void* ptr);
    int (*cc_update)(uint64_t time, uint64_t path_id, bytestream* s, void* ptr);
    int (*info_message)(uint64_t time, bytestream* s, void* ptr);
    int (*connection_end)(uint64_t time, void * ptr);

    /*! Caller provided context pointer that is passed through to the callbacks */
    void * ptr;

} binlog_convert_cb_t;

/*! \brief Convert the content of a binary log file into a sequence of log
 *         event calls for a specific connection.
 *
 *  \param f_binlog  The file handle of the opened binary log file.
 *  \param cid       Initial connection id for the events to be called back.
 *  \param callbacks Callback functions for the events.
 */
int binlog_convert(FILE * f_binlog, const picoquic_connection_id_t * cid, binlog_convert_cb_t * callbacks);

/*! \brief Write all connection ids contained in a binary log file into a
 *         picohash_table.
 *
 *  \param f_binlog The file handle of the opened binary log file.
 *  \param cids     picohash_table that will collect the connection ids
 *                  found in f_binlog.
 */
int binlog_list_cids(FILE * binlog, picohash_table * cids);

/*! \brief Return the file handle of the output file for log file conversion.
 *
 *  \param cid_name The initial connection id converted to a string. This will
 *                  be used as the standard output file name if out_dir is not
 *                  NULL.
 *  \param binlog_name This is the name of the input file and is used for error
 *                  reporting only.
 *  \param out_dir  If out_dir is not NULL it contains the output directory name.
 *                  Otherwise, if out_dir is NULL the returned file handle is
 *                  standard output.
 *  \param out_ext  out_ext will be used as extenstion for the file name if out_dir
 *                  is not NULL.
 *
 */
FILE * open_outfile(const char * cid_name, const char * binlog_name, const char * out_dir, const char * out_ext);

FILE * picoquic_open_cc_log_file_for_read(char const * bin_cc_log_name, uint16_t * flags, uint64_t * log_time);

int picoquic_cc_log_file_to_csv(char const * bin_cc_log_name, char const * csv_cc_log_name);

#ifdef __cplusplus
}
#endif

#endif /* LOGREADER_H */