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

#ifndef AUTOQLOG_H
#define AUTOQLOG_H
#ifdef __cplusplus
extern "C" {
#endif

#include "picoquic.h"
/* Set the qlog log folder and start generating per connection qlog traces into it.
    * Set to NULL value to stop binary tracing.
    * If the binary folder is not set, binary traces will be generated temporarily in
    * the qlog folder during the connection, and then deleted after the connection
    * is closed and the binary trace has been converted to qlog.
    * This conversion from binary to qlog consumes resource and can affect performance.
    * Applications that are concerned about the performance issues should not use this
    * option, and should instead use binary logs, from which qlogs can be extracted
    * using the picolog_t app.
    */
int picoquic_set_qlog(picoquic_quic_t* quic, char const* qlog_dir);

#ifdef __cplusplus
}
#endif
#endif /* AUTOQLOG_H */
