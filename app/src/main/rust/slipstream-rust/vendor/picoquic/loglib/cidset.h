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
#include <stdio.h>
#include "picoquic_internal.h"
#include "picohash.h"

picohash_table * cidset_create();
picohash_table * cidset_delete(picohash_table * cids);

/*! \brief Insert connection id \a cid into a set of connection ids \a cids if
 *         \a cids doesn't contain \a cid already.
 *  \return 0 if successful, -1 otherwise.
 */
int cidset_insert(picohash_table * cids, const picoquic_connection_id_t * cid);

/*! \brief Return 1 if a given set of connection ids \a cids contains a specific
 *         connection id \cid, return 0 otherwise.
 */
int cidset_has_cid(picohash_table * cids, const picoquic_connection_id_t * cid);

/*! \brief Call the given callback once for every connection id in the given
 *         set of connection ids.
 *
 *  \param cids   Set of connection ids to iterate.
 *  \param cb     Callback to call with each connection id.
 *  \param cbptr  A caller provided context pointer that is passed through
 *                to the callback.
 *
 *  \return 0 if successfully iterated through all items, otherwise return
 *          the return value of the failing callback.
 */
int cidset_iterate(const picohash_table * cids, int(*cb)(const picoquic_connection_id_t *, void *), void * cbptr);

/*! \brief Convert all connection ids as hexadecimal values into strings
 *         and print them into the provided file.
 *
 *  \param f    The file handle of the opened output stream.
 *  \param cids Set of connection ids to print.
 */
void cidset_print(FILE * f, picohash_table * cids);
