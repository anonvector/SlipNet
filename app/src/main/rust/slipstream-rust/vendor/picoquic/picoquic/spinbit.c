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

#include "picoquic_internal.h"
#include "tls_api.h"

#ifndef UNREFERENCED_PARAMETER
#define UNREFERENCED_PARAMETER(x) (void)(x)
#endif

/*
 * Two procedures defining the spin bit basic variant 
 */
void picoquic_spinbit_basic_incoming(picoquic_cnx_t * cnx, picoquic_path_t * path_x, picoquic_packet_header * ph)
{
    path_x->current_spin = ph->spin ^ cnx->client_mode;
}

uint8_t picoquic_spinbit_basic_outgoing(picoquic_cnx_t * cnx)
{
    uint8_t spin_bit = (uint8_t)((cnx->path[0]->current_spin) << 5);

    return spin_bit;
}

/*
 * Two procedures defining the null spin bit variant
 */

void picoquic_spinbit_null_incoming(picoquic_cnx_t * cnx, picoquic_path_t * path_x, picoquic_packet_header * ph)
{
    UNREFERENCED_PARAMETER(cnx);
    UNREFERENCED_PARAMETER(path_x);
    UNREFERENCED_PARAMETER(ph);
}

uint8_t picoquic_spinbit_null_outgoing(picoquic_cnx_t * cnx)
{
    UNREFERENCED_PARAMETER(cnx);
    return 0;
}

/*
 * Two procedures defining the null spin bit randomized variant
 */

void picoquic_spinbit_random_incoming(picoquic_cnx_t * cnx, picoquic_path_t * path_x, picoquic_packet_header * ph)
{
    UNREFERENCED_PARAMETER(cnx);
    UNREFERENCED_PARAMETER(path_x);
    UNREFERENCED_PARAMETER(ph);
}

uint8_t picoquic_spinbit_random_outgoing(picoquic_cnx_t * cnx)
{
    UNREFERENCED_PARAMETER(cnx);
    return (uint8_t) (picoquic_public_random_64()&0x20);
}

/*
 * Table of spin bit functions
 */
picoquic_spinbit_def_t picoquic_spin_function_table[] = {
    {picoquic_spinbit_basic_incoming, picoquic_spinbit_basic_outgoing},
    {picoquic_spinbit_random_incoming, picoquic_spinbit_random_outgoing},
	{picoquic_spinbit_null_incoming, picoquic_spinbit_null_outgoing}
};
