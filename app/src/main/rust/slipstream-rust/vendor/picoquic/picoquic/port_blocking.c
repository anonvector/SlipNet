/*
* Author: Christian Huitema
* Copyright (c) 2022, Private Octopus, Inc.
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
* 
* The blocked port list used in this document is copied from the msquic
* implementation by Microsoft and from the list published by Cloudflare.
*/

#include "picoquic_internal.h"
#include "picoquic_unified_log.h"
#include "tls_api.h"
#include <stdlib.h>
#include <string.h>

/* Picoquic servers running over UDP can be both victims and enablers
 * of reflection attacks.
 *
 * Servers may be targeted by DDOS attacks, which often use reflection
 * through an unwitting UDP-based server to hide the actual source of
 * the attack, and often to amplify the volume of the attack. The
 * reflected attacks will appear as coming from the address and port
 * of the server, such as NTP, DNS, other popular services, and also
 * port number 0 in case of fragmented UDP datagrams. The code
 * protect against those by just dropping packets from a list of
 * such ports. This protection is described in this message to the
 * HTTP WG list:
 * https://lists.w3.org/Archives/Public/ietf-http-wg/2021JulSep/0053.html
 * 
 * The blog entry https://blog.cloudflare.com/reflections-on-reflections/
 * provides a list of UDP ports that Cloudflare saw used in
 * reflection attacks:
 * Count  Proto  Src port
 *  3774   udp    123        NTP
 *  1692   udp    1900       SSDP
 *   438   udp    0          IP fragmentation
 *   253   udp    53         DNS
 *    42   udp    27015      SRCDS
 *    20   udp    19         Chargen
 *    19   udp    20800      Call Of Duty
 *    16   udp    161        SNMP
 *    12   udp    389        CLDAP
 *    11   udp    111        Sunrpc
 *    10   udp    137        Netbios
 *     6   tcp    80         HTTP
 *     5   udp    27005      SRCDS
 *     2   udp    520        RIP
 * 
 * Nick Banks at Microsoft pointed to the filtering list implemented
 * in msquic:
 * https://github.com/microsoft/msquic/blob/main/src/core/binding.c#L1399
 * The list contains a different set than the one defined by cloudflare,
 * with the inclusion of services like mDNS, NetBIOS, etc. 
 *       11211,  // memcache
 *       5353,   // mDNS
 *       1900,   // SSDP
 *       500,    // IKE
 *       389,    // CLDAP
 *       161,    // SNMP
 *       138,    // NETBIOS Datagram Service
 *       137,    // NETBIOS Name Service
 *       123,    // NTP
 *       111,    // Portmap
 *       53,     // DNS
 *       19,     // Chargen
 *       17,     // Quote of the Day
 *       0,      // Unusable
 * Services like mDNS or SSDp are typical local, and thus unlikely to be
 * used for DDOS amplification. Attackers would have difficulties reaching
 * these services from outside the local network. However, the attackers
 * could forge the source address and cause the QUIC servers to bounce 
 * packets towards these services. This kind of "request forgery attacks"
 * is discussed in section 21.5 of RFC 9000. Blocking the port numbers
 * of servers targeted by such attacks provides a layer of protection.
 * 
 * There are a couple of downsides to this protection:
 * - Some of the ports listed here are part of the randomly assigned range,
 *   and a unlucky client could end up using one of these ports.
 * - Even if clients do not use a reserved port, NATs might. Not much recourse
 *   there.
 * - New vulnerable protocols are likely to be created in the future, which
 *   means that the list will have to be updated.
 * - If the server sits behind a firewall, the firewall might be a better
 *   place for maintaining a list of blocked ports.
 * 
 * The implementation provides teo mitigations against these downsides:
 * 
 * - Servers can disable the protection if they don't want it.
 * - Clients can test the port number assigned to their sockets and
 *   pick a new one if they find a collision.
 * 
 */

const uint16_t picoquic_blocked_port_list[] = {
        27015,  /* SRCDS */
        20800,  /* Call Of Duty */
        11211,  /* memcache */
        5353,   /* mDNS */
        1900,   /* SSDP */
        520,    /* RIP */
        500,    /* IKE */
        389,    /* CLDAP */
        161,    /* SNMP */
        138,    /* NETBIOS Datagram Service */
        137,    /* NETBIOS Name Service */
        123,    /* NTP */
        111,    /* Portmap -- used by SUN RPC */
        53,     /* DNS */
        19,     /* Chargen */
        17,     /* Quote of the Day */
        7,      /* Echo */
        0,      /* Unusable */
};

const size_t nb_picoquic_blocked_port_list = sizeof(picoquic_blocked_port_list) / sizeof(uint16_t);

int picoquic_check_port_blocked(uint16_t port)
{
    int ret = 0;

    for (size_t i = 0; i < nb_picoquic_blocked_port_list && port <= picoquic_blocked_port_list[i]; i++) {
        if (port == picoquic_blocked_port_list[i]){
            ret = 1;
            break;
        }
    }

    return ret;
}

int picoquic_check_addr_blocked(const struct sockaddr* addr_from)
{
    uint16_t port = UINT16_MAX;

    if (addr_from->sa_family == AF_INET) {
        port = ((struct sockaddr_in*)addr_from)->sin_port;
    }
    else if (addr_from->sa_family == AF_INET6) {
        /* configure an IPv6 sockaddr */
        port = ((struct sockaddr_in6*)addr_from)->sin6_port;
    }
    return picoquic_check_port_blocked(ntohs(port));
}

void picoquic_disable_port_blocking(picoquic_quic_t * quic, int is_port_blocking_disabled)
{
    quic->is_port_blocking_disabled = is_port_blocking_disabled;
}