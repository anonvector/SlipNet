/*
* Author: Christian Huitema
* Copyright (c) 2017, Private Octopus, Inc.
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

#include "picosocks.h"
#include "picoquic_utils.h"

int picoquic_bind_to_port(SOCKET_TYPE fd, int af, int port)
{
    struct sockaddr_storage sa;
    int addr_length = 0;

    memset(&sa, 0, sizeof(sa));

    if (af == AF_INET) {
        struct sockaddr_in* s4 = (struct sockaddr_in*)&sa;
#ifdef _WINDOWS
        s4->sin_family = (ADDRESS_FAMILY)af;
#else
        s4->sin_family = af;
#endif
        s4->sin_port = htons((unsigned short)port);
        addr_length = sizeof(struct sockaddr_in);
    } else {
        struct sockaddr_in6* s6 = (struct sockaddr_in6*)&sa;

        s6->sin6_family = AF_INET6;
        s6->sin6_port = htons((unsigned short)port);
        addr_length = sizeof(struct sockaddr_in6);
    }

    return bind(fd, (struct sockaddr*)&sa, addr_length);
}

int picoquic_get_local_address(SOCKET_TYPE sd, struct sockaddr_storage * addr)
{
    socklen_t name_len = sizeof(struct sockaddr_storage);
    return getsockname(sd, (struct sockaddr *)addr, &name_len);
}

int picoquic_socket_set_pkt_info(SOCKET_TYPE sd, int af)
{
    int ret;
#ifdef _WINDOWS
    int option_value = 1;
    if (af == AF_INET6) {
        ret = setsockopt(sd, IPPROTO_IPV6, IPV6_PKTINFO, (char*)&option_value, sizeof(int));
    }
    else {
        ret = setsockopt(sd, IPPROTO_IP, IP_PKTINFO, (char*)&option_value, sizeof(int));
    }
#else
    if (af == AF_INET6) {
        int val = 1;
        ret = setsockopt(sd, IPPROTO_IPV6, IPV6_V6ONLY,
            &val, sizeof(val));
        if (ret == 0) {
            val = 1;
            ret = setsockopt(sd, IPPROTO_IPV6, IPV6_RECVPKTINFO, (char*)&val, sizeof(int));
        }
    }
    else {
        int val = 1;
#ifdef IP_PKTINFO
        ret = setsockopt(sd, IPPROTO_IP, IP_PKTINFO, (char*)&val, sizeof(int));
#else
        /* The IP_PKTINFO structure is not defined on BSD */
        ret = setsockopt(sd, IPPROTO_IP, IP_RECVDSTADDR, (char*)&val, sizeof(int));
#endif
    }
#endif

    return ret;
}

int picoquic_socket_set_ecn_options(SOCKET_TYPE sd, int af, int * recv_set, int * send_set)
{
    int ret = -1;
#ifdef _WINDOWS

    if (af == AF_INET6) {
#ifdef IPV6_ECN
        {
            DWORD recvEcn = 1;
            /* Request receiving ECN reports in recvmsg */
            ret = setsockopt(sd, IPPROTO_IPV6, IPV6_ECN, (char *)&recvEcn, sizeof(recvEcn));
            if (ret < 0) {
                DBG_PRINTF("setsockopt IPV6_ECN (0x%x) fails, errno: %d\n", recvEcn, GetLastError());
                ret = -1;
                *recv_set = 0;
            }
            else {
                *recv_set = 1;
                ret = 0;
            }
        }
        * send_set = 0;
#else
        * recv_set = 0;
        * send_set = 0;
#endif
    }
    else {
        /* Using IPv4 options. */
#if defined(IP_ECN)
        {
            DWORD recvEcn =1;

            /* Request receiving ECN reports in recvmsg */
            ret = setsockopt(sd, IPPROTO_IP, IP_ECN, (CHAR*)&recvEcn, sizeof(recvEcn));
            if (ret < 0) {
                DBG_PRINTF("setsockopt IP_ECN (0x%x) fails, errno: %d\n", recvEcn, GetLastError());
                ret = -1;
                *recv_set = 0;
            }
            else {
                *recv_set = 1;
                ret = 0;
            }
        }
#else
        * recv_set = 0;
#endif
        *send_set = 0;
    }
#else
    if (af == AF_INET6) {
#if defined(IPV6_TCLASS)
        {
            unsigned int ecn = PICOQUIC_ECN_ECT_1; /* Setting ECN_ECT_1 in outgoing packets */
            if (setsockopt(sd, IPPROTO_IPV6, IPV6_TCLASS, &ecn, sizeof(ecn)) < 0) {
                DBG_PRINTF("setsockopt IPV6_TCLASS (0x%x) fails, errno: %d\n", ecn, errno);
                *send_set = 0;
            }
            else {
                *send_set = 1;
            }
        }
#else
        DBG_PRINTF("%s", "IPV6_TCLASS is not defined\n");
        *send_set = 0;
#endif
#ifdef IPV6_RECVTCLASS
        {
            unsigned int set = 0x01;

            /* Request receiving TOS reports in recvmsg */
            if (setsockopt(sd, IPPROTO_IPV6, IPV6_RECVTCLASS, &set, sizeof(set)) < 0) {
                DBG_PRINTF("setsockopt IPv6 IPV6_RECVTCLASS (0x%x) fails, errno: %d\n", set, errno);
                ret = -1;
                *recv_set = 0;
            }
            else {
                *recv_set = 1;
                ret = 0;
            }
        }
#else
        DBG_PRINTF("%s", "IPV6_RECVTCLASS is not defined\n");
        *recv_set = 0;
#endif 

    }
    else {
#if defined(IP_TOS)
        {
            unsigned int ecn = PICOQUIC_ECN_ECT_1;
            /* Request setting ECN_ECT_1 in outgoing packets */
            if (setsockopt(sd, IPPROTO_IP, IP_TOS, &ecn, sizeof(ecn)) < 0) {
                DBG_PRINTF("setsockopt IPv4 IP_TOS (0x%x) fails, errno: %d\n", ecn, errno);
                *send_set = 0;
            }
            else {
                *send_set = 1;
            }
        }
#else
        *send_set = 0;
        DBG_PRINTF("%s", "IP_TOS is not defined\n");
#endif

#ifdef IP_RECVTOS
        {
            unsigned int set = 1;

            /* Request receiving TOS reports in recvmsg */
            if (setsockopt(sd, IPPROTO_IP, IP_RECVTOS, &set, sizeof(set)) < 0) {
                DBG_PRINTF("setsockopt IPv4 IP_RECVTOS (0x%x) fails, errno: %d\n", set, errno);
                ret = -1;
                *recv_set = 0;
            }
            else {
                *recv_set = 1;
                ret = 0;
            }
        }
#else
        *recv_set = 0;
        DBG_PRINTF("%s", "IP_RECVTOS is not defined\n");
#endif
    }
#endif

    return ret;
}

int picoquic_socket_set_pmtud_options(SOCKET_TYPE sd, int af)
{
    int ret = 0;
#if defined __linux && defined(IP_MTU_DISCOVER) && defined(IPV6_MTU_DISCOVER) && defined(IP_PMTUDISC_PROBE)
    int val = IP_PMTUDISC_PROBE;
    if (af == AF_INET6) {
        ret = setsockopt(sd, IPPROTO_IPV6, IPV6_MTU_DISCOVER, &val, sizeof(int));
    }
    else {
        ret = setsockopt(sd, IPPROTO_IP, IP_MTU_DISCOVER, &val, sizeof(int));
    }
#else
#ifdef UNREFERENCED_PARAMETER
    UNREFERENCED_PARAMETER(af);
    UNREFERENCED_PARAMETER(sd);
#endif
#endif  /* #if defined __linux && ... */
    return ret;
}

SOCKET_TYPE picoquic_open_client_socket(int af)
{
#ifdef _WINDOWS
    WSADATA wsaData = { 0 };
    (void)WSA_START(MAKEWORD(2, 2), &wsaData);
    SOCKET_TYPE sd = WSASocket(af, SOCK_DGRAM, IPPROTO_UDP, NULL, 0, WSA_FLAG_OVERLAPPED);
#else
    SOCKET_TYPE sd = socket(af, SOCK_DGRAM, IPPROTO_UDP);
#endif

    if (sd != INVALID_SOCKET) {
        int send_set = 0;
        int recv_set = 0;

        if (picoquic_socket_set_pkt_info(sd, af) != 0) {
            DBG_PRINTF("Cannot set PKTINFO option (af=%d)\n", af);
        }
        if (picoquic_socket_set_ecn_options(sd, af, &recv_set, &send_set) != 0) {
            DBG_PRINTF("Cannot set ECN options (af=%d)\n", af);
        }
        if (picoquic_socket_set_pmtud_options(sd, af) != 0) {
            DBG_PRINTF("Cannot set PMTUD options (af=%d)\n", af);
        }
    }
    else {
#ifdef _WINDOWS
        DBG_PRINTF("Cannot open socket(AF=%d), error: %d\n", af, GetLastError());
#else
        DBG_PRINTF("Cannot open socket(AF=%d), error: %d\n", af, errno);
#endif
    }

    return sd;
}

int picoquic_open_server_sockets(picoquic_server_sockets_t* sockets, int port)
{
    int ret = 0;

#ifdef _WINDOWS
    WSADATA wsaData = { 0 };
    if (WSA_START(MAKEWORD(2, 2), &wsaData)) {
        ret = -1;
    }
#endif

    const int sock_af[] = { AF_INET6, AF_INET };

    for (int i = 0; i < PICOQUIC_NB_SERVER_SOCKETS; i++) {
        if (ret == 0) {
            sockets->s_socket[i] = socket(sock_af[i], SOCK_DGRAM, IPPROTO_UDP);
        } else {
            sockets->s_socket[i] = INVALID_SOCKET;
        }

        if (sockets->s_socket[i] == INVALID_SOCKET) {
            ret = -1;
        }
        else {
            int recv_set = 0;
            int send_set = 0;
            if (picoquic_socket_set_ecn_options(sockets->s_socket[i], sock_af[i], &recv_set, &send_set) != 0) {
                DBG_PRINTF("Cannot set ECN options (af=%d)\n", sock_af[i]);
            }
            ret = picoquic_socket_set_pkt_info(sockets->s_socket[i], sock_af[i]);
            if (ret == 0) {
                ret = picoquic_bind_to_port(sockets->s_socket[i], sock_af[i], port);
            }
            if (ret == 0) {
                ret = picoquic_socket_set_pmtud_options(sockets->s_socket[i], sock_af[i]);
            }
        }
    }

    return ret;
}

void picoquic_close_server_sockets(picoquic_server_sockets_t* sockets)
{
    for (int i = 0; i < PICOQUIC_NB_SERVER_SOCKETS; i++) {
        if (sockets->s_socket[i] != INVALID_SOCKET) {
            SOCKET_CLOSE(sockets->s_socket[i]);
            sockets->s_socket[i] = INVALID_SOCKET;
        }
    }
}

void picoquic_socks_cmsg_parse(
    void* vmsg,
    struct sockaddr_storage* addr_dest,
    int* dest_if,
    unsigned char* received_ecn,
    size_t * udp_coalesced_size)
{
    /* Assume that msg has been filled by a call to recvmsg */
#if _WINDOWS
    struct cmsghdr* cmsg;
    WSAMSG* msg = (WSAMSG*)vmsg;

    /* Get the control information */
    for (cmsg = WSA_CMSG_FIRSTHDR(msg); cmsg != NULL; cmsg = WSA_CMSG_NXTHDR(msg, cmsg)) {
        if (cmsg->cmsg_level == IPPROTO_IP) {
            if (cmsg->cmsg_type == IP_PKTINFO) {
                if (addr_dest != NULL) {
                    IN_PKTINFO* pPktInfo = (IN_PKTINFO*)WSA_CMSG_DATA(cmsg);
                    ((struct sockaddr_in*)addr_dest)->sin_family = AF_INET;
                    ((struct sockaddr_in*)addr_dest)->sin_port = 0;
                    ((struct sockaddr_in*)addr_dest)->sin_addr.s_addr = pPktInfo->ipi_addr.s_addr;

                    if (dest_if != NULL) {
                        *dest_if = (int)pPktInfo->ipi_ifindex;
                    }
                }
            }
            else if (cmsg->cmsg_type == IP_TOS
#ifdef IP_ECN
                || cmsg->cmsg_type == IP_ECN
#endif
                ) {
                if (cmsg->cmsg_len > 0) {
                    if (received_ecn != NULL) {
                        *received_ecn = *((unsigned char*)WSA_CMSG_DATA(cmsg));
                    }
                }
            }
            else {
                DBG_PRINTF("Cmsg level: %d, type: %d\n", cmsg->cmsg_level, cmsg->cmsg_type);
            }
        }
        else if (cmsg->cmsg_level == IPPROTO_IPV6) {
            if (cmsg->cmsg_type == IPV6_PKTINFO) {
                if (addr_dest != NULL) {
                    IN6_PKTINFO* pPktInfo6 = (IN6_PKTINFO*)WSA_CMSG_DATA(cmsg);
                    ((struct sockaddr_in6*)addr_dest)->sin6_family = AF_INET6;
                    ((struct sockaddr_in6*)addr_dest)->sin6_port = 0;
                    memcpy(&((struct sockaddr_in6*)addr_dest)->sin6_addr, &pPktInfo6->ipi6_addr, sizeof(IN6_ADDR));

                    if (dest_if != NULL) {
                        *dest_if = (int)pPktInfo6->ipi6_ifindex;
                    }
                }
            }
            else if (cmsg->cmsg_type == IPV6_TCLASS
#ifdef IPV6_ECN
                || cmsg->cmsg_type == IPV6_ECN
#endif
                ) {
                if (cmsg->cmsg_len > 0 && received_ecn != NULL) {
                    *received_ecn = *((unsigned char*)WSA_CMSG_DATA(cmsg));
                }
            }
            else {
                DBG_PRINTF("Cmsg level: %d, type: %d\n", cmsg->cmsg_level, cmsg->cmsg_type);
            }
        }
#ifdef UDP_COALESCED_INFO
        if (cmsg->cmsg_level == IPPROTO_UDP &&
            cmsg->cmsg_type == UDP_COALESCED_INFO) {
            if (cmsg->cmsg_len > 0) {
                if (udp_coalesced_size != NULL) {
                    *udp_coalesced_size = *((DWORD*)WSA_CMSG_DATA(cmsg));
                }
            }
            else {
                DBG_PRINTF("Cmsg level: %d, type: %d\n", cmsg->cmsg_level, cmsg->cmsg_type);
            }
        }
#endif
        else {
            DBG_PRINTF("Cmsg level: %d, type: %d\n", cmsg->cmsg_level, cmsg->cmsg_type);
        }
    }
#else
    /* Get the control information */
    struct msghdr* msg = (struct msghdr*)vmsg;
    struct cmsghdr* cmsg;

    for (cmsg = CMSG_FIRSTHDR(msg); cmsg != NULL; cmsg = CMSG_NXTHDR(msg, cmsg)) {
        if (cmsg->cmsg_level == IPPROTO_IP) {
#ifdef IP_PKTINFO
            if (cmsg->cmsg_type == IP_PKTINFO) {
                if (addr_dest != NULL) {
                    struct in_pktinfo* pPktInfo = (struct in_pktinfo*)CMSG_DATA(cmsg);
                    ((struct sockaddr_in*)addr_dest)->sin_family = AF_INET;
                    ((struct sockaddr_in*)addr_dest)->sin_port = 0;
                    ((struct sockaddr_in*)addr_dest)->sin_addr.s_addr = pPktInfo->ipi_addr.s_addr;

                    if (dest_if != NULL) {
                        *dest_if = (int)pPktInfo->ipi_ifindex;
                    }
                }
            }
#else
            /* The IP_PKTINFO structure is not defined on BSD */
            if (cmsg->cmsg_type == IP_RECVDSTADDR) {
                if (addr_dest != NULL) {
                    struct in_addr* pPktInfo = (struct in_addr*)CMSG_DATA(cmsg);
                    ((struct sockaddr_in*)addr_dest)->sin_family = AF_INET;
                    ((struct sockaddr_in*)addr_dest)->sin_port = 0;
                    ((struct sockaddr_in*)addr_dest)->sin_addr.s_addr = pPktInfo->s_addr;

                    if (dest_if != NULL) {
                        *dest_if = 0;
                    }
                }
            }
#endif
            else if ((cmsg->cmsg_type == IP_TOS || cmsg->cmsg_type == IP_RECVTOS) && cmsg->cmsg_len > 0) {
                if (received_ecn != NULL) {
                    *received_ecn = *((unsigned char*)CMSG_DATA(cmsg));
                }
            }
        }
        else if (cmsg->cmsg_level == IPPROTO_IPV6) {
            if (cmsg->cmsg_type == IPV6_PKTINFO) {
                if (addr_dest != NULL) {
                    struct in6_pktinfo* pPktInfo6 = (struct in6_pktinfo*)CMSG_DATA(cmsg);

                    ((struct sockaddr_in6*)addr_dest)->sin6_family = AF_INET6;
                    ((struct sockaddr_in6*)addr_dest)->sin6_port = 0;
                    memcpy(&((struct sockaddr_in6*)addr_dest)->sin6_addr, &pPktInfo6->ipi6_addr, sizeof(struct in6_addr));

                    if (dest_if != NULL) {
                        *dest_if = (int)pPktInfo6->ipi6_ifindex;
                    }
                }
            }
            else if (cmsg->cmsg_type == IPV6_TCLASS) {
                if (cmsg->cmsg_len > 0 && received_ecn != NULL) {
                    *received_ecn = *((unsigned char*)CMSG_DATA(cmsg));
                }
            }
        }
    }
#endif
}

#ifdef _WINDOWS
static void* cmsg_format_header_return_data_ptr(WSAMSG* msg, struct cmsghdr** last_cmsg, int * control_length,
    INT cmsg_level, INT cmsg_type, size_t cmsg_data_len)
{
    void* cmsg_data_ptr = NULL;
    WSACMSGHDR* cmsg = (*last_cmsg == NULL)? WSA_CMSG_FIRSTHDR(msg): WSA_CMSG_NXTHDR(msg, *last_cmsg);

    if (cmsg != NULL) {
        size_t cmsg_required_space = WSA_CMSG_SPACE(cmsg_data_len);
        *control_length += (INT)cmsg_required_space;
        memset(cmsg, 0, cmsg_required_space);
        cmsg->cmsg_level = cmsg_level;
        cmsg->cmsg_type = cmsg_type;
        cmsg->cmsg_len = WSA_CMSG_LEN(cmsg_data_len);
        cmsg_data_ptr = (void*)WSA_CMSG_DATA(cmsg);
        *last_cmsg = cmsg;
    }

    return cmsg_data_ptr;
}
#else
static void* cmsg_format_header_return_data_ptr(struct msghdr* msg, struct cmsghdr** last_cmsg, int* control_length,
    int cmsg_level, int cmsg_type, size_t cmsg_data_len)
{
    void* cmsg_data_ptr = NULL;
#ifdef CMSG_ALIGN
    struct cmsghdr* cmsg = (*last_cmsg == NULL) ? CMSG_FIRSTHDR(msg) :
        (struct cmsghdr*)((unsigned char*)(*last_cmsg) + CMSG_ALIGN((*last_cmsg)->cmsg_len));
#else
    struct cmsghdr* cmsg = (*last_cmsg == NULL) ? CMSG_FIRSTHDR(msg) : CMSG_NXTHDR(msg, *last_cmsg);
#endif

    if (cmsg != NULL) {
        size_t cmsg_required_space = CMSG_SPACE(cmsg_data_len);
        *control_length += (int)cmsg_required_space;
        memset(cmsg, 0, cmsg_required_space);
        cmsg->cmsg_level = cmsg_level;
        cmsg->cmsg_type = cmsg_type;
        cmsg->cmsg_len = CMSG_LEN(cmsg_data_len);
        cmsg_data_ptr = (void*)CMSG_DATA(cmsg);
        *last_cmsg = cmsg;
    }

    return cmsg_data_ptr;
}
#endif

void picoquic_socks_cmsg_format(
    void* vmsg,
    size_t message_length,
    size_t send_msg_size,
    struct sockaddr* addr_from,
    int dest_if)
{
#ifdef _WINDOWS
    WSAMSG* msg = (WSAMSG*)vmsg;
    int control_length = 0;
    struct cmsghdr* last_cmsg = NULL;
    int is_null = 0;
    /* Format the control message */
    if (addr_from != NULL && addr_from->sa_family != 0) {
        if (addr_from->sa_family == AF_INET) {
            struct in_pktinfo* pktinfo = (struct in_pktinfo*)cmsg_format_header_return_data_ptr(msg, &last_cmsg,
                &control_length, IPPROTO_IP, IP_PKTINFO, sizeof(struct in_pktinfo));
            if (pktinfo != NULL) {
                pktinfo->ipi_addr.s_addr = ((struct sockaddr_in*)addr_from)->sin_addr.s_addr;
                pktinfo->ipi_ifindex = (unsigned long)dest_if;
            }
            else {
                is_null = 1;
            }
            if (!is_null && message_length > PICOQUIC_INITIAL_MTU_IPV4) {
                int* pval = (int*)cmsg_format_header_return_data_ptr(msg, &last_cmsg,
                    &control_length, IPPROTO_IP, IP_DONTFRAGMENT, sizeof(int));
                if (pval != NULL) {
                    *pval = 1;
                }
                else {
                    is_null = 1;
                }
            }
#ifdef IP_ECN
            if (!is_null) {
                /* Request setting ECN_ECT_1 in outgoing packets */
                DWORD* p_ecn = (DWORD*)cmsg_format_header_return_data_ptr(msg, &last_cmsg,
                    &control_length, IPPROTO_IP, IP_ECN, sizeof(DWORD));
                if (p_ecn != NULL) {
                    *p_ecn = PICOQUIC_ECN_ECT_1;
                }
                else {
                    is_null = 1;
                }
            }
#endif
        }
        else {
            struct in6_pktinfo* pktinfo6 = (struct in6_pktinfo*)cmsg_format_header_return_data_ptr(msg, &last_cmsg,
                &control_length, IPPROTO_IPV6, IPV6_PKTINFO, sizeof(struct in6_pktinfo));
            if (pktinfo6 != NULL) {
                memcpy(&pktinfo6->ipi6_addr.u, &((struct sockaddr_in6*)addr_from)->sin6_addr.u, sizeof(IN6_ADDR));
                pktinfo6->ipi6_ifindex = (unsigned long)dest_if;
            }
            else {
                is_null = 1;
            }
            if (!is_null) {
                int* pval = (int*)cmsg_format_header_return_data_ptr(msg, &last_cmsg,
                    &control_length, IPPROTO_IPV6, IPV6_DONTFRAG, sizeof(int));
                if (pval != NULL) {
                    *pval = 1;
                }
                else {
                    is_null = 1;
                }
            }
#ifdef IPV6_ECN
            if (!is_null) {
                /* Request setting ECN_ECT_1 in outgoing packets */
                DWORD* p_ecn = (DWORD*)cmsg_format_header_return_data_ptr(msg, &last_cmsg,
                    &control_length, IPPROTO_IPV6, IPV6_ECN, sizeof(DWORD));
                if (p_ecn != NULL) {
                    *p_ecn = PICOQUIC_ECN_ECT_1;
                }
                else {
                    is_null = 1;
                }
            }
#endif
        }
    }
    if (!is_null && send_msg_size > 0 && send_msg_size < message_length) {
        DWORD* pdw = (DWORD*)cmsg_format_header_return_data_ptr(msg, &last_cmsg,
            &control_length, IPPROTO_UDP, UDP_SEND_MSG_SIZE, sizeof(DWORD));
        if (pdw != NULL) {
            *pdw = (DWORD)send_msg_size;
        }
    }

    msg->Control.len = control_length;
    if (control_length == 0) {
        msg->Control.buf = NULL;
    }

#else
    struct msghdr* msg = (struct msghdr*)vmsg;
    int control_length = 0;
    struct cmsghdr* last_cmsg = NULL;
    int is_null = 0;

    if (addr_from != NULL && addr_from->sa_family != 0) {
        if (addr_from->sa_family == AF_INET) {
#ifdef IP_PKTINFO
            struct in_pktinfo* pktinfo = (struct in_pktinfo*)cmsg_format_header_return_data_ptr(msg, &last_cmsg,
                &control_length, IPPROTO_IP, IP_PKTINFO, sizeof(struct in_pktinfo));
            if (pktinfo != NULL) {
                pktinfo->ipi_spec_dst.s_addr = ((struct sockaddr_in*)addr_from)->sin_addr.s_addr;
                pktinfo->ipi_ifindex = (unsigned long)dest_if;
            }
            else {
                is_null = 1;
            }
#else 
            /* The IP_PKTINFO structure is not defined on BSD */
            struct in_addr* pktinfo = (struct in_addr*)cmsg_format_header_return_data_ptr(msg, &last_cmsg,
                &control_length, IPPROTO_IP, IP_SENDSRCADDR, sizeof(struct in_addr));
            if (pktinfo != NULL) {
                pktinfo->s_addr = ((struct sockaddr_in*)addr_from)->sin_addr.s_addr;
            }
            else {
                is_null = 1;
            }
#endif
#if 0
#ifdef IP_DONTFRAG
            if (!is_null && message_length > PICOQUIC_INITIAL_MTU_IPV4) {
                int* pval = (int*)cmsg_format_header_return_data_ptr(msg, &last_cmsg,
                    &control_length, IPPROTO_IP, IP_DONTFRAG, sizeof(int));
                if (pval != NULL) {
                    *pval = 1;
                }
                else {
                    is_null = 1;
                }
            }
#endif
#endif
        }
        else {
            struct in6_pktinfo* pktinfo6 = (struct in6_pktinfo*)cmsg_format_header_return_data_ptr(msg, &last_cmsg,
                &control_length, IPPROTO_IPV6, IPV6_PKTINFO, sizeof(struct in6_pktinfo));
            if (pktinfo6 != NULL) {
                memcpy(&pktinfo6->ipi6_addr, &((struct sockaddr_in6*)addr_from)->sin6_addr, sizeof(struct in6_addr));
                pktinfo6->ipi6_ifindex = (unsigned long)dest_if;
            }
            else {
                is_null = 1;
            }
#ifdef IPV6_DONTFRAG
            if (!is_null) {
                int* pval = (int*)cmsg_format_header_return_data_ptr(msg, &last_cmsg,
                    &control_length, SOL_IPV6, IPV6_DONTFRAG, sizeof(int));
                if (pval != NULL) {
                    *pval = 1;
                }
                else {
                    is_null = 1;
                }
            }
#endif
        }
    }
#if defined(UDP_SEGMENT)
    if (!is_null && send_msg_size > 0 && send_msg_size < message_length) {
        uint16_t* pval = (uint16_t*)cmsg_format_header_return_data_ptr(msg, &last_cmsg,
            &control_length, SOL_UDP, UDP_SEGMENT, sizeof(uint16_t));
        if (pval != NULL) {
            *pval = (uint16_t)send_msg_size;
        }
        else {
            is_null = 1;
        }
    }
#endif

    msg->msg_controllen = control_length;
    if (control_length == 0) {
        msg->msg_control = NULL;
    }
#endif
}


#ifdef _WINDOWS

void picoquic_delete_async_socket(picoquic_recvmsg_async_ctx_t * ctx)
{
    if (ctx->fd != INVALID_SOCKET) {
        SOCKET_CLOSE(ctx->fd);
        ctx->fd = INVALID_SOCKET;
    }

    if (ctx->overlap.hEvent != WSA_INVALID_EVENT) {
        WSACloseEvent(ctx->overlap.hEvent);
        ctx->overlap.hEvent = WSA_INVALID_EVENT;
    }

    free(ctx);
}

picoquic_recvmsg_async_ctx_t * picoquic_create_async_socket(int af, int recv_coalesced, int send_coalesced)
{
    int ret = 0;
    int last_error = 0;
    picoquic_recvmsg_async_ctx_t * ctx = (picoquic_recvmsg_async_ctx_t *)malloc(sizeof(picoquic_recvmsg_async_ctx_t));

    if (ctx == NULL) {
        DBG_PRINTF("Could not create async socket context, AF = %d!\n", af);
    }
    else {
        memset(ctx, 0, sizeof(picoquic_recvmsg_async_ctx_t));
        ctx->overlap.hEvent = WSA_INVALID_EVENT;

        ctx->fd = picoquic_open_client_socket(af);

        if (ctx->fd == INVALID_SOCKET) {
            last_error = WSAGetLastError();
            DBG_PRINTF("Could not initialize UDP socket, AF = %d, err=%d!\n",
                af, last_error);
            ret = -1;
        }
        else {
            GUID WSARecvMsg_GUID = WSAID_WSARECVMSG;
            DWORD NumberOfBytes;
            int nResult = WSAIoctl(ctx->fd, SIO_GET_EXTENSION_FUNCTION_POINTER,
                &WSARecvMsg_GUID, sizeof(WSARecvMsg_GUID),
                &ctx->WSARecvMsg, sizeof(ctx->WSARecvMsg),
                &NumberOfBytes, NULL, NULL);

            if (nResult == SOCKET_ERROR) {
                last_error = WSAGetLastError();
                DBG_PRINTF("Could not initialize WSARecvMsg on UDP socket %d= %d!\n",
                    (int)ctx->fd, last_error);
                ret = -1;
            }
            else {
                GUID WSASendMsg_GUID = WSAID_WSASENDMSG;
                nResult = WSAIoctl(ctx->fd, SIO_GET_EXTENSION_FUNCTION_POINTER,
                    &WSASendMsg_GUID, sizeof(WSASendMsg_GUID),
                    &ctx->WSASendMsg, sizeof(ctx->WSASendMsg),
                    &NumberOfBytes, NULL, NULL);

                if (nResult == SOCKET_ERROR) {
                    last_error = WSAGetLastError();
                    DBG_PRINTF("Could not initialize WSASendMsg on UDP socket %d= %d!\n",
                        (int)ctx->fd, last_error);
                    ret = -1;
                }
                else {
                    // ctx->overlap.hEvent = WSACreateEvent();
                    ctx->overlap.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
                    if (ctx->overlap.hEvent == WSA_INVALID_EVENT) {
                        last_error = WSAGetLastError();
                        DBG_PRINTF("Could not create WSA event for UDP socket %d= %d!\n",
                            (int)ctx->fd, last_error);
                        ret = -1;
                    }
                }
#ifdef UDP_RECV_MAX_COALESCED_SIZE
                if (ret == 0) {
                    DWORD coalesced_size = 0x10000;
                    ctx->recv_buffer_size = (recv_coalesced)?coalesced_size:PICOQUIC_MAX_PACKET_SIZE;
                    ctx->recv_buffer = (uint8_t*)malloc(ctx->recv_buffer_size);
                    ctx->supports_udp_recv_coalesced = recv_coalesced;
                    ctx->supports_udp_send_coalesced = send_coalesced;
                    if (ctx->recv_buffer == NULL) {
                        DBG_PRINTF("Could not allocate buffer size %zu for socket %d!\n",
                            ctx->recv_buffer_size, (int)ctx->fd);
                        ret = -1;
                    }
                    else if (recv_coalesced)
                    {
                        if ((ret = setsockopt(ctx->fd, IPPROTO_UDP, UDP_RECV_MAX_COALESCED_SIZE, (char*)&coalesced_size,
                            (int)sizeof(coalesced_size))) != 0) {
                            last_error = GetLastError();
                            DBG_PRINTF("Cannot set UDP_RECV_MAX_COALESCED_SIZE %d, returns %d (%d)",
                                coalesced_size, ret, last_error);
                            ret = -1;
                        }
                    }
                }
#else
                if (ret == 0) {
                    ctx->recv_buffer_size = PICOQUIC_MAX_PACKET_SIZE;
                    ctx->recv_buffer = (uint8_t*)malloc(ctx->recv_buffer_size);
                    ctx->supports_udp_recv_coalesced = 0;
                    ctx->supports_udp_send_coalesced = 0;
                    if (ctx->recv_buffer == NULL) {
                        DBG_PRINTF("Could allocate buffer size %zu for socket %d!\n",
                            ctx->recv_buffer_size, (int)ctx->fd);
                        ret = -1;
                    }
                }
#endif
            }
        }

        if (ret != 0) {
            picoquic_delete_async_socket(ctx);
            ctx = NULL;
        }
    }

    return ctx;
}

int picoquic_recvmsg_async_finish(
    picoquic_recvmsg_async_ctx_t * ctx)
{
    DWORD cbTransferred = 0;
    DWORD ret = 0;
    DWORD flags = 0;

    if (ctx == NULL) {
        return -1;
    }

    if (!WSAGetOverlappedResult(ctx->fd, &ctx->overlap, &cbTransferred, FALSE, &flags)) {
        ret = WSAGetLastError();
        if (ret == WSAECONNRESET) {
            ctx->bytes_recv = 0;
            ret = 0;
        }
        else {
            DBG_PRINTF("Could not complete async call (WSARecvMsg) on UDP socket %d = %d!\n",
                (int)ctx->fd, ret);
            ctx->bytes_recv = -1;
        }
    } 
    else {
        ctx->bytes_recv = cbTransferred;
        ctx->from_length = ctx->msg.namelen;

        picoquic_socks_cmsg_parse(&ctx->msg, &ctx->addr_dest, &ctx->dest_if, &ctx->received_ecn, &ctx->udp_coalesced_size);
    }

    return ret;
}

int picoquic_recvmsg_async_start(picoquic_recvmsg_async_ctx_t* ctx)
{
    int last_error;
    int ret = 0;
    DWORD numberOfBytesReceived = 0;
    int should_retry;

    do {
        should_retry = 0;
        ctx->from_length = 0;
        ctx->dest_length = 0;
        ctx->dest_if = 0;
        ctx->received_ecn = 0;
        ctx->bytes_recv = 0;
        ctx->udp_coalesced_size = 0;

        ctx->overlap.Internal = 0;
        ctx->overlap.InternalHigh = 0;
        ctx->overlap.Offset = 0;
        ctx->overlap.OffsetHigh = 0;

        ctx->dataBuf.buf = (char*)ctx->recv_buffer;
        ctx->dataBuf.len = (ULONG)ctx->recv_buffer_size;

        ctx->msg.name = (struct sockaddr*) & ctx->addr_from;
        ctx->msg.namelen = sizeof(ctx->addr_from);
        ctx->msg.lpBuffers = &ctx->dataBuf;
        ctx->msg.dwBufferCount = 1;
        ctx->msg.dwFlags = 0;
        ctx->msg.Control.buf = ctx->cmsg_buffer;
        ctx->msg.Control.len = sizeof(ctx->cmsg_buffer);

        /* Setting the &nbReceived parameter to NULL to force async behavior */
        ret = ctx->WSARecvMsg(ctx->fd, &ctx->msg, &numberOfBytesReceived, &ctx->overlap, NULL);

        if (ret != 0) {
            last_error = WSAGetLastError();
            if (last_error == WSA_IO_PENDING) {
                ret = 0;
            }
            else if (last_error == WSAECONNRESET) {
                /* Ignore the ICMP errors */
                should_retry = 1;
                ret = 0;
            }
            else {
                DBG_PRINTF("Could not start receive async (WSARecvMsg) on UDP socket %d = %d!\n",
                    (int)ctx->fd, last_error);
                ctx->bytes_recv = -1;
            }
        }
        else {
            ctx->nb_immediate_receive++;
        }
    } while (should_retry);

    return ret;
}

#endif

int picoquic_recvmsg(SOCKET_TYPE fd,
    struct sockaddr_storage* addr_from,
    struct sockaddr_storage* addr_dest,
    int* dest_if,
    unsigned char* received_ecn,
    uint8_t* buffer, int buffer_max)
#ifdef _WINDOWS
{
    GUID WSARecvMsg_GUID = WSAID_WSARECVMSG;
    LPFN_WSARECVMSG WSARecvMsg;
    char cmsg_buffer[1024];
    DWORD NumberOfBytes;
    int nResult;
    WSAMSG msg;
    WSABUF dataBuf;
    int recv_ret = 0;
    int bytes_recv;
    int last_error;

    if (dest_if != NULL) {
        *dest_if = 0;
    }

    if (received_ecn != NULL) {
        *received_ecn = 0;
    }

    nResult = WSAIoctl(fd, SIO_GET_EXTENSION_FUNCTION_POINTER,
        &WSARecvMsg_GUID, sizeof WSARecvMsg_GUID,
        &WSARecvMsg, sizeof WSARecvMsg,
        &NumberOfBytes, NULL, NULL);

    if (nResult == SOCKET_ERROR) {
        last_error = WSAGetLastError();
        DBG_PRINTF("Could not initialize WSARecvMsg) on UDP socket %d= %d!\n",
            (int)fd, last_error);
        bytes_recv = -1;
    } else {
        dataBuf.buf = (char*)buffer;
        dataBuf.len = buffer_max;

        msg.name = (struct sockaddr*)addr_from;
        msg.namelen = sizeof(struct sockaddr_storage);
        msg.lpBuffers = &dataBuf;
        msg.dwBufferCount = 1;
        msg.dwFlags = 0;
        msg.Control.buf = cmsg_buffer;
        msg.Control.len = sizeof(cmsg_buffer);

        recv_ret = WSARecvMsg(fd, &msg, &NumberOfBytes, NULL, NULL);

        if (recv_ret != 0) {
            last_error = WSAGetLastError();
            DBG_PRINTF("Could not receive message (WSARecvMsg) on UDP socket %d = %d!\n",
                (int)fd, last_error);
            bytes_recv = -1;
        } else {
            bytes_recv = NumberOfBytes;
            picoquic_socks_cmsg_parse(&msg, addr_dest, dest_if, received_ecn, NULL);
        }
    }

    return bytes_recv;
}
#else
{
    int bytes_recv = 0;
    struct msghdr msg;
    struct iovec dataBuf;
    char cmsg_buffer[1024];

    if (dest_if != NULL) {
        *dest_if = 0;
    }

    dataBuf.iov_base = (char*)buffer;
    dataBuf.iov_len = buffer_max;

    msg.msg_name = (struct sockaddr*)addr_from;
    msg.msg_namelen = sizeof(struct sockaddr_storage);
    msg.msg_iov = &dataBuf;
    msg.msg_iovlen = 1;
    msg.msg_flags = 0;
    msg.msg_control = (void*)cmsg_buffer;
    msg.msg_controllen = sizeof(cmsg_buffer);

    bytes_recv = recvmsg(fd, &msg, 0);

    if (bytes_recv <= 0) {
        addr_from->ss_family = 0;
    } else {
        picoquic_socks_cmsg_parse(&msg, addr_dest, dest_if, received_ecn, NULL);
    }

    return bytes_recv;
}
#endif

int picoquic_sendmsg(SOCKET_TYPE fd,
    struct sockaddr* addr_dest,
    struct sockaddr* addr_from,
    int dest_if,
    const char* bytes, int length,
    int send_msg_size,
    int * sock_err)
#ifdef _WINDOWS
{
    GUID WSASendMsg_GUID = WSAID_WSASENDMSG;
    LPFN_WSASENDMSG WSASendMsg;
    char cmsg_buffer[1024];
    DWORD NumberOfBytes;
    int ret = 0;
    DWORD dwBytesSent = 0;
    WSAMSG msg;
    WSABUF dataBuf;
    int bytes_sent;
    int last_error = 0;

    ret = WSAIoctl(fd, SIO_GET_EXTENSION_FUNCTION_POINTER,
        &WSASendMsg_GUID, sizeof WSASendMsg_GUID,
        &WSASendMsg, sizeof WSASendMsg,
        &NumberOfBytes, NULL, NULL);

    if (ret == SOCKET_ERROR) {
        last_error = WSAGetLastError();
        DBG_PRINTF("Could not initialize WSASendMsg on UDP socket %d= %d!\n",
            (int)fd, last_error);
        bytes_sent = -1;
    }
    else {
        /* Format the control message header */
        memset(&msg, 0, sizeof(msg));
        msg.name = addr_dest;
        msg.namelen = picoquic_addr_length(addr_dest);
        dataBuf.buf = (char*)bytes;
        dataBuf.len = length;
        msg.lpBuffers = &dataBuf;
        msg.dwBufferCount = 1;
        msg.Control.buf = (char*)cmsg_buffer;
        msg.Control.len = sizeof(cmsg_buffer);

        /* Format the control message */
        picoquic_socks_cmsg_format(&msg, length, send_msg_size, addr_from, dest_if);

        /* Send the message */
        ret = WSASendMsg(fd, &msg, 0, &dwBytesSent, NULL, NULL);

        if (ret != 0) {
            bytes_sent = -1;
        } else {
            bytes_sent = (int)dwBytesSent;
        }

        if (bytes_sent <= 0) {
            last_error = WSAGetLastError();

#ifndef DISABLE_DEBUG_PRINTF
            DBG_PRINTF("Could not send packet on UDP socket[AF=%d]= %d!\n",
                addr_dest->sa_family, last_error);
#endif
        }
    }

    if (sock_err != NULL) {
        *sock_err = last_error;
    }


    return bytes_sent;
}
#else
{
    struct msghdr msg;
    struct iovec dataBuf;
    char cmsg_buffer[1024];
    int bytes_sent;

    /* Format the message header */

    // calculate segment count
    if (send_msg_size > 0) {
        const int segment_count = length / send_msg_size;
        if (segment_count > 128) {
            DBG_PRINTF("Segment count %d too large\n", segment_count);
            return -1;
        }
    }

    dataBuf.iov_base = (char*)bytes;
    dataBuf.iov_len = length;

    memset(&msg, 0, sizeof(msg));
    msg.msg_name = addr_dest;
    msg.msg_namelen = picoquic_addr_length(addr_dest);
    msg.msg_iov = &dataBuf;
    msg.msg_iovlen = 1;
    msg.msg_control = (void*)cmsg_buffer;
    msg.msg_controllen = sizeof(cmsg_buffer);

    /* Format the control message */
    picoquic_socks_cmsg_format(&msg, length, send_msg_size, addr_from, dest_if);

    bytes_sent = sendmsg(fd, &msg, 0);


    if (bytes_sent <= 0) {
        int last_error = errno;
#ifndef DISABLE_DEBUG_PRINTF
        DBG_PRINTF("Could not send packet on UDP socket[AF=%d]= %d! %s\n",
            addr_dest->sa_family, last_error, strerror(errno));
#endif
        if (sock_err != NULL) {
            *sock_err = last_error;
        }
    }
    return bytes_sent;
}
#endif

int picoquic_select_ex(SOCKET_TYPE* sockets,
    int nb_sockets,
    struct sockaddr_storage* addr_from,
    struct sockaddr_storage* addr_dest,
    int* dest_if,
    unsigned char * received_ecn,
    uint8_t* buffer, int buffer_max,
    int64_t delta_t,
    int * socket_rank,
    uint64_t* current_time)
{
    fd_set readfds;
    struct timeval tv;
    int ret_select = 0;
    int bytes_recv = 0;
    int sockmax = 0;

    if (received_ecn != NULL) {
        *received_ecn = 0;
    }

    FD_ZERO(&readfds);

    for (int i = 0; i < nb_sockets; i++) {
        if (sockmax < (int)sockets[i]) {
            sockmax = (int)sockets[i];
        }
        FD_SET(sockets[i], &readfds);
    }

    if (delta_t <= 0) {
        tv.tv_sec = 0;
        tv.tv_usec = 0;
    } else {
        if (delta_t > 10000000) {
            tv.tv_sec = (long)10;
            tv.tv_usec = 0;
        } else {
            tv.tv_sec = (long)(delta_t / 1000000);
            tv.tv_usec = (long)(delta_t % 1000000);
        }
    }

    ret_select = select(sockmax + 1, &readfds, NULL, NULL, &tv);

    if (ret_select < 0) {
        bytes_recv = -1;
        DBG_PRINTF("Error: select returns %d\n", ret_select);
    } else if (ret_select > 0) {
        for (int i = 0; i < nb_sockets; i++) {
            if (FD_ISSET(sockets[i], &readfds)) {
                *socket_rank = i;
                bytes_recv = picoquic_recvmsg(sockets[i], addr_from,
                    addr_dest, dest_if, received_ecn,
                    buffer, buffer_max);

                if (bytes_recv <= 0) {
#ifdef _WINDOWS
                    int last_error = WSAGetLastError();

                    if (last_error == WSAECONNRESET || last_error == WSAEMSGSIZE) {
                        bytes_recv = 0;
                        continue;
                    }
#endif
                    DBG_PRINTF("Could not receive packet on UDP socket[%d]= %d!\n",
                        i, (int)sockets[i]);

                    break;
                } else {
                    break;
                }
            }
        }
    }

    *current_time = picoquic_current_time();

    return bytes_recv;
}

int picoquic_select(SOCKET_TYPE* sockets,
    int nb_sockets,
    struct sockaddr_storage* addr_from,
    struct sockaddr_storage* addr_dest,
    int* dest_if,
    unsigned char* received_ecn,
    uint8_t* buffer, int buffer_max,
    int64_t delta_t,
    uint64_t* current_time) {
    int socket_rank;
    return picoquic_select_ex(sockets, nb_sockets, addr_from, addr_dest, dest_if,
        received_ecn, buffer, buffer_max, delta_t, &socket_rank, current_time);
}

int picoquic_send_through_socket(
    SOCKET_TYPE fd,
    struct sockaddr* addr_dest,
    struct sockaddr* addr_from, int from_if,
    const char* bytes, int length, int* sock_err)
{
    int sent = picoquic_sendmsg(fd, addr_dest, addr_from, from_if, bytes, length, 0, sock_err);

    return sent;
}

int picoquic_send_through_server_sockets(
    picoquic_server_sockets_t* sockets,
    struct sockaddr* addr_dest,
    struct sockaddr* addr_from, int from_if,
    const char* bytes, int length, int* sock_err)
{
    /* Both Linux and Windows use separate sockets for V4 and V6 */
    int socket_index = (addr_dest->sa_family == AF_INET) ? 1 : 0;

    return picoquic_send_through_socket(sockets->s_socket[socket_index], addr_dest, addr_from, from_if, bytes, length, sock_err);
}

int picoquic_get_server_address(const char* ip_address_text, int server_port,
    struct sockaddr_storage* server_address, int* is_name)
{
    int ret = 0;
    struct sockaddr_in* ipv4_dest = (struct sockaddr_in*)server_address;
    struct sockaddr_in6* ipv6_dest = (struct sockaddr_in6*)server_address;

    /* get the IP address of the server */
    memset(server_address, 0, sizeof(struct sockaddr_storage));
    *is_name = 0;

    if (inet_pton(AF_INET, ip_address_text, &ipv4_dest->sin_addr) == 1) {
        /* Valid IPv4 address */
        ipv4_dest->sin_family = AF_INET;
        ipv4_dest->sin_port = htons((unsigned short)server_port);
    } else if (inet_pton(AF_INET6, ip_address_text, &ipv6_dest->sin6_addr) == 1) {
        /* Valid IPv6 address */
        ipv6_dest->sin6_family = AF_INET6;
        ipv6_dest->sin6_port = htons((unsigned short)server_port);
    } else {
        /* Server is described by name. Do a lookup for the IP address,
        * and then use the name as SNI parameter */
        struct addrinfo* result = NULL;
        struct addrinfo hints;

        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_DGRAM;
        hints.ai_protocol = IPPROTO_UDP;

        if ((ret = getaddrinfo(ip_address_text, NULL, &hints, &result)) != 0) {
#ifdef _WINDOWS
            int err = GetLastError();
#else
            int err = ret;
#endif
            fprintf(stderr, "Cannot get IP address for %s, err = %d (0x%x)\n", ip_address_text, err, err);
            ret = -1;
        } else {
            *is_name = 1;

            switch (result->ai_family) {
            case AF_INET:
                ipv4_dest->sin_family = AF_INET;
                ipv4_dest->sin_port = htons((unsigned short)server_port);
#ifdef _WINDOWS
                ipv4_dest->sin_addr.S_un.S_addr = ((struct sockaddr_in*)result->ai_addr)->sin_addr.S_un.S_addr;
#else
                ipv4_dest->sin_addr.s_addr = ((struct sockaddr_in*)result->ai_addr)->sin_addr.s_addr;
#endif
                break;
            case AF_INET6:
                ipv6_dest->sin6_family = AF_INET6;
                ipv6_dest->sin6_port = htons((unsigned short)server_port);
                memcpy(&ipv6_dest->sin6_addr,
                    &((struct sockaddr_in6*)result->ai_addr)->sin6_addr,
                    sizeof(ipv6_dest->sin6_addr));
                break;
            default:
                fprintf(stderr, "Error getting IPv6 address for %s, family = %d\n",
                    ip_address_text, result->ai_family);
                ret = -1;
                break;
            }

            freeaddrinfo(result);
        }
    }

    return ret;
}

/* Wireshark needs the session keys in order to decrypt and analyze packets.
 * In Unix and Windows, Wireshark reads these keys from a file. The name
 * of the file is passed in the environment variable SSLKEYLOGFILE,
 * which is accessed through system dependent API.
 * 
 * This is a very dangerous API, so we implement two levels of protection:
 *  * The feature can only be enabled if the build is compiled without
 *    the option "PICOQUIC_WITHOUT_SSLKEYLOG"
 *  * The feature is only enabled if the "SSLKEYLOG" option is
 *    explicitly set.
 */

void picoquic_set_key_log_file_from_env(picoquic_quic_t* quic)
{
#ifdef PICOQUIC_WITHOUT_SSLKEYLOG
#ifdef _WINDOWS
    UNREFERENCED_PARAMETER(quic);
#endif /* WINDOWS*/
#else
    if (picoquic_is_sslkeylog_enabled(quic)) {
        char* keylog_filename = NULL;

#ifdef _WINDOWS
        size_t len;

        if (_dupenv_s(&keylog_filename, &len, "SSLKEYLOGFILE") != 0 ||
            keylog_filename == NULL) {
            return;
        }
#else
        keylog_filename = getenv("SSLKEYLOGFILE");
        if (keylog_filename == NULL) {
            return;
        }
#endif

        picoquic_set_key_log_file(quic, keylog_filename);
    }
#endif /* PICOQUIC_WITHOUT_SSLKEYLOG */
}

/* Some socket errors, but not all, indicate that a destination is
 * unreachable and that the corresponding "path" should be abandoned.
 */

int picoquic_socket_error_implies_unreachable(int sock_err)
{
#ifdef _WINDOWS
    static int unreachable_errors[] = {
        WSAEACCES, WSAEADDRNOTAVAIL, WSAEAFNOSUPPORT, WSAECONNRESET,
        WSAEDESTADDRREQ, WSAEHOSTUNREACH, WSAENETDOWN, WSAENETRESET,
        WSAENETUNREACH, WSAESHUTDOWN, -1 };
#else
    static int unreachable_errors[] = {
        EAFNOSUPPORT, ECONNRESET, EHOSTUNREACH, ENETDOWN, ENETUNREACH, -1 };
#endif
    size_t nb_errors = sizeof(unreachable_errors) / sizeof(int);
    int ret = 0;

    for (size_t i = 0; ret == 0 && i < nb_errors; i++) {
        ret = (sock_err == unreachable_errors[i]);
    }

    return ret;
}
