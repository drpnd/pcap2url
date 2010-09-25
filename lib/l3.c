/*_
 * Copyright 2010 Scyphus Solutions Co. Ltd.  All rights reserved.
 *
 * Authors:
 *      Hirochika Asai  <asai@scyphus.co.jp>
 */

/* $Id: l3.c,v 063444a01fa1 2010/09/25 15:42:48 Hirochika $ */

#include "anacap.h"
#include "anacap_private.h"

/* For NetBSD */
#include <arpa/inet.h>
#include <netinet/in_systm.h>
/* ip */
#include <netinet/ip.h>
/* ip6 */
#include <netinet/ip6.h>

/*
 * Process IPv4 datagram
 */
int
proc_l3_ipv4(anacap_t *acap, anacap_packet_t *p, uint8_t *mbuf, size_t len)
{
    int i;
    int offset;
    uint32_t src;
    uint32_t dst;
    struct ip *iph;

    /* Check captured length */
    if ( len < sizeof(struct ip) ) {
        return -1;
    }

    /* Set L3 type */
    p->l3_type = L3_IP4;

    /* Get IPv4 header */
    iph = (struct ip *)mbuf;
    offset = sizeof(struct ip);

    /* Get IPv4 addresses */
    src = ntohl(iph->ip_src.s_addr);
    dst = ntohl(iph->ip_dst.s_addr);
    for ( i = 0; i < 4; i++ ) {
        p->l3.ip4.src[i] = 0xff&(src>>(8*(3-i)));
        p->l3.ip4.dst[i] = 0xff&(dst>>(8*(3-i)));
    }

    /* Get protocol number */
    p->l3.ip4.proto = iph->ip_p;

    if ( 6 == p->l3.ip4.proto ) {
        /* TCP */
        return proc_l4_tcp(acap, p, mbuf+offset, len-offset);
    } else if ( 17 == p->l3.ip4.proto ) {
        /* UDP */
        return proc_l4_udp(acap, p, mbuf+offset, len-offset);
    }

    return 0;
}

/*
 * Process IPv6 datagram
 */
int
proc_l3_ipv6(anacap_t *acap, anacap_packet_t *p, uint8_t *mbuf, size_t len)
{
    int i;
    int offset;
    struct ip6_hdr *iph;

    /* Check captured length */
    if ( len < sizeof(struct ip6_hdr) ) {
        return -1;
    }

    /* Set L3 type */
    p->l3_type = L3_IP6;

    /* Get IPv6 header */
    iph = (struct ip6_hdr *)mbuf;
    offset = sizeof(struct ip6_hdr);

    /* Assertion */
    if ( 16 != sizeof(iph->ip6_src.s6_addr)
         || 16 != sizeof(iph->ip6_dst.s6_addr) ) {
        return -1;
    }

    /* Get IPv6 addresses */
    for ( i = 0; i < 16; i++ ) {
        p->l3.ip6.src[i] = iph->ip6_src.s6_addr[i];
        p->l3.ip6.dst[i] = iph->ip6_dst.s6_addr[i];
    }

    /* Set protocol number */
    p->l3.ip6.proto = iph->ip6_ctlun.ip6_un1.ip6_un1_nxt;

    if ( 6 == p->l3.ip6.proto ) {
        /* TCP */
        return proc_l4_tcp(acap, p, mbuf+offset, len-offset);
    } else if ( 17 == p->l3.ip6.proto ) {
        /* UDP */
        return proc_l4_udp(acap, p, mbuf+offset, len-offset);
    }

    return 0;
}

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: sw=4 ts=4 fdm=marker
 * vim<600: sw=4 ts=4
 */
