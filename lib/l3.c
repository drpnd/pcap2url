/*_
 * Copyright (c) 2010,2017 Hirochika Asai <asai@jar.jp>
 * All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

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
