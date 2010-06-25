/*_
 * Copyright 2010 Scyphus Solutions Co. Ltd.  All rights reserved.
 *
 * Authors:
 *      Hirochika Asai  <asai@scyphus.co.jp>
 */

/* $Id: l4.c,v 1a6039a88c34 2010/06/25 07:46:23 Hirochika $ */

#include "anacap.h"
#include "anacap_private.h"

/* Use BSD format for struct tcphdr */
#ifndef __USE_BSD
#define __USE_BSD
#endif
#ifndef __FAVOR_BSD
#define __FAVOR_BSD
#endif

/* tcp */
#include <netinet/tcp.h>
/* udp */
#include <netinet/udp.h>

/*
 * Process TCP datagram
 */
int
proc_l4_tcp(anacap_t *acap, anacap_packet_t *p, uint8_t *mbuf, size_t len)
{
    int offset;
    struct tcphdr *tcph;

    /* Check the length */
    if ( len < sizeof(struct tcphdr) ) {
        /* not captured */
        return -1;
    }

    /* Get TCP header */
    tcph = (struct tcphdr *)mbuf;
    offset = sizeof(struct tcphdr);

    /* Get port numbers */
    p->l4.tcp.src = ntohs(tcph->th_sport);
    p->l4.tcp.dst = ntohs(tcph->th_dport);

    return 0;
}

/*
 * Process UDP datagram
 */
int
proc_l4_udp(anacap_t *acap, anacap_packet_t *p, uint8_t *mbuf, size_t len)
{
    int offset;
    struct udphdr *udph;

    /* Check the length */
    if ( len < sizeof(struct udphdr) ) {
        /* not captured */
        return -1;
    }

    /* Get UDP header */
    udph = (struct udphdr *)mbuf;
    offset = sizeof(struct udphdr);

    /* Get port numbers */
    p->l4.udp.src = ntohs(udph->uh_sport);
    p->l4.udp.dst = ntohs(udph->uh_dport);

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
