/*_
 * Copyright 2010 Scyphus Solutions Co.,Ltd.  All rights reserved.
 *
 * Authors:
 *      Hirochika Asai  <asai@scyphus.co.jp>
 */

/* $Id: l4.c,v 79df6e8e7b5d 2010/06/23 14:52:39 Hirochika $ */

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

int
proc_l4_tcp(struct pcap_gheader *pgh, anacap_packet_t *p, uint8_t *mbuf,
            size_t len)
{
    int offset;
    struct tcphdr *tcph;

    if ( len < sizeof(struct tcphdr) ) {
        /* not captured */
        return -1;
    }

    tcph = (struct tcphdr *)mbuf;
    offset = sizeof(struct tcphdr);

    p->l4.tcp.src = ntohs(tcph->th_sport);
    p->l4.tcp.dst = ntohs(tcph->th_dport);

    return 0;
}

int
proc_l4_udp(struct pcap_gheader *pgh, anacap_packet_t *p, uint8_t *mbuf,
            size_t len)
{
    int offset;
    struct udphdr *udph;

    if ( len < sizeof(struct udphdr) ) {
        /* not captured */
        return -1;
    }

    udph = (struct udphdr *)mbuf;
    offset = sizeof(struct udphdr);

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
