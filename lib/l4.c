/*_
 * Copyright 2010 Scyphus Solutions Co. Ltd.  All rights reserved.
 *
 * Authors:
 *      Hirochika Asai  <asai@scyphus.co.jp>
 */

/* $Id: l4.c,v 063444a01fa1 2010/09/25 15:42:48 Hirochika $ */

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
    p->l4.tcp.src_port = ntohs(tcph->th_sport);
    p->l4.tcp.dst_port = ntohs(tcph->th_dport);

    /* Parse flags */
    p->l4.tcp.orig_flags = tcph->th_flags;
    /* FIN */
    if ( TH_FIN & tcph->th_flags ) {
        p->l4.tcp.flags.fin = 1;
    } else {
        p->l4.tcp.flags.fin = 0;
    }
    /* SYN */
    if ( TH_SYN & tcph->th_flags ) {
        p->l4.tcp.flags.syn = 1;
    } else {
        p->l4.tcp.flags.syn = 0;
    }
    /* RST */
    if ( TH_RST & tcph->th_flags ) {
        p->l4.tcp.flags.rst = 1;
    } else {
        p->l4.tcp.flags.rst = 0;
    }
    /* PUSH */
    if ( TH_PUSH & tcph->th_flags ) {
        p->l4.tcp.flags.psh = 1;
    } else {
        p->l4.tcp.flags.psh = 0;
    }
    /* ACK */
    if ( TH_ACK & tcph->th_flags ) {
        p->l4.tcp.flags.ack = 1;
    } else {
        p->l4.tcp.flags.ack = 0;
    }
    /* URG */
    if ( TH_URG & tcph->th_flags ) {
        p->l4.tcp.flags.urg = 1;
    } else {
        p->l4.tcp.flags.urg = 0;
    }
    /* ECE */
    if ( TH_ECE & tcph->th_flags ) {
        p->l4.tcp.flags.ece = 1;
    } else {
        p->l4.tcp.flags.ece = 0;
    }
    /* CWR */
    if ( TH_CWR & tcph->th_flags ) {
        p->l4.tcp.flags.cwr = 1;
    } else {
        p->l4.tcp.flags.cwr = 0;
    }

    /* Get payload */
    offset = tcph->th_off * 4;
    if ( len <= offset ) {
        /* No payload */
        p->l4.tcp.payload.len = 0;
        p->l4.tcp.payload.data = NULL;
    } else {
        p->l4.tcp.payload.len = len - offset;
        p->l4.tcp.payload.data = mbuf + offset;
    }

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
    p->l4.udp.src_port = ntohs(udph->uh_sport);
    p->l4.udp.dst_port = ntohs(udph->uh_dport);

    /* Get payload */
    offset = 8;
    if ( len <= offset ) {
        /* No payload */
        p->l4.udp.payload.len = 0;
        p->l4.udp.payload.data = NULL;
    } else {
        p->l4.udp.payload.len = len - offset;
        p->l4.udp.payload.data = mbuf + offset;
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
