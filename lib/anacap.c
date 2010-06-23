/*_
 * Copyright 2010 Scyphus Solutions Co. Ltd.  All rights reserved.
 *
 * Authors:
 *      Hirochika Asai  <asai@scyphus.co.jp>
 */

/* $Id: anacap.c,v 79df6e8e7b5d 2010/06/23 14:52:39 Hirochika $ */

#include "anacap.h"
#include "anacap_private.h"

#include <unistd.h>
#include <time.h>
#include <sys/time.h>

static int _proc_pcap_header(struct pcap_gheader *, unsigned char *, off_t);
static int _proc_pcap_body(struct pcap_gheader *, unsigned char *, off_t,
                           void (*)(anacap_packet_t *));

/*
 * handle pcap file from the head
 */
int
anacap_proc_pcap(unsigned char *mbuf, off_t fsize)
{
    struct pcap_gheader pgh;

    if ( 0 != _proc_pcap_header(&pgh, mbuf, fsize) ) {
        return;
    }
}

/*
 * process pcap header
 */
static int
_proc_pcap_header(struct pcap_gheader *pgh, unsigned char *mbuf, off_t fsize)
{
    if ( fsize < 24 ) {
        /* file size is too small */
        return -1;
    }
    pgh->magic_number = *(uint32_t *)mbuf;
    mbuf += 4;

    /* check the magic number */
    if ( 0xa1b2c3d4UL != pgh->magic_number ) {
        /* FIXME */
        //fprintf(stderr, "Magic number mismatch\n");
        return -1;
    }

    pgh->version_major = *(uint16_t *)mbuf;
    mbuf += 2;
    pgh->version_minor = *(uint16_t *)mbuf;
    mbuf += 2;
    pgh->thiszone = *(int32_t *)mbuf;
    mbuf += 4;
    pgh->sigfigs = *(uint32_t *)mbuf;
    mbuf += 4;
    pgh->snaplen = *(uint32_t *)mbuf;
    mbuf += 4;
    pgh->network = *(uint32_t *)mbuf;
    mbuf += 4;

    return 0;
}

/*
 * Process pcap body
 */
static int
_proc_pcap_body(struct pcap_gheader *pgh, unsigned char *mbuf, off_t fsize,
                void (*analyzer)(anacap_packet_t *))
{
    /* packet */
    anacap_packet_t p;
    /* definitions of packet headers */
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint32_t incl_len;
    uint32_t orig_len;
    off_t ptr;

    p.l3_type = L3_NONE;
    p.l4_type = L4_NONE;

    ptr = 0;
    while ( fsize >= (ptr+16) ) {
        /* handle each packet */
        ts_sec = *(uint32_t *)&mbuf[ptr];
        ptr += 4;
        ts_usec = *(uint32_t *)&mbuf[ptr];
        ptr += 4;
        incl_len = *(uint32_t *)&mbuf[ptr];
        ptr += 4;
        orig_len = *(uint32_t *)&mbuf[ptr];
        ptr += 4;

        p.len = orig_len;
        p.tv.tv_sec = ts_sec;
        p.tv.tv_usec = ts_usec;
        p.caplen = incl_len;
        p.head = mbuf+ptr;

        if ( fsize >= (ptr+incl_len) ) {
            if ( 1 == pgh->network ) {
                /* Ethernet */
                //if ( 0 == proc_l2_ethernet(pgh, &p, p.head, p.caplen) ) {
                /* analyze */
                analyzer(&p);
                //}
            } else if ( 105 == pgh->network ) {
                /* 802.11 */
                return -1;
            }
        }
        ptr += incl_len;
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
