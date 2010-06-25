/*_
 * Copyright 2010 Scyphus Solutions Co. Ltd.  All rights reserved.
 *
 * Authors:
 *      Hirochika Asai  <asai@scyphus.co.jp>
 */

/* $Id: l2.c,v 1a6039a88c34 2010/06/25 07:46:23 Hirochika $ */

#include "anacap.h"
#include "anacap_private.h"

#include <stdlib.h>

/*
 * Process L2 ethernet frame
 */
int
proc_l2_ethernet(anacap_t *acap, anacap_packet_t *p, unsigned char *mbuf,
                 size_t len)
{
    int i;

    /* Check the length */
    if ( len < 14 ) {
        return -1;
    }

    /* Set L2 type to ethernet */
    p->l2_type = L2_ETHER;

    /* Parse MAC addresses */
    for ( i = 0; i < 6; i++ ) {
        p->l2.eth.dst[i] = mbuf[i];
        p->l2.eth.src[i] = mbuf[i+6];
    }
    /* Ethernet type */
    p->l2.eth.type = bs2uint16(mbuf + 12, _ENDIAN_NETWORK);

    /* Proceed to upper layers */
    if ( 0x0800 == p->l2.eth.type ) {
        /* IPv4 */
        return proc_l3_ipv4(acap, p, mbuf+14, len-14);
    } else if ( 0x86dd == p->l2.eth.type ) {
        /* IPv6 */
        return proc_l3_ipv6(acap, p, mbuf+14, len-14);
    }

    return 0;
}



#if 0
void
_proc_ethernet_frame(unsigned char *mbuf, size_t psize, size_t orig_len)
{
    int i;
    int offset;
    uint16_t type;
    uint8_t dstaddr[6];
    uint8_t srcaddr[6];

    /* check size */
    if ( psize <= 14 ) {
        /* error */
        return;
    }

    /* reset offset */
    offset = 0;

    /* get mac addresses */
    for ( i = 0; i < 6; i++ ) {
        dstaddr[i] = mbuf[offset+i];
        srcaddr[i] = mbuf[offset+i+6];
    }
    offset += 12;

    /* get the frame type */
    type = bs2uint16(mbuf + offset, _ENDIAN_NETWORK);
    offset += 2;

    /* check ethernet type */
    if ( 0x8100 == type ) {
        /* VLAN */
    } else if ( 0x0806 == type ) {
        /* ARP */
    } else if ( 0x0800 == type ) {
        /* IPv4 */
    } else if ( 0x86dd == type ) {
        /* IPv6 */
    } else if ( type <= 1500 ) {
        /* length in type */
    }
}

void
_proc_802_11_frame(unsigned char *mbuf, size_t psize, size_t orig_len)
{
    int i;
    int offset;
    uint16_t type;
    /* 802.11 header */
    uint8_t dstaddr[6];
    uint8_t srcaddr[6];
    uint8_t bssid[6];
    uint16_t frame_control;
    uint16_t duration;
    int tods;
    int fromds;
    char direction;
    /* ip */
    int frtype;

    /* check size */
    if ( psize <= 32 ) {
        /* error */
        return;
    }

    /* reset offset */
    offset = 0;

    /* get frame control: swapped... */
    frame_control = bs2uint16(mbuf + offset, _ENDIAN_NETWORK);
    offset += 2;

    /* get duration: not swapped */
    duration = (((uint16_t)mbuf[offset+1])<<8) + mbuf[offset];
    offset += 2;

    /* check type */
    type = 0x3&(frame_control>>10);
    if ( type != 0x2 ) {
        /* not data type */
        return -1;
    }
    fromds = 0x1&(frame_control>>1);
    tods = 0x1&frame_control;
    if ( 0 == (fromds ^ tods) ) {
        return -1;
    }

    /* get mac addresses */
    for ( i = 0; i < 6; i++ ) {
        if ( tods ) {
            bssid[i] = mbuf[offset+i];
            srcaddr[i] = mbuf[offset+i+6];
            dstaddr[i] = mbuf[offset+i+12];
        } else if ( fromds ) {
            dstaddr[i] = mbuf[offset+i];
            bssid[i] = mbuf[offset+i+6];
            srcaddr[i] = mbuf[offset+i+12];
        } else {
            /* FIXME */
        }
    }
    offset += 18;

    /* skip SNAP etc. */
    offset += 8;

    /* get type */
    frtype = bytes2uint16(mbuf + offset);
    offset += 2;

    /* check ethernet type */
    if ( 0x8100 == frtype ) {
        /* VLAN */
    } else if ( 0x0806 == frtype ) {
        /* ARP */
    } else if ( 0x0800 == frtype ) {
        /* IPv4 */
    } else if ( 0x86dd == frtype ) {
        /* IPv6 */
    } else if ( type <= 1500 ) {
        /* length in type */
    }
}
#endif

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: sw=4 ts=4 fdm=marker
 * vim<600: sw=4 ts=4
 */
