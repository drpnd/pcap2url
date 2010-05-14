/*_
 * Copyright 2010 Scyphus Solutions Co.,Ltd.  All rights reserved.
 *
 * Authors:
 *      Hirochika Asai  <asai@scyphus.co.jp>
 */

/* $Id: l2.c,v 9da8dacb89c3 2010/05/14 15:48:02 Hirochika $ */

void *
pana_l2_proc(unsigned char *mbuf, uint32_t type)
{

    return NULL;
}

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
    type = _bs2uint16(mbuf + offset, _PANA_ENDIAN_NETWORK);
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
    frame_control = _bs2uint16(mbuf + offset, _PANA_ENDIAN_NETWORK);
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

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: sw=4 ts=4 fdm=marker
 * vim<600: sw=4 ts=4
 */
