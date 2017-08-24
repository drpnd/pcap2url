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
