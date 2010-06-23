/*_
 * Copyright 2010 Scyphus Solutions Co.,Ltd.  All rights reserved.
 *
 * Authors:
 *      Hirochika Asai  <asai@scyphus.co.jp>
 */

/* $Id: l3.c,v 79df6e8e7b5d 2010/06/23 14:52:39 Hirochika $ */

#include "anacap.h"
#include "anacap_private.h"

int
proc_l3_ipv4(struct pcap_gheader *pgh, anacap_packet_t *p, uint8_t *mbuf,
             size_t len)
{
    return 0;
}

int
proc_l3_ipv6(struct pcap_gheader *pgh, anacap_packet_t *p, uint8_t *mbuf,
             size_t len)
{
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
