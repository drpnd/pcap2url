/*_
 * Copyright 2010 Scyphus Solutions Co. Ltd.  All rights reserved.
 *
 * Authors:
 *      Hirochika Asai  <asai@scyphus.co.jp>
 */

/* $Id: anacap_private.h,v 1a6039a88c34 2010/06/25 07:46:23 Hirochika $ */

#ifndef _ANACAP_PRIVATE_H
#define _ANACAP_PRIVATE_H

#include <stdint.h>

#define _MAX_PACKET_SIZE 0x1000

enum _endian {
    _ENDIAN_MACHINE,
    _ENDIAN_NETWORK,
};

#ifdef __cplusplus
extern "C" {
#endif

    uint16_t bs2uint16(const unsigned char *, enum _endian);
    uint32_t bs2uint32(const unsigned char *, enum _endian);

    int
    proc_l2_ethernet(anacap_t *, anacap_packet_t *, unsigned char *, size_t);

    int proc_l3_ipv4(anacap_t *, anacap_packet_t *, uint8_t *, size_t);
    int proc_l3_ipv6(anacap_t *, anacap_packet_t *, uint8_t *, size_t);

    int proc_l4_tcp(anacap_t *, anacap_packet_t *, uint8_t *, size_t );
    int proc_l4_udp(anacap_t *, anacap_packet_t *, uint8_t *, size_t );

#ifdef __cplusplus
}
#endif

#endif /* _ANACAP_PRIVATE_H */

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: sw=4 ts=4 fdm=marker
 * vim<600: sw=4 ts=4
 */
