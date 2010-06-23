/*_
 * Copyright 2010 Scyphus Solutions Co. Ltd.  All rights reserved.
 *
 * Authors:
 *      Hirochika Asai  <asai@scyphus.co.jp>
 */

/* $Id: anacap_private.h,v 79df6e8e7b5d 2010/06/23 14:52:39 Hirochika $ */

#ifndef _ANACAP_PRIVATE_H
#define _ANACAP_PRIVATE_H

#include <stdint.h>

enum _endian {
    _ENDIAN_MACHINE,
    _ENDIAN_NETWORK,
};

struct pcap_gheader {
    uint32_t magic_number;      /* magic number */
    uint16_t version_major;     /* major version number */
    uint16_t version_minor;     /* minor version number */
    int32_t thiszone;           /* GMT to local correction */
    uint32_t sigfigs;           /* accuracy of timestamps */
    uint32_t snaplen;           /* max length of captured packets, in octets */
    uint32_t network;           /* data link type */
};

#ifdef __cplusplus
extern "C" {
#endif
    uint16_t _bs2uint16(const unsigned char *, enum _endian);
    uint32_t _bs2uint32(const unsigned char *, enum _endian);
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
