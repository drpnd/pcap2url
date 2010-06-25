/*_
 * Copyright 2010 Scyphus Solutions Co.,Ltd.  All rights reserved.
 *
 * Authors:
 *      Hirochika Asai  <asai@scyphus.co.jp>
 */

/* $Id: bsconv.c,v 1a6039a88c34 2010/06/25 07:46:23 Hirochika $ */

#include "anacap.h"
#include "anacap_private.h"

#include <stdint.h>

/*
 * Convert byte stream to uint16_t
 */
uint16_t
bs2uint16(const unsigned char *bs, enum _endian endian)
{
    int i;
    uint16_t res;

    switch (endian) {
    case _ENDIAN_MACHINE:
        /* machine endian */
        res = *(uint16_t *)bs;
        break;
    case _ENDIAN_NETWORK:
    default:
        /* big endian */
        res = 0;
        for ( i = 0; i < 2; i++ ) {
            res <<= 8;
            res |= (uint16_t)bs[i];
        }
    }

    return res;
}

/*
 * Convert byte stream to uint32_t
 */
uint32_t
bs2uint32(const unsigned char *bs, enum _endian endian)
{
    int i;
    uint32_t res;

    switch (endian) {
    case _ENDIAN_MACHINE:
        /* machine endian */
        res = *(uint32_t *)bs;
        break;
    case _ENDIAN_NETWORK:
    default:
        /* big endian */
        res = 0;
        for ( i = 0; i < 4; i++ ) {
            res <<= 8;
            res |= (uint32_t)bs[i];
        }
    }

    return res;
}

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: sw=4 ts=4 fdm=marker
 * vim<600: sw=4 ts=4
 */
