/*_
 * Copyright 2010 Scyphus Solutions Co.,Ltd.  All rights reserved.
 *
 * Authors:
 *      Hirochika Asai  <asai@scyphus.co.jp>
 */

/* $Id: pana_private.h,v 9da8dacb89c3 2010/05/14 15:48:02 Hirochika $ */

#ifndef _PANA_PRIVATE_H
#define _PANA_PRIVATE_H

#include <stdint.h>
#include <sys/types.h>          /* off_t */
#include <sys/time.h>           /* timeval */

enum _pana_type {
    _PANA_TYPE_MMAP,
    _PANA_TYPE_FILE,
};

enum _pana_endian {
    _PANA_ENDIAN_MACHINE,
    _PANA_ENDIAN_NETWORK,
};

struct _pana_mmap {
    int fd;                     /* file descriptor */
    unsigned char *mbuf;        /* memory buffer */
    off_t fsize;                /* filesize */
};
struct _pana_file {

};

typedef struct _pana_packet {
    int a;
    //union{pana_ethernet_t}
} pana_packet_t;

typedef struct _pana {
    enum _pana_type _type;
    union {
        struct _pana_mmap mmap;
        struct _pana_file file;
    } _input;
    struct {
        enum _pana_endian endian; /* endian */
        uint32_t datalink;        /* datalink type */
        off_t pos;                /* current position */
    } _proc;
} pana_t;


#ifdef __cplusplus
extern "C" {
#endif

#ifdef __cplusplus
}
#endif

#endif /* _PANA_PRIVATE_H */

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: sw=4 ts=4 fdm=marker
 * vim<600: sw=4 ts=4
 */
