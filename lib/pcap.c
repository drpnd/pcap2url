/*_
 * Copyright 2010 Scyphus Solutions Co.,Ltd.  All rights reserved.
 *
 * Authors:
 *      Hirochika Asai  <asai@scyphus.co.jp>
 */

/* $Id: pcap.c,v 9da8dacb89c3 2010/05/14 15:48:02 Hirochika $ */

#include <stdlib.h>
#include <stdint.h>
#include <sys/types.h>          /* off_t */
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/time.h>           /* timeval */
#include <assert.h>

#include "pana_private.h"

/*
 * Convert byte stream to uint16_t
 */
uint16_t
_bs2uint16(const unsigned char *bs, enum _pana_endian endian)
{
    int i;
    uint16_t res;

    switch (endian) {
    case _PANA_ENDIAN_MACHINE:
        /* machine endian */
        res = *(uint16_t *)bs;
        break;
    case _PANA_ENDIAN_NETWORK:
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
_bs2uint32(const unsigned char *bs, enum _pana_endian endian)
{
    int i;
    uint32_t res;

    switch (endian) {
    case _PANA_ENDIAN_MACHINE:
        /* machine endian */
        res = *(uint32_t *)bs;
        break;
    case _PANA_ENDIAN_NETWORK:
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
 * Process pcap header
 */
int
_proc_pcap_header(pana_t *pana)
{
    uint32_t magic_number;      /* magic number */
    uint16_t version_major;     /* major version number */
    uint16_t version_minor;     /* minor version number */
    int32_t thiszone;           /* GMT to local correction */
    uint32_t sigfigs;           /* accuracy of timestamps */
    uint32_t snaplen;           /* max length of captured packets, in octets */
    uint32_t network;           /* data link type */

    /* check the argument */
    assert( NULL != pana );

    /* by type */
    if ( _PANA_TYPE_MMAP == pana->_type ) {
        /* check the filesize */
        if ( pana->_input.mmap.fsize < 24 ) {
            /* file size is too small */
            return -1;
        }

        /* check the magic number */
        if ( 0xa1b2c3d4UL == *(uint32_t *)pana->_input.mmap.mbuf ) {
            pana->_proc.endian = _PANA_ENDIAN_MACHINE;
        } else {
            /* magic number mismatch */
            return -1;
        }

        /* get magic number */
        magic_number = _bs2uint32(
            pana->_input.mmap.mbuf + pana->_proc.pos, pana->_proc.endian);
        pana->_proc.pos += 4;
        /* get major version */
        version_major = _bs2uint16(
            pana->_input.mmap.mbuf + pana->_proc.pos, pana->_proc.endian);
        pana->_proc.pos += 2;
        /* get minor version */
        version_minor = _bs2uint16(
            pana->_input.mmap.mbuf + pana->_proc.pos, pana->_proc.endian);
        pana->_proc.pos += 2;
        /* get this time zone */
        thiszone = _bs2uint32(
            pana->_input.mmap.mbuf + pana->_proc.pos, pana->_proc.endian);
        pana->_proc.pos += 4;
        /* get the accuracy of timestamps */
        sigfigs = _bs2uint32(
            pana->_input.mmap.mbuf + pana->_proc.pos, pana->_proc.endian);
        pana->_proc.pos += 4;
        /* get snap length */
        snaplen = _bs2uint32(
            pana->_input.mmap.mbuf + pana->_proc.pos, pana->_proc.endian);
        pana->_proc.pos += 4;
        /* get datalink type */
        network = _bs2uint32(
            pana->_input.mmap.mbuf + pana->_proc.pos, pana->_proc.endian);
        pana->_proc.pos += 4;
    } else {
        /* unsupported */
        return -1;
    }

    /* set the datalink type */
    pana->_proc.datalink = network;

    return 0;
}


/*
 * Open the pana structure from a file
 */
pana_t *
pana_open_file(const char *fname, char *errbuf)
{
    /* file descriptor of fname */
    int ifd;
    /* filesize of fname */
    off_t fsize;
    off_t aligned_fsize;
    /* pagesize */
    long psize;
    /* memory buffer */
    unsigned char *mbuf;
    /* pana_t */
    pana_t *pana;

    /* Open the file */
    ifd = open(fname, O_RDONLY);
    if ( -1 == ifd ) {
        /* error */
        return NULL;
    }
    /* Get file size */
    fsize = lseek(ifd, 0, SEEK_END);
    (void)lseek(ifd, 0L, SEEK_SET);

    /* Get pagesize */
    psize = sysconf(_SC_PAGESIZE);
    /* Note that getpagesize is the "legacy" function. */

    /* Align the memory size to pagesize */
    aligned_fsize = ((fsize - 1)/psize + 1) * psize;

    /* mmap: note that specify MAP_PRIVATE or MAP_SHARED */
    mbuf = mmap(NULL, aligned_fsize, PROT_READ, MAP_PRIVATE, ifd, 0);
    if ( MAP_FAILED == mbuf ) {
        /* error */
        return NULL;
    }

    /* Allocate the packet analyzer */
    pana = malloc(sizeof(pana_t));
    if ( NULL == pana ) {
        /* error */
        return NULL;
    }

    /* Assign values */
    pana->_type = _PANA_TYPE_MMAP;
    pana->_input.mmap.fd = ifd;
    pana->_input.mmap.mbuf = mbuf;
    pana->_input.mmap.fsize = fsize;
    pana->_proc.pos = 0;

    /* Analyze the header */
    if ( 0 != _proc_pcap_header(pana) ) {
        /* free the allocated memory */
        (void)pana_close(pana);
        return NULL;
    }

    return pana;
}

/*
 * Loop
 */
int
pana_proc_packet(pana_t *pana)
{
    /* definitions of packet headers */
    struct timeval tv;
    uint32_t incl_len;
    uint32_t orig_len;

    /* NULL ckeck */
    if ( NULL == pana ) {
        return 0;
    }

    /* by type */
    if ( _PANA_TYPE_MMAP == pana->_type ) {
        /* check the size */
        if ( pana->_input.mmap.fsize < pana->_proc.pos + 16 ) {
            /* size error */
            return -1;
        }
        /* get sec */
        tv.tv_sec = _bs2uint32(
            pana->_input.mmap.mbuf + pana->_proc.pos, pana->_proc.endian);
        pana->_proc.pos += 4;
        /* get usec */
        tv.tv_usec = _bs2uint32(
            pana->_input.mmap.mbuf + pana->_proc.pos, pana->_proc.endian);
        pana->_proc.pos += 4;
        /* get incl_len */
        incl_len = _bs2uint32(
            pana->_input.mmap.mbuf + pana->_proc.pos, pana->_proc.endian);
        pana->_proc.pos += 4;
        /* get orig_len */
        orig_len = _bs2uint32(
            pana->_input.mmap.mbuf + pana->_proc.pos, pana->_proc.endian);
        pana->_proc.pos += 4;

        /* check the size again */
        if ( pana->_input.mmap.fsize < pana->_proc.pos + incl_len ) {
            /* The captured packet is too short */
            return -1;
        }

        /* process the packet */
#if 0
        pana_l2_proc(
            pana->_input.mmap.mbuf + pana->_proc.pos, pana->_proc.datalink);
#endif
    } else {
        /* unsupported */
        return -1;
    }

    return 0;
}

/*
 * Close
 */
int
pana_close(pana_t *pana)
{
    /* NULL check */
    if ( NULL == pana ) {
        /* nothing to do */
        return 0;
    }
    /* check the type */
    switch ( pana->_type ) {
    case _PANA_TYPE_MMAP:
        (void)close(pana->_input.mmap.fd);
        break;
    case _PANA_TYPE_FILE:
        break;
    default:
        /* nothing to do */
        ;
    }
    /* free */
    free(pana);

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
