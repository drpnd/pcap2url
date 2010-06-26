/*_
 * Copyright 2010 Scyphus Solutions Co. Ltd.  All rights reserved.
 *
 * Authors:
 *      Hirochika Asai  <asai@scyphus.co.jp>
 */

/* $Id: anacap.c,v 6b82e25fd65d 2010/06/26 05:15:24 Hirochika $ */

#include "anacap.h"
#include "anacap_private.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <time.h>
#include <sys/time.h>

#include <assert.h>

static int _proc_pcap_header(anacap_t *);
static int _loop_gz(anacap_t *, int, void (*)(anacap_packet_t *), void *);
static int _loop_mmap(anacap_t *, int, void (*)(anacap_packet_t *), void *);

/*
 * Open a file and initialize anacap pointer
 */
anacap_t *
anacap_gzopen(const char *fname, const char *mode)
{
    anacap_t *acap;
    gzFile fp;

    /* Allocate the instance */
    acap = malloc(sizeof(anacap_t));
    if ( NULL == acap ) {
        /* memory error */
        return NULL;
    }

    /* open the file */
    fp = gzopen(fname, mode);
    if ( NULL == fp ) {
        /* error */
        free(acap);
        return NULL;
    }
    acap->_type = _TYPE_GZ;
    acap->gz.fp = fp;

    /* parse global header */
    if ( 0 != _proc_pcap_header(acap) ) {
        gzclose(fp);
        free(acap);
        return NULL;
    }

    return acap;
}

/*
 * Open a file and initialize anacap pointer
 */
anacap_t *
anacap_mmapopen(const char *fname)
{
    anacap_t *acap;
    int fd;
    unsigned char *mbuf;
    off_t fsize;
    long psize;
    off_t len;

    /* Allocate the instance */
    acap = malloc(sizeof(anacap_t));
    if ( NULL == acap ) {
        /* memory error */
        return NULL;
    }

    /* Open the file */
    fd = open(fname, O_RDONLY);
    if ( -1 == fd ) {
        /* error */
        free(acap);
        return NULL;
    }
    acap->_type = _TYPE_MMAP;
    acap->mmap.fd = fd;

    /* Get file size */
    fsize = lseek(fd, 0, SEEK_END);
    (void)lseek(fd, 0L, SEEK_SET);

    /* Get pagesize */
    psize = sysconf(_SC_PAGESIZE);
    /* Note that getpagesize is the "legacy" function. */

    /* Align the memory size to pagesize */
    len = ((fsize - 1)/psize + 1) * psize;

    /* mmap: note that specify MAP_PRIVATE or MAP_SHARED */
    mbuf = mmap(NULL, len, PROT_READ, MAP_PRIVATE, fd, 0);
    if ( MAP_FAILED == mbuf ) {
        /* error */
        (void)close(fd);
        free(acap);
        return NULL;
    }

    /* parse global header */
    if ( 0 != _proc_pcap_header(acap) ) {
        /* close */
        (void)munmap(mbuf, len);
        (void)close(fd);
        free(acap);
        return NULL;
    }

    /* Set attributes */
    acap->mmap.fd = fd;
    acap->mmap.mbuf = mbuf;
    acap->mmap.ptr = 0;
    acap->mmap.fsize = fsize;
    acap->mmap.psize = psize;
    acap->mmap.len = len;

    return acap;
}


/*
 * Close the file and release anacap pointer
 */
int
anacap_close(anacap_t *acap)
{
    /* NULL check */
    if ( NULL == acap ) {
        return 0;
    }

    /* close the file */
    switch ( acap->_type ) {
    case _TYPE_GZ:
        /* gzip */
        gzclose(acap->gz.fp);
        break;
    case _TYPE_MMAP:
        /* mmap */
        /* close */
        if ( -1 == munmap(acap->mmap.mbuf, acap->mmap.len) ) {
            /* error */
        }
        (void)close(acap->mmap.fd);
        break;
    default:
        ;
    }

    /* Free */
    free(acap);

    return 0;
}

/*
 * process pcap header
 */
static int
_proc_pcap_header(anacap_t *acap)
{
    unsigned char hbuf[24];
    size_t len;

    /* assertion */
    assert( NULL != acap );

    /* load from the file */
    len = 0;
    if ( _TYPE_GZ == acap->_type ) {
        /* gz */
        len = gzread(acap->gz.fp, hbuf, sizeof(hbuf));
    } else {
        /* to be supported */
        return -1;
    }

    if ( len < 24 ) {
        /* Length is too small to parse the header */
        return -1;
    }
    acap->gheader.magic_number = *(uint32_t *)hbuf;
    acap->gheader.version_major = *(uint16_t *)(hbuf+4);
    acap->gheader.version_minor = *(uint16_t *)(hbuf+6);
    acap->gheader.thiszone = *(int32_t *)(hbuf+8);
    acap->gheader.sigfigs = *(uint32_t *)(hbuf+12);
    acap->gheader.snaplen = *(uint32_t *)(hbuf+16);
    acap->gheader.network = *(uint32_t *)(hbuf+20);

    /* check the magic number */
    if ( 0xa1b2c3d4UL != acap->gheader.magic_number ) {
        /* FIXME */
        /*fprintf(stderr, "Magic number mismatch\n");*/
        return -1;
    }

    return 0;
}

/*
 * Loop
 */
int
anacap_loop(anacap_t *acap, int cnt, void (*analyzer)(anacap_packet_t *),
            void *userdata)
{
    assert( NULL != acap );

    if ( _TYPE_GZ == acap->_type ) {
        /* GZFILE */
        return _loop_gz(acap, cnt, analyzer, userdata);
    } else if ( _TYPE_MMAP == acap->_type ) {
        /* MMAP */
        return _loop_mmap(acap, cnt, analyzer, userdata);
    }  else {
        /* not supported */
        return -1;
    }

    return 0;
}

/*
 * Loop for gzfile
 */
static int
_loop_gz(anacap_t *acap, int cnt, void (*analyzer)(anacap_packet_t *),
         void *userdata)
{
    int i;
    /* packet */
    anacap_packet_t p;
    /* definitions of packet headers */
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint32_t incl_len;
    uint32_t orig_len;
    unsigned char hbuf[16];
    unsigned char mbuf[_MAX_PACKET_SIZE];

    /* Assertion */
    assert( NULL != acap );

    for ( i = 0; i != cnt; i++ ) {
        if ( 16 == gzread(acap->gz.fp, hbuf, sizeof(hbuf)) ) {
            /* End of file */
            break;
        }
        /* handle each packet */
        ts_sec = *(uint32_t *)hbuf;
        ts_usec = *(uint32_t *)(hbuf+4);
        incl_len = *(uint32_t *)(hbuf+8);
        orig_len = *(uint32_t *)(hbuf+12);

        /* initialize */
        p.l2_type = L2_NONE;
        p.l3_type = L3_NONE;
        p.l4_type = L4_NONE;

        /* set */
        p.len = orig_len;
        p.tv.tv_sec = ts_sec;
        p.tv.tv_usec = ts_usec;
        p.caplen = incl_len;

        /* read from the file */
        if ( p.caplen != gzread(acap->gz.fp, mbuf, p.caplen) ) {
            return -1;
        }
        p.head = mbuf;

        if ( 1 == acap->gheader.network ) {
            /* Ethernet */
            if ( 0 == proc_l2_ethernet(acap, &p, p.head, p.caplen) ) {
                /* analyze */
                (*analyzer)(&p);
            } else {
                (*analyzer)(&p);
            }
        } else if ( 105 == acap->gheader.network ) {
            /* 802.11 */
            (*analyzer)(&p);
        } else {
            (*analyzer)(&p);
        }
    }

    return 0;
}

/*
 * Loop for gzfile
 */
static int
_loop_mmap(anacap_t *acap, int cnt, void (*analyzer)(anacap_packet_t *),
           void *userdata)
{
    int i;
    /* packet */
    anacap_packet_t p;
    /* definitions of packet headers */
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint32_t incl_len;
    uint32_t orig_len;
    unsigned char *hbuf;
    unsigned char *mbuf;

    /* Assertion */
    assert( NULL != acap );

    for ( i = 0; i != cnt; i++ ) {
        if ( acap->mmap.fsize < acap->mmap.ptr + 16 ) {
            /* End of file */
            break;
        }
        hbuf = acap->mmap.mbuf + acap->mmap.ptr;
        /* handle each packet */
        ts_sec = *(uint32_t *)hbuf;
        ts_usec = *(uint32_t *)(hbuf+4);
        incl_len = *(uint32_t *)(hbuf+8);
        orig_len = *(uint32_t *)(hbuf+12);

        /* initialize */
        p.l2_type = L2_NONE;
        p.l3_type = L3_NONE;
        p.l4_type = L4_NONE;

        /* set */
        p.len = orig_len;
        p.tv.tv_sec = ts_sec;
        p.tv.tv_usec = ts_usec;
        p.caplen = incl_len;

        /* read from the file */
        if ( acap->mmap.fsize < acap->mmap.ptr + 16 + p.caplen ) {
            /* End of file */
            break;
        }
        mbuf = acap->mmap.mbuf + acap->mmap.ptr + 16;
        p.head = mbuf;

        if ( 1 == acap->gheader.network ) {
            /* Ethernet */
            if ( 0 == proc_l2_ethernet(acap, &p, p.head, p.caplen) ) {
                /* analyze */
                (*analyzer)(&p);
            } else {
                (*analyzer)(&p);
            }
        } else if ( 105 == acap->gheader.network ) {
            /* 802.11 */
            (*analyzer)(&p);
        } else {
            (*analyzer)(&p);
        }

        /* proceed the pointer */
        acap->mmap.ptr += 16 + p.caplen;
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
