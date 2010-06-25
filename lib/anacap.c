/*_
 * Copyright 2010 Scyphus Solutions Co. Ltd.  All rights reserved.
 *
 * Authors:
 *      Hirochika Asai  <asai@scyphus.co.jp>
 */

/* $Id: anacap.c,v 1a6039a88c34 2010/06/25 07:46:23 Hirochika $ */

#include "anacap.h"
#include "anacap_private.h"

#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <sys/time.h>

#include <assert.h>

static int _proc_pcap_header(anacap_t *);


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
        gzclose(acap->gz.fp);
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
    /* packet */
    anacap_packet_t p;
    /* definitions of packet headers */
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint32_t incl_len;
    uint32_t orig_len;
    unsigned char hbuf[16];
    unsigned char mbuf[_MAX_PACKET_SIZE];

    assert( NULL != acap );

    /* FIXME: currently do not handle "cnt"  */

    if ( _TYPE_GZ != acap->_type ) {
        /* FIXME */
        return -1;
    }

    while ( 16 == gzread(acap->gz.fp, hbuf, sizeof(hbuf)) ) {
        /* handle each packet */
        ts_sec = *(uint32_t *)hbuf;
        ts_usec = *(uint32_t *)(hbuf+4);
        incl_len = *(uint32_t *)(hbuf+8);
        orig_len = *(uint32_t *)(hbuf+12);

        /* initialize */
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
            }
        } else if ( 105 == acap->gheader.network ) {
            /* 802.11 */
            return -1;
        }
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
