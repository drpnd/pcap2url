/*_
 * Copyright 2010 Scyphus Solutions Co. Ltd.  All rights reserved.
 *
 * Authors:
 *      Hirochika Asai  <asai@scyphus.co.jp>
 */

/* $Id: main.c,v 1a6039a88c34 2010/06/25 07:46:23 Hirochika $ */

#include "anacap.h"

#include <stdio.h>
#include <stdlib.h>
#include <zlib.h>

#define GZ_MODE "rb"
#define GZW_MODE "wb6f"

unsigned char mac_us[6] = { 0x00, 0x0e, 0x39, 0xe3, 0x34, 0x00 };
unsigned char mac_jp[6] = { 0x00, 0x90, 0x69, 0xec, 0xad, 0x5c };
int g_dir;

#define COMP_MAC_ADDR(mac1, mac2)                               \
    ((mac1)[0] == (mac2)[0] && (mac1)[1] == (mac2)[1]           \
     && (mac1)[2] == (mac2)[2] && (mac1)[3] == (mac2)[3]        \
     && (mac1)[4] == (mac2)[4] && (mac1)[5] == (mac2)[5])

void
analyze(anacap_packet_t *p)
{
    double tm;
    int d;

    tm = p->tv.tv_sec + p->tv.tv_usec/1000000.0;

    if ( COMP_MAC_ADDR(mac_us, p->l2.eth.src)
         && COMP_MAC_ADDR(mac_jp, p->l2.eth.dst) ) {
        /* US --> JP */
        d = -1;
    } else if ( COMP_MAC_ADDR(mac_jp, p->l2.eth.src)
                && COMP_MAC_ADDR(mac_us, p->l2.eth.dst) ) {
        /* JP --> US */
        d = 1;
    } else {
#if 0
        int i;
        printf("%x\t", p->l2.eth.type);
        for ( i = 0; i < 6; i++ ) {
            printf("%02x", p->l2.eth.src[i]);
        }
        printf("->");
        for ( i = 0; i < 6; i++ ) {
            printf("%02x", p->l2.eth.dst[i]);
        }
        printf("\n");
        return;
#endif
    }

    if ( d != g_dir ) {
        return;
    }

    if ( L3_IP4 == p->l3_type ) {
        printf("%.6lf %d", tm, p->l3.ip4.proto);
        printf(" %d.%d.%d.%d %d", p->l3.ip4.src[0], p->l3.ip4.src[1],
               p->l3.ip4.src[2], p->l3.ip4.src[3], p->l4.tcp.src);
        printf(" %d.%d.%d.%d %d", p->l3.ip4.dst[0], p->l3.ip4.dst[1],
               p->l3.ip4.dst[2], p->l3.ip4.dst[3], p->l4.tcp.dst);
        printf(" %d", p->len);
        printf("\n");
    } else if ( L3_IP6 == p->l3_type ) {
        /*printf("%.6lf %d v6\n", tm, p->len);*/
    }
}


int
main(int argc, const char *const argv[], const char *const envp[])
{
    /*
     * Declare local variables
     */
    const char *iname;
    void (*analyzer)(anacap_packet_t *) = analyze;
    anacap_t *acap;

    /* Get filename from arguments */
    if ( argc < 3 ) {
        fprintf(stderr, "Usage: %s <filename>\n", argv[0]);
        return EXIT_FAILURE;
    }
    iname = argv[1];
    g_dir = atoi(argv[2]);

    acap = anacap_gzopen(iname, GZ_MODE);
    if ( NULL == acap ) {
        /* error */
        fprintf(stderr, "Cannot gzopen a file: %s\n", iname);
        return EXIT_FAILURE;
    }

    /* Handle pcap file from the header */
    anacap_loop(acap, -1, analyzer, NULL);

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
