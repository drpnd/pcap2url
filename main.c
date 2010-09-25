/*_
 * Copyright 2010 Scyphus Solutions Co. Ltd.  All rights reserved.
 *
 * Authors:
 *      Hirochika Asai  <asai@scyphus.co.jp>
 */

/* $Id: main.c,v 063444a01fa1 2010/09/25 15:42:48 Hirochika $ */

#include "anacap.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>
#include <arpa/inet.h>          /* inet_aton */

#define GZ_MODE "rb"
#define GZW_MODE "wb6f"

const char *target_host = NULL;

/*
 * Prototype declaration
 */
int maccmp(uint8_t *mac1, uint8_t *mac2);

/*
 * Compare MAC addresses
 */
int
maccmp(uint8_t *mac1, uint8_t *mac2)
{
    int i;

    for ( i = 0; i < 6; i++ ) {
        if ( mac1[i] != mac2[i] ) {
            return (int)mac1[6] - (int)mac2[6];
        }
    }

    return 0;
}

/*
 * Analyzer
 */
void
analyze(anacap_packet_t *p)
{
    double tm;
    char addrbuf[16];
    int flag;
    uint8_t ggw_mac[6] = { 0x00, 0x0c, 0x29, 0x9d, 0xd2, 0xb4 };

    /* Skip non-ether frame */
    if ( L2_ETHER != p->l2_type ) {
        return;
    }

    /* Process only ggw traffic */
    if ( maccmp(p->l2.eth.src, ggw_mac) || maccmp(p->l2.eth.dst, ggw_mac) ) {
        return;
    }

    /* Print IPv4 datagrams */
    if ( L3_IP4 == p->l3_type ) {
        if ( L4_TCP == p->l3.ip4.proto ) {
            if ( p->l4.tcp.dst_port == 80 ) {

            }
            printf("%d.%d.%d.%d", p->l3.ip4.src[0], p->l3.ip4.src[1],
                   p->l3.ip4.src[2], p->l3.ip4.src[3]);
        }
    }

#if 0
    struct in_addr target_addr;
    int res;
    if ( NULL != target_host ) {
        res = addr2ascii(AF_INET, target_addr, &target_addr);
        if ( sizeof(target_addr) == res ) {
        }
    }
#endif


#if 0
    tm = p->tv.tv_sec + p->tv.tv_usec/1000000.0;

    /* Print IPv4 datagrams */
    if ( L3_IP4 == p->l3_type ) {
        /* Filter by host */
        if ( NULL != target_host ) {
            flag = 0;
            (void)snprintf(addrbuf, sizeof(addrbuf), "%d.%d.%d.%d",
                           p->l3.ip4.src[0], p->l3.ip4.src[1],
                           p->l3.ip4.src[2], p->l3.ip4.src[3]);
            if ( 0 == strcmp(target_host, addrbuf) ) {
                flag = 1;
            }
            (void)snprintf(addrbuf, sizeof(addrbuf), "%d.%d.%d.%d",
                           p->l3.ip4.dst[0], p->l3.ip4.dst[1],
                           p->l3.ip4.dst[2], p->l3.ip4.dst[3]);
            if ( 0 == strcmp(target_host, addrbuf) ) {
                flag = 1;
            }
            if ( 0 == flag ) {
                return;
            }
        }

        printf("%.6lf %d", tm, p->l3.ip4.proto);
        if ( L4_TCP == p->l3.ip4.proto ) {
            /* For TCP */
            printf(" %d.%d.%d.%d %d", p->l3.ip4.src[0], p->l3.ip4.src[1],
                   p->l3.ip4.src[2], p->l3.ip4.src[3], p->l4.tcp.src_port);
            printf(" %d.%d.%d.%d %d", p->l3.ip4.dst[0], p->l3.ip4.dst[1],
                   p->l3.ip4.dst[2], p->l3.ip4.dst[3], p->l4.tcp.dst_port);
            /* TCP flags */
            printf(" %u", p->l4.tcp.orig_flags);
        } else if ( L4_UDP == p->l3.ip4.proto ) {
            /* For UDP */
            printf(" %d.%d.%d.%d %d", p->l3.ip4.src[0], p->l3.ip4.src[1],
                   p->l3.ip4.src[2], p->l3.ip4.src[3], p->l4.tcp.src_port);
            printf(" %d.%d.%d.%d %d", p->l3.ip4.dst[0], p->l3.ip4.dst[1],
                   p->l3.ip4.dst[2], p->l3.ip4.dst[3], p->l4.tcp.dst_port);
            /* TCP flags */
            printf(" 0");
        } else {
            /* Others than TCP and UDP */
            printf(" %d.%d.%d.%d 0", p->l3.ip4.src[0], p->l3.ip4.src[1],
                   p->l3.ip4.src[2], p->l3.ip4.src[3]);
            printf(" %d.%d.%d.%d 0", p->l3.ip4.dst[0], p->l3.ip4.dst[1],
                   p->l3.ip4.dst[2], p->l3.ip4.dst[3]);
            /* TCP flags */
            printf(" 0");
        }
        printf(" %d", p->len);
        printf("\n");
    } else if ( L3_IP6 == p->l3_type ) {
        /*printf("%.6lf %d v6\n", tm, p->len);*/
    }
#endif
}


/*
 * Main
 */
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
    if ( argc < 2 ) {
        fprintf(stderr, "Usage: %s <filename>\n", argv[0]);
        return EXIT_FAILURE;
    }
    iname = argv[1];
    if ( argc == 3 ) {
        target_host = argv[2];
    }

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
