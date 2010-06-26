/*_
 * Copyright 2010 Scyphus Solutions Co. Ltd.  All rights reserved.
 *
 * Authors:
 *      Hirochika Asai  <asai@scyphus.co.jp>
 */

/* $Id: anacap.h,v 6b82e25fd65d 2010/06/26 05:15:24 Hirochika $ */

#ifndef _ANACAP_H
#define _ANACAP_H

#include <stdio.h>
#include <stdint.h>
#include <time.h>
#include <sys/time.h>
#include <zlib.h>
#include <bzlib.h>

/*
 * anacap type
 */
enum _anacap_type {
    _TYPE_MMAP,
    _TYPE_FILE,
    _TYPE_GZ,
    _TYPE_BZ2,
};

/*
 * Layer 2 types
 */
typedef enum _l2_type {
    L2_NONE,
    L2_ETHER,
    L2_80211,
} anacap_l2_type_t;

/*
 * Layer 3 types
 */
typedef enum _l3_type {
    L3_NONE,
    L3_IP4,
    L3_IP6,
} anacap_l3_type_t;

/*
 * Layer 4 types
 */
typedef enum _l4_type {
    L4_NONE = 0,
    L4_UDP = 17,
    L4_TCP = 6,
} anacap_l4_type_t;

/*
 * L2 ethernet
 */
typedef struct _ethernet {
    uint8_t dst[6];
    uint8_t src[6];
    uint16_t type;
} anacap_l2_ethernet_t;

/*
 * L3 IPv4
 */
typedef struct _ipv4 {
    uint8_t src[4];
    uint8_t dst[4];
    uint16_t proto;
} anacap_l3_ipv4_t;

/*
 * L3 IPv6
 */
typedef struct _ipv6 {
    uint8_t src[16];
    uint8_t dst[16];
    uint16_t proto;
} anacap_l3_ipv6_t;

/*
 * L4 TCP
 */
typedef struct _tcp {
    uint16_t src;
    uint16_t dst;
} anacap_l4_tcp_t;

/*
 * L4 UDP
 */
typedef struct _udp {
    uint16_t src;
    uint16_t dst;
} anacap_l4_udp_t;

/*
 * Packet
 */
typedef struct _packet {
    /* packet length */
    uint32_t len;
    /* captured length */
    uint32_t caplen;
    /* captured time */
    struct timeval tv;
    /* address of packet head */
    uint8_t *head;

    /* L2 */
    enum _l2_type l2_type;
    union {
        struct _ethernet eth;
    } l2;
    /* L3 */
    enum _l3_type l3_type;
    union {
        struct _ipv4 ip4;
        struct _ipv6 ip6;
    } l3;
    /* L4 */
    enum _l4_type l4_type;
    union {
        struct _tcp tcp;
        struct _udp udp;
    } l4;
} anacap_packet_t;

/*
 * Instance
 */
typedef struct _anacap {
    enum _anacap_type _type;
    union {
        FILE *fp;
    } file;
    union {
        gzFile fp;
    } gz;
    union {
        BZFILE *fp;
    } bz;
    union {
        /* file descripter */
        int fd;
        /* buffer */
        unsigned char *mbuf;
        /* current pointer */
        off_t ptr;
        /* file size */
        off_t fsize;
        /* page size */
        long psize;
        /* mapped length */
        off_t len;
    } mmap;
    struct {
        uint32_t magic_number;      /* magic number */
        uint16_t version_major;     /* major version number */
        uint16_t version_minor;     /* minor version number */
        int32_t thiszone;           /* GMT to local correction */
        uint32_t sigfigs;           /* accuracy of timestamps */
        uint32_t snaplen;           /* max length of captured packets */
        uint32_t network;           /* data link type */
    } gheader;
    /* need to free on release? */
    int _need_to_free;
} anacap_t;


#ifdef __cplusplus
extern "C" {
#endif

    anacap_t * anacap_gzopen(const char *, const char *);
    int anacap_close(anacap_t *);

    int anacap_loop(anacap_t *, int, void (*)(anacap_packet_t *), void *);

#ifdef __cplusplus
}
#endif

#endif /* _ANACAP_H */

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: sw=4 ts=4 fdm=marker
 * vim<600: sw=4 ts=4
 */
