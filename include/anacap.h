/*_
 * Copyright (c) 2010,2017 Hirochika Asai <asai@jar.jp>
 * All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

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
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t orig_flags;
    struct {
        unsigned int cwr:1;
        unsigned int ece:1;
        unsigned int urg:1;
        unsigned int ack:1;
        unsigned int psh:1;
        unsigned int rst:1;
        unsigned int syn:1;
        unsigned int fin:1;
    } flags;
    struct {
        uint8_t *data;
        uint32_t len;
        /* Must have orig_len;? */
    } payload;
} anacap_l4_tcp_t;

/*
 * L4 UDP
 */
typedef struct _udp {
    uint16_t src_port;
    uint16_t dst_port;
    struct {
        uint8_t *data;
        uint32_t len;
    } payload;
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
