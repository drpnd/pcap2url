/*_
 * Copyright 2010 Scyphus Solutions Co. Ltd.  All rights reserved.
 *
 * Authors:
 *      Hirochika Asai  <asai@scyphus.co.jp>
 */

/* $Id: anacap.h,v 79df6e8e7b5d 2010/06/23 14:52:39 Hirochika $ */

#ifndef _ANACAP_H
#define _ANACAP_H

#include <stdint.h>
#include <time.h>
#include <sys/time.h>

/*
 * Layer 2 types
 */
typedef enum _l2_type {
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

#ifdef __cplusplus
extern "C" {
#endif

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
