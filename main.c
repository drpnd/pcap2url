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

#include "anacap.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
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

int
stricmp(const char *s1, const char *s2, int n)
{
    int i;
    for ( i = 0; i < n; i++ ) {
        if ( tolower(*s1) != tolower(*s2) ) {
            return tolower(*s1) - tolower(*s2);
        }
        if ( '\0' == *s1 ) {
            return 0;
        }
        s1++;
        s2++;
    }

    return 0;
}

/*
 * Parse HTTP header
 */
void
analyze_http_header(anacap_packet_t *p, uint8_t *buf, int len)
{
    double tm;
    int pos;
    int piv;
    char method[32];
    int method_comp;
    char path[1024];
    int path_comp;
    char host[1024];
    int host_comp;
    static int first = 1;

    if ( !first ) {
        printf(",\n");
    }
    first = 0;

    printf("{\n");

    pos = 0;

    /* Method */
    sscanf((char *)buf + pos, "%32[^ ]s", method);
    pos += strlen(method);
    if ( ' ' == buf[pos] ) {
        method_comp = 1;
    } else {
        method_comp = 0;
    }
    pos++;
    /* Path */
    sscanf((char *)buf + pos, "%1024[^ ]s", path);
    pos += strlen(path);
    if ( ' ' == buf[pos] ) {
        path_comp = 1;
    } else {
        path_comp = 0;
    }
    pos++;
    /* Host */
    while ( '\0' != buf[pos] ) {
        if ( '\r' == buf[pos] || '\n' == buf[pos] ) {
            pos++;
            if ( 0 == stricmp((char *)buf + pos, "Host:", 5) ) {
                pos += 5;
                while ( ' ' == buf[pos] ) {
                    pos++;
                }
                break;
            }
        } else {
            pos++;
        }
    }
    host[0] = 0;
    sscanf((char *)buf + pos, "%1024[^\r\n]s", host);
    pos += strlen(host);
    if ( '\r' == buf[pos] || '\n' == buf[pos] ) {
        host_comp = 1;
    } else {
        host_comp = 0;
    }
    pos++;

    if ( host_comp && path_comp ) {
        printf("  url=\"http://%s%s\",\n", host, path);
    }
    printf("  method=\"%s\",\n", method);
    printf("  method_complete=\"%d\",\n", method_comp);
    printf("  path=\"%s\",\n", path);
    printf("  path_complete=\"%d\",\n", path_comp);
    printf("  host=\"%s\",\n", host);
    printf("  host_complete=\"%d\",\n", host_comp);

    if ( L3_IP4 == p->l3_type ) {
        printf("  src_addr=\"%d.%d.%d.%d\",\n",
               p->l3.ip4.src[0], p->l3.ip4.src[1],
               p->l3.ip4.src[2], p->l3.ip4.src[3]);
        printf("  dst_addr=\"%d.%d.%d.%d\",\n",
               p->l3.ip4.dst[0], p->l3.ip4.dst[1],
               p->l3.ip4.dst[2], p->l3.ip4.dst[3]);
    } else if ( L3_IP6 == p->l3_type ) {
        printf("  src_addr=\"%02x%02x:%02x%02x:%02x%02x:%02x%02x"
               ":%02x%02x:%02x%02x:%02x%02x:%02x%02x\",\n",
               p->l3.ip6.src[0], p->l3.ip6.src[1],
               p->l3.ip6.src[2], p->l3.ip6.src[3],
               p->l3.ip6.src[4], p->l3.ip6.src[5],
               p->l3.ip6.src[6], p->l3.ip6.src[7],
               p->l3.ip6.src[8], p->l3.ip6.src[9],
               p->l3.ip6.src[10], p->l3.ip6.src[11],
               p->l3.ip6.src[12], p->l3.ip6.src[13],
               p->l3.ip6.src[14], p->l3.ip6.src[15]);
        printf("  src_addr=\"%02x%02x:%02x%02x:%02x%02x:%02x%02x"
               ":%02x%02x:%02x%02x:%02x%02x:%02x%02x\",\n",
               p->l3.ip6.dst[0], p->l3.ip6.dst[1],
               p->l3.ip6.dst[2], p->l3.ip6.dst[3],
               p->l3.ip6.dst[4], p->l3.ip6.dst[5],
               p->l3.ip6.dst[6], p->l3.ip6.dst[7],
               p->l3.ip6.dst[8], p->l3.ip6.dst[9],
               p->l3.ip6.dst[10], p->l3.ip6.dst[11],
               p->l3.ip6.dst[12], p->l3.ip6.dst[13],
               p->l3.ip6.dst[14], p->l3.ip6.dst[15]);
    }
    printf("  src_port=\"%d\",\n", p->l4.tcp.src_port);
    printf("  dst_port=\"%d\",\n", p->l4.tcp.dst_port);

    tm = p->tv.tv_sec + p->tv.tv_usec/1000000.0;
    printf("  timestamp=\"%lf\"\n", tm);

    printf("}");
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

    /* Skip non-ether frame */
    if ( L2_ETHER != p->l2_type ) {
        return;
    }

    /* Print IPv4 datagrams */
    if ( L3_IP4 == p->l3_type || L3_IP6 == p->l3_type ) {
        if ( L4_TCP == p->l3.ip4.proto ) {
            if ( p->l4.tcp.payload.len > 8 ) {
                if ( 0 == memcmp("GET ", p->l4.tcp.payload.data, 4)
                     || 0 == memcmp("HEAD ", p->l4.tcp.payload.data, 5)
                     || 0 == memcmp("POST ", p->l4.tcp.payload.data, 5)
                     || 0 == memcmp("PUT ", p->l4.tcp.payload.data, 4)
                     || 0 == memcmp("DELETE ", p->l4.tcp.payload.data, 7)
                     || 0 == memcmp("OPTIONS ", p->l4.tcp.payload.data, 8)
                     || 0 == memcmp("CONNECT ", p->l4.tcp.payload.data, 8)
                     || 0 == memcmp("TRACE ", p->l4.tcp.payload.data, 6)
                     || 0 == memcmp("PATCH ", p->l4.tcp.payload.data, 6) ) {
                    analyze_http_header(p, p->l4.tcp.payload.data,
                                        p->l4.tcp.payload.len);
                }
            }
        }
    }
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

    printf("[");
    /* Handle pcap file from the header */
    anacap_loop(acap, -1, analyzer, NULL);
    printf("]");

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
