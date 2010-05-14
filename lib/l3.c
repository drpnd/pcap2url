/*_
 * Copyright 2010 Scyphus Solutions Co.,Ltd.  All rights reserved.
 *
 * Authors:
 *      Hirochika Asai  <asai@scyphus.co.jp>
 */

/* $Id: l3.c,v 9da8dacb89c3 2010/05/14 15:48:02 Hirochika $ */

/*
 * process ipv4 packet
 */
int
proc_ipv4_packet(unsigned char *mbuf, size_t psize, size_t orig_len,
                 struct timeval tv)
{
    int offset;
    struct ip *iph;
    uint32_t ip_src;
    uint32_t ip_dst;
    uint16_t port_src;
    uint16_t port_dst;

    /* check captured length */
    if ( psize < sizeof(struct ip) ) {
        return -1;
    }

    printf(" 4");

    offset = 0;

    /* get IP header */
    iph = (struct ip *)mbuf;
    offset += sizeof(struct ip);

    ip_src = ntohl(iph->ip_src.s_addr);
    ip_dst = ntohl(iph->ip_dst.s_addr);

    printf(" %u", iph->ip_p);
    printf(" %d.%d.%d.%d", ip_src>>24, 0xff&(ip_src>>16),
           0xff&(ip_src>>8), 0xff&ip_src);
    printf(" %d.%d.%d.%d", ip_dst>>24, 0xff&(ip_dst>>16),
           0xff&(ip_dst>>8), 0xff&ip_dst);

    /* initialize port numbers */
    port_src = 0;
    port_dst = 0;


    /*ntohs(tcph->th_win), ntohl(th_seq), ntohl(th_ack), th_flag*/
/*
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#define TH_ECE  0x40
#define TH_CWR  0x80
*/
    /* check protocol: see /etc/protocols */
    if ( 0 == iph->ip_p ) {
        /* IP */
    } else if ( 1 == iph->ip_p ) {
        /* ICMP */
    } else if ( 6 == iph->ip_p ) {
        /* TCP */
        /* check captured length */
        if ( psize < offset+sizeof(struct tcphdr) ) {
            /* not captured */
            return -1;
        }
        struct tcphdr *tcph;
        tcph = (struct tcphdr *)(mbuf+offset);
        offset += sizeof(struct tcphdr);

        /* get port numbers */
        port_src = ntohs(tcph->th_sport);
        port_dst = ntohs(tcph->th_dport);

        /* get tcp options */
        if ( psize < offset + 4*((int)tcph->th_off - 5) ) {
            /* not captured */
            return -1;
        }
        int optoff;
        int optlen;
        int mss;
        int wscale;
        optoff = 0;
        mss = 0;
        wscale = 0;
        while ( optoff < 4*((int)tcph->th_off - 5) ) {
            if ( 2 == mbuf[offset + optoff] ) {
                /* MSS */
                optlen = mbuf[offset + optoff + 1];
                mss = bytes2uint16(mbuf+offset+optoff+2);
                optoff += optlen;
            } else if ( 1 == mbuf[offset + optoff] ) {
                /* NO-OP */
                optoff += 1;
            } else if ( 0 == mbuf[offset + optoff] ) {
                /* end of option */
                optoff += 1;
            } else if ( 3 == mbuf[offset + optoff] ) {
                /* window scale */
                optlen = mbuf[offset + optoff + 1];
                wscale = mbuf[offset + optoff + 2];
                optoff += optlen;
            } else {
                break;
            }
        }
        /* proceed to the data head */
        offset += 4*((int)tcph->th_off - 5);

        /* search session */
        struct tcp4_session *ent;
        struct tcp4_session *csess = NULL;
        STAILQ_FOREACH(ent, &tcp4_head, sessions) {
            /* search */
            if ( ent->ip4_src == ip_src && ent->ip4_dst == ip_dst
                 && ent->sport == port_src && ent->dport == port_dst ) {
                csess = ent;
                break;
            }
        }
        /* check flags */
        if ( TH_SYN == (TH_SYN & tcph->th_flags) ) {
            /* SYN */
            if ( NULL != csess ) {
                STAILQ_REMOVE(&tcp4_head, csess, tcp4_session, sessions);
                free(csess);
                csess = NULL;
            }
            csess = malloc(sizeof(struct tcp4_session));
            if ( NULL == csess ) {
                fprintf(stderr, "ENOMEM\n");
                exit(EXIT_FAILURE);
            }
            csess->ip4_src = ip_src;
            csess->ip4_dst = ip_dst;
            csess->sport = port_src;
            csess->dport = port_dst;
            csess->tv_syn = tv;
            csess->opt.wscale = wscale;
            csess->opt.mss = mss;
            STAILQ_INSERT_TAIL(&tcp4_head, csess, sessions);
        }
        if ( NULL != csess ) {
            csess->tv_last = tv;

            printf(" y %d %d", port_src, port_dst);
            printf(" %u %u %d %u %u", ntohl(tcph->th_seq), ntohl(tcph->th_ack),
                   tcph->th_flags, ntohs(tcph->th_win)<<(csess->opt.wscale),
                   csess->opt.mss);
        } else {
            printf(" n %d %d", port_src, port_dst);
            printf(" %u %u %d %u %u", ntohl(tcph->th_seq), ntohl(tcph->th_ack),
                   tcph->th_flags, 0, 0);
        }
        if ( TH_FIN == (TH_FIN & tcph->th_flags)
             || TH_RST == (TH_RST & tcph->th_flags) ) {
            /* FIN or RST */
            if ( NULL != csess ) {
                STAILQ_REMOVE(&tcp4_head, csess, tcp4_session, sessions);
                free(csess);
                csess = NULL;
            }
        }
    } else if ( 17 == iph->ip_p ) {
        /* UDP */
        /* check captured length */
        if ( psize < offset+sizeof(struct udphdr) ) {
            /* not captured */
            return -1;
        }
        struct udphdr *udph;
        udph = (struct udphdr *)(mbuf+offset);
        offset += sizeof(struct udphdr);

        /* get port numbers */
        port_src = ntohs(udph->uh_sport);
        port_dst = ntohs(udph->uh_dport);
        printf(" %d %d", port_src, port_dst);
    } else if ( 41 == iph->ip_p ) {
        /* IPv6: not to be in this IPv4 packet */
    } else if ( 58 == iph->ip_p ) {
        /* ICMPv6: not to be in this IPv4 packet */
    } else {
        /* see /etc/protocols for greater detail */
    }

    return 0;
}

/*
 * process ipv6 packet
 */
int
proc_ipv6_packet(unsigned char *mbuf, size_t psize, size_t orig_len,
                 struct timeval tv)
{
    int i;
    int offset;
    struct ip6_hdr *iph;
    uint16_t port_src;
    uint16_t port_dst;

    /* check captured length */
    if ( psize < sizeof(struct ip6_hdr) ) {
        return -1;
    }

    printf(" 6");

    offset = 0;

    /* get IP header */
    iph = (struct ip6_hdr *)mbuf;
    offset += sizeof(struct ip6_hdr);

    printf(" %u", iph->ip6_ctlun.ip6_un1.ip6_un1_nxt);

    printf(" ");
    for ( i = 0; i < sizeof(iph->ip6_src.s6_addr); i++ ) {
        printf("%02x", iph->ip6_src.s6_addr[i]);
    }
    printf(" ");
    for ( i = 0; i < sizeof(iph->ip6_dst.s6_addr); i++ ) {
        printf("%02x", iph->ip6_dst.s6_addr[i]);
    }

    if ( 6 == iph->ip6_ctlun.ip6_un1.ip6_un1_nxt ) {
        /* TCP */
        /* check captured length */
        if ( psize < offset+sizeof(struct tcphdr) ) {
            /* not captured */
            return -1;
        }
        struct tcphdr *tcph;
        tcph = (struct tcphdr *)(mbuf+offset);
        offset += sizeof(struct tcphdr);

        /* get port numbers */
        port_src = ntohs(tcph->th_sport);
        port_dst = ntohs(tcph->th_dport);

        /* get tcp options */
        if ( psize < offset + 4*((int)tcph->th_off - 5) ) {
            /* not captured */
            return -1;
        }
        int optoff;
        int optlen;
        int mss;
        int wscale;
        optoff = 0;
        mss = 0;
        wscale = 0;
        while ( optoff < 4*((int)tcph->th_off - 5) ) {
            if ( 2 == mbuf[offset + optoff] ) {
                /* MSS */
                optlen = mbuf[offset + optoff + 1];
                mss = bytes2uint16(mbuf+offset+optoff+2);
                optoff += optlen;
            } else if ( 1 == mbuf[offset + optoff] ) {
                /* NO-OP */
                optoff += 1;
            } else if ( 0 == mbuf[offset + optoff] ) {
                /* end of option */
                optoff += 1;
            } else if ( 3 == mbuf[offset + optoff] ) {
                /* window scale */
                optlen = mbuf[offset + optoff + 1];
                wscale = mbuf[offset + optoff + 2];
                optoff += optlen;
            } else {
                break;
            }
        }
        /* proceed to the data head */
        offset += 4*((int)tcph->th_off - 5);

        /* search session */
        struct tcp6_session *ent;
        struct tcp6_session *csess = NULL;
        STAILQ_FOREACH(ent, &tcp6_head, sessions) {
            /* search */
            if ( !memcmp(&(iph->ip6_src.s6_addr), &(ent->ip6_src.s6_addr),
                         sizeof(iph->ip6_src.s6_addr))
                 && !memcmp(&(iph->ip6_dst.s6_addr), &(ent->ip6_dst.s6_addr),
                            sizeof(iph->ip6_dst.s6_addr))
                 && ent->sport == port_src && ent->dport == port_dst ) {
                csess = ent;
                break;
            }
        }
        /* check flags */
        if ( TH_SYN == (TH_SYN & tcph->th_flags) ) {
            /* SYN */
            if ( NULL != csess ) {
                STAILQ_REMOVE(&tcp6_head, csess, tcp6_session, sessions);
                free(csess);
                csess = NULL;
            }
            csess = malloc(sizeof(struct tcp6_session));
            if ( NULL == csess ) {
                fprintf(stderr, "ENOMEM\n");
                exit(EXIT_FAILURE);
            }
            memcpy(&(csess->ip6_src.s6_addr), &(iph->ip6_src.s6_addr),
                   sizeof(iph->ip6_src.s6_addr));
            memcpy(&(csess->ip6_dst.s6_addr), &(iph->ip6_dst.s6_addr),
                   sizeof(iph->ip6_dst.s6_addr));
            csess->sport = port_src;
            csess->dport = port_dst;
            csess->tv_syn = tv;
            csess->opt.wscale = wscale;
            csess->opt.mss = mss;
            STAILQ_INSERT_TAIL(&tcp6_head, csess, sessions);
        }
        if ( NULL != csess ) {
            csess->tv_last = tv;

            printf(" y %d %d", port_src, port_dst);
            printf(" %u %u %d %u %u", ntohl(tcph->th_seq), ntohl(tcph->th_ack),
                   tcph->th_flags, ntohs(tcph->th_win)<<(csess->opt.wscale),
                   csess->opt.mss);
        } else {
            printf(" n %d %d", port_src, port_dst);
            printf(" %u %u %d %u %u", ntohl(tcph->th_seq), ntohl(tcph->th_ack),
                   tcph->th_flags, 0, 0);
        }
        if ( TH_FIN == (TH_FIN & tcph->th_flags)
             || TH_RST == (TH_RST & tcph->th_flags) ) {
            /* FIN or RST */
            if ( NULL != csess ) {
                STAILQ_REMOVE(&tcp6_head, csess, tcp6_session, sessions);
                free(csess);
                csess = NULL;
            }
        }
    } else if ( 17 == iph->ip6_ctlun.ip6_un1.ip6_un1_nxt ) {
        /* UDP */
        /* check captured length */
        if ( psize < offset+sizeof(struct udphdr) ) {
            /* not captured */
            return -1;
        }
        struct udphdr *udph;
        udph = (struct udphdr *)(mbuf+offset);
        offset += sizeof(struct udphdr);

        /* get port numbers */
        port_src = ntohs(udph->uh_sport);
        port_dst = ntohs(udph->uh_dport);
        printf(" %d %d", port_src, port_dst);
    } else  {
        /* see /etc/protocols for greater detail */
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
