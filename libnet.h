#pragma once
#include <stdint.h>

#define http_port 80
#define ETHER_ADDR_LEN 6
#define IP_ADDR_LEN 4
#define ETHERTYPE_IP 0x0800  /* IP protocol */
#define TCP_PROTOCOL 0x06 /* TCP protocol */
/*
 *  Ethernet II header
 *  Static header size: 14 bytes
 */
struct libnet_ethernet_hdr
{
    uint8_t  ether_dhost[ETHER_ADDR_LEN];/* destination ethernet address */
    uint8_t  ether_shost[ETHER_ADDR_LEN];/* source ethernet address */
    uint16_t ether_type;                 /* protocol */
};

/*
 *  IPv4 header
 *  Internet Protocol, version 4
 *  Static header size: 20 bytes
 */
struct libnet_ipv4_hdr
{
    uint8_t ip_hl:4,      /* header length */
           ip_v:4;         /* version */

    uint8_t ip_tos;       /* type of service */
    uint16_t ip_len;         /* total length */
    uint16_t ip_id;          /* identification */
    uint16_t ip_off;
    uint8_t ip_ttl;          /* time to live */
    uint8_t ip_p;            /* protocol */
    uint16_t ip_sum;         /* checksum */
    uint8_t  ip_src[IP_ADDR_LEN]; /* source and dest address */
    uint8_t  ip_dst[IP_ADDR_LEN];
};


/*
 *  TCP header
 *  Transmission Control Protocol
 *  Static header size: 20 bytes
 */
struct libnet_tcp_hdr
{
    uint16_t th_sport;       /* source port */
    uint16_t th_dport;       /* destination port */
    uint32_t th_seq;          /* sequence number */
    uint32_t th_ack;          /* acknowledgement number */

    uint8_t th_x2:4,         /* (unused) */
           th_off:4;        /* data offset */

    uint8_t  th_flags;       /* control flags */

    uint16_t th_win;         /* window */
    uint16_t th_sum;         /* checksum */
    uint16_t th_urp;         /* urgent pointer */
};