/*
 *  VPNConnect -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2010 OpenVPN.Technologies, Inc. <sale@vpnconnect.net>
 *  Copyright (C) 2016 XNXSoft <dnfsec@gmail.com>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2
 *  as published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program (see the file COPYING included with this
 *  distribution); if not, write to the Free Software Foundation, Inc.,
 *  59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifndef PROTO_H
#define PROTO_H

#include "common.h"
#include "buffer.h"

#pragma pack(1)

/*
 * Tunnel types
 */
#define DEV_TYPE_UNDEF 0
#define DEV_TYPE_NULL  1
#define DEV_TYPE_TUN   2    /* point-to-point IP tunnel */
#define DEV_TYPE_TAP   3    /* ethernet (802.3) tunnel */

/* TUN topologies */

#define TOP_UNDEF   0
#define TOP_NET30   1
#define TOP_P2P     2
#define TOP_SUBNET  3

/*
 * IP and Ethernet protocol structs.  For portability,
 * VPNConnect.needs its own definitions of these structs, and
 * names have been adjusted to avoid collisions with
 * native structs.
 */

#define VPNCONNECT_ETH_ALEN 6            /* ethernet address length */
struct vpnconnect_ethhdr 
{
  uint8_t dest[VPNCONNECT_ETH_ALEN];     /* destination ethernet addr */
  uint8_t source[VPNCONNECT_ETH_ALEN];   /* source ethernet addr	*/

# define VPNCONNECT_ETH_P_IPV4   0x0800  /* IPv4 protocol */
# define VPNCONNECT_ETH_P_IPV6   0x86DD  /* IPv6 protocol */
# define VPNCONNECT_ETH_P_ARP    0x0806  /* ARP protocol */
  uint16_t proto;                     /* packet type ID field */
};

struct vpnconnect_arp {
# define ARP_MAC_ADDR_TYPE 0x0001
  uint16_t mac_addr_type;       /* 0x0001 */

  uint16_t proto_addr_type;     /* 0x0800 */
  uint8_t  mac_addr_size;       /* 0x06 */
  uint8_t  proto_addr_size;     /* 0x04 */

# define ARP_REQUEST 0x0001
# define ARP_REPLY   0x0002
  uint16_t arp_command;         /* 0x0001 for ARP request, 0x0002 for ARP reply */

  uint8_t   mac_src[VPNCONNECT_ETH_ALEN];
  in_addr_t ip_src;
  uint8_t   mac_dest[VPNCONNECT_ETH_ALEN];
  in_addr_t ip_dest;
};

struct vpnconnect_iphdr {
# define VPNCONNECT_IPH_GET_VER(v) (((v) >> 4) & 0x0F)
# define VPNCONNECT_IPH_GET_LEN(v) (((v) & 0x0F) << 2)
  uint8_t    version_len;

  uint8_t    tos;
  uint16_t   tot_len;
  uint16_t   id;

# define VPNCONNECT_IP_OFFMASK 0x1fff
  uint16_t   frag_off;

  uint8_t    ttl;

# define VPNCONNECT_IPPROTO_IGMP 2 /* IGMP protocol */
# define VPNCONNECT_IPPROTO_TCP  6 /* TCP protocol */
# define VPNCONNECT_IPPROTO_UDP 17 /* UDP protocol */
  uint8_t    protocol;

  uint16_t   check;
  uint32_t   saddr;
  uint32_t   daddr;
  /*The options start here. */
};

/*
 * IPv6 header
 */
struct vpnconnect_ipv6hdr {
        uint8_t		version_prio;
        uint8_t		flow_lbl[3];
        uint16_t	payload_len;
        uint8_t		nexthdr;
        uint8_t		hop_limit;

        struct  in6_addr        saddr;
        struct  in6_addr        daddr;
};


/*
 * UDP header
 */
struct vpnconnect_udphdr {
  uint16_t   source;
  uint16_t   dest;
  uint16_t   len;
  uint16_t   check;
};

/*
 * TCP header, per RFC 793.
 */
struct vpnconnect_tcphdr {
  uint16_t      source;    /* source port */
  uint16_t      dest;      /* destination port */
  uint32_t      seq;       /* sequence number */
  uint32_t      ack_seq;   /* acknowledgement number */

# define VPNCONNECT_TCPH_GET_DOFF(d) (((d) & 0xF0) >> 2)
  uint8_t       doff_res;

# define VPNCONNECT_TCPH_FIN_MASK (1<<0)
# define VPNCONNECT_TCPH_SYN_MASK (1<<1)
# define VPNCONNECT_TCPH_RST_MASK (1<<2)
# define VPNCONNECT_TCPH_PSH_MASK (1<<3)
# define VPNCONNECT_TCPH_ACK_MASK (1<<4)
# define VPNCONNECT_TCPH_URG_MASK (1<<5)
# define VPNCONNECT_TCPH_ECE_MASK (1<<6)
# define VPNCONNECT_TCPH_CWR_MASK (1<<7)
  uint8_t       flags;

  uint16_t      window;
  uint16_t      check;
  uint16_t      urg_ptr;
};

#define	VPNCONNECT_TCPOPT_EOL     0
#define	VPNCONNECT_TCPOPT_NOP     1
#define	VPNCONNECT_TCPOPT_MAXSEG  2
#define VPNCONNECT_TCPOLEN_MAXSEG 4

struct ip_tcp_udp_hdr {
  struct vpnconnect_iphdr ip;
  union {
    struct vpnconnect_tcphdr tcp;
    struct vpnconnect_udphdr udp;
  } u;
};

#pragma pack()

/*
 * The following macro is used to update an
 * internet checksum.  "acc" is a 32-bit
 * accumulation of all the changes to the
 * checksum (adding in old 16-bit words and
 * subtracting out new words), and "cksum"
 * is the checksum value to be updated.
 */
#define ADJUST_CHECKSUM(acc, cksum) { \
  int _acc = acc; \
  _acc += (cksum); \
  if (_acc < 0) { \
    _acc = -_acc; \
    _acc = (_acc >> 16) + (_acc & 0xffff); \
    _acc += _acc >> 16; \
    (cksum) = (uint16_t) ~_acc; \
  } else { \
    _acc = (_acc >> 16) + (_acc & 0xffff); \
    _acc += _acc >> 16; \
    (cksum) = (uint16_t) _acc; \
  } \
}

#define ADD_CHECKSUM_32(acc, u32) { \
  acc += (u32) & 0xffff; \
  acc += (u32) >> 16;	 \
}

#define SUB_CHECKSUM_32(acc, u32) { \
  acc -= (u32) & 0xffff; \
  acc -= (u32) >> 16;	 \
}

/*
 * We are in a "liberal" position with respect to MSS,
 * i.e. we assume that MSS can be calculated from MTU
 * by subtracting out only the IP and TCP header sizes
 * without options.
 *
 * (RFC 879, section 7).
 */
#define MTU_TO_MSS(mtu) (mtu - sizeof(struct vpnconnect_iphdr) \
                             - sizeof(struct vpnconnect_tcphdr))

/*
 * If raw tunnel packet is IPv4 or IPv6, return true and increment
 * buffer offset to start of IP header.
 */
bool is_ipv4 (int tunnel_type, struct buffer *buf);
bool is_ipv6 (int tunnel_type, struct buffer *buf);

#ifdef PACKET_TRUNCATION_CHECK
void ipv4_packet_size_verify (const uint8_t *data,
			      const int size,
			      const int tunnel_type,
			      const char
			      *prefix,
			      counter_type *errors);
#endif

#endif
