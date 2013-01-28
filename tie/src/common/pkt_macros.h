/*
 *  src/common/pkt_macros.h - Component of the TIE v1.0.0-beta3 platform 
 *
 *  Copyright (C) 2007-2011 Alberto Dainotti, Walter de Donato,
 *                            Antonio Pescape', Alessio Botta.
 *  Email: alberto@unina.it, walter.dedonato@unina.it,
 *         pescape@unina.it, a.botta@unina.it 
 *
 *  DIS - Dipartimento di Informatica e Sistemistica (Computer Science Department)
 *  University of Naples Federico II
 *  All rights reserved.
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU Affero General Public License as
 *  published by the Free Software Foundation, either version 3 of the
 *  License, or (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Affero General Public License for more details.
 *
 *  You should have received a copy of the GNU Affero General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef	H_PKT_MACROS
#define	H_PKT_MACROS

/*
 * Dependences
 */
#include "common.h"


/*
 * Ethernet (Dec/Intel/Xerox=Eth-II or 802.3)
 *
 * If the 2-bytes field immediately after eth dst and src address is <= 1500, then
 * the captured frame is of 802.3 type. XXX In the next macros we assume
 * we're always working with Ethernet-II kind of frames, the other standard. So we always need to check before.
 * For an example of how to treat this case see tcpdump/print-ether.c line 112.
 * Anyway, for 802.3 frames we should just add an 8 bytes offset to the numbers below.
 *
 * For reserved 'type' fields in both ethernet standards see RFC 1340.
 */
#define PKT_ETH_HLEN				14
#define PKT_ETH_LEN(a)				((a[12] << 8) + a[13])
#define PKT_IS_ETH_802(a)			(PKT_ETH_LEN(a) <= 1500)

/*
 * ###### Macro function offsets are relative to an IP Packet #####
 */

/*
 * IP Fragments
 */
/* MF bit set */
#define PKT_MF(a)				(a[6] & 0x20)
/* IP fragment offset field */
#define PKT_FRAG_OFFSET(a)			(a[6] & 0x1f)
/* IP fragment offset in bytes */
#define PKT_FRAG_OFFSET_B(a)			(PKT_FRAG_OFFSET(a) << 3)
/* pkt is a fragment: if frag_offset != 0 or MF is set */
#define PKT_IS_FRAGMENT(a)			((PKT_FRAG_OFFSET(a) != 0) || PKT_MF(a))
/* pkt is the first fragment of an original ip packet */
#define PKT_FIRST_FRAG(a)			(PKT_MF(a) && (PKT_FRAG_OFFSET(a) == 0))
/* pkt is the last fragment of an original ip packet */
#define PKT_LAST_FRAG(a)			((! PKT_MF(a)) && (PKT_FRAG_OFFSET(a) != 0))

/*
 * Transport level
 */
#define PKT_IS_TCP(a)				(a[9] == 0x6)
#define PKT_IS_UDP(a)				(a[9] == 0x11)
#define L4_PROTO(a)				a[9]

#define L4_PROTO_TCP				0x6
#define L4_PROTO_UDP				0x11

/*
 * Options
 */
/* pkt has no IP options */
#define PKT_IS_NO_IP_OPTIONS(a)			(a[0] == 0x45)
/* pkt has IP options */
#define PKT_IS_IP_OPTIONS(a)			!PKT_IS_NO_IP_OPTIONS(a)
/* pkt has TCP options */
#define PKT_IS_TCP_OPTIONS(a)			((a[32] & 0xf0) != 0x50)

/*
 * Headers
 */
/* IP header length in bytes */
#define PKT_IP_HLEN_B(a)			((a[0] & 0x0f) << 2)
/* IP total length in bytes */
#define PKT_IP_TLEN_B(a)			((a[2] << 8) + a[3])
/* TCP header length in bytes */
#define PKT_TCP_HLEN_B_OLD(a)			((a[32] & 0xf0) >> 2)
/* TCP header length in bytes */
#define PKT_TCP_HLEN_B(a)			((a[PKT_IP_HLEN_B(a)+12] & 0xf0) >> 2)
/* UDP header length */
#define PKT_UDP_HLEN_B				8

/*
 * Payloads
 */
/* IP payload - valid only for non-fragments */
#define PKT_IP_PAYLOAD_B(a)			(PKT_IP_TLEN_B(a) - PKT_IP_HLEN_B(a))
/* IP payload - valid only if applied to last fragment */
#define PKT_F_IP_PAYLOAD_B(a)			(PKT_FRAG_OFFSET_B(a) + PKT_IP_TLEN_B(a))
/* TCP payload - valid only for non-fragments */
#define PKT_TCP_PAYLOAD_B(a)			(PKT_IP_TLEN_B(a) - PKT_IP_HLEN_B(a) - PKT_TCP_HLEN_B(a))
/* UDP payload */
#define PKT_UDP_PAYLOAD_B(a)			(PKT_IP_TLEN_B(a) - PKT_IP_HLEN_B(a) - PKT_UDP_HLEN_B)

/*
 * Ports
 */
/* TCP/UDP source port */
#define PKT_SRC_PRT(a)				((a[PKT_IP_HLEN_B(a)] << 8) + a[PKT_IP_HLEN_B(a)+1])
/* TCP/UDP destination port */
#define PKT_DST_PRT(a)				((a[PKT_IP_HLEN_B(a)+2] << 8) + a[PKT_IP_HLEN_B(a)+3])

/*
 * IP Header fields
 */
#define PKT_IP_TOS(a)				(a[1])

/*
 * TCP Flags
 */
#define PKT_TCP_FLAGS(a)			(a[PKT_IP_HLEN_B(a)+13])
#define TCP_FLAG_FIN				0x1
#define TCP_FLAG_SYN				0x2
#define TCP_FLAG_RST				0x4
#define TCP_FLAG_PSH				0x8
#define TCP_FLAG_ACK				0x10
#define TCP_FLAG_URG				0x20
#define PKT_TCP_FLAG_FIN(a)			(a[PKT_IP_HLEN_B(a)+13] & TCP_FLAG_FIN)
#define PKT_TCP_FLAG_SYN(a)			(a[PKT_IP_HLEN_B(a)+13] & TCP_FLAG_SYN)
#define PKT_TCP_FLAG_RST(a)			(a[PKT_IP_HLEN_B(a)+13] & TCP_FLAG_RST)
#define PKT_TCP_FLAG_PSH(a)			(a[PKT_IP_HLEN_B(a)+13] & TCP_FLAG_PSH)
#define PKT_TCP_FLAG_ACK(a)			(a[PKT_IP_HLEN_B(a)+13] & TCP_FLAG_ACK)
#define PKT_TCP_FLAG_URG(a)			(a[PKT_IP_HLEN_B(a)+13] & TCP_FLAG_URG)
#define PKT_TCP_FLAG_SYN_ONLY(a)		((a[PKT_IP_HLEN_B(a)+13] & 0x3f) == 0x2)

/* Stream direction: dest ip is server => traffic is upstream */
#define PKT_IS_UPSTREAM_BY_IP(a,b)		((a[16] == ((u_char *)&b)[0]) && (a[17] == ((u_char *)&b)[1]) && (a[18] == ((u_char *)&b)[2]) && (a[19] == ((u_char *)&b)[3]))


/*
 * Public functions
 */
void *pkt_payload(unsigned char *packet, unsigned int pl_size, uint16_t *pl_stored, bool printable);
char *payload_string(unsigned char *payload, unsigned int pl_size);

#endif
