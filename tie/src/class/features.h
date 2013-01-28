/*
 *  src/class/features.h - Component of the TIE v1.0.0-beta3 platform 
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

#ifndef H_FEATURES
#define H_FEATURES

/*
 * Dependences
 */
#include <pcap.h>
#include <ctype.h>
#include <string.h>

#include "../common/pkt_macros.h"
#include "../biflow/biflow_table.h"

/*
 * Extract features from packets and store them into session structure (BiFlow session type)
 */
inline int extract_biflow_features(struct biflow *s, u_char *ip_packet, const struct pcap_pkthdr head)
{
	u_int16_t pl;		/* Payload length as computed from IP Total Length field */
	u_int16_t pl_snapped;	/* Effective payload length as computed from pcap caplen */
	u_int8_t l4proto;
	bool upstream;

	if (PKT_IS_TCP(ip_packet)) {
		pl = PKT_TCP_PAYLOAD_B(ip_packet);
		pl_snapped = head.caplen - PKT_ETH_HLEN - PKT_IP_HLEN_B(ip_packet) - PKT_TCP_HLEN_B(ip_packet);
		l4proto = L4_PROTO_TCP;
	} else if (PKT_IS_UDP(ip_packet)) {
		pl = PKT_UDP_PAYLOAD_B(ip_packet);
		pl_snapped = head.caplen - PKT_ETH_HLEN - PKT_IP_HLEN_B(ip_packet) - PKT_UDP_HLEN_B;
		l4proto = L4_PROTO_UDP;
	} else {
		PRINTDD("bt_process_packet: not TCP or UDP\n");
		return (-1);
	}
	upstream = IS_UPSTREAM(s);

	/*
	 * Array of IPTs between packets with payload (optional)
	 */
	if (pl > 0 && pv.ipts > 0) {
		if (((upstream) && (s->up_pl_pkts > 0)) || ((!upstream) && (s->dw_pl_pkts > 0))) {  /* we have a new IPT */
			if (s->ipt_array_len < pv.ipts) {  /* we have space for a new IPT */
				/* Allocate IPTs array if necessary */
				if (s->ipt_array == NULL) {
					s->ipt_array = (int64_t *) calloc(pv.ipts, sizeof(int64_t));
				}
				if (upstream) {
					/* A negative value is given to upstream IPTs */
					s->ipt_array[s->ipt_array_len++] = (int64_t) TV_SUB_TO_QUAD(head.ts, s->up_pl_ts_last);
				} else {
					s->ipt_array[s->ipt_array_len++] = (int64_t) TV_SUB_TO_QUAD(s->dw_pl_ts_last, head.ts);
				}
#if DEBUG > 1
				/*
				 * dump the array when is full
				 */
				if (s->ipt_array_len == pv.ipts) {
					int i;

					fprintf(stdout, "%lu\t%s\t", s->id, (s->f_tuple.l4proto == L4_PROTO_TCP) ? "TCP" : "UDP");
					fprintf(stdout, "%s\t%d\t", inet_ntoa(s->f_tuple.src_ip), s->f_tuple.src_port);
					fprintf(stdout, "%s\t%d\t%lu\t%lu\tIPT: ", inet_ntoa(s->f_tuple.dst_ip), s->f_tuple.dst_port, s->up_pl_pkts,
						s->dw_pl_pkts);
					for (i = 0; i < pv.ipts; i++) {
						printf("%qd ", s->ipt_array[i]);
					}
					printf("\n");
				}
#endif	
			}
		}
	}

	/*
	 * Payload size array
	 */
	if (pl > 0 && pv.psize > 0) {
		/* Allocate psize vector if necessary */
		if (s->ps_array == NULL) {
			s->ps_array = (int16_t *) calloc(pv.psize, sizeof(int16_t));
		}

		if (s->ps_array_len < pv.psize) {
			if (upstream) {
				s->ps_array[s->ps_array_len++] = pl;
			} else {
				s->ps_array[s->ps_array_len++] = -pl;
			}
#if DEBUG > 1
			if (s->ps_array_len == pv.psize) {
				int i;

				fprintf(stdout, "%lu\t%s\t", s->id, (s->f_tuple.l4proto == L4_PROTO_TCP) ? "TCP" : "UDP");
				fprintf(stdout, "%s\t%d\t", inet_ntoa(s->f_tuple.src_ip), s->f_tuple.src_port);
				fprintf(stdout, "%s\t%d\tPS: ", inet_ntoa(s->f_tuple.dst_ip), s->f_tuple.dst_port);
				for (i = 0; i < pv.psize; i++) {
					printf("%d ", s->ps_array[i]);
				}
				printf("\n");
			}
#endif
		}
	}

	/*
	 * Packet size array
	 */
	if (pv.pktsize > 0) {
		/* Allocate psize vector if necessary */
		if (s->pkts_array == NULL) {
			s->pkts_array = (int16_t *) calloc(pv.pktsize, sizeof(int16_t));
		}

		if (s->pkts_array_len < pv.pktsize) {
			if (upstream) {
				s->pkts_array[s->pkts_array_len++] = PKT_IP_TLEN_B(ip_packet);
			} else {
				s->pkts_array[s->pkts_array_len++] = -PKT_IP_TLEN_B(ip_packet);
			}
#if DEBUG > 1
			if (s->pkts_array_len == pv.pktsize) {
				int i;

				fprintf(stdout, "%lu\t%s\t", s->id, (s->f_tuple.l4proto == L4_PROTO_TCP) ? "TCP" : "UDP");
				fprintf(stdout, "%s\t%d\t", inet_ntoa(s->f_tuple.src_ip), s->f_tuple.src_port);
				fprintf(stdout, "%s\t%d\tPS: ", inet_ntoa(s->f_tuple.dst_ip), s->f_tuple.dst_port);
				for (i = 0; i < pv.pktsize; i++) {
					printf("%d ", s->pkts_array[i]);
				}
				printf("\n");
			}
#endif
		}
	}

	/*
	 * First packet payload bytes
	 */
	if (pl > 0) {
		if ((IS_UPSTREAM(s) && TEST_BIT(s->flags, SESS_PL_UP, 0)) || (IS_DWSTREAM(s) && TEST_BIT(s->flags, SESS_PL_DW, 0))) {

			/*
			 * Payload inspection routines (optional)
			 */
			if (pv.pl_inspect > 0) {
				uint16_t pl_stored;
				u_char *payload = (u_char *) pkt_payload(ip_packet, pl_snapped, &pl_stored, false);
#if DEBUG > 1
				char *p_payload = pkt_payload(ip_packet, pl_snapped, &pl_stored, true);

				/* dump payload into a file */
				fprintf(stdout, "%lu %c \"%s\"\n", s->id, (IS_UPSTREAM(s) ? 'U' : 'D'), p_payload);
				free(p_payload);	/* string MUST be freed after printing! */
#endif
				

				if (upstream) {
					/* save first upstream payload bytes */
					s->payload_up = payload;
					s->payload_up_len = pl_stored;
				} else {
					/* save first dwstream payload bytes */
					s->payload_dw = payload;
					s->payload_dw_len = pl_stored;
				}

				/* check if the first byte is alpha */
				if (payload != NULL && !isalpha((char) payload[0])) {
					SET_BIT(s->flags, SESS_NO_ALPHA, 1);
				}
			}

			/*
			 * the first payload packet is downstream
			 */
			if (IS_DWSTREAM(s) && TEST_BIT(s->flags, SESS_PL_UP, 0) && TEST_BIT(s->flags, SESS_PL_DW, 0)) {
				SET_BIT(s->flags, SESS_DW_START, 1);
			}

			/* need to set them at the end */
			if (upstream) {
				SET_BIT(s->flags, SESS_PL_UP, 1);
			} else {
				SET_BIT(s->flags, SESS_PL_DW, 1);
			}
		}
	}

	/*
	 * Payloads stream array
	 */
	if (pl > 0) {
		if (pv.stream_len > 0 && (s->payload_len + pl) <= pv.stream_len) {
			u_int16_t index;

			/* Allocate payload vector only once */
			if (s->payload_len == 0) {
				s->payload = calloc(pv.stream_len, sizeof(u_char));
			}

			/* Find current payload */
			if (PKT_IS_TCP(ip_packet)) {
				index = PKT_IP_HLEN_B(ip_packet) + PKT_TCP_HLEN_B(ip_packet);
			} else if (PKT_IS_UDP(ip_packet)) {
				index = PKT_IP_HLEN_B(ip_packet) + PKT_UDP_HLEN_B;
			} else
				index = 0;

			if (index > 0) {
				memcpy(&s->payload[s->payload_len], &ip_packet[index], (pl > pl_snapped) ? pl_snapped : pl);
				s->payload_len += pl;
			}
#if DEBUG > 1
			char *p_stream = payload_string(s->payload, s->payload_len);

			/* dump payload into a file */
			fprintf(stdout, "%lu %u \"%s\"\n", s->id, s->payload_len, p_stream);
			free(p_stream);		/* string MUST be freed after printing! */
#endif
		}

		/* This check should be done at the end of each feature extraction routine that may add a SESS_SKIP tag */
		if (TEST_BIT(s->flags, SESS_SKIP, 1)) {
			session_stats.skipped_sessions++;
			stats.skipped_pkts++;
			return (1);
		}
	}

	return 0;
}

/*
 * Extract features from packets and store them into session structure (Flow session type)
 */
inline int extract_flow_features(struct flow *s, u_char *ip_packet, const struct pcap_pkthdr head)
{
	u_int16_t pl;		/* Payload length as computed form IP Total Length field */
	u_int16_t pl_snapped;	/* Effective payload length as computed form pcap caplen */
	u_int8_t l4proto;

	if (PKT_IS_TCP(ip_packet)) {
		pl = PKT_TCP_PAYLOAD_B(ip_packet);
		pl_snapped = head.caplen - PKT_ETH_HLEN - PKT_IP_HLEN_B(ip_packet) - PKT_TCP_HLEN_B(ip_packet);
		l4proto = L4_PROTO_TCP;
		s->tcp_flags |= PKT_TCP_FLAGS(ip_packet);	/* TCP flags */
	} else if (PKT_IS_UDP(ip_packet)) {
		pl = PKT_UDP_PAYLOAD_B(ip_packet);
		pl_snapped = head.caplen - PKT_ETH_HLEN - PKT_IP_HLEN_B(ip_packet) - PKT_UDP_HLEN_B;
		l4proto = L4_PROTO_UDP;
	} else {
		PRINTDD("ft_process_packet: not TCP or UDP\n");
		return (-1);
	}

	/*
	 * IPTs array
	 */
	if (pl > 0 && pv.ipts > 0 && s->pkts > 0) {
		/* Allocate IPTs array if necessary */
		if (s->ipt_array == NULL) {
			s->ipt_array = (u_int32_t *) calloc(pv.ipts, sizeof(u_int32_t));
		}

		if (s->ipt_array_len < pv.ipts) {
			s->ipt_array[s->ipt_array_len++] = (u_int32_t) TV_SUB_TO_QUAD(head.ts, s->ts_pl_last);
#if DEBUG > 1
			if (s->ipt_array_len == pv.ipts) {
				int i;

				fprintf(stdout, "%lu\t%s\t", (unsigned long int) s->id, (s->f_tuple.l4proto == L4_PROTO_TCP) ? "TCP" : "UDP");
				fprintf(stdout, "%s\t%d\t", inet_ntoa(s->f_tuple.src_ip), s->f_tuple.src_port);
				fprintf(stdout, "%s\t%d\t%lu\tIPT: ", inet_ntoa(s->f_tuple.dst_ip), s->f_tuple.dst_port, s->pkts);
				for (i = 0; i < pv.ipts; i++) {
					printf("%u ", s->ipt_array[i]);
				}
				printf("\n");
			}
#endif
		}
	}

	/*
	 * Payload size array
	 */
	if (pl > 0 && pv.psize > 0) {
		/* Allocate psize vector if necessary */
		if (s->ps_array == NULL) {
			s->ps_array = (u_int16_t *) calloc(pv.psize, sizeof(u_int16_t));
		}

		if (s->ps_array_len < pv.psize) {
			s->ps_array[s->ps_array_len++] = pl;
#if DEBUG > 1
			if (s->ps_array_len == pv.psize) {
				int i;

				fprintf(stdout, "%lu\t%s\t", (unsigned long int) s->id, (s->f_tuple.l4proto == L4_PROTO_TCP) ? "TCP" : "UDP");
				fprintf(stdout, "%s\t%d\t", inet_ntoa(s->f_tuple.src_ip), s->f_tuple.src_port);
				fprintf(stdout, "%s\t%d\tPS: ", inet_ntoa(s->f_tuple.dst_ip), s->f_tuple.dst_port);
				for (i = 0; i < pv.psize; i++) {
					printf("%u ", s->ps_array[i]);
				}
				printf("\n");
			}
#endif
		}
	}

	/*
	 * Packet size array
	 */
	if (pv.pktsize > 0) {
		/* Allocate psize vector if necessary */
		if (s->pkts_array == NULL) {
			s->pkts_array = (u_int16_t *) calloc(pv.pktsize, sizeof(u_int16_t));
		}

		if (s->pkts_array_len < pv.pktsize) {
			s->pkts_array[s->pkts_array_len++] = PKT_IP_TLEN_B(ip_packet);
#if DEBUG > 1
			if (s->pkts_array_len == pv.pktsize) {
				int i;

				fprintf(stdout, "%lu\t%s\t", (unsigned long int) s->id, (s->f_tuple.l4proto == L4_PROTO_TCP) ? "TCP" : "UDP");
				fprintf(stdout, "%s\t%d\t", inet_ntoa(s->f_tuple.src_ip), s->f_tuple.src_port);
				fprintf(stdout, "%s\t%d\tPS: ", inet_ntoa(s->f_tuple.dst_ip), s->f_tuple.dst_port);
				for (i = 0; i < pv.pktsize; i++) {
					printf("%u ", s->pkts_array[i]);
				}
				printf("\n");
			}
#endif
		}
	}

	/*
	 * First packet payload bytes
	 */
	if (pl > 0) {
		if (TEST_BIT(s->flags, SESS_PL, 0)) {

			/*
			 * Payload inspection routines (optional)
			 */
			if (pv.pl_inspect > 0) {
				uint16_t pl_stored;
				u_char *payload = (u_char *) pkt_payload(ip_packet, pl_snapped, &pl_stored, false);
#if DEBUG > 1
				char *p_payload = pkt_payload(ip_packet, pl_snapped, &pl_stored, true);

				/* dump payload into a file */
				fprintf(stdout, "%lu \"%s\"\n", (unsigned long int) s->id, p_payload);
				free(p_payload);	/* string MUST be freed after printing! */
#endif
				/* save first upstream payload bytes */
				s->payload = payload;
				s->payload_len = pl_stored;

				/* check if the first byte is alpha */
				if (payload != NULL && !isalpha((char) payload[0])) {
					SET_BIT(s->flags, SESS_NO_ALPHA, 1);
				}
			}

			SET_BIT(s->flags, SESS_PL, 1);
		}
	}

	/*
	 * Payloads stream array
	 */
	if (pl > 0) {
		if (pv.stream_len > 0 && (s->payload_stream_len + pl) <= pv.stream_len) {
			u_int16_t index;

			/* Allocate payload vector only once */
			if (s->payload_stream_len == 0) {
				s->payload_stream = calloc(pv.stream_len, sizeof(u_char));
			}

			/* Find current payload */
			if (PKT_IS_TCP(ip_packet)) {
				index = PKT_IP_HLEN_B(ip_packet) + PKT_TCP_HLEN_B(ip_packet);
			} else if (PKT_IS_UDP(ip_packet)) {
				index = PKT_IP_HLEN_B(ip_packet) + PKT_UDP_HLEN_B;
			} else
				index = 0;

			if (index > 0) {
				memcpy(&s->payload_stream[s->payload_stream_len], &ip_packet[index], (pl > pl_snapped) ? pl_snapped : pl);
				s->payload_stream_len += pl;
			}
#if DEBUG > 1
			char *p_stream = payload_string(s->payload_stream, s->payload_stream_len);

			/* dump payload into a file */
			fprintf(stdout, "%lu %u \"%s\"\n", (unsigned long int) s->id, s->payload_stream_len, p_stream);
			free(p_stream);		/* string MUST be freed after printing! */
#endif
		}

		/* This check should be done at the end of each feature extraction routine that may add a SESS_SKIP tag */
		if (TEST_BIT(s->flags, SESS_SKIP, 1)) {
			session_stats.skipped_sessions++;
			stats.skipped_pkts++;
			return (1);
		}
	}

	return 0;
}

#endif
