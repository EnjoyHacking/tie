/*
 *  src/flow/flow_table.h - Component of the TIE v1.0.0-beta3 platform 
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

#ifndef H_FLOW_TABLE
#define H_FLOW_TABLE

/*
 * Constants and Types
 */
#define FLOW_TABLE_SIZE		1572869	/* needs to be a prime number */

typedef struct str_old_cycle_flow {
	u_long pkts;	/* number of upstream pkts */
	u_long bytes;	/* number of downstream bytes */
} str_old_cycle_flow;

struct flow {
	u_int32_t id;
	int entry_id;
	struct timeval ts_start;		/* timestamp of first pkt */
	struct timeval ts_last;			/* timestamp of last pkt */
	struct timeval ts_pl_last;		/* timestamp of last pkt with payload */
	struct flow *prev;			/* prev flow (pointer to prev linked list entry) */

	u_int32_t flags;			/* session flags */
	five_tuple f_tuple;			/* 5 tuple identifying the biflow */
	class_output app;			/* application info resulting from classification */
	str_old_cycle_flow *old_cycle;		/* used only in cyclic mode to keep pkts/bytes counters for each interval */

	/*
	 * Features
	 */
	u_int32_t pkts;				/* number of pkts */
	u_int32_t pl_pkts;			/* number of pkts with payload*/
	u_int64_t bytes;			/* number of payload bytes */
	u_int64_t ip_bytes;			/* number of IP layer bytes */
	u_int8_t tos;				/* IP type of service (from the first packet) */
	u_int8_t tcp_flags;			/* TCP flags seen in the overall session */

	u_char *payload;			/* payload: first bytes of first pkt w/ payload (this is truncated to a fixed maximum of bytes) */
	u_char payload_len;			/* */

	u_int16_t *pkts_array;			/* packet-sizes array */
	u_char pkts_array_len;			/* counter for collected packet sizes */

	u_int16_t *ps_array;			/* payload-sizes array */
	u_char ps_array_len;			/* counter for collected payload sizes */

	u_int32_t *ipt_array;			/* IPTs array */
	u_char ipt_array_len;			/* counter for collected IPTs */

	u_char *payload_stream;			/* vector containing payloads stream */
	u_int16_t payload_stream_len;		/* number of bytes collected into payload vector */

};

struct ft_entry {
	u_int32_t id;				/* Entry ID */
	u_char key[13];				/* key of this entry (dstIP + srcIP + srcPrt + dstPrt + Prot) */
	u_int num_flows;			/* number of flows with this key */
	struct flow *last_flow;			/* pointer to last active flow */
	struct timeval ts_last;			/* timestamp of last pkt */
	struct ft_entry *next;			/* pointer to the next entry w/ different key but same mapping */
};

typedef struct {
	u_quad_t flows;				/* Total flows processed */
	u_quad_t ft_flows;			/* Flows stored in memory */
	u_quad_t ft_entries;
	u_quad_t skipped_flows;
	struct timeval tv_last_flow;		/* Timestamp of latest flow arrival */
	FILE *fs_flow_data;			/* File stream to dump flows data */
	FILE *fs_flow_iat;			/* File stream to dump flows data */
	FILE *fs_log_ip;			/* File stream to dump IPs */
	FILE *fs_flow_deleted;

} flow_statistics;

/*
 * Public functions
 */
void ft_init_table(struct ft_entry **);
struct ft_entry *ft_get_entry(u_char * packet, struct ft_entry **flow_table);
struct flow *flow_delete(struct flow *s);
struct flow *flow_init(struct flow *prev);
int ft_free_flows(struct ft_entry **ft);

#endif
