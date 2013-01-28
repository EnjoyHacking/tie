/*
 *  src/biflow/biflow_table.h - Component of the TIE v1.0.0-beta3 platform 
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

#ifndef	H_BIFLOW_TABLE
#define H_BIFLOW_TABLE

/*
 * Dependences
 */
#include "../common/common.h"
#include "../class/class.h"


/*
 * Constants, Types and Macros
 */
#define BIFLOW_TABLE_SIZE		1572869	/* needs to be a prime number */

#define BIFLOW_IS_PKT_UPSTREAM(p, b)	(! bcmp(&(p[12]), &(b->key[0]), 4))	/* XXX No sense when srcIP=dstIP */
#define BIFLOW_IS_PKT_DWSTREAM(p, b)	(! BIFLOW_IS_UPSTREAM(p, b))
#define IS_UPSTREAM(s)			(TEST_BIT(s->flags, SESS_LAST_PKT, 0))
#define IS_DWSTREAM(s)			(TEST_BIT(s->flags, SESS_LAST_PKT, 1))

typedef struct str_old_cycle {
	u_long up_pkts;				/* number of upstream pkts */
	u_long up_bytes;			/* number of upstream bytes */
	u_long dw_pkts;				/* number of downstream pkts */
	u_long dw_bytes;			/* number of downstream bytes */
} str_old_cycle;

struct biflow {
	u_long id;
	int entry_id;
	struct timeval ts_last;			/* timestamp of last pkt */
	struct timeval ts_start;		/* timestamp of first pkt */
	struct timeval up_ts_last;		/* timestamp of last upstream pkt. Used for timeouts.
						   It is valid only if up_pkts > 0 */
	struct timeval dw_ts_last;		/* timestamp of last downstream pkt. Used for timeouts.
						   It is valid only if dw_pkts > 0 */
	struct timeval up_pl_ts_last;		/* timestamp of last upstream pkt carrying payload. Used for IPTs. */
	struct timeval dw_pl_ts_last;		/* timestamp of last downstream pkt carrying payload. Used for IPTs. */
	struct biflow *prev;			/* previous session (pointer to next linked list entry) */
	u_int32_t flags;			/* session flags */
	five_tuple f_tuple;			/* 5 tuple identifying the biflow */
	class_output app;			/* application info resulting from classification */
	u_int32_t id_class;			/* id of the classifier that gave the classification results */
	str_old_cycle *old_cycle;		/* used only in cyclic mode to keep pkts/bytes counters for each interval */

	/*
	 * Features
	 */
	u_long up_pkts;				/* number of upstream pkts */
	u_long up_bytes;			/* number of upstream bytes */
	u_long dw_pkts;				/* number of downstream pkts */
	u_long dw_bytes;			/* number of downstream bytes */
	u_long up_pl_pkts;			/* number of upstream pkts carrying payload */
	u_long dw_pl_pkts;			/* number of downstream pkts carrying payload */

	u_char *payload_up;			/* payload: first bytes in first packet with payload - upstream (Typically this is truncated to a fixed maximum of bytes) */
	uint16_t payload_up_len;
	u_char *payload_dw;			/* payload: first bytes in first packet with payload - downstream */
	uint16_t payload_dw_len;

	int16_t *pkts_array;			/* packet-sizes array (positive = upstream, negative = dwstream) */
	u_char pkts_array_len;			/* counter for collected packet sizes */

	int16_t *ps_array;			/* payload-sizes array (positive = upstream, negative = dwstream) */
	u_char ps_array_len;			/* counter for collected payload sizes */

	int64_t *ipt_array;			/* IPTs array (positive = upstream, negative = dwstream) */
	u_char ipt_array_len;			/* counter for collected IPTs */

	u_char *payload;			/* vector containing payloads stream */
	u_int16_t payload_len;			/* number of bytes collected into payload vector */
};

struct bt_entry {
	u_char key[12];				/* key of this entry (src_ip + dst_ip + src_prt + dst_prt) */
	u_char key2[12];			/* 2nd key of this entry (dst_ip + src_ip + dst_prt + src_prt) */
	u_long id;
	u_long num_biflows;			/* number of sessions with this key */
	struct biflow *last_biflow;		/* pointer to linked list of sessions */
	struct bt_entry *next;			/* pointer to the next entry w/ different key but same mapping */
};


/*
 * Public functions
 */
void bt_init_table(struct bt_entry **);
struct bt_entry *bt_get_entry(u_char *, struct bt_entry **);
struct biflow *biflow_delete(struct biflow *s);
struct biflow *biflow_init(struct biflow *);
int bt_free_biflows(struct bt_entry **bt);

#endif
