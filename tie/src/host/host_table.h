/*
 *  src/host/host_table.h - Component of the TIE v1.0.0-beta3 platform 
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

#ifndef H_HOST_TABLE
#define H_HOST_TABLE

/*
 * Constants and Types
 */
#define HOST_TABLE_SIZE		798443	/* needs to be a prime number */
#define HOST_OUT 0
#define HOST_IN 1

struct ht_entry {
	u_char key[4]; /* key of this entry (src_ip) */
	u_long id;
	struct timeval ts_start; /* timestamp of first pkt/flow out */
	struct timeval ts_last_in; /* timestamp of last pkt/flow in */
	struct timeval ts_last_out; /* timestamp of last pkt/flow out*/
	u_quad_t iat; /* interhost time with previous seen host */
	u_quad_t siat; /* interhost time with previous seen source host */
	u_quad_t diat; /* interhost time with previous seen dest host */
	u_long pkts_in; /* number of in pkts */
	u_long pkts_out; /* number of out pkts */
	int count; /* count range -20,20  */
	struct ht_entry *next; /* pointer to the next entry w/ different key but same mapping */
	struct ht_entry *prev; /* pointer to the previous entry, same key but when timout is occured */
};

typedef struct {
	u_long ht_entries;
	u_long ht_oldentries;
	u_long ht_src_entries;
	u_long ht_src_entries2;
	u_long ht_dst_entries;
	u_long ht_dst_entries2;
	struct timeval tv_last_pkt; /* Timestamp of latest pkt arrived */
	struct timeval tv_last_host; /* Timestamp of latest host seen */
	struct timeval tv_last_shost; /* Timestamp of latest source host seen */
	struct timeval tv_last_dhost; /* Timestamp of latest destination host seen */

	FILE *fs_pkts_all;
} host_statistics;


/*
 * Public functions
 */
void ht_init_table(struct ht_entry **);
int ht_populate_entry(u_char *hostIP, u_long hostID, struct ht_entry **table);
struct ht_entry *ht_new_entry_src(u_char * packet, struct ht_entry **table, struct ht_entry *oldentry);
struct ht_entry *ht_get_entry_src(u_char *, struct ht_entry **);
struct ht_entry *ht_new_entry_dst(u_char * packet, struct ht_entry **table, struct ht_entry *oldentry);
struct ht_entry *ht_get_entry_dst(u_char *, struct ht_entry **);
int ht_walk_through(struct ht_entry **ht, int(* func)(struct ht_entry *));
struct ht_entry *ht_lookup_entry(u_char *, struct ht_entry **);


/*
 * Public variables
 */
extern host_statistics hoststats;

#endif

