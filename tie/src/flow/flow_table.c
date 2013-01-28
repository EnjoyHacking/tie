/*
 *  src/flow/flow_table.c - Component of the TIE v1.0.0-beta3 platform 
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

/*
 * Dependences
 */
#include <stdlib.h>
#include <string.h>
#include <pcap.h>

#include "../common/pkt_macros.h"
#include "../common/common.h"
#include "../common/utils.h"
#include "../common/session.h"
#include "flow_table.h"

/*
 * Private functions
 */
u_long ft_hash(u_char *key);
struct ft_entry *ft_dup_check(u_char *packet, struct ft_entry **flow_table, u_long loc);
struct ft_entry *ft_add_entry(u_char *packet, struct ft_entry **flow_table, u_long loc);


/*
 * Allocate and initialize a flow
 */
struct flow *flow_init(struct flow *prev)
{
	struct flow *newflow = calloc(1, sizeof(struct flow));

	if (newflow != NULL) {
		newflow->prev = prev;
		session_stats.table_sessions++;
	}

	return newflow;
}

/*
 * Delete a flow from ft_entry chain and free its memory
 */
struct flow *flow_delete(struct flow *s)
{
	struct flow *tmp = s;

	if (s) {
		tmp = s->prev; /* save link to previous flow */

		/* Free dynamically allocated memory */
		if (s->payload) free(s->payload);
		if (s->payload_stream) free(s->payload_stream);
		if (s->ps_array) free(s->ps_array);
		if (s->ipt_array) free(s->ipt_array);
		if (s->pkts_array) free(s->pkts_array);

		free(s); /* free session memory */
		session_stats.table_sessions--;
	}

	return (tmp);
}

/*
 * Initialize the hash table
 *
 * The hash table is an array of FLOW_TABLE_SIZE pointers where mapped key goes
 * from 0 to FLOW_TABLE_SIZE - 1 and each pointer points to an hash table entry
 */
void ft_init_table(struct ft_entry **flow_table)
{
	u_long c;

	for (c = 0; c < FLOW_TABLE_SIZE; c++) {
		flow_table[c] = NULL;
	}
}

/*
 * Hashing function
 *
 * Map the packet key (source + dest address) in to the table
 *
 * Return: table location
 */
u_long ft_hash(u_char *packet)
{
	int i;
	u_long j;

	/*  key is (srcIP, srcPort, dstIP, dstPort, proto)  */
	for (i = 12, j = 0; i < 24; i++)
		j = (j * 13) + packet[i]; /* srcIP + dstIP + srcPort + dstPort */

	PRINTDD("ft_hash: generated hash: %ld\n", ((j + L4_PROTO(packet)) % FLOW_TABLE_SIZE));
	return ((j + L4_PROTO(packet)) % FLOW_TABLE_SIZE);
}

/*
 * Verify if packet belongs to an existing ft_entry in loc (mapped key)
 *
 * Return: ft_entry pointer (collision) or NULL (loc was unused)
 */
struct ft_entry *ft_dup_check(u_char *packet, struct ft_entry **flow_table, u_long loc)
{
	struct ft_entry *p;

	for (p = flow_table[loc]; p; p = p->next) {
		if (!bcmp(&(packet[12]), &(p->key[0]), 12))
			return (p); /* this key is already in our table */
	}

	/* this key has collided with another entry in our table or ht[loc] was NULL */
	return (NULL);
}

/*
 * Add a new ft_entry to the table in position "loc"
 *
 * Return: a pointer to the new ft_entry
 */
struct ft_entry *ft_add_entry(u_char *packet, struct ft_entry **flow_table, u_long loc)
{
	struct ft_entry *p;

	if (flow_table[loc] == NULL) {
		/* this is the first entry in this location in the table */
		flow_table[loc] = malloc(sizeof(struct ft_entry));
		if (flow_table[loc] == NULL) {
			perror("ft_add_entry");
			return (NULL);
		}

		p = flow_table[loc];
	} else {
		/* this is a chain, find the end of it */
		for (p = flow_table[loc]; p->next; p = p->next)
			;
		p->next = malloc(sizeof(struct ft_entry));
		if (p->next == NULL) {
			perror("ft_add_entry");
			return (NULL);
		}

		p = p->next;
	}

	/*
	 * Initialize table_entry
	 */
	p->key[0] = packet[12];	/* src IP */
	p->key[1] = packet[13];
	p->key[2] = packet[14];
	p->key[3] = packet[15];
	p->key[4] = packet[16]; /* dst IP */
	p->key[5] = packet[17];
	p->key[6] = packet[18];
	p->key[7] = packet[19];
	p->key[8] = packet[20]; /* src port */
	p->key[9] = packet[21];
	p->key[10] = packet[22];/* dst port */
	p->key[11] = packet[23];
	PRINTDD("FT: Generated a new entry:  %d.%d.%d.%d:0x%x%x %d.%d.%d.%d:0x%x%x\n",
		p->key[0], p->key[1], p->key[2], p->key[3],
		p->key[8], p->key[9], p->key[4], p->key[5],
		p->key[6], p->key[7], p->key[10], p->key[11]);

	p->id = session_stats.table_entries++;
	p->next = NULL;
	p->last_flow = NULL;
	p->num_flows = 0;

	return (p);
}

/*
 * Given a packet, get a pointer to the corresponding ft_entry
 * and if necessary allocate and initialize a new entry
 *
 * Return: a pointer to ft_entry or NULL
 */
struct ft_entry *ft_get_entry(u_char * packet, struct ft_entry **flow_table)
{
	u_long n;
	struct ft_entry *entry;

	/* calculate the hash corresponding to the packet (map the key in to a table location) */
	n = ft_hash(packet);

	/* check to see if we have to add a new entry */
	entry = ft_dup_check(packet, flow_table, n);
	if (entry == NULL) {
		entry = ft_add_entry(packet, flow_table, n);
	}

	return (entry);
}

/*
 * Scan flow table deleting expired sessions
 */
int ft_free_flows(struct ft_entry **ft)
{
	u_long i;
	struct flow *s, *next;
	struct ft_entry *entry, *prev;

	for (i = 0; i < FLOW_TABLE_SIZE; i++) {
		entry = ft[i];
		prev = NULL;

		/* process entry chain */
		while (entry) {
			s = entry->last_flow;
			next = NULL;

			/* process flow chain */
			while (s) {
				if (TEST_BIT(s->flags, SESS_EXPIRED, 1)) {
					if (s == entry->last_flow) {
						entry->last_flow = flow_delete(s);
						s = entry->last_flow;
					} else {
						next->prev = flow_delete(s);
						s = next->prev;
					}
					entry->num_flows--;
				} else {
					next = s;
					s = s->prev;
				}
			}

			/* free ft_entry if empty */
			if (entry->num_flows == 0) {
				if (entry == ft[i]) {
					ft[i] = entry->next;
					free(entry);
					entry = ft[i];
				} else {
					prev->next = entry->next;
					free(entry);
					entry = prev->next;
				}
			} else {
				prev = entry;
				entry = entry->next;
			}
		}
	}

	return (1);
}
