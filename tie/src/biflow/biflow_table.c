/*
 *  src/biflow/biflow_table.c - Component of the TIE v1.0.0-beta3 platform 
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
#include <pcap.h>
#include <stdlib.h>
#include <strings.h>

#include "../common/common.h"
#include "../common/pkt_macros.h"
#include "../common/session.h"
#include "biflow_table.h"


/*
 * Private functions
 */
u_long bt_hash(u_char *);
struct bt_entry *bt_dup_check(u_char *, struct bt_entry **, u_long);
struct bt_entry *bt_add_entry(u_char *, struct bt_entry **, u_long);


/*
 * Allocate and initialize a biflow
 */
struct biflow *biflow_init(struct biflow *prev)
{
	struct biflow *newbiflow = calloc(1, sizeof(struct biflow));

	if (newbiflow != NULL) {
		newbiflow->prev = prev;
		session_stats.table_sessions++;
	}

	return newbiflow;
}

/*
 * Delete a biflow from bt_entry chain and free its memory
 */
struct biflow *biflow_delete(struct biflow *s)
{
	struct biflow *tmp = s;

	if (s) {
		tmp = s->prev; /* save link to previous flow */

		/* Free dynamically allocated memory */
		if (s->payload) free(s->payload);
		if (s->payload_dw) free(s->payload_dw);
		if (s->payload_up) free(s->payload_up);
		if (s->ps_array) free(s->ps_array);
		if (s->ipt_array) free(s->ipt_array);
		if (s->pkts_array) free(s->pkts_array);
		if (s->old_cycle) free(s->old_cycle);

		free(s); /* free session memory */
		session_stats.table_sessions--;
	}

	return (tmp);
}

/*
 * Initialize the hash table
 *
 * The hash table is an array of BIFLOW_TABLE_SIZE pointers where mapped key goes
 * from 0 to BIFLOW_TABLE_SIZE - 1 and each pointer points to an hash table entry
 */
void bt_init_table(struct bt_entry **hash_table)
{
	u_long c;

	for (c = 0; c < BIFLOW_TABLE_SIZE; c++) {
		hash_table[c] = NULL;
	}
}

/*
 * Hashing function
 *
 * Map the packet key (source + dest address) in to the table.
 *
 * Return: table location
 */
u_long bt_hash(u_char *packet)
{
	int i;
	u_long j, k;

	/*
	 * Hash generation routine must give the same result for the same
	 * peers even if source and dest are swapped.
	 */

	/* source ip */
	for (i = 12, j = 0; i != 16; i++) {
		j = (j * 13) + packet[i];
	}
	/* source port */
	for (i = 20; i != 22; i++) {
		j = (j * 13) + packet[i];
	}

	/* dest ip */
	for (i = 16, k = 0; i != 20; i++) {
		k = (k * 13) + packet[i];
	}
	/* dest port */
	for (i = 22; i != 24; i++) {
		k = (k * 13) + packet[i];
	}

	/*
	 * i contains the hash of one host+port pair
	 * j contains the hash of the other host+port pair
	 * By summing i+j we obtain the same hash for both directions
	 * We then add the layer 4 protocol. Please note that we do not need the l4proto into the key,
	 * because the way the hash is built guarantees that we cannot have 2 same 4-tuples with different protocols
	 * with the same hash.
	 */
	PRINTDD("BT# generated hash: %ld\n", (j + k + L4_PROTO(packet)) % BIFLOW_TABLE_SIZE);
	return ((j + k + L4_PROTO(packet)) % BIFLOW_TABLE_SIZE);
}

/*
 * Verify if packet belongs to an existing ft_entry in loc (mapped key)
 *
 * Return: ft_entry pointer (collision) or NULL (loc was unused)
 *
 * TODO: This function could become "inline" to speed things up a bit more.
 */
struct bt_entry *bt_dup_check(u_char *packet, struct bt_entry **hash_table, u_long loc)
{
	struct bt_entry *p;

	for (p = hash_table[loc]; p; p = p->next) {
		if ((!bcmp(&(packet[12]), &(p->key[0]), 12)) || (!bcmp(&(packet[12]), &(p->key2[0]), 12))) {
			/* this key is already in our table */
			return (p);
		}
	}
	/* this key has collided with another entry in our table or bt[loc] was NULL */
	return (NULL);
}

/*
 * Add a new bt_entry to the table in position "loc"
 *
 * Return: a pointer to the new bt_entry
 */
struct bt_entry *bt_add_entry(u_char *packet, struct bt_entry **hash_table, u_long loc)
{
	struct bt_entry *p;

	if (hash_table[loc] == NULL) {
		/* this is the first entry in this location in the table */
		hash_table[loc] = malloc(sizeof(struct bt_entry));
		if (hash_table[loc] == NULL) {
			perror("bt_add_entry");
			return (NULL);
		}

		p = hash_table[loc];
	} else {
		/* this is a chain, find the end of it */
		for (p = hash_table[loc]; p->next; p = p->next)
			;
		p->next = malloc(sizeof(struct bt_entry));
		if (p->next == NULL) {
			perror("bt_add_entry");
			return (NULL);
		}

		p = p->next;
	}

	/*
	 * Initialize bt_entry
	 */
	p->key[0] = packet[12]; /* src IP */
	p->key[1] = packet[13];
	p->key[2] = packet[14];
	p->key[3] = packet[15];
	p->key[4] = packet[16]; /* dst IP */
	p->key[5] = packet[17];
	p->key[6] = packet[18];
	p->key[7] = packet[19];
	p->key[8] = packet[20]; /* src port */
	p->key[9] = packet[21];
	p->key[10] = packet[22]; /* dst port */
	p->key[11] = packet[23];
	PRINTDD("BT: Generated a new entry: %d.%d.%d.%d:0x%x%x %d.%d.%d.%d:0x%x%x\n",
			p->key[0], p->key[1], p->key[2], p->key[3],
			p->key[8], p->key[9], p->key[4], p->key[5],
			p->key[6], p->key[7], p->key[10], p->key[11]);

	/*
	 * key #2 . To speed lookups of keys with bcmp()
	 * This key corresponds to packets in the downstream direction
	 */
	p->key2[0] = packet[16]; /* dst IP */
	p->key2[1] = packet[17];
	p->key2[2] = packet[18];
	p->key2[3] = packet[19];
	p->key2[4] = packet[12]; /* src IP */
	p->key2[5] = packet[13];
	p->key2[6] = packet[14];
	p->key2[7] = packet[15];
	p->key2[8] = packet[22]; /* dst port */
	p->key2[9] = packet[23];
	p->key2[10] = packet[20]; /* src port */
	p->key2[11] = packet[21];

	p->id = session_stats.table_entries++;
	p->next = NULL;
	p->last_biflow = NULL;
	p->num_biflows = 0;

	return (p);
}

/*
 * Given a packet, get a pointer to the corresponding bt_entry
 * and if necessary allocate and initialize a new entry
 *
 * Return: a pointer to ft_entry or NULL
 */
struct bt_entry *bt_get_entry(u_char * packet, struct bt_entry **hash_table)
{
	u_long n;
	struct bt_entry *entry;

	/* calculate the hash corresponding to the packet (map the key in to a table location) */
	n = bt_hash(packet);

	/* check to see if we have to add a new entry */
	entry = bt_dup_check(packet, hash_table, n);
	if (entry == NULL) {
		entry = bt_add_entry(packet, hash_table, n);
	}

	return (entry);
}

/*
 * Scan biflow table deleting expired sessions
 */
int bt_free_biflows(struct bt_entry **bt)
{
	u_long i;
	struct biflow *s, *next;
	struct bt_entry *entry, *prev;

	for (i = 0; i < BIFLOW_TABLE_SIZE; i++) {
		entry = bt[i];
		prev = NULL;

		/* process entry chain */
		while (entry) {
			s = entry->last_biflow;
			next = NULL;

			/* process biflow chain */
			while (s) {
				if (TEST_BIT(s->flags, SESS_EXPIRED, 1)) {
					if (s == entry->last_biflow) {
						entry->last_biflow = biflow_delete(s);
						s = entry->last_biflow;
					} else {
						next->prev = biflow_delete(s);
						s = next->prev;
					}
					entry->num_biflows--;
				} else {
					next = s;
					s = s->prev;
				}
			}

			/* free bt_entry if empty */
			if (entry->num_biflows == 0) {
				if (entry == bt[i]) {
					bt[i] = entry->next;
					free(entry);
					entry = bt[i];
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

