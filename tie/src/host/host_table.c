/*
 *  src/host/host_table.c - Component of the TIE v1.0.0-beta3 platform 
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

#include "../common/common.h"
#include "../common/pkt_macros.h"
#include "host_table.h"

/*
 * Private functions
 */
u_long ip_hash(u_char *);
struct ht_entry *ht_dup_check(u_char *, struct ht_entry **, u_long);
struct ht_entry *ht_add_entry(u_char * packet, struct ht_entry **table, u_long loc, struct ht_entry *oldentry);

/*
 * Global variables
 */
host_statistics hoststats;


/*
 * This function takes an hash table and a pointer to a function as arguments.
 * It would walk through the hash table calling func(ht_entry *entry) for each
 * table entry found.
 */
int ht_walk_through(struct ht_entry **ht, int(* func)(struct ht_entry *))
{
	u_long i;
	struct ht_entry *entry;

	for (i = 0; i < HOST_TABLE_SIZE; i++) {
		entry = ht[i];
		while (entry) {
			func(entry);
			entry = entry->next;
		}
	}

	return (0);
}

/*
 * Initialize the hash table.
 * The hash table is an array of MSS_TABLE_SIZE pointers.
 * Where mapped key goes from 0 to MSS_TABLE_SIZE - 1
 * and each pointer points to an hash table entry
 */
void ht_init_table(struct ht_entry **table)
{
	u_long c;

	for (c = 0; c < HOST_TABLE_SIZE; c++) {
		table[c] = NULL;
	}
}

/*
 * Hashing function.
 * Map the packet key (source + dest address) in to the table.
 * Return the table location
 */
u_long ip_hash(u_char * packet)
{
	int i;
	u_long j;

	for (i = 0, j = 0; i < 4; i++) {
		j = (j * 13) + packet[i];
	}

	PRINTDD("ip_hash: generated hash: %ld\n", j % HOST_TABLE_SIZE);
	return (j % HOST_TABLE_SIZE);
}

/*
 * Verify if packet belongs to an existing ht_entry in loc (mapped key).
 * If so, return the ht_entry pointer.
 * Otherwise return NULL. In this case we have a collision or loc was unused.
 */
struct ht_entry *ht_dup_check(u_char *packet, struct ht_entry **table, u_long loc)
{
	struct ht_entry *p;

	for (p = table[loc]; p; p = p->next) {
		if (p->key[0] == packet[0] && p->key[1] == packet[1] && p->key[2] == packet[2] && p->key[3] == packet[3]) {
			/* this key is already in our table */
			return (p);
		}
	}
	/* this key has collided with other entries in our table or ht[loc] was NULL */
	return (NULL);
}

/*
 * Add a new ht_entry to the table in position loc
 * Return the pointer to the new ht_entry
 */
struct ht_entry *ht_add_entry(u_char * packet, struct ht_entry **table, u_long loc, struct ht_entry *oldentry)
{
	struct ht_entry *p, *temp;

	if (table[loc] == NULL) {
		/* this is the first entry in this location in the table */
		table[loc] = malloc(sizeof(struct ht_entry));
		if (table[loc] == NULL) {
			perror("host_add_entry");
			return (NULL);
		}

		p = table[loc];
		p->prev = NULL;

	} else {
		/* we have an entry in loc; */
		p = table[loc];
		if (oldentry == NULL) {
			/* no new entry; we have a chain! find the end of it */
			for (p = table[loc]; p->next; p = p->next)
				;
			p->next = malloc(sizeof(struct ht_entry));
			if (p->next == NULL) {
				perror("host_add_entry");
				return (NULL);
			}

			p = p->next;
			p->prev = NULL;

		} else {
			/* we have a new entry; this is most complex situation. Use oldentryID to look for correct record */
			/* no new entry; we have a chain! find the end of it */
			while (p && (p != oldentry))
				p = p->next;
			if (p) {
				temp = p;
				p = malloc(sizeof(struct ht_entry));
				if (p == NULL) {
					perror("host_add_entry");
					return (NULL);
				}
				p->prev = temp;
			}
		}

	}

	/*
	 * Initialize ht_entry
	 */
	p->key[0] = packet[0];
	p->key[1] = packet[1];
	p->key[2] = packet[2];
	p->key[3] = packet[3];

	p->id = hoststats.ht_entries++;PRINTDD("Host_table, generated a new ip entry: %d.%d.%d.%d\n", packet[0], packet[1], packet[2], packet[3]);
	p->next = NULL;
	p->count = 0;
	p->pkts_in = 0;
	p->pkts_out = 0;
	p->ts_start.tv_sec = 0;
	p->iat = 0;
	p->siat = 0;
	p->diat = 0;

	return (p);
}

/*
 * Given a packet, get a pointer to the corresponding ht_entry.
 * If necessary allocate and initialize a new entry.
 * On error return NULL.
 */
struct ht_entry *ht_new_entry_src(u_char *packet, struct ht_entry **table, struct ht_entry *oldentry)
{
	u_long n;
	struct ht_entry *entry;
	u_char *hostIP = packet + 12;
	PRINTD("%d.%d.%d.%d\n",packet[12],packet[13],packet[14],packet[15]);

	/* calculate the hash corresponding to the packet (map the key in to a table location) */
	n = ip_hash(hostIP);

	entry = ht_add_entry(hostIP, table, n, oldentry);
	hoststats.ht_src_entries2++;
	entry->ts_start = stats.tv_end;

	return (entry);
}

struct ht_entry *ht_get_entry_src(u_char *packet, struct ht_entry **table)
{
	u_long n;
	struct ht_entry *entry;
	u_char *hostIP = packet + 12;
	PRINTD("%d.%d.%d.%d\n",packet[12],packet[13],packet[14],packet[15]);

	/* calculate the hash corresponding to the packet (map the key in to a table location) */
	n = ip_hash(hostIP);

	/* check to see if we have to add a new entry */
	entry = ht_dup_check(hostIP, table, n);

	if (entry == NULL) {

		entry = ht_add_entry(hostIP, table, n, NULL);
		hoststats.ht_src_entries++;
		entry->ts_start = stats.tv_end;

	} else {
		if (entry->ts_start.tv_sec == 0)
			entry->ts_start = stats.tv_end;

		if (entry->pkts_out == 0) { /*it's first time we see this host sending packtes */
			PRINTD("old host: %lu\n",entry->id);
			hoststats.ht_src_entries++;
			//entry->ts_start = stats.tv_end;
		}

	}

	return (entry);
}

struct ht_entry *ht_new_entry_dst(u_char * packet, struct ht_entry **table, struct ht_entry *oldentry)
{
	u_long n;
	struct ht_entry *entry;
	u_char *hostIP = packet + 16;

	PRINTD("%d.%d.%d.%d\n",packet[16],packet[17],packet[18],packet[19]);
	/* calculate the hash corresponding to the packet (map the key in to a table location) */
	n = ip_hash(hostIP);

	entry = ht_add_entry(hostIP, table, n, oldentry);
	hoststats.ht_dst_entries2++;
	entry->ts_start = stats.tv_end;

	return (entry);
}

struct ht_entry *ht_get_entry_dst(u_char * packet, struct ht_entry **table)
{
	u_long n;
	struct ht_entry *entry;
	u_char *hostIP = packet + 16;

	PRINTD("%d.%d.%d.%d\n",packet[16],packet[17],packet[18],packet[19]);
	/* calculate the hash corresponding to the packet (map the key in to a table location) */
	n = ip_hash(hostIP);

	/* check to see if we have to add a new entry */
	entry = ht_dup_check(hostIP, table, n);
	if (entry == NULL) {
		entry = ht_add_entry(hostIP, table, n, NULL);
		hoststats.ht_dst_entries++;
		entry->ts_start = stats.tv_end;

	} else {
		if (entry->ts_start.tv_sec == 0)
			entry->ts_start = stats.tv_end;

		if (entry->pkts_in == 0) { /*it's first time we see this host receing packtes */
			PRINTD("old host: %lu\n",entry->id);
			hoststats.ht_dst_entries++;
			//entry->ts_start_in = stats.tv_end;
		}
	}

	return (entry);
}

int ht_populate_entry(u_char *hostIP, u_long hostID, struct ht_entry **table)
{
	u_long n;
	struct ht_entry *p;

	/* calculate the hash corresponding to the packet (map the key in to a table location) */
	n = ip_hash(hostIP);

	if (table[n] == NULL) {
		/* this is the first entry in this location in the table */
		table[n] = malloc(sizeof(struct ht_entry));
		if (table[n] == NULL) {
			perror("host_add_entry");
			return (-1);
		}

		p = table[n];
	} else {
		/* this is a chain, find the end of it */
		for (p = table[n]; p->next; p = p->next)
			;
		p->next = malloc(sizeof(struct ht_entry));
		if (p->next == NULL) {
			perror("host_populate_entry");
			return (-1);
		}

		p = p->next;
	}

	/*
	 * Initialize ht_entry
	 */
	p->key[0] = hostIP[0];
	p->key[1] = hostIP[1];
	p->key[2] = hostIP[2];
	p->key[3] = hostIP[3];

	p->id = hostID;PRINTDD("Host_table, generated a new ip entry: %d.%d.%d.%d\n", hostIP[0], hostIP[1], hostIP[2], hostIP[3]);
	p->next = NULL;
	p->count = 0;
	p->pkts_in = 0;
	p->pkts_out = 0;
	p->ts_start.tv_sec = 0;
	p->ts_last_in.tv_sec = 0;
	p->ts_last_in.tv_usec = 0;
	p->ts_last_out.tv_sec = 0;
	p->ts_last_out.tv_sec = 0;
	p->iat = 0;
	p->siat = 0;
	p->diat = 0;

	hoststats.ht_entries++;
	hoststats.ht_oldentries++;

	return (1);
}

struct ht_entry *ht_lookup_entry(u_char *hostIP, struct ht_entry **table)
{
	u_long loc;

	/* calculate the hash corresponding to the packet (map the key in to a table location) */
	loc = ip_hash(hostIP);
	/* check to see if we have to add a new entry */
	return (ht_dup_check(hostIP, table, loc));
}
