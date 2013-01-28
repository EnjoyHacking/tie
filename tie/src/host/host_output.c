/*
 *  src/host/host_output.c - Component of the TIE v1.0.0-beta3 platform 
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
#include <sys/time.h>
#include <time.h>

#include "../common/common.h"
#include "../common/utils.h"
#include "host_table.h"
#include "host_output.h"

/*
 * Display host table statistics
 */
void ht_display_stats()
{
	if (pv.hosttable) {
		printf("New Hosts found:\t%lu\n", hoststats.ht_entries - hoststats.ht_oldentries);
		printf("Previous Hosts: \t%lu\n\n", hoststats.ht_oldentries);
	} else {
		printf("Total Hosts found:\t%lu\n\n", hoststats.ht_entries);
	}
	printf("Src Hosts found:\t%lu\n", hoststats.ht_src_entries);
	printf("Src Hosts timeout:\t%lu\n", hoststats.ht_src_entries2);
	printf("Dst Hosts found:\t%lu\n", hoststats.ht_dst_entries);
	printf("Dst Hosts timeout:\t%lu\n", hoststats.ht_dst_entries2);
}

/*
 * Execute garbage collection on host table dumping to file classification results
 *
 * XXX Garbage collection is not implemented yet
 */
int ht_dump_host_data(struct ht_entry **ht, char *filename)
{
	FILE *fs, *fs2;
	u_long i;
	char path[200];
	char path2[200];
	struct ht_entry *m_entry;

	if (pv.directory) {
		sprintf(path, "%s/%s", pv.directory, filename);
		sprintf(path2, "%s/%s_ip2id", pv.directory, filename);
	} else {
		sprintf(path, "%s", filename);
		sprintf(path2, "%s_ip2id", filename);
	}

	fs = fopen(path, "w");
	fs2 = fopen(path2, "w");
	if ((fs == NULL) || (fs2 == NULL)) {
		perror("dump_host_data");
		return (-1);
	}

	for (i = 0; i < HOST_TABLE_SIZE; i++) {
		m_entry = ht[i];
		while (m_entry) {
			fprintf(fs2, "%d.%d.%d.%d %lu\n", m_entry->key[0], m_entry->key[1], m_entry->key[2], m_entry->key[3], m_entry->id);
			if ((m_entry->pkts_in > 0) || (m_entry->pkts_out > 0)) {
				fprintf(fs, "%lu", m_entry->id);
				if (m_entry->pkts_out) {
					fprintf(fs, " %qu -1", m_entry->siat);
				} else if (m_entry->pkts_in) {
					fprintf(fs, " -1 %qu", m_entry->diat);
				}
				fprintf(fs, " %qu %lu %lu", m_entry->iat, m_entry->pkts_out, m_entry->pkts_in);
				fprintf(fs, "\n");
			}
			m_entry = m_entry->next;
		}
	}

	fclose(fs);
	fclose(fs2);
	return (0);
}

/*
 * Dump some statistics to "report.txt" file
 */
int ht_dump_report(FILE *fs)
{

	/* Hosts etc. */
	fprintf(fs, "\n");
	if (pv.hosttable) {
		fprintf(fs, "New Hosts found:\t%lu\n", hoststats.ht_entries - hoststats.ht_oldentries);
		fprintf(fs, "Previous Hosts:\t%lu\n\n", hoststats.ht_oldentries);
	} else {
		fprintf(fs, "Total Hosts found:\t%lu\n\n", hoststats.ht_entries);
	}
	fprintf(fs, "Src Hosts found:\t%lu\n", hoststats.ht_src_entries);
	fprintf(fs, "Src Hosts timeout:\t%lu\n", hoststats.ht_src_entries2);
	fprintf(fs, "Dst Hosts found:\t%lu\n", hoststats.ht_dst_entries);
	fprintf(fs, "Dst Hosts timeout:\t%lu\n", hoststats.ht_dst_entries2);

	return (0);
}
