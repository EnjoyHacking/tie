/*
 *  src/biflow/biflow_output.c - Component of the TIE v1.0.0-beta3 platform 
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

#include "biflow_table.h"
#include "biflow_output.h"
#include "../common/common.h"
#include "../host/host_table.h"
#include "../common/utils.h"
#include "../output/output.h"
#include "../common/session.h"
#include "../common/pkt_macros.h"

/*
 * Display biflow table statistics
 */
void bt_display_stats()
{
	PRINTDD("Unique 5-tuples found:\t%qu\n", session_stats.table_entries);
	printf("Valid sessions found:\t%qu\t(Total: %qu, Skipped: %qu)\n",
		session_stats.sessions - session_stats.skipped_sessions,
		session_stats.sessions,	session_stats.skipped_sessions);
}

/*
 * Dump some statistics to "report.txt" file
 */
int bt_dump_report(FILE *fs)
{
	/* Sessions etc. */
	fprintf(fs, "\n");
	
	fprintf(fs, "Valid sessions found:\t%qu\t(Total: %qu, Skipped: %qu)\n",
		session_stats.sessions - session_stats.skipped_sessions,
		session_stats.sessions,	session_stats.skipped_sessions);
	fprintf(fs, "Skipped packets:\t%qu\n", stats.skipped_pkts);

	return (0);
}

/*
 * Execute garbage collection on biflow table dumping to file classification results
 *
 * Depending on flags in "mode" following actions are performed:
 * - DUMP_ALL		dump to file every session
 * - DUMP_EXPIRED	dump to file only expired sessions
 * - DUMP_INTERVAL	dump to file only sessions belonging to current interval
 * - FREE_EXPIRED	free only expired sessions
 * - FREE_ALL		free every session
 */
int bt_dump_biflows_data(struct bt_entry **ht, int mode)
{
	struct bt_entry *entry, *prev;
	struct biflow *s, *next;
	u_long i;

	for (i = 0; i < BIFLOW_TABLE_SIZE; i++) {
		entry = ht[i];
		prev = NULL;

		/* Process entry chain */
		while (entry) {
			s = entry->last_biflow;
			next = NULL;

			/* Process flow chain */
			while (s) {
				PRINTDD("Session id: [%d][%d]\n", s->entry_id, s->id);

				/*
				 * Set corresponding flag if session is expired
				 * - Timeout for UDP and TCP without heuristics
				 * - FIN flags for TCP with heuristics
				 */
				if ((pv.tcp_heuristics &&
				     s->f_tuple.l4proto == L4_PROTO_TCP &&
				     TEST_BIT(s->flags, (SESS_TCP_FIN_UP | SESS_TCP_FIN_DW), 1)) ||
					(stats.tv_end.tv_sec - s->ts_last.tv_sec) > pv.session_timeout) {
					SET_BIT(s->flags, SESS_EXPIRED, 1);
				}

				/*
				 * Data dumping
				 */
				if (TEST_BIT(mode, DUMP_INTERVAL, 1)) {
					/* Cyclic Mode */
					if (TEST_BIT(s->flags, SESS_SKIP, 0) &&
					    /* dump session data only if generated packets during the interval */
					    ((s->dw_pkts - s->old_cycle->dw_pkts != 0) || (s->up_pkts - s->old_cycle->up_pkts != 0))) {
						store_result(s, mode);
					}
				} else if (TEST_BIT(s->flags, SESS_SKIP, 0) &&
				    (TEST_BIT(mode, DUMP_ALL, 1) ||
				    (TEST_BIT(mode, DUMP_EXPIRED, 1) && TEST_BIT(s->flags, SESS_EXPIRED, 1)))) {
					store_result(s, mode);
				}

				/*
				 * Memory cleaning
				 */
				if (TEST_BIT(mode, FREE_ALL, 1) ||
				    (TEST_BIT(mode, FREE_EXPIRED, 1) && TEST_BIT(s->flags, SESS_EXPIRED, 1))) {
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

			/* Free bt_entry if empty */
			if (entry->num_biflows == 0) {
				if (entry == ht[i]) {
					ht[i] = entry->next;
					free(entry);
					entry = ht[i];
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

	return (0);
}




