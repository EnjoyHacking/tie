/*
 *  src/class/preclassification.c - Component of the TIE v1.0.0-beta3 platform 
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
#include <string.h>
#include <time.h>

#include "preclassification.h"
#include "../plugins/plugin.h"
#include "../common/apps.h"

/*
 * Constants
 */
#define HASH_SIZE		4999
#define KEY_LENGTH		sizeof(five_tuple)


/*
 * Global variables
 */
hash_tab *pre_class = NULL;			/* Pre-classification results hash table */
int pre_stype;					/* Pre-classification session type */

/*
 * Pre-classification Hash table functions
 */
int class_info_cmp(const void *id1, const void *id2)
{
	if (pv.stype == SESS_TYPE_FLOW && pre_stype == SESS_TYPE_BIFLOW) {
		const five_tuple *ft[] = {
			&((class_info *)id1)->f_tuple,
			&((class_info *)id2)->f_tuple
		};

		if (!bcmp(id1, id2, KEY_LENGTH) ||
		    (ft[0]->l4proto == ft[1]->l4proto &&
		     ft[0]->src_ip.s_addr == ft[1]->dst_ip.s_addr &&
		     ft[0]->src_port == ft[1]->dst_port &&
		     ft[0]->dst_ip.s_addr == ft[1]->src_ip.s_addr &&
		     ft[0]->dst_port == ft[1]->src_port))
			return 0;
		else
			return 1;
	} else {
		return (bcmp(id1, id2, KEY_LENGTH));
	}
}

unsigned long class_info_hash_key(const void *data)
{
	const class_info *check = (const class_info *) data;
	return (check->f_tuple.l4proto +
		((check->f_tuple.src_ip.s_addr) * 13 + check->f_tuple.src_port) * 13 +
		((check->f_tuple.dst_ip.s_addr) * 13 + check->f_tuple.dst_port) * 13);
}

void class_info_delete(void *data)
{
	class_info *kill = (class_info *) data;
	free(kill);
}

/*
 * Load pre-classification by 5 tuple
 * parsing T2 output file and populates pre_class table
 *
 * TODO: add also timestamp to the key
 */
int load_pre_class()
{
	char *row = malloc(MAX_BUFFER * sizeof(char));		/* Buffer to store file rows */
	bool *app_found = calloc(max_app_id + 1, sizeof(bool));	/* Array used to count classified applications */
	FILE *fp;
	int i;
	char *field;
	char *sptr = NULL;
	class_info *entry;

	/* Open pre_class_file */
	if ((fp = fopen(pv.pre_class_file, "r")) == NULL) {
		return 1;
	}

	/* Init hash table */
	srandom(time(NULL));
	pre_class = init_hash_table("pre-class table", class_info_cmp, class_info_hash_key, class_info_delete, HASH_SIZE);

	/*
	 * Fill pre_class table
	 */
	rewind(fp);
	while (fgets(row, MAX_BUFFER, fp)) {

		/* Skip void rows */
		if (row[0] == '\n')
			continue;

		/* Process commented rows (header) */
		if (row[0] == '#') {
			/* Session type */
			if (!strncmp(&row[2], "Session Type", 12)) {
				if (!strncmp(&row[16], "biflow", 6)) {
					pre_stype = SESS_TYPE_BIFLOW;
				} else if (!strncmp(&row[16], "flow", 4)) {
					pre_stype = SESS_TYPE_FLOW;
				} else if (!strncmp(&row[16], "host", 4)) {
					pre_stype = SESS_TYPE_HOST;
				} else {
					/* Assume biflow session type */
					pre_stype = SESS_TYPE_BIFLOW;
				}

				/* Check consistency */
				if (pv.stype != pre_stype && pre_stype != SESS_TYPE_BIFLOW) {
					printf("Warning: pre-classification input file has incorrect session type!\n");
					fclose(fp);
					pv.pre_class_file = NULL;
					return 2;
				}
			}
			continue;
		}

		entry = malloc(sizeof(class_info));

		/* Skip ID field */
		strtok_r(row, "\t", &sptr);

		/* Get src IP */
		field = strtok_r(NULL, "\t", &sptr);
		inet_aton(field, (void *) &entry->f_tuple.src_ip);

		/* Get dst IP */
		field = strtok_r(NULL, "\t", &sptr);
		inet_aton(field, (void *) &entry->f_tuple.dst_ip);

		/* Get protocol */
		field = strtok_r(NULL, "\t", &sptr);
		entry->f_tuple.l4proto = atoi(field);

		/* Get src port */
		field = strtok_r(NULL, "\t", &sptr);
		entry->f_tuple.src_port = atoi(field);

		/* Get dst port */
		field = strtok_r(NULL, "\t", &sptr);
		entry->f_tuple.dst_port = atoi(field);

		/* Skip other fields */
		for (i = 0; i < 6; i++)
			strtok_r(NULL, "\t", &sptr);

		/* Get App ID */
		field = strtok_r(NULL, "\t", &sptr);
		entry->app_id = atoi(field);
		app_found[entry->app_id] = true;

		/* Get App Sub ID */
		field = strtok_r(NULL, "\t", &sptr);
		entry->app_subid = atoi(field);

		/* Add entry to hash table */
		add_hash_entry(pre_class, entry);
	}

	/*
	 * Count applications IDs
	 */
	for (i = 0; i <= max_app_id; i++) {
		if (app_found[i]) {
			pv.gt_app_count++;
		}
	}

	free(app_found);
	free(row);
	fclose(fp);
	return 0;
}
