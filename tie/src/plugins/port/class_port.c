/*
 *  src/plugins/port/class_port.c - Component of the TIE v1.0.0-beta3 platform 
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

#include <string.h>
#include <sys/time.h>
#include <time.h>
#include "../plugin.h"
#include "../../common/hashtab.h"

/*
 * Constants and Macros
 */
#define HASH_SIZE		18059
#define MAX_PATH_LEN		150

#define PORT_VECTOR_SIZE	65536
#define APP_PORTS		"Application_ports_Master.txt"

/*
 * This is the structure used to store port info
 */
typedef struct port_info {
	u_int16_t sport;			/* source port (key) */
	u_int16_t dport;			/* destination port (key) */
	u_int8_t proto;				/* protocol type (key) */
	u_int16_t app_id;			/* application ID */
	u_int8_t app_subid;			/* application sub ID */
} port_info;

/*
 * Function prototypes
 */
int p_disable();
int p_enable();
bool p_is_session_classifiable(void *sess);
int p_load_signatures(char *error);
int p_train(char* path);
class_output* p_classify_session(void *sess);
int p_dump_statistics(FILE *fp);
int p_session_sign(void *sess, void *packet);

/*
 * Globals
 */
u_int32_t *src_port;				/* source port signature counters vector */
u_int32_t *dst_port;				/* destination port signature counters vector */
char *name = NULL;				/* Name is taken from filename and assigned by plug-in loader */
u_int32_t flags = 0;
u_int32_t stat_hits = 0;
u_int32_t stat_miss = 0;
u_int32_t sig_up = 0;
u_int32_t sig_dw = 0;
hash_tab *port_table = NULL;			/* Port hash table */
extern u_int16_t max_app_id;			/* Max application identifier */


/*
 * This is the external function called to initialize the classification engine
 */
int class_init(classifier * id)
{
	id->disable = p_disable;
	id->enable = p_enable;
	id->load_signatures = p_load_signatures;
	id->train = p_train;
	id->is_session_classifiable = p_is_session_classifiable;
	id->classify_session = p_classify_session;
	id->dump_statistics = p_dump_statistics;
	id->session_sign = p_session_sign;
	id->flags = &flags;
	id->version = VERSION;
	name = id->name;

	if (pv.training) {
		src_port = calloc(PORT_VECTOR_SIZE, sizeof(u_int32_t));
		dst_port = calloc(PORT_VECTOR_SIZE, sizeof(u_int32_t));
	}

	return (1);
}

/*
 * This is the classification engine algorithm
 */
class_output* p_classify_session(void *sess)
{
	class_output *result = calloc(1, sizeof(class_output));
	port_info *hit;
	register u_int8_t i;

	switch (pv.stype) {
	case SESS_TYPE_FLOW: {
		struct flow *s = sess;
		port_info entry[] = {
			{s->f_tuple.src_port, s->f_tuple.dst_port, s->f_tuple.l4proto, 0, 0},
			{0, s->f_tuple.dst_port, s->f_tuple.l4proto, 0, 0},
			{s->f_tuple.src_port, 0, s->f_tuple.l4proto, 0, 0}
		};

		for (i = 0; i < 3; i++) {
			hit = find_hash_entry(port_table, &entry[i]);

			if (hit) {
				result->id = hit->app_id;
				result->subid = hit->app_subid;
				result->confidence = 100;
				stat_hits++;
				break;
			}
		}

		if (!hit) {
			result->id = 0;
			result->subid = 0;
			result->confidence = 0;
			stat_miss++;
		}

		break;
	}
	case SESS_TYPE_BIFLOW: {
		struct biflow *s = sess;
		port_info entry[] = {
			{s->f_tuple.src_port, s->f_tuple.dst_port, s->f_tuple.l4proto, 0, 0},
			{0, s->f_tuple.dst_port, s->f_tuple.l4proto, 0, 0},
			{s->f_tuple.src_port, 0, s->f_tuple.l4proto, 0, 0}
		};

		for (i = 0; i < 3; i++) {
			hit = find_hash_entry(port_table, &entry[i]);

			if (hit) {
				result->id = hit->app_id;
				result->subid = hit->app_subid;
				result->confidence = 100;
				stat_hits++;
				break;
			}
		}

		if (!hit) {
			result->id = 0;
			result->subid = 0;
			result->confidence = 0;
			stat_miss++;
		}
		break;
	}
	case SESS_TYPE_HOST: {
		struct host *s;
		s = sess;
		/* Insert your code here */
		break;
	}
	}

	return result;
}

/*
 * This function decides if the biflow is ready to be classified
 */
bool p_is_session_classifiable(void *sess)
{
	return true;
}

/*
 * This function disables the classifier
 */
int p_disable()
{
	SET_BIT(flags, CLASS_ENABLE, 0);

	return 1;
}

/*
 * This function enables the classifier
 */
int p_enable()
{
	SET_BIT(flags, CLASS_ENABLE, 1);

	return 1;
}

/*
 * Port Hash table functions
 */
int port_info_cmp(const void *id1, const void *id2)
{
	const port_info *check1 = (const port_info *) id1;
	const port_info *check2 = (const port_info *) id2;
	return (check1->proto != check2->proto || check1->sport != check2->sport || check1->dport != check2->dport);
}

unsigned long port_info_hash_key(const void *data)
{
	const port_info *check = (const port_info *) data;
	return (check->proto + 13 * (check->sport + 13 * check->dport));
}

void port_info_delete(void *data)
{
	port_info *kill = (port_info *) data;
	free(kill);
}

/*
 * This function loads signatures needed for classification
 */
int p_load_signatures(char *error)
{
	char *row = malloc(MAX_BUFFER * sizeof(char));	/* Buffer to store file rows */
	FILE *fp;
	int i, j = 0;
	u_int16_t app_id = 0, app_subid = 0;
	char sport[100], dport[100], proto[10];
	u_int8_t count = 0;
	char path[MAX_PATH_LEN];

	/* Open Application_ports_Master file */
	sprintf(path, "%s/plugins/%s/%s", tie_path, name, APP_PORTS);
	if ((fp = fopen(path, "r")) == NULL) {
		sprintf(error, "error: cannot open %s", path);
		return -1;
	}

	/* Init hash table */
	srandom(time(NULL));
	port_table = init_hash_table("ports table", port_info_cmp, port_info_hash_key, port_info_delete, HASH_SIZE);

	/*
	 * Fill port table
	 */
	rewind(fp);
	while (fgets(row, MAX_BUFFER, fp)) {
		char *field;
		char *sptr = NULL;

		/* Get field name */
		field = strtok_r(row, ":", &sptr);

		if (!strcmp(field, "name")) {	/* Application name */
			bool found = false;

			field = strtok_r(NULL, "\n", &sptr);

			/* Remove spaces before and after the label */
			while (field[0] <= 32)
				field++;
			for (i = 0; i < strlen(field); i++) {
				if (field[i] <= 32) {
					field[i] = '\0';
					break;
				}
			}

			/* Find app_id and app_sub_id from label */
			for (i = 0; i <= max_app_id; i++) {
				if (apps[i].label) {
					for (j = 0; j < apps[i].sub_id_count; j++) {
						if (!strncmp
						    (apps[i].sub_id[j].sub_label, field,
						     MAX(strlen(apps[i].sub_id[j].sub_label), strlen(field)))) {
							found = true;
							break;
						}
					}
					if (found)
						break;
				}
			}

			app_id = i;
			app_subid = j;
			count = 1;

		} else if (!strcmp(field, "sport")) {	/* Application destination port */

			field = strtok_r(NULL, "\n", &sptr);
			while (field[0] <= 32)
				field++;
			strncpy(dport, field, sizeof(dport));
			if (count > 0)
				count++;

		} else if (!strcmp(field, "dport")) {	/* Application source port */

			field = strtok_r(NULL, "\n", &sptr);
			while (field[0] <= 32)
				field++;
			strncpy(sport, field, sizeof(sport));
			if (count > 0)
				count++;

		} else if (!strcmp(field, "protocol")) {	/* Application protocol */

			field = strtok_r(NULL, "\n", &sptr);
			while (field[0] <= 32)
				field++;
			strncpy(proto, field, sizeof(proto));
			if (count > 0)
				count++;

		}

		/* Elaborate app info to generate port table entries */
		if (count == 4) {
			u_int16_t dmin, dmax, smin, smax;
			char *sep, *sptr1 = NULL, *f1 = strtok_r(proto, ",", &sptr1);

			do {
				char *sptr2 = NULL, *f2 = strtok_r(dport, ",", &sptr2);

				PRINTDD("\nID: %d\tSUB_ID: %d\tPROTO: %s\tDPORT: %s\tSPORT: %s\n", app_id, app_subid, f1, dport, sport);
				do {
					sep = strstr(f2, "-");
					dmin = atoi(f2);
					dmax = sep ? atoi(++sep) : dmin;

					for (i = dmin; i <= dmax; i++) {
						char *sptr3 = NULL, *f3 = strtok_r(sport, ",", &sptr3);

						PRINTDD("dport=%d\n", i);
						do {
							sep = strstr(f3, "-");
							smin = atoi(f3);
							smax = sep ? atoi(++sep) : smin;

							for (j = smin; j <= smax; j++) {
								port_info *entry;

								PRINTDD("proto=%s\tsport=%d\tdport=%d\n", f1, j, i);

								entry = malloc(sizeof(port_info));
								entry->proto = atoi(f1);
								entry->dport = i;
								entry->sport = j;
								entry->app_id = app_id;
								entry->app_subid = app_subid;

								add_hash_entry(port_table, entry);
							}

							f3 = strtok_r(NULL, ",", &sptr3);
						} while (f3);
					}

					f2 = strtok_r(NULL, ",", &sptr2);
				} while (f2);

				f1 = strtok_r(NULL, ",", &sptr1);
			} while (f1);

			count = 0;
		}
	}

	fclose(fp);
	free(row);
	return 0;
}

/*
 * This function saves signatures obtained by p_session_sign to file
 */
int p_train(char *path)
{
	FILE *fp;
	int i;

	if ((fp = fopen(path, "w")) == NULL) {
		perror("error opening idt up file");
		exit(EXIT_FAILURE);
	}

	for (i = 0; i < PORT_VECTOR_SIZE; i++) {
		if (src_port[i] > pv.training) {
			fprintf(fp, "U %u\t\t %d\n", src_port[i], i);
		}
	}

	for (i = 0; i < PORT_VECTOR_SIZE; i++) {
		if (dst_port[i] > pv.training) {
			fprintf(fp, "D %u\t\t %d\n", dst_port[i], i);
		}
	}
	fclose(fp);

	return 0;
}

/*
 * This function prints some statistics to file pointed by fp
 */
int p_dump_statistics(FILE * fp)
{

	if (pv.class) {
		fprintf(fp, "%s\t| %d\t| %d\n", name, stat_hits, stat_miss);
	}
	if (pv.training) {
		fprintf(fp, "Signatures collected UP: %d\n", sig_up);
		fprintf(fp, "Signatures collected DW: %d\n", sig_dw);
	}
	return 0;
}

/*
 * This function is called for each packet with PS > 0 of a session until
 * the flag SESS_SIGNED is set. It should be used to store information
 * about sessions useful to fingerprint collection
 */
int p_session_sign(void *sess, void *packet)
{
	switch (pv.stype) {
	case SESS_TYPE_FLOW: {
		struct flow *s;
		s = sess;
		/* Insert your code here */
		break;
	}
	case SESS_TYPE_BIFLOW: {
		struct biflow *s = sess;

		if (src_port[s->f_tuple.src_port] == 0)
			sig_up++;
		src_port[s->f_tuple.src_port]++;

		if (dst_port[s->f_tuple.dst_port] == 0)
			sig_dw++;
		dst_port[s->f_tuple.dst_port]++;

		break;
	}
	case SESS_TYPE_HOST: {
		struct host *s;
		s = sess;
		/* Insert your code here */
		break;
	}
	}

	return 0;
}
