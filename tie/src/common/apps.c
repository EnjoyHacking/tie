/*
 *  src/common/apps.c - Component of the TIE v1.0.0-beta3 platform 
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
#include "apps.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>


/*
 * Constants and Macros
 */
#define APPS_FILE		"tie_apps.txt"

#define SKIP_CHAR(str,c)	while (*str == c) { str++; }
#define SEEK_CHAR(str,c)	while (*str != c) { str++; }


/*
 * Global variables
 */
app *apps;					/* Application definitions */
u_int16_t max_app_id = 0;			/* Max application identifier */
u_int16_t app_count = 0;			/* Applications counter */


/*
 * Read APPS_FILE and fill "apps" structure according to its content
 */
int load_app_defs()
{
	FILE *fp;				/* Pointer to app_id file */
	char *field;
	char *row = malloc(MAX_BUFFER * sizeof(char));	/* Buffer to store file rows */
	char *sptr = NULL;
	char path[MAX_BUFFER];
	u_int16_t id = 0, sub_id, i;

	/* open file for reading */
	sprintf(path ,"%s/%s", tie_path, APPS_FILE);
	if ((fp = fopen(path, "r")) == NULL) {
		printf("\nERROR: Unable to open tie_apps.txt file!\n\n");
		return -1;
	}

	/*
	 * 1st pass: find max app_id
	 */
	while (fgets(row, MAX_BUFFER, fp)) {
		/* Skip commented rows */
		if (row[0] == '#')
			continue;

		/* Read app_id, evaluate max_app_id and increment app_count */
		field = strtok_r(row, ",", &sptr);
		if (atoi(field) > max_app_id) {
			max_app_id = atoi(field);
			app_count++;
		}
	}

	/* Allocate apps structure */
	apps = calloc(max_app_id + 1, sizeof(app));

	/*
	 * 2nd pass: fill app structs and sub_id counters
	 */
	rewind(fp);
	while (fgets(row, MAX_BUFFER, fp)) {
		/* Skip commented rows */
		if (row[0] == '#')
			continue;

		/* Read app_id */
		field = strtok_r(row, ",", &sptr);
		id = atoi(field);
		PRINTDD("ID: %d\n", id);

		/* Read sub_id and find max */
		SKIP_CHAR(sptr, '\t');
		field = strtok_r(NULL, ",", &sptr);
		if (atoi(field) > apps[id].sub_id_count - 1) {
			apps[id].sub_id_count = atoi(field) + 1;
		}
		PRINTDD("SubId count: %d\n", apps[id].sub_id_count);

		/* Read group_id */
		SKIP_CHAR(sptr, '\t');
		field = strtok_r(NULL, ",", &sptr);
		apps[id].group_id = atoi(field);
		PRINTDD("GID: %d\n", apps[id].group_id);

		/* Read label and store it */
		if (apps[id].label == NULL) {
			SEEK_CHAR(sptr, '"');
			field = strtok_r(NULL, "\"", &sptr);
			apps[id].label = strdup(field);
			PRINTDD("Label: %s\n", apps[id].label);
		}
	}

	/*
	 * Allocate sub_id vectors
	 */
	for (i = 0; i <= max_app_id; i++) {
		if (apps[i].label != NULL) {
			apps[i].sub_id = malloc(apps[i].sub_id_count * sizeof(sub_app));
		}
	}

	/*
	 * 3rd pass: fill sub_app structs
	 */
	rewind(fp);
	while (fgets(row, MAX_BUFFER, fp)) {
		/* Skip commented rows */
		if (row[0] == '#')
			continue;

		/* Read app_id */
		field = strtok_r(row, ",", &sptr);
		id = atoi(field);
		PRINTDD("ID: %d\n", id);

		/* Read sub_id */
		SKIP_CHAR(sptr, '\t');
		field = strtok_r(NULL, ",", &sptr);
		sub_id = atoi(field);
		PRINTDD("SubId count: %d\n", apps[id].sub_id_count);

		/* Skip label */
		SEEK_CHAR(sptr, '"');
		field = strtok_r(NULL, "\"", &sptr);
		PRINTDD("Label: %s\n", apps[id].label);

		/* Read sublabel and store it */
		SEEK_CHAR(sptr, '"');
		field = strtok_r(NULL, "\"", &sptr);
		apps[id].sub_id[sub_id].sub_label = strdup(field);
		PRINTDD("SubLabel: %s\n", apps[id].sub_id[sub_id].sub_label);

		/* Read description and store it */
		SEEK_CHAR(sptr, '"');
		field = strtok_r(NULL, "\"", &sptr);
		apps[id].sub_id[sub_id].descr = strdup(field);
		PRINTDD("Description: %s\n", apps[id].sub_id[sub_id].descr);

	}

	/* Close file and free buffer */
	fclose(fp);
	free(row);

	if (max_app_id == 0)
		printf("\nERROR: Invalid or empty tie_apps.txt file!\n\n");

	return max_app_id;
}

/*
 * Free all applications related memory
 */
int unload_app_defs()
{
	int i, j;

	for (i = 0; i <= max_app_id; i++) {
		free(apps[i].label);
		for (j = 0; j < apps[i].sub_id_count; j++) {
			free(apps[i].sub_id[j].descr);
			free(apps[i].sub_id[j].sub_label);
		}
		free(apps[i].sub_id);
	}
	free(apps);
	return 0;
}
