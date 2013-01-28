/*
 *  src/class/plugin_manager.c - Component of the TIE v1.0.0-beta3 platform 
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
#include "../common/common.h" /* DO NOT move this. It must be before dlfcn.h to correctly compile under MacOSX */
#include <dlfcn.h>
#include <string.h>

#include "../plugins/plugin.h"
#include "../common/apps.h"
#include "../class/combiner.h"


/*
 * Constants
 */
#define MAX_PLUGINS		30
#define ENABLED_PLUGINS		"plugins/enabled_plugins"


/*
 * Global variables
 */
void **class_handle;				/* Dynamic array of classifiers handlers */
classifier *classifiers;			/* Dynamic array of classifiers */
int num_classifiers = 0;			/* Number of classifiers available */
int enabled_classifiers = 0;			/* Number of classifiers enabled */


/*
 * Parse enabled_plugins file
 *
 * Return: 2 lists containing names and paths of effectively existing plug-ins
 */
int enabled_plugins(char **namelist, char **pathlist)
{
	char *row = malloc(MAX_BUFFER * sizeof(char));	/* Buffer to store file rows */
	char path[MAX_BUFFER];
	FILE *fp;
	int n = 0;

	/* Open enabled_plugins file */
	sprintf(path, "%s/%s", tie_path, ENABLED_PLUGINS);
	if ((fp = fopen(path, "r")) == NULL) {
		printf("Unable to open enabled_plugins file!\n");
		return 0;
	}

	/*
	 * Parse plug-ins list
	 */
	rewind(fp);
	while (fgets(row, MAX_BUFFER, fp)) {
		char *name, *sptr = row;
		FILE *tfp;
		bool skip = false;

		/* Skip initial spaces */
		while (*sptr <= ' ') {
			if (*sptr != '\0') {
				sptr++;
			} else {
				skip = true;
				break;
			}
		}

		/* Skip commented lines */
		if (*sptr == '#' || skip)
			continue;

		/* Get plug-in name */
		name = sptr;
		while (*sptr > ' ')
			sptr++;
		*sptr = '\0';

		/* Add plug-in name to namelist only if really exists */
		snprintf(path, MAX_BUFFER, "%s/plugins/%s/class_%s.so", tie_path, name, name);
		if ((tfp = fopen(path, "r")) != NULL) {
			fclose(tfp);
			namelist[n] = malloc(strlen(name) + 1);
			pathlist[n] = malloc(strlen(path) + 1);
			strncpy(namelist[n], name, strlen(name));
			strncpy(pathlist[n], path, strlen(path));
			namelist[n][strlen(name)] = '\0';
			pathlist[n][strlen(path)] = '\0';
			n++;
		}
	}

	fclose(fp);
	free(row);
	return n;
}

/*
 * Load plug-ins
 *
 * Return: enabled plug-ins count
 */
int load_plugins()
{
	const char *error;
	char path[70];
	char *namelist[MAX_PLUGINS];
	char *pathlist[MAX_PLUGINS];
	int n, i;

	/* Obtain the list of enabled plug-ins */
	n = enabled_plugins(namelist, pathlist);
	if (n > 0) {
		int base_len = strlen(PLUGINS_FOLDER);

		strncpy(path, PLUGINS_FOLDER, base_len);
		path[base_len++] = '/';

		/*
		 * Allocate classifiers related dynamic arrays
		 */
		classifiers = calloc(n, sizeof(classifier));
		class_handle = calloc(n, sizeof(void *));

		/*
		 * Plug-ins loading loop
		 */
		for (i = 0; i < n; i++) {
			int (*class_init) (classifier *);	/* Classifiers initialization function pointer */

			/* Set classifier name */
			classifiers[i].name = namelist[i];
			PRINTDD("name: %s\n", classifiers[i].name);

			/*
			 * Load classifier plug-in module
			 */
			class_handle[i] = dlopen(pathlist[i], RTLD_LAZY);
			if (!class_handle[i]) {
				printf("%s\n", dlerror());
				return 1;
			}
			dlerror();		/* Clear any existing error */

			/*
			 * Search class_init pointer and save it
			 */
			class_init = dlsym(class_handle[i], "class_init");
			if ((error = dlerror()) != NULL) {
				fprintf(stderr, "%s\n", error);
				return 2;
			}

			class_init(&classifiers[i]);	/* Initialize classifier */
			if (classifiers[i].enable()) {
				/* Enable classifier */
				printf("Engine %s-%s initialized and enabled.\n", classifiers[i].name, classifiers[i].version);
				enabled_classifiers++;
			} else {
				/* Disable classifier */
				printf("Engine %s-%s initialized but disabled (some requisites not satisfied).\n", classifiers[i].name, classifiers[i].version);
			}

			free(pathlist[i]);
		}
	} else {
		printf("No classification engines found!\n");
	}
	printf("\n");

	return n;
}



/*
 * Unload plug-ins and free related dynamic memory
 */
int unload_plugins()
{
	u_int i;

	for (i = 0; i < num_classifiers; i++) {
		dlclose(class_handle[i]);
	}

	free(classifiers);
	free(class_handle);

	return 0;
}


/*
 * Print some statistics about classification process
 */
int dump_statistics(FILE *fp)
{
	int i;

	fprintf(fp, "\nClassification statistics:\n");
	fprintf(fp, "plug-in\t| hit\t| miss\n");
	fprintf(fp, "---------------------------\n");

	for (i = 0; i < num_classifiers; i++) {
		if (TEST_BIT(*classifiers[i].flags, CLASS_ENABLE, 1)) {
			classifiers[i].dump_statistics(fp);
		}
	}

	if (pv.class) {
		fprintf(fp, "---------------------------\n");
		fprintf(fp, "Total\t| %d\t| %d\n\n", class_hits, class_miss);
		PRINTD("Forced classifications:\t %d\n", class_forced);
	}

	return 0;
}


