/*
 *  src/class/class.c - Component of the TIE v1.0.0-beta3 platform 
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

#include "../common/common.h"
#include "../class/plugin_manager.h"
#include "../plugins/plugin.h"


/*
 * Load classification signatures for each enabled plug-in
 */
int load_signatures()
{
	char error[MAX_BUFFER];
	int i;

	for (i = 0; i < num_classifiers; i++) {
		error[0] = '\0';
		if (TEST_BIT(*classifiers[i].flags, CLASS_ENABLE, 1)) {
			printf("Loading %s-%s signatures...", classifiers[i].name, classifiers[i].version);
			if (classifiers[i].load_signatures(error) == 0) {
				printf("done\n");
			} else {
				printf("%s => plugin disabled\n", error);
				classifiers[i].disable();
				enabled_classifiers--;
			}
		}
	}
	printf("\n");

	return 0;
}

/*
 * Start training process for each enabled plug-in
 */
int train()
{
	int i;
	char path[200];

	for (i = 0; i < num_classifiers; i++) {
		if (TEST_BIT(*classifiers[i].flags, CLASS_ENABLE, 1)) {
			printf("Starting %s-%s training...", classifiers[i].name, classifiers[i].version);

			sprintf(path, "%s/%s", pv.directory, classifiers[i].name);
			if (pv.sign_suffix != NULL)
				sprintf(&path[strlen(path)], "_%s.txt", pv.sign_suffix);
			else
				sprintf(&path[strlen(path)], ".txt");
			classifiers[i].train(path);

			printf("done\n");
		}
	}

	return 0;
}

/*
 * Collects signatures for each enabled plug-in
 */
int session_sign(void *s, void *packet)
{
	int i;

	for (i = 0; i < num_classifiers; i++) {
		if (TEST_BIT(*classifiers[i].flags, CLASS_ENABLE, 1)) {
			
			classifiers[i].session_sign(s, packet);
		}
	}

	return 0;
}

