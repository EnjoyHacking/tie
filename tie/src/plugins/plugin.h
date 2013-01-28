/*
 *  src/plugins/plugin.h - Component of the TIE v1.0.0-beta3 platform 
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

#ifndef	H_PLUGIN
#define H_PLUGIN

/*
 * Dependences
 */
#include "../common/common.h"
#include "../class/class.h"

/* To be used by classifiers */
#include "../biflow/biflow_table.h"
#include "../common/apps.h"
#include "../common/session.h"

/*
 * Constants and types
 */
#define PLUGINS_FOLDER	"plugins"	/* Folder containing plug-ins */

/* Functions and properties of a classification engine (classifier) */
typedef struct classifier {
	int (*disable) ();
	int (*enable) ();
	int (*load_signatures) (char *);
	int (*train) (char *);
	class_output *(*classify_session) (void *session);
	int (*dump_statistics) (FILE *);
	bool (*is_session_classifiable) (void *session);
	int (*session_sign) (void *session, void *packet);

	char *name;			/* string representing the name of the classification engine */
	char *version;			/* string representing the version of the engine */
	u_int32_t *flags;
} classifier;

/* Classifier flags */
#define CLASS_ENABLE		1	/* classifier is enabled */


/*
 * Public functions
 */
extern int class_init(classifier *);	/* Initialization routine needs to be exported */


#endif
