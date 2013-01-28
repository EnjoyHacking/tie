/*
 *  src/common/apps.h - Component of the TIE v1.0.0-beta3 platform 
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

#ifndef	H_APPS
#define	H_APPS

/*
 * Dependences
 */
#include <sys/types.h>
#include "common.h"


/*
 * Types
 */
typedef struct sub_app {
	char *sub_label;
	char *descr;
} sub_app;

typedef struct app {
	char *label;
	u_int8_t group_id;
	sub_app *sub_id;
	u_int8_t sub_id_count;
} app;


/*
 * Public variables
 */
extern app *apps; 		/* Application definitions */
extern u_int16_t max_app_id;	/* Greatest application id */
extern u_int16_t app_count;	/* Applications counter */


/*
 * Public function
 */
int load_app_defs();
int unload_app_defs();

#endif

