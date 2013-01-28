/*
 *  src/class/plugin_manager.h - Component of the TIE v1.0.0-beta3 platform 
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

#ifndef	H_PLUGIN_MANAGER
#define H_PLUGIN_MANAGER

/*
 * Dependences
 */
#include "../plugins/plugin.h"


/*
 * Public functions
 */
int load_plugins();
int unload_plugins();
int dump_statistics(FILE * fp);


/*
 * Public variables
 */
extern void **class_handle;			/* Dynamic array of classifiers handlers */
extern classifier *classifiers;			/* Classifiers Dynamic array */
extern int num_classifiers;			/* Number of available classifiers */
extern int enabled_classifiers;			/* Number of enabled classifiers */

#endif
