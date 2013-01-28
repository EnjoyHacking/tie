/*
 *  src/class/preclassification.h - Component of the TIE v1.0.0-beta3 platform 
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

#ifndef H_PRECLASS
#define H_PRECLASS

/*
 * Dependences
 */
#include "../common/common.h"
#include "../common/hashtab.h"


/*
 * This is the structure used to store pre-classification info
 * TODO Reuse class_output and five_tuple structures
 *      Add also time_start
 */
typedef struct class_info {
	five_tuple f_tuple;			/* 5 tuple identifying the biflow */
	u_int16_t app_id;			/* application ID */
	u_int8_t app_subid;			/* application sub ID */
} class_info;


/*
 * Public variables
 */
extern hash_tab *pre_class;			/* Pre-classification results hash table */


/*
 * Public functions
 */
int load_pre_class();

#endif
