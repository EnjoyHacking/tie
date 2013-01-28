/*
 *  src/class/class.h - Component of the TIE v1.0.0-beta3 platform 
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

#ifndef	H_CLASS
#define H_CLASS

/*
 * Constants and Types
 */
#define CLASS_TIMEOUT	60		/* Classification timeout in seconds */

/* Generic output given by a classifier */
typedef struct class_output {
	u_int16_t id;			/* Application identifier */
	u_int8_t subid;			/* Application sub id */
	u_int8_t confidence;		/* Confidence associated with match */
	u_int32_t flags;
} class_output;

/* Classification output flags */
#define CLASS_OUT_ERR		1	/* classification error */
#define CLASS_OUT_REDO		2	/* classifier wants to re-examine session
					   when new data is available */
#define CLASS_OUT_NOMORE	4	/* classifier will not re-examine this session */


/*
 * Public functions
 */
int load_signatures();
int train();
int session_sign(void *session, void *packet);

#endif
