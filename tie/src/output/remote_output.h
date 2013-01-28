/*
 *  src/output/remote_output.h - Component of the TIE v1.0.0-beta3 platform 
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

#ifndef H_REMOTE_OUTPUT
#define H_REMOTE_OUTPUT

/*
 * Dependences
 */
#include <pthread.h>

#include "../common/common.h"
#include "../plugins/plugin.h"


/*
 * Constants and types
 */
#define MSG_CLASS	1
#define MSG_KILL	2

/*
 * Classification message structure
 *  ----- ------- --------- ------- --------- ----------- ------- ------- ------------
 * | L4P | SrcIp | SrcPort | DstIp | DstPort | Timestamp | AppID | SubID | Confidence |
 *  ----- ------- --------- ------- --------- ----------- ------- ------- ------------
 */
typedef struct {
	five_tuple f_tuple;	/* 5 tuple */
	time_t timestamp; 	/* last packet timestamp */
	class_output app;	/* application info */
} msg_class;

/*
 * Pipe message structure
 *  --------- ------
 * | MsgType | Body |
 *  --------- ------
 */
typedef struct {
	char type;	/* Message type */
	void *body;	/* Message body */
} pipe_message;


/*
 * Public functions
 */
int send_class_result(msg_class *);
void * dispatcher(void *);

#endif
