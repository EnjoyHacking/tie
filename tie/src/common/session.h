/*
 *  src/common/session.h - Component of the TIE v1.0.0-beta3 platform 
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

#ifndef H_SESSION
#define H_SESSION

/*
 * Dependences
 */
#include "../biflow/biflow_table.h"
#include "../flow/flow_table.h"
#include "../host/host_table.h"


/*
 * Constants and Types
 */
typedef struct sessions_statistics {
	u_quad_t sessions;			/* updated by tie.c (also used to assign an id to the session) */
	u_quad_t table_sessions;		/* updated by the table subsystem */
	u_quad_t table_entries;			/*
						 * This is the number of unique tuples (i.e. without counting previously
						 * timed out sessions). Updated by the table subsystem
						 */
	u_quad_t ht_entries;			/* host_table is sometimes managed also in other session modes */
	u_quad_t skipped_sessions;		/* updated by tie.c */
	struct timeval tv_last_session;		/* Timestamp of latest session arrival */
	FILE *fs_data;				/* File stream to dump sessions data */
	FILE *fs_deleted;			/* File stream to dump sessions expired */
} sessions_statistics;

typedef union session {
	struct biflow b;
	struct flow f;
	struct ht_entry h;
} session;

/* Session Flags */
#define SESS_SKIP			0x1	/* 1 => skip session processing */
#define SESS_PL				0x2	/* 1 => first packet with payload received */
#define SESS_PL_UP			0x2	/* 1 => first upstream packet with payload received */
#define SESS_PL_DW			0x4	/* 1 => first dwstream packet with payload received */
#define SESS_NO_ALPHA			0x8	/* 1 => payload is not alpha-numeric */
#define SESS_DW_START			0x10	/* 1 => first packet with payload was in dwstream */
#define SESS_LAST_PKT			0x20	/* Last packet direction: 0 => upstream , 1 => downstream */
#define SESS_DONT_CLASSIFY		0x40	/* 1 => session is not to be classified */
#define SESS_CLASSIFIED			0x80	/* 1 => session has been classified */
#define SESS_CLASSIFIED_TMP		0x100	/* 1 => session has been temporarily classified */
#define SESS_RECLASSIFY			0x200	/* 1 => session is to be reclassified */
#define SESS_SIGNED			0x400	/* 1 => signature saved */
#define SESS_EXPIRED			0x800	/* 1 => session expired */
/* TCP FLAGS */
#define SESS_TCP_SYN			0x1000	/* 1 => SYN flag seen for this session */
#define SESS_TCP_FIN			0x2000	/* 1 => FIN flag seen for this session */
#define SESS_TCP_FIN_UP			0x2000	/* 1 => FIN flag seen in upstream for this session */
#define SESS_TCP_FIN_DW			0x4000	/* 1 => FIN flag seen in dwstream for this session */
#define SESS_TCP_RST			0x8000	/* 1 => RST flag seen for this session */

/* Traffic directions */
#define UP	0
#define DW	1


/*
 * Public variables
 */
extern sessions_statistics session_stats;	/* Maintained by tie.c */

#endif
