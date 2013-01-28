/*
 *  src/plugins/l7/l7_matcher.c - Component of the TIE v1.0.0-beta3 platform 
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
  Parts of this file are derived from the l7-filter project source
  code (userspace version 0.10), released under the GPL v2 license
  and copyrighted by:

  Ethan Sommer <sommere@users.sf.net> and
  Matthew Strait  <quadong@users.sf.net>, (C) 2006-2007
  http://l7-filter.sf.net
 */

#define _GNU_SOURCE
#include <unistd.h>
#include <stdlib.h>
#include <stddef.h>
#include <ctype.h>
#include <stdio.h>
#include <sys/types.h>
#include <dirent.h>
#include <string.h>
#include <limits.h>
#include "../../common/common.h"
#include "../../common/pkt_macros.h"
#include "../../common/apps.h"
#include "../plugin.h"
#include "l7_matcher.h"
#include "l7_config.h"
#include "regex/regex.h"
#include <sys/time.h>
#ifdef FreeBSD
#include "getline.h"
#endif

extern char* name;
char* temp_buffer = NULL;

/*
 * struct pattern
 * contains compiled regular expression + flags to use on matching
 */
typedef struct protocol_t protocol_t;

struct protocol_t {
	int eflags; // flags for regexec
	int cflags; // flags for reccomp
	regex_t compiled_regex;
	char* name; // for logging
	int app_id; // app code to return on match
	int app_sub_id; // app subId to return on match
	protocol_t* next; // next element in linked list
};

/* Prototypes */
static int matches(protocol_t* pattern, const char* buffer);
static void cleanup();
static int hex2dec(char c);
static char* preprocess(const char* s);

#ifdef DEBUG
static void print_payload_dump(const void *s, const class_output* resul);
#endif


/* module private data */
static protocol_t* patterns_head; // pointer to head of patterns list
static protocol_t* patterns_tail; // to implement list insertion at the end in costant time


/*
 * create a new pattern and add it to internal linked list
 */
int add_pattern(const char* proto_name, const char* pattern, int eflags, int cflags, int app_id, int app_sub_id)
{
	int rc = 0;
	protocol_t* new_pattern = 0;
	char* preprocessed = 0;

	new_pattern = (protocol_t*) calloc(1, sizeof(protocol_t));
	if (new_pattern == 0) {
		PRINTD( "WARNING: Not enough memory. Can't classify %s protocol\n", proto_name );
		return 0;
	}
	new_pattern->name = strdup(proto_name);
	new_pattern->eflags = eflags;
	new_pattern->cflags = cflags;
	new_pattern->app_id = app_id;
	new_pattern->app_sub_id = app_sub_id;
	new_pattern->next = 0;
	preprocessed = preprocess(pattern);
	rc = tie_regcomp(&new_pattern->compiled_regex, preprocessed, cflags);
	free(preprocessed);
	if (rc != 0) {
		PRINTD( "WARNING: Unable to compile regex pattern. Can't classify %s protocol\n", proto_name );
		free(new_pattern->name);
		free(new_pattern);
		return 0;
	}

	// insert at the end
	if (patterns_head == 0) {
		patterns_head = new_pattern;
		patterns_tail = new_pattern;
	} else {
		patterns_tail->next = new_pattern;
		patterns_tail = new_pattern;
	}
	return 1;
}

/*
 * match a pattern against a buffer
 */
int matches(protocol_t* pattern, const char* buffer)
{
	int code;

#ifdef DEBUG
	regmatch_t pmatches;
	code = tie_regexec(&pattern->compiled_regex, buffer, 1, &pmatches, pattern->eflags);
#else
	code = tie_regexec(&pattern->compiled_regex, buffer, 0, 0, pattern->eflags);
#endif
	if (code == 0) return 1; /* match (1==true) */
	else return 0;
}


/*
 * deallocate patterns list
 */
void cleanup()
{
	protocol_t* current = 0;
	while (patterns_head != 0) {
		current = patterns_head;
		patterns_head = patterns_head->next;
		tie_regfree(&current->compiled_regex);
		free(current->name);
		free(current);
	}
}


/*
 * convert an hexadecimal digit to a char code
 */
int hex2dec(char c)
{
	switch (c) {
		case '0': case '1': case '2': case '3': case '4':
		case '5': case '6': case '7': case '8': case '9':
			return c - '0';

		case 'a': case 'b': case 'c': case 'd':	case 'e':
		case 'f':
			return c - 'a' + 10;

		case 'A': case 'B': case 'C': case 'D': case 'E':
		case 'F':
			return c - 'A' + 10;

		default:
			PRINTD( "WARNING: Bad hex digit, %c in regular expression! It could give a false match\n", c );
			return c;
	}
}

/*
 * replace perl-style hex syntax in regular expression
 * with corresponding character
 */
char* preprocess(const char * s)
{
	char* result = (char*) malloc(strlen(s) + 1);
	size_t i = 0, r = 0;
	size_t slen = strlen(s);

	while (i < slen) {
		if ((i + 3 < slen && s[i] == '\\') && (s[i+1] == 'x') && (isxdigit( s[i+2] )) && isxdigit( s[i+3] )) {
			result[r] = hex2dec(s[i+2]) * 16 + hex2dec(s[i+3]);

			switch (result[r]) {
				case '$': case '(': case ')': case '*': case '+':
				case '.': case '?': case '[': case ']': case '^':
				case '|': case '{': case '}': case '\\':
					PRINTD("WARNING: regexp contains a regexp control character, %c"
							", in hex (\\x%c%c.\nI recommend that you write this as %c"
							" or \\%c depending on what you meant.\n",
							result[r], s[i+2], s[i+3], result[r], result[r]);
					break;

				case '\0':
					PRINTD("WARNING: null (\\x00) in layer7 regexp. "
						"A null terminates the regexp string!\n");
					break;

				default:
					break;
			}
			i += 3; /* 4 total */
		} else
			result[r] = s[i];

		i++;
		r++;
	}

	result[r] = '\0';

	return result;
}



/*
 * try matching passed buffer to all loaded patterns
 */
void try_match(const void *sess, class_output *result)
{
	protocol_t* iterator = 0;
	ptrdiff_t i, j = 0;

	switch (pv.stype) {
	case SESS_TYPE_FLOW: {
		const struct flow *s = sess;

		for (i = 0, j = 0; i < s->payload_stream_len; ++i) {
			if (s->payload_stream[i] != '\0') {
				temp_buffer[j] = s->payload_stream[i];
				++j;
			}
		}
		break;
	}
	case SESS_TYPE_BIFLOW: {
		const struct biflow *s = sess;

		for (i = 0, j = 0; i < s->payload_len; ++i) {
			if (s->payload[i] != '\0') {
				temp_buffer[j] = s->payload[i];
				++j;
			}
		}
		break;
	}
	}
	temp_buffer[j] = '\0';

	for (iterator = patterns_head; iterator != NULL; iterator = iterator->next) {
		if (matches(iterator, temp_buffer)) {
			result->id = iterator->app_id;
			result->subid = iterator->app_sub_id;
			result->confidence = 100; // find a better way to estimate confidence
			SET_BIT(result->flags, CLASS_OUT_NOMORE, 1);
#ifdef DEBUG
			print_payload_dump(sess, result);
#endif
			return;
		}
	}

	/* no match here */
	result->id = 0;
	result->subid = 0;
	result->confidence = 0;
	SET_BIT(result->flags, CLASS_OUT_REDO, 1);
}

/*
 * read configuration file, load required pattern file
 * and init classifier
 */
bool init_matcher(char *error)
{
	int ret = 1;
	temp_buffer = (char*) malloc(pv.stream_len + 1);
	if (temp_buffer == NULL) {
		strcpy(error, "ERROR: Cannot allocate memory for temporary buffer");
		return false;
	}

	ret = l7_load_config(error);
	return ret;
}

/*
 * cleanup allocated memory and close debug files
 */
void deinit_matcher()
{
	cleanup();
	if (temp_buffer) {
		free(temp_buffer);
		temp_buffer = NULL;
	}
#ifdef DEBUG
	if (l7_config.payload_dump != NULL)
		fclose(l7_config.payload_dump);
#endif // DEBUG
}


#ifdef DEBUG

void print_payload_dump(const void* s, const class_output* result)
{
	char *payload;

	if (l7_config.payload_dump == NULL)
		return;

	if (pv.stype == SESS_TYPE_FLOW) {
		payload = payload_string(((const struct flow *)s)->payload_stream, ((const struct flow *)s)->payload_stream_len);
		fprintf( l7_config.payload_dump,
			"Session id: %ld\nApp: %s App_sub: %s \nPayload:\n%s\n\n",
			(u_long)((const struct flow *)s)->id, apps[result->id].label, apps[result->id].sub_id[result->subid].sub_label, payload);
	} else	if (pv.stype == SESS_TYPE_BIFLOW) {
		payload = payload_string(((const struct biflow *)s)->payload, ((const struct biflow *)s)->payload_len);
		fprintf( l7_config.payload_dump,
			"Session id: %ld\nApp: %s App_sub: %s \nPayload:\n%s\n\n",
			((const struct biflow *)s)->id, apps[result->id].label, apps[result->id].sub_id[result->subid].sub_label, payload);
	}

	free(payload);
}

#endif
