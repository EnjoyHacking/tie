/*
 *  src/plugins/l7/class_l7.c - Component of the TIE v1.0.0-beta3 platform 
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

#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include "../plugin.h"
#include "l7_matcher.h"
#include "l7_config.h"


/*
 * Function prototypes
 */
int p_disable();
int p_enable();
bool p_is_session_classifiable(void *sess);
int p_load_signatures(char *error);
int p_train(char* path);
class_output* p_classify_session(void *sess);
int p_dump_statistics(FILE *fp);
int p_session_sign(void *sess, void *packet);

/*
 * Globals
 */
char *name = NULL; /* Name is taken from filename and assigned by plug-in loader */
u_int32_t flags = 0;
u_int32_t stat_hits = 0;
u_int32_t stat_miss = 0;

/*
 * This is the external function called to initialize the classification engine
 */
int class_init(classifier *id)
{
	id->disable = p_disable;
	id->enable = p_enable;
	id->load_signatures = p_load_signatures;
	id->train = p_train;
	id->is_session_classifiable = p_is_session_classifiable;
	id->classify_session = p_classify_session;
	id->dump_statistics = p_dump_statistics;
	id->session_sign = p_session_sign;
	id->flags = &flags;
	id->version = VERSION;
	name = id->name;
	plugin_name = name;

	return 1;
}

/*
 * This is the classification engine algorithm
 *
 * This routine is called once for each session
 * when the p_is_session_classifiable() function
 * returns "true"
 */
class_output* p_classify_session(void *sess)
{
	class_output *result = malloc(sizeof(class_output));
	result->flags = 0;

	switch (pv.stype) {
	case SESS_TYPE_FLOW: {
		struct flow *s = sess;

		// analyze at most l7_config.max_packets packets
		if (s->pkts > l7_config.max_packets) {
			++stat_miss;
			result->id = 0;
			result->subid = 0;
			result->confidence = 0;
			SET_BIT( result->flags, CLASS_OUT_NOMORE, 1 );
			break;
		}

		try_match(s, result);
		break;
	}
	case SESS_TYPE_BIFLOW: {
		struct biflow *s = sess;

		// TODO: call classify when struct biflow is updated to maintain the flow as single stream

		// analyze at most l7_config.max_packets packets
		u_long total_pkts = s->up_pkts + s->dw_pkts;
		if (total_pkts > l7_config.max_packets) {
			++stat_miss;
			result->id = 0;
			result->subid = 0;
			result->confidence = 0;
			SET_BIT( result->flags, CLASS_OUT_NOMORE, 1 );
			break;
		}

		try_match(s, result);
		break;
	}
	case SESS_TYPE_HOST: {
		struct host *s;
		s = sess;
		break;
	}
	}

	if(TEST_BIT(result->flags, CLASS_OUT_REDO, 0)) {
		if (result->id != 0)
			++stat_hits;
	}

	return result;
}

/*
 * This function decides a session is ready to be classified
 *
 * This routine is called for each packet of a session that
 * has not yet been classified
 */
bool p_is_session_classifiable(void *sess)
{
	switch (pv.stype) {
	case SESS_TYPE_FLOW: {
		struct flow *s = sess;

		if (s->payload_stream_len > 0)
			return true;
		break;
	}
	case SESS_TYPE_BIFLOW: {
		struct biflow *s = sess;

		if (s->payload_len > 0)
			return true;
		break;
	}
	case SESS_TYPE_HOST: {
		struct host *s;
		s = sess;
		break;
	}
	}
	return false;
}

/*
 * This function disables the classifier
 */
int p_disable()
{
	deinit_matcher();
	SET_BIT( flags, CLASS_ENABLE, 0 );
	return 1;
}

/*
 * This function enables the classifier
 *
 * This function is called just after class_init() and should
 * control if the plugin has enough information to classify.
 */
int p_enable()
{
	// if user has enabled payload stream capturing (-S option)
	// we can classify
	if (pv.stream_len > 0) {
		SET_BIT( flags, CLASS_ENABLE, 1 );
		return 1;
	}

	SET_BIT( flags, CLASS_ENABLE, 0 );
	return 0;
}

/*
 * This function loads signatures needed for classification
 *
 * This function is called after the plugin has been enabled.
 * Here the plugin should read from some files its fingerprints
 * and store them somewhere in memory.
 */
int p_load_signatures(char *error)
{
	if (!init_matcher(error)) {
		SET_BIT(flags, CLASS_ENABLE, 0);
		return -1;
	}

	return 0;
}

/*
 * This function saves signatures obtained by p_session_sign to file
 *
 * This function is called at the end of tie execution and should
 * store in some files the results of the fingerprint collection
 * in a format readable by load_signatures() function.
 */
int p_train(char *path)
{
	/* Insert your code here */

	return 0;
}

/*
 * This function prints some statistics on classification
 * to the file pointed by fp
 */
int p_dump_statistics(FILE *fp)
{
	char p_name[8];

	if (pv.class) {
		strncpy(p_name, name, 7);
		p_name[7] = '\0';
		fprintf(fp, "%s\t| %d\t| %d\n", p_name, stat_hits, stat_miss);
	}
	return 0;
}

/*
 * This function is called for each packet with PS > 0 of a session until
 * the flag SESS_SIGNED is set. It should be used to store information
 * about sessions useful to fingerprint collection
 */
int p_session_sign(void *sess, void *packet)
{
	/* Insert your code here */

	return 0;
}
