/*
 *  src/class/combiner.c - Component of the TIE v1.0.0-beta3 platform 
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
#include "../common/common.h"
#include "../common/session.h"
#include "../class/plugin_manager.h"
#include "../plugins/plugin.h"


/*
 * Global variables
 */
u_int32_t class_hits = 0;
u_int32_t class_miss = 0;
u_int32_t class_forced = 0;


/*
 * Decide if the classification process
 * can start for the session specified.
 */
bool is_session_classifiable(void *sess)
{
	u_int i, duration = 0;

	switch (pv.stype) {
	case SESS_TYPE_FLOW: {
		struct flow *s = sess;

		/* Compute session duration */
		duration = s->ts_last.tv_sec - s->ts_start.tv_sec;

		break;
	}
	case SESS_TYPE_BIFLOW: {
		struct biflow *s = sess;

		/* Compute session duration */
		duration = s->ts_last.tv_sec - s->ts_start.tv_sec;

		/* Test if the session has at least one packet carrying payload */ 
		/* IMPORTANT NOTE: Currently TIE forces UNKNOWN on all biflows which do not contain payload */
		if (s->dw_pl_pkts < 1 && s->up_pl_pkts < 1)
			return false;
		break;
	}
	case SESS_TYPE_HOST: {
		//struct host *s = sess;
		break;
	}
	}

	/*
	 * Take decision depending on is_session_classifiable() from each plugin.
	 * Rationale: wait for all classifiers to be able to perform classification attempt,
	 * or wait CLASS_TIMEOUT seconds to attempt classification with only those that are available.
	 */
	if (duration > CLASS_TIMEOUT) {
		/* Classification Timeout exceeded => Classify if there is at least one classifier willing */
		for (i = 0; i < num_classifiers; i++)
			if (TEST_BIT(*classifiers[i].flags, CLASS_ENABLE, 1) && classifiers[i].is_session_classifiable(sess))
				return true;
		return false;
	} else {
		/* Classify if ALL classifiers are willing to classify */
		for (i = 0; i < num_classifiers; i++)
			if (TEST_BIT(*classifiers[i].flags, CLASS_ENABLE, 1) && !classifiers[i].is_session_classifiable(sess))
				return false;
		return true;
	}
}

/*
 * Let each classifier take its decision in turn and compute
 * the final response (actually using a priority based approach)
 */
int classify(void *sess)
{
	u_int i;
	class_output *result;

	switch (pv.stype) {
	case SESS_TYPE_FLOW: {
		struct flow *s = sess;

		PRINTDD("FLAGS before: %08X\t", s->flags);
		SET_BIT(s->flags, SESS_RECLASSIFY, 0);
		s->app.confidence = 0;
		/*
		 * For every classifier
		 */
		for (i = 0; i < num_classifiers; i++) {
			/* Skip current classifier if disabled */
			if (TEST_BIT(*classifiers[i].flags, CLASS_ENABLE, 0))
				continue;

			/* Skip current classifier if cannot attempt classification */
			if (! classifiers[i].is_session_classifiable(s))
				continue;

			/* Perform classification */
			result = classifiers[i].classify_session(s);

			/* If current classifier wants to retry classification process set SESS_RECLASSIFY */
			if (TEST_BIT(result->flags, CLASS_OUT_REDO, 1))
				SET_BIT(s->flags, SESS_RECLASSIFY, 1);

			/*
			 * If current classifier gives a result != UNKNOWN then apply the following priority scheme:
			 * - Classifiers priority is given by the order in which they are called
			 * - The output class is determined by the first classifier that recognizes the session
			 * - Agreement or disagreement of subsequent classifiers only affects output confidence.
			 */
			if (TEST_BIT(result->flags, CLASS_OUT_ERR, 0) && (result->id != 0)) {
				if (s->app.id == 0) {	/* the previous classifiers did not recognize the session */
					s->app.id = result->id;
					s->app.subid = result->subid;
					s->app.confidence += result->confidence / enabled_classifiers;
				} else if (s->app.id == result->id) { /* current classifier agrees with previous classifiers */
					/* Increase confidence */
					s->app.confidence += result->confidence / enabled_classifiers;
				} else {		/* current classifier disagrees with previous classifiers */
					/* Decrease confidence */
					s->app.confidence /= 2;
				}
			}
			free(result);
		}

		/*
		 * At the end of this code block the session will be flagged with one of the following:
		 * - SESS_RECLASSIFY
		 * - SESS_DONT_CLASSIFY
		 * - SESS_CLASSIFIED
		 */
		if (TEST_BIT(s->flags, SESS_RECLASSIFY, 1)) {
			/*
			 * If it's realtime mode and we received at least two pkts with payload:
			 * - force to not attempt any reclassifications 
			 * - set the session either in DON'T CLASSIFY -- if it was an unknown 
			 * - or to CLASSIFIED if otherwise
			 */
			if (pv.wmode == MODE_REALTIME && s->pl_pkts > 2) {
				SET_BIT(s->flags, s->app.confidence == 0 ? SESS_DONT_CLASSIFY : SESS_CLASSIFIED, 1);
				SET_BIT(s->flags, SESS_RECLASSIFY, 0);
				if (s->app.id == 0) {
					class_miss++;
				} else {
					class_hits++;
				}
				class_forced++;
			}
			/* Otherwise implicitly let the SESS_RECLASSIFY flag set */
		} else if (s->app.id == 0) {
			SET_BIT(s->flags, SESS_DONT_CLASSIFY, 1);
			class_miss++;
		} else {
			SET_BIT(s->flags, SESS_CLASSIFIED, 1);
			class_hits++;
		}
		PRINTDD("FLAGS after: %08X\n", s->flags);
		break;
	}
	case SESS_TYPE_BIFLOW: {
		struct biflow *s = sess;

		PRINTDD("FLAGS before: %08X\t", s->flags);
		SET_BIT(s->flags, SESS_RECLASSIFY, 0);
		s->app.confidence = 0;
		/*
		 * For every classifier
		 */
		for (i = 0; i < num_classifiers; i++) {
			/* Skip current classifier if disabled */
			if (TEST_BIT(*classifiers[i].flags, CLASS_ENABLE, 0))
				continue;

			/* Skip current classifier if cannot attempt classification */
			if (! classifiers[i].is_session_classifiable(s))
				continue;

			/* Perform classification */
			result = classifiers[i].classify_session(s);

			/* If current classifier wants to retry classification process set SESS_RECLASSIFY */
			if (TEST_BIT(result->flags, CLASS_OUT_REDO, 1))
				SET_BIT(s->flags, SESS_RECLASSIFY, 1);

			/*
			 * If current classifier gives a result != UNKNOWN then apply the following priority scheme:
			 * - Classifiers priority is given by the order in which they are called
			 * - The output class is determined by the first classifier that recognizes the session
			 * - Agreement or disagreement of subsequent classifiers only affects output confidence.
			 */
			if (TEST_BIT(result->flags, CLASS_OUT_ERR, 0) && (result->id != 0)) {
				if ( (s->app.id == 0) || (s->id_class == i ) ) { /* the previous classifiers did not recognize the session or result was set by the current classifier in a previous classification round (SESS_RECLASSIFY was set) XXX: biflows only */
					s->id_class = i;
					s->app.id = result->id;
					s->app.subid = result->subid;
					s->app.confidence += result->confidence / enabled_classifiers;
				} else if (s->app.id == result->id) {	/* current classifier agrees with previous classifiers */
					/* Increase confidence */
					s->app.confidence += result->confidence / enabled_classifiers;
				} else {				/* current classifier disagrees with previous classifiers */
					/* Decrease confidence */
					s->app.confidence /= 2;
				}
			}

			free(result);
		}

		/*
		 * At the end of this code block the session will be flagged with one of the following:
		 * - SESS_RECLASSIFY
		 * - SESS_DONT_CLASSIFY
		 * - SESS_CLASSIFIED
		 */
		if (TEST_BIT(s->flags, SESS_RECLASSIFY, 1)) {		/* session will be reclassified */
			/*
			 * If it's realtime mode and we received at least two pkts with payload:
			 * - force to not attempt any reclassifications 
			 * - set the session either in DON'T CLASSIFY -- if it was an unknown 
			 * - or to CLASSIFIED if otherwise
			 */
			if (pv.wmode == MODE_REALTIME && s->dw_pl_pkts + s->up_pl_pkts > 2) {
				SET_BIT(s->flags, s->app.confidence == 0 ? SESS_DONT_CLASSIFY : SESS_CLASSIFIED, 1);
				SET_BIT(s->flags, SESS_RECLASSIFY, 0);
				if (s->app.id == 0) {
					class_miss++;
				} else {
					class_hits++;
				}
				class_forced++;
			}
			/* Otherwise implicitly let the SESS_RECLASSIFY flag set */
		} else if (s->app.id == 0) {				/* session won't be reclassified and is unknown */
			SET_BIT(s->flags, SESS_DONT_CLASSIFY, 1);
			class_miss++;
		} else {						/* session won't be reclassified and is known */
			SET_BIT(s->flags, SESS_CLASSIFIED, 1);
			class_hits++;
		}
		PRINTDD("FLAGS after: %08X\n", s->flags);
	} 
	} 
	return 0;
}

