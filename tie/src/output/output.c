/*
 *  src/output/output.c - Component of the TIE v1.0.0-beta3 platform 
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
#include <stdlib.h>
#include <pcap.h>
#include <time.h>
#include <sys/time.h>
#include <string.h>
#include <unistd.h>

#include "../common/common.h"
#include "../common/utils.h"
#include "../common/session.h"
#include "../class/plugin_manager.h"
#include "../biflow/biflow_table.h"
#include "../flow/flow_table.h"
#include "../host/host_table.h"
#include "../common/apps.h"
#include "output.h"
#include "remote_output.h"

/*
 * Constants
 */
#define MAX_STRING_SIZE		255


/*
 * Global variables
 */
FILE *class_out;		/* Classification output file pointer */
char *command_line = NULL;	/* Command-line string */
bool header = false;		/* True if table header has been generated */

/*
 * Dump a report to file
 */
FILE *dump_report(char *filename)
{
	FILE *fs;
	char path[MAX_STRING_SIZE];
	struct timeval diff;

	snprintf(path, MAX_STRING_SIZE, "%s/%s", pv.directory, filename);
	fs = fopen(path, "w");
	if (fs == NULL) {
		perror("dump_report");
		return (NULL);
	}

	/* Command line */
	fprintf(fs, "command line: %s\n", command_line);

	/* Time */
	fprintf(fs, "\n");
	tvsub(&diff, stats.tv_end, stats.tv_start);
	fprintf(fs, "Time interval of observation: %ld seconds (%ld min - %ld h)\n", diff.tv_sec, diff.tv_sec / 60, diff.tv_sec / 3600);
	fprintf(fs, "First examined packet had timestamp:\t%s", asctime(gmtime((time_t *)&(stats.tv_start.tv_sec))));
	fprintf(fs, "Last examined packet had timestamp:\t%s", asctime(gmtime((time_t *)&(stats.tv_end.tv_sec))));
	fprintf(fs, "Packet processing started at:\t\t%s", asctime(gmtime(&(stats.cpu_start))));
	fprintf(fs, "Packet processing finished at:\t\t%s", asctime(gmtime(&(stats.cpu_end))));
	if (stats.interrupted)
		fprintf(fs, "Program execution was INTERRUPTED BY USER (CTRL-C)\n");

	/* Packets */
	fprintf(fs, "\n");
	fprintf(fs, "packets read:\t\t\t\t%qu\n", stats.pkts);
	fprintf(fs, "mean throughput:\t\t\t%lu pkts/sec\n", (u_long) (stats.pkts / (diff.tv_sec + ((float) diff.tv_usec / 1000000))));
	fprintf(fs, "\n");
	fprintf(fs, "packets discarded:\t\t\t%qu\n", stats.discarded);
	PRINTDD(fs, "fragments:\t\t\t\t%qu\n", stats.frags);
	PRINTDD(fs, "packets were found truncated (damaged):\t%qu\n", stats.truncated);
	PRINTDD(fs, "packets with optional IP headers:\t%qu\n", stats.ip_options);
	PRINTDD(fs, "packets had invalid tcp payload:\t%qu\n", stats.err_payload);
	fprintf(fs, "\n");

	/* Classification */
	/* dump_statistics(fs); */

	return (fs);
}

/*
 * Dump some statistics to stdout
 */
void display_stats()
{
	struct timeval diff;

	printf("\n");
	tvsub(&diff, stats.tv_end, stats.tv_start);
	printf("Time interval of observation: %ld seconds (%ld min - %ld h)\n", diff.tv_sec, diff.tv_sec / 60, diff.tv_sec / 3600);
	printf("%qu packets read\n", stats.pkts);
	printf("mean throughput: %lu pkts/sec\n", (u_long) (stats.pkts / (diff.tv_sec + ((float) diff.tv_usec / 1000000))));
	printf("\n");
	printf("%qu packets discarded\n", stats.discarded);
	PRINTD("%qu packets were fragments\n", stats.frags);
	PRINTD("%qu packets were found truncated (damaged)\n", stats.truncated);
	PRINTD("%qu packets had invalid tcp payload\n", stats.err_payload);
	PRINTD("%qu packets had optional IP headers\n", stats.ip_options);
	printf("\n");

}

/*
 * Open the log file to store classification results
 */
void open_log_file()
{
	char name[MAX_STRING_SIZE];
	int i, j;

	header = false;
	if (pv.wmode == MODE_CYCLIC) {
		sprintf(name, "%s/%s.%ld", pv.directory, pv.class_out_file, stats.tv_last_cycle.tv_sec);
	} else {
		sprintf(name, "%s/%s", pv.directory, pv.class_out_file);
	}
	class_out = fopen(name, "w");
	if (class_out == NULL) {
		printf("Unable to open output file");
		exit(2);
	}

	/* Parse command line and store it */
	if (command_line == NULL) {
		for (i = 0, j = 0; i < g_argc; i++) {
			sprintf(&name[j], "%s ", g_argv[i]);
			j += strlen(g_argv[i]) + 1;
		}
		command_line = strdup(name);
	}

	/*
	 * Write log header
	 */
	fprintf(class_out, "# tie output version: 1.0 (text format)\n" "# generated by: %s\n\n", command_line);
	fprintf(class_out, "# Working Mode: %s\n", pv.wmode == MODE_OFFLINE ? "off-line" :
						   pv.wmode == MODE_REALTIME ? "real-time" : "cyclic");
	fprintf(class_out, "# Session Type: %s\n", pv.stype == SESS_TYPE_BIFLOW ? "biflow" :
						   pv.stype == SESS_TYPE_FLOW ? "flow" : "host");

	/* Print enabled plug-ins names */
	fprintf(class_out, "# %d plugins enabled: ", enabled_classifiers);
	for (i = 0; i < num_classifiers; i++) {
		if (TEST_BIT(*classifiers[i].flags, CLASS_ENABLE, 1))
			fprintf(class_out, "%s ", classifiers[i].name);
	}
}

/*
 * Write classification result to file
 */
void store_result(void *session, int mode)
{
	pipe_message msg;

	if (!header) {
		if (TEST_BIT(mode, DUMP_INTERVAL, 1)) {
			fprintf(class_out, "\n\n# begin trace interval: %ld.%ld\n",
			    stats.tv_last_cycle.tv_sec, stats.tv_last_cycle.tv_usec);
			fprintf(class_out, "# trace interval duration: %u s\n", pv.cycle);
		} else {
			fprintf(class_out, "\n\n# begin trace interval: %ld.%ld\n",
			    stats.tv_start.tv_sec, stats.tv_start.tv_usec);
		}

		fprintf(class_out, "\n# begin TIE Table\n"
			"# id\tsrc_ip\t\tdst_ip\t\tproto\tsport\tdport\t"
			"dwpkts\tuppkts\tdwbytes\tupbytes\t" "t_start\t\t\tt_last\t\t\tapp_id\tsub_id\tconfidence\n");
		header = true;
	}

	switch (pv.stype) {
	case SESS_TYPE_HOST:
		{
			break;
		}
	case SESS_TYPE_FLOW:
		{
			struct flow *s = session;
			ssize_t ret;

			fprintf(class_out, "%lu\t", (long unsigned int) s->id);
			fprintf(class_out, "%s\t", inet_ntoa(s->f_tuple.src_ip));
			fprintf(class_out, "%s\t", inet_ntoa(s->f_tuple.dst_ip));
			fprintf(class_out, "%d\t%d\t%d\t", s->f_tuple.l4proto, s->f_tuple.src_port, s->f_tuple.dst_port);
			if (TEST_BIT(mode, DUMP_INTERVAL, 0)) {
				fprintf(class_out, "-\t%lu\t-\t%llu\t", (long unsigned int) s->pkts, (long long unsigned int) s->bytes);
			} else {
				fprintf(class_out, "-\t%lu\t-\t%llu\t",
					(long unsigned int) (s->pkts - s->old_cycle->pkts),
					(long long unsigned int) (s->bytes - s->old_cycle->bytes));
				s->old_cycle->pkts = s->pkts;
				s->old_cycle->bytes = s->bytes;
			}
			fprintf(class_out, "%lu.%06lu\t%lu.%06lu\t", s->ts_start.tv_sec, s->ts_start.tv_usec, s->ts_last.tv_sec, s->ts_last.tv_usec);

			if (pv.labels) {
				fprintf(class_out, "%s\t%s\t%d\n", apps[s->app.id].label, apps[s->app.id].sub_id[s->app.subid].sub_label,
					s->app.confidence);
			} else {
				fprintf(class_out, "%u\t%u\t%d\n", s->app.id, s->app.subid, s->app.confidence);
			}

			/*
			 * Remote output generation (unknown are skipped)
			 */
			if (pv.rh_addr.s_addr != 0 && TEST_BIT(s->flags, SESS_CLASSIFIED, 1)) {
				msg_class *body = malloc(sizeof(msg_class));
				body->f_tuple = s->f_tuple;
				body->app = s->app;
				body->timestamp = s->ts_last.tv_sec;
				msg.type = MSG_CLASS;
				msg.body = body;
				ret = write(pv.ro_pipe, &msg, sizeof(pipe_message));
			}

			break;
		}
	case SESS_TYPE_BIFLOW:
		{
			struct biflow *s = session;
			ssize_t ret;

			fprintf(class_out, "%lu\t", s->id);
			fprintf(class_out, "%s\t", inet_ntoa(s->f_tuple.src_ip));
			fprintf(class_out, "%s\t", inet_ntoa(s->f_tuple.dst_ip));
			fprintf(class_out, "%d\t%d\t%d\t", s->f_tuple.l4proto, s->f_tuple.src_port, s->f_tuple.dst_port);
			if (TEST_BIT(mode, DUMP_INTERVAL, 0)) {
				fprintf(class_out, "%lu\t%lu\t%lu\t%lu\t", s->dw_pkts, s->up_pkts, s->dw_bytes, s->up_bytes);
			} else {
				fprintf(class_out, "%lu\t%lu\t%lu\t%lu\t", s->dw_pkts - s->old_cycle->dw_pkts, s->up_pkts - s->old_cycle->up_pkts,
					s->dw_bytes - s->old_cycle->dw_bytes, s->up_bytes - s->old_cycle->up_bytes);
				s->old_cycle->dw_pkts = s->dw_pkts;
				s->old_cycle->dw_bytes = s->dw_bytes;
				s->old_cycle->up_pkts = s->up_pkts;
				s->old_cycle->up_bytes = s->up_bytes;
			}
			fprintf(class_out, "%lu.%06lu\t%lu.%06lu\t", s->ts_start.tv_sec, s->ts_start.tv_usec, s->ts_last.tv_sec, s->ts_last.tv_usec);

			if (pv.labels) {
				fprintf(class_out, "%s\t%s\t%d\n", apps[s->app.id].label, apps[s->app.id].sub_id[s->app.subid].sub_label,
					s->app.confidence);
			} else {
				fprintf(class_out, "%u\t%u\t%d\n", s->app.id, s->app.subid, s->app.confidence);
			}

			/*
			 * Remote output generation (unknown are skipped)
			 */
			if (pv.rh_addr.s_addr != 0 && TEST_BIT(s->flags, SESS_CLASSIFIED, 1)) {
				msg_class *body = malloc(sizeof(msg_class));
				body->f_tuple = s->f_tuple;
				body->app = s->app;
				body->timestamp = s->ts_last.tv_sec;
				msg.type = MSG_CLASS;
				msg.body = body;
				ret = write(pv.ro_pipe, &msg, sizeof(pipe_message));
			}

			break;
		}
	}

	fflush(class_out);
}
