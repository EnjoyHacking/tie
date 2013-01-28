/*
 *  src/tie.c - Component of the TIE v1.0.0-beta3 platform 
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
 * Dependencies
 */
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <string.h>
#include <pcap.h>
#include <signal.h>
#include <time.h>
#include <libgen.h>

#include "common/pkt_macros.h"
#include "common/common.h"
#include "common/utils.h"
#include "common/hashtab.h"
#include "common/apps.h"
#include "common/session.h"
#include "class/class.h"
#include "class/preclassification.h"
#include "class/combiner.h"
#include "class/plugin_manager.h"
#include "class/features.h"
#include "output/remote_output.h"
#include "output/output.h"
#include "host/host_output.h"
#include "flow/flow_output.h"
#include "biflow/biflow_output.h"
#include "plugins/plugin.h"

/*
 * These lines are necessary to have visibility of the pcap_t structure
 */
#define HAVE_SNPRINTF
#define HAVE_VSNPRINTF
#define HAVE_STRLCPY
#include "common/pcap-int.h"


/*
 * Constants and Macros
 */
#define PROMISC				1
#define TIMEOUT				500
#define _FILE_OFFSET_BITS		64
#define DEFAULT_SNAPLEN			1518

#define TICK(ts, sec)			(ts - (ts % sec))	/* find the nearest previous tick, with a resolution of sec */


/*
 * Private functions
 */
int init_program();
int load_host_table();
int ht_process_packet(u_char *, const struct pcap_pkthdr);
int ft_process_packet(u_char *, const struct pcap_pkthdr);
int bt_process_packet(u_char *, const struct pcap_pkthdr);
void cleanup(int);
void parse_command_line(int, char **);
int filter_packet(u_char *, const struct pcap_pkthdr);
char *read_infile(char *);
void print_help();


/*
 * Global variables
 */
/* From <unistd.h> for getopt() */
extern char *optarg;
extern int optind;

/* Hash tables for different session types  */
struct ht_entry *host_table[HOST_TABLE_SIZE];
struct ft_entry *flow_table[FLOW_TABLE_SIZE];
struct bt_entry *biflow_table[BIFLOW_TABLE_SIZE];

/* Options and statistics */
program_variables pv;
statistics stats;
sessions_statistics session_stats;

/* Exported command-line parameters */
int g_argc;
char **g_argv;

/* Others */
char tie_path[MAX_BUFFER];
uid_t uid = 0;			/* Sudoer User ID */
gid_t gid = 0;			/* Sudoer Group ID */
pcap_dumper_t *dumpd = NULL;
int loop = 1;


/*
 * Print command-line help
 */
void print_help()
{
	printf("MAIN OPTIONS:\n");
	printf("\n");
	printf("-m mode	    set the operating mode.\n");
	printf("            mode can be:\n");
	printf("                'o'  for offline mode (default)\n");
	printf("                'c'  for cyclic mode\n");
	printf("                'r'  for realtime mode\n");
	printf("-q type	    session type definition.\n");
	printf("            type can be:\n");
	printf("                'h'  for host\n");
	printf("                'f'  for flow\n");
	printf("                'b'  for biflow (default)\n");
	printf("-t num      set sessions timeout (in seconds)\n");
	printf("-i if       read packets from interface 'if'\n");
	printf("-r file     read traffic from 'file' in pcap format\n");
	printf("-l trsld    enable classifiers training using 'trsld' as threshold value (disables classification)\n");
	printf("-k          enable classification when -l option is specified\n");
	printf("-s num      set snaplen when capturing traffic\n");
	printf("\n");
	printf("FEATURE RELATED OPTIONS:\n");
	printf("\n");
	printf("-p num      store the first 'num' payload sizes of each session\n");
	printf("-b num      store the first 'num' packet sizes of each session\n");
	printf("-P num      store payload content of first packet in each direction (only num bytes per packet)\n");
	printf("-S num      store num bytes of payloads stream per session\n");
	printf("-I num	    save the first 'num' IPTs of each session\n");
	printf("\n");
	printf("FILTERING OPTIONS:\n");
	printf("\n");
	printf("-C num      skip the first 'num' packets\n");
	printf("-c num      stop after 'num' packets\n");
	printf("-D 0-6      consider only packets from a specific day of week\n");
	printf("-F path     use BPF file specified in 'path' to filter out packets\n");
	printf("-T string   set a specific time range you want analyze. Time range is a string must be in the form 'hh:mm-HH:MM'\n");
	printf("-Z num      set a custom timezone offset\n");
	printf("-f          disable filter\n");
	printf("\nTcpdump/bpf style filters can be specified at the end of the command line\n");
	printf("(e.g. for HTTP launch: \"./tie [options] tcp port 80\").\n");
	printf("\n");
	printf("OTHER OPTIONS:\n");
	printf("\n");
	printf("-a num      set cyclic mode interval duration in seconds\n");
	printf("-d path     output directory\n");
	printf("-e file     classification results input file name\n");
	printf("-E file     classification results ouput file name\n");
	printf("-L suffix   set the suffix to append to file containing training result\n");
	printf("-h          print help and exit\n");
	printf("-H path     read host table from file\n");
	printf("-M num      perform periodical dump of data and garbage collection each num packets (default 10k pkts)\n");
	printf("-o ip port  enable classification notifications toward a remote host\n");
	printf("-O          use persistent connection to a remote host\n");
	printf("-n          write classification output using labels instead of IDs\n");
	printf("-w path     dump traffic to file 'pathtofile'\n");
	printf("-W num      dump packet contents in pcap file containing up to L4 headers plus 'num' bytes of payload\n");
	printf("-x          enable TCP heuristics (watching SYN/FIN flags)\n");
	printf("\n");
}

/*
 * Initialize program optional parameters and set them by parsing command line arguments.
 */
void parse_command_line(int argc, char **argv)
{
	int c;

	/* Set global command line info */
	g_argc = argc;
	g_argv = argv;

	/* Setting of default options */
	memset(&pv, 0, sizeof(program_variables));	/* Set to 0/NULL/false all variables */
	pv.snaplen = DEFAULT_SNAPLEN;
	pv.directory = "output";
	pv.dump_headers = -1;
	pv.day_of_week = -1;
	pv.tz = -1;
	pv.stype = SESS_TYPE_BIFLOW;
	pv.wmode = MODE_OFFLINE;
	pv.class_out_file = "class.tie";
	pv.labels = false;
	pv.cycle = 300;
	pv.clean_interval = 100000;
	pv.session_timeout = 60;

	while ((c = getopt(argc, argv, "a:b:C:c:D:d:E:e:F:fhH:i:I:kl:L:m:M:nOo:p:P:q:r:s:S:T:t:W:w:xZ:")) != EOF) {
		switch (c) {
		case 'a':
			pv.cycle = atoi(optarg);
			break;
		case 'b':
			pv.pktsize = atoi(optarg);
			break;
		case 'C':
			pv.start_pkts = atoi(optarg);
			break;
		case 'c':
			pv.stop_pkts = atoi(optarg);
			break;
		case 'D':
			pv.day_of_week = atoi(optarg);	/* 0-6 = Sun/Mon/Tue/Wed/Thu/Fri/Sat */
			break;
		case 'd':
			pv.directory = optarg;
			break;
		case 'e':
			pv.pre_class_file = optarg;
			break;
		case 'E':
			pv.class_out_file = optarg;
			break;
		case 'f':
			pv.filter_disable = 1;
			break;
		case 'F':
			pv.filter_file = optarg;
			break;
		case 'h':
			print_help();
			exit(EXIT_FAILURE);
			break;
		case 'H':
			pv.hosttable = optarg;
			break;
		case 'i':
			pv.device = optarg;
			break;
		case 'I':
			pv.ipts = atoi(optarg);
			break;
		case 'k':
			pv.class = true;
			break;
		case 'l':
			pv.training = atoi(optarg);
			pv.class = false;
			break;
		case 'L':
			pv.sign_suffix = optarg;
			break;
		case 'm':
			if (!strncmp(optarg, "o", 1))
				pv.wmode = MODE_OFFLINE;
			else if (!strncmp(optarg, "c", 1))
				pv.wmode = MODE_CYCLIC;
			else if (!strncmp(optarg, "r", 1))
				pv.wmode = MODE_REALTIME;
			else
				pv.wmode = MODE_REALTIME;
			break;
		case 'M':
			pv.clean_interval = atoi(optarg);
			if (pv.clean_interval < 10000 && pv.clean_interval != 0) {
				pv.clean_interval = 10000;
				printf("Warning: cleaning interval forced to 10k packets\n");
			}
			break;
		case 'n':
			pv.labels = false;
			break;
		case 'O':
			pv.rh_keep_alive = true;
			break;
		case 'o':
			if (inet_aton(optarg, &pv.rh_addr) != 1) {
				printf("Error in Remote Host address syntax\n");
				exit(EXIT_FAILURE);
			}
			if (argc > optind && IS_DIGIT(argv[optind][0]))
				pv.rh_port = atoi(argv[optind++]);
			else {
				printf("Error in Remote Host port syntax\n");
				exit(EXIT_FAILURE);
			}
			PRINTD("Remote Host: %s %d\n", inet_ntoa(pv.rh_addr), pv.rh_port);
			break;
		case 'p':
			pv.psize = atoi(optarg);
			break;
		case 'P':
			pv.pl_inspect = atoi(optarg);
			break;
		case 'q':
			if (!strncmp(optarg, "h", 1))
				pv.stype = SESS_TYPE_HOST;
			else if (!strncmp(optarg, "f", 1))
				pv.stype = SESS_TYPE_FLOW;
			else if (!strncmp(optarg, "b", 1))
				pv.stype = SESS_TYPE_BIFLOW;
			else
				pv.stype = SESS_TYPE_BIFLOW;
			break;
		case 'r':
			pv.sourcefile[pv.readmode] = optarg;
			PRINTDD("sourcefile: %s\n", pv.sourcefile[pv.readmode]);
			pv.readmode++;
			break;
		case 's':
			pv.snaplen = atoi(optarg);
			break;
		case 'S':
			pv.stream_len = atoi(optarg);
			break;
		case 't':
			pv.session_timeout = atoi(optarg);
			break;
		case 'T':
			pv.time_range = 1;
			if (string_to_time_range(optarg, &pv.tr_hmin, &pv.tr_mmin, &pv.tr_hmax, &pv.tr_mmax) < 0) {
				printf("Error in selected timerange syntax\n");
				exit(EXIT_FAILURE);
			}
			break;
		case 'W':
			pv.dump_headers = atoi(optarg);
			break;
		case 'w':
			pv.destfile = optarg;
			pv.writemode = 1;
			break;
		case 'x':
			pv.tcp_heuristics = true;
			printf("TCP heuristics enabled\n");
			break;
		case 'Z':
			pv.tz = atoi(optarg);	/* seconds ! (es. 3600) */
			printf("User requested timezone offset: %d\n", pv.tz);
			break;
		default:
			print_help();
			exit(EXIT_FAILURE);
		}
	}

	/*
	 * Overall options control
	 */
	/* By default enable classification */
	if (pv.training == 0 && pv.class == false) {
		pv.class = true;
	}

	/* Classification enabled only with biflow session type. TODO: extend to other session types */
	if (pv.class && pv.stype != SESS_TYPE_BIFLOW && pv.stype != SESS_TYPE_FLOW) {
		printf("ERROR: Classification is currently available only with biflow and flow session type.\n");
		exit(EXIT_FAILURE);
	}

	/* Check root permissions when capturing from physical interfaces */
	if (pv.readmode == 0 && getuid() > 0) {
		printf("ERROR: Root permissions needed to capture from physical interfaces!\n");
		exit(EXIT_FAILURE);
	}

	/*
	 * TODO: Display used options
	 */
	printf("Working mode: %s\n", pv.wmode == MODE_OFFLINE ? "Offline" :
				     pv.wmode == MODE_REALTIME ? "RealTime" : "Cyclic");
}

/*
 * Perform initializations based on working mode
 */
int init_program()
{
	char *dir;
	int ret;

	/* Set all stats to 0 */
	memset(&stats, 0, sizeof(stats));

	/* Get sudoer ID */
	if (getenv("SUDO_USER")) {
		uid = atoi(getenv("SUDO_UID"));
		gid = atoi(getenv("SUDO_GID"));
	}

	/* Get TIE base dir */
	if (!access("tie", X_OK) && !access("tie_apps.txt", R_OK)) {
		sprintf(tie_path, ".");
	} else if ((dir = getenv("TIE_BASE_DIR")) != NULL) {
		strncpy(tie_path, dir, MAX_BUFFER);
	} else if ((ret = readlink(TIE_SYM_LINK, tie_path, MAX_BUFFER)) != -1) {
		dir = dirname(tie_path);
		strncpy(tie_path, dir, MAX_BUFFER);
	} else {
		printf("Unable to find TIE path!\n");
		printf("(you might want to set the TIE_BASE_DIR \n");
		printf(" environment variable to TIE binary directory.)\n");
		exit(1);
	}
	printf("TIE path: %s\n", tie_path);

	/* Create output directory */
	mkdir(pv.directory, 0777);
	ret = chown(pv.directory, uid, gid);


	/* Perform init according to working mode */
	switch (pv.stype) {
	case SESS_TYPE_HOST:
		ht_init_table(host_table);
		memset(&hoststats, 0, sizeof(hoststats));
		break;
	case SESS_TYPE_FLOW:
		ht_init_table(host_table);
		memset(&hoststats, 0, sizeof(hoststats));
		ft_init_table(flow_table);
		memset(&session_stats, 0, sizeof(session_stats));
		break;
	case SESS_TYPE_BIFLOW:
		ht_init_table(host_table);
		memset(&hoststats, 0, sizeof(hoststats));
		bt_init_table(biflow_table);
		memset(&session_stats, 0, sizeof(session_stats));
		break;
	}
	return (1);
}

/*
 * Load host table from file
 */
int load_host_table()
{
	FILE *fs;
	u_long hostID;
	char buffer[51], *b;
	u_char hostIP[4];

	/* we need to init the host table with data from file */
	printf("Init Host Table\n");

	fs = fopen(pv.hosttable, "r");
	if (fs == NULL) {
		perror("init_host_table");
		return (-1);
	}

	b = fgets(buffer, 50, fs);
	while (feof(fs) == 0) {
		sscanf(buffer, "%hhu.%hhu.%hhu.%hhu %lu", &(hostIP[0]), &(hostIP[1]), &(hostIP[2]), &(hostIP[3]), &hostID);
		ht_populate_entry(hostIP, hostID, host_table);
		b = fgets(buffer, 50, fs);
	}

	fclose(fs);
	printf("Completed: %lu hosts read\n", hoststats.ht_entries);
	return (1);
}

/*
 * Packet capture loop
 */
int main_loop(pcap_t * p)
{
	u_char *packet;
	struct pcap_pkthdr h;

	loop = 1;
	while (loop) {
		/*
		 *  pcap_next() gives us the next packet from pcap's internal packet buffer.
		 */
		packet = (u_char *) pcap_next(p, &h);
		if (packet == NULL) {
			/*
			 *  We have to be careful here as pcap_next() can return NULL
			 *  if the timer expires with no data in the packet buffer or
			 *  in some special circumstances with linux.
			 */
			if (!pv.readmode) {
				continue;
			} else {
				loop = 0;
				continue;
			}
		}

		/*
		 * Increment packets counter
		 */
		if (++stats.pkts == 0) {
			printf("WARNING: Packets Number Overflow!\n");
		}

		/*
		 * Start to process only after # packets, if specified by user
		 */
		if (pv.start_pkts != 0 && stats.pkts < pv.start_pkts) {
			continue;
		}

		/*
		 * Update first and last packet timestamps.
		 * Also, some inits must be done when the first packet is seen.
		 */
		if (stats.tv_start.tv_sec == 0) {
			stats.tv_start = h.ts;
			session_stats.tv_last_session = h.ts;
			hoststats.tv_last_pkt = h.ts;
			hoststats.tv_last_host = h.ts;
			hoststats.tv_last_shost = h.ts;
			hoststats.tv_last_dhost = h.ts;
			stats.tv_last_cycle = h.ts;		/* initialize timestamp for cyclic mode */
		}
		stats.tv_end = h.ts;

		/*
		 * Stop processing after # packets, if specified by user
		 */
		if (pv.stop_pkts != 0 && stats.pkts > pv.stop_pkts) {
			loop = 0;
			stats.pkts--;
			continue;
		}

		PRINTDD("cap: %d wire: %d iptlen: %d\n", h.caplen, h.len, PKT_IP_TLEN_B(packet + stats.frame_offset));

		/*
		 * Print some information each PRINT_STATUS good pkts sniffed
		 */
		if ((stats.pkts - stats.bad_pkts) % PRINT_STATUS == 0) {
			char *ts = asctime(tztime((time_t *)&h.ts.tv_sec));
			ts[strlen(ts) - 1] = '\0';

			printf("[%s] pkts: %qu - ", ts, stats.pkts);

			switch (pv.stype) {
			case SESS_TYPE_HOST:
				printf("src hosts: %lu - dst hosts: %lu\n", hoststats.ht_src_entries, hoststats.ht_dst_entries);
				break;
			case SESS_TYPE_FLOW:
				printf("total flows:  %qu\n", session_stats.sessions);
				break;
			case SESS_TYPE_BIFLOW:
				printf("total biflows:  %qu\n", session_stats.sessions);
				break;
			}

		}

		/*
		 * If we disable filtering we cannot process packets because packet processor
		 * doesn't know how to work with some kind of packets.
		 */
		if (!pv.filter_disable) {
			/* Filter packet */
			if (filter_packet(packet, h)) {
				stats.discarded++;
				continue;
			} else {
				/* Process packet */
				switch (pv.stype) {
				case SESS_TYPE_HOST:
					ht_process_packet(packet, h);
					break;
				case SESS_TYPE_FLOW:
					ft_process_packet(packet, h);
					break;
				case SESS_TYPE_BIFLOW:
					bt_process_packet(packet, h);
					break;
				}
			}
		}

		/*
		 * Periodical dump & garbage collection
		 */
		if (((pv.wmode != MODE_CYCLIC) && (pv.clean_interval && stats.pkts % pv.clean_interval == 0)) ||
		    ((pv.wmode == MODE_CYCLIC) && (h.ts.tv_sec - stats.tv_last_cycle.tv_sec > pv.cycle))) {
#ifdef DEBUG
			u_quad_t sessions_before = session_stats.table_sessions;
#endif

			switch (pv.wmode) {
			case MODE_OFFLINE:
				switch (pv.stype) {
				case SESS_TYPE_HOST:
					break;
				case SESS_TYPE_BIFLOW:
					bt_dump_biflows_data(biflow_table, DUMP_EXPIRED | FREE_EXPIRED);
					break;
				case SESS_TYPE_FLOW:
					ft_dump_flows_data(flow_table, DUMP_EXPIRED | FREE_EXPIRED);
					break;
				}
				break;
			case MODE_REALTIME:
				switch (pv.stype) {
				case SESS_TYPE_HOST:
					break;
				case SESS_TYPE_BIFLOW:
					bt_dump_biflows_data(biflow_table, FREE_EXPIRED);
					break;
				case SESS_TYPE_FLOW:
					ft_dump_flows_data(flow_table, FREE_EXPIRED);
					break;
				}
				break;
			case MODE_CYCLIC:
				switch (pv.stype) {
				case SESS_TYPE_HOST:
					break;
				case SESS_TYPE_BIFLOW:
					bt_dump_biflows_data(biflow_table, DUMP_INTERVAL | FREE_EXPIRED);
					break;
				case SESS_TYPE_FLOW:
					ft_dump_flows_data(flow_table, DUMP_INTERVAL | FREE_EXPIRED);
					break;
				}
				fprintf(class_out, "# end of text table\n");
				fclose(class_out);
				stats.tv_last_cycle.tv_sec = h.ts.tv_sec; 	/* update timestamp of last cycle */
				stats.tv_last_cycle.tv_usec = h.ts.tv_usec; 	/* update timestamp of last cycle */
				open_log_file();

				break;
			}

			/* Print garbage collection statistics */
			PRINTD("[Garbage Collector] Sessions in memory: %qu -> %qu\n", sessions_before, session_stats.table_sessions);
		}

		/*
		 * Dump pkt on a file in tcpdump format
		 */
		if (pv.writemode) {
			/*
			 * Truncate packet before dump.
			 */
			if (pv.dump_headers != -1) {
				u_char *ip = packet + stats.frame_offset;

				if (L4_PROTO(ip) == L4_PROTO_TCP) {
					/* Stop at the end of TCP header + pv.dump_headers */
					h.caplen = MIN(h.caplen, stats.frame_offset + PKT_IP_HLEN_B(ip) + PKT_TCP_HLEN_B(ip) + pv.dump_headers);
				} else if (L4_PROTO(ip) == L4_PROTO_UDP) {
					/* Stop at the end of UDP header + pv.dump_headers */
					h.caplen = MIN(h.caplen, stats.frame_offset + PKT_IP_HLEN_B(ip) + PKT_UDP_HLEN_B + pv.dump_headers);
				}
			} else {
				/* Stop at user-supplied snaplen (it makes sense when reading from file) */
				h.caplen = MIN(h.caplen, pv.snaplen);
			}
			/*
			 * If requested zero out ip addresses to preserve privacy.
			 * Warning: checksums become wrong !
			 */
			if (pv.zero) {
				memset(&packet[12 + stats.frame_offset], 0, 8);
			}
			pcap_dump((u_char *) dumpd, &h, packet);
		}
	}					/* main loop */
	return (0);
}

/*
 * Main function
 */
int main(int argc, char **argv)
{
	pcap_t *p;				/* pcap descriptor */
	struct pcap_stat ps;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program filter_code;
	bpf_u_int32 local_net, netmask;
	bpf_u_int32 defaultnet = 0x00000000;	/* 0xFFFFFF00 */
	char *pcap_cmd;
	char *pcap_cmd2;
	int loops = 0;
	FILE *fs_report;

	/*
	 * Inits
	 */
	printf("************************************************************************\n");
	printf("* TIE %s [Traffic Identification Engine]\n", VERSION);
	printf("* Copyright (C) 2007-%s Alberto Dainotti,  Walter de Donato,\n", YEAR);
	printf("*                         Alessio Botta, Antonio Pescape'.\n");
	printf("* DIS - Dipartimento di Informatica e Sistemistica\n");
	printf("* University of Napoli Federico II\n");
	printf("* All rights reserved.\n");
	printf("*\n");
	printf("* This program is free software: you can redistribute it and/or modify\n");
	printf("* it under the terms of the GNU General Public License as published by\n");
	printf("* the Free Software Foundation, either version 3 of the License, or\n");
	printf("* (at your option) any later version.\n");
	printf("* \n");
	printf("* This program is distributed in the hope that it will be useful,\n");
	printf("* but WITHOUT ANY WARRANTY; without even the implied warranty of\n");
	printf("* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the\n");
	printf("* GNU General Public License for more details.\n");
	printf("* \n");
	printf("************************************************************************\n");

	parse_command_line(argc, argv);
	init_program();

	/*
	 * Load plug-ins and related signatures
	 */
	if (load_app_defs() > 0) {
		printf("\nLoaded %d application types.\n\n", app_count);
	} else {
		return 1;
	}
	num_classifiers = load_plugins();
	load_signatures();

	/*
	 * Load pre-classification from file
	 */
	if (pv.pre_class_file) {
		if (!load_pre_class()) {
			printf("Pre-classified applications: %d\n", pv.gt_app_count);
		} else {
			printf("Warning: Unable to load pre-classification\n");
		}
	}

	/*
	 *  We want to catch the interrupt signal so we can inform the user
	 *  how many packets we captured before we exit.
	 *  XXX We should probably clean up memory and free up the hashtable
	 *  before we go.
	 */
	if (catch_sig(SIGINT, cleanup) == -1) {
		fprintf(stderr, "can't catch SIGINT signal.\n");
		exit(EXIT_FAILURE);
	}

	/*
	 * Catch SIGHUP to null so we can detach from shell
	 */
	if (catch_sig(SIGHUP, hup) == -1) {
		fprintf(stderr, "can't catch SIGHUP signal.\n");
		exit(EXIT_FAILURE);
	}

	/*
	 *  If device is NULL, that means the user did not specify one and is
	 *  leaving it up libpcap to find one.
	 */
	if ((pv.device == NULL) && (!pv.readmode)) {
		pv.device = pcap_lookupdev(errbuf);
		if (pv.device == NULL) {
			fprintf(stderr, "pcap_lookupdev() failed: %s\n", errbuf);
			exit(EXIT_FAILURE);
		}
	}

	/*
	 * Create dispatcher thread if -o option is enabled
	 */
	if (pv.rh_addr.s_addr != 0) {
		pthread_t id;

		if (pthread_create(&id, NULL, dispatcher, NULL)) {
			printf("plab: error creating dispatcher thread!\n");
		}
	}

	/* Record start of packet processing date/time */
	stats.cpu_start = time(NULL);

	printf("<ctrl-c> (SIGINT) to quit\n\n");
	/*
	 * Repeat packet capturing loop for each source file.
	 * Do it just once for network sniffing.
	 */
	do {
		/*
		 *  Open the packet capturing device
		 */
		if (!pv.readmode) {
			printf("reading from device %s with snaplen %d\n", pv.device, pv.snaplen);
			*errbuf = '\0';
			p = pcap_open_live(pv.device, pv.snaplen, PROMISC, TIMEOUT, errbuf);
			if (p == NULL) {
				fprintf(stderr, "pcap_open_live() failed: %s\n", errbuf);
				exit(EXIT_FAILURE);
			}
			p->tzoff = (pv.tz != -1) ? pv.tz : 0;
			/* printf("Capturing with TimeZone offset: %d\n", p->tzoff); */
		} else {
			printf("reading from file %s\n", pv.sourcefile[loops]);
			p = pcap_open_offline(pv.sourcefile[loops], errbuf);
			if (p == NULL) {
				fprintf(stderr, "pcap_open_offline() failed: %s\n", errbuf);
				exit(EXIT_FAILURE);
			}
			PRINTDD("File has TimeZone offset: %d\n", p->tzoff);
		}

		/* Set the timezone offset used by program */
		if (pv.tz != -1) {
			printf("Using user requested timezone offset (%d)\n", pv.tz);
			stats.tzoff = pv.tz;
		} else {
			/* printf("Using pcap header timezone offset (%d) to store timestamps\n", p->tzoff);
			   stats.tzoff = p->tzoff; */
			stats.tzoff = 0;
		}

		/*
		 *  Set the BPF filter.
		 */
		if (pv.filter_file) {
			pcap_cmd2 = read_infile(pv.filter_file);
		} else {
			pcap_cmd2 = copy_argv(&argv[optind]);
		}

		/* Force filtering of IP packets only */
		if (pcap_cmd2) {
			pcap_cmd = malloc(strlen(pcap_cmd2) + 10);
			sprintf(pcap_cmd, "ip and (%s)", pcap_cmd2);
		} else {
			pcap_cmd = malloc(10);
			sprintf(pcap_cmd, "ip");
		}
                printf("pcap command: %s\n", pcap_cmd);

		if (pcap_lookupnet(pv.device, &local_net, &netmask, errbuf) == -1) {
			printf("pcap_lookupnet() failed: %s\n", errbuf);
			netmask = htonl(defaultnet);
		}
		if (pcap_compile(p, &filter_code, pcap_cmd, 1, netmask) == -1) {
			fprintf(stderr, "pcap_compile() failed: %s\n", pcap_geterr(p));
			pcap_close(p);
			exit(EXIT_FAILURE);
		}
		if (pcap_setfilter(p, &filter_code) == -1) {
			fprintf(stderr, "pcap_setfilter() failed: %s\n", pcap_geterr(p));
			pcap_close(p);
			exit(EXIT_FAILURE);
		}

		/* Check DataLink: TIE supports only Ethernet & RAW datalink */
		if (pcap_datalink(p) == DLT_EN10MB) {
			/* Ethernet */
			stats.frame_offset = 14;
		} else if (pcap_datalink(p) == DLT_RAW) {
			/* Raw */
			stats.frame_offset = 0;
		} else {
			stats.frame_offset = 14;
			printf("WARNING Datalink type not supported: %d %s \n", pcap_datalink(p),
			       pcap_datalink_val_to_name(pcap_datalink(p)));
		}

		/* Print info on source data link (defines are in libpcap/bpf/net/bpf.h) */
		printf("Datalink type: %s \n", pcap_datalink_val_to_name(pcap_datalink(p)));

		if (pv.hosttable) {
			load_host_table();
		}

		/*
		 * Open output dump file.
		 * Warning: If we read from multiple
		 * input files then they MUST have the same timezone and snaplen, otherwise behaviour
		 * is not consistent anymore. This happens because we copy some data from the first input
		 * file header to the output file header (look at pcap_dump() code in libpcap for more).
		 */
		if (pv.destfile != NULL) {
			dumpd = pcap_dump_open(p, pv.destfile);
			if (dumpd == NULL) {
				printf("error opening output file: %s\n", pcap_geterr(p));
				pcap_close(p);
				exit(EXIT_FAILURE);
			}
			printf("Writing to file %s\n", pv.destfile);
		}

		/* Open classification output file for logging */
		open_log_file();

		/*
		 * Packet capture loop: get packets and analyze them.
		 */
		main_loop(p);

		/*
		 *  Finished to examine packets. It's time to dump statistics.
		 */
		if (pcap_stats(p, &ps) == -1) {
			if (!pv.readmode)
				fprintf(stderr, "pcap_stats() failed: %s\n", pcap_geterr(p));
		} else {
			/*
			 *  Remember that the ps statistics change slightly depending on
			 *  the underlying architecture.  We gloss over that here.
			 */
			printf("\nPackets received by libpcap:\t%6d\n" "Packets dropped by libpcap:\t%6d\n", ps.ps_recv, ps.ps_drop);
		}

		pcap_close(p);
		loops++;

		/* Insert here identified application count */
	} while (loops < pv.readmode);

	/* XXX Everything from here should probably go in cleanup() .. */
	/* Record date when program finished packet processing */
	stats.cpu_end = time(NULL);

	/*
	 * Tell dispatcher to die
	 */
	if (pv.rh_addr.s_addr != 0) {
		ssize_t ret;
		pipe_message *msg = malloc(sizeof(pipe_message));
		msg->type = MSG_KILL;
		ret = write(pv.ro_pipe, msg, sizeof(pipe_message));
		free(msg);
	}

	/* Close output dump file */
	if (dumpd != NULL)
		pcap_dump_close(dumpd);
	fs_report = dump_report("report.txt");

	/* Perform specific actions according to current session type */
	switch (pv.stype) {
	case SESS_TYPE_HOST:
		fclose(hoststats.fs_pkts_all);
		ht_dump_host_data(host_table, "hosts");

		/* Dump summary text */
		if (fs_report)
			ht_dump_report(fs_report);
		display_stats();
		ht_display_stats();
		break;
	case SESS_TYPE_FLOW:
		ft_dump_flows_data(flow_table, pv.wmode == MODE_REALTIME ? FREE_ALL : DUMP_ALL | FREE_ALL);

		/* Dump summary text */
		if (fs_report)
			ft_dump_report(fs_report);
		display_stats();
		ft_display_stats();
		break;
	case SESS_TYPE_BIFLOW:
		bt_dump_biflows_data(biflow_table, pv.wmode == MODE_REALTIME ? FREE_ALL : DUMP_ALL | FREE_ALL);

		/* Dump summary text */
		if (fs_report)
			bt_dump_report(fs_report);
		display_stats();
		bt_display_stats();
		break;
	}

	/* Close classification output file */
	fprintf(class_out, "# end of text table\n");
#ifdef Linux
	if (uid != 0) {
		int ret;

		ret = fchown(class_out->_fileno, uid, gid);
		ret = fchown(fs_report->_fileno, uid, gid);
	}
#endif
	fclose(class_out);
	fclose(fs_report);

	/*
	 * Start training process
	 */
	if (pv.training) {
		train();
	}

	/* Free pre_class table */
	if (pre_class) {
		clear_hash_table(pre_class);
	}

	/* Unload plug-ins */
#if DEBUG > 1
	dump_statistics(stdout);
#endif
	unload_plugins();
	unload_app_defs();


	return (EXIT_SUCCESS);
}

/*
 * Packet processing (Host session type)
 */
int ht_process_packet(u_char * packet, const struct pcap_pkthdr head)
{
	struct ht_entry *entry_in, *entry_out, *temp;
	int pl;
	u_char *ip_packet = packet + stats.frame_offset;	/* define IP packet */

	/* get the corresponding table entry for the given packet */
	entry_out = ht_get_entry_src(ip_packet, host_table);
	entry_in = ht_get_entry_dst(ip_packet, host_table);

	if ((entry_in == NULL) || (entry_out == NULL)) {
		printf("ht_process_packet: error getting corresponding table entry\n");
		return (-1);
	}

	/*
	 * check source host timeout (if session_timeout is set)
	 */
	if (pv.session_timeout) {
		if ((entry_out->pkts_in || entry_out->pkts_out) &&
		    ((head.ts.tv_sec - MAX(entry_out->ts_last_out.tv_sec, entry_out->ts_last_in.tv_sec)) > pv.session_timeout)) {
			/* Timeout: host didn't send or receive pkts for a time longer than timeout (in seconds) */
			temp = entry_out;
			entry_out = ht_new_entry_src(ip_packet, host_table, temp);

			if (entry_out == NULL) {
				printf("ht_process_packet: error getting new src table entry\n");
				return (-1);
			}

		}

		if ((entry_in->pkts_in || entry_in->pkts_out) &&
		    ((head.ts.tv_sec - MAX(entry_in->ts_last_out.tv_sec, entry_in->ts_last_in.tv_sec)) > pv.session_timeout)) {
			/* Timeout: host didn't send or receive pkts for a time longer than timeout (in seconds) */
			temp = entry_in;
			entry_in = ht_new_entry_dst(ip_packet, host_table, temp);

			if (entry_in == NULL) {
				printf("ht_process_packet: error getting new dst table entry\n");
				return (-1);
			}

		}
	}

	/*
	 * Update global hosts stats
	 */

	/* first time we see this host sending packets */
	if (!entry_out->pkts_out) {
		/* set sending_host_session time (wrt first plab packet) */
		entry_out->siat = TV_SUB_TO_QUAD(head.ts, stats.tv_start);

		hoststats.tv_last_shost = head.ts;
		if (!entry_out->pkts_in) {
			/* first time we see this host at all */
			entry_out->iat = TV_SUB_TO_QUAD(head.ts, stats.tv_start);
			hoststats.tv_last_host = head.ts;
		}
	}

	/* first time we see this host receiving packets */
	if (!entry_in->pkts_in) {
		/* set receiving_host_session time (wrt first plab packet) */
		entry_in->diat = TV_SUB_TO_QUAD(head.ts, stats.tv_start);

		hoststats.tv_last_dhost = head.ts;
		if (!entry_in->pkts_out) {
			/* first time we see this host at all */
			entry_in->iat = TV_SUB_TO_QUAD(head.ts, stats.tv_start);
			hoststats.tv_last_host = head.ts;
		}
	}

	if (PKT_IS_TCP(ip_packet)) {
		pl = PKT_TCP_PAYLOAD_B(ip_packet);	/* TCP Payload */
	} else if (PKT_IS_UDP(ip_packet)) {
		pl = PKT_UDP_PAYLOAD_B(ip_packet);	/* UDP Payload */
	} else {
		pl = 0;
	}

	//fprintf(hoststats.fs_pkts_all, "%qu %d\n", TV_SUB_TO_QUAD(head.ts, hoststats.tv_last_pkt), pl);
	hoststats.tv_last_pkt = head.ts;

	entry_in->pkts_in++;
	entry_out->pkts_out++;

	entry_in->ts_last_in = head.ts;
	entry_out->ts_last_out = head.ts;

	return (1);
}

/*
 * Packet processing (Flow session type)
 */
int ft_process_packet(u_char * packet, const struct pcap_pkthdr head)
{
	struct ft_entry *entry;
	struct flow *tmp;
	struct flow *s;
	u_int pl, l4proto;
	u_char *ip_packet = packet + stats.frame_offset;	/* move offset to the start of IP header */
	bool new_session = false;

	/*
	 * At the moment we operate only on TCP and UDP packets.
	 * Also:
	 * - set the layer4 protocol variable
	 * - set the payload length variable.
	 */
	if (PKT_IS_TCP(ip_packet)) {
		pl = PKT_TCP_PAYLOAD_B(ip_packet);
		l4proto = L4_PROTO_TCP;
	} else if (PKT_IS_UDP(ip_packet)) {
		pl = PKT_UDP_PAYLOAD_B(ip_packet);
		l4proto = L4_PROTO_UDP;
	} else {
		PRINTDD("ft_process_packet: not TCP or UDP\n");
		return (-1);
	}

	/* Get the corresponding table entry for the given packet */
	entry = ft_get_entry(ip_packet, flow_table);
	if (entry == NULL) {
		printf("ft_process_packet: error getting corresponding table entry\n");
		return (-1);
	}

	/*
	 * Decide if a new session should be created
	 */
	if (pv.tcp_heuristics && l4proto == L4_PROTO_TCP) {
		/* The flow chain is void or a SYN flag is forcing a new session */
		if (entry->last_flow == NULL || PKT_TCP_FLAG_SYN_ONLY(ip_packet)) {
			new_session = true;
		}
	} else {
		/* The flow chain is void or the session timeout is expired */
		if (entry->last_flow == NULL ||
		    (head.ts.tv_sec - entry->last_flow->ts_last.tv_sec) > pv.session_timeout) {
			new_session = true;
		}
	}

	/*
	 * Create a new session
	 */
	if (new_session) {
		/*
		 * Create a new flow
		 */
		tmp = entry->last_flow;
		entry->last_flow = flow_init(tmp);
		if (entry->last_flow == NULL) {
			perror("flow_init");
			return (-1);
		}
		entry->num_flows++;					/* Count flows belonging to this entry */
		entry->last_flow->id = session_stats.sessions++;	/* Session ID is assigned */
		entry->last_flow->entry_id = entry->id;
		entry->last_flow->ts_start = head.ts;
		entry->last_flow->f_tuple.l4proto = l4proto;
		s = entry->last_flow;
		if (pv.wmode == MODE_CYCLIC)
			s->old_cycle = calloc(1, sizeof(str_old_cycle));

		PRINTDD("Started a new flow [%lu][%lu]\n", (unsigned long int) entry->id, (unsigned long int) entry->last_flow->id);

		/*
		 * Explicitly assign source address and ports variables.
		 * This is redundant, but being done only once per session it practically only affects memory.
		 */
		memcpy(&(s->f_tuple.src_ip.s_addr), &ip_packet[12], 4);
		s->f_tuple.src_port = PKT_SRC_PRT(ip_packet);
		memcpy(&(s->f_tuple.dst_ip.s_addr), &ip_packet[16], 4);
		s->f_tuple.dst_port = PKT_DST_PRT(ip_packet);

		/* Inspect TCP SYN flag */
		if (l4proto == L4_PROTO_TCP && PKT_TCP_FLAG_SYN_ONLY(ip_packet)) {
			SET_BIT(s->flags, SESS_TCP_SYN, 1);
		}

		/* Get ToS value */
		s->tos = PKT_IP_TOS(ip_packet);

		/*
		 * Session pre-classification
		 */
		if (pv.training && pv.pre_class_file) {
			class_info *entry = find_hash_entry(pre_class, &s->f_tuple);

			if (entry) {
				s->app.id = entry->app_id;
				s->app.subid = entry->app_subid;
			}
		}
	} /* End of new session setup */

	/* Just for ease: copy session pointer and set direction flag */
	s = entry->last_flow;

	/*
	 * Heuristics for TCP connections
	 */
	if (pv.tcp_heuristics && l4proto == L4_PROTO_TCP) {
		/* Check for FIN flag */
		if (PKT_TCP_FLAG_FIN(ip_packet)) {
			SET_BIT(s->flags, SESS_TCP_FIN, 1);
		}
		/* Check for RST flag */
		if (PKT_TCP_FLAG_RST(ip_packet)) {
			SET_BIT(s->flags, SESS_TCP_RST, 1);
		}
	}

	/* If session must be skipped do not process the packet */
	if (TEST_BIT(s->flags, SESS_SKIP, 1)) {
		stats.skipped_pkts++;
		s->ts_last=head.ts;
		return (1);
	}

	/*
	 * Extract features
	 */
	extract_flow_features(s, ip_packet, head);

	/*
	 * Update session counters and timestamps.
	 */
	if (pl > 0) {
		s->ts_pl_last = head.ts;
		s->pl_pkts++;
		s->bytes += pl;
	}
	s->pkts++;
	s->ip_bytes += PKT_IP_TLEN_B(ip_packet);
	s->ts_last = head.ts;
	session_stats.tv_last_session = head.ts;

	/*
	 * Classification
	 */
	if (pv.class && TEST_BIT(s->flags, (SESS_DONT_CLASSIFY|SESS_CLASSIFIED), 0)) {
		if (is_session_classifiable(s)) {

			/* Take classification decision */
			classify(s);

			/* REALTIME mode: we immediately output the classification result */
			if (pv.wmode == MODE_REALTIME && ! TEST_BIT(s->flags, (SESS_DONT_CLASSIFY|SESS_CLASSIFIED), 0))
				/* XXX We are supposing we are using a combiner that deals with REALTIME mode */
				store_result(s, 0);
		}
	}

	/*
	 * Training: tells to the classification plugin under training to gather information for this session
	 */
	if (pv.training && TEST_BIT(s->flags, SESS_SIGNED, 0)) {
		session_sign(s, packet);

		/* debug output */
		PRINTD("%lu\tS:%s\t%s\t%d\t", (unsigned long int) s->id, (s->f_tuple.l4proto == L4_PROTO_TCP) ? "TCP" : "UDP",
		       inet_ntoa(s->f_tuple.src_ip), s->f_tuple.src_port);
		PRINTD("%s\t%d\n", inet_ntoa(s->f_tuple.dst_ip), s->f_tuple.dst_port);
		
		PRINTDD("payload: %s\n", payload_string(s->payload, pv.pl_inspect));
	}

	return (1);
}

/*
 * Packet processing (Biflow session type)
 */
int bt_process_packet(u_char * packet, const struct pcap_pkthdr head)
{
	struct bt_entry *entry;
	struct biflow *tmp;
	struct biflow *s;
	u_int pl, l4proto;
	u_char *ip_packet = packet + stats.frame_offset;	/* move offset to the start of IP header */
	bool upstream, new_session = false;

	/*
	 * At the moment we operate only on TCP and UDP packets.
	 * Also:
	 * - set the layer4 protocol variable
	 * - set the payload length variable.
	 */
	if (PKT_IS_TCP(ip_packet)) {
		pl = PKT_TCP_PAYLOAD_B(ip_packet);
		l4proto = L4_PROTO_TCP;
	} else if (PKT_IS_UDP(ip_packet)) {
		pl = PKT_UDP_PAYLOAD_B(ip_packet);
		l4proto = L4_PROTO_UDP;
	} else {
		PRINTDD("bt_process_packet: not TCP or UDP\n");
		return (-1);
	}

	/* Get the corresponding table entry for the given packet */
	entry = bt_get_entry(ip_packet, biflow_table);
	if (entry == NULL) {
		printf("bt_process_packet: error getting corresponding table entry\n");
		return (-1);
	}

	upstream = BIFLOW_IS_PKT_UPSTREAM(ip_packet, entry);

	/*
	 * Decide if a new session should be created
	 */
	if (pv.tcp_heuristics && (l4proto == L4_PROTO_TCP)) {
		/* The biflow chain is void or a SYN flag is forcing a new session */
		if (entry->last_biflow == NULL || PKT_TCP_FLAG_SYN_ONLY(ip_packet)) {
			new_session = true;
		}
	} else {
		/* The biflow chain is void or the session timeout is expired */
		if (entry->last_biflow == NULL ||
		    (head.ts.tv_sec - entry->last_biflow->ts_last.tv_sec) > pv.session_timeout) {
			new_session = true;
		}
	}

	/*
	 * Create a new session
	 */
	if (new_session) {
		/*
		 * Create a new biflow
		 */
		tmp = entry->last_biflow;
		entry->last_biflow = biflow_init(tmp);
		if (entry->last_biflow == NULL) {
			perror("biflow_init");
			return (-1);
		}
		entry->num_biflows++;					/* Count biflows belonging to this entry */
		entry->last_biflow->id = session_stats.sessions++;	/* Session ID is assigned */
		entry->last_biflow->entry_id = entry->id;
		entry->last_biflow->ts_start = head.ts;
		entry->last_biflow->f_tuple.l4proto = l4proto;
		s = entry->last_biflow;
		if (pv.wmode == MODE_CYCLIC)
			s->old_cycle=calloc(1, sizeof(str_old_cycle));

		PRINTDD("started a new biflow [%ld][%ld]\n", entry->id, entry->last_biflow->id);

		/*
		 * Explicitly assign source address and ports variables.
		 * This is redundant, but being done only once per session it practically only affects memory.
		 */
		if (upstream) {
			memcpy(&(s->f_tuple.src_ip.s_addr), &ip_packet[12], 4);
			s->f_tuple.src_port = PKT_SRC_PRT(ip_packet);
			memcpy(&(s->f_tuple.dst_ip.s_addr), &ip_packet[16], 4);
			s->f_tuple.dst_port = PKT_DST_PRT(ip_packet);
		} else {
			memcpy(&(s->f_tuple.dst_ip.s_addr), &ip_packet[12], 4);
			s->f_tuple.dst_port = PKT_SRC_PRT(ip_packet);
			memcpy(&(s->f_tuple.src_ip.s_addr), &ip_packet[16], 4);
			s->f_tuple.src_port = PKT_DST_PRT(ip_packet);
		}

		/* Inspect TCP SYN flag */
		if (l4proto == L4_PROTO_TCP && PKT_TCP_FLAG_SYN_ONLY(ip_packet)) {
			SET_BIT(s->flags, SESS_TCP_SYN, 1);
		}

		/*
		 * Session pre-classification
		 */
		if (pv.training && pv.pre_class_file) {
			class_info *entry = find_hash_entry(pre_class, &s->f_tuple);

			if (entry) {
				s->app.id = entry->app_id;
				s->app.subid = entry->app_subid;
			}
		}
	} /* End of new session setup */

	/* Just for ease: copy session pointer and set direction flag */
	s = entry->last_biflow;
	SET_BIT(s->flags, SESS_LAST_PKT, upstream ? UP : DW);

	/*
	 * Heuristics for TCP connections
	 */
	if (pv.tcp_heuristics && l4proto == L4_PROTO_TCP) {
		/* Skip TCP sessions without 3-way handshake */
		if (TEST_BIT(s->flags, (SESS_TCP_SYN | SESS_SKIP), 0)) {
			SET_BIT(s->flags, SESS_SKIP, 1);
			session_stats.skipped_sessions++;
		}

		/* Check for FIN flag */
		if (PKT_TCP_FLAG_FIN(ip_packet)) {
			SET_BIT(s->flags, (upstream ? SESS_TCP_FIN_UP : SESS_TCP_FIN_DW), 1);
		}
	}

	/* If session must be skipped do not process the packet */
	if (TEST_BIT(s->flags, SESS_SKIP, 1)) {
		stats.skipped_pkts++;
		s->ts_last=head.ts;
		return (1);
	}

	/*
	 * Extract features
	 */
	extract_biflow_features(s, ip_packet, head);

	/*
	 * Update session counters and timestamps.
	 */
	if (upstream) {
		if (pl > 0) {
			s->up_pl_ts_last = head.ts;
			s->up_pl_pkts++;
			s->up_bytes += pl;
		}
		s->up_pkts++;
		s->up_ts_last = head.ts;
	} else {
		if (pl > 0) {
			s->dw_pl_ts_last = head.ts;
			s->dw_pl_pkts++;
			s->dw_bytes += pl;
		}
		s->dw_ts_last = head.ts;
		s->dw_pkts++;
	}
	s->ts_last = head.ts;
	session_stats.tv_last_session = head.ts;

	/*
	 * Classification
	 */
	if (pv.class && TEST_BIT(s->flags, (SESS_DONT_CLASSIFY|SESS_CLASSIFIED), 0)) {
		if (is_session_classifiable(s)) {

			/* Take classification decision */
			classify(s);

			/* REALTIME mode: we immediately output the classification result */
			if (pv.wmode == MODE_REALTIME && ! TEST_BIT(s->flags, (SESS_DONT_CLASSIFY|SESS_CLASSIFIED), 0))
				/* XXX We are supposing we are using a combiner that deals with REALTIME mode */
				store_result(s, 0);
		}
	}

	/*
	 * Training: tells to the classification plugin under training to gather information for this session
	 */
	if (pv.training && TEST_BIT(s->flags, SESS_SIGNED, 0)) {
		session_sign(s, packet);

		/* debug output */
		PRINTD("%lu\tS:%s\t%s\t%d\t", s->id, (s->f_tuple.l4proto == L4_PROTO_TCP) ? "TCP" : "UDP",
		       inet_ntoa(s->f_tuple.src_ip), s->f_tuple.src_port);
		PRINTD("%s\t%d\t", inet_ntoa(s->f_tuple.dst_ip), s->f_tuple.dst_port);
				
		PRINTDD("up: %s\tdw: %s\n", payload_string(s->payload_up, pv.pl_inspect),
		       payload_string(s->payload_dw, pv.pl_inspect));
	}

	return (1);
}


/*
 * Clean all before quitting
 * TODO: quit also without incoming packets
 */
void cleanup(int signo)
{
	loop = 0;
	stats.interrupted = 1;
	printf("INTerrupt signal caught...\n");
}

/*
 * Read from file to buffer
 */
char *read_infile(char *fname)
{
	register int fd, cc;
	register char *cp;
	struct stat buf;

	fd = open(fname, O_RDONLY);
	if (fd < 0) {
		printf("can't open %s: %s", fname, pcap_strerror(errno));
		exit(1);
	}

	if (fstat(fd, &buf) < 0) {
		printf("can't stat %s: %s", fname, pcap_strerror(errno));
		exit(1);
	}

	cp = malloc((u_int) buf.st_size + 1);
	if (cp == NULL) {
		printf("malloc(%d) for %s: %s", (u_int) buf.st_size + 1, fname, pcap_strerror(errno));
		exit(1);
	}
	cc = read(fd, cp, (u_int) buf.st_size);
	if (cc < 0) {
		printf("read %s: %s", fname, pcap_strerror(errno));
		exit(1);
	}
	if (cc != buf.st_size) {
		printf("short read %s (%d != %d)", fname, cc, (int) buf.st_size);
		exit(1);
	}
	cp[(int) buf.st_size] = '\0';

	return (cp);
}

/*
 * Check if we want to process packet (return 0) or if we want to skip it (return 1).
 * Increment statistics counters.
 */
int filter_packet(u_char * packet, const struct pcap_pkthdr head)
{
	struct tm *tm;

	u_char *ip_packet = packet + stats.frame_offset;

	/*
	 * XXX Reactivate it, but with a datalink control
	 */
	/* We work only with Ethernet-II frame types */
	/*if (PKT_IS_ETH_802(packet)) {
	   printf("Captured an 802.3 frame !\n");
	   return(1);
	   } */

	PRINTDD("head.caplen: %d stats.frame_offset: %d\n", head.caplen, stats.frame_offset);
	/* Discard packets with truncated header */
	if (head.caplen - stats.frame_offset < 20) {
		PRINTDD("[%d] Truncated packet header! Only %d bytes.\n", stats.pkts, head.len - stats.frame_offset);
		stats.truncated++;
		return (1);
	}

	/* Discard fragments */
	if (PKT_IS_FRAGMENT(ip_packet)) {
		stats.frags++;
		return (1);
	}

	/* Discard packets with optional IP headers. XXX We're not able to process them */
	if (PKT_IS_IP_OPTIONS(ip_packet)) {
		stats.ip_options++;
		return (1);
	}

	/*
	 * Check payload. Warning: this is strictly necessary when processing is done because we
	 * use this value as an index to an array. Wrong values lead to segfaults or buggy data.
	 */
	if (PKT_IS_TCP(ip_packet)) {
		if ((PKT_TCP_PAYLOAD_B(ip_packet) > MAX_PAYLOAD - 1) || (PKT_TCP_PAYLOAD_B(ip_packet) < 0)) {
			PRINTD("[%qu] Warning, invalid TCP payload size:\t%d\n", stats.pkts, PKT_TCP_PAYLOAD_B(ip_packet));
			stats.err_payload++;
			return (1);
		}
		PRINTDD("tcp header length: %d\n", PKT_TCP_HLEN_B(ip_packet));
	} else if (PKT_IS_UDP(ip_packet)) {
		if ((PKT_UDP_PAYLOAD_B(ip_packet) > MAX_PAYLOAD - 1) || (PKT_UDP_PAYLOAD_B(ip_packet) < 0)) {
			PRINTD("[%qu] Warning, invalid UDP payload size:\t%d\n", stats.pkts, PKT_UDP_PAYLOAD_B(ip_packet));
			stats.err_payload++;
			return (1);
		}
	}

	


	/* If requested discard pkts outside specified day of week */
	/* XXX: timezone */
	if (pv.day_of_week >= 0) {
		tm = tztime((time_t *)&(head.ts.tv_sec));
		if (tm->tm_wday != pv.day_of_week)
			return (1);
	}

	/* If requested discard pkts outside specified time range */
	/* XXX: timezone */
	if (pv.time_range) {
		tm = tztime((time_t *)&(head.ts.tv_sec));
		if (pv.tr_hmin <= pv.tr_hmax) {
			/* Range does not cross a 24h day */
			if (tm->tm_hour < pv.tr_hmin)
				return (1);
			if (tm->tm_hour > pv.tr_hmax)
				return (1);
		} else {
			/* Range crosses a 24h day */
			if ((tm->tm_hour < pv.tr_hmin) && (tm->tm_hour > pv.tr_hmax))
				return (1);
		}
		/* In both of above cases we need to check minutes this way */
		if ((tm->tm_hour == pv.tr_hmin) && (tm->tm_min < pv.tr_mmin))
			return (1);
		if ((tm->tm_hour == pv.tr_hmax) && (tm->tm_min > pv.tr_mmax))
			return (1);
	}

	return (0);
}

/* EOF */
