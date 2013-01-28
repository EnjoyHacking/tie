/*
 *  src/output/remote_output.c - Component of the TIE v1.0.0-beta3 platform 
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
#include <string.h>
#include <unistd.h>

#include "../common/common.h"
#include "remote_output.h"


/*
 * Constants
 */
#define MAX_LEN 250


/*
 * Private functions
 */
int rh_connect();
int rh_disconnect();


/*
 * Global variables
 */
int sock;


/*
 * Thread: listen on a pipe for messages to deliver
 */
void *dispatcher(void *arg)
{
	pipe_message msg;
	int ro_pipe[2];
	bool loop = true;

	if (pipe(ro_pipe) == -1) {
		printf("dispatcher: error creating pipe!\n");
		return NULL;
	}

	pv.ro_pipe = ro_pipe[1];

	if (pv.rh_keep_alive)
		rh_connect();

	while (loop) {
		ssize_t ret;
		ret = read(ro_pipe[0], &msg, sizeof(pipe_message));
		switch (msg.type) {
			case MSG_KILL:
				loop = false;
				break;
			case MSG_CLASS:
				if (send_class_result((void *) msg.body) != 0) {
					printf("dispatcher: error sending classification output!\n");
				}
				free(msg.body);
				break;
			default:
				printf("dispatcher: received unknown message!\n");
		}
	}

	close(ro_pipe[0]);
	close(ro_pipe[1]);
	if (pv.rh_keep_alive)
		rh_disconnect();
	return NULL;
}

/*
 * Establish a TCP connection with the remote host
 */
int rh_connect()
{
	int opt = 1;
	struct sockaddr_in cli, srv;

	sock = socket(AF_INET, SOCK_STREAM, 0);
	setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (char *) &opt, sizeof(opt));

	/* client side */
	memset(&cli, 0, sizeof(cli));
	cli.sin_family = AF_INET;
	cli.sin_addr.s_addr = htonl(INADDR_ANY);
	cli.sin_port = htons(0);

	bind(sock, (struct sockaddr*) &cli, sizeof(cli));

	/* server side */
	memset(&srv, 0, sizeof(srv));
	srv.sin_family = AF_INET;
	srv.sin_addr.s_addr = pv.rh_addr.s_addr;
	srv.sin_port = htons(pv.rh_port);

	if (connect(sock, (struct sockaddr*) &srv, sizeof(srv))) {
		printf("rh_connect: error connecting with Context Manager!\n");
		if (pv.rh_keep_alive) {
			pv.rh_addr.s_addr = 0;
			printf("Context Manager communication disabled!\n");
		}
		return -1;
	}

	return 0;
}

/*
 * Close the TCP connection with the remote host
 */
int rh_disconnect()
{
	return close(sock);
}

/*
 * Send classification result over established TCP connection
 */
int send_class_result(msg_class *m)
{
	char message[MAX_LEN], *mess_ptr;
	int len;

	if (!pv.rh_keep_alive)
		rh_connect();

	/*
	 * Build message
	 *             ----- ------- --------- ------- --------- ----------- ------- ------- ------------
	 * Structure: | L4P | SrcIp | SrcPort | DstIp | DstPort | Timestamp | AppID | SubID | Confidence |
	 *             ----- ------- --------- ------- --------- ----------- ------- ------- ------------
	 * the string is terminated by "\r\n" sequence to allow readline use on server-side
	 */
	mess_ptr = message;
	len = sprintf(mess_ptr, "%d\t", m->f_tuple.l4proto);
	mess_ptr += len;
	len = sprintf(mess_ptr, "%s\t%d\t", inet_ntoa(m->f_tuple.src_ip), m->f_tuple.src_port);
	mess_ptr += len;
	len = sprintf(mess_ptr, "%s\t%d\t", inet_ntoa(m->f_tuple.dst_ip), m->f_tuple.dst_port);
	mess_ptr += len;
	len = sprintf(mess_ptr, "%lu\t%d\t%d\t%d\r\n", (u_long) m->timestamp, m->app.id, m->app.subid, m->app.confidence);

	if (send(sock, message, strlen(message), 0) == -1) {
		printf("send_class_result: cannot send classification result\n");
	}

	if (!pv.rh_keep_alive)
		rh_disconnect();

	return 0;
}
