/*
 *  src/common/utils.c - Component of the TIE v1.0.0-beta3 platform 
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
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include <sys/time.h>

#include "common.h"
#include "utils.h"

/*
 * Catch HUP signal
 */
void hup(int signo)
{
	printf("HUP signal caught...\n");
}

/*
 * Associate an incoming signal (e.g. HUP) to a specific function
 */
int catch_sig(int signo, void(*handler)())
{
	struct sigaction action;

	action.sa_handler = handler;
	sigemptyset(&action.sa_mask);
	action.sa_flags = 0;

	if (sigaction(signo, &action, NULL) == -1) {
		return (-1);
	} else {
		return (1);
	}
}

/*
 * Copy a 2D array (like argv) into a flat string. (Stolen from TCPDump)
 *
 * Return: Pointer to the flat string
 */
char *copy_argv(char **argv)
{
	char **p;
	u_int len = 0;
	char *buf;
	char *src, *dst;
	void ftlerr(char *, ...);

	p = argv;
	if (*p == 0)
		return 0;

	while (*p)
		len += strlen(*p++) + 1;

	buf = (char *) malloc(len);

	if (buf == NULL) {
		printf("copy_argv: malloc() failed: %s\n", strerror(errno));
		exit(1);
	}
	p = argv;
	dst = buf;

	while ((src = *p++) != NULL) {
		while ((*dst++ = *src++) != '\0')
			;
		dst[-1] = ' ';
	}

	dst[-1] = '\0';

	return buf;
}

/*
 * Compute IP header checksum (Taken from Libnet)
 */
int ip_cksum(u_short *addr, int len)
{
	int sum;
	int nleft;
	u_short ans;
	u_short *w;

	sum = 0;
	ans = 0;
	nleft = len;
	w = addr;

	while (nleft > 1) {
		sum += *w++;
		nleft -= 2;
	}

	if (nleft == 1) {
		*(u_char *) (&ans) = *(u_char *) w;
		sum += ans;
	}

	return (sum = (sum >> 16) + (sum & 0xffff), (~(sum + (sum >> 16)) & 0xffff));
}

/*
 * Convert a string in the form "hh:mm:ss:MM:yyyy"
 *
 * struct tm {
 *                     int     tm_sec;         * seconds *
 *                     int     tm_min;         * minutes *
 *                     int     tm_hour;        * hours *
 *                     int     tm_mday;        * day of the month *
 *                     int     tm_mon;         * month *
 *                     int     tm_year;        * year *
 *                     int     tm_wday;        * day of the week *
 *                     int     tm_yday;        * day in the year *
 *                     int     tm_isdst;       * daylight saving time *
 * };
 */
int string_to_time_range(char *opt, int *hmin, int *mmin, int *hmax, int *mmax)
{
	char tmp[3] = "00\0";

	/* At least check for separators */
	if ((opt[2] != ':') || (opt[5] != '-') || (opt[8] != ':')) {
		return (-1);
	}

	tmp[0] = opt[0];
	tmp[1] = opt[1];
	*hmin = atoi(tmp);

	tmp[0] = opt[3];
	tmp[1] = opt[4];
	*mmin = atoi(tmp);

	tmp[0] = opt[6];
	tmp[1] = opt[7];
	*hmax = atoi(tmp);

	tmp[0] = opt[9];
	tmp[1] = opt[10];
	*mmax = atoi(tmp);

	return (0);
}

/*
 * Compute the time interval duration between t1 and t0
 */
void tvsub(struct timeval *tdiff, struct timeval t1, struct timeval t0)
{
	tdiff->tv_sec = t1.tv_sec - t0.tv_sec;
	tdiff->tv_usec = t1.tv_usec - t0.tv_usec;
	if (tdiff->tv_usec < 0) {
		tdiff->tv_sec--;
		tdiff->tv_usec += 1000000;
	}
}

/*
 * Convert time in readable UTC format
 */
struct tm *tztime(const time_t *time)
{
	time_t tmp_time_t;

	tmp_time_t = *time + stats.tzoff;
	return (gmtime(&tmp_time_t));
}
