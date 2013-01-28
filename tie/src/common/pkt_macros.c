/*
 *  src/common/pkt_macros.c - Component of the TIE v1.0.0-beta3 platform 
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
#include <ctype.h>
#include "pkt_macros.h"

/*
 * Extract payload from packet
 *
 * Return: pointer to the payload of the packet specified.
 *
 * Returned string can be printable (char *) or not (u_char *) and is allocated dynamically.
 * The string MUST be freed after its use to avoid memory leaks!
 */
void *pkt_payload(u_char *packet, u_int pl_size, uint16_t *pl_stored, bool printable)
{
	void *payload; /* pointer to payload: printable (char *) or not (u_char *) */
	u_int index = 0;

	*pl_stored = MIN(pl_size, pv.pl_inspect);

	if (PKT_IS_TCP(packet)) {
		/* Size can be negative if TCP header has not been captured totally */
		index = PKT_IP_HLEN_B(packet) + PKT_TCP_HLEN_B(packet);
	} else if (PKT_IS_UDP(packet)) {
		/* XXX check!! */
		index = PKT_IP_HLEN_B(packet) + PKT_UDP_HLEN_B;
	} else {
		return NULL;
	}

	if (*pl_stored > 0) {
		if (printable) {
			char *tmp = payload_string(&packet[index], *pl_stored);
			u_int len = strlen(tmp);

			payload = malloc(len + 1);
			strncpy((char *) payload, tmp, len);

			free(tmp);
		} else {
			payload = calloc(*pl_stored, sizeof(u_char));
			memcpy(payload, &packet[index], *pl_stored);
		}
	} else {
		payload = NULL;
	}

	return payload;
}

/*
 * Convert packet payload in printable form
 *
 * Return: dynamically allocated string representing the payload content
 */
char *payload_string(u_char *payload, u_int pl_size)
{
	char *tmp = malloc((4 * pl_size) + 1);
	u_int i, j;

	/* Substitute all non printable characters with escape sequence '\xXX' */
	for (i = 0, j = 0; i < pl_size; i++) {
		if (isgraph(payload[i])) {
			tmp[j] = (char) payload[i];
			j++;
		} else {
			snprintf(&tmp[j], 5, "\\x%02x", payload[i]);
			j += 4;
		}
	}
	tmp[j] = '\0';

	return tmp;
}
