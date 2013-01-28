/*
 *  src/plugins/l7/l7_matcher.h - Component of the TIE v1.0.0-beta3 platform 
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

#ifndef L7_REGEXPR_H
#define L7_REGEXPR_H

#include "../plugin.h"
#include "../../biflow/biflow_table.h"

extern int add_pattern(const char* proto_name, const char* pattern, int eflags, int cflags, int app_id, int app_sub_id);
extern bool init_matcher();
extern void try_match(const void* s, class_output* result);
extern void deinit_matcher();

#endif // L7_REGEXPR_H
