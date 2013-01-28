#   Classifiers Makefile
#
#   Copyright (c) 2007-2008 Alberto Dainotti, Walter de Donato, Antonio Pescape, Alessio Botta
#   Email: alberto@unina.it, walter.dedonato@unina.it, pescape@unina.it, a.botta@unina.it
#   DIS - Dipartimento di Informatica e Sistemistica (Computer Science Department)
#   University of Naples Federico II
#   All rights reserved.

#---------------------
include ../options.mk
#---------------------

# Specify here additional OBJECTS needed by this plugin
OBJECTS	+= l7_matcher.o l7_config.o pat_file_parser.o ../../common/pkt_macros.o regex/regex.o
ifeq "$(OS)" "FreeBSD"
OBJECTS += getline.o getstr.o
endif

# Specify here additional linker flags needed by this plugin
LDFLAGS +=

# Specify here static libraries needed by this plugin
LIBS	:=

# Specify here files and folders to be copied to plugin destination folder together with the plugin.
# Each folder is recursively processed skipping hidden files/folders.
# Each file will be copied in update mode (overwrite only if newer).
COPY	:= config.txt pats 

#---------------------
include ../rules.mk
#---------------------

# Specify here custom rules if needed
.SECONDARY: regex/regex.o

regex/regex.o: regex/regex.c
	@ printf "[ SO ]\t"
	$(CC) -c $(CFLAGS) -o regex/regex.o regex/regex.c
# EOF
