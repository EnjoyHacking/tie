#   Plugins Makefile
#
#   Copyright (c) 2007-2008 Alberto Dainotti, Walter de Donato, Antonio Pescape, Alessio Botta
#   Email: alberto@unina.it, walter.dedonato@unina.it, pescape@unina.it, a.botta@unina.it
#   DIS - Dipartimento di Informatica e Sistemistica (Computer Science Department)
#   University of Naples Federico II
#   All rights reserved.

###################
# Dynamic Options #
###################

# DEBUG option
ifdef debug
	OPT := $(OPT) -ggdb -DDEBUG=$(debug)
else
	OPT := $(OPT) -O2
endif

##################
# Static Options #
##################

# OS options
OS := $(shell uname)
ifeq "$(OS)" "Linux"
 	STAT := stat -c %Y
endif
ifeq "$(OS)" "FreeBSD"
	STAT := stat -f %m
endif

CC	:= gcc
CFLAGS	:= -Wall $(OPT)

OBJECTS	:=
INCS	:=
LDFLAGS	:= 
LIBS	:=

FILE	:= enabled_plugins
PLUGINS	:= $(shell cut -d "\#" -f1 $(FILE) | sort | uniq)
DESTDIR	:= ../../bin/plugins

#################
# Generic Rules #
#################

all: copy
	@ if [ "$(PLUGINS)" ]; then \
	  	echo '------------------------' ; \
	  	echo 'Building plug-in modules' ; \
	  	echo '------------------------' ; \
	  fi
	@ for plugdir in $(PLUGINS); do \
		if [ -d $$plugdir ]; then \
			$(MAKE) -C $$plugdir --no-print-directory ; \
		fi ; \
	  done

copy:
	@ printf 'Copying files to $(DESTDIR) dir...'
	@ [ -d $(DESTDIR) ] || mkdir -p $(DESTDIR)  
	@ if [ -e $(DESTDIR)/$(FILE) ]; then \
		bmod=`$(STAT) $(DESTDIR)/$(FILE)` ; \
		smod=`$(STAT) $(FILE)` ; \
		if [ $$bmod -lt $$smod ] ; then \
			cp $(FILE) $(DESTDIR) ; \
			printf "." ; \
		fi ; \
	  else \
		cp $(FILE) $(DESTDIR) ; \
		printf "." ; \
	  fi
	@ echo 'done' 

install:
	@ $(MAKE) copy DESTDIR=$(INSTDIR)/plugins --no-print-directory
	@ for plugdir in $(PLUGINS); do \
		if [ -d $$plugdir ]; then \
			$(MAKE) -C $$plugdir install INSTDIR=$(INSTDIR) --no-print-directory ; \
		fi ; \
	  done

clean:
	@ printf 'Cleaning tie plugins main dir...'
	@ rm -f *.o
	@ echo 'done'
	@ for plugdir in `ls -1 -d */ | cut -d"/" -f1`; do \
	    $(MAKE) -C $$plugdir --no-print-directory clean ; \
	  done	      


# EOF
