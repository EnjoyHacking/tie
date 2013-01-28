#   TIE Makefile
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
	OPT += -ggdb -DDEBUG=$(debug)
else
	OPT += -O2
endif

# ENABLE_PIC option
ifdef fpic
	OPT += -fPIC
endif

# DISABLE_LFS option
ifneq "$(lfs)" "off"
	OPT += -D_FILE_OFFSET_BITS=64
endif

# DAG_SUPPORT option
ifdef dag
	LOPT += -ldag
endif

# Old libpcap option
ifdef oldpcap
	OPT += -DPCAP_OLD
endif

##################
# Static options # 
##################

# OS options
OS := $(shell uname)
ifeq "$(OS)" "Linux"
 	STAT := stat -c %Y
	LDL  := -ldl -lpthread
endif
ifeq "$(OS)" "FreeBSD"
	STAT := stat -f %m
	LDL  := -pthread
endif

CC	:= gcc
CFLAGS	:= -Wall -Winline -D$(OS) $(OPT)

LDFLAGS	:= -rdynamic 
INCS	:= 
OBJECTS	:= $(shell ls -1 *.c */*.c | sed -e 's/\.c/\.o/g')
LIBS	:= $(LDL) $(LOPT) -lpcap
VERSION	:= $(shell cat ../VERSION)
COPY	:= tie ../conf/*.txt ../utils/tie_stats
DESTDIR	:= ../bin
INSTDIR := /opt/tie
LINKDIR := /usr/local/bin

#################
# Generic Rules #
#################

.PHONY: help clean all plugins 

all: head tie copy plugins help

help:
	@ echo '-----------------------'
	@ echo 'Building options:'
	@ echo '-----------------------'
	@ echo '    debug=<n>  : enable debug mode using verbosity level n'
	@ echo '    fpic=on    : enable position-independent code compilation'
	@ echo '    dag=on     : enable DAG support'
	@ echo '    lfs=off    : disable Large FileSystem support'
	@ echo '    oldpcap=on : enable support for libpcap versions <= 0.9.4' 
	@ echo '-----------------------'
	@ echo 'Building tips:'
	@ echo '-----------------------'
	@ echo '* To enable the building of plugins edit "plugins/enabled_plugins" file'
	@ echo '  and run "make" again'
	@ echo '* To build a specific plugin:'
	@ echo '    make -C plugins/<plugin_dir>'
	@ echo '* To build TIE with options use the following syntax:' 
	@ echo '    make clean all [options]'
	@ echo '-----------------------'
	@ echo 'Installation tips:'
	@ echo '-----------------------'
	@ echo '* After compilation everything you need to run TIE should be in the "../bin/" directory'
	@ echo '  However we suggest to install TIE into your system.'
	@ echo '* To install TIE type "make install" as root. This will also install'
	@ echo '  enabled plugins (as specified in "plugins/enabled_plugins").'
	@ echo '  By default it will copy all needed files in /opt/tie/ and will create'
	@ echo '  symbolic links from /usr/local/bin'
	@ echo '* To install a TIE plugin type as root:'
	@ echo '    make -C plugins/<plugin_dir> install'
	@ echo 

head:
	@ echo '-----------------------'
	@ echo 'Building TIE executable'
	@ echo '-----------------------'

plugins:
	@ $(MAKE) -C plugins --no-print-directory

copy:
	@ printf "Copying files to $(DESTDIR) folder..."
	@ [ -d $(DESTDIR) ] || mkdir -p $(DESTDIR)
	@ for file in $(COPY); do \
		: -- If file already exists overwrite it only if older -- ; \
		if [ -f $(DESTDIR)/$${file##*/} ]; then \
			bmod=`$(STAT) $(DESTDIR)/$${file##*/}` ; \
			smod=`$(STAT) $$file` ; \
			if [ $$bmod -lt $$smod ] ; then \
				cp $$file $(DESTDIR)/$${file##*/} ; \
				printf "!" ; \
			fi ; \
		else \
			cp $$file $(DESTDIR)/$${file##*/} ; \
			printf "." ; \
		fi ; \
	  done ; \
	  printf "done\n"

clean:
	@ echo '------------'
	@ echo 'Cleaning all'
	@ echo '------------'
	@ printf 'Cleaning tie source tree...'
	@ rm -f */*.o *.o *~ tie
	@ printf 'done\n'
	@ $(MAKE) -C plugins --no-print-directory clean
	@ printf 'Cleaning tie bin tree...'
	@ rm -f ../bin/tie
	@ printf 'done\n'

check_tie:
	@ if [ ! -e $(INSTDIR)/plugins/enabled_plugins ]; then \
		echo 'TIE is not installed.' ; \
		exit 1 ; \
	  fi

check_uid:
	@ if [ `id -u` -ne 0 ]; then \
		echo 'You need to be root to install TIE.' ; \
		exit 1; \
	  fi

install: check_uid tie
	@ echo '--------------'
	@ echo 'Installing TIE'
	@ echo '--------------'
	@ $(MAKE) copy DESTDIR=$(INSTDIR) --no-print-directory
	@ printf 'Creating symbolic links in $(LINKDIR)...'
	@ ln -sf $(INSTDIR)/tie $(LINKDIR)/tie
	@ ln -sf $(INSTDIR)/tie_stats $(LINKDIR)/tie_stats
	@ printf 'done\n'
	@ $(MAKE) -C plugins install INSTDIR=$(INSTDIR) --no-print-directory

uninstall: check_tie
	@ echo '----------------'
	@ echo 'Uninstalling TIE'
	@ echo '----------------'
	@ printf 'Removing files from $(INSTDIR)...'
	@ rm -rf $(INSTDIR)
	@ printf 'done\n'
	@ printf 'Removing symbolic links from $(LINKDIR)...'
	@ rm -f $(LINKDIR)/tie
	@ rm -f $(LINKDIR)/tie_stats
	@ printf 'done\n'
	

# Generic Object
%.o: %.c %.h
	@ printf "[ GO ]\t"
	$(CC) -c $(CFLAGS) $(INCS) -o $@ $<

%.o: %.c
	@ printf "[ GO ]\t"
	$(CC) -c $(CFLAGS) $(INCS) -o $@ $<

##################
# Specific Rules #
##################

# Specific Executables
tie: $(OBJECTS) $(CLASS_OBJ) common/pkt_macros.h common/common.h
	@ printf "[ SE ]\t"
	$(CC) $(CFLAGS) $(INCS) -o $@ $(OBJECTS) $(CLASS_OBJ) $(LDFLAGS) $(LIBS)

# Specific Objects
tie.o: tie.c
	@ printf "[ SO ]\t"
	$(CC) -c $(CFLAGS) $(INCS) -D 'YEAR="$(shell date +%Y)"' -D 'VERSION="$(VERSION)"' $<

plugins/plugin_manager.o: plugins/plugin_manager.c plugins/plugin.h
	@ printf "[ SO ]\t"
	$(CC) -c $(CFLAGS) $(INCS) -o $@  $<

# EOF
