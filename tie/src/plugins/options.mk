#   Common Makefile Options for plug-ins
#
#   Copyright (c) 2007-2008 Alberto Dainotti, Walter de Donato, Antonio Pescape, Alessio Botta
#   Email: alberto@unina.it, walter.dedonato@unina.it, pescape@unina.it, a.botta@unina.it
#   DIS - Dipartimento di Informatica e Sistemistica (Computer Science Department)
#   University of Naples Federico II
#   All rights reserved.

########################
# Command-line Options #
########################

# DEBUG option
ifdef debug
	OPT += -ggdb -DDEBUG=$(debug)
else
	OPT += -O2
endif

ifdef fpic
	OPT += -fPIC
endif

####################
# Internal Options #
####################

# OS options
OS := $(shell uname)
ifeq "$(OS)" "Linux"
 	STAT := stat -c %Y
endif
ifeq "$(OS)" "FreeBSD"
	STAT := stat -f %m
endif

# Don't modify these options
CC	:= gcc
CFLAGS	:= -Wall -D$(OS) $(OPT)
OBJECTS	:= ../../common/apps.o 
INCS	:= ../plugin.h
LDFLAGS	:= -shared -nostartfiles
NAME	:= $(shell name=`pwd` && echo $${name\#\#*/})
PLUGIN	:= class_$(NAME).so
DESTDIR	:= ../../../bin/plugins/$(NAME)
INSTDIR := $(shell dirname "`readlink /usr/local/bin/tie`")
VERSION	:= $(shell cat VERSION)

# EOF
