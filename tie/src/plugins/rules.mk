#   Common Makefile Rules for plug-ins
#
#   Copyright (c) 2007-2008 Alberto Dainotti, Walter de Donato, Antonio Pescape, Alessio Botta
#   Email: alberto@unina.it, walter.dedonato@unina.it, pescape@unina.it, a.botta@unina.it
#   DIS - Dipartimento di Informatica e Sistemistica (Computer Science Department)
#   University of Naples Federico II
#   All rights reserved.

#################
# Generic Rules #
#################

all: head $(PLUGIN) copy

.INTERMEDIATE: $(OBJECTS)

# Plugin Shared Object
%.so: %.c $(OBJECTS) $(INCS)
	@ printf "[ PS ]\t"
	$(CC) -D 'VERSION="$(VERSION)"' $(CFLAGS) $(LDFLAGS) -o $@ $(OBJECTS) $(LIBS) $<

# Generic Object
%.o: %.c %.h
	@ printf "[ GO ]\t"
	$(CC) -c $(CFLAGS) -o $@ $<

# Generic Object (without header) 
%.o: %.c
	@ printf "[ GO ]\t"
	$(CC) -c $(CFLAGS) -o $@ $<

head:
	@ echo '## Plugin: $(NAME) ##'

copy:
	@ mkdir -p $(DESTDIR)
	@ for entry in $(PLUGIN) $(COPY); do \
		if [ -d $$entry ]; then \
			: -- Get files list skipping hidden ones -- ; \
			files="$$files $$(find $$entry | grep -v '/\.')"; \
		else \
			files="$$files $$entry"; \
		fi ; \
	  done ; \
	  : -- Process file list -- ; \
	  for file in $$files; do \
		: -- Process sub-directories -- ; \
		if [ -d $$file ]; then \
			mkdir -p $(DESTDIR)/$$file ; \
			printf "done\nCopying $$file to plugin folder..." ; \
		: -- Process files -- ; \
		else \
			[ -z $$f ] && printf 'Copying main files...' && f=1 ; \
			: -- If file already exists overwrite it only if older -- ; \
			if [ -f $(DESTDIR)/$$file ]; then \
				bmod=`$(STAT) $(DESTDIR)/$$file` ; \
				smod=`$(STAT) $$file` ; \
				if [ $$bmod -lt $$smod ] ; then \
					cp $$file $(DESTDIR)/$$file ; \
					printf "!" ; \
				fi ; \
			else \
				cp $$file $(DESTDIR)/$$file ; \
				printf "." ; \
			fi ; \
		fi ; \
	  done ; \
	  [ -z "$$entry" ] || printf "done\n"
	@ if [ `grep -c "^[# ]*$(NAME)" $(DESTDIR)/../enabled_plugins` -eq 0 ] ; then \
		printf 'Updating enabled_plugins file...' ; \
		printf '$(NAME)\n' >> $(DESTDIR)/../enabled_plugins ; \
		printf 'done\n' ; \
	  fi

check_tie:
	@ if [ ! -e $(INSTDIR)/plugins/enabled_plugins ]; then \
		echo 'TIE is not installed.' ; \
		exit 1 ; \
	  fi
	  
check_plugin:
	@ if [ ! -e $(INSTDIR)/plugins/$(NAME) ] ; then \
	  	echo 'Plugin $(NAME) is not installed.' ; \
	  	exit 1 ; \
	  fi

check_uid:
	@ if [ `id -u` -ne 0 ]; then \
		echo 'You need to be root to install TIE.' ; \
		exit 1; \
	  fi

install: check_uid check_tie head $(PLUGIN)
	@ $(MAKE) copy DESTDIR=$(INSTDIR)/plugins/$(NAME) --no-print-directory

uninstall: check_uid check_tie check_plugin
	@ echo 'Uninstalling $(NAME) plugin:'
	@ printf 'Removing plugin tree...'
	@ rm -rf $(INSTDIR)/plugins/$(NAME)
	@ printf 'done\n'
	@ printf 'Updating enabled_plugins file...'
	@ grep -v "^[# ]*$(NAME)" $(INSTDIR)/plugins/enabled_plugins > /tmp/ep
	@ mv /tmp/ep $(INSTDIR)/plugins/enabled_plugins
	@ printf 'done\n'

clean:
	@ printf 'Cleaning $(NAME) plugin folder...'
	@ rm -f $(OBJECTS) *.so 
	@ echo 'done'

