COMMANDS = print_blacklist add_to_blacklist switch_state remove_from_blacklist

.PHONY: all install

all: $(COMMANDS)

install: $(COMMANDS)
	for cmd in $(COMMANDS); do \
		mv $$cmd /usr/local/bin/$$cmd; \
		chmod +x /usr/local/bin/$$cmd; \
	done

$(COMMANDS): %: %.c
	gcc $< -o $@
