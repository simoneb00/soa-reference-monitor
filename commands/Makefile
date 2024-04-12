COMMANDS = print_blacklist add_to_blacklist switch_state remove_from_blacklist
OBJS = $(patsubst %,%.o,$(COMMANDS))

.PHONY: all install clean

all: $(COMMANDS)

install: $(COMMANDS)
	for cmd in $(COMMANDS); do \
		mv $$cmd /usr/local/bin/$$cmd; \
		chmod +x /usr/local/bin/$$cmd; \
	done

$(COMMANDS): %: %.c get_syscall_codes.c
	gcc $^ -o $@

clean:
	rm -f $(COMMANDS) $(OBJS) get_syscall_codes
