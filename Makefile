CC ?= gcc
PKG_CONFIG ?= pkg-config

CPPFLAGS += $(shell $(PKG_CONFIG) --cflags libsodium)
CFLAGS ?= -std=c17 -O2 -Wall -Wextra -Wshadow -Wpedantic -fstack-protector-strong -D_FORTIFY_SOURCE=3
LDLIBS += $(shell $(PKG_CONFIG) --libs libsodium)

all: lcc

lcc: lcc.c
	$(CC) $(CPPFLAGS) $(CFLAGS) $< -o $@ $(LDLIBS)

check: lcc
	./lcc selftest

clean:
	rm -f lcc *.o msg.txt msg.out msg.lcc

.PHONY: all check clean
