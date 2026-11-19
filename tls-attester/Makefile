# SPDX-License-Identifier: GPL-2.0-only

PKG_CONFIG ?= pkg-config
PREFIX ?= /usr/local

BINS := tarako-tls-attester tarako-tls-client
ENDPOINT_SRC := early_tls.c evidence.c main.c
ENDPOINT_HEADERS := early_tls.h evidence.h
WARNINGS := -std=c11 -Wall -Wextra -Werror
ENDPOINT_CFLAGS = $(shell $(PKG_CONFIG) --cflags libcurl json-c openssl)
ENDPOINT_LIBS = $(shell $(PKG_CONFIG) --static --libs libcurl json-c openssl)

.PHONY: all install clean

all: $(BINS)

tarako-tls-client: CPPFLAGS += -DTARAKO_CLIENT
$(BINS): $(ENDPOINT_SRC) $(ENDPOINT_HEADERS)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(WARNINGS) $(ENDPOINT_CFLAGS) $(LDFLAGS) -static \
		$(ENDPOINT_SRC) $(ENDPOINT_LIBS) $(LDLIBS) -pthread -o $@

install: all
	install -d "$(DESTDIR)$(PREFIX)/bin"
	install -m755 $(BINS) "$(DESTDIR)$(PREFIX)/bin/"

clean:
	rm -f $(BINS)
