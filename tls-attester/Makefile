# SPDX-License-Identifier: GPL-2.0-only

PKG_CONFIG ?= pkg-config
OPENSSL ?= openssl
READELF ?= readelf
PREFIX ?= /usr/local

BINS := tarako-tls-attester tarako-tls-attester-test tarako-tls-client
ENDPOINT_SRC := early_tls.c evidence.c main.c
ENDPOINT_HEADERS := early_tls.h evidence.h
WARNINGS := -std=c11 -Wall -Wextra -Werror
ENDPOINT_CFLAGS = $(shell $(PKG_CONFIG) --cflags libcurl json-c openssl)
ENDPOINT_LIBS = $(shell $(PKG_CONFIG) --static --libs libcurl json-c openssl)

.PHONY: all check install clean

all: $(BINS)

tarako-tls-attester-test: CPPFLAGS += -DTARAKO_TEST
tarako-tls-client: CPPFLAGS += -DTARAKO_CLIENT
$(BINS): $(ENDPOINT_SRC) $(ENDPOINT_HEADERS)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(WARNINGS) $(ENDPOINT_CFLAGS) $(LDFLAGS) -static \
		$(ENDPOINT_SRC) $(ENDPOINT_LIBS) $(LDLIBS) -pthread -o $@

loopback: early_tls.c loopback.c early_tls.h
	$(CC) $(CPPFLAGS) $(CFLAGS) $(WARNINGS) $(shell $(PKG_CONFIG) --cflags openssl) \
		$(LDFLAGS) -static early_tls.c loopback.c \
		$(shell $(PKG_CONFIG) --static --libs openssl) $(LDLIBS) -pthread -o $@

check: all loopback
	@set -eu; \
	tmp=$$(mktemp -d); trap 'rm -rf "$$tmp"' EXIT; \
	$(OPENSSL) req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -noenc \
		-subj /CN=localhost -addext subjectAltName=DNS:localhost \
		-keyout "$$tmp/key.pem" -out "$$tmp/cert.pem" -days 1; \
	OPENSSL_CONF=/dev/null OPENSSL_MODULES=/nonexistent ./loopback "$$tmp/cert.pem" "$$tmp/key.pem"; \
	for binary in $(BINS) loopback; do \
		$(READELF) -lW "$$binary" > "$$tmp/headers"; \
		if grep -E 'INTERP|DYNAMIC' "$$tmp/headers"; then \
			echo "$$binary is not statically linked" >&2; exit 1; \
		fi; \
	done

install: all
	install -d "$(DESTDIR)$(PREFIX)/bin"
	install -m755 $(BINS) "$(DESTDIR)$(PREFIX)/bin/"

clean:
	rm -f $(BINS) loopback
