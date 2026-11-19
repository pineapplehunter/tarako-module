/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef TARAKO_EARLY_TLS_H
#define TARAKO_EARLY_TLS_H

#include <openssl/ssl.h>
#include <stdint.h>

#define BINDING_SIZE 32
#define CMW_LIMIT 49152
#ifdef TARAKO_TDX
#define EVIDENCE_TYPE "application/vnd.tarako.tdx-evidence+json"
#else
#define EVIDENCE_TYPE "application/vnd.tarako.tls-evidence+json"
#endif

/* Return 1 on success, 0 on failure. Buffers and keys are borrowed. */
struct attestation_callbacks {
    int (*emit)(void *arg, const uint8_t *binder, const uint8_t *spki_hash,
                char *cmw, size_t *length);
    int (*appraise)(void *arg, const uint8_t *binder, const uint8_t *spki_hash,
                    const char *cmw, size_t length);
    void *arg;
};

int early_tls_configure(SSL_CTX *ctx, int server);
int early_tls_attach(SSL *ssl, const struct attestation_callbacks *callbacks);

#endif
