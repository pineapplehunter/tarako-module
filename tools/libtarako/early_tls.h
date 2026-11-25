/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef TARAKO_EARLY_TLS_H
#define TARAKO_EARLY_TLS_H

#include <openssl/ssl.h>
#include <stdint.h>

#define BINDING_SIZE 32
#define CMW_LIMIT 49152
static inline const char *tarako_evidence_type(int tdx)
{
    return tdx ? "application/vnd.tarako.tdx-evidence+json"
               : "application/vnd.tarako.tls-evidence+json";
}

/* Return 1 on success, 0 on failure. Buffers and keys are borrowed. */
struct attestation_callbacks {
    int (*emit)(void *arg, const uint8_t *binder, const uint8_t *spki_hash,
                char *cmw, size_t *length);
    int (*appraise)(void *arg, const uint8_t *binder, const uint8_t *spki_hash,
                    const char *cmw, size_t length);
    void *arg;
    int tdx;
};

int early_tls_configure(SSL_CTX *ctx, int server);
int early_tls_attach(SSL *ssl, const struct attestation_callbacks *callbacks);
int early_tls_socket_timeout(BIO *socket, int seconds);

#endif
