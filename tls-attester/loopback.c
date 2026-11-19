/* SPDX-License-Identifier: GPL-2.0-only */
#include "early_tls.h"

#include <assert.h>
#include <openssl/err.h>
#include <stdio.h>
#include <string.h>

struct sample {
    unsigned char binder[BINDING_SIZE], spki[BINDING_SIZE];
    int emitted, appraised, reject;
};

static int emit(void *arg, const uint8_t *binder, const uint8_t *spki,
                char *cmw, size_t *length)
{
    struct sample *s = arg;
    assert(*length >= 2);
    s->emitted++;
    memcpy(s->binder, binder, BINDING_SIZE);
    memcpy(s->spki, spki, BINDING_SIZE);
    memcpy(cmw, "[]", 2);
    *length = 2;
    return 1;
}

static int appraise(void *arg, const uint8_t *binder, const uint8_t *spki,
                    const char *cmw, size_t length)
{
    struct sample *s = arg;
    assert(s->emitted == 1);
    assert(length == 2 && memcmp(cmw, "[]", 2) == 0);
    assert(memcmp(s->binder, binder, BINDING_SIZE) == 0);
    assert(memcmp(s->spki, spki, BINDING_SIZE) == 0);
    s->appraised++;
    return !s->reject;
}

static int step(SSL *ssl)
{
    if (SSL_is_init_finished(ssl))
        return 1;
    int ret = SSL_do_handshake(ssl);
    if (ret == 1)
        return 1;
    int error = SSL_get_error(ssl, ret);
    return error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE ? 0 : -1;
}

static void run(const char *cert, const char *key, int retry, int reject,
                unsigned char *last_binder)
{
    struct sample sample = {.reject = reject};
    struct attestation_callbacks cb = {.emit = emit, .appraise = appraise, .arg = &sample};
    SSL_CTX *cc = SSL_CTX_new(TLS_client_method());
    SSL_CTX *sc = SSL_CTX_new(TLS_server_method());
    assert(cc && sc && early_tls_configure(cc, 0) && early_tls_configure(sc, 1));
    assert(SSL_CTX_load_verify_locations(cc, cert, NULL));
    assert(SSL_CTX_use_certificate_chain_file(sc, cert));
    assert(SSL_CTX_use_PrivateKey_file(sc, key, SSL_FILETYPE_PEM));
    assert(SSL_CTX_set1_groups_list(cc, "*X25519:P-256"));
    assert(SSL_CTX_set1_groups_list(sc, retry ? "P-256" : "X25519"));
    SSL *client = SSL_new(cc), *server = SSL_new(sc);
    assert(client && server && SSL_set1_host(client, "localhost"));
    assert(early_tls_attach(client, &cb) && early_tls_attach(server, &cb));
    BIO *a, *b;
    assert(BIO_new_bio_pair(&a, 0, &b, 0) == 1);
    SSL_set_bio(client, a, a);
    SSL_set_bio(server, b, b);
    SSL_set_connect_state(client);
    SSL_set_accept_state(server);

    int c = 0, s = 0;
    for (int i = 0; i < 32 && c >= 0 && s >= 0 && (!c || !s); i++) {
        c = step(client);
        if (c >= 0)
            s = step(server);
    }
    if (!reject && (c != 1 || s != 1))
        ERR_print_errors_fp(stderr);
    assert(sample.emitted == 1 && sample.appraised == 1);
    assert(reject ? c == -1 : (c == 1 && s == 1));
    assert(memcmp(last_binder, sample.binder, BINDING_SIZE) != 0);
    memcpy(last_binder, sample.binder, BINDING_SIZE);
    SSL_free(server);
    SSL_free(client);
    SSL_CTX_free(sc);
    SSL_CTX_free(cc);
}

int main(int argc, char **argv)
{
    unsigned char last_binder[BINDING_SIZE] = {0};
    assert(argc == 3);
    run(argv[1], argv[2], 0, 0, last_binder);
    run(argv[1], argv[2], 1, 0, last_binder);
    run(argv[1], argv[2], 1, 1, last_binder);
    puts("early TLS loopback passed: normal, HelloRetryRequest, and failed appraisal");
}
