/* SPDX-License-Identifier: GPL-2.0-only */
#include "early_tls.h"

#include <openssl/kdf.h>
#include <openssl/tls1.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>

/* Experimental private-use codepoint; not an IANA registration. */
#define REMOTE_ATTESTATION 0xffa5

struct handshake {
    struct attestation_callbacks callbacks;
    EVP_MD_CTX *transcript;
    uint8_t checkpoint[BINDING_SIZE];
    uint8_t evidence[3 + CMW_LIMIT];
    size_t evidence_length;
    unsigned int client_hellos;
    int retry, ready, failed, selected;
};

static CRYPTO_ONCE index_once = CRYPTO_ONCE_STATIC_INIT;
static int state_index = -1;

static void free_state(void *parent, void *ptr, CRYPTO_EX_DATA *ad,
                       int index, long argl, void *argp)
{
    struct handshake *hs = ptr;
    (void)parent; (void)ad; (void)index; (void)argl; (void)argp;
    if (hs) {
        EVP_MD_CTX_free(hs->transcript);
        OPENSSL_free(hs);
    }
}

static void make_index(void)
{
    state_index = SSL_get_ex_new_index(0, NULL, NULL, NULL, free_state);
}

static struct handshake *state(SSL *ssl)
{
    return SSL_get_ex_data(ssl, state_index);
}

static void transcript_message(int write, int version, int type, const void *buf,
                               size_t len, SSL *ssl, void *arg)
{
    static const uint8_t hrr_random[] = {
        0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11,
        0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
        0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e,
        0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
    };
    const uint8_t *msg = buf;
    struct handshake *hs = state(ssl);
    (void)write; (void)version; (void)arg;

    if (!hs || hs->ready || hs->failed || type != SSL3_RT_HANDSHAKE || len < 4)
        return;
    switch (msg[0]) {
    case SSL3_MT_CLIENT_HELLO:
        if (hs->client_hellos != (unsigned int)hs->retry) {
            hs->failed = 1;
            return;
        }
        hs->client_hellos++;
        hs->failed = !EVP_DigestUpdate(hs->transcript, buf, len);
        break;
    case SSL3_MT_SERVER_HELLO:
        if (len < 38 || hs->client_hellos != 1U + (unsigned int)hs->retry) {
            hs->failed = 1;
            return;
        }
        /* Four-byte handshake header, two-byte legacy_version, then Random. */
        if (memcmp(msg + 6, hrr_random, sizeof(hrr_random)) == 0) {
            uint8_t synthetic[4 + BINDING_SIZE] = {SSL3_MT_MESSAGE_HASH, 0, 0, BINDING_SIZE};
            if (hs->retry) {
                hs->failed = 1;
                return;
            }
            if (!EVP_DigestFinal_ex(hs->transcript, synthetic + 4, NULL) ||
                !EVP_DigestInit_ex(hs->transcript, EVP_sha256(), NULL) ||
                !EVP_DigestUpdate(hs->transcript, synthetic, sizeof(synthetic))) {
                hs->failed = 1;
                return;
            }
            hs->retry = 1;
            hs->failed = !EVP_DigestUpdate(hs->transcript, buf, len);
            return;
        }
        hs->ready = EVP_DigestUpdate(hs->transcript, buf, len) &&
            EVP_DigestFinal_ex(hs->transcript, hs->checkpoint, NULL);
        hs->failed = !hs->ready;
        break;
    }
}

static int expand_label(const uint8_t *key, const char *label,
                        const uint8_t *context, uint8_t *out)
{
    /* RFC 9846 HkdfLabel for this profile's fixed SHA-256 output and context. */
    uint8_t info[3 + 32 + 1 + BINDING_SIZE] = {0, BINDING_SIZE};
    const size_t label_len = strlen(label);
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    size_t out_len = BINDING_SIZE;
    info[2] = (uint8_t)label_len;
    memcpy(info + 3, label, label_len);
    info[3 + label_len] = BINDING_SIZE;
    memcpy(info + 4 + label_len, context, BINDING_SIZE);
    int ok = ctx && EVP_PKEY_derive_init(ctx) > 0 &&
        EVP_PKEY_CTX_hkdf_mode(ctx, EVP_PKEY_HKDEF_MODE_EXPAND_ONLY) > 0 &&
        EVP_PKEY_CTX_set_hkdf_md(ctx, EVP_sha256()) > 0 &&
        EVP_PKEY_CTX_set1_hkdf_key(ctx, key, BINDING_SIZE) > 0 &&
        EVP_PKEY_CTX_add1_hkdf_info(ctx, info, (int)(4 + label_len + BINDING_SIZE)) > 0 &&
        EVP_PKEY_derive(ctx, out, &out_len) > 0 && out_len == BINDING_SIZE;
    EVP_PKEY_CTX_free(ctx);
    return ok;
}

static int binding(struct handshake *hs, X509 *leaf, uint8_t *binder, uint8_t *spki_hash)
{
    uint8_t *der = NULL;
    uint8_t base[BINDING_SIZE];
    const uint8_t zeros[BINDING_SIZE] = {0};
    if (!hs || !hs->ready || hs->failed || !leaf)
        return 0;
    int n = i2d_X509_PUBKEY(X509_get_X509_PUBKEY(leaf), &der);
    int ok = n > 0 && SHA256(der, (size_t)n, spki_hash) &&
        expand_label(zeros, "tls13 attestation base", hs->checkpoint, base) &&
        expand_label(base, "tls13 attestation", spki_hash, binder);
    OPENSSL_free(der);
    return ok;
}

static size_t put_scheme(uint8_t *out, int tdx)
{
    const char *type = tarako_evidence_type(tdx);
    size_t len = strlen(type);
    /* The offer stores the whole scheme length in one byte. */
    out[0] = 0;
    out[1] = 1;
    out[2] = 0;
    out[3] = (uint8_t)len;
    memcpy(out + 4, type, len);
    return 4 + len;
}

static int add_extension(SSL *ssl, unsigned int id, unsigned int context,
                         const unsigned char **out, size_t *outlen, X509 *cert,
                         size_t chainidx, int *alert, void *arg)
{
    struct handshake *hs = state(ssl);
    uint8_t binder[BINDING_SIZE], spki_hash[BINDING_SIZE];
    size_t length = CMW_LIMIT;
    (void)id; (void)arg;

    if (!hs)
        goto fail;
    switch (context) {
    case SSL_EXT_CLIENT_HELLO:
        /* Offer one server-attester scheme and no client-attester schemes. */
        hs->evidence[0] = 0;
        hs->evidence[1] = (uint8_t)put_scheme(hs->evidence + 2, hs->callbacks.tdx);
        *outlen = 2 + hs->evidence[1];
        hs->evidence[(*outlen)++] = 0;
        hs->evidence[(*outlen)++] = 0;
        break;
    case SSL_EXT_TLS1_3_ENCRYPTED_EXTENSIONS:
        if (!hs->selected)
            goto fail;
        *outlen = put_scheme(hs->evidence, hs->callbacks.tdx);
        break;
    case SSL_EXT_TLS1_3_CERTIFICATE:
        if (chainidx != 0)
            return 0;
        if (!hs->selected || !hs->callbacks.emit || !binding(hs, cert, binder, spki_hash) ||
            !hs->callbacks.emit(hs->callbacks.arg, binder, spki_hash,
                                (char *)hs->evidence + 3, &length) ||
            length == 0 || length > CMW_LIMIT)
            goto fail;
        hs->evidence[0] = 0;
        hs->evidence[1] = (uint8_t)(length >> 8);
        hs->evidence[2] = (uint8_t)length;
        *outlen = 3 + length;
        break;
    default:
        return 0;
    }
    *out = hs->evidence;
    return 1;
fail:
    *alert = SSL_AD_INTERNAL_ERROR;
    return -1;
}

static int parse_extension(SSL *ssl, unsigned int id, unsigned int context,
                           const unsigned char *in, size_t inlen, X509 *cert,
                           size_t chainidx, int *alert, void *arg)
{
    struct handshake *hs = state(ssl);
    uint8_t expected[UINT8_MAX];
    (void)id; (void)cert; (void)arg;

    *alert = SSL_AD_ILLEGAL_PARAMETER;
    if (!hs)
        return 0;
    const size_t n = put_scheme(expected, hs->callbacks.tdx);
    switch (context) {
    case SSL_EXT_CLIENT_HELLO:
        /* This experimental profile accepts exactly its own single offer. */
        if (inlen != 2 + n + 2 || in[0] || in[1] != n ||
            memcmp(in + 2, expected, n) || in[2 + n] || in[3 + n])
            return 0;
        hs->selected = 1;
        return 1;
    case SSL_EXT_TLS1_3_ENCRYPTED_EXTENSIONS:
        if (inlen != n || memcmp(in, expected, n))
            return 0;
        hs->selected = 1;
        return 1;
    case SSL_EXT_TLS1_3_CERTIFICATE:
        if (chainidx != 0 || !hs->selected)
            return 0;
        *alert = SSL_AD_BAD_CERTIFICATE;
        if (inlen <= 3 || inlen > sizeof(hs->evidence) || in[0] ||
            (((size_t)in[1] << 8) | in[2]) != inlen - 3)
            return 0;
        hs->evidence_length = inlen - 3;
        memcpy(hs->evidence, in + 3, hs->evidence_length);
        return 1;
    default:
        return 0;
    }
}

static int require_offer(SSL *ssl, int *alert, void *arg)
{
    const unsigned char *p;
    size_t length;
    (void)arg;
    if (SSL_client_hello_get0_ext(ssl, REMOTE_ATTESTATION, &p, &length))
        return SSL_CLIENT_HELLO_SUCCESS;
    fputs("missing required attestation offer\n", stderr);
    *alert = SSL_AD_MISSING_EXTENSION;
    return SSL_CLIENT_HELLO_ERROR;
}

static int verify_certificate(X509_STORE_CTX *store, void *arg)
{
    SSL *ssl = X509_STORE_CTX_get_ex_data(store, SSL_get_ex_data_X509_STORE_CTX_idx());
    struct handshake *hs = state(ssl);
    uint8_t binder[BINDING_SIZE], spki_hash[BINDING_SIZE];
    (void)arg;

    if (X509_verify_cert(store) != 1) {
        fprintf(stderr, "TLS authentication: %s\n",
                X509_verify_cert_error_string(X509_STORE_CTX_get_error(store)));
        return 0;
    }
    if (!hs || !hs->selected || hs->evidence_length == 0 || !hs->callbacks.appraise ||
        !binding(hs, X509_STORE_CTX_get0_cert(store), binder, spki_hash) ||
        !hs->callbacks.appraise(hs->callbacks.arg, binder, spki_hash,
                                (const char *)hs->evidence, hs->evidence_length)) {
        fprintf(stderr, "attestation missing or rejected\n");
        X509_STORE_CTX_set_error(store, X509_V_ERR_APPLICATION_VERIFICATION);
        return 0;
    }
    return 1;
}

int early_tls_configure(SSL_CTX *ctx, int server)
{
    if (!CRYPTO_THREAD_run_once(&index_once, make_index) || state_index < 0 ||
        !SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION) ||
        !SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION) ||
        !SSL_CTX_set_ciphersuites(ctx, "TLS_AES_128_GCM_SHA256") ||
        !SSL_CTX_set_num_tickets(ctx, 0) || !SSL_CTX_set_max_early_data(ctx, 0) ||
        !SSL_CTX_add_custom_ext(ctx, REMOTE_ATTESTATION, SSL_EXT_TLS_ONLY |
              SSL_EXT_TLS1_3_ONLY | SSL_EXT_CLIENT_HELLO |
              SSL_EXT_TLS1_3_ENCRYPTED_EXTENSIONS | SSL_EXT_TLS1_3_CERTIFICATE,
              add_extension, NULL, NULL, parse_extension, NULL))
        return 0;

    SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);
    SSL_CTX_set_msg_callback(ctx, transcript_message);
    if (server) {
        SSL_CTX_set_client_hello_cb(ctx, require_offer, NULL);
    } else {
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
        SSL_CTX_set_cert_verify_callback(ctx, verify_certificate, NULL);
    }
    return 1;
}

int early_tls_attach(SSL *ssl, const struct attestation_callbacks *callbacks)
{
    if (state_index < 0 || state(ssl))
        return 0;
    struct handshake *hs = OPENSSL_zalloc(sizeof(*hs));
    if (!hs)
        return 0;
    hs->callbacks = *callbacks;
    hs->transcript = EVP_MD_CTX_new();
    if (hs->transcript && EVP_DigestInit_ex(hs->transcript, EVP_sha256(), NULL) &&
        SSL_set_ex_data(ssl, state_index, hs))
        return 1;
    EVP_MD_CTX_free(hs->transcript);
    OPENSSL_free(hs);
    return 0;
}

int early_tls_socket_timeout(BIO *socket, int seconds)
{
    const struct timeval timeout = {.tv_sec = seconds};
    int fd = BIO_get_fd(socket, NULL);
    return fd >= 0 && setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0 &&
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) == 0;
}
