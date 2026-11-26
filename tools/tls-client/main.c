#include "evidence.h"

#include <arpa/inet.h>
#include <curl/curl.h>
#include <nghttp2/nghttp2.h>
#include <openssl/err.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>

struct endpoint {
    const char *address, *name, *authority, *path;
    const char *ca, *verifier_key;
};

static int http2_configure_client(SSL *ssl)
{
    static const unsigned char alpn[] = {2, 'h', '2'};
    return SSL_set_alpn_protos(ssl, alpn, sizeof(alpn)) == 0;
}

static int is_h2(SSL *ssl)
{
    const unsigned char *protocol;
    unsigned int length;
    SSL_get0_alpn_selected(ssl, &protocol, &length);
    if (length == 2 && memcmp(protocol, "h2", 2) == 0)
        return 1;
    fputs("TLS did not negotiate h2\n", stderr);
    return 0;
}

struct exchange {
    int32_t stream;
    int closed; /* 1 for normal close, -1 for a stream error. */
    int status_ok;
    char body[4096];
    size_t body_length;
};

static int stream_closed(nghttp2_session *session, int32_t stream, uint32_t error, void *arg)
{
    struct exchange *ex = arg;
    (void)session;
    if (stream == ex->stream)
        ex->closed = error == NGHTTP2_NO_ERROR ? 1 : -1;
    return 0;
}

static int flush_frames(SSL *ssl, nghttp2_session *session)
{
    const uint8_t *data;
    nghttp2_ssize n;
    while ((n = nghttp2_session_mem_send2(session, &data)) > 0) {
        size_t written;
        if (!SSL_write_ex(ssl, data, (size_t)n, &written) || written != (size_t)n)
            return 0;
    }
    return n == 0;
}

static int run_exchange(SSL *ssl, nghttp2_session *session, const struct exchange *ex)
{
    uint8_t data[4096];
    while (!ex->closed && flush_frames(ssl, session)) {
        size_t length;
        if (!nghttp2_session_want_read(session) || !SSL_read_ex(ssl, data, sizeof(data), &length) ||
            nghttp2_session_mem_recv2(session, data, length) != (nghttp2_ssize)length)
            return 0;
    }
    return ex->closed == 1;
}

static nghttp2_nv header(const char *name, const char *value)
{
    /* nghttp2 copies both strings when the HEADERS frame is submitted. */
    return (nghttp2_nv){(uint8_t *)name, (uint8_t *)value, strlen(name), strlen(value), NGHTTP2_NV_FLAG_NONE};
}

static int matches(const uint8_t *bytes, size_t length, const char *text)
{
    return length == strlen(text) && memcmp(bytes, text, length) == 0;
}

static int response_header(nghttp2_session *session, const nghttp2_frame *frame,
                           const uint8_t *name, size_t namelen, const uint8_t *value,
                           size_t valuelen, uint8_t flags, void *arg)
{
    struct exchange *ex = arg;
    (void)session; (void)flags;
    if (frame->hd.stream_id == ex->stream && matches(name, namelen, ":status"))
        ex->status_ok = matches(value, valuelen, "200");
    return 0;
}

static int receive_body(nghttp2_session *session, uint8_t flags, int32_t stream,
                        const uint8_t *data, size_t length, void *arg)
{
    struct exchange *ex = arg;
    (void)session; (void)flags;
    if (stream != ex->stream || length > sizeof(ex->body) - ex->body_length)
        return NGHTTP2_ERR_CALLBACK_FAILURE;
    memcpy(ex->body + ex->body_length, data, length);
    ex->body_length += length;
    return 0;
}

static int http2_get(SSL *ssl, const char *authority, const char *path)
{
    nghttp2_session_callbacks *callbacks;
    if (!is_h2(ssl) || nghttp2_session_callbacks_new(&callbacks) != 0)
        return 0;
    nghttp2_session_callbacks_set_on_header_callback(callbacks, response_header);
    nghttp2_session_callbacks_set_on_data_chunk_recv_callback(callbacks, receive_body);
    nghttp2_session_callbacks_set_on_stream_close_callback(callbacks, stream_closed);
    struct exchange ex = {0};
    nghttp2_session *session = NULL;
    int rc = nghttp2_session_client_new(&session, callbacks, &ex);
    nghttp2_session_callbacks_del(callbacks);
    if (rc != 0)
        return 0;

    const nghttp2_settings_entry settings = {NGHTTP2_SETTINGS_ENABLE_PUSH, 0};
    const nghttp2_nv headers[] = {
        header(":method", "GET"), header(":scheme", "https"),
        header(":authority", authority), header(":path", path),
    };
    if (nghttp2_submit_settings(session, NGHTTP2_FLAG_NONE, &settings, 1) == 0)
        ex.stream = nghttp2_submit_request2(session, NULL, headers, 4, NULL, NULL);
    int ok = ex.stream > 0 && run_exchange(ssl, session, &ex) && ex.status_ok;
    nghttp2_session_del(session);
    if (!ok) {
        fputs("attested server did not return a complete HTTP/2 200 response\n", stderr);
        return 0;
    }
    return fwrite(ex.body, 1, ex.body_length, stdout) == ex.body_length && fflush(stdout) == 0;
}

static int set_host(SSL *ssl, const char *host)
{
    char unbracketed[INET6_ADDRSTRLEN];
    uint8_t address[16];
    size_t len = strlen(host);
    if (len > 2 && len - 2 < sizeof(unbracketed) && host[0] == '[' && host[len - 1] == ']') {
        memcpy(unbracketed, host + 1, len - 2);
        unbracketed[len - 2] = 0;
        return X509_VERIFY_PARAM_set1_ip_asc(SSL_get0_param(ssl), unbracketed);
    }
    if (inet_pton(AF_INET, host, address) == 1 || inet_pton(AF_INET6, host, address) == 1)
        return X509_VERIFY_PARAM_set1_ip_asc(SSL_get0_param(ssl), host);
    return SSL_set1_host(ssl, host) && SSL_set_tlsext_host_name(ssl, host);
}

static int valid_target(const char *s)
{
    for (; *s; s++) {
        if ((unsigned char)*s <= 32 || (unsigned char)*s >= 127)
            return 0;
    }
    return 1;
}

static int client_fetch(const struct endpoint *ep, struct verifier *verifier)
{
    if (!*ep->name || !valid_target(ep->name) || !valid_target(ep->authority) ||
        ep->path[0] != '/' || !valid_target(ep->path)) {
        fputs("invalid HTTPS request target\n", stderr);
        return 0;
    }
    const struct attestation_callbacks callbacks = {
        .appraise = appraise_evidence, .arg = verifier, .tdx = 0,
    };
    BIO *pem = BIO_new_file(ep->verifier_key, "r");
    if (pem)
        verifier->public_key = PEM_read_bio_PUBKEY(pem, NULL, NULL, NULL);
    BIO_free(pem);
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    SSL *ssl = NULL;
    BIO *socket = NULL;
    int ok = 0;
    if (!ctx || !verifier->public_key || !EVP_PKEY_is_a(verifier->public_key, "EC") ||
        !early_tls_configure(ctx, 0) ||
        !SSL_CTX_load_verify_locations(ctx, ep->ca, NULL))
        goto done;
    ssl = SSL_new(ctx);
    socket = BIO_new_connect(ep->address);
    if (!ssl || !socket || !set_host(ssl, ep->name) || !early_tls_attach(ssl, &callbacks) ||
        !http2_configure_client(ssl) ||
        BIO_do_connect(socket) != 1 || !early_tls_socket_timeout(socket, 10))
        goto done;
    SSL_set_bio(ssl, socket, socket);
    socket = NULL;
    if (SSL_connect(ssl) != 1)
        goto done;
    ok = http2_get(ssl, ep->authority, ep->path);
    SSL_shutdown(ssl);
done:
    BIO_free(socket);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    EVP_PKEY_free(verifier->public_key);
    return ok;
}

static int run(int argc, char **argv)
{
    if (argc != 6) {
        fprintf(stderr, "usage: %s address:port hostname ca.pem verifier-url verifier-public.pem\n", argv[0]);
        return 0;
    }
    const struct endpoint ep = {
        .address = argv[1], .name = argv[2], .authority = argv[2],
        .path = "/", .ca = argv[3], .verifier_key = argv[5],
    };
    struct verifier verifier = {.url = argv[4]};
    return client_fetch(&ep, &verifier);
}

int main(int argc, char **argv)
{
    signal(SIGPIPE, SIG_IGN);
    if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK)
        return 1;
    int ok = run(argc, argv);
    if (!ok)
        ERR_print_errors_fp(stderr);
    curl_global_cleanup();
    return ok ? 0 : 1;
}
