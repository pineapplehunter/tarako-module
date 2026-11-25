#include "evidence.h"

#include <curl/curl.h>
#include <nghttp2/nghttp2.h>
#include <openssl/err.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>

static const unsigned char h2[] = {2, 'h', '2'};

static int select_h2(SSL *ssl, const unsigned char **out, unsigned char *outlen,
                     const unsigned char *in, unsigned int inlen, void *arg)
{
    unsigned char *selected;
    (void)ssl; (void)arg;
    if (SSL_select_next_proto(&selected, outlen, h2, sizeof(h2), in, inlen) != OPENSSL_NPN_NEGOTIATED)
        return SSL_TLSEXT_ERR_ALERT_FATAL;
    *out = selected;
    return SSL_TLSEXT_ERR_OK;
}

static void http2_configure_server(SSL_CTX *ctx)
{
    SSL_CTX_set_alpn_select_cb(ctx, select_h2, NULL);
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
    int get, root;
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
    while (flush_frames(ssl, session)) {
        if (ex->closed)
            return ex->closed == 1;
        size_t length;
        if (!nghttp2_session_want_read(session) || !SSL_read_ex(ssl, data, sizeof(data), &length) ||
            nghttp2_session_mem_recv2(session, data, length) != (nghttp2_ssize)length)
            break;
    }
    return 0;
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

static int request_header(nghttp2_session *session, const nghttp2_frame *frame,
                          const uint8_t *name, size_t namelen, const uint8_t *value,
                          size_t valuelen, uint8_t flags, void *arg)
{
    struct exchange *ex = arg;
    (void)session; (void)flags;
    if (frame->headers.cat != NGHTTP2_HCAT_REQUEST)
        return 0;
    if (!ex->stream)
        ex->stream = frame->hd.stream_id;
    if (frame->hd.stream_id == ex->stream) {
        if (matches(name, namelen, ":method"))
            ex->get = matches(value, valuelen, "GET");
        if (matches(name, namelen, ":path"))
            ex->root = matches(value, valuelen, "/");
    }
    return 0;
}

static nghttp2_ssize send_body(nghttp2_session *session, int32_t stream, uint8_t *out,
                              size_t capacity, uint32_t *flags, nghttp2_data_source *source, void *arg)
{
    const char *body = source->ptr;
    size_t length = strlen(body);
    (void)session; (void)stream; (void)arg;
    if (length <= capacity)
        *flags |= NGHTTP2_DATA_FLAG_EOF;
    else
        length = capacity;
    memcpy(out, body, length);
    source->ptr = (char *)source->ptr + length;
    return (nghttp2_ssize)length;
}

static int respond(nghttp2_session *session, const nghttp2_frame *frame, void *arg)
{
    const struct exchange *ex = arg;
    if (!ex->stream || frame->hd.stream_id != ex->stream ||
        (frame->hd.type != NGHTTP2_HEADERS && frame->hd.type != NGHTTP2_DATA) ||
        !(frame->hd.flags & NGHTTP2_FLAG_END_STREAM))
        return 0;

    int accepted = ex->get && ex->root;
    nghttp2_nv headers[] = {
        header(":status", accepted ? "200" : ex->get ? "404" : "405"),
        header("content-type", "text/plain"),
    };
    nghttp2_data_provider2 body = {.source.ptr = "Tarako OK", .read_callback = send_body};
    if (nghttp2_submit_response2(session, ex->stream, headers, 2, accepted ? &body : NULL) != 0)
        return NGHTTP2_ERR_CALLBACK_FAILURE;
    if (accepted) {
        puts("HTTP request accepted");
        fflush(stdout);
    }
    return 0;
}

static int http2_serve(SSL *ssl)
{
    nghttp2_session_callbacks *callbacks;
    if (!is_h2(ssl) || nghttp2_session_callbacks_new(&callbacks) != 0)
        return 0;
    nghttp2_session_callbacks_set_on_header_callback(callbacks, request_header);
    nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks, respond);
    nghttp2_session_callbacks_set_on_stream_close_callback(callbacks, stream_closed);
    struct exchange ex = {0};
    nghttp2_session *session = NULL;
    int rc = nghttp2_session_server_new(&session, callbacks, &ex);
    nghttp2_session_callbacks_del(callbacks);
    if (rc != 0)
        return 0;

    const nghttp2_settings_entry settings = {NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 1};
    int ok = nghttp2_submit_settings(session, NGHTTP2_FLAG_NONE, &settings, 1) == 0 &&
        run_exchange(ssl, session, &ex) &&
        nghttp2_session_terminate_session2(session, ex.stream, NGHTTP2_NO_ERROR) == 0 &&
        flush_frames(ssl, session);
    nghttp2_session_del(session);
    return ok;
}


static int run(int argc, char **argv)
{
#ifdef TARAKO_TDX
    if (argc != 4) {
        fprintf(stderr, "usage: %s listen:port cert.pem key.pem\n", argv[0]);
        return 0;
    }
    const struct attestation_callbacks callbacks = {.tdx = 1, .emit = emit_evidence};
    const int timeout = 30;
#else
#ifdef TARAKO_TEST
    if (argc != 6) {
        fprintf(stderr, "usage: %s listen:port cert.pem key.pem signer-url {valid|tarako|platform|both}\n", argv[0]);
        return 0;
    }
#else
    if (argc != 5) {
        fprintf(stderr, "usage: %s listen:port cert.pem key.pem signer-url\n", argv[0]);
        return 0;
    }
#endif
    struct quote_source quote_source = {.url = argv[4]};
    const struct attestation_callbacks callbacks = {.emit = emit_evidence, .arg = &quote_source};
    const int timeout = 10;
#ifdef TARAKO_TEST
    if (strcmp(argv[5], "valid") != 0 && strcmp(argv[5], "tarako") != 0 &&
        strcmp(argv[5], "platform") != 0 && strcmp(argv[5], "both") != 0)
        return 0;
    quote_source.tarako_fault = strcmp(argv[5], "tarako") == 0 || strcmp(argv[5], "both") == 0;
    quote_source.platform_fault = strcmp(argv[5], "platform") == 0 || strcmp(argv[5], "both") == 0;
#endif
#endif
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    BIO *listener = BIO_new_accept(argv[1]);
    if (!ctx || !listener || !early_tls_configure(ctx, 1) ||
        !SSL_CTX_use_certificate_chain_file(ctx, argv[2]) ||
        !SSL_CTX_use_PrivateKey_file(ctx, argv[3], SSL_FILETYPE_PEM) ||
        !SSL_CTX_check_private_key(ctx) || !BIO_set_bind_mode(listener, BIO_BIND_REUSEADDR) ||
        BIO_do_accept(listener) != 1)
        goto done;
    http2_configure_server(ctx);
    while (BIO_do_accept(listener) == 1) {
        BIO *socket = BIO_pop(listener);
        SSL *ssl = SSL_new(ctx);
        if (ssl && socket && early_tls_socket_timeout(socket, timeout) && early_tls_attach(ssl, &callbacks)) {
            SSL_set_bio(ssl, socket, socket);
            socket = NULL;
            if (SSL_accept(ssl) != 1)
                ERR_print_errors_fp(stderr);
            else if (http2_serve(ssl) && SSL_shutdown(ssl) == 0) {
                /* Drain in-flight HTTP/2 frames before closing the TCP socket. */
                char buf[4096];
                size_t length;
                while (SSL_read_ex(ssl, buf, sizeof(buf), &length))
                    ;
            }
        }
        BIO_free(socket);
        SSL_free(ssl);
    }
done:
    BIO_free_all(listener);
    SSL_CTX_free(ctx);
    return 0;
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
