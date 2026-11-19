/* SPDX-License-Identifier: GPL-2.0-only */
#define _POSIX_C_SOURCE 200809L
#include "evidence.h"

#include <curl/curl.h>
#include <getopt.h>
#include <openssl/err.h>
#include <arpa/inet.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>

static int socket_timeouts(BIO *socket)
{
#ifdef TARAKO_TDX
    const struct timeval timeout = {.tv_sec = 30};
#else
    const struct timeval timeout = {.tv_sec = 10};
#endif
    int fd = BIO_get_fd(socket, NULL);
    return fd >= 0 && setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0 &&
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) == 0;
}

#if defined(TARAKO_CLIENT) && defined(TARAKO_TDX)
static int set_host(SSL *ssl, char *host)
{
    uint8_t address[16];
    size_t len = strlen(host);
    if (len > 2 && host[0] == '[' && host[len - 1] == ']') {
        host[len - 1] = 0;
        int ok = X509_VERIFY_PARAM_set1_ip_asc(SSL_get0_param(ssl), host + 1);
        host[len - 1] = ']';
        return ok;
    }
    if (inet_pton(AF_INET, host, address) == 1)
        return X509_VERIFY_PARAM_set1_ip_asc(SSL_get0_param(ssl), host);
    return SSL_set1_host(ssl, host) && SSL_set_tlsext_host_name(ssl, host);
}

/* The demo serves a small HTTP/1.0 response and then sends close_notify. */
static int get_resource(SSL *ssl, const char *authority, const char *path, const char *query)
{
    char request[4096];
    int n = snprintf(request, sizeof(request), "GET %s%s%s HTTP/1.0\r\nHost: %s\r\n\r\n",
                     path, query ? "?" : "", query ? query : "", authority);
    if (n <= 0 || (size_t)n >= sizeof(request) || SSL_write(ssl, request, n) != n)
        return 0;

    char response[4096];
    size_t used = 0;
    while (used < sizeof(response) - 1) {
        n = SSL_read(ssl, response + used, (int)(sizeof(response) - 1 - used));
        if (n <= 0)
            break;
        used += (size_t)n;
    }
    if (used == sizeof(response) - 1 || SSL_get_error(ssl, n) != SSL_ERROR_ZERO_RETURN) {
        fputs("HTTP response too large or not cleanly terminated\n", stderr);
        return 0;
    }
    response[used] = 0;
    const char *body = strstr(response, "\r\n\r\n");
    if (!body || strncmp(response, "HTTP/1.0 200 ", sizeof("HTTP/1.0 200 ") - 1)) {
        fputs("attested server did not return HTTP 200\n", stderr);
        return 0;
    }
    body += 4;
    return fwrite(body, 1, used - (size_t)(body - response), stdout) ==
        used - (size_t)(body - response) && fflush(stdout) == 0;
}

static int valid_target(const char *s)
{
    for (; *s; s++) {
        if ((unsigned char)*s <= 32 || (unsigned char)*s >= 127)
            return 0;
    }
    return 1;
}

static int run(int argc, char **argv)
{
    static const struct option opts[] = {
        {"ca", required_argument, NULL, 'c'},
        {"verifier", required_argument, NULL, 'V'},
        {"verifier-key", required_argument, NULL, 'k'},
        {"ima-log-url", required_argument, NULL, 'i'},
        {"tls-name", required_argument, NULL, 'n'},
        {"verbose", no_argument, NULL, 'v'},
        {0}
    };
    const char *ca = NULL, *key = NULL;
    char *tls_name = NULL;
    struct verifier verifier = {.url = "http://127.0.0.1:5102/verify"};
    int opt;
    while ((opt = getopt_long(argc, argv, "v", opts, NULL)) != -1) {
        switch (opt) {
        case 'c': ca = optarg; break;
        case 'k': key = optarg; break;
        case 'V': verifier.url = optarg; break;
        case 'i': verifier.ima_url = optarg; break;
        case 'n': tls_name = optarg; break;
        case 'v': verifier.verbose = 1; break;
        default: return 0;
        }
    }
    if (argc - optind != 1 || !key || !verifier.ima_url) {
        fprintf(stderr, "usage: %s [-v] [--ca CA.pem] [--verifier URL] "
                        "--verifier-key KEY.pem --ima-log-url URL https://host[:port]/\n", argv[0]);
        return 0;
    }
    CURLU *url = curl_url();
    char *scheme = NULL, *host = NULL, *port = NULL, *path = NULL, *query = NULL;
    char authority[320];
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    BIO *socket = NULL, *pem = NULL;
    int ok = 0;
    if (!url || curl_url_set(url, CURLUPART_URL, argv[optind], CURLU_DISALLOW_USER) ||
        curl_url_get(url, CURLUPART_SCHEME, &scheme, 0) || strcmp(scheme, "https") ||
        curl_url_get(url, CURLUPART_HOST, &host, 0) ||
        curl_url_get(url, CURLUPART_PORT, &port, CURLU_DEFAULT_PORT) ||
        curl_url_get(url, CURLUPART_PATH, &path, 0)) {
        fputs("expected an HTTPS URL without user information\n", stderr);
        goto done;
    }
    CURLUcode query_status = curl_url_get(url, CURLUPART_QUERY, &query, 0);
    int n = snprintf(authority, sizeof(authority), "%s:%s", host, port);
    if ((query_status != CURLUE_OK && query_status != CURLUE_NO_QUERY) || !valid_target(host) ||
        path[0] != '/' || !valid_target(path) || (query && !valid_target(query)) ||
        (tls_name && (!*tls_name || !valid_target(tls_name))) ||
        n <= 0 || (size_t)n >= sizeof(authority)) {
        fputs("invalid HTTPS request target\n", stderr);
        goto done;
    }
    const struct attestation_callbacks callbacks = {.appraise = appraise_evidence, .arg = &verifier};
    pem = BIO_new_file(key, "r");
    if (pem)
        verifier.public_key = PEM_read_bio_PUBKEY(pem, NULL, NULL, NULL);
    ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx || !verifier.public_key || !EVP_PKEY_is_a(verifier.public_key, "EC") ||
        !early_tls_configure(ctx, 0) ||
        !(ca ? SSL_CTX_load_verify_locations(ctx, ca, NULL) : SSL_CTX_set_default_verify_paths(ctx)))
        goto done;
    ssl = SSL_new(ctx);
    socket = BIO_new_connect(authority);
    if (!ssl || !socket || !set_host(ssl, tls_name ? tls_name : host) ||
        !early_tls_attach(ssl, &callbacks) ||
        BIO_do_connect(socket) != 1 || !socket_timeouts(socket))
        goto done;
    SSL_set_bio(ssl, socket, socket);
    socket = NULL;
    if (verifier.verbose)
        fprintf(stderr, "* Connecting to %s with required TDX attestation\n", authority);
    if (SSL_connect(ssl) != 1)
        goto done;
    if (verifier.verbose)
        fputs("* TLS handshake passed; sending GET\n", stderr);
    ok = get_resource(ssl, authority, path, query);
    SSL_shutdown(ssl);
done:
    BIO_free(socket);
    BIO_free(pem);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    EVP_PKEY_free(verifier.public_key);
    curl_free(query);
    curl_free(path);
    curl_free(port);
    curl_free(host);
    curl_free(scheme);
    curl_url_cleanup(url);
    return ok;
}
#elif defined(TARAKO_CLIENT)
static int run(int argc, char **argv)
{
    if (argc != 6) {
        fprintf(stderr, "usage: %s address:port hostname ca.pem verifier-url verifier-public.pem\n", argv[0]);
        return 0;
    }
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    SSL *ssl = NULL;
    BIO *socket = NULL, *pem = BIO_new_file(argv[5], "r");
    struct verifier verifier = {.url = argv[4], .public_key = pem ? PEM_read_bio_PUBKEY(pem, NULL, NULL, NULL) : NULL};
    const struct attestation_callbacks callbacks = {.appraise = appraise_evidence, .arg = &verifier};
    int ok = 0;
    if (!ctx || !verifier.public_key || !EVP_PKEY_is_a(verifier.public_key, "EC") ||
        !early_tls_configure(ctx, 0) || !SSL_CTX_load_verify_locations(ctx, argv[3], NULL))
        goto done;
    ssl = SSL_new(ctx);
    socket = BIO_new_connect(argv[1]);
    if (!ssl || !socket || !SSL_set1_host(ssl, argv[2]) ||
        !SSL_set_tlsext_host_name(ssl, argv[2]) || !early_tls_attach(ssl, &callbacks) ||
        BIO_do_connect(socket) != 1 || !socket_timeouts(socket))
        goto done;
    SSL_set_bio(ssl, socket, socket);
    socket = NULL;
    if (SSL_connect(ssl) != 1)
        goto done;

    char request[512];
    int n = snprintf(request, sizeof(request), "GET / HTTP/1.0\r\nHost: %s\r\n\r\n", argv[2]);
    if (n <= 0 || (size_t)n >= sizeof(request) || SSL_write(ssl, request, n) != n)
        goto done;
    char response[1024];
    size_t used = 0;
    while (used < sizeof(response)) {
        n = SSL_read(ssl, response + used, (int)(sizeof(response) - used));
        if (n <= 0)
            break;
        used += (size_t)n;
    }
    const char expected[] = "HTTP/1.0 200 OK\r\n";
    if (used < sizeof(expected) - 1 || memcmp(response, expected, sizeof(expected) - 1) ||
        fwrite(response, 1, used, stdout) != used)
        goto done;
    ok = 1;
    SSL_shutdown(ssl);
done:
    BIO_free(socket);
    BIO_free(pem);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    EVP_PKEY_free(verifier.public_key);
    return ok;
}
#else
static int serve_request(SSL *ssl)
{
    const char request_line[] = "GET / HTTP/1.0\r\n";
    const char response[] = "HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\n"
                            "Content-Length: 9\r\nConnection: close\r\n\r\nTarako OK";
    char request[4096];
    size_t used = 0;
    while (used < sizeof(request) - 1) {
        int n = SSL_read(ssl, request + used, (int)(sizeof(request) - 1 - used));
        if (n <= 0)
            return 0;
        used += (size_t)n;
        request[used] = 0;
        if (strstr(request, "\r\n\r\n")) {
            if (used < sizeof(request_line) - 1 || memcmp(request, request_line, sizeof(request_line) - 1))
                return 0;
            puts("HTTP request accepted");
            fflush(stdout);
            return SSL_write(ssl, response, sizeof(response) - 1) == (int)(sizeof(response) - 1);
        }
    }
    return 0;
}

static int run(int argc, char **argv)
{
#ifdef TARAKO_TDX
    if (argc != 4) {
        fprintf(stderr, "usage: %s listen:port cert.pem key.pem\n", argv[0]);
        return 0;
    }
    void *source = NULL;
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
    void *source = &quote_source;
#ifdef TARAKO_TEST
    if (strcmp(argv[5], "valid") != 0 && strcmp(argv[5], "tarako") != 0 &&
        strcmp(argv[5], "platform") != 0 && strcmp(argv[5], "both") != 0)
        return 0;
    quote_source.tarako_fault = strcmp(argv[5], "tarako") == 0 || strcmp(argv[5], "both") == 0;
    quote_source.platform_fault = strcmp(argv[5], "platform") == 0 || strcmp(argv[5], "both") == 0;
#endif
#endif
    const struct attestation_callbacks callbacks = {.emit = emit_evidence, .arg = source};
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    BIO *listener = BIO_new_accept(argv[1]);
    if (!ctx || !listener || !early_tls_configure(ctx, 1) ||
        !SSL_CTX_use_certificate_chain_file(ctx, argv[2]) ||
        !SSL_CTX_use_PrivateKey_file(ctx, argv[3], SSL_FILETYPE_PEM) ||
        !SSL_CTX_check_private_key(ctx) || !BIO_set_bind_mode(listener, BIO_BIND_REUSEADDR) ||
        BIO_do_accept(listener) != 1)
        goto done;
    while (BIO_do_accept(listener) == 1) {
        BIO *socket = BIO_pop(listener);
        SSL *ssl = SSL_new(ctx);
        if (ssl && socket && socket_timeouts(socket) && early_tls_attach(ssl, &callbacks)) {
            SSL_set_bio(ssl, socket, socket);
            socket = NULL;
            if (SSL_accept(ssl) != 1)
                ERR_print_errors_fp(stderr);
            else if (serve_request(ssl))
                SSL_shutdown(ssl);
        }
        BIO_free(socket);
        SSL_free(ssl);
    }
done:
    BIO_free_all(listener);
    SSL_CTX_free(ctx);
    return 0;
}
#endif

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
