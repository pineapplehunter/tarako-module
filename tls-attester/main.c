/* SPDX-License-Identifier: GPL-2.0-only */
#define _POSIX_C_SOURCE 200809L
#include "evidence.h"

#include <curl/curl.h>
#include <openssl/err.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>

static int socket_timeouts(BIO *socket)
{
    const struct timeval timeout = {.tv_sec = 10};
    int fd = BIO_get_fd(socket, NULL);
    return fd >= 0 && setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0 &&
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) == 0;
}

#ifdef TARAKO_CLIENT
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
    struct quote_source source = {.url = argv[4]};
#ifdef TARAKO_TEST
    if (strcmp(argv[5], "valid") != 0 && strcmp(argv[5], "tarako") != 0 &&
        strcmp(argv[5], "platform") != 0 && strcmp(argv[5], "both") != 0)
        return 0;
    source.tarako_fault = strcmp(argv[5], "tarako") == 0 || strcmp(argv[5], "both") == 0;
    source.platform_fault = strcmp(argv[5], "platform") == 0 || strcmp(argv[5], "both") == 0;
#endif
    const struct attestation_callbacks callbacks = {.emit = emit_evidence, .arg = &source};
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
