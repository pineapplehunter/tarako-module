#define _POSIX_C_SOURCE 200809L
#include "tarako.h"

#include <event2/buffer.h>
#include <event2/event.h>
#include <event2/http.h>
#include <json-c/json.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define QUOTE_JSON_SIZE 640
#define BODY_LIMIT (1024 * 1024)

static int from_hex(const char *text, size_t length, uint8_t *out, size_t capacity)
{
    if (!length || length % 2 || length / 2 > capacity || strspn(text, "0123456789abcdefABCDEF") != length)
        return 0;
    return OPENSSL_hexstr2buf_ex(out, capacity, NULL, text, '\0');
}

static int format_quote(const struct tarako_quote *quote, char body[QUOTE_JSON_SIZE])
{
    uint8_t signature[TARAKO_SIGNATURE_DER_MAX];
    int size = tarako_signature_der(quote, signature);
    if (size <= 0)
        return 0;
    char hash[2 * sizeof(quote->hash) + 1], pubkey[2 * sizeof(quote->pubkey) + 1];
    char der[2 * sizeof(signature) + 1], data[2 * sizeof(quote->user_data) + 1];
    tarako_hex(hash, quote->hash, sizeof(quote->hash));
    tarako_hex(pubkey, quote->pubkey, sizeof(quote->pubkey));
    tarako_hex(der, signature, (size_t)size);
    tarako_hex(data, quote->user_data, sizeof(quote->user_data));
    snprintf(body, QUOTE_JSON_SIZE,
             "{\"hash\":\"%s\",\"public_key\":\"%s\",\"signature_der\":\"%s\",\"user_data\":\"%s\"}",
             hash, pubkey, der, data);
    return 1;
}

static int quote_command(const char *hex)
{
    struct tarako_quote quote = {0};
    if (hex) {
        if (!from_hex(hex, strlen(hex), quote.user_data, sizeof(quote.user_data))) {
            fputs("user data must contain 1 to 128 bytes of hex\n", stderr);
            return 1;
        }
    } else if (RAND_bytes(quote.user_data, 32) != 1) {
        fputs("failed to generate a nonce\n", stderr);
        return 1;
    }
    double ms;
    if (!tarako_sign(&quote, &ms)) {
        perror("TARAKO_SIGN_DATA");
        return 1;
    }
    char body[QUOTE_JSON_SIZE];
    if (!format_quote(&quote, body))
        return 1;
    printf("sign ioctl: %.3f ms\n%s\n", ms, body);
    return 0;
}

static int request_binding(const char *body, size_t size, uint8_t binding[32])
{
    static const char domain[] = "TARAKO-TQ-REQUEST-V1";
    struct json_tokener *parser = json_tokener_new();
    if (!parser || !body || !size) {
        if (parser)
            json_tokener_free(parser);
        return 0;
    }
    json_tokener_set_flags(parser, JSON_TOKENER_STRICT | JSON_TOKENER_VALIDATE_UTF8);
    struct json_object *input = json_tokener_parse_ex(parser, body, (int)size);
    struct json_object *request, *nonce;
    struct json_object *context = NULL;
    EVP_MD_CTX *hasher = NULL;
    uint8_t bytes[32];
    char hex[2 * sizeof(bytes) + 1];
    int ok = 0;
    if (json_tokener_get_error(parser) != json_tokener_success ||
        !json_object_is_type(input, json_type_object) || json_object_object_length(input) != 2 ||
        !json_object_object_get_ex(input, "nonce", &nonce) ||
        !json_object_is_type(nonce, json_type_string) ||
        json_object_get_string_len(nonce) != sizeof(hex) - 1 ||
        !from_hex(json_object_get_string(nonce), sizeof(hex) - 1, bytes, sizeof(bytes)) ||
        !json_object_object_get_ex(input, "request", &request) ||
        !json_object_is_type(request, json_type_string) || !json_object_get_string_len(request))
        goto done;

    /* Match the verifier: compact UTF-8 JSON, nonce first, lowercase hex. */
    tarako_hex(hex, bytes, sizeof(bytes));
    context = json_object_new_object();
    if (!context)
        goto done;
    json_object_object_add(context, "nonce", json_object_new_string(hex));
    json_object_object_add(context, "request", json_object_get(request));
    const char *encoded = json_object_to_json_string_ext(context, JSON_C_TO_STRING_PLAIN | JSON_C_TO_STRING_NOSLASHESCAPE);
    hasher = EVP_MD_CTX_new();
    ok = encoded && hasher && EVP_DigestInit_ex(hasher, EVP_sha256(), NULL) &&
        EVP_DigestUpdate(hasher, domain, sizeof(domain)) &&
        EVP_DigestUpdate(hasher, encoded, strlen(encoded)) &&
        EVP_DigestFinal_ex(hasher, binding, NULL);
done:
    EVP_MD_CTX_free(hasher);
    json_object_put(context);
    json_object_put(input);
    json_tokener_free(parser);
    return ok;
}

static void reply(struct evhttp_request *request, int status, const char *json)
{
    struct evbuffer *body = evbuffer_new();
    if (!body) {
        evhttp_send_error(request, HTTP_INTERNAL, NULL);
        return;
    }
    evhttp_add_header(evhttp_request_get_output_headers(request), "Content-Type", "application/json");
    evbuffer_add_printf(body, "%s\n", json);
    evhttp_send_reply(request, status, NULL, body);
    evbuffer_free(body);
}

static void handle_quote(struct evhttp_request *request, void *arg)
{
    (void)arg;
    if (evhttp_request_get_command(request) != EVHTTP_REQ_POST) {
        reply(request, 405, "{\"error\":\"POST required\"}");
        return;
    }
    struct evbuffer *input = evhttp_request_get_input_buffer(request);
    size_t size = evbuffer_get_length(input);
    struct tarako_quote quote = {0};
    if (!request_binding((const char *)evbuffer_pullup(input, -1), size, quote.user_data)) {
        reply(request, HTTP_BADREQUEST, "{\"error\":\"expected a request and a 32-byte hex nonce\"}");
        return;
    }
    if (!tarako_sign(&quote, NULL)) {
        perror("TARAKO_SIGN_DATA");
        reply(request, HTTP_INTERNAL, "{\"error\":\"TARAKO signing failed\"}");
        return;
    }
    char body[QUOTE_JSON_SIZE];
    if (!format_quote(&quote, body)) {
        reply(request, HTTP_INTERNAL, "{\"error\":\"failed to encode quote\"}");
        return;
    }
    reply(request, HTTP_OK, body);
}

static int serve(const char *listen)
{
    const char *colon = strrchr(listen, ':');
    if (!colon || !colon[1] || strspn(colon + 1, "0123456789") != strlen(colon + 1))
        return 1;
    long port = strtol(colon + 1, NULL, 10);
    if (port < 1 || port > 65535)
        return 1;
    char *host = strndup(listen, (size_t)(colon - listen));
    struct event_base *base = event_base_new();
    struct evhttp *http = base ? evhttp_new(base) : NULL;
    int rc = 1;
    if (host && http && evhttp_bind_socket(http, *host ? host : "0.0.0.0", (uint16_t)port) == 0 &&
        evhttp_set_cb(http, "/quote", handle_quote, NULL) == 0) {
        evhttp_set_max_body_size(http, BODY_LIMIT);
        evhttp_set_timeout(http, 10);
        fprintf(stderr, "listening on %s\n", listen);
        rc = event_base_dispatch(base) < 0;
    } else {
        fprintf(stderr, "could not listen on %s\n", listen);
    }
    if (http)
        evhttp_free(http);
    if (base)
        event_base_free(base);
    free(host);
    return rc;
}

int main(int argc, char **argv)
{
    if (argc == 1)
        return serve(":5000");
    if (argc <= 3 && strcmp(argv[1], "quote") == 0)
        return quote_command(argc == 3 ? argv[2] : NULL);
    if (argc == 3 && (strcmp(argv[1], "--listen") == 0 || strcmp(argv[1], "-listen") == 0))
        return serve(argv[2]);
    fprintf(stderr, "usage: %s [--listen address:port | quote [hex-user-data]]\n", argv[0]);
    return 1;
}
