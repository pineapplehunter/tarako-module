#define _POSIX_C_SOURCE 200809L
#include "evidence.h"
#include "tarako.h"

#include <curl/curl.h>
#include <json-c/json.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static const uint8_t binding_domain[] = "TARAKO-TLS-V1";
static const uint8_t report_domain[] = "TARAKO-TLS-REPORTDATA-V1";
static const uint8_t result_domain[] = "TARAKO-TLS-RESULT-V1";

typedef struct json_object json;

struct response {
    char *buf;
    size_t len, capacity;
};

static size_t receive_body(char *data, size_t size, size_t count, void *arg)
{
    struct response *r = arg;
    if (size && count > (r->capacity - r->len) / size)
        return 0;
    const size_t n = size * count;
    memcpy(r->buf + r->len, data, n);
    r->len += n;
    return n;
}

static json *post(const char *url, json *request, long *status, long timeout_ms)
{
    char buf[16384];
    struct response r = {.buf = buf, .capacity = sizeof(buf)};
    CURL *curl = curl_easy_init();
    struct curl_slist *headers = curl_slist_append(NULL, "Content-Type: application/json");
    struct json_tokener *parser = json_tokener_new_ex(8);
    json *reply = NULL;
    *status = 0;
    if (!curl || !request || !headers || !parser)
        goto done;
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_PROTOCOLS_STR, "http");
    curl_easy_setopt(curl, CURLOPT_PROXY, "");
    curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_0);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_object_to_json_string_ext(request, JSON_C_TO_STRING_PLAIN));
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, timeout_ms);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, receive_body);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &r);
    if (curl_easy_perform(curl) != CURLE_OK)
        goto done;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, status);
    json_tokener_set_flags(parser, JSON_TOKENER_STRICT | JSON_TOKENER_VALIDATE_UTF8);
    reply = json_tokener_parse_ex(parser, r.buf, (int)r.len);
    if (json_tokener_get_error(parser) != json_tokener_success ||
        !json_object_is_type(reply, json_type_object)) {
        json_object_put(reply);
        reply = NULL;
    }
done:
    if (parser)
        json_tokener_free(parser);
    curl_easy_cleanup(curl);
    curl_slist_free_all(headers);
    return reply;
}

static int add_hex(json *obj, const char *name, const uint8_t *bytes, size_t len)
{
    if (len > TDX_QUOTE_LIMIT)
        return 0;
    char *hex = malloc(2 * len + 1);
    if (!hex)
        return 0;
    tarako_hex(hex, bytes, len);
    json *value = json_object_new_string_len(hex, (int)(len * 2));
    free(hex);
    if (!value)
        return 0;
    if (!json_object_object_add(obj, name, value))
        return 1;
    json_object_put(value);
    return 0;
}

static int encode_cmw(json *evidence, int tdx, char *cmw, size_t *length)
{
    const char *inner = json_object_to_json_string_ext(evidence, JSON_C_TO_STRING_PLAIN);
    const size_t len = strlen(inner);
    char encoded[CMW_LIMIT];
    if (len == 0 || 4 * ((len + 2) / 3) >= sizeof(encoded))
        return 0;
    size_t n = (size_t)EVP_EncodeBlock((uint8_t *)encoded, (const uint8_t *)inner, (int)len);
    while (n && encoded[n - 1] == '=')
        n--;
    for (size_t i = 0; i < n; i++) {
        if (encoded[i] == '+') encoded[i] = '-';
        if (encoded[i] == '/') encoded[i] = '_';
    }
    int prefix = snprintf(cmw, *length, "[\"%s\",\"", tarako_evidence_type(tdx));
    if (prefix < 0 || (size_t)prefix + n + 2 > *length)
        return 0;
    memcpy(cmw + prefix, encoded, n);
    memcpy(cmw + prefix + n, "\"]", 2);
    *length = (size_t)prefix + n + 2;
    return 1;
}

static int add_mock_quote(json *evidence, const struct quote_source *source,
                          const uint8_t report[64])
{
    json *request = json_object_new_object(), *mock = NULL;
    long status;
    int ok = 0;
    if (!request || !add_hex(request, "report_data", report, 64))
        goto done;
    mock = post(source->url, request, &status, 4000L);
    if (status != 200 || !mock) {
        fputs("platform signer unavailable or rejected request\n", stderr);
        goto done;
    }
    const uint8_t invalid = 0;
    if (source->platform_fault && !add_hex(mock, "signature", &invalid, 1))
        goto done;
    ok = json_object_object_add(evidence, "platform", mock) == 0;
done:
    if (!ok)
        json_object_put(mock);
    json_object_put(request);
    return ok;
}

int emit_evidence(void *arg, const uint8_t *binder, const uint8_t *spki,
                  char *cmw, size_t *length)
{
    const struct quote_source *source = arg;
    struct tarako_quote quote = {0};
    memcpy(quote.user_data, binding_domain, sizeof(binding_domain));
    memcpy(quote.user_data + sizeof(binding_domain), binder, BINDING_SIZE);
    memcpy(quote.user_data + sizeof(binding_domain) + BINDING_SIZE, spki, BINDING_SIZE);
    if (!tarako_sign(&quote, NULL)) {
        perror("TARAKO_SIGN_DATA");
        return 0;
    }

    uint8_t input[sizeof(report_domain) + sizeof(quote.hash)];
    uint8_t report[64] = {0};
    memcpy(input, report_domain, sizeof(report_domain));
    memcpy(input + sizeof(report_domain), quote.hash, sizeof(quote.hash));
    if (!SHA256(input, sizeof(input), report))
        return 0;

    json *tarako = json_object_new_object(), *evidence = json_object_new_object();
    int ok = 0;
    if (!tarako || !evidence)
        goto done;
    if (source) {
        if (!add_mock_quote(evidence, source, report))
            goto done;
        if (source->tarako_fault)
            memset(quote.sig_s, 0, sizeof(quote.sig_s));
    } else {
        uint8_t raw[TDX_QUOTE_LIMIT];
        size_t size = sizeof(raw);
        if (!tdx_quote(raw, &size, report) || !add_hex(evidence, "tdx_quote", raw, size))
            goto done;
    }
    if (!add_hex(tarako, "hash", quote.hash, sizeof(quote.hash)) ||
        !add_hex(tarako, "pubkey", quote.pubkey, sizeof(quote.pubkey)) ||
        !add_hex(tarako, "sig_r", quote.sig_r, sizeof(quote.sig_r)) ||
        !add_hex(tarako, "sig_s", quote.sig_s, sizeof(quote.sig_s)))
        goto done;
    if (json_object_object_add(evidence, "tarako", tarako))
        goto done;
    tarako = NULL;
    ok = encode_cmw(evidence, !source, cmw, length);
done:
    json_object_put(evidence);
    json_object_put(tarako);
    return ok;
}

static int verify_result(const struct verifier *verifier, json *reply,
                         const uint8_t *binder, const uint8_t *spki,
                         const char *cmw, size_t len)
{
    json *expiry, *sig;
    if (json_object_object_length(reply) != 2 ||
        !json_object_object_get_ex(reply, "expires", &expiry) ||
        !json_object_is_type(expiry, json_type_int) ||
        !json_object_object_get_ex(reply, "signature", &sig) ||
        !json_object_is_type(sig, json_type_string))
        return 0;
    const int64_t now = (int64_t)time(NULL), expires = json_object_get_int64(expiry);
    const int hex_len = json_object_get_string_len(sig);
    const char *hex = json_object_get_string(sig);
    if (now < 0 || expires <= now || expires - now > 60 ||
        hex_len <= 0 || hex_len > 144 || (hex_len & 1) || strlen(hex) != (size_t)hex_len)
        return 0;
    size_t n = 0;
    uint8_t signature[72];
    if (!OPENSSL_hexstr2buf_ex(signature, sizeof(signature), &n, hex, '\0'))
        return 0;

    uint8_t data[sizeof(result_domain) + 3 * BINDING_SIZE + 8];
    memcpy(data, result_domain, sizeof(result_domain));
    uint8_t *out = data + sizeof(result_domain);
    memcpy(out, binder, BINDING_SIZE);
    memcpy(out + BINDING_SIZE, spki, BINDING_SIZE);
    if (!SHA256((const uint8_t *)cmw, len, out + 2 * BINDING_SIZE))
        return 0;
    for (int i = 0; i < 8; i++)
        out[3 * BINDING_SIZE + i] = (uint8_t)((uint64_t)expires >> (56 - 8 * i));

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    int ok = ctx && EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, verifier->public_key) &&
        EVP_DigestVerify(ctx, signature, n, data, sizeof(data)) == 1;
    EVP_MD_CTX_free(ctx);
    return ok;
}

static long long now_ms(void)
{
    struct timespec t;
    if (clock_gettime(CLOCK_MONOTONIC, &t) != 0)
        return -1;
    return (long long)t.tv_sec * 1000 + t.tv_nsec / 1000000;
}

static int attach_ima(json *request, const char *url, long timeout_ms)
{
    struct response r = {.buf = malloc(IMA_LOG_LIMIT), .capacity = IMA_LOG_LIMIT};
    CURL *curl = curl_easy_init();
    int ok = 0;
    if (!r.buf || !curl)
        goto done;
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_PROTOCOLS_STR, "http");
    curl_easy_setopt(curl, CURLOPT_PROXY, "");
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, timeout_ms);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, receive_body);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &r);
    long status = 0;
    if (curl_easy_perform(curl) != CURLE_OK ||
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status) != CURLE_OK ||
        status != 200 || !r.len || memchr(r.buf, 0, r.len))
        goto done;
    json *log = json_object_new_string_len(r.buf, (int)r.len);
    if (log && !json_object_object_add(request, "ima_log", log))
        ok = 1;
    else
        json_object_put(log);
done:
    curl_easy_cleanup(curl);
    free(r.buf);
    return ok;
}

static json *appraise_tdx(const struct verifier *verifier, json *request, long *status)
{
    const long long start = now_ms();
    if (start < 0)
        return NULL;
    const long long deadline = start + 20000;
    for (unsigned int attempt = 0; attempt < 3; attempt++) {
        long long remaining = deadline - now_ms();
        if (remaining <= 0 || remaining > 20000)
            break;
        if (verifier->verbose)
            fprintf(stderr, "* Fetching IMA log (attempt %u)\n", attempt + 1);
        if (!attach_ima(request, verifier->ima_url, remaining < 4000 ? (long)remaining : 4000)) {
            fputs("IMA log unavailable, invalid, or exceeds size limit\n", stderr);
            return NULL;
        }
        remaining = deadline - now_ms();
        if (remaining <= 0 || remaining > 20000)
            break;
        if (verifier->verbose)
            fputs("* Submitting TDX quote, IMA log and TARAKO evidence\n", stderr);
        json *reply = post(verifier->url, request, status, (long)remaining);
        json *error;
        if (attempt == 2 || *status != 400 || !reply ||
            !json_object_object_get_ex(reply, "error", &error) ||
            !json_object_is_type(error, json_type_string) ||
            strcmp(json_object_get_string(error), "ima_replay"))
            return reply;
        if (verifier->verbose)
            fputs("* IMA replay mismatch; refetching log\n", stderr);
        struct timespec pause = {.tv_nsec = 100000000};
        nanosleep(&pause, NULL);
        json_object_put(reply);
    }
    return NULL;
}

int appraise_evidence(void *arg, const uint8_t *binder, const uint8_t *spki,
                      const char *cmw, size_t length)
{
    const struct verifier *verifier = arg;
    json *request = json_object_new_object(), *reply = NULL;
    int ok = 0;
    long status = 0;
    if (!request || !add_hex(request, "binder", binder, BINDING_SIZE) ||
        !add_hex(request, "spki_hash", spki, BINDING_SIZE))
        goto done;
    json *value = json_object_new_string_len(cmw, (int)length);
    if (!value)
        goto done;
    if (json_object_object_add(request, "evidence", value)) {
        json_object_put(value);
        goto done;
    }
    reply = verifier->ima_url ? appraise_tdx(verifier, request, &status)
                              : post(verifier->url, request, &status, 4000L);
    if (!reply) {
        fprintf(stderr, "verifier unavailable or invalid reply\n");
    } else if (status != 200) {
        json *err;
        const char *reason = json_object_object_get_ex(reply, "error", &err) &&
            json_object_is_type(err, json_type_string) ? json_object_get_string(err) : "request";
        fprintf(stderr, "verifier rejected: %s\n", reason);
    } else if (!(ok = verify_result(verifier, reply, binder, spki, cmw, length))) {
        fprintf(stderr, "invalid or expired verifier result\n");
    } else if (verifier->verbose) {
        fputs("* Verifier accepted TDX collateral, IMA replay and TARAKO binding\n", stderr);
    }
done:
    json_object_put(reply);
    json_object_put(request);
    return ok;
}
