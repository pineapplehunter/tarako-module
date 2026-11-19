#include <stdint.h>
#include <stdio.h>
#include <time.h>
#include <sgx_dcap_quoteverify.h>

/* Exit status: 2 input/format, 3 clock/DCAP failure, 4 rejected by policy,
 * 5 output failure, 6 missing/expired collateral. Success authenticates claims,
 * not freshness of the quote
 * itself: callers must check their challenge in report_data and apply policy
 * to the measurements. The verifier host and its wall clock must be trusted.
 */
enum { INPUT = 2, VERIFY = 3, POLICY = 4, OUTPUT = 5, COLLATERAL = 6 };

static int collateral_error(quote3_error_t status)
{
    switch (status) {
    case SGX_QL_NETWORK_ERROR:
    case SGX_QL_NETWORK_FAILURE:
    case SGX_QL_NO_QUOTE_COLLATERAL_DATA:
    case SGX_QL_UNABLE_TO_GET_COLLATERAL:
    case SGX_QL_SERVICE_UNAVAILABLE:
    case SGX_QL_SERVICE_TIMEOUT:
    case SGX_QL_PLATFORM_UNKNOWN:
    case SGX_QL_CERTS_UNAVAILABLE:
    case SGX_QL_QEIDENTITY_NOT_FOUND:
    case SGX_QL_TCBINFO_NOT_FOUND:
    case SGX_QL_SGX_TCB_INFO_EXPIRED:
    case SGX_QL_SGX_PCK_CERT_CHAIN_EXPIRED:
    case SGX_QL_SGX_CRL_EXPIRED:
    case SGX_QL_SGX_SIGNING_CERT_CHAIN_EXPIRED:
    case SGX_QL_SGX_ENCLAVE_IDENTITY_EXPIRED:
        return 1;
    default:
        return 0;
    }
}

static int fail(int code, const char *message)
{
    fprintf(stderr, "tarako-dcap-verify: %s\n", message);
    return code;
}

static uint16_t le16(const uint8_t *p)
{
    return p[0] | ((uint16_t)p[1] << 8);
}

static uint32_t le32(const uint8_t *p)
{
    return le16(p) | ((uint32_t)le16(p + 2) << 16);
}

/* Intel quote wire format: 48-byte header, optional v5 type/size,
 * report body, then a 32-bit length and exactly that many signature bytes.
 * DCAP validates the signature section and the nested certification data.
 */
static const uint8_t *td_body(const uint8_t *q, size_t len)
{
    size_t offset = 48, body_size = 584;
    if (len < offset || le32(q + 4) != 0x81 || le16(q + 2) != 2)
        return NULL; /* TDX, ECDSA P-256 only */

    switch (le16(q)) {
    case 4:
        break;
    case 5:
        offset += 6;
        if (len < offset)
            return NULL;
        switch (le16(q + 48)) {
        case 2: body_size = 584; break; /* TDX 1.0 */
        case 3: body_size = 648; break; /* TDX 1.5 */
        case 4: body_size = 885; break; /* TDX 1.5 extended */
        default: return NULL;
        }
        if (le32(q + 50) != body_size)
            return NULL;
        break;
    default:
        return NULL;
    }

    size_t end = offset + body_size;
    if (len <= end + 4 || le32(q + end) != len - end - 4)
        return NULL;
    return q + offset;
}

static void print_hex(const uint8_t *p, size_t len)
{
    putchar('"');
    for (size_t i = 0; i < len; i++)
        printf("%02x", (unsigned)p[i]);
    putchar('"');
}

int main(int argc, char **argv)
{
    (void)argv;
    if (argc != 1)
        return fail(INPUT, "usage: tarako-dcap-verify < raw-quote.bin");

    /* Reserve one extra byte to detect oversize input without draining it. */
    static uint8_t quote[64 * 1024 + 1];
    size_t len = fread(quote, 1, sizeof(quote), stdin);
    if (ferror(stdin) || !feof(stdin) || len == sizeof(quote))
        return fail(INPUT, "cannot read quote or quote exceeds 64 KiB");
    const uint8_t *body = td_body(quote, len);
    if (body == NULL)
        return fail(INPUT, "malformed or unsupported TDX quote");

    time_t now = time(NULL);
    if (now <= 0)
        return fail(VERIFY, "cannot read verifier wall clock");
    quote3_error_t status = sgx_qv_set_path(SGX_QV_QPL_PATH, QPL_PATH);
    if (status != SGX_QL_SUCCESS) {
        fprintf(stderr, "tarako-dcap-verify: setting DCAP QPL path failed (0x%x)\n",
                (unsigned)status);
        return VERIFY;
    }

    uint32_t expired = 1;
    sgx_ql_qv_result_t result = SGX_QL_QV_RESULT_UNSPECIFIED;
    /* NULL collateral lets Intel QPL fetch it via operator QCNL settings.
     * NULL report info requests software QVL, not an SGX enclave.
     */
    status = tee_verify_quote(quote, (uint32_t)len, NULL, now, &expired,
                              &result, NULL, NULL);
    if (status != SGX_QL_SUCCESS) {
        fprintf(stderr, "tarako-dcap-verify: DCAP verification failed (0x%x)\n",
                (unsigned)status);
        return collateral_error(status) ? COLLATERAL : VERIFY;
    }
    if (expired != 0 || result != SGX_QL_QV_RESULT_OK) {
        fprintf(stderr, "tarako-dcap-verify: collateral status %u, QV result 0x%x\n",
                (unsigned)expired, (unsigned)result);
        return expired != 0 ? COLLATERAL : POLICY;
    }

    /* All accepted bodies share the TDX 1.0 prefix. Read claims only from
     * the very buffer authenticated above. TDATTRIBUTES.DEBUG is bit 0.
     */
    if (body[120] & 1)
        return fail(POLICY, "debug TD is not allowed");
    fputs("{\"report_data\":", stdout);
    print_hex(body + 520, 64);
    fputs(",\"mr_td\":", stdout);
    print_hex(body + 136, 48);
    fputs(",\"rtmrs\":[", stdout);
    for (size_t i = 0; i < 4; i++) {
        if (i != 0)
            putchar(',');
        print_hex(body + 328 + i * 48, 48);
    }
    puts("]}");
    if (fflush(stdout) == EOF || ferror(stdout))
        return fail(OUTPUT, "cannot write result");
    return 0;
}
