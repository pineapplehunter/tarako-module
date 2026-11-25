#define _POSIX_C_SOURCE 200809L
#include "tarako.h"

#include <errno.h>
#include <fcntl.h>
#include <openssl/ecdsa.h>
#include <sys/ioctl.h>
#include <time.h>
#include <unistd.h>

#define TARAKO_SIGN_DATA _IOWR('S', 2, struct tarako_quote)
_Static_assert(sizeof(struct tarako_quote) == 257, "TARAKO_SIGN_DATA ABI");

int tarako_sign(struct tarako_quote *quote, double *ioctl_ms)
{
    int fd = open("/dev/tarako", O_RDWR | O_CLOEXEC);
    if (fd < 0)
        return 0;

    struct timespec start, end;
    int timed = ioctl_ms && clock_gettime(CLOCK_MONOTONIC, &start) == 0;
    int rc = ioctl(fd, TARAKO_SIGN_DATA, quote);
    int saved_errno = rc < 0 ? errno : EIO;
    if (ioctl_ms) {
        *ioctl_ms = 0;
        if (timed && clock_gettime(CLOCK_MONOTONIC, &end) == 0)
            *ioctl_ms = (end.tv_sec - start.tv_sec) * 1000.0 +
                        (end.tv_nsec - start.tv_nsec) / 1000000.0;
    }
    close(fd);
    if (rc != 0)
        errno = saved_errno;
    return rc == 0;
}

int tarako_signature_der(const struct tarako_quote *quote,
                         uint8_t der[TARAKO_SIGNATURE_DER_MAX])
{
    ECDSA_SIG *sig = ECDSA_SIG_new();
    BIGNUM *r = BN_bin2bn(quote->sig_r, sizeof(quote->sig_r), NULL);
    BIGNUM *s = BN_bin2bn(quote->sig_s, sizeof(quote->sig_s), NULL);
    int length = 0;
    if (sig && r && s && ECDSA_SIG_set0(sig, r, s)) {
        length = i2d_ECDSA_SIG(sig, &der);
    } else {
        BN_free(r);
        BN_free(s);
    }
    ECDSA_SIG_free(sig);
    return length;
}

void tarako_hex(char *out, const uint8_t *bytes, size_t length)
{
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < length; i++) {
        *out++ = digits[bytes[i] >> 4];
        *out++ = digits[bytes[i] & 15];
    }
    *out = '\0';
}
