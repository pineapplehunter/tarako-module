#ifndef LIBTARAKO_H
#define LIBTARAKO_H

#include <stddef.h>
#include <stdint.h>

#define TARAKO_USER_DATA_SIZE 128
#define TARAKO_SIGNATURE_DER_MAX 72

/* TARAKO_SIGN_DATA takes user_data and fills in the remaining fields. */
struct tarako_quote {
    uint8_t user_data[TARAKO_USER_DATA_SIZE];
    uint8_t hash[32], sig_r[32], sig_s[32], pubkey[33];
};

/* Returns 1 on success, or 0 with errno set. Timing is optional. */
int tarako_sign(struct tarako_quote *quote, double *ioctl_ms);
int tarako_signature_der(const struct tarako_quote *quote,
                         uint8_t der[TARAKO_SIGNATURE_DER_MAX]);
/* The output buffer must have room for 2 * length + 1 bytes. */
void tarako_hex(char *out, const uint8_t *bytes, size_t length);

#endif
