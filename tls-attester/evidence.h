/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef TARAKO_EVIDENCE_H
#define TARAKO_EVIDENCE_H
#include "early_tls.h"

struct quote_source {
    const char *url;
};

struct verifier {
    const char *url;
    EVP_PKEY *public_key;
};

int emit_evidence(void *, const uint8_t *, const uint8_t *, char *, size_t *);
int appraise_evidence(void *, const uint8_t *, const uint8_t *, const char *, size_t);
#endif
