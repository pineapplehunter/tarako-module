/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef TARAKO_EVIDENCE_H
#define TARAKO_EVIDENCE_H
#include "early_tls.h"

struct quote_source {
    const char *url;
#ifdef TARAKO_TEST
    int tarako_fault, platform_fault;
#endif
};

struct verifier {
    const char *url;
    EVP_PKEY *public_key;
#ifdef TARAKO_TDX
    const char *ima_url;
    int verbose;
#endif
};

#define TDX_QUOTE_LIMIT 16384
#define IMA_LOG_LIMIT (4 * 1024 * 1024)

int tdx_quote(uint8_t *output, size_t *size, const uint8_t report[64]);
int emit_evidence(void *, const uint8_t *, const uint8_t *, char *, size_t *);
int appraise_evidence(void *, const uint8_t *, const uint8_t *, const char *, size_t);
#endif
