/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef TARAKO_EVIDENCE_H
#define TARAKO_EVIDENCE_H
#include "early_tls.h"

struct quote_source {
    const char *url;
    int tarako_fault, platform_fault; /* Set only by the fault-injection test server. */
};

struct verifier {
    const char *url;
    EVP_PKEY *public_key;
    const char *ima_url; /* Set for live TDX appraisal. */
    int verbose;
};

#define TDX_QUOTE_LIMIT 16384
#define IMA_LOG_LIMIT (4 * 1024 * 1024)

int tdx_quote(uint8_t *output, size_t *size, const uint8_t report[64]);
/* A NULL quote source selects the local TDX quote provider. */
int emit_evidence(void *, const uint8_t *, const uint8_t *, char *, size_t *);
int appraise_evidence(void *, const uint8_t *, const uint8_t *, const char *, size_t);
#endif
