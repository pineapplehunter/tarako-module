/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef TDX_QGS_PROTOCOL_H
#define TDX_QGS_PROTOCOL_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* Intel QGS v1.1: a big-endian stream length, then a little-endian message. */
#define TDX_QGS_PREFIX_SIZE 4
#define TDX_QGS_MESSAGE_SIZE 24
#define TDX_QGS_HEADER_SIZE (TDX_QGS_PREFIX_SIZE + TDX_QGS_MESSAGE_SIZE)

static inline uint32_t tdx_qgs_le32(const uint8_t *p)
{
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 |
           (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

static inline void tdx_qgs_put_le32(uint8_t *p, uint32_t value)
{
    p[0] = value;
    p[1] = value >> 8;
    p[2] = value >> 16;
    p[3] = value >> 24;
}

/* The caller reserves TDX_QGS_HEADER_SIZE bytes before the TDREPORT. */
static inline void tdx_qgs_request_header(uint8_t *p, uint32_t report_size)
{
    uint32_t size = TDX_QGS_MESSAGE_SIZE + report_size;

    memset(p, 0, TDX_QGS_HEADER_SIZE);
    p[0] = size >> 24;
    p[1] = size >> 16;
    p[2] = size >> 8;
    p[3] = size;
    p[4] = 1; /* major version (u16 LE) */
    p[6] = 1; /* minor version (u16 LE) */
    /* type = GET_QUOTE_REQ (0), error_code = 0, id_list_size = 0 */
    tdx_qgs_put_le32(p + 12, size);
    tdx_qgs_put_le32(p + 20, report_size);
}

/* Return -1 for invalid, 0 for incomplete, 1 for a complete nonempty quote. */
static inline int tdx_qgs_parse_response(const uint8_t *p, size_t received,
                                         size_t capacity, size_t *quote_size)
{
    uint32_t size;

    if (received > capacity || capacity < TDX_QGS_HEADER_SIZE) {
        return -1;
    }
    if (received < TDX_QGS_PREFIX_SIZE) {
        return 0;
    }
    size = (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 |
           (uint32_t)p[2] << 8 | (uint32_t)p[3];
    if (size <= TDX_QGS_MESSAGE_SIZE ||
        size > capacity - TDX_QGS_PREFIX_SIZE ||
        received > TDX_QGS_PREFIX_SIZE + (size_t)size) {
        return -1;
    }
    if (received < TDX_QGS_HEADER_SIZE) {
        return 0;
    }
    if (p[4] != 1 || p[5] != 0 || p[6] != 1 || p[7] != 0 ||
        tdx_qgs_le32(p + 8) != 1 || /* GET_QUOTE_RESP */
        tdx_qgs_le32(p + 12) != size ||
        tdx_qgs_le32(p + 16) != 0 || /* QGS error code */
        tdx_qgs_le32(p + 20) != 0 || /* no selected ID requested */
        tdx_qgs_le32(p + 24) != size - TDX_QGS_MESSAGE_SIZE) {
        return -1;
    }
    if (received != TDX_QGS_PREFIX_SIZE + (size_t)size) {
        return 0;
    }
    *quote_size = size - TDX_QGS_MESSAGE_SIZE;
    return 1;
}

#endif
