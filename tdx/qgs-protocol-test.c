/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <assert.h>
#include <stdio.h>

#include "tdx-qgs-protocol.h"

int main(void)
{
    uint8_t request[TDX_QGS_HEADER_SIZE];
    uint8_t response[TDX_QGS_HEADER_SIZE + 96];
    uint8_t bad[sizeof(response)];
    size_t quote_size = 0;
    size_t i;
    const size_t corrupt[] = { 4, 8, 12, 16, 20, 24 };

    tdx_qgs_request_header(request, 1024);
    assert(request[0] == 0 && request[1] == 0 &&
           request[2] == 4 && request[3] == 0x18);
    assert(tdx_qgs_le32(request + 4) == 0x00010001);
    assert(tdx_qgs_le32(request + 8) == 0);
    assert(tdx_qgs_le32(request + 12) == 1048);
    assert(tdx_qgs_le32(request + 16) == 0);
    assert(tdx_qgs_le32(request + 20) == 1024);
    assert(tdx_qgs_le32(request + 24) == 0);

    tdx_qgs_request_header(response, 96);
    tdx_qgs_put_le32(response + 8, 1); /* GET_QUOTE_RESP */
    tdx_qgs_put_le32(response + 20, 0);
    tdx_qgs_put_le32(response + 24, 96);
    memset(response + TDX_QGS_HEADER_SIZE, 0xa5, 96);

    /* Every possible partial read must remain incomplete, never successful. */
    for (i = 0; i < sizeof(response); i++) {
        assert(tdx_qgs_parse_response(response, i, sizeof(response),
                                      &quote_size) == 0);
    }
    assert(tdx_qgs_parse_response(response, sizeof(response), sizeof(response),
                                  &quote_size) == 1);
    assert(quote_size == 96);
    assert(response[TDX_QGS_HEADER_SIZE] == 0xa5);

    /* Bad version/type, mismatched lengths, server error, unexpected ID. */
    for (i = 0; i < sizeof(corrupt) / sizeof(corrupt[0]); i++) {
        memcpy(bad, response, sizeof(bad));
        bad[corrupt[i]] ^= 1;
        assert(tdx_qgs_parse_response(bad, sizeof(bad), sizeof(bad),
                                      &quote_size) == -1);
    }
    memcpy(bad, response, sizeof(bad));
    memset(bad, 0xff, 4); /* oversized frame */
    assert(tdx_qgs_parse_response(bad, 4, sizeof(bad), &quote_size) == -1);
    memset(bad, 0, sizeof(bad)); /* zero-length frame */
    assert(tdx_qgs_parse_response(bad, 4, sizeof(bad), &quote_size) == -1);
    tdx_qgs_request_header(bad, 0); /* response without a quote */
    assert(tdx_qgs_parse_response(bad, TDX_QGS_HEADER_SIZE, sizeof(bad),
                                  &quote_size) == -1);
    assert(tdx_qgs_parse_response(response, sizeof(response),
                                  sizeof(response) - 1, &quote_size) == -1);

    puts("QGS framing and response tests passed");
    return 0;
}
