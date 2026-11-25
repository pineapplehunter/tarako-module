"""Hardware-free verification tests for signed TDX quotes."""

import contextlib
import io
import os
from pathlib import Path
import runpy
import unittest

ATTEST = runpy.run_path(os.environ["TDX_ATTEST"])


class QuoteTests(unittest.TestCase):
    quote = (Path(os.environ["TDX_VERIFY_TESTDATA"]) /
             "tdx_prod_quote_SPR_E4.dat").read_bytes()
    report_data = bytes.fromhex(
        "6c62dec1b8191749a31dab490be532a35944dea47caef1f980863993d9899545eb"
        "7406a38d1eed313b987a467dacead6f0c87a6d766c66f6f29f8acb281f1113"
    )

    def test_signed_quote_and_reportdata(self):
        with contextlib.redirect_stdout(io.StringIO()) as output:
            ATTEST["verify_quote"](self.quote, self.report_data)
        self.assertIn("TDX verification: OK", output.getvalue())

    def test_wrong_reportdata_on_same_signed_quote(self):
        wrong = bytes([self.report_data[0] ^ 1]) + self.report_data[1:]
        with self.assertRaisesRegex(SystemExit, "quote field REPORT_DATA"):
            ATTEST["verify_quote"](self.quote, wrong)

    def test_tampered_body_and_signature(self):
        for offset in (568, 636):
            quote = bytearray(self.quote)
            quote[offset] ^= 1
            with self.subTest(offset=offset), self.assertRaises(SystemExit):
                ATTEST["verify_quote"](bytes(quote), self.report_data)

    def test_empty_or_truncated_quote(self):
        for quote in (b"", self.quote[:1024]):
            with self.subTest(size=len(quote)), self.assertRaises(SystemExit):
                ATTEST["verify_quote"](quote, self.report_data)


if __name__ == "__main__":
    unittest.main()
