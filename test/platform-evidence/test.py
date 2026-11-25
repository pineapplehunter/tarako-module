"""Hardware-free quote and IMA checks; no fixture ties the two together."""

import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import runpy
import struct
import tempfile
import unittest

ATTEST = runpy.run_path(os.environ["TDX_ATTEST"])
REPLAY = runpy.run_path(os.environ["IMA_RTMR_VALIDATE"])
FIXTURES = Path(os.environ.get("IMA_TEST_FIXTURES", Path(__file__).resolve().parent / "assets"))
GOLDEN = json.loads((FIXTURES / "golden.json").read_text())


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


def replay_end(log, target):
    digests = REPLAY["load_log"](str(log))
    return REPLAY["replay_from"](
        bytes.fromhex(GOLDEN["initial"]), digests, target, GOLDEN["skip"]
    )


def appraise_fixture(log, target):
    """Test-only TAK policy for these SHA-256 ima-buf records, not a verifier."""
    end = replay_end(log, target)
    if end is None:
        raise ValueError("RTMR replay mismatch")
    lines = [line for line in log.read_text().splitlines() if line.strip()]
    for line in lines[GOLDEN["skip"]:end]:
        fields = line.split()
        if (len(fields) != 6 or fields[2] != "ima-buf" or
                fields[4] != "public-key-generate" or fields[5] != GOLDEN["tak"]):
            continue
        key = bytes.fromhex(fields[5])
        inner = hashlib.sha256(key).digest()
        if fields[3] != "sha256:" + inner.hex():
            continue
        template = b"".join(
            struct.pack("<I", len(field)) + field
            for field in (b"sha256:\0" + inner, fields[4].encode() + b"\0", key)
        )
        if hashlib.sha384(template).hexdigest() == fields[1]:
            return
    raise ValueError("expected TAK missing from replayed entries")


class ImaTests(unittest.TestCase):
    def test_sha384_replay_and_expected_tak(self):
        log = FIXTURES / "with-tak.log"
        target = bytes.fromhex(GOLDEN["with-tak"])
        self.assertEqual(replay_end(log, target), 3)
        appraise_fixture(log, target)

    def test_rtmr_replay_mismatch(self):
        log = FIXTURES / "with-tak.log"
        target = bytes.fromhex(GOLDEN["with-tak"])
        wrong = bytes([target[0] ^ 1]) + target[1:]
        with self.assertRaisesRegex(ValueError, "RTMR replay mismatch"):
            appraise_fixture(log, wrong)

    def test_replay_valid_but_expected_tak_missing(self):
        log = FIXTURES / "without-expected-tak.log"
        target = bytes.fromhex(GOLDEN["without-expected-tak"])
        self.assertEqual(replay_end(log, target), 3)
        with self.assertRaisesRegex(ValueError, "expected TAK missing"):
            appraise_fixture(log, target)

    def test_unreplayed_suffix_does_not_supply_tak(self):
        target = bytes.fromhex(GOLDEN["without-expected-tak"])
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "longer.log"
            original = (FIXTURES / "without-expected-tak.log").read_text()
            key_entry = (FIXTURES / "with-tak.log").read_text().splitlines()[-1]
            log.write_text(original + key_entry + "\n")
            self.assertEqual(replay_end(log, target), 3)
            with self.assertRaisesRegex(ValueError, "expected TAK missing"):
                appraise_fixture(log, target)


if __name__ == "__main__":
    unittest.main()
