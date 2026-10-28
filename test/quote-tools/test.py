"""Hardware-free checks for quote verification and per-invocation freshness."""

import contextlib
import errno
import io
import os
from pathlib import Path
import runpy
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, patch

ROOT = Path(__file__).resolve().parent.parent
BENCH = runpy.run_path(str(ROOT / "quote-bench.py"))
ATTEST = runpy.run_path(str(ROOT / "tdx-attest.py"))
TARAKO = runpy.run_path(str(ROOT / "tarako-quote.py"))


class BenchmarkTests(unittest.TestCase):
    def test_fresh_nonce_for_every_target_and_warmup(self):
        commands = []

        def run(command, **kwargs):
            commands.append(command)
            return SimpleNamespace(
                returncode=0,
                stdout="TDX verification: OK\n",
                stderr="TDX quote: 5.000 ms\nTPM quote: 2.000 ms\n"
                "sign ioctl: 0.100 ms\n",
            )

        nonces = [i.to_bytes(32, "big") for i in range(9)]
        with patch("os.urandom", side_effect=nonces) as random:
            with patch("subprocess.run", side_effect=run):
                with contextlib.redirect_stdout(io.StringIO()):
                    for target in BENCH["TARGETS"]:
                        BENCH["benchmark"](target, warmup=1, runs=2)
        self.assertEqual(random.call_count, 9)
        self.assertTrue(
            all(call.args == (32,) for call in random.call_args_list)
        )
        actual = [command[2] if command[0] == "tdx-attest"
                  else command[1] for command in commands]
        self.assertEqual(actual, [nonce.hex() for nonce in nonces])

    def test_rejects_failed_or_unverified_tdx_sample(self):
        for code, message in [(2, "signature invalid"), (0, "")]:
            result = SimpleNamespace(
                returncode=code, stdout=message, stderr="TDX quote: 5.000 ms"
            )
            with self.subTest(code=code):
                with patch("subprocess.run", return_value=result):
                    with self.assertRaises(SystemExit):
                        BENCH["measure"]("tdx")

    def test_online_verification_flag_is_forwarded(self):
        result = SimpleNamespace(
            returncode=0,
            stdout="TDX verification: OK",
            stderr="TDX quote: 5 ms",
        )
        with patch("subprocess.run", return_value=result) as run:
            self.assertEqual(BENCH["measure"]("tdx", True), 5)
        self.assertIn("--verify-collateral", run.call_args.args[0])


class TarakoQuoteTests(unittest.TestCase):
    def test_uses_go_attester_quote_command(self):
        nonce = "ab" * 32
        response = b'sign ioctl: 0.100 ms\n{"hash":"test"}\n'
        main = TARAKO["main"]
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "quote.txt"
            with (
                patch.dict(main.__globals__, prepare_app=lambda: None),
                patch("sys.argv", ["tarako-quote", nonce, "-o", str(output)]),
                patch("subprocess.run", return_value=SimpleNamespace(
                    stdout=response,
                )) as run,
                contextlib.redirect_stdout(io.StringIO()),
                contextlib.redirect_stderr(io.StringIO()),
            ):
                main()
            self.assertEqual(
                run.call_args.args[0],
                (Path("/var/lib/tarako/tarako-attester"), "quote", nonce),
            )
            self.assertEqual(output.read_bytes(), response)


class GetQuoteTests(unittest.TestCase):
    def test_kernel_failure_reports_elapsed_time_and_cleans_up(self):
        root = MagicMock()
        instance = root.__truediv__.return_value
        instance.__truediv__.return_value.read_bytes.side_effect = OSError(
            errno.EIO, "Input/output error"
        )
        get_quote = ATTEST["get_quote"]
        with patch.dict(get_quote.__globals__, TSM_REPORT_ROOT=root):
            with patch(
                "time.perf_counter_ns", side_effect=[0, 30_000_000_000]
            ):
                with self.assertRaisesRegex(
                    SystemExit, "TDX GetQuote failed after 30000.000 ms"
                ):
                    get_quote(bytes(64))
        instance.rmdir.assert_called_once()


@unittest.skipUnless(
    os.environ.get("TDX_VERIFY_TESTDATA"),
    "set TDX_VERIFY_TESTDATA to go-tdx-guest/testing/testdata",
)
class SignatureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.quote = (Path(os.environ["TDX_VERIFY_TESTDATA"]) /
                     "tdx_prod_quote_SPR_E4.dat").read_bytes()
        # This upstream fixture is Quote v4: 48-byte header, 584-byte TD body;
        # REPORTDATA is the final 64 bytes of the TD body.
        cls.report_data = cls.quote[568:632]

    def verify(self, quote, data):
        with contextlib.redirect_stdout(io.StringIO()):
            ATTEST["verify_quote"](quote, data)

    def test_valid_signed_quote(self):
        self.verify(self.quote, self.report_data)

    def test_wrong_nonce(self):
        wrong = bytes([self.report_data[0] ^ 1]) + self.report_data[1:]
        with self.assertRaisesRegex(SystemExit, "TDX verification failed"):
            self.verify(self.quote, wrong)

    def test_tampered_body_and_signature(self):
        for offset in (568, 636):
            quote = bytearray(self.quote)
            quote[offset] ^= 1
            with self.subTest(offset=offset):
                with self.assertRaises(SystemExit):
                    self.verify(bytes(quote), self.report_data)

    def test_empty_or_truncated_quote(self):
        for quote in (b"", self.quote[:1024]):
            with self.subTest(size=len(quote)):
                with self.assertRaises(SystemExit):
                    self.verify(quote, self.report_data)


if __name__ == "__main__":
    unittest.main()
