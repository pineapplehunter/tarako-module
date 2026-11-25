"""Generated evidence; only the DCAP subprocess is replaced in these tests."""
import base64
import hashlib
import json
import subprocess
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils

import tarako_tdx_verifier as verifier


def tak_record(key):
    inner = hashlib.sha256(key).digest()
    payload = (b"sha256:\x00" + inner, b"public-key-generate\x00", key)
    digest = hashlib.sha384(b"".join(len(part).to_bytes(4, "little") + part
                                     for part in payload)).digest()
    return (f"10 sha384:{digest.hex()} ima-buf sha256:{inner.hex()} "
            f"public-key-generate {key.hex()}\n"), digest


def extend(current, digest):
    return hashlib.sha384(current + digest).digest()


class VerifierTests(unittest.TestCase):
    def setUp(self):
        self.binder = bytes(range(32))
        self.spki = b"s" * 32
        self.baseline = b"b" * 48
        digest = b"d" * 32
        self.policy = verifier.parse_policy(dict(
            mr_td="11" * 48, rtmr0="22" * 48, rtmr1="33" * 48, rtmr3="44" * 48,
            ima_start_rtmr2=self.baseline.hex(), fsverity_digest=digest.hex()))
        private = ec.generate_private_key(ec.SECP256R1())
        self.pub = private.public_key().public_bytes(serialization.Encoding.X962,
                                                     serialization.PublicFormat.CompressedPoint)
        signed = digest + (b"TARAKO-TLS-V1\0" + self.binder + self.spki).ljust(128, b"\0")
        quote_hash = hashlib.sha256(signed).digest()
        r, s = utils.decode_dss_signature(private.sign(signed, ec.ECDSA(hashes.SHA256())))
        self.quote = b"\x00synthetic quote\xff"
        self.evidence = {"tdx_quote": self.quote.hex(), "tarako": {
            "hash": quote_hash.hex(), "pubkey": self.pub.hex(), "sig_r": f"{r:064x}",
            "sig_s": f"{s:064x}"}}
        self.record, record_digest = tak_record(self.pub)
        self.first = f"10 {'77' * 48} ima-ng boot_aggregate\n"
        self.violation = f"10 {'00' * 48} ima-ng violation\n"
        self.before_key = extend(extend(self.baseline, b"\x77" * 48), b"\xff" * 48)
        self.target = extend(self.before_key, record_digest)
        self.claims = {
            "report_data": (hashlib.sha256(b"TARAKO-TLS-REPORTDATA-V1\0" + quote_hash).digest()
                            + bytes(32)).hex(),
            "mr_td": "11" * 48,
            "rtmrs": ["22" * 48, "33" * 48, self.target.hex(), "44" * 48],
        }
        self.result_key = ec.generate_private_key(ec.SECP256R1())
        self.request = {"binder": self.binder.hex(), "spki_hash": self.spki.hex(),
                        "ima_log": self.first + self.violation + self.record}
        self.update_cmw()

    def update_cmw(self):
        encoded = base64.urlsafe_b64encode(json.dumps(self.evidence).encode()).rstrip(b"=").decode()
        self.request["evidence"] = f' [ "application/vnd.tarako.tdx-evidence+json", "{encoded}" ]\n'

    def verify(self):
        with patch.object(verifier.subprocess, "run") as run:
            run.return_value.stdout = json.dumps(self.claims).encode()
            result = verifier.verify(self.request, self.result_key, self.policy)
            run.assert_called_once()
            self.assertEqual(run.call_args.args, (["tarako-dcap-verify"],))
            self.assertEqual(run.call_args.kwargs["input"], self.quote)
            self.assertTrue(run.call_args.kwargs["check"])
            return result

    def reject(self, error):
        with self.assertRaisesRegex(verifier.Rejected, f"^{error}$"):
            self.verify()

    def test_verdict_signs_exact_cmw_and_ignores_uncommitted_suffix(self):
        other, _ = tak_record(bytes([self.pub[0] ^ 1]) + self.pub[1:])
        self.request["ima_log"] += other
        with patch.object(verifier.time, "time", return_value=1000):
            result = self.verify()
        self.assertEqual(set(result), {"expires", "signature"})
        self.assertEqual(result["expires"], 1030)
        message = (b"TARAKO-TLS-RESULT-V1\0" + self.binder + self.spki
                   + hashlib.sha256(self.request["evidence"].encode()).digest()
                   + (1030).to_bytes(8, "big"))
        self.result_key.public_key().verify(bytes.fromhex(result["signature"]), message,
                                            ec.ECDSA(hashes.SHA256()))

    def test_retryable_replay_mismatch(self):
        self.request["ima_log"] = self.first + self.violation
        self.reject("ima_replay")

    def test_malformed_log_not_retryable(self):
        self.request["ima_log"] = self.first + "10 sha256:abcd ima-buf\n"
        self.reject("ima")

    def test_uncommitted_suffix_cannot_supply_key(self):
        self.claims["rtmrs"][2] = self.before_key.hex()
        self.reject("ima")

    def test_missing_first_entry_breaks_replay(self):
        self.request["ima_log"] = self.violation + self.record
        self.reject("ima_replay")

    def test_legacy_skip_policy_is_rejected(self):
        policy = {name: value.hex() for name, value in self.policy.items()}
        for skip in (0, 1):
            with self.subTest(skip=skip), self.assertRaisesRegex(ValueError, "unexpected JSON fields"):
                verifier.parse_policy(dict(policy, ima_skip_count=skip))

    def test_committed_wrong_key_is_rejected_even_when_replay_matches(self):
        other, digest = tak_record(bytes([self.pub[0] ^ 1]) + self.pub[1:])
        self.claims["rtmrs"][2] = extend(self.before_key, digest).hex()
        self.request["ima_log"] = self.first + self.violation + other
        self.reject("ima")

    def test_forged_template_fields_fail_despite_replay_match(self):
        self.request["ima_log"] = self.request["ima_log"].replace(
            self.pub.hex(), (bytes([self.pub[0] ^ 1]) + self.pub[1:]).hex())
        self.reject("ima")

    def test_ambiguous_committed_keys(self):
        other, digest = tak_record(bytes([self.pub[0] ^ 1]) + self.pub[1:])
        self.claims["rtmrs"][2] = extend(self.target, digest).hex()
        self.request["ima_log"] += other
        self.reject("ima")

    def test_wrong_platform_or_report_data(self):
        for name in ("mr_td", "report_data"):
            with self.subTest(name=name):
                original = self.claims[name]
                self.claims[name] = original[:-2] + "ff"
                self.reject("platform")
                self.claims[name] = original

    def test_dcap_failure(self):
        with patch.object(verifier.subprocess, "run", side_effect=subprocess.CalledProcessError(1, "dcap")):
            with self.assertRaisesRegex(verifier.Rejected, "^platform$"):
                verifier.verify(self.request, self.result_key, self.policy)

    def test_collateral_failure_is_distinct(self):
        for error, reason in (
            (subprocess.CalledProcessError(6, "dcap"), "collateral"),
            (subprocess.TimeoutExpired("dcap", 15), "collateral_timeout"),
        ):
            with self.subTest(reason=reason), patch.object(
                verifier.subprocess, "run", side_effect=error
            ):
                with self.assertRaisesRegex(verifier.Rejected, f"^{reason}$"):
                    verifier.verify(self.request, self.result_key, self.policy)

    def test_bad_tarako_binding_or_signature(self):
        self.request["binder"] = "00" * 32
        self.reject("tarako")
        self.request["binder"] = self.binder.hex()
        self.evidence["tarako"]["sig_r"] = "00" * 32
        self.update_cmw()
        self.reject("tarako")

    def test_strict_request_and_size(self):
        with self.assertRaises(ValueError):
            verifier.strict_json(b'{"binder": "a", "binder": "b"}')
        self.request["ima_log"] = "a" * (verifier.MAX_LOG + 1)
        with self.assertRaisesRegex(ValueError, "IMA log or CMW too large"):
            verifier.verify(self.request, self.result_key, self.policy)


if __name__ == "__main__":
    unittest.main()
