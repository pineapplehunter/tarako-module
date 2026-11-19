import base64
import hashlib
import json
import unittest
from datetime import datetime, timezone
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils

from tarako_tls_mock.mock_http import Rejected
from tarako_tls_mock.mock_signer import quote
from tarako_tls_mock.verifier import verify


def sha(data):
    return hashlib.sha256(data).digest()


def der_sign(key, data):
    return key.sign(data, ec.ECDSA(hashes.SHA256()))


def certificate(name, key, issuer_key, issuer=None):
    subject = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, name)])
    ca = issuer is None
    return (
        x509.CertificateBuilder().subject_name(subject).issuer_name(issuer or subject)
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(datetime(1970, 1, 1, tzinfo=timezone.utc))
        .not_valid_after(datetime(2050, 1, 1, tzinfo=timezone.utc))
        .add_extension(x509.BasicConstraints(ca, 0 if ca else None), critical=True)
        .add_extension(x509.KeyUsage(not ca, False, False, False, False, ca, ca, None, None),
                       critical=True)
        .sign(issuer_key, hashes.SHA256())
    )


class ServicesTest(unittest.TestCase):
    def setUp(self):
        self.mock = ec.generate_private_key(ec.SECP256R1())
        ca_key = ec.generate_private_key(ec.SECP256R1())
        self.platform_ca = certificate("Platform CA", ca_key, ca_key)
        self.leaf = certificate("Report signer", self.mock, ca_key, self.platform_ca.subject)
        self.leaf_der = self.leaf.public_bytes(serialization.Encoding.DER)
        self.result = ec.generate_private_key(ec.SECP256R1())
        self.tarako = ec.generate_private_key(ec.SECP256R1())
        self.tak = self.tarako.public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint)
        self.digest, self.binder, self.spki = b'd'*32, b'b'*32, b's'*32
        self.data = self.digest + (b'TARAKO-TLS-V1\0' + self.binder + self.spki).ljust(128, b'\0')
        r, s = utils.decode_dss_signature(der_sign(self.tarako, self.data))
        self.report = sha(b'TARAKO-TLS-REPORTDATA-V1\0' + sha(self.data)) + bytes(32)
        self.inner = {
            'platform': quote({'report_data': self.report.hex()}, self.mock, self.tak, self.leaf_der),
            'tarako': {'hash': sha(self.data).hex(), 'pubkey': self.tak.hex(),
                       'sig_r': f'{r:064x}', 'sig_s': f'{s:064x}'},
        }

    def request(self):
        value = base64.urlsafe_b64encode(json.dumps(self.inner).encode()).decode().rstrip('=')
        # Whitespace is intentional: hash verbatim, not a reserialization.
        cmw = json.dumps(['application/vnd.tarako.tls-evidence+json', value],
                         indent=2) + '\n'
        return {'binder': self.binder.hex(), 'spki_hash': self.spki.hex(), 'evidence': cmw}

    def check(self, request=None, *, tak=None, digest=None):
        return verify(self.request() if request is None else request,
                      self.result, self.platform_ca, tak or self.tak, digest or self.digest)

    def test_signer_signature_and_input_size(self):
        result = self.inner['platform']
        self.assertEqual(result['report_data'], self.report.hex())
        self.assertEqual(result['tak'], self.tak.hex())
        self.assertEqual(result['certificate'], self.leaf_der.hex())
        self.mock.public_key().verify(bytes.fromhex(result['signature']),
                                      b'TARAKO-MOCK-TDX-V1\0' + self.report + self.tak,
                                      ec.ECDSA(hashes.SHA256()))
        with self.assertRaises(ValueError):
            quote({'report_data': '00'*63}, self.mock, self.tak, self.leaf_der)

    def test_success_signs_exact_evidence_bytes_and_expiry(self):
        request = self.request()
        with patch('tarako_tls_mock.verifier.time.time', return_value=1000.25):
            result = self.check(request)
        self.assertEqual(result['expires'], 1030)
        payload = (b'TARAKO-TLS-RESULT-V1\0' + self.binder + self.spki
                   + sha(request['evidence'].encode('utf-8')) + (1030).to_bytes(8, 'big'))
        self.result.public_key().verify(bytes.fromhex(result['signature']), payload,
                                        ec.ECDSA(hashes.SHA256()))

    def test_platform_signature_failure_with_valid_tarako(self):
        self.inner['platform']['signature'] = '3006020101020101'
        with self.assertRaisesRegex(Rejected, '^platform$'):
            self.check()
        # Platform errors take precedence even if TARAKO also fails.
        self.inner['tarako']['sig_s'] = '00'*32
        with self.assertRaisesRegex(Rejected, '^platform$'):
            self.check()

    def test_tarako_signature_failure_with_valid_platform(self):
        self.inner['tarako']['sig_s'] = '00'*32
        with self.assertRaisesRegex(Rejected, '^tarako$'):
            self.check()

    def test_wrong_pinned_tak(self):
        with self.assertRaisesRegex(Rejected, '^platform$'):
            self.check(tak=bytes(33))

    def test_wrong_approved_digest(self):
        with self.assertRaisesRegex(Rejected, '^tarako$'):
            self.check(digest=bytes(32))

    def test_signed_wrong_report_data(self):
        self.inner['platform'] = quote({'report_data': '00'*64}, self.mock, self.tak, self.leaf_der)
        with self.assertRaisesRegex(Rejected, '^platform$'):
            self.check()

    def test_other_ca_cannot_authorize_the_same_report_key(self):
        other_ca = ec.generate_private_key(ec.SECP256R1())
        leaf = certificate("Report signer", self.mock, other_ca, self.platform_ca.subject)
        self.inner['platform']['certificate'] = leaf.public_bytes(serialization.Encoding.DER).hex()
        with self.assertRaisesRegex(Rejected, '^platform$'):
            self.check()

    def test_expired_report_certificate(self):
        with patch('tarako_tls_mock.verifier.time.time',
                   return_value=datetime(2051, 1, 1, tzinfo=timezone.utc).timestamp()):
            with self.assertRaisesRegex(Rejected, '^platform$'):
                self.check()

    def test_non_record_cmw_rejected(self):
        request = self.request()
        media_type, value = json.loads(request['evidence'])
        request['evidence'] = json.dumps({'type': media_type, 'value': value})
        with self.assertRaisesRegex(Rejected, '^platform$'):
            self.check(request)

    def test_wrong_handshake_or_leaf_key(self):
        for field in ('binder', 'spki_hash'):
            request = self.request()
            request[field] = '00' * 32
            with self.subTest(field=field), self.assertRaisesRegex(Rejected, '^tarako$'):
                self.check(request)


if __name__ == '__main__':
    unittest.main()
