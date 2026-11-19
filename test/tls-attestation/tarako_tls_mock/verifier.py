"""Private test-only verifier; only issues results for platform-bound TARAKO quotes."""
import base64
import hashlib
import re
import time
from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils

from .mock_http import (MOCK_DOMAIN, Rejected, cli, fields, hex_bytes, load_tak,
                       p256_point, serve, signing_key, strict_json)


EVIDENCE_TYPE = "application/vnd.tarako.tls-evidence+json"
RESULT_TTL = 30


def sha256(data):
    return hashlib.sha256(data).digest()


def unpack_evidence(raw):
    cmw = strict_json(raw)
    if not isinstance(cmw, list) or len(cmw) != 2:
        raise ValueError("expected a JSON Record CMW")
    media_type, value = cmw
    if (media_type != EVIDENCE_TYPE or not isinstance(value, str)
            or not re.fullmatch(r"[A-Za-z0-9_-]+", value)):
        raise ValueError("invalid evidence")
    decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    if base64.urlsafe_b64encode(decoded).decode("ascii").rstrip("=") != value:
        raise ValueError("noncanonical base64url")
    return fields(strict_json(decoded), "tarako", "platform")


def report_signing_key(certificate, platform_ca):
    """The mock has exactly one signing leaf directly under its pinned root."""
    leaf = x509.load_der_x509_certificate(certificate)
    leaf.verify_directly_issued_by(platform_ca)
    now = datetime.fromtimestamp(time.time(), timezone.utc)
    for cert in (platform_ca, leaf):
        if not cert.not_valid_before_utc <= now < cert.not_valid_after_utc:
            raise ValueError("certificate outside validity period")
    if (not platform_ca.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
            or not platform_ca.extensions.get_extension_for_class(x509.KeyUsage).value.key_cert_sign
            or leaf.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
            or not leaf.extensions.get_extension_for_class(x509.KeyUsage).value.digital_signature):
        raise ValueError("incorrect certificate roles")
    key = leaf.public_key()
    if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(key.curve, ec.SECP256R1):
        raise ValueError("expected P-256 mock signing key")
    return key


def verify(request, result_key, platform_ca, expected_tak, digest):
    fields(request, "binder", "spki_hash", "evidence")
    binder = hex_bytes(request["binder"], 32)
    spki_hash = hex_bytes(request["spki_hash"], 32)
    try:
        if not isinstance(request["evidence"], str):
            raise ValueError("evidence must be a string")
        cmw_bytes = request["evidence"].encode("utf-8")
        cmw_hash = sha256(cmw_bytes)
        evidence = unpack_evidence(cmw_bytes)
        platform = fields(evidence["platform"], "report_data", "tak", "signature", "certificate")
        report = hex_bytes(platform["report_data"], 64)
        tak = hex_bytes(platform["tak"], 33)
        signature = hex_bytes(platform["signature"])
        mock_key = report_signing_key(hex_bytes(platform["certificate"]), platform_ca)
        mock_key.verify(signature, MOCK_DOMAIN + report + tak, ec.ECDSA(hashes.SHA256()))
        if tak != expected_tak:
            raise ValueError("untrusted TAK")
        tarako = evidence["tarako"]
        if not isinstance(tarako, dict):
            raise ValueError("missing report-data binding")
        quote_hash = hex_bytes(tarako.get("hash"), 32)
        if report != sha256(b"TARAKO-TLS-REPORTDATA-V1\0" + quote_hash) + bytes(32):
            raise ValueError("report-data mismatch")
    except (InvalidSignature, UnsupportedAlgorithm, ValueError, RecursionError,
            x509.DuplicateExtension, x509.ExtensionNotFound) as error:
        raise Rejected("platform") from error

    try:
        fields(tarako, "hash", "pubkey", "sig_r", "sig_s")
        pubkey = hex_bytes(tarako["pubkey"], 33)
        if pubkey != tak:
            raise ValueError("TARAKO public key does not match platform TAK")
        key = p256_point(pubkey)
        r, s = (int.from_bytes(hex_bytes(tarako[name], 32), "big")
                for name in ("sig_r", "sig_s"))
        user_data = (b"TARAKO-TLS-V1\0" + binder + spki_hash).ljust(128, b"\0")
        signed = digest + user_data
        if quote_hash != sha256(signed):
            raise ValueError("TARAKO hash mismatch")
        key.verify(utils.encode_dss_signature(r, s), signed, ec.ECDSA(hashes.SHA256()))
    except (InvalidSignature, ValueError) as error:
        raise Rejected("tarako") from error

    expires = int(time.time()) + RESULT_TTL
    signed = (b"TARAKO-TLS-RESULT-V1\0" + binder + spki_hash + cmw_hash
              + expires.to_bytes(8, "big"))
    signature = result_key.sign(signed, ec.ECDSA(hashes.SHA256()))
    return {"expires": expires, "signature": signature.hex()}


def main():
    parser = cli(5102)
    parser.add_argument("--platform-ca", type=Path, required=True)
    parser.add_argument("--digest-file", type=Path, required=True)
    args = parser.parse_args()
    key = signing_key(args.signing_key)
    platform_ca = x509.load_pem_x509_certificate(args.platform_ca.read_bytes())
    tak = load_tak(args.tak_file)
    digest = hex_bytes(args.digest_file.read_text(encoding="ascii").strip(), 32)
    serve(args.listen, args.port, "/verify", lambda request: verify(request, key, platform_ca, tak, digest))


if __name__ == "__main__":
    main()
