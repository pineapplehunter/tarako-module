"""Run the RATS Background-Check flow for one Tarako Quote."""

import argparse
import json
from pathlib import Path
import subprocess
import tempfile
import time

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
import requests


def request_challenge(verifier_host: str, request_value: str) -> dict:
    for attempt in range(5):
        try:
            response = requests.post(
                f"http://{verifier_host}:5001/challenge",
                json={"request": request_value},
                timeout=10,
            )
            response.raise_for_status()
            return response.json()
        except requests.RequestException:
            if attempt == 4:
                raise
            time.sleep(1)
    raise AssertionError("unreachable")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--trusted-root-ca", required=True, type=Path)
    parser.add_argument("verifier_host")
    parser.add_argument("attester_host")
    parser.add_argument("request")
    args = parser.parse_args()

    challenge = request_challenge(args.verifier_host, args.request)
    quote_response = requests.post(
        f"http://{args.attester_host}:5000/quote",
        json={
            "nonce": challenge["nonce"],
            "request": challenge["request"],
        },
        timeout=15,
    )
    quote_response.raise_for_status()

    result_response = requests.post(
        f"http://{args.verifier_host}:5001/verify",
        json={
            "challenge_id": challenge["challenge_id"],
            "nonce": challenge["nonce"],
            "request": challenge["request"],
            "tq": quote_response.json(),
        },
        timeout=15,
    )
    result_response.raise_for_status()
    envelope = result_response.json()
    certificate_pem = envelope["certificate"].encode()
    with tempfile.NamedTemporaryFile() as certificate_file:
        certificate_file.write(certificate_pem)
        certificate_file.flush()
        subprocess.run(
            [
                "openssl",
                "verify",
                "-CAfile",
                str(args.trusted_root_ca),
                certificate_file.name,
            ],
            check=True,
            capture_output=True,
            text=True,
        )

    root_certificate = x509.load_pem_x509_certificate(
        args.trusted_root_ca.read_bytes()
    )
    verifier_certificate = x509.load_pem_x509_certificate(certificate_pem)
    if verifier_certificate.issuer != root_certificate.subject:
        message = "Verifier certificate was not issued by the root CA"
        raise RuntimeError(message)
    verifier_public_key = verifier_certificate.public_key()
    if not isinstance(verifier_public_key, ec.EllipticCurvePublicKey):
        raise RuntimeError("Verifier certificate does not contain an EC key")

    result = envelope["result"]
    result_bytes = json.dumps(
        result, sort_keys=True, separators=(",", ":")
    ).encode()
    verifier_public_key.verify(
        bytes.fromhex(envelope["signature"]),
        result_bytes,
        ec.ECDSA(hashes.SHA256()),
    )
    if result.get("accepted") is not True:
        raise RuntimeError("Verifier rejected the Tarako Quote")
    if result.get("challenge_id") != challenge["challenge_id"]:
        raise RuntimeError("Attestation Result has the wrong challenge ID")
    if result.get("nonce") != challenge["nonce"]:
        raise RuntimeError("Attestation Result has the wrong nonce")
    if result.get("request") != args.request:
        raise RuntimeError("Attestation Result has the wrong request")
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
