"""Background-check Verifier for nonce-bound Tarako Quotes."""

import argparse
import hashlib
import json
import logging
import os
from pathlib import Path
import threading

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from flask import Flask, jsonify, request

DOMAIN = b"TARAKO-TQ-REQUEST-V1\x00"
USER_DATA_BYTES = 128

app = Flask(__name__)
logger = logging.getLogger(__name__)
policy_directory = Path("/var/lib/tarako")
verifier_certificate = ""
verifier_signing_key = None
outstanding_challenges = {}
challenge_lock = threading.Lock()


def make_request_binding(request_value: str, nonce: bytes) -> bytes:
    context = json.dumps(
        {"nonce": nonce.hex(), "request": request_value},
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    return hashlib.sha256(DOMAIN + context).digest()


def load_appraisal_policy():
    digest = bytes.fromhex(
        (policy_directory / "approved-digest").read_text().strip()
    )
    public_key_bytes = (policy_directory / "trusted-tak.bin").read_bytes()
    public_key = ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256R1(), public_key_bytes
    )
    return digest, public_key_bytes, public_key


def verify_tarako_quote(
    quote: dict,
    binding: bytes,
    digest: bytes,
    trusted_key_bytes: bytes,
    trusted_key,
) -> str:
    expected_user_data = binding + bytes(USER_DATA_BYTES - len(binding))
    response_user_data = bytes.fromhex(quote["user_data"])
    if response_user_data != expected_user_data:
        message = "TQ user data does not contain the expected request binding"
        raise ValueError(message)

    quoted_key = bytes.fromhex(quote["public_key"])
    if quoted_key != trusted_key_bytes:
        raise ValueError("TQ public key does not match the provisioned TAKpub")

    message = digest + expected_user_data
    expected_hash = hashlib.sha256(message).hexdigest()
    if quote["hash"] != expected_hash:
        raise ValueError("TQ message hash does not match D || U")

    signature_der = bytes.fromhex(quote["signature_der"])
    trusted_key.verify(signature_der, message, ec.ECDSA(hashes.SHA256()))
    return expected_hash


def json_request_value():
    body = request.get_json(silent=True)
    if not isinstance(body, dict) or not isinstance(body.get("request"), str):
        raise ValueError("request must be a JSON string")
    if not body["request"]:
        raise ValueError("request must not be empty")
    return body


@app.post("/challenge")
def challenge():
    try:
        body = json_request_value()
    except ValueError as error:
        return jsonify(error=str(error)), 400

    nonce = os.urandom(32)
    challenge_id = os.urandom(16).hex()
    with challenge_lock:
        outstanding_challenges[challenge_id] = {
            "nonce": nonce.hex(),
            "request": body["request"],
        }
    return jsonify(
        challenge_id=challenge_id,
        nonce=nonce.hex(),
        request=body["request"],
    )


@app.post("/verify")
def verify():
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        return jsonify(accepted=False, error="JSON object required"), 400
    challenge_id = body.get("challenge_id")
    if not isinstance(challenge_id, str):
        return jsonify(accepted=False, error="challenge_id required"), 400

    # Consume the challenge before parsing Evidence so each challenge can
    # produce at most one Attestation Result, including after failed Evidence.
    with challenge_lock:
        expected = outstanding_challenges.pop(challenge_id, None)
    if expected is None:
        error = "unknown or consumed challenge"
        return jsonify(accepted=False, error=error), 409

    try:
        if body.get("request") != expected["request"]:
            raise ValueError("request does not match the challenge")
        if body.get("nonce") != expected["nonce"]:
            raise ValueError("nonce does not match the challenge")
        quote = body.get("tq")
        if not isinstance(quote, dict):
            raise ValueError("tq must be a JSON object")
        nonce = bytes.fromhex(expected["nonce"])
        binding = make_request_binding(expected["request"], nonce)
        digest, public_key_bytes, public_key = load_appraisal_policy()
        kernel_hash = verify_tarako_quote(
            quote, binding, digest, public_key_bytes, public_key
        )
    except Exception as error:
        logger.exception("Tarako Quote verification failed")
        return jsonify(accepted=False, error=str(error)), 400

    result = {
        "accepted": True,
        "challenge_id": challenge_id,
        "digest": digest.hex(),
        "kernel_hash": kernel_hash,
        "nonce": expected["nonce"],
        "request": expected["request"],
        "request_binding": binding.hex(),
    }
    result_bytes = json.dumps(
        result, sort_keys=True, separators=(",", ":")
    ).encode()
    signature = verifier_signing_key.sign(
        result_bytes, ec.ECDSA(hashes.SHA256())
    )
    return jsonify(
        certificate=verifier_certificate,
        result=result,
        signature=signature.hex(),
    )


def main() -> None:
    global policy_directory
    global verifier_certificate
    global verifier_signing_key

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy-directory", required=True, type=Path)
    parser.add_argument("--certificate", required=True, type=Path)
    parser.add_argument("--signing-key", required=True, type=Path)
    parser.add_argument("--port", type=int, default=5001)
    args = parser.parse_args()

    policy_directory = args.policy_directory
    verifier_certificate = args.certificate.read_text()
    verifier_signing_key = serialization.load_pem_private_key(
        args.signing_key.read_bytes(), password=None
    )
    if not isinstance(verifier_signing_key, ec.EllipticCurvePrivateKey):
        raise SystemExit("Verifier signing key is not an elliptic-curve key")

    app.run(host="0.0.0.0", port=args.port)


if __name__ == "__main__":
    main()
