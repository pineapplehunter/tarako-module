"""Local TARAKO TLS verifier backed by a strict DCAP quote verifier."""
import argparse
import base64
import hashlib
import ipaddress
import json
import re
import struct
import subprocess
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from socket import AF_INET6

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils

MAX_LOG = 4 * 1024 * 1024
MAX_CMW = 49152
MAX_QUOTE = 16384
MAX_BODY = 6 * MAX_LOG + 2 * MAX_CMW
EVIDENCE_TYPE = "application/vnd.tarako.tdx-evidence+json"
REPORT_DOMAIN = b"TARAKO-TLS-REPORTDATA-V1\0"
USER_DOMAIN = b"TARAKO-TLS-V1\0"
RESULT_DOMAIN = b"TARAKO-TLS-RESULT-V1\0"


def sha256(data):
    return hashlib.sha256(data).digest()


class Rejected(ValueError):
    pass


def strict_json(data):
    def pairs(items):
        result = dict(items)
        if len(result) != len(items):
            raise ValueError("duplicate JSON key")
        return result

    def invalid_constant(value):
        raise ValueError(value)

    return json.loads(data.decode("utf-8"), object_pairs_hook=pairs,
                      parse_constant=invalid_constant)


def fields(value, *names):
    if not isinstance(value, dict) or value.keys() != set(names):
        raise ValueError("unexpected JSON fields")
    return value


def hex_bytes(value, size=None):
    if (not isinstance(value, str) or not value or len(value) % 2
            or (size is not None and len(value) != size * 2)
            or not re.fullmatch(r"[0-9a-fA-F]+", value)):
        raise ValueError("invalid hex")
    return bytes.fromhex(value)


def parse_policy(value):
    measurements = ("mr_td", "rtmr0", "rtmr1", "rtmr3", "ima_start_rtmr2")
    fields(value, *measurements, "fsverity_digest", "ima_skip_count")
    skip = value["ima_skip_count"]
    if type(skip) is not int or skip != 0:
        raise ValueError("full IMA coverage requires ima_skip_count = 0")
    return {**{name: hex_bytes(value[name], 48) for name in measurements},
            "ima_skip_count": skip,
            "fsverity_digest": hex_bytes(value["fsverity_digest"], 32)}


def unpack_evidence(raw):
    cmw = strict_json(raw)
    if not isinstance(cmw, list) or len(cmw) != 2:
        raise ValueError("expected a JSON Record CMW")
    media, value = cmw
    if (media != EVIDENCE_TYPE or not isinstance(value, str)
            or not re.fullmatch(r"[A-Za-z0-9_-]+", value)):
        raise ValueError("invalid evidence")
    decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    if base64.urlsafe_b64encode(decoded).decode("ascii").rstrip("=") != value:
        raise ValueError("noncanonical base64url")
    return fields(strict_json(decoded), "tarako", "tdx_quote")


def authenticate_quote(quote):
    try:
        result = subprocess.run(["tarako-dcap-verify"], input=quote,
                                stdout=subprocess.PIPE, check=True, timeout=15)
    except subprocess.CalledProcessError as error:
        if error.returncode == 6:
            raise Rejected("collateral") from error
        raise
    except subprocess.TimeoutExpired as error:
        raise Rejected("collateral_timeout") from error
    return strict_json(result.stdout)


def measured_key(columns, digest):
    # The ASCII fields themselves are not authenticated. Rebuild the binary
    # d-ng|n-ng|buf template and verify its SHA-384 bank digest.
    if len(columns) != 6 or columns[2] != b"ima-buf" or columns[4] != b"public-key-generate":
        return None
    alg, sep, inner_hex = columns[3].partition(b":")
    if not sep or alg not in (b"sha1", b"sha224", b"sha256", b"sha384", b"sha512"):
        return None
    try:
        key = hex_bytes(columns[5].decode("ascii"))
        inner = hex_bytes(inner_hex.decode("ascii"))
    except ValueError:
        return None
    if hashlib.new(alg.decode("ascii"), key).digest() != inner:
        return None
    template = b"".join(struct.pack("<I", len(field)) + field for field in
                        (alg + b":\0" + inner, columns[4] + b"\0", key))
    if hashlib.sha384(template).digest() == digest:
        return key
    return None


def replay_key(log, baseline, target, expected):
    # Start with the very first IMA record. Extend the
    # SHA-384 template digest (FF for a violation). Stop at the first match.
    current = baseline
    key = None
    ambiguous = False
    for line in log.split(b"\n"):
        if current == target:
            break
        columns = line.split(None, 6)
        if not columns:
            continue
        try:
            if len(columns) < 3 or not columns[0].isdigit():
                raise ValueError("invalid measurement")
            token = columns[1]
            if token.startswith(b"sha384:"):
                token = token[7:]
            digest = hex_bytes(token.decode("ascii"), 48)
        except ValueError as error:
            raise Rejected("ima") from error
        if any(digest):
            candidate = measured_key(columns, digest)
            if candidate is not None:
                ambiguous |= key is not None and key != candidate
                key = candidate
        else:
            digest = b"\xff" * 48
        current = hashlib.sha384(current + digest).digest()

    if current != target:
        raise Rejected("ima_replay")
    if ambiguous or key is None or key != expected:
        raise Rejected("ima")


def verify(request, result_key, policy):
    fields(request, "binder", "spki_hash", "evidence", "ima_log")
    binder = hex_bytes(request["binder"], 32)
    spki_hash = hex_bytes(request["spki_hash"], 32)
    if not isinstance(request["evidence"], str) or not isinstance(request["ima_log"], str):
        raise ValueError("evidence and ima_log must be strings")
    cmw = request["evidence"].encode("utf-8")
    log = request["ima_log"].encode("utf-8")
    if len(log) > MAX_LOG or len(cmw) > MAX_CMW:
        raise ValueError("IMA log or CMW too large")

    try:
        evidence = unpack_evidence(cmw)
        quote = hex_bytes(evidence["tdx_quote"])
        if len(quote) > MAX_QUOTE:
            raise ValueError("TDX quote too large")
        claims = fields(authenticate_quote(quote), "report_data", "mr_td", "rtmrs")
        report = hex_bytes(claims["report_data"], 64)
        rtmrs = claims["rtmrs"]
        if not isinstance(rtmrs, list) or len(rtmrs) != 4:
            raise ValueError("expected four RTMRs")
        rtmrs = [hex_bytes(value, 48) for value in rtmrs]
        if (hex_bytes(claims["mr_td"], 48) != policy["mr_td"] or
                any(rtmrs[i] != policy[f"rtmr{i}"] for i in (0, 1, 3))):
            raise ValueError("platform measurement mismatch")
        tarako = evidence["tarako"]
        if not isinstance(tarako, dict):
            raise ValueError("missing report-data binding")
        quote_hash = hex_bytes(tarako.get("hash"), 32)
        if report != sha256(REPORT_DOMAIN + quote_hash) + bytes(32):
            raise ValueError("report-data mismatch")
    except Rejected:
        raise
    except (OSError, subprocess.SubprocessError, ValueError, RecursionError) as error:
        raise Rejected("platform") from error

    try:
        fields(tarako, "hash", "pubkey", "sig_r", "sig_s")
        pubkey = hex_bytes(tarako["pubkey"], 33)
        key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), pubkey)
        r, s = (int.from_bytes(hex_bytes(tarako[name], 32), "big")
                for name in ("sig_r", "sig_s"))
        signed = policy["fsverity_digest"] + (USER_DOMAIN + binder + spki_hash).ljust(128, b"\0")
        if quote_hash != sha256(signed):
            raise ValueError("TARAKO hash mismatch")
        key.verify(utils.encode_dss_signature(r, s), signed, ec.ECDSA(hashes.SHA256()))
    except (InvalidSignature, ValueError) as error:
        raise Rejected("tarako") from error

    replay_key(log, policy["ima_start_rtmr2"], rtmrs[2], pubkey)
    expires = int(time.time()) + 30
    signed = RESULT_DOMAIN + binder + spki_hash + sha256(cmw) + expires.to_bytes(8, "big")
    signature = result_key.sign(signed, ec.ECDSA(hashes.SHA256()))
    return {"expires": expires, "signature": signature.hex()}


def serve(listen, port, operation):
    address = ipaddress.ip_address(listen)
    if not address.is_loopback:
        raise ValueError("--listen must be a loopback address")

    class Server(HTTPServer):
        if address.version == 6:
            address_family = AF_INET6

    class Handler(BaseHTTPRequestHandler):
        def setup(self):
            self.request.settimeout(5)
            super().setup()

        def reply(self, status, value):
            body = json.dumps(value, separators=(",", ":")).encode("ascii")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self):
            if self.path != "/verify":
                self.reply(404, {"error": "request"})
                return
            lengths = self.headers.get_all("Content-Length", [])
            if (self.headers.get_all("Transfer-Encoding") or len(lengths) != 1
                    or not re.fullmatch(r"[0-9]{1,10}", lengths[0])):
                self.reply(400, {"error": "request"})
                return
            length = int(lengths[0])
            if length > MAX_BODY:
                self.reply(413, {"error": "request"})
                return
            try:
                body = self.rfile.read(length)
                if len(body) != length:
                    raise ValueError("incomplete body")
                result = operation(strict_json(body))
            except Rejected as error:
                self.reply(400, {"error": str(error)})
            except (ValueError, RecursionError, TimeoutError):
                self.reply(400, {"error": "request"})
            else:
                self.reply(200, result)

    with Server((listen, port), Handler) as server:
        server.serve_forever()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--listen", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5102)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--signing-key", type=Path, required=True)
    args = parser.parse_args()
    try:
        policy = parse_policy(strict_json(args.policy.read_bytes()))
        key = serialization.load_pem_private_key(args.signing_key.read_bytes(), password=None)
        if (not isinstance(key, ec.EllipticCurvePrivateKey)
                or not isinstance(key.curve, ec.SECP256R1)):
            raise ValueError("expected P-256 EC signing key")
        serve(args.listen, args.port, lambda request: verify(request, key, policy))
    except (OSError, ValueError, TypeError, RecursionError) as error:
        parser.error(str(error))


if __name__ == "__main__":
    main()
