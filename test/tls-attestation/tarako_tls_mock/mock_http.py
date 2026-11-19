"""Shared HTTP/JSON framing for the private mock services."""
import argparse
import json
import re
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec


MAX_BODY = 16 * 1024
MOCK_DOMAIN = b"TARAKO-MOCK-TDX-V1\0"


def fields(value, *names):
    if not isinstance(value, dict) or value.keys() != set(names):
        raise ValueError("unexpected JSON fields")
    return value


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


def hex_bytes(value, size=None):
    if (not isinstance(value, str) or not re.fullmatch(r"(?:[0-9a-fA-F]{2})+", value)
            or (size is not None and len(value) != 2 * size)):
        raise ValueError("invalid hex")
    return bytes.fromhex(value)


def p256_point(raw):
    if len(raw) != 33 or raw[0] not in (2, 3):
        raise ValueError("expected compressed P-256 point")
    return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), raw)


def load_tak(path):
    raw = path.read_bytes()
    p256_point(raw)
    return raw


def signing_key(path):
    key = serialization.load_pem_private_key(path.read_bytes(), password=None)
    if not isinstance(key, ec.EllipticCurvePrivateKey):
        raise ValueError("expected EC signing key")
    return key


def cli(port):
    parser = argparse.ArgumentParser()
    parser.add_argument("--listen", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=port)
    parser.add_argument("--signing-key", type=Path, required=True)
    parser.add_argument("--tak-file", type=Path, required=True)
    return parser


class Rejected(ValueError):
    pass


def serve(listen, port, path, operation):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.0"

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
            self.close_connection = True
            if self.path != path:
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
            except (ValueError, RecursionError):
                self.reply(400, {"error": "request"})
            else:
                self.reply(200, result)

    with HTTPServer((listen, port), Handler) as server:
        server.serve_forever()
