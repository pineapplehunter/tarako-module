"""Private test-only mock platform quote signer."""
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from .mock_http import MOCK_DOMAIN, cli, fields, hex_bytes, load_tak, serve, signing_key


def quote(request, key, tak, certificate_der):
    report_data = hex_bytes(fields(request, "report_data")["report_data"], 64)
    signature = key.sign(MOCK_DOMAIN + report_data + tak, ec.ECDSA(hashes.SHA256()))
    return {
        "report_data": report_data.hex(), "tak": tak.hex(),
        "signature": signature.hex(), "certificate": certificate_der.hex(),
    }


def main():
    parser = cli(5101)
    parser.add_argument("--signing-cert", type=Path, required=True)
    args = parser.parse_args()
    key, tak = signing_key(args.signing_key), load_tak(args.tak_file)
    leaf = x509.load_pem_x509_certificate(args.signing_cert.read_bytes())
    if leaf.public_key() != key.public_key():
        parser.error("--signing-cert does not match --signing-key")
    der = leaf.public_bytes(serialization.Encoding.DER)
    serve(args.listen, args.port, "/quote", lambda request: quote(request, key, tak, der))


if __name__ == "__main__":
    main()
