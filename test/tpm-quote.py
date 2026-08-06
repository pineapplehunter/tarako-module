"""Request a TPM quote bound to a caller-provided nonce."""

import argparse
import os
from pathlib import Path
import subprocess
import sys
import time

STATE_DIR = Path("/tmp/tpm-quote")


def parse_nonce(value: str | None) -> bytes:
    if value is None:
        return os.urandom(32)
    try:
        nonce = bytes.fromhex(value)
    except ValueError as error:
        message = f"invalid hexadecimal nonce: {error}"
        raise SystemExit(message) from error
    if not nonce or len(nonce) > 64:
        raise SystemExit("nonce must contain between 1 and 64 bytes")
    return nonce


def run(*command: str) -> None:
    subprocess.run(command, cwd=STATE_DIR, check=True)


def ensure_attestation_key() -> None:
    STATE_DIR.mkdir(mode=0o700, exist_ok=True)
    if (STATE_DIR / "ak.ctx").exists():
        return

    print("creating TPM endorsement and attestation keys", file=sys.stderr)
    run("tpm2_createek", "-G", "rsa", "-c", "ek.ctx")
    run(
        "tpm2_createak",
        "-C",
        "ek.ctx",
        "-G",
        "ecc",
        "-g",
        "sha256",
        "-s",
        "ecdsa",
        "-c",
        "ak.ctx",
        "-u",
        "ak.pub",
        "-n",
        "ak.name",
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("nonce", nargs="?", help="1 to 64 bytes of hex")
    args = parser.parse_args()
    nonce = parse_nonce(args.nonce)

    ensure_attestation_key()
    command = (
        "tpm2_quote",
        "-c",
        "ak.ctx",
        "-l",
        "sha256:0,1,2,3,4,5,6,7",
        "-q",
        nonce.hex(),
        "-m",
        "quote.msg",
        "-s",
        "quote.sig",
        "-o",
        "quote.pcr",
    )
    started = time.perf_counter_ns()
    run(*command)
    elapsed_ms = (time.perf_counter_ns() - started) / 1_000_000

    print(f"nonce: {nonce.hex()}")
    print(f"TPM quote: {elapsed_ms:.3f} ms", file=sys.stderr)
    print(f"quote files: {STATE_DIR}/quote.msg, quote.sig, quote.pcr")


if __name__ == "__main__":
    main()
