"""Generate synthetic SHA-384 fixtures independently using OpenSSL."""

import argparse
import json
from pathlib import Path
import struct
import subprocess

# Compressed P-256 generator and its negation; neither is a deployed TAK.
X = bytes.fromhex(
    "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
)


def digest(alg, data):
    return subprocess.run(
        ["openssl", "dgst", "-" + alg, "-binary"],
        input=data, capture_output=True, check=True,
    ).stdout


def record(name, data):
    inner = digest("sha256", data)
    # ima-buf = d-ng | n-ng | buf, each prefixed by a little-endian u32 length.
    fields = (b"sha256:\0" + inner, name.encode() + b"\0", data)
    template = b"".join(
        struct.pack("<I", len(field)) + field for field in fields
    )
    bank = digest("sha384", template)
    line = (
        f"10 {bank.hex()} ima-buf sha256:{inner.hex()} {name} {data.hex()}\n"
    )
    return line, bank


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output_directory', type=Path)
    dest = parser.parse_args().output_directory
    dest.mkdir(parents=True, exist_ok=True)
    initial = bytes(range(48))  # Deliberately nonzero startup baseline.
    startup, first_digest = record("startup", b"first measured entry")
    # The displayed zero template digest is extended as 48 bytes of 0xff.
    violation = f"10 {'00' * 48} ima-ng sha256:{'00' * 32} invalidated\n"
    after_startup = digest("sha384", initial + first_digest)
    after_violation = digest("sha384", after_startup + b"\xff" * 48)
    expected_tak = b"\x03" + X
    other_tak = b"\x02" + X
    values = {"initial": initial.hex(), "skip": 0, "tak": expected_tak.hex()}
    for name, tak in (
        ("with-tak", expected_tak), ("without-expected-tak", other_tak)
    ):
        entry, bank = record("public-key-generate", tak)
        (dest / f"{name}.log").write_text(startup + violation + entry)
        values[name] = digest("sha384", after_violation + bank).hex()
    (dest / "golden.json").write_text(json.dumps(values, indent=2) + "\n")


if __name__ == "__main__":
    main()
