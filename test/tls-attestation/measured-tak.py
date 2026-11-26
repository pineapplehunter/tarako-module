"""Extract the TARAKO key from an IMA log matching vTPM PCR 10."""
import argparse
from hashlib import new, sha256
from struct import pack
import sys


def measured_tak(log, expected_pcr):
    assert len(expected_pcr) == 32, "expected one SHA-256 PCR value"
    pcr = bytes(32)
    tak = None
    for line in log:
        index, digest, template, *fields = line.split()
        if index != "10":
            continue
        bank_digest = bytes.fromhex(digest)
        assert len(bank_digest) == 32, "expected a SHA-256 IMA bank digest"
        if template == "ima-buf" and fields[1:2] == ["public-key-generate"]:
            assert tak is None, "multiple TARAKO public-key events in IMA"
            hash_field, event_name, payload = fields
            algorithm, inner_digest = hash_field.split(":", 1)
            tak = bytes.fromhex(payload)
            assert len(tak) == 33 and tak[0] in (2, 3), "invalid TARAKO key"
            inner = new(algorithm, tak).digest()
            assert inner.hex() == inner_digest, "bad TARAKO payload digest"
            # Rebuild ima-buf to bind the displayed key to the PCR.
            data = (
                algorithm.encode() + b":\0" + inner,
                event_name.encode() + b"\0",
                tak,
            )
            encoded = b"".join(pack("<I", len(part)) + part for part in data)
            assert sha256(encoded).digest() == bank_digest, "bad IMA digest"
        extend = bank_digest if any(bank_digest) else b"\xff" * 32
        pcr = sha256(pcr + extend).digest()
        if pcr == expected_pcr:
            assert tak is not None, "TARAKO key not in the matching prefix"
            return tak.hex()
    raise AssertionError("SHA-256 IMA log did not replay to vTPM PCR 10")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pcr", help="hex PCR 10; read the log on stdin")
    args = parser.parse_args()
    print(measured_tak(sys.stdin, bytes.fromhex(args.pcr)))


if __name__ == "__main__":
    main()
