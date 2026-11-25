"""Print candidate reference values from a known-good guest, never enroll."""
import argparse
import json
from pathlib import Path
import re
import subprocess

MEASUREMENTS = Path("/sys/class/misc/tdx_guest/measurements")
IMA_RTMR2 = Path("/sys/kernel/ima_rtmr2")


def measurement(name):
    raw = (MEASUREMENTS / (name + ":sha384")).read_bytes()
    if len(raw) != 48:
        raise ValueError(f"invalid {name} measurement size")
    return raw.hex()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("attester", type=Path, help="fs-verity binary")
    args = parser.parse_args()
    try:
        initial = (IMA_RTMR2 / "initial").read_text().strip()
        if not re.fullmatch(r"[0-9a-fA-F]{96}", initial):
            raise ValueError("invalid IMA replay baseline")
        line = subprocess.run(
            ["fsverity", "measure", str(args.attester.resolve())],
            check=True, text=True, stdout=subprocess.PIPE, timeout=10,
        ).stdout.split()
        if not line or not re.fullmatch(r"sha256:[0-9a-fA-F]{64}", line[0]):
            raise ValueError("expected SHA-256 fs-verity digest")
        policy = {
            "mr_td": measurement("mrtd"),
            "rtmr0": measurement("rtmr0"),
            "rtmr1": measurement("rtmr1"),
            "rtmr3": measurement("rtmr3"),
            "ima_start_rtmr2": initial.lower(),
            "fsverity_digest": line[0].split(":")[1].lower(),
        }
    except (OSError, ValueError, subprocess.CalledProcessError,
            subprocess.TimeoutExpired) as error:
        parser.exit(1, f"cannot collect candidate policy: {error}\n")
    print(json.dumps(policy, indent=2))


if __name__ == "__main__":
    main()
