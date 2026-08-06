"""Generate raw TDX reports and quotes and print operation latency."""

import argparse
import fcntl
import os
from pathlib import Path
import sys
import time

TDX_GUEST = "/dev/tdx_guest"
TDX_REPORT_DATA_LEN = 64
TDX_REPORT_LEN = 1024
# _IOWR('T', 1, struct tdx_report_req) on Linux x86_64.
TDX_CMD_GET_REPORT0 = 0xC4405401
TSM_REPORT_ROOT = Path("/sys/kernel/config/tsm/report")


def parse_nonce(value: str | None) -> bytes:
    if value is None:
        return os.urandom(32)
    try:
        nonce = bytes.fromhex(value)
    except ValueError as error:
        message = f"invalid hexadecimal nonce: {error}"
        raise SystemExit(message) from error
    if not nonce or len(nonce) > TDX_REPORT_DATA_LEN:
        raise SystemExit("nonce must contain between 1 and 64 bytes")
    return nonce


def write_result(path: str, data: bytes) -> None:
    Path(path).write_bytes(data)
    print(f"wrote {len(data)} bytes to {path}")


def get_report(data: bytes) -> tuple[bytes, float]:
    request = bytearray(data + bytes(TDX_REPORT_LEN))
    with open(TDX_GUEST, "rb+", buffering=0) as device:
        started = time.perf_counter_ns()
        fcntl.ioctl(device.fileno(), TDX_CMD_GET_REPORT0, request, True)
        elapsed_ms = (time.perf_counter_ns() - started) / 1_000_000
    return bytes(request[TDX_REPORT_DATA_LEN:]), elapsed_ms


def get_quote(data: bytes) -> tuple[bytes, float]:
    if not TSM_REPORT_ROOT.is_dir():
        message = (
            f"{TSM_REPORT_ROOT} is unavailable; "
            "load tdx_guest and mount configfs"
        )
        raise SystemExit(message)

    instance = TSM_REPORT_ROOT / f"tarako-{os.getpid()}"
    instance.mkdir()
    try:
        (instance / "inblob").write_bytes(data)
        started = time.perf_counter_ns()
        quote = (instance / "outblob").read_bytes()
        elapsed_ms = (time.perf_counter_ns() - started) / 1_000_000
        provider = (instance / "provider").read_text().strip()
        print(f"provider: {provider}")
        return quote, elapsed_ms
    finally:
        instance.rmdir()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("report", "quote"))
    parser.add_argument(
        "nonce",
        nargs="?",
        help="1 to 64 bytes of hex (default: random 32-byte nonce)",
    )
    parser.add_argument("-o", "--output", help="output file")
    args = parser.parse_args()

    nonce = parse_nonce(args.nonce)
    data = nonce.ljust(TDX_REPORT_DATA_LEN, b"\0")
    if args.operation == "report":
        result, elapsed_ms = get_report(data)
        output = args.output or "/tmp/tdreport.bin"
    else:
        result, elapsed_ms = get_quote(data)
        output = args.output or "/tmp/tdquote.bin"

    print(f"nonce: {nonce.hex()}")
    write_result(output, result)
    print(f"TDX {args.operation}: {elapsed_ms:.3f} ms", file=sys.stderr)


if __name__ == "__main__":
    main()
