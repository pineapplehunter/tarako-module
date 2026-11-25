"""Generate raw TDX reports and quotes and print operation latency."""

import argparse
import fcntl
import os
from pathlib import Path
import subprocess
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


def verify_quote(quote: bytes, data: bytes, collateral: bool = False) -> None:
    """Verify with go-tdx-guest, outside the quote-generation timer."""
    online = str(collateral).lower()
    started = time.perf_counter_ns()
    try:
        result = subprocess.run(
            (
                "tdx-verify",
                "-in=-",
                "-inform=bin",
                f"-report_data={data.hex()}",
                f"-get_collateral={online}",
                f"-check_crl={online}",
                "-timeout=20s",
            ),
            input=quote,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=180,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise SystemExit(f"TDX verification failed: {error}") from error
    if result.returncode != 0:
        details = result.stdout.decode(errors="replace")
        raise SystemExit(f"TDX verification failed:\n{details}")
    elapsed_ms = (time.perf_counter_ns() - started) / 1_000_000
    scope = (
        "signatures, Intel chain, REPORTDATA, QE identity, TCB, CRLs"
        if collateral
        else "signatures, Intel-rooted certificates, REPORTDATA; "
        "offline: no QE identity/TCB/revocation appraisal"
    )
    print(f"TDX verification: OK ({scope})")
    print(
        f"TDX verification time: {elapsed_ms:.3f} ms "
        "(excluded from quote time)"
    )


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
        try:
            quote = (instance / "outblob").read_bytes()
        except OSError as error:
            elapsed_ms = (time.perf_counter_ns() - started) / 1_000_000
            raise SystemExit(
                f"TDX GetQuote failed after {elapsed_ms:.3f} ms: {error}.\n"
                "No quote was generated or verified. Check the host QEMU "
                "QGS diagnostics and journalctl -u tdx-qgs."
            ) from error
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
    parser.add_argument(
        "--verify-collateral",
        action="store_true",
        help="also check online PCS collateral, QE identity, TCB and CRLs",
    )
    args = parser.parse_args()
    if args.verify_collateral and args.operation != "quote":
        parser.error("--verify-collateral requires the quote operation")

    nonce = parse_nonce(args.nonce)
    print(f"nonce: {nonce.hex()}", flush=True)
    data = nonce.ljust(TDX_REPORT_DATA_LEN, b"\0")
    if args.operation == "report":
        result, elapsed_ms = get_report(data)
        output = args.output or "/tmp/tdreport.bin"
    else:
        result, elapsed_ms = get_quote(data)
        output = args.output or "/tmp/tdquote.bin"

    write_result(output, result)
    if args.operation == "quote":
        # Save rejected evidence for diagnosis, but never report a timing
        # sample until verification (including the caller's nonce) succeeds.
        verify_quote(result, data, args.verify_collateral)
    print(f"TDX {args.operation}: {elapsed_ms:.3f} ms", file=sys.stderr)


if __name__ == "__main__":
    main()
