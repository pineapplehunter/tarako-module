"""Benchmark TDX, TPM, and Tarako quote operations."""

import argparse
import os
import re
import statistics
import subprocess

TARGETS = {
    "tdx": (
        ("tdx-attest", "quote"),
        re.compile(r"TDX quote: ([0-9.]+) ms"),
        "TDX quote",
    ),
    "tpm": (
        ("tpm-quote",),
        re.compile(r"TPM quote: ([0-9.]+) ms"),
        "TPM quote",
    ),
    "tarako": (
        ("tarako-quote",),
        re.compile(r"sign ioctl: ([0-9.]+) ms"),
        "Tarako sign ioctl",
    ),
}


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


def measure(target: str, nonce: bytes) -> float:
    command, pattern, _ = TARGETS[target]
    result = subprocess.run(
        (*command, nonce.hex()),
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    output = result.stdout + result.stderr
    match = pattern.search(output)
    if match is None:
        raise SystemExit(
            f"could not find internal timing in {target} output:\n{output}"
        )
    return float(match.group(1))


def print_results(target: str, values: list[float]) -> None:
    _, _, label = TARGETS[target]
    mean = statistics.fmean(values)
    deviation = statistics.stdev(values) if len(values) > 1 else 0.0
    median = statistics.median(values)

    print(f"Benchmark: {label}")
    print(f"  Time (mean ± σ): {mean:.3f} ms ± {deviation:.3f} ms")
    print(f"  Median:          {median:.3f} ms")
    print(f"  Range (min … max): {min(values):.3f} ms … {max(values):.3f} ms")
    print(f"  Runs:            {len(values)}")


def benchmark(target: str, nonce: bytes, warmup: int, runs: int) -> None:
    _, _, label = TARGETS[target]
    print(f"Warming up {label} ({warmup} runs)")
    for _ in range(warmup):
        measure(target, nonce)

    print(f"Measuring {label} ({runs} runs)")
    values = [measure(target, nonce) for _ in range(runs)]
    print_results(target, values)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("target", choices=(*TARGETS, "all"))
    parser.add_argument("nonce", nargs="?", help="1 to 64 bytes of hex")
    parser.add_argument("--warmup", type=int, default=1)
    parser.add_argument("--runs", type=int, default=10)
    args = parser.parse_args()
    if args.warmup < 0:
        parser.error("--warmup cannot be negative")
    if args.runs < 1:
        parser.error("--runs must be at least 1")

    nonce = parse_nonce(args.nonce)
    print(f"Nonce: {nonce.hex()}")
    targets = TARGETS if args.target == "all" else (args.target,)
    for index, target in enumerate(targets):
        if index:
            print()
        benchmark(target, nonce, args.warmup, args.runs)


if __name__ == "__main__":
    main()
