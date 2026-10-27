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


def measure(target: str, tdx_collateral: bool = False) -> float:
    command, pattern, _ = TARGETS[target]
    # Freshness applies to every invocation, including warmups and all targets.
    nonce = os.urandom(32)
    arguments = (*command, nonce.hex())
    if target == "tdx" and tdx_collateral:
        arguments += ("--verify-collateral",)
    result = subprocess.run(
        arguments,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    output = result.stdout + result.stderr
    if result.returncode != 0:
        raise SystemExit(f"{target} quote command failed:\n{output}")
    if target == "tdx" and "TDX verification: OK" not in output:
        raise SystemExit(f"TDX quote was not verified:\n{output}")
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


def benchmark(
    target: str, warmup: int, runs: int, tdx_collateral: bool = False
) -> None:
    _, _, label = TARGETS[target]
    print(f"Warming up {label} ({warmup} runs)")
    for _ in range(warmup):
        measure(target, tdx_collateral)

    print(f"Measuring {label} ({runs} runs)")
    values = [measure(target, tdx_collateral) for _ in range(runs)]
    print_results(target, values)
    if target == "tdx":
        scope = (
            "signatures, Intel chain, nonce, QE identity, TCB, CRLs"
            if tdx_collateral
            else "signatures, Intel-rooted certificates, nonce "
            "(offline; no QE identity/TCB/revocation appraisal)"
        )
        print(f"  Verification:    all quotes passed: {scope}")
        print("  Verification time is excluded from quote-generation latency.")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("target", choices=(*TARGETS, "all"))
    parser.add_argument("--warmup", type=int, default=1)
    parser.add_argument("--runs", type=int, default=10)
    parser.add_argument(
        "--tdx-collateral",
        action="store_true",
        help="also check online PCS collateral, QE identity, TCB and CRLs",
    )
    args = parser.parse_args()
    if args.warmup < 0:
        parser.error("--warmup cannot be negative")
    if args.runs < 1:
        parser.error("--runs must be at least 1")

    if args.tdx_collateral and args.target not in ("tdx", "all"):
        parser.error("--tdx-collateral requires target tdx or all")

    print(
        "Nonce: fresh random 32-byte value per invocation (including warmups)"
    )
    targets = TARGETS if args.target == "all" else (args.target,)
    for index, target in enumerate(targets):
        if index:
            print()
        benchmark(target, args.warmup, args.runs, args.tdx_collateral)


if __name__ == "__main__":
    main()
