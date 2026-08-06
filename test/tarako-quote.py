"""Request a Tarako signature bound to a caller-provided nonce."""

import argparse
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

TARAKO_APP = Path("/mnt/tarako-app")
VERITY_IMAGE = Path("/tmp/verity.img")
VERITY_IMAGE_SIZE = 64 * 1024 * 1024


def run(*command: str) -> None:
    subprocess.run(command, check=True)


def is_verity_enabled(path: Path) -> bool:
    result = subprocess.run(
        ("fsverity", "measure", path),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    return result.returncode == 0


def use_existing_app() -> bool:
    if not TARAKO_APP.exists():
        return False
    if not is_verity_enabled(TARAKO_APP):
        message = f"existing {TARAKO_APP} is not protected by fs-verity"
        raise SystemExit(message)
    print(f"using existing {TARAKO_APP}", file=sys.stderr)
    return True


def prepare_app() -> None:
    if use_existing_app():
        return

    source = shutil.which("tarako-app")
    if source is None:
        raise SystemExit("tarako-app is not available in PATH")

    mountpoint = TARAKO_APP.parent
    mountpoint.mkdir(parents=True, exist_ok=True)
    if not os.path.ismount(mountpoint):
        if not VERITY_IMAGE.exists():
            message = f"creating fs-verity image at {VERITY_IMAGE}"
            print(message, file=sys.stderr)
            with VERITY_IMAGE.open("wb") as image:
                image.truncate(VERITY_IMAGE_SIZE)
            run("mkfs.ext4", "-q", "-F", "-O", "verity", VERITY_IMAGE)
        run("mount", VERITY_IMAGE, mountpoint)

    if use_existing_app():
        return
    shutil.copy2(source, TARAKO_APP)
    run("fsverity", "enable", "--block-size=1024", TARAKO_APP)
    if not is_verity_enabled(TARAKO_APP):
        raise SystemExit(f"failed to enable fs-verity on {TARAKO_APP}")
    message = f"installed fs-verity-protected app at {TARAKO_APP}"
    print(message, file=sys.stderr)


def parse_nonce(value: str | None) -> bytes:
    if value is None:
        return os.urandom(32)
    try:
        nonce = bytes.fromhex(value)
    except ValueError as error:
        message = f"invalid hexadecimal nonce: {error}"
        raise SystemExit(message) from error
    if not nonce or len(nonce) > 128:
        raise SystemExit("nonce must contain between 1 and 128 bytes")
    return nonce


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("nonce", nargs="?", help="1 to 128 bytes of hex")
    parser.add_argument(
        "-o",
        "--output",
        default="/tmp/tarako-quote.txt",
        help="application output file (default: %(default)s)",
    )
    args = parser.parse_args()
    nonce = parse_nonce(args.nonce)

    prepare_app()
    started = time.perf_counter_ns()
    result = subprocess.run(
        (TARAKO_APP, nonce.hex()),
        check=True,
        stdout=subprocess.PIPE,
    )
    elapsed_ms = (time.perf_counter_ns() - started) / 1_000_000
    Path(args.output).write_bytes(result.stdout)
    app_output = result.stdout.decode()
    sign_timing = next(
        (
            line
            for line in app_output.splitlines()
            if line.startswith("sign ioctl:")
        ),
        "sign ioctl: unavailable in the installed tarako-app",
    )

    print(f"nonce: {nonce.hex()}")
    print(sign_timing)
    print(f"wrote Tarako response to {args.output}")
    print(f"Tarako request: {elapsed_ms:.3f} ms", file=sys.stderr)


if __name__ == "__main__":
    main()
