"""Run the live split-host test; no SSH access to the TDX guest is needed."""
import argparse
import subprocess
import sys
from urllib.parse import urlsplit, urlunsplit


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("url", help="attester HTTPS URL (its DNS name in SAN)")
    parser.add_argument("--ima-log-url", required=True)
    parser.add_argument("--verifier-key", required=True)
    parser.add_argument("--ca")
    parser.add_argument("--verifier", default="http://127.0.0.1:5102/verify")
    parser.add_argument("--wrong-digest-verifier", required=True)
    parser.add_argument("--wrong-ima-verifier", required=True)
    args = parser.parse_args()

    url = urlsplit(args.url)
    if (url.scheme != "https" or not url.hostname or ":" in url.hostname
            or url.username or url.password):
        parser.error("supply an HTTPS DNS-name URL without user information")
    # The test runner passes a different expected name to the client without
    # changing where the TCP connection goes.
    wrong_name = "not-the-attester.invalid"
    if url.hostname == wrong_name:
        parser.error("the positive test must use the real certificate name")
    target = urlunsplit((url.scheme, url.netloc, url.path, url.query, ""))

    def run(name, endpoint, expected=None, tls_name=None):
        command = [
            "tarako-tdx-client", "-v", "--verifier", endpoint,
            "--verifier-key", args.verifier_key, "--ima-log-url",
            args.ima_log_url,
        ]
        if args.ca:
            command += ["--ca", args.ca]
        if tls_name:
            command += ["--tls-name", tls_name]
        result = subprocess.run(
            command + [target], capture_output=True, text=True, timeout=65,
        )
        if expected is None:
            passed = result.returncode == 0 and result.stdout == "Tarako OK"
        else:
            passed = (result.returncode != 0 and not result.stdout
                      and expected in result.stderr
                      and "* TLS handshake passed; sending GET"
                      not in result.stderr)
        if not passed:
            print(f"FAIL: {name}\n{result.stderr}", file=sys.stderr)
            raise SystemExit(1)
        print(f"PASS: {name}", flush=True)

    try:
        run("verified HTTPS GET", args.verifier)
        run("TLS hostname rejected", args.verifier, "TLS authentication:",
            wrong_name)
        run("wrong approved digest rejected", args.wrong_digest_verifier,
            "verifier rejected: tarako")
        run("IMA replay mismatch rejected", args.wrong_ima_verifier,
            "verifier rejected: ima_replay")
    except (OSError, subprocess.TimeoutExpired) as error:
        parser.exit(1, f"live test failed: {error}\n")


if __name__ == "__main__":
    main()
