# Local TDX verifier

Build with `nix build .#live-tdx-verifier` or use `pkgs.live-tdx-verifier` with
TARAKO's default overlay. The `dcap-verify` dependency provides
`bin/tarako-dcap-verify`, which accepts a raw
quote on stdin and exits successfully only after authenticating the quote,
collateral, and claims. The Python service does not appraise collateral itself.

```sh
tarako-tdx-verifier --policy policy.json --signing-key verdict-key.pem
```

The service accepts `POST /verify` on `127.0.0.1:5102` by default and binds only
on loopback. The policy pins `mr_td`, `rtmr0`, `rtmr1`, `rtmr3`, and
`ima_start_rtmr2` (each 48-byte hex), `ima_skip_count` (nonnegative integer),
and `fsverity_digest` (32-byte hex). The signing key is an EC private key in PEM.
The client supplies the exact CMW string and the plaintext SHA-384 IMA bank log;
the verifier never fetches either from the guest. It limits the decoded UTF-8 IMA log to 4 MiB and the TDX quote to 16 KiB.

Only `ima_replay` indicates a retryable snapshot mismatch. A matching RTMR2
prefix must independently authenticate the claimed TAK through an `ima-buf`
`public-key-generate` record; skipped records and the uncommitted suffix
cannot satisfy this requirement. The request does not carry an authenticated
IMA extender fail-stop flag, so this protocol cannot attest that flag.

Run the hardware-free tests with `python -m unittest -v` in this directory
(with `cryptography` installed). They generate keys and IMA evidence and mock
the DCAP subprocess; they do not exercise real quotes or collateral.
