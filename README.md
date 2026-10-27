# tarako — Remote Attestation with an ECDSA P-256 Kernel Module

A Linux kernel module that generates an ECDSA P-256 key pair on load, exposes it via `/dev/tarako`, and signs a measurement of the calling process (its fs-verity digest) bound to 1024 bits of opaque user data. A challenge nonce can be placed in that data to provide freshness.

## Architecture

The integration follows the RATS **Background-Check Model**. The Client acts as the Relying Party and carries Evidence between the Attester and Verifier:

```text
Client/Relying Party          Attester                 Verifier
        |                         |                        |
        |--- request challenge -------------------------->|
        |<-- nonce + challenge ID ------------------------|
        |--- request + nonce ------>|                     |
        |<-- Tarako Quote ----------|                     |
        |--- Tarako Quote + expected request/nonce ------>|
        |<-- signed Attestation Result + certificate ------|
```

The Attester never contacts the Verifier and never receives an Attestation Result.

**Attester** (runs the kernel module):
1. Loads `tarako` module — ECDSA P-256 key pair is generated in kernel space.
2. The private key never leaves the kernel and is zeroized on module unload.
3. The fs-verity-protected Go Attester webserver accepts a Client request and Verifier nonce, calls `TARAKO_SIGN_DATA` directly, and returns Tarako Quote Evidence to the Client.

**Kernel module (`driver/src/`)** — three ioctls:

| Ioctl | Code | Description |
|-------|------|-------------|
| `TARAKO_HELLO` | `0x0000_5300` | Sanity check |
| `TARAKO_GET_PUBKEY` | `0x8021_5301` | Return the compressed SEC1 ECDSA P-256 public key (33 bytes) |
| `TARAKO_SIGN_DATA` | `0xC101_5302` | Sign `SHA256(fsverity_digest \|\| user_data)` with ECDSA P-256; `user_data` is 128 bytes |

The signing ioctl is guarded: the generated public key must have been measured successfully by **IMA**, and the caller's executable must be protected by **fs-verity**. This binds the signature to a remotely verifiable key, the measured executable, and caller-supplied data.

## Components

| Path | Role |
|------|------|
| `driver/src/` | Kernel module (Rust, `rust/kernel` framework) — multi-file layout |
| `app/src/main.rs` | Userspace `tarako-app` — opens `/dev/tarako` and issues ioctls |
| `attester/main.go` | Single-binary Go Attester webserver that calls the ioctls directly |
| `test/attestation.py` | Three-node Background-Check NixOS VM integration test |
| `test/verifier.py` | Stateful Verifier challenge, TQ validation, and result service |

## Build & Test

```sh
# Kernel module
nix build .#default

# Userspace ioctl app and single-binary Go Attester
nix build .#app
nix build .#attester

# NixOS VM attestation test
nix build .#checks.x86_64-linux.attestation

# Build (but do not run) the TDX test driver and its TDVF firmware
nix build .#tdx-test-driver

# Build only the TDX-enabled TDVF firmware
nix build .#tdx-firmware

# Dev shell with Rust + rust-src
nix develop
```

The integration test creates three VMs:
- **client/Relying Party**: obtains a challenge from the Verifier, sends the request and nonce to the Attester, forwards the returned Tarako Quote and expected values to the Verifier, validates the Verifier certificate against its trusted root CA, and authenticates the signed Attestation Result.
- **verifier**: generates and records a fresh nonce, atomically consumes it when Evidence arrives, verifies the TAK public key, `D || U` hash, and ECDSA signature, and signs the Attestation Result with the private key for its root-signed certificate.
- **attester**: loads the module and runs one fs-verity-protected Go webserver binary as `tarako-attester.service`. That binary handles the request and directly invokes the Tarako ioctls, so its own executable digest is `D`.

The Verifier service starts at boot with a test leaf certificate and private key; its appraisal-policy files may be provisioned afterward. The Client has only the test root CA certificate. These committed credentials are integration-test fixtures, not production keys. The Attester service remains disabled at boot, and its systemd service script copies the Go binary to mutable storage, enables fs-verity on it, and then executes that exact file.

The Attester and Verifier never communicate directly. The test repeats identical Client requests and requires distinct Verifier nonces and request bindings. TDX/IMA appraisal is outside this network flow; the test harness provisions the measured TAK public key and approved executable digest to test only Tarako Quote generation and Background-Check appraisal.

### Running the test on TDX

Build the driver and firmware without running the VM in the Nix build sandbox, then execute the driver on the TDX host:

```sh
nix build .#tdx-test-driver
./result/bin/nixos-test-driver
```

The TDX attester defaults to pinned vendor QEMU and source-built TDVF for the
experiment's `6.8.0-1028-intel` host kernel.

> **Intended host environment:** The added `tdx-qemu` package targets Ubuntu
> 24.04.4 LTS (Noble), x86_64, with the vendor Intel kernel shown below. It is
> not intended as a general-purpose QEMU replacement for other TDX host stacks.
> The hostname has been anonymized.

```text
Linux <tdx-host> 6.8.0-1028-intel #35-Ubuntu SMP PREEMPT_DYNAMIC Fri May 23 17:34:54 UTC 2025 x86_64 x86_64 x86_64 GNU/Linux
No LSB modules are available.
Distributor ID: Ubuntu
Description:    Ubuntu 24.04.4 LTS
Release:        24.04
Codename:       noble
```

- **QEMU:** 8.2.2 built from source with the complete patch series from Ubuntu
  `2:8.2.2+ds-0ubuntu1.4+tdx1.1`, with VDE networking enabled. The upstream tarball
  and [Canonical TDX PPA](https://ppa.launchpadcontent.net/kobuk-team/tdx-release/ubuntu/)
  patch archive are hash-pinned in `tdx/qemu.nix`. A local
  `tdx/qemu-qgs-protocol.patch` adds Intel QGS request/response framing, rejects
  EOF/empty responses, and preserves 64-bit GetQuote error codes.
- **TDVF:** EDK II's dedicated `IntelTdxX64` Config-B firmware, built from source
  using nixpkgs' `OVMF-inteltdx` builder. `flake.lock` pins the EDK II source and
  submodules (currently `edk2-stable202608`). The PPA's prebuilt `OVMF.tdx.fd` is
  not used: it failed to boot in this experiment.

The firmware builder follows the [EDK II TDVF source-build steps](https://github.com/tianocore/edk2/blob/edk2-stable202608/OvmfPkg/IntelTdx/README.md):
build BaseTools, source `edksetup.sh`, and run
`build -p OvmfPkg/IntelTdx/IntelTdxX64.dsc -a X64 -t GCC -b RELEASE`.
No host-installed QEMU or manually supplied firmware is needed. Build them
independently with `nix build .#tdx-qemu` and `nix build .#tdx-firmware`; inspect
QEMU with `nix run .#tdx-qemu -- --version` and locate the firmware with
`nix eval --raw .#tdx-firmware.firmware`.
The Client and Verifier still use nixpkgs' QEMU. The vendor QEMU is for the older
TDX host ABI, not a replacement for upstream QEMU on newer upstream TDX hosts.

The host must have KVM access and a quote-generation service listening on vsock
CID 2, port 4050. The attester uses direct kernel boot through TDVF, 4 CPUs,
4 GiB RAM, and a CRB vTPM backed by `swtpm`. Its TPM state is kept in
`tarako-attestation-tdx-attester-swtpm` by default; set `NIX_SWTPM_DIR` to choose
another location. Extra test-driver options, such as `--keep-machine-state`,
can be passed normally.

For debugging other vendor builds, optional runtime overrides remain available:

```sh
TARAKO_TDX_QEMU=/usr/bin/qemu-system-x86_64 \
TARAKO_TDX_FIRMWARE=/absolute/path/to/working/OVMF.fd \
nix run -L .#tdx-quote-benchmark-driver
```

These overrides affect only the TDX attester, work with all TDX drivers, and do
not require an impure Nix evaluation. Without them, the packaged QEMU and TDVF
remain the defaults. Use absolute paths: the test driver changes the working
directory for each VM. The full three-node attestation test requires VDE support
in any overridden QEMU (check its `-netdev help` output); the packaged build
includes VDE.
Benchmark mode disables the test VLANs and does not require VDE; TDX quoting
still uses the host QGS over vsock. The TDX attester uses direct kernel boot
and an EROFS Nix store block image, generated at startup, instead of virtiofs.
TDX's required `iommu_platform` setting is incompatible with this virtiofs device.
The attester is explicitly headless (`-nodefaults -vga none`), with the serial
console preferred; hiding the display with `-nographic` alone leaves a VGA device
whose emulation can trigger forbidden register accesses on this TDX stack.
Host shared folders are disabled for the TDX attester, so shared-folder-based
test-driver copy helpers are unavailable; use `copy_from_host_via_shell` for
host-to-guest transfers. The existing tests do not use shared-folder copy helpers.

### Automated quote benchmark on TDX

Build the benchmark driver, copy the result to the TDX host if necessary, and run it outside the Nix build sandbox:

```sh
nix run -L .#tdx-quote-benchmark-driver
```

This automatically builds the pinned QEMU, firmware, and guest. No
`TARAKO_TDX_QEMU` or `TARAKO_TDX_FIRMWARE` overrides are needed. To build without
running, use `nix build .#tdx-quote-benchmark-driver` and copy its closure to the
TDX host.

The benchmark boots the TDX attester and performs two warmups and twenty measured runs of each operation. Every invocation, including warmups, uses a fresh random 32-byte nonce for TDX, Tarako/TQ, and TPM. The host quote-generation service must be available on vsock CID 2, port 4050. Every TDX quote must pass the offline cryptographic and nonce-binding checks described below before its timing is accepted.

TDX CPUs cannot be reset by this QEMU stack. After enabling fs-verity, the TDX
tests power off the attester and launch a new QEMU process with the same disk
rather than requesting an in-guest reboot. This also generates a fresh Tarako key.

The non-TDX variant remains available as `nix build .#checks.x86_64-linux.quote-benchmark`; it skips only the TDX quote.

### Interactive quote timing

Build and launch the interactive TDX test driver:

```sh
nix build .#tdx-test-driver-interactive
./result/bin/nixos-test-driver
```

At the Python prompt, run the test setup and enter the attester shell:

```py
>>> test_script()
>>> attester.shell_interact()
```

The setup leaves the fs-verity-protected Tarako application at `/mnt/tarako-app`. The VM includes `tdx-attest`, `tpm-quote`, `tarako-quote`, `tpm2-tools`, and `hyperfine`. Use the same hexadecimal nonce for each mechanism:

```sh
nonce=$(openssl rand -hex 32)

tdx-attest report "$nonce"
tdx-attest quote "$nonce"
tpm-quote "$nonce"
tarako-quote "$nonce"
```

If the nonce is omitted, each script generates and prints a random 32-byte nonce. `tdx-attest` accepts nonces up to 64 bytes, `tpm-quote` accepts up to 64 bytes, and `tarako-quote` accepts up to 128 bytes.

The commands print the measured operation latency and save their outputs under `/tmp`. The first `tpm-quote` invocation creates an endorsement key and attestation key before starting its quote timer; later invocations reuse that key. `tarako-quote` creates a verity-enabled ext4 image when needed, installs `tarako-app` at `/mnt/tarako-app`, and enables fs-verity before starting its timer. It reports both the signing ioctl latency and the complete request duration. The complete duration includes process startup, output formatting, and the hello and public-key ioctls.

The dedicated benchmark commands use each tool's internal operation timer, excluding Python and shell startup. By default they perform one warmup and ten measured runs and display mean, standard deviation, median, and range:

```sh
bench-tdx-quote
bench-tpm-quote
bench-tarako-quote

# Benchmark all three, each invocation using a fresh nonce:
quote-bench all --warmup 2 --runs 20
```

Benchmark commands always generate a fresh random 32-byte nonce per invocation, including warmups, and no longer accept a fixed nonce argument. Single-operation commands still accept explicit nonces. Options accepted by every benchmark command are `--warmup N` and `--runs N`.

### TDX quote verification

`tdx-attest quote` verifies every returned quote with the pinned `go-tdx-guest` verifier (`tdx-verify`). The default offline checks verify the quote signature, QE report signature, attestation-key binding, PCK certificate chain against the verifier's embedded Intel root, and exact 64-byte REPORTDATA (the supplied nonce padded with zeros). Verification runs **after** the generation timer stops; its separate duration is not included in benchmark latency. Failed verification aborts the command and benchmark, preserving the rejected quote at `/tmp/tdquote.bin` (or `--output`) for diagnosis.

Offline verification does **not** check current QE identity, TCB status, or revocation collateral. It also does not establish an approved guest measurement/RTMR policy. For online Intel PCS collateral, QE identity, TCB, and CRL checks:

```sh
# Inside the guest, with outbound HTTPS access:
tdx-attest quote --verify-collateral
bench-tdx-quote --tdx-collateral --warmup 1 --runs 10
```

Online verification fails if collateral cannot be fetched or the platform's TCB is not accepted; there is no automatic fallback to offline mode. To verify a saved quote elsewhere, build the standalone verifier with `nix build .#tdx-verify`, copy `/tmp/tdquote.bin`, and supply the original nonce, zero-padded to 64 bytes:

```sh
report_data=$(python3 -c 'import sys; print(bytes.fromhex(sys.argv[1]).ljust(64, b"\0").hex())' "$nonce")
./result/bin/tdx-verify -in=tdquote.bin -report_data="$report_data" \
  -get_collateral=true -check_crl=true
```

A latency close to 5 ms can still reflect the guest's completion-polling floor rather than the exact host signing duration; successful cryptographic verification establishes that the returned evidence is signed and bound to the requested nonce, not that generation consumed the whole measured interval.

If an older build reports `wrote 0 bytes` / `raw quote is empty`, that is a failed quote operation, not a fast valid quote. The unpatched vendor QEMU incorrectly treated EOF as success; its 32-bit status conversion could also turn the 64-bit generic error into success. The patched QEMU uses framed QGS requests, but framing alone does not establish the cause of a host failure: some Intel QGS versions also support raw TDREPORT requests. Rebuild the test driver to use the patched **host QEMU**, and unset `TARAKO_TDX_QEMU` if it points to an unpatched binary. Verification must not be bypassed.

`GetQuote failed, status=0x8000000000000000` is a generic transport/service error, not a signature-verification result. The diagnostics patch reports which stage reached the 30-second transaction timeout, malformed response headers/QGS error codes, byte counts, and host-monotonic stage timings on failure. Set `TARAKO_TDX_QUOTE_TRACE=1` on the host to report successful requests too:

```sh
TARAKO_TDX_QUOTE_TRACE=1 nix run -L path:.#tdx-quote-benchmark-driver
sudo journalctl -u tdx-qgs --since '5 minutes ago' --no-pager
sudo journalctl -t qgsd --since '5 minutes ago' --no-pager
```

Timing fields are in microseconds: `connect`, `send`, `wait_first_byte`, `receive`, and `total`; `-1` means the stage has not completed. These are host-side transport/response timings, not a breakdown of QE cryptography. `wait_first_byte` includes QGS processing and transport. Failure summaries include byte progress; if `tx=1052/1052 rx=0`, the framed TDREPORT request was sent but no reply bytes reached QEMU. Check the QGS logs for the underlying service/quoting-library error before changing timeouts. Successful-request logging can perturb the benchmark slightly; leave tracing unset for normal runs.

## How the signing works

1. On load, the module generates an ECDSA P-256 key pair. The curve order `n` is cached.
2. When `TARAKO_SIGN_DATA` is called, the kernel:
   - Reads the calling process's fs-verity digest (SHA-256 of the file's Merkle tree root) using `get_task_exe_file`.
   - Concatenates it with 128 bytes of opaque user data from userspace.
   - Computes `SHA256(digest || user_data)` and reduces it modulo `n`.
   - Signs the result with ECDSA P-256 using kernel `ecc_*` helpers.
   - Returns the signature in big-endian wire format and the compressed SEC1 public key.

## RA-TLS compatibility

The module can sign the attestation binder from `draft-fossati-seat-early-attestation-05`. Under the documented assumptions that platform Evidence and IMA state have authenticated Tarako's public key, and that the TLS application runs with confidentiality and integrity guarantees, this signature can be the source of fresh, application-specific Evidence. The application retains its separate certificate private key and performs normal TLS signing; Tarako only signs Evidence. CMW encoding and TLS integration remain application responsibilities. See [RA_TLS.md](RA_TLS.md) for the complete assumptions, Evidence profile, and integration design.

## Key files

- `driver/src/lib.rs` — module entry point and key pair lifecycle
- `driver/src/ioctl.rs` — ioctl handlers, ECDSA signing, fs-verity helper
- `driver/src/vli.rs` — variable-length integer type (LE limbs), zeroized on drop
- `driver/src/ecc.rs` — safe wrappers around kernel ECC/crypto helpers
- `driver/src/ffi.rs` — FFI declarations for kernel C functions
- `driver/src/convert.rs` — byte-order conversion and public key format
- `driver/src/set_once.rs` — atomic once-only cell for global key storage
- `app/src/main.rs` — userspace ioctl client
- `test/benchmark.py` — automated TDX, TPM, and Tarako latency benchmark
- `test/tdx-attest.py` — TDREPORT and verified TDX quote utility
- `tdx/verify.nix` — pinned upstream TDX signature/certificate/collateral verifier
- `test/tpm-quote.py` — nonce-bound TPM quote utility
- `test/tarako-quote.py` — fs-verity setup and nonce-bound Tarako utility
- `test/root-ca.crt`, `test/verifier.crt`, `test/verifier-key.pem` — test-only Verifier PKI fixtures
- `test/quote-bench.py` — repeated benchmark runner and statistics
- `AGENTS.md` — developer reference for common commands
