# tarako — Remote Attestation with an ECDSA P-256 Kernel Module

A Linux kernel module that generates an ECDSA P-256 key pair on load, exposes it via `/dev/tarako`, and signs a measurement of the calling process (its fs-verity digest) bound to 1024 bits of opaque user data. A challenge nonce can be placed in that data to provide freshness.

## Architecture

```
┌─────────────┐     TCP (nonce)     ┌──────────────┐
│  Verifier   │ ──────────────────► │  Attester    │
│ (challenger)│                     │ (kernel mod) │
│             │ ◄────────────────── │              │
│             │  sig + pubkey       │  /dev/tarako │
└─────────────┘                     └──────────────┘
```

**Attester** (runs the kernel module):
1. Loads `tarako` module — ECDSA P-256 key pair is generated in kernel space.
2. The private key never leaves the kernel and is zeroized on module unload.
3. A TCP responder accepts nonces from the network, calls `TARAKO_SIGN_DATA`, and returns the signature.

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
| `test/attestation.py` | Two-machine NixOS VM integration test |

## Build & Test

```sh
# Kernel module
nix build .#default

# Userspace app
nix build .#app

# NixOS VM attestation test
nix build .#checks.x86_64-linux.attestation

# Build (but do not run) the TDX test driver and its TDVF firmware
nix build .#tdx-test-driver

# Build only the TDX-enabled TDVF firmware
nix build .#tdx-firmware

# Dev shell with Rust + rust-src
nix develop
```

The integration test creates two VMs:
- **attester**: loads the module, creates a verity-protected ext4 image, runs `tarako-app` from it, and exposes a TCP responder.
- **verifier**: generates a random nonce, sends it to the attester over TCP, receives the signature, and verifies it with OpenSSL. The app zero-pads the nonce to the 128-byte ioctl input.

### Running the test on TDX

Build the driver and firmware without running the VM in the Nix build sandbox, then execute the driver on the TDX host:

```sh
nix build .#tdx-test-driver
./result/bin/nixos-test-driver
```

QEMU is supplied by the locked nixpkgs revision (currently QEMU 11.0.2 with TDX and VDE support). The firmware is built automatically from nixpkgs' `OVMF-inteltdx` package using edk2's `OvmfPkg/IntelTdx/IntelTdxX64.dsc` Config-B target. It can also be built separately with `nix build .#tdx-firmware`. The host must have KVM access and a quote-generation service listening on vsock CID 2, port 4050. The attester uses QEMU direct kernel boot through TDVF, 4 CPUs, 4 GiB RAM, and a CRB vTPM backed by `swtpm`. Its TPM state is kept in `tarako-attestation-tdx-attester-swtpm` by default; set `NIX_SWTPM_DIR` to choose another location. Extra test-driver options, such as `--keep-machine-state`, can be passed normally.

### Automated quote benchmark on TDX

Build the benchmark driver, copy the result to the TDX host if necessary, and run it outside the Nix build sandbox:

```sh
nix build .#tdx-quote-benchmark-driver
./result/bin/nixos-test-driver
```

The benchmark boots the TDX attester, generates one random 32-byte nonce, and uses it for TDX, Tarako, and TPM measurements. It performs two warmups and twenty measured runs of each operation. The host quote-generation service must be available on vsock CID 2, port 4050.

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
bench-tdx-quote "$nonce"
bench-tpm-quote "$nonce"
bench-tarako-quote "$nonce"

# Benchmark all three with the same nonce and custom run counts:
quote-bench all "$nonce" --warmup 2 --runs 20
```

The nonce is optional and defaults to a random 32-byte value. Options accepted by every benchmark command are `--warmup N` and `--runs N`.

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
- `test/tdx-attest.py` — TDREPORT and TDX quote utility
- `test/tpm-quote.py` — nonce-bound TPM quote utility
- `test/tarako-quote.py` — fs-verity setup and nonce-bound Tarako utility
- `test/quote-bench.py` — repeated benchmark runner and statistics
- `AGENTS.md` — developer reference for common commands
