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
| `TARAKO_GET_PUBKEY` | `0x8041_5301` | Return the raw ECDSA P-256 public key (65 bytes) |
| `TARAKO_SIGN_DATA` | `0xC121_5302` | Sign `SHA256(fsverity_digest \|\| user_data)` with ECDSA P-256; `user_data` is 128 bytes |

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

# Build (but do not run) the TDX test driver
nix build .#tdx-test-driver

# Dev shell with Rust + rust-src
nix develop
```

The integration test creates two VMs:
- **attester**: loads the module, creates a verity-protected ext4 image, runs `tarako-app` from it, and exposes a TCP responder.
- **verifier**: generates a random nonce, sends it to the attester over TCP, receives the signature, and verifies it with OpenSSL. The app zero-pads the nonce to the 128-byte ioctl input.

### Running the test on TDX

Build the driver without running the VM in the Nix build sandbox, then execute it on the TDX host:

```sh
nix build .#tdx-test-driver
TDX_QEMU=/home/takata/tdx/qemu/build/qemu-system-x86_64 \
  ./result/bin/nixos-test-driver
```

The host must have KVM access and a quote-generation service listening on vsock CID 2, port 4050. The attester is direct-booted with the kernel and initramfs (no OVMF), uses 4 CPUs and 4 GiB RAM, and gets a CRB vTPM backed by `swtpm`. Its TPM state is kept in `tarako-attestation-tdx-attester-swtpm` by default; set `NIX_SWTPM_DIR` to choose another location. Extra test-driver options, such as `--keep-machine-state`, can be passed normally.

## How the signing works

1. On load, the module generates an ECDSA P-256 key pair. The curve order `n` is cached.
2. When `TARAKO_SIGN_DATA` is called, the kernel:
   - Reads the calling process's fs-verity digest (SHA-256 of the file's Merkle tree root) using `get_task_exe_file`.
   - Concatenates it with 128 bytes of opaque user data from userspace.
   - Computes `SHA256(digest || user_data)` and reduces it modulo `n`.
   - Signs the result with ECDSA P-256 using kernel `ecc_*` helpers.
   - Returns the signature in big-endian wire format and the uncompressed public key.

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
- `AGENTS.md` — developer reference for common commands
