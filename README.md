# signer — Remote Attestation with an ECDSA P-256 Kernel Module

A Linux kernel module that generates an ECDSA P-256 key pair on load, exposes it via `/dev/signer`, and signs a measurement of the calling process (its fs-verity digest) bound to a challenge nonce. This enables **remote attestation**: a remote verifier sends a random nonce, and the kernel returns a signature that proves the exact code is running unmodified.

## Architecture

```
┌─────────────┐     TCP (nonce)     ┌──────────────┐
│  Verifier   │ ──────────────────► │  Attester    │
│ (challenger)│                     │ (kernel mod) │
│             │ ◄────────────────── │              │
│             │  sig + pubkey       │  /dev/signer │
└─────────────┘                     └──────────────┘
```

**Attester** (runs the kernel module):
1. Loads `signer` module — ECDSA P-256 key pair is generated in kernel space.
2. The private key never leaves the kernel and is zeroized on module unload.
3. A TCP responder accepts nonces from the network, calls `SIGNER_SIGN_DATA`, and returns the signature.

**Kernel module (`driver/src/`)** — three ioctls:

| Ioctl | Code | Description |
|-------|------|-------------|
| `SIGNER_HELLO` | `0x0000_5300` | Sanity check |
| `SIGNER_GET_PUBKEY` | `0x8041_5301` | Return the raw ECDSA P-256 public key (65 bytes) |
| `SIGNER_SIGN_DATA` | `0xC0C1_5302` | Sign `SHA256(fsverity_digest \|\| nonce)` with ECDSA P-256 |

All ioctls are guarded: only processes whose executable is protected by **fs-verity** may call them. This ensures the measured code path is authentic.

## Components

| Path | Role |
|------|------|
| `driver/src/` | Kernel module (Rust, `rust/kernel` framework) — multi-file layout |
| `app/src/main.rs` | Userspace `signer-app` — opens `/dev/signer` and issues ioctls |
| `test/attestation.py` | Two-machine NixOS VM integration test |
| `test/feature-lacking-kernel.py` | Verifies module loads on kernels without fs-verity |
| `modules/` | NixOS modules enabling `FS_VERITY` and `IMA` kernel config |

## Build & Test

```sh
# Kernel module
nix build .#default

# Userspace app
nix build .#app

# NixOS VM attestation test
nix build .#checks.x86_64-linux.attestation

# Feature-lacking kernel test
nix build .#checks.x86_64-linux.feature-lacking-kernel

# Dev shell with Rust + rust-src
nix develop
```

The integration test creates two VMs:
- **attester**: loads the module, creates a verity-protected ext4 image, runs `signer-app` from it, and exposes a TCP responder.
- **verifier**: generates a random nonce, sends it to the attester over TCP, receives the signature, and the test driver verifies it cryptographically with the `cryptography` Python library.

## How the signing works

1. On load, the module generates an ECDSA P-256 key pair. The curve order `n` is cached.
2. When `SIGNER_SIGN_DATA` is called, the kernel:
   - Reads the calling process's fs-verity digest (SHA-256 of the file's Merkle tree root) using `get_task_exe_file`.
   - Concatenates it with the 32-byte nonce from userspace.
   - Computes `SHA256(digest || nonce)` and reduces it modulo `n`.
   - Signs the result with ECDSA P-256 using kernel `ecc_*` helpers.
   - Returns the signature in big-endian wire format and the uncompressed public key.

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
