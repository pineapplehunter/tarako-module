# signer — Remote Attestation with an ECDSA P-256 Kernel Module

A Linux kernel module that generates an ECDSA P-256 key pair on load, exposes it via `/dev/signer`, and signs a measurement of the calling process (its fs-verity digest) bound to a challenge nonce. This enables **remote attestation**: a remote verifier sends a random nonce, and the kernel returns a signature that proves the exact code is running unmodified.

## Architecture

```
┌─────────────┐     TCP (nonce)     ┌──────────────┐
│  Verifier   │ ──────────────────► │  Attester    │
│ (challenger)│                     │ (kernel mod) │
│             │ ◄────────────────── │              │
│             │  cert + sig + pubkey│  /dev/signer │
└─────────────┘                     └──────────────┘
```

**Attester** (runs the kernel module):
1. Loads `ecc` + `signer` modules — key pair is generated and a self-signed X.509 certificate is built in kernel space.
2. The private key never leaves the kernel.
3. A TCP responder accepts nonces from the network, calls `SIGNER_SIGN_DATA`, and returns the signature.

**Kernel module (`src/lib.rs`)** — three ioctls:

| Ioctl | Code | Description |
|-------|------|-------------|
| `SIGNER_HELLO` | `0x0000_5300` | Sanity check |
| `SIGNER_GET_CERT` | `0x8800_5301` | Return the self-signed certificate |
| `SIGNER_SIGN_DATA` | `0xC0C1_5302` | Sign `SHA256(fsverity_digest \|\| nonce)` with ECDSA P-256 |

All ioctls are guarded: only processes whose executable is protected by **fs-verity** may call them. This ensures the measured code path is authentic.

## Components

| Path | Role |
|------|------|
| `src/lib.rs` | Kernel module (Rust, `rust/kernel` framework) |
| `app/src/main.rs` | Userspace `signer-app` — opens `/dev/signer` and issues ioctls |
| `test/test.py` | Two-machine NixOS VM integration test |
| `test.nix` | NixOS test definition |
| `modules/` | NixOS modules enabling `FS_VERITY` and `IMA` kernel config |

## Build & Test

```sh
# Kernel module only
nix build .#kernel-module

# Userspace app
nix build .#default

# Full NixOS VM integration test (remote attestation)
nix build .#checks.x86_64-linux.nixos-test

# Dev shell with Rust + rust-src
nix develop
```

The integration test creates two VMs:
- **attester**: loads the module, creates a verity-protected ext4 image, runs `signer-app` from it, and exposes a TCP responder.
- **verifier**: generates a random nonce, sends it to the attester over TCP, receives the signature, and the test driver verifies it cryptographically with the `cryptography` Python library.

## How the signing works

1. On load, the module generates an ECDSA P-256 key pair and a self-signed X.509 certificate.
2. When `SIGNER_SIGN_DATA` is called, the kernel:
   - Reads the calling process's fs-verity digest (SHA-256 of the file's Merkle tree root).
   - Concatenates it with the 32-byte nonce from userspace.
   - Computes `SHA256(digest || nonce)`.
   - Signs the result with ECDSA P-256 using `ecc_gen_privkey`, `ecc_make_pub_key`, `vli_mod_inv`, and `vli_mod_mult_slow`.

The internal limb format of the kernel's ECC helpers is LE-limb (native u64 on x86_64), but `ecc_make_pub_key` applies `ecc_swap_digits` to its output, producing a big-endian memory image. The module handles vli conversion via `unswap_digits`. Byte-order conversion for the ioctl response (`sig_r`/`sig_s`) is done in **userspace** — the kernel returns raw LE-limb bytes and the app converts to big-endian hex for display.

## Key files

- `src/lib.rs` — kernel module (single file, ~850 lines)
- `app/src/main.rs` — userspace ioctl client
- `test/test.py` — NixOS test script
- `AGENTS.md` — developer reference for common commands
