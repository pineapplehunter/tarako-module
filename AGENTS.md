# AGENTS.md — rust-kernel-module

## Build

```sh
nix build .#default                # kernel module
nix build .#app                    # userspace app
nix build .#checks.x86_64-linux.attestation  # attestation test
nix build .#checks.x86_64-linux.feature-lacking-kernel  # feature-lacking kernel test
nix develop                         # dev shell with Rust + rust-src
make -C driver                      # local kernel module build (uses running kernel)
```

## Test

- `nix build .#checks.x86_64-linux.attestation` — two-machine attestation test: loads signer module, verifies ECDSA signature via `openssl`
- `nix build .#checks.x86_64-linux.feature-lacking-kernel` — verifies module symbol dependencies are present in .ko

## Architecture

- **`driver/src/`**: kernel module (multi-file Rust). Creates `/dev/signer` miscdevice. On load, generates ECDSA P-256 key pair. Let the generated private key be SK and public key PK. Ioctls:
  - `SIGNER_HELLO` (0x0000_5300) — sanity check
  - `SIGNER_GET_PUBKEY` (0x8041_5301) — return PK (raw 65-byte uncompressed point).
  - `SIGNER_SIGN_DATA` (0xC0C1_5302) — reads calling process's exe_file fs-verity digest as FVHASH, computes `sign(SK,SHA256(FVHASH || nonce))` where nonce is a value provided in ioctl from userspace. The signing process MUST be done in kernel space, since the kernel is the only entity trusted in this security model.
- **`app/`**: userspace Cargo binary (`signer-app`), uses `libc::ioctl` with hardcoded ioctl numbers
- **`modules/`**: NixOS modules enabling `FS_VERITY` and `IMA` kernel config
- **`test/`**: NixOS VM test definitions and scripts (`attestation.*`, `feature-lacking-kernel.*`)

## About Cryptography
- Use der format in most cases
- Use ECC in most cases
- MUST use specialized library to parse or format DER data. DO NOT role your own formatter or parser.

# References

Nixpkgs source code: `/home/takata/tmp/nixpkgs.git/master`
Linux source code: `/home/takata/tmp/linux`
