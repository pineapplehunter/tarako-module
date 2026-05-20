# AGENTS.md — rust-kernel-module

## Build

```sh
nix build .#kernel-module          # kernel module only
nix build .#default                # userspace app
nix build .#checks.x86_64-linux.nixos-test  # NixOS VM integration test
nix develop                         # dev shell with Rust + rust-src
make                                # local kernel module build (uses running kernel)
```

## Test

- `nix build .#checks.x86_64-linux.nixos-test` — builds kernel, loads `ecc` + `signer`, mounts fs-verity ext4, runs `signer-app`, compares kernel SHA256 against Python `hashlib.sha256`
- `test/test.py` is the test script; `test.nix` wraps it in `testers.runNixOSTest`
- Host Python needs `cryptography` for key generation — added via `extraPythonPackages` in `test.nix` (with `skipTypeCheck = true`)

## Architecture

- **`src/lib.rs`**: single-file kernel module. Creates `/dev/signer` miscdevice. On load, generates ECDSA P-256 key pair. Let the generated private key be SK and public key PK. Ioctls:
  - `SIGNER_HELLO` (0x0000_5300) — sanity check
  - `SIGNER_GET_PUBKEY` (0x8041_5301) — return PK (raw 65-byte uncompressed point).
  - `SIGNER_SIGN_DATA` (0xC0C1_5302) — reads calling process's exe_file fs-verity digest as FVHASH, computes `sign(SK,SHA256(FVHASH || nonce))` where nonce is a value provided in ioctl from userspace. The signing process MUST be done in kernel space, since the kernel is the only entity trusted in this security model.
- **`app/`**: userspace Cargo binary (`signer-app`), uses `libc::ioctl` with hardcoded ioctl numbers
- **`modules/`**: NixOS modules enabling `FS_VERITY` and `IMA` kernel config

# References

Nixpkgs source code: `/home/takata/tmp/nixpkgs.git/master`
Linux source code: `/home/takata/tmp/linux`
