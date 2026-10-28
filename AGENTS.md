# TARAKO

This is a codebase for a rust based linux kernel module used for remote attestation.
See also README.md

## Development
Nix build system is used for development.

User these commands for common tasks.

```sh
nix build .#default # the TARAKO kernel module
nix build .#attester # Go Attester webserver
nix flake check # build test packages and nixos tests
nix fmt # format the nix files
make -C driver # build module against running kernel (outside nix)
```

## Architecture

- **`driver/src/`**: Rust kernel module
- **`attester/`**: single-binary Go webserver to test attestation.
- **`test/`**: NixOS test definitions and driver definitions to run in a TDX machine.

Ioctls:
| Constant | Code | Direction |
|---|---|---|
| `TARAKO_HELLO` | `0x0000_5300` | none |
| `TARAKO_GET_PUBKEY` | `0x8021_5301` | read (33-byte compressed SEC1 point) |
| `TARAKO_SIGN_DATA` | `0xC101_5302` | read/write (SignDataReq: user_data+hash+sig_r+sig_s+pubkey = 257 bytes) |

The kernel computes `ECDSA-SHA256(SK, fsverity_digest || user_data)` for 128 bytes of opaque user data — signing must happen in kernel space by design.

## Non-obvious dev tools

- `python3 dev/generate_rust_analyzer.py > rust-project.json` - generates IDE config for the kernel module.

## Conventions

- The kernel driver uses `include!("...")` at `lib.rs:19-33` to embed sub-modules (not Cargo or `mod` in separate files). Do not add files without adding an `include!()` line in `lib.rs`.
- DER encoding for public key and signature is done in userspace (`app/`) using the `der` crate — do NOT roll your own DER parser/formatter.
- Private key lives in a `SetOnce<KeyPair>` global (`KEY_PAIR`), populated during module init.

