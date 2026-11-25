# TARAKO

This is a codebase for a rust based linux kernel module used for remote attestation.
See also README.md

## Development
Nix build system is used for development.

Use these commands for common tasks.

```sh
nix build .#default # the TARAKO kernel module
nix build .#simple-attester # HTTP and CLI quote generation
nix flake check # build test packages and nixos tests
nix fmt # format the nix files
make -C driver # build module against running kernel (outside nix)
```

## Architecture

- **`driver/src/`**: Rust kernel module
- **`tools/`**: simple attester, TLS attester and client, and their shared `libtarako` code.
- **`test/`**: Hardware-independent checks and NixOS VM tests.
- **`real-hardware/`**: Intel TDX guest configuration, live verifier, and hardware test drivers.

Ioctls:
| Constant | Code | Direction |
|---|---|---|
| `TARAKO_HELLO` | `0x0000_5300` | none |
| `TARAKO_GET_PUBKEY` | `0x8021_5301` | read (33-byte compressed SEC1 point) |
| `TARAKO_SIGN_DATA` | `0xC101_5302` | read/write (SignDataReq: user_data+hash+sig_r+sig_s+pubkey = 257 bytes) |

The kernel computes `ECDSA-SHA256(SK, fsverity_digest || user_data)` for 128 bytes of opaque user data — signing must happen in kernel space by design.

## Non-obvious dev tools

- `nix develop --command generate-rust-analyzer > rust-project.json` - generates IDE config for the kernel module.

## Conventions

- The kernel driver uses `include!("...")` in `driver/src/lib.rs` to embed submodules. Add an `include!()` entry when adding a driver submodule.
- Use OpenSSL in `tools/` for public-key and signature DER encoding; do not write a custom parser or formatter.
- Private key lives in a `SetOnce<KeyPair>` global (`KEY_PAIR`), populated during module init.

