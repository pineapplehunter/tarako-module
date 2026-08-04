# AGENTS.md — rust-kernel-module

## Build & Test

```sh
nix build .#default                                     # kernel module
nix build .#app                                         # userspace app
nix build .#checks.x86_64-linux.attestation             # two-machine NixOS VM test
nix build .#kernel-src                                  # minimal ~4.7 MB kernel Rust source tree
nix develop                                             # dev shell (rust-src, rust-analyzer, python3 w/ cryptography)
nix fmt                                                 # format using nixfmt-tree
make -C driver                                          # build module against running kernel (outside nix)
```

Commands run in `nix develop` shell unless noted. The attestation test verifies ECDSA signatures via `openssl dgst -sha256 -verify`.

## Architecture

- **`driver/src/`**: Rust kernel module (`miscdevice`, `/dev/tarako`). Sub-files are `include!()`'d from `lib.rs` (not separate compiled units — Kbuild only lists `src/lib.o`). Generates ECDSA P-256 key pair on load, zeroizes private key on unload. The signing ioctl is guarded: IMA must measure the generated key and the caller's exe must be fs-verity protected.
- **`app/`**: standalone Cargo binary with `der` and `libc` crates. Uses hardcoded ioctl numbers matching the kernel module. Accepts up to 1024 bits of hex user data on the CLI; shorter values such as a nonce are zero-padded.
- **`test/`**: NixOS VM test definition (`attestation.nix`/`.py`), plus TCP responder (`responder.py`, Flask) and client (`client.py`, requests).

Ioctls:
| Constant | Code | Direction |
|---|---|---|
| `TARAKO_HELLO` | `0x0000_5300` | none |
| `TARAKO_GET_PUBKEY` | `0x8021_5301` | read (33-byte compressed SEC1 point) |
| `TARAKO_SIGN_DATA` | `0xC101_5302` | read/write (SignDataReq: user_data+hash+sig_r+sig_s+pubkey = 257 bytes) |

The kernel computes `ECDSA-SHA256(SK, fsverity_digest || user_data)` for 128 bytes of opaque user data — signing must happen in kernel space by design.

## Non-obvious dev tools

- `python3 generate_rust_analyzer.py > rust-project.json` — generates IDE config for the kernel module. **Must run from `nix develop` shell** (needs `RUST_KERNEL_SRCTREE`, `RUST_KERNEL_OBJTREE`, `RUST_SYSROOT`, `RUST_LIB_SRC`).
- `python3 analyze_pubkey.py` — debug tool that tests byte-order permutations of kernel ECC limb output against the P-256 curve.

## Conventions

- The kernel driver uses `include!("...")` at `lib.rs:19-33` to embed sub-modules (not Cargo or `mod` in separate files). Do not add files without adding an `include!()` line in `lib.rs`.
- `rust-project.json` is generated, not committed (in `.gitignore`).
- `result*` symlinks from `nix build` are in `.gitignore`.
- DER encoding for public key and signature is done in userspace (`app/`) using the `der` crate — do NOT roll your own DER parser/formatter.
- Private key lives in a `SetOnce<KeyPair>` global (`KEY_PAIR`), populated during module init.

## References

Nixpkgs source: `/home/takata/tmp/nixpkgs.git/master`
Linux source: `/home/takata/tmp/linux`
