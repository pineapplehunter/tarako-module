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
- **`attester/`**: single-binary Go attester. By default, its HTTP server receives the request and Verifier nonce from the Client/Relying Party and invokes the Tarako ioctls directly, so its own fs-verity digest is signed. `tarako-attester quote [hex-user-data]` generates a quote on the CLI and reports signing-ioctl latency; user data is limited to 128 bytes and zero-padded. Omitting user data generates a fresh random 32-byte nonce.
- **`test/`**: Shared attester, TDX, and quote-tool configuration. Separate test definitions live in `attestation/`, `attestation-tdx/`, `quote-benchmark/`, and `quote-benchmark-tdx/`; hardware-free regression tests live in `quote-tools/`. `attestation/` contains the three-node Background-Check test, Client/Relying Party (`client.py`), stateful Verifier (`verifier.py`), and test PKI fixtures. The boot-enabled Verifier signs results with its test leaf certificate key, and the Client validates them against `root-ca.crt`. The disabled-at-boot Attester service copies and enables fs-verity on the Go binary in its service script before executing it.

Ioctls:
| Constant | Code | Direction |
|---|---|---|
| `TARAKO_HELLO` | `0x0000_5300` | none |
| `TARAKO_GET_PUBKEY` | `0x8021_5301` | read (33-byte compressed SEC1 point) |
| `TARAKO_SIGN_DATA` | `0xC101_5302` | read/write (SignDataReq: user_data+hash+sig_r+sig_s+pubkey = 257 bytes) |

The kernel computes `ECDSA-SHA256(SK, fsverity_digest || user_data)` for 128 bytes of opaque user data — signing must happen in kernel space by design.

## Non-obvious dev tools

- `python3 dev/generate_rust_analyzer.py > rust-project.json` — generates IDE config for the kernel module. **Must run from `nix develop` shell** (needs `RUST_KERNEL_SRCTREE`, `RUST_KERNEL_OBJTREE`, `RUST_SYSROOT`, `RUST_LIB_SRC`).

## Conventions

- The kernel driver uses `include!("...")` at `lib.rs:19-33` to embed sub-modules (not Cargo or `mod` in separate files). Do not add files without adding an `include!()` line in `lib.rs`.
- `rust-project.json` is generated, not committed (in `.gitignore`).
- `result*` symlinks from `nix build` are in `.gitignore`.
- DER encoding for signatures is done in userspace (`attester/`) using Go's `encoding/asn1` — do NOT roll your own DER parser/formatter.
- Private key lives in a `SetOnce<KeyPair>` global (`KEY_PAIR`), populated during module init.

## References

Nixpkgs source: `/home/takata/tmp/nixpkgs.git/master`
Linux source: `/home/takata/tmp/linux`
