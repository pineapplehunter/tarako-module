# TARAKO — An application attestation mechanism for confidential VMs

Trusted Application Remote Attestation Kernel Object (TARAKO) is a Linux kernel module for measuring running applications, intended for use in confidential VMs such as those based on [Intel TDX].
This module exposes a virtual device at `/dev/tarako` that returns a signed measurement of the caller's binary when invoked.
This can be used for remote attestation.

[Intel TDX]: https://www.intel.com/content/www/us/en/developer/tools/trust-domain-extensions/overview.html

## What this solves

Confidential VMs lack an easy way to prove which application is running in userspace.
Confidential VMs are mostly used for security-sensitive applications in the cloud, where the goal is to protect the VM from attacks by the host and other VMs.
However, a critical issue is that this protection does not extend to threats originating within the VM.
Malware running inside the VM may compromise userspace.

TARAKO allows an external client to verify the integrity of a userspace application's binary through remote attestation.

It is intended to be used in combination with remote attestation of the confidential VM itself.

## Required facilities

This module requires a kernel with the following features enabled:

- [Linux IMA]
- [fs-verity]

It also requires the following module:

- `ecc`

[Linux IMA]: https://ima-doc.readthedocs.io/en/latest/ima-concepts.html
[fs-verity]: https://www.kernel.org/doc/html/latest/filesystems/fsverity.html

## How it works

When the module is loaded, it generates a fresh ECDSA key pair and exposes a virtual device at `/dev/tarako`.
The public key is recorded in the IMA log.
When an application invokes the device using the signing ioctl, the device returns the application's fs-verity digest and a signature.

The digest and signature can be passed to the client, which can independently check the digest and verify the signature.

## Architecture

This documentation follows the Background-Check Model in [RATS].

[RATS]: https://www.rfc-editor.org/rfc/rfc9334.html

The client requests evidence from the attester.

We assume that the client has already remotely attested the confidential VM and checked the IMA log, which includes TARAKO's public key.

```mermaid
sequenceDiagram
    participant C as Client/Relying Party
    participant A as Attester
    participant V as Verifier

    C->>V: Request challenge
    V-->>C: Nonce + Challenge ID
    C->>A: Request + Nonce
    A-->>C: Tarako Quote
    C->>V: Tarako Quote + Expected Request/Nonce
    V-->>C: Signed Attestation Result + Certificate
```

**Attester** (runs the kernel module):
1. Loads the `tarako` module — an ECDSA P-256 key pair is generated in kernel space.
2. The private key never leaves the kernel and is zeroized on module unload.
3. The fs-verity-protected Go Attester webserver accepts a request from the Client and a nonce from the Verifier, calls `TARAKO_SIGN_DATA` directly, and returns Tarako Quote Evidence to the Client.

## Build & Test

```sh
# Kernel module
nix build .#default

# Go attester (HTTP server and command-line quote generation)
nix build .#attester

# NixOS VM attestation test
nix flake check

# Build (but do not run) the TDX test driver and its TDVF firmware for an Intel TDX-capable host
nix build .#tdx-test-driver
```

The Go attester runs an HTTP server by default. Its `tarako-attester quote [hex-user-data]` command generates a quote directly; without user data, it generates a fresh random 32-byte nonce. Signing requires running an fs-verity-protected copy of the binary.

### Running the test on TDX

Build the driver and firmware without running the VM in the Nix build sandbox, then execute the driver on the TDX host:

```sh
nix build .#tdx-test-driver
./result/bin/nixos-test-driver
```

The TDX attester defaults to pinned vendor QEMU and source-built TDVF for the
experiment's `6.8.0-1028-intel` host kernel.

> **Intended host environment:** The added `tdx-qemu` package targets Ubuntu
> 24.04.4 LTS (Noble), x86_64, with the vendor Intel kernel shown below. It is
> not intended as a general-purpose QEMU replacement for other TDX host stacks.
> The hostname has been anonymized.

```text
Linux <tdx-host> 6.8.0-1028-intel #35-Ubuntu SMP PREEMPT_DYNAMIC Fri May 23 17:34:54 UTC 2025 x86_64 x86_64 x86_64 GNU/Linux
No LSB modules are available.
Distributor ID: Ubuntu
Description:    Ubuntu 24.04.4 LTS
Release:        24.04
Codename:       noble
```

## How the signing works

1. On load, the module generates an ECDSA P-256 key pair. The curve order `n` is cached.
2. When `TARAKO_SIGN_DATA` is called, the kernel:
   - Reads the calling process's fs-verity digest (SHA-256 of the file's Merkle tree root) using `get_task_exe_file`.
   - Concatenates it with 128 bytes of opaque user data from userspace.
   - Computes `SHA256(digest || user_data)` and reduces it modulo `n`.
   - Signs the result with ECDSA P-256 using kernel `ecc_*` helpers.
   - Returns the signature in big-endian wire format and the compressed SEC1 public key.
