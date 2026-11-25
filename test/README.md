# Tests

| Directory | Purpose |
| --- | --- |
| `tarako-basics/` | Single-VM sanity checks for module lockdown, fs-verity signing, ptrace restrictions, and key freshness. |
| `attestation/` | Three-node remote attestation integration test. |
| `tls-attestation/` | Four-node early TLS attestation test with real TARAKO quotes, IMA replay to a vTPM, and a mock platform signer. |
| `platform-evidence/` | Hardware-free checks for signed Intel TDX quotes and IMA-to-RTMR replay. |

Each suite keeps its Nix entry point and test code together. Checked-in test
inputs (certificates, keys, and evidence fixtures) live in the owning suite’s
`assets/` directory. The live TDX runners use the shared quote helpers.
[`flake.nix`](../flake.nix) composes shared NixOS modules through each test
node’s `imports` list. Suites keep their own settings in module options.

The simple-attestation test client uses its NixOS system CA bundle to validate
the result signer. This is a test trust policy, not a production recommendation.

The [live TDX runbook](../live-tdx/README.md) covers the hardware runners.
