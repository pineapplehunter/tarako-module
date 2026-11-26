# Tests

| Directory | Purpose |
| --- | --- |
| `basics/` | Single-VM sanity checks for module lockdown, fs-verity signing, ptrace restrictions, and key freshness. |
| `quote-attestation/` | Three-node remote attestation integration test using the quote API. |
| `tls-attestation/` | Four-node early TLS attestation test with real TARAKO quotes, IMA replay to a vTPM, and a mock platform signer. |
| `platform-evidence/` | Hardware-free checks for signed Intel TDX quotes and REPORTDATA binding. |

Each suite keeps its Nix entry point and test code together. Checked-in test
inputs (certificates, keys, and evidence fixtures) live in the owning suite’s
`assets/` directory. Offline TDX quote tooling lives in `tools/tdx-verify/`.
[`flake.nix`](../flake.nix) composes shared NixOS modules through each test
node’s `imports` list. Suites keep their own settings in module options.

The quote-attestation test client uses its NixOS system CA bundle to validate
the result signer. This is a test trust policy, not a production recommendation.
For the mock TLS test, the harness supplies the attester's vTPM PCR snapshot
and IMA log. The verifier VM replays the log to extract the TARAKO key during
setup; the mock verifier does not replay IMA on each request.

The [real-hardware runbook](../real-hardware/README.md) covers TDX tests,
which live separately from these checks.
