# Tests

| Directory | Purpose |
| --- | --- |
| `attestation/` | Three-node remote attestation integration test. |
| `attestation-tdx/` | Attestation integration test on an Intel TDX host. |
| `quote-benchmark/` | Tarako and TPM quote latency benchmarks. |
| `quote-benchmark-tdx/` | Quote latency benchmarks including Intel TDX quotes. |
| `quote-tools/` | Hardware-free quote verification and nonce-freshness tests. |
| `tls-attestation/` | Four-node early TLS attestation test with real TARAKO quotes, IMA replay to a vTPM, and a mock platform signer. |
| `platform-evidence/` | Hardware-free checks for signed Intel TDX quotes and IMA-to-RTMR replay. |
| `live-tdx/` | Live TLS attestation on real Intel TDX, or an attester VM for an external client and verifier. |

Shared VM configuration and quote utilities live directly in this directory.

The [live TDX runbook](../live-tdx/README.md) covers the automated suite,
the attester-only driver, and operator-managed guests.
