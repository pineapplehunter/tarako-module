# TARAKO early TLS attestation PoC

`tarako-tls-attester` terminates TLS 1.3, calls `/dev/tarako` from the
fs-verity-protected executable, and serves one HTTP/2 `GET /` per connection.
Both endpoints require ALPN `h2`; there is no HTTP/1 fallback.
`tarako-tls-client` requires normal HTTPS identity verification **and** signed
appraisal of the evidence before it sends the request. On success it prints
the response body, `Tarako OK`. The [client source](../tls-client/)
is separate from the server. The server links statically so its fs-verity
measurement covers the evidence code and dependencies. The client uses the
same [libtarako](../libtarako/) code but links its system libraries dynamically.
The request code uses nghttp2 and runs only after the handshake.

The experimental profile follows IETF `draft-fossati-seat-early-attestation-09`
for the ServerHello transcript checkpoint (including HelloRetryRequest), the
binder over the leaf's DER SubjectPublicKeyInfo, extension placement, and a
single RFC 9999 JSON Record CMW. The extension uses private-use codepoint
`0xffa5`, one server-evidence scheme, and `TLS_AES_128_GCM_SHA256`. The demo
requires an offer and does not allow resumption or early data. It uses existing
TLS alerts for the experimental profile. DTLS, client attestation, EKU
reattestation and attesting TLS private-key provenance are out of scope.

## Four-VM test trust model

- **HTTPS CA:** signs the HTTPS server leaf. The client independently checks
  the web trust chain, hostname, and normal TLS proof of possession.
- **Mock platform CA:** public trust anchor provisioned to all four VMs. The
  mock quote signer carries a signing leaf issued by this CA. The verifier
  validates that leaf against the platform CA, then checks the report signature.
  The platform CA is never used for HTTPS authentication.
- **Verifier:** has a separate result-signing key pinned by the client. Its
  short-lived verdict covers the binder, the HTTPS leaf-key hash, and the exact
  CMW bytes. The harness replays the boot's SHA-256 IMA log against vTPM PCR 10
  and checks that the matched prefix commits to the TARAKO key. It then
  provisions that key and the approved fs-verity digest as test policy. The
  mock TLS verifier does not appraise IMA itself.

The `tls-mock-services` Python package provides `tarako-mock-platform-signer`
and `tarako-tls-verifier`. The test starts them and the attester through declared
systemd units after provisioning the keys and policy.

The mock signer is contacted via private HTTP/TCP. Its signed `REPORTDATA`
commits to the signed TARAKO message hash; its simulated platform measurement
is the provisioned TARAKO public key. It does not emulate Intel hardware or
prove that the TLS private key is protected by the guest. Real signed TDX
fixture verification and IMA-to-RTMR replay are separate checks; the IMA logs
are synthetic and do not match the upstream signed quote.

For real quote generation and cross-machine appraisal, see the separate
[split-host live TDX suite](../../real-hardware/README.md).

## Build and test

The `tls-attester` package contains the mock, fault-test, and live TDX servers.
The `tls-client` package contains the mock and live TDX clients.
`libtarako` installs the static archive, headers, and `pkg-config` metadata.
Each tool uses CMake.

```sh
nix build --no-link .#tls-attester .#tls-client .#libtarako
nix build --no-link .#checks.x86_64-linux.platform-evidence
nix build --no-link .#checks.x86_64-linux.tls-attestation
```

The standalone VM suite under `test/tls-attestation/` runs real TARAKO signing
and checks the eight combinations of TLS authentication, TARAKO quote, and mock
platform validity. Only the all-valid combination reaches the HTTP handler.
