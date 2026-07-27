# SEAT early-attestation compatibility assessment

This assessment uses
[`draft-fossati-seat-early-attestation-05`](https://datatracker.ietf.org/doc/html/draft-fossati-seat-early-attestation-05).
It is an active Internet-Draft rather than an RFC. Its TLS extension and alert
code points are still unassigned.

## Deployment assumptions

This assessment assumes that:

- the application executes inside an attested environment that guarantees its
  confidentiality and integrity;
- the application owns and protects the X.509 certificate private key (the
  TIK) and performs the normal TLS `CertificateVerify` signature;
- Tarako is used only as an Evidence signer, not as the TLS certificate signer;
- fresh platform Evidence and the IMA log are appraised before the TLS
  connection;
- that appraisal establishes a trusted association between the platform state,
  the approved Tarako module/workload, and the Tarako public key;
- Tarako is loaded exactly once, so its generated Evidence-signing key remains
  stable for the deployment lifetime; and
- TLS negotiation, binder derivation, CMW encoding, certificate-extension
  handling, and relying-party integration are implemented by application-side
  TLS patches and are out of scope for the module.

The pre-appraisal result must remain available to the relying party or Verifier
that processes the later TLS connection. These assumptions replace the need to
send and re-appraise the full platform quote and IMA log in every handshake.
The pre-appraisal establishes trust in Tarako's key and initial platform state;
the per-connection attestation binder provides freshness for each later Tarako
Evidence signature.

## Result

Under these assumptions, Tarako **can be used as the source of fresh,
application-specific Evidence** for the draft. Its 128-byte opaque signing
input can carry the per-connection **attestation binder**, while the signature
binds that value to the calling executable's fs-verity digest and to the
pre-verified Tarako public key. Because the binder incorporates the hash of the
application's certificate public key, the Evidence is also bound to the TIK
used by that TLS connection. Possession of the corresponding TIK private key is
proved independently by the application's normal `CertificateVerify` message.

The ioctl output is an evidence-signing primitive, not a wire-format
`remoteAttestation` payload. The application-side integration must define the
Evidence claims and package the result in CMW.

Unlike the withdrawn predecessor, this draft:

- always combines attestation with X.509 authentication;
- requires the TLS Identity Key (TIK) to be the end-entity certificate key;
- derives a per-session binder from `ClientHello...ServerHello` and the hash of
  that certificate's DER SubjectPublicKeyInfo;
- carries Evidence or Attestation Results as CMW in a `remoteAttestation`
  extension on the first TLS `CertificateEntry`; and
- leaves the normal TLS `CertificateVerify` operation unchanged.

For TLS 1.3 cipher suites using SHA-256 or SHA-384, the binder is 32 or 48
bytes, respectively, and therefore fits in Tarako's 128-byte input. A Tarako
Evidence profile must define a deterministic, domain-separated encoding of the
binder in that fixed-size input so signatures cannot be confused with another
use of the ioctl.

## Compatibility by requirement

| Draft requirement | Current module |
|---|---|
| Accept a TEE challenge/binder | **Yes:** SHA-256 and SHA-384 binders fit in the opaque input. The application supplies the draft-derived value. |
| Evidence signature includes binder and public-key binding | **Yes, with a profile:** Tarako signs a domain-separated encoding of the binder and the signature verifies with its pre-verified key. The binder incorporates the TLS certificate public-key hash. |
| Attestation key remains stable | **Yes under the assumptions:** it is generated once and retained while the module remains loaded. |
| Platform/workload Evidence is rooted in a trusted key | **Satisfied by deployment:** prior platform/IMA appraisal authenticates Tarako's key and approved state. The TLS verifier must retain or receive that appraisal result. |
| Distinguish the calling workload | **Yes:** the signature includes the caller's fs-verity digest, for which the verifier needs an approved reference value. |
| Validate binder derivation inside the trusted component | **No:** Tarako accepts opaque bytes and cannot check the transcript or certificate-key inputs. Correct derivation is delegated to the pre-verified TLS application/shim. |
| TIK equals the X.509 end-entity key and is protected | **Satisfied by assumption:** the confidential, integrity-protected application owns the certificate key. Tarako does not use it. |
| Standard TLS `CertificateVerify` | **Out of scope:** performed normally by the application with its certificate private key. |
| CMW and `remoteAttestation` handling | **Out of scope:** performed by the patched TLS application. |

## Proposed integration

A background-check implementation could work as follows:

1. **Pre-appraise the platform.** Verify the platform Evidence and replay the
   IMA log. Record the resulting association between the Tarako public key,
   approved platform/module state, and approved application fs-verity digest.
2. **Compute the binder in the patched TLS application.** Derive it exactly as
   specified from `ClientHello...ServerHello` and the hash of the end-entity
   certificate's DER SPKI.
3. **Encode and pass the binder to Tarako.** Use a domain-separated 128-byte
   `user_data` value, for example:

   ```text
   ASCII("SEAT-TARAKO-v1") || uint8(binder_length) || binder || zero_padding
   ```

   The complete encoding must be exactly 128 bytes. Tarako signs
   `fsverity_digest || user_data`, thereby binding the approved executable to
   the TLS session and certificate identity.
4. **Construct fresh Evidence in userspace.** The Evidence should contain at
   least the profile identifier, binder and actual length, Tarako public key or
   stable key identifier, fs-verity digest and algorithm, Tarako signature and
   signature algorithm, and an identifier for the pre-appraisal result. The
   identifier allows the Verifier to securely locate the previously validated
   platform/IMA state.
5. **Complete the application-side protocol.** Wrap the Evidence in CMW, place
   it in the first certificate entry's `remoteAttestation` extension, and have
   the relying party:

   - recompute the binder from the TLS transcript and certificate SPKI;
   - reconstruct the exact 128-byte `user_data` value;
   - retrieve and validate the pre-appraisal result and its validity period;
   - check the approved fs-verity digest;
   - verify the Tarako signature with the pre-verified Tarako public key; and
   - independently perform normal certificate-chain and `CertificateVerify`
     validation using the application's TIK.

In this model the two keys have deliberately separate roles: the application
TIK authenticates the TLS endpoint, while Tarako's pre-verified key signs fresh
Evidence about the application and binds it to that endpoint's TIK through the
attestation binder.

## Security limitations

- The existing nonce VM test validates the ioctl's generic challenge path, but
  it does not derive or test a SEAT attestation binder.
- A compromised host can feed arbitrary data to Tarako. The relying party will
  reject an incorrect binder, but the module itself does not meet the draft's
  stronger recommendation that the trusted component validate the binder
  against its TIK. This design relies on the pre-verified, fs-verity-bound
  application/shim to supply it correctly.
- Pre-appraisal needs a defined lifetime, revocation policy, and secure lookup
  by Tarako key identifier. Loading the module only once provides key stability
  but does not by itself guarantee that old platform appraisal remains valid.
- fs-verity authenticates the executable file, not its runtime state. The
  pre-appraised platform boundary must cover the kernel and any other trusted
  components assumed by the design.
- A normal kernel module is not a TEE boundary against a compromised kernel.
  The deployment must define and attest the actual boundary, such as a TDX
  guest containing the module and measured TLS stack.
- Passport mode could carry the pre-appraisal as signed Attestation Results,
  but Tarako does not create those results.
