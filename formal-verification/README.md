# Tarako remote-attestation ProVerif model

This directory models a three-device deployment with the verifier split into specialized appraisal services:

- **Client** requests an integrity decision.
- **Attester** contains the TDX quoting source, IMA log, and Tarako signer.
- **Verifier side** contains a relying verifier, an opaque TDX verifier, and an opaque IMA verifier. These may be separate processes or services on the verifier device.

The TDX and IMA verifiers accept opaque evidence and return signed appraisal answers. The relying verifier does not parse either evidence format.

The end-to-end goal is: **if the client accepts the TA file, the accepted digest equals the verifier's approved TA fs-verity digest**.

## Architecture and protocol

```text
Client             Relying verifier       TDX verifier       IMA verifier       Attester
  | request                |                    |                  |                 |
  |----------------------->|                    |                  |                 |
  |                        | TDX challenge      |                  |       TDX quote |
  |                        |------------------------------------------------------->|
  |                        |<-------------------------------------------------------|
  |                        | appraise(quote)    |                  |                 |
  |                        |------------------->|                  |                 |
  |                        | signed TDX answer |                  |                 |
  |                        |<-------------------|                  |                 |
  |                        |                                       get IMA log      |
  |                        |------------------------------------------------------->|
  |                        |<-------------------------------------------------------|
  |                        | appraise(TDX answer, IMA log)        |                 |
  |                        |------------------------------------->|                 |
  |                        | signed IMA answer                    |                 |
  |                        |<-------------------------------------|                 |
  |                        | Tarako request = H(signed IMA answer)                  |
  |                        |------------------------------------------------------->|
  |                        |<-------------------------------------------------------|
  | signed final verdict   |                    Tarako signature                    |
  |<-----------------------|                                                        |
```

### Stage bindings

1. The TDX challenge is `H(client request, fresh verifier nonce)`.
2. The signed TDX appraisal answer contains `H(TDX quote)`, the challenge, and the authenticated RTMR.
3. The IMA evidence contains `H(signed TDX answer)`.
4. The signed IMA appraisal answer contains both `H(signed TDX answer)` and `H(IMA evidence)`, plus the accepted Tarako public key.
5. The Tarako claim contains `H(signed IMA answer)` and the caller's fs-verity digest.
6. The final signed verdict contains the client's fresh request and accepted TA digest.

The client authenticates this verdict but deliberately does not repeat the relying verifier's digest policy check. This makes the end-to-end digest query depend on the authenticated chain and the relying verifier's check instead of making it true by construction at the client.

Consequently, substituting an answer, log, or quote from another protocol run breaks a checked hash or fresh challenge.

## Opaque verifiers

### TDX verifier

`TdxOpaqueVerifier` receives an opaque quote and performs the checks represented by:

```prolog
let tdx_claim(challenge, =approved_tdx_measurement, quoted_rtmr) =
    verify(received_quote, public_key(tdx_attestation_key)) in
```

It returns a result signed with `tdx_verifier_key`. In a real implementation this service must also validate Intel certificate chains, quote collateral, TCB status, algorithms, field encoding, and policy.

The relying verifier only verifies the appraisal-result signature and checks that the answer contains its challenge and the hash of the quote it submitted.

### IMA verifier

`ImaOpaqueVerifier` receives the signed TDX answer and IMA evidence. It:

1. authenticates the TDX verifier's answer;
2. checks that the IMA evidence is bound to that answer;
3. replays the log and compares its root with the RTMR from the TDX answer; and
4. finds the Tarako public key in that exact log snapshot.

It returns a result signed with `ima_verifier_key`. The relying verifier only checks that signature and the two evidence hashes.

The relying verifier must provision authentic public keys for both appraisal services. Key distribution is abstracted by `public_key(tdx_verifier_key)` and `public_key(ima_verifier_key)`.

## IMA table

The IMA log is represented by:

```prolog
table ima_log(bitstring, bitstring).
```

The attester commits the Tarako key under the replay root:

```prolog
insert ima_log(current_ima_root, ima_key_entry(tarako_public_key));
```

The IMA verifier accepts it only when the replay root matches the TDX-authenticated RTMR and the key belongs to that snapshot:

```prolog
let rtmr_with_ima(=replayed_ima_root) = quoted_rtmr in
get ima_log(=replayed_ima_root, =ima_key_entry(tarako_public_key)) in
```

`ima_root(...)` abstracts ordered log replay and `rtmr_with_ima(...)` abstracts the TDX RTMR extension. The model also runs a genuine TDX quoting entity with the approved TDX measurement but an unapproved IMA root. This state must be rejected by the RTMR comparison and log-membership check; it provides a negative control showing that the TDX measurement alone is insufficient. A concrete verifier must parse all records, preserve order, select the correct hash bank, reproduce the RTMR extensions, and apply an allow-list policy.

Unlike a TDX or Tarako quote, a raw IMA log normally has no independent signature. Therefore the model proves that accepted IMA evidence refers to a genuinely committed log snapshot, not that its transport sender is authentic. The opaque IMA verifier's **answer** is source-authenticated by its signature.

## Authenticity properties

The correspondence queries express “accepted implies genuine source”:

```prolog
event(TdxQuoteVerified(...))
  ==> event(TdxQuoteIssued(...)).

event(TdxAnswerAccepted(...))
  ==> event(TdxAnswerIssued(...)).

event(ImaEvidenceVerified(...))
  ==> event(ImaLogCommitted(...)).

event(ImaEvidenceVerified(...))
  ==> event(TdxAnswerIssued(...)).

event(ImaAnswerAccepted(...))
  ==> event(ImaAnswerIssued(...)).

event(TarakoQuoteAccepted(...))
  ==> event(TarakoQuoteIssued(...)).

event(TarakoQuoteAccepted(...))
  ==> event(ImaAnswerIssued(...)).
```

Thus:

- a quote accepted by the TDX verifier came from the genuine TDX attestation key;
- a TDX answer accepted by the relying verifier came from the opaque TDX verifier;
- IMA evidence accepted by the IMA verifier matches an authenticated, committed log root and a genuine signed TDX appraisal answer;
- an IMA answer accepted by the relying verifier came from the opaque IMA verifier; and
- a Tarako quote accepted by the relying verifier came from the IMA-bound Tarako key and is bound to a genuine signed IMA appraisal answer.

`UntrustedCaller` deliberately obtains a genuine Tarako signature over `unapproved_ta_digest`. The reference-value comparison prevents that authentic but unacceptable quote from producing a verdict.

These are non-injective authenticity correspondences: valid evidence can be replayed, but freshness and cross-stage hash bindings prevent it from satisfying an unrelated fresh end-to-end session. They do not claim that a genuine source issues each byte sequence only once.

## Signing-key secrecy

Two attacker queries prove that messages sent over the public network do not disclose the long-term evidence-signing keys:

```prolog
query attacker(tdx_attestation_key).
query attacker(tarako_signing_key).
```

ProVerif proves `not attacker(...) is true` for both the TDX attestation private key and the Tarako private key. Publishing either key in a mutated model makes its secrecy query false, providing a negative control. This is protocol-level secrecy under the symbolic model; it does not cover implementation memory disclosure, side channels, or runtime compromise.

## Successful-run reachability

The ProVerif manual recommends event reachability queries for detecting vacuous correspondence proofs caused by unreachable protocol code. The mutation-test script adds this diagnostic query to a temporary copy of the canonical model:

```prolog
query request: bitstring, digest: bitstring;
  event(ClientAcceptedIntegrity(request, digest)).
```

A fact-only ProVerif query abbreviates `event(...) ==> false`. The required result is:

```text
RESULT not event(ClientAcceptedIntegrity(request,digest)) is false.
```

Here, `false` is expected: ProVerif found an execution that reaches client acceptance. That execution traverses the TDX and IMA appraisal services, Tarako signing, and the relying verifier's verdict, so the canonical correspondence proofs are not succeeding merely because the end-to-end path is dead code. The canonical model retains only its eleven security queries; the diagnostic query exists only in the temporary test model.

## Run ProVerif

ProVerif 2.05 is in the default Nix development shell:

```sh
nix develop
proverif formal-verification/tarako-attestation.pv
```

A successful run ends with every query marked `true`. Important results include:

```text
Query event(TdxQuoteVerified(...)) ==> event(TdxQuoteIssued(...)) is true.
Query event(TdxAnswerAccepted(...)) ==> event(TdxAnswerIssued(...)) is true.
Query event(ImaEvidenceVerified(...)) ==> event(ImaLogCommitted(...)) is true.
Query event(ImaEvidenceVerified(...)) ==> event(TdxAnswerIssued(...)) is true.
Query event(ImaAnswerAccepted(...)) ==> event(ImaAnswerIssued(...)) is true.
Query event(TarakoQuoteAccepted(...)) ==> event(TarakoQuoteIssued(...)) is true.
Query event(TarakoQuoteAccepted(...)) ==> event(ImaAnswerIssued(...)) is true.
Query event(ClientAcceptedIntegrity(...)) ==> event(IntegrityVerdictIssued(...)) is true.
Query event(ClientAcceptedIntegrity(request,digest)) ==> digest = approved_ta_digest is true.
Query not attacker(tdx_attestation_key) is true.
Query not attacker(tarako_signing_key) is true.
```

ProVerif may rename variables or print constants with `[]`. Check the final **Verification summary** for `is false`, `cannot be proved`, or `RESULT unknown` when diagnosing a failure.

## Counterexample tests

The positive model is also mutation-tested. Run:

```sh
python3 formal-verification/test-negative-models.py
```

The script first requires every query in the sound model to be true. It then creates temporary model variants and requires ProVerif to find a counterexample in each one:

| Mutation | Property required to fail |
|---|---|
| Publish `tdx_attestation_key` | TDX attestation-key secrecy; verified TDX quote has a genuine quoting event |
| Publish `tdx_verifier_key` | accepted TDX answer has a genuine TDX-verifier event |
| Publish `ima_verifier_key` | accepted IMA answer has a genuine IMA-verifier event |
| Publish `tarako_signing_key` | Tarako private-key secrecy; accepted Tarako quote has a genuine Tarako event |
| Publish `relying_verifier_key` | client acceptance has a genuine relying-verifier verdict event; end-to-end digest integrity |
| TDX service skips the quote signature | verified TDX quote has a genuine quoting event |
| IMA service skips the TDX-answer signature | verified IMA evidence has a genuine TDX-verifier event |
| IMA service skips the RTMR comparison | verified IMA evidence is bound to the TDX-authenticated root |
| IMA service skips log membership | verified IMA evidence has a committed root/key pair |
| Relying verifier skips the TDX-answer signature | accepted TDX answer has a genuine TDX-verifier event |
| Relying verifier skips the IMA-answer signature | accepted IMA answer has a genuine IMA-verifier event |
| Relying verifier skips the Tarako signature | accepted Tarako quote has a genuine Tarako event |
| Client skips the final-verdict signature | client acceptance has a genuine relying-verifier verdict event; end-to-end digest integrity |

For a skipped signature, the mutation replaces signature verification with direct parsing of attacker-controlled input. This models an implementation that treats the corresponding verifier or signer response as unauthenticated data. A test passes only when the expected query is reported `is false`; merely leaking a key and checking a secrecy query itself is not considered sufficient.

The model intentionally omits correspondences between consecutive events in the same process because those can collapse to one-step checks without exercising the protocol. The TDX and Tarako key-secrecy queries are tested by publishing each key in a negative model and requiring the corresponding query to become false. Every positive query has at least one mutation in this suite that makes it false, guarding against vacuous or structurally tautological proofs.

The same suite is available as the Nix flake check:

```sh
nix build .#checks.x86_64-linux.formal-verification
```

## Assumptions and limitations

This proves a symbolic protocol, not the Rust implementation or concrete evidence parsers. It assumes:

- a Dolev-Yao attacker controls the network but cannot forge signatures or find hash collisions;
- TDX, appraisal-service, Tarako, and relying-verifier signing keys remain secret;
- the relying verifier has authentic TDX-verifier and IMA-verifier public keys;
- the TDX verifier correctly implements Intel quote and reference-value appraisal;
- the modeled RTMR commits to the replayed IMA log with the expected ordering and hash algorithm;
- the IMA table is append-only/authentic relative to its replay root;
- IMA measured the generated Tarako public key before Tarako signing was enabled;
- the kernel correctly obtains and signs the caller's fs-verity digest;
- `approved_ta_digest` is securely provisioned; and
- the attested TDX guest and kernel are in the trusted computing base.

The model's `sign` operation abstracts ECDSA and its hashing. Availability, side channels, key revocation, collateral expiry, parser vulnerabilities, hash-algorithm confusion, runtime compromise, and fs-verity limitations beyond file-content integrity are out of scope.

## Files

- [`tarako-attestation.pv`](tarako-attestation.pv) — executable model and proof queries.
- [`test-negative-models.py`](test-negative-models.py) — positive proof, successful-run reachability check, and required-counterexample mutation suite.
- `README.md` — architecture, verification instructions, and assumptions.
