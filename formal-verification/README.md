# Tarako cached-session remote-attestation model

This ProVerif model separates **one-time TDX/IMA establishment** from
**repeated application attestations using a cached Tarako key**. The network is
public and controlled by a Dolev–Yao attacker. Multiple established sessions and
unbounded application requests may coexist.

The end-to-end goal remains: **if a client accepts an integrity verdict, its
accepted digest equals the relying verifier's approved TA fs-verity digest**.
The model additionally checks injective TQ authentication: one issued quote
cannot be replayed to account for two accepted application checks.

## Parties and trust boundaries

- **Client:** requests an integrity decision and authenticates the final verdict.
- **Attester:** contains the TDX quoting source, IMA commitment, and Tarako signer.
- **TDX appraisal service:** checks the quote and returns a signed answer.
- **IMA appraisal service:** authenticates the TDX answer, checks the root/key
  commitment, and returns a signed answer.
- **Relying verifier:** establishes and retains the authenticated appraisal/key,
  then checks fresh TQs without contacting either appraisal service again.

The three verifier roles can reside on one device. Their signed answers are
explicit protocol components in this model, not outputs of the kernel module.
The existing HTTP/nonce integration test does not implement this orchestration.

## Establishment: once per cached session

Each `RelyingVerifier` instance generates a fresh session identifier and verifier
nonce before accepting application requests:

```text
C = H(session_context(session_id, verifier_nonce))
TDX_quote = Sign_TDX(tdx_claim(C, approved_measurement, quoted_RTMR))
TDX_answer = Sign_TDX_verifier(H(TDX_quote), C, quoted_RTMR)
IMA_evidence = (H(TDX_answer), replayed_root, TAK_pub)
IMA_answer = Sign_IMA_verifier(H(TDX_answer), H(IMA_evidence), TAK_pub)
cache_binding = H(IMA_answer)
```

The real model uses distinct typed constructors for each signed message; the
notation above is an abbreviated description, not a concrete wire format.

The relying verifier validates both appraisal signatures and their exact
bindings. The IMA service checks that the evidence root matches the RTMR in the
TDX answer and that the accepted Tarako key belongs to that root. The established
state contains `cache_binding`, `tarako_public_key`, and the validated appraisal
context. These values are lexically scoped inside the request handler, not
read from an attacker-controlled cache lookup.

The process structure is important:

```text
!RelyingVerifier:
    fresh establishment challenge
    TDX quote + TDX appraisal
    IMA evidence + IMA appraisal
    retain authenticated cache and key
    ! application-request handler:
        fresh request nonce
        obtain and verify TQ
        return signed integrity verdict
```

The outer replication allows independent concurrent sessions. The inner
replication allows unbounded requests under each established cache. TDX/IMA
operations are outside the inner replication and are not repeated per TQ.

## Subsequent requests: no new hardware quote

For every received client request, the relying verifier creates a new nonce:

```text
request_binding = H(cached_request_context(
    cache_binding, client_request, fresh_request_nonce))
TQ = Sign_TAK(tarako_claim(request_binding, caller_fsverity_digest))
verdict = Sign_relying_verifier(integrity_verdict(
    client_request, accepted_digest))
```

It sends `request_binding` to the attester, verifies the TQ with the cached key,
requires the signed binding to equal its current request binding, and checks the
caller digest against the approved digest. The client authenticates the verdict
and checks its own fresh request. It deliberately does not repeat the digest
policy comparison: end-to-end digest integrity depends on the authenticated
verifier verdict rather than a tautological comparison at the client.

The request nonce prevents replay even if the attacker submits the same client
request repeatedly. The cache binding associates the challenge with the accepted
appraisal. Reusing only `H(IMA_answer)` is **not sufficient**: unlike the old
full-establishment-per-request model, the cached answer is no longer fresh for
each application check. Negative tests exercise both this static-binding bug
and omission of the fresh verifier nonce.

Tarako itself treats the binding as opaque. It does not parse or authenticate
the appraisal answer; those checks belong to the relying verifier.

## Relation to the kernel API

The current module signs the following concrete message:

```text
M = caller_fsverity_digest || user_data[128]
signature = ECDSA-P256 over SHA256(M)
```

A possible userspace profile is to hash a canonical, domain-separated encoding
of `(cache_binding, client_request, request_nonce)` with SHA-256 and pass that
32-byte binding followed by 96 zero bytes as `user_data`. The verifier would
reconstruct that exact buffer and the expected executable digest before checking
the signature. This fits the existing ioctl; no kernel-side appraisal parsing
is needed.

**That profile is not implemented by this change.** The model uses typed
constructors, perfect signatures, and abstract hashes; it does not prove a
concrete serializer, padding scheme, hash-algorithm selection, or ECDSA code.
`verify(sign(message,key),public_key(key)) = message` abstracts verification of a
known/reconstructed message, not literal message recovery from an ECDSA signature.
The current ioctl returns the message hash, signature, key, and user-data buffer,
not a separate executable digest. A real verifier must bind the signature to its
expected digest and challenge instead of trusting the returned hash alone.

The nonce VM integration test still sends a fresh nonce padded to 128 bytes. It
checks the signing primitive, not the modeled signed-appraisal services or the
cached-session binder profile. This directory's changes do not alter the module,
application, or VM test.

## Cache validity assumptions

This model verifies repeated authentication **while an established cache remains
valid**. It does not implement a cache-expiry or revocation mechanism.

- The guest/kernel remains trusted throughout the session.
- The Tarako signing key and relevant approved platform state remain unchanged.
- No reboot, key rotation, module reload, rollback, migration, revocation, or
  policy expiry occurs within a modeled valid session.
- A real verifier must discard/re-establish a cache when its validity policy
  requires it. This model does not prove how such events are detected remotely.
- A fresh TQ proves request freshness under the established key; it does not
  constitute fresh hardware appraisal or prove that a cache is still valid.

The model uses one fixed genuine Tarako key and one approved IMA root, while
allowing multiple independent appraisal sessions over them. It does not model
multiple guests/rotating keys, arbitrary log evolution, wall-clock time, or
post-establishment compromise.

## IMA and trusted measurement abstractions

The IMA log is represented by an authentic root/key table:

```prolog
table ima_log(bitstring, bitstring).
insert ima_log(current_ima_root, ima_key_entry(tarako_public_key));
```

The IMA verifier checks:

```prolog
let rtmr_with_ima(=replayed_ima_root) = quoted_rtmr in
get ima_log(=replayed_ima_root, =ima_key_entry(tarako_public_key)) in
```

`ima_root(...)` abstracts ordered log replay; `rtmr_with_ima(...)` abstracts the
RTMR commitment. A genuine quoting entity also exposes an unapproved root as a
negative control. A concrete implementation must parse records, preserve order,
select the correct hash bank, reproduce the RTMR extensions, and enforce policy.
An IMA log is not independently signed: the model authenticates its committed
root/key association, not its transport sender.

The TDX service abstracts certificate-chain/collateral/TCB/reference appraisal.
The approved and unapproved Tarako caller processes abstract correct kernel
retrieval of executable identity. `UntrustedCaller` can obtain genuine signatures
for an unapproved digest; the relying verifier must reject them.

## Security queries

There are **12 security queries**:

| # | Property |
|---|---|
| 1 | Verified TDX quote has a genuine TDX issuing event |
| 2 | Accepted TDX appraisal answer has a genuine service issuing event |
| 3 | Accepted IMA evidence has a committed root/key pair |
| 4 | Accepted IMA evidence matches a genuine TDX appraisal's RTMR |
| 5 | Accepted IMA answer has a genuine IMA service issuing event |
| 6 | Accepted TQ has a genuine Tarako issuing event for its request binding and digest |
| 7 | Accepted TQ's cached appraisal has a genuine IMA answer issuing event |
| 8 | **Injective** TQ acceptance: distinct acceptances require distinct issuing events |
| 9 | Client acceptance has a genuine relying-verifier verdict issuing event |
| 10 | Client-accepted digest equals the approved TA digest |
| 11 | TDX evidence-signing key is not disclosed by network messages |
| 12 | Tarako evidence-signing key is not disclosed by network messages |

Queries 1–7 and 9 are non-injective correspondences. Query 8 strengthens TQ
origin authentication to detect reuse of evidence across requests, including
requests in the same cache. It does not claim a signature can only be generated
once or that a network endpoint possesses a TLS key. Query 10 is the end-to-end
digest property; queries 11–12 are symbolic key secrecy, not memory-safety proofs.

## Run the checks

The lightweight shell avoids kernel/Rust development dependencies:

```sh
nix develop .#formal-verification --command \
  proverif formal-verification/tarako-attestation.pv

nix develop .#formal-verification --command \
  python3 formal-verification/test-negative-models.py
```

ProVerif 2.05 is supplied by the pinned flake. The default development shell also
contains it. The complete suite remains available through the existing check:

```sh
nix build .#checks.x86_64-linux.formal-verification
```

A successful suite reports all 12 security queries true, both reachability
checks passing, all 17 mutation scenarios passing, and every positive query
covered by at least one required counterexample. “Passing” a mutation means
ProVerif reports the expected security property **false**, not merely unknown.

### Successful-run and cache-reuse reachability

The test script adds two diagnostic queries to a temporary model:

```prolog
query request: bitstring, digest: bitstring;
  event(ClientAcceptedIntegrity(request, digest)).

query cache: bitstring, first: bitstring, second: bitstring, digest: bitstring;
  event(TarakoQuoteAccepted(cache, first, digest)) &&
  event(TarakoQuoteAccepted(cache, second, digest)) && first <> second.
```

These fact-only queries assert unreachability, so their required result is
**false**: a successful client acceptance exists, and two distinct TQs can be
accepted under the same cached appraisal. These diagnostics guard against a
proof that succeeds only because establishment or cache reuse is unreachable.
The canonical model contains only the 12 security queries.

### Negative models

| Mutation | Required failure |
|---|---|
| Publish TDX evidence key | TDX quote origin and key secrecy |
| Publish TDX verifier key | TDX answer origin |
| Publish IMA verifier key | IMA answer origin and TQ cached-appraisal origin |
| Publish Tarako key | TQ origin and key secrecy |
| Publish relying-verifier key | Verdict origin and accepted-digest integrity |
| Skip TDX quote signature | TDX quote origin |
| Skip TDX-answer signature at IMA service | IMA evidence's TDX-appraisal origin |
| Skip RTMR comparison | IMA evidence's authenticated-root binding |
| Skip IMA log membership | IMA committed-root/key origin |
| Skip TDX-answer signature at relying verifier | TDX answer origin |
| Skip IMA-answer signature at relying verifier | IMA answer origin |
| Skip TQ signature | TQ origin |
| Reuse static cached appraisal hash as request binding | Injective TQ authentication |
| Omit per-request verifier nonce | Injective TQ authentication under repeated client requests |
| Skip signed request-binding comparison | Injective TQ authentication |
| Skip approved-digest comparison | End-to-end accepted-digest integrity |
| Skip final-verdict signature at client | Verdict origin and accepted-digest integrity |

## Other assumptions and exclusions

The adversary cannot forge signatures or find hash collisions. Appraisal-service
and verdict verification keys are authentically provisioned; all signing keys
remain secret. The approved TA digest is securely provisioned. The measured
kernel obtains the correct caller digest and protects the key; IMA key
registration is trusted. Availability, side channels, parser vulnerabilities,
concrete cryptographic/serialization bugs, fs-verity limitations beyond file
identity, runtime compromise, and attested TLS channel binding remain outside
this proof. The cache-lifetime exclusions above are essential, not properties
established by the new injective query.

## Files

- [`tarako-attestation.pv`](tarako-attestation.pv): cached-session protocol and queries.
- [`test-negative-models.py`](test-negative-models.py): positive, reachability,
  cache-reuse, and mutation checks.
- `README.md`: protocol, implementation mapping, commands, and proof scope.
