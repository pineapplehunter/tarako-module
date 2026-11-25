# Hardware-free platform evidence checks

**Quote:** The existing `tools/tdx-verify/package.nix` package and `tools/tdx-verify/tdx-attest.py`
verification path check go-tdx-guest's signed `tdx_prod_quote_SPR_E4.dat`
fixture. The expected REPORTDATA is fixed to the quote v4 body bytes 568–631.
Changing only the caller's expectation must fail specifically on REPORTDATA.
Tampered quote bodies and signatures, and empty or truncated quotes, are rejected.
Verification is offline: signatures and the Intel-rooted certificate chain are
checked, but online QE identity, TCB appraisal and revocation are not.

IMA replay and key appraisal are tested directly in the [live verifier’s unit
tests](../../real-hardware/verifier/test_verifier.py). The
[real-hardware suite](../../real-hardware/README.md) supplies fresh same-guest
quotes and IMA logs and checks their binding end to end.

## Run

```sh
nix build --no-link .#checks.x86_64-linux.platform-evidence
```
