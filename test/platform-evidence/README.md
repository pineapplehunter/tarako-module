# Hardware-free platform evidence checks

**Quote:** The existing `tdx/verify.nix` package and `test/tdx-attest.py`
verification path check go-tdx-guest's signed `tdx_prod_quote_SPR_E4.dat`
fixture. The expected REPORTDATA is fixed to the quote v4 body bytes 568–631.
Changing only the caller's expectation must fail specifically on REPORTDATA.
Verification is offline: signatures and the Intel-rooted certificate chain are
checked, but online QE identity, TCB appraisal and revocation are not.

**IMA:** At `ima-rtmr-extend` revision
`33101a9db9fcf1a7172aaede8fd943817d836941`, `src/detect.c` selects
`/sys/class/misc/tdx_guest/measurements/rtmr2:sha384` on TDX. `src/log.c`
skips the entries already present at initialization and extends subsequent
entries in log order. `src/extend.c` writes the SHA-384 bank template digest
(not the event/buffer digest), substituting 48 `ff` bytes for an all-zero
violation digest. The paired log in `validate.py` is
`/sys/kernel/security/ima/ascii_runtime_measurements_sha384`, not the
unsuffixed IMA log. Replay starts from the startup RTMR and applies
`SHA384(previous_RTMR || template_digest)` from `skip_count`, stopping at the
prefix that matches the target. The tests call the pinned upstream parser and
replay function, not the sysfs-reading CLI.

The synthetic logs use a nonzero baseline, one skipped entry, one violation,
and one `ima-buf` event. `generate-fixtures.py` independently computes the
serialized template digests and golden RTMRs with OpenSSL. Regenerate with
`nix run .#generate-platform-fixtures -- test/platform-evidence/fixtures`.
The test-only policy checks that the matching replay slice contains an
`ima-buf` `public-key-generate` record that binds the exact expected Tarako
Attestation Key (TAK) bytes through its buffer and template digests. An
otherwise replay-valid log with a different key fails policy, as does a right
key appended beyond the matched prefix.

**Hardware boundary:** The synthetic RTMR targets are unsigned and unrelated
to the signed quote. This suite does not establish quote-to-live-log binding.
A TDX integration run must still exercise TDREPORT/quote generation through
TSM/QGS, real SHA-384 bank log emission and RTMR2 extension (including startup
baseline, skip count, asynchronous ordering and failure state), real driver
TAK measurement, and replay of a same-guest, same-snapshot log against the
RTMR2 authenticated by a fresh quote. This is not the four-VM test.

## Run and integrate

From the repository root, build standalone using the existing flake's pinned
nixpkgs, without editing `flake.nix`:

```sh
nix build --no-link --impure --expr '
  let
    root = builtins.toPath (builtins.getEnv "PWD");
    flake = builtins.getFlake ("path:" + root);
    pkgs = import flake.inputs.nixpkgs { system = builtins.currentSystem; };
  in pkgs.callPackage (root + "/test/platform-evidence") { }
'
```

To wire it into `nix flake check` later, add this in `perSystem` alongside
`checks.quote-tools` and ensure the new files are tracked by Git:

```nix
checks.platform-evidence = pkgs.callPackage ./test/platform-evidence { };
```
