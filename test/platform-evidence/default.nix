{
  pkgs,
  tdx-verify,
  tdxAttestSource,
}:
let
  suite = pkgs.writers.writePython3Bin "test-platform-evidence" { doCheck = false; } ./test.py;
in
pkgs.runCommand "platform-evidence-tests"
  {
    nativeBuildInputs = [
      suite
      tdx-verify
    ];
    TDX_VERIFY_TESTDATA = "${tdx-verify.src}/testing/testdata";
    TDX_ATTEST = tdxAttestSource;
  }
  ''
    test-platform-evidence -v
    touch "$out"
  ''
