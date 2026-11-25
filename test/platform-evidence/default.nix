{
  pkgs,
  tdx-verify,
  tdxAttestSource,
}:
let
  # Standalone replay oracle for these fixtures, not the guest kernel backend.
  imaRtmrSrc = pkgs.fetchFromGitHub {
    owner = "acompany-develop";
    repo = "ima-rtmr-extend";
    rev = "33101a9db9fcf1a7172aaede8fd943817d836941";
    hash = "sha256-PZBJBcv69b2bh5NcIR075hFRU22crSQWLddXIXohi5I=";
  };
  suite = pkgs.writers.writePython3Bin "test-platform-evidence" { doCheck = false; } ./test.py;
in
pkgs.runCommand "platform-evidence-tests"
  {
    nativeBuildInputs = [
      suite
      tdx-verify
    ];
    TDX_VERIFY_TESTDATA = "${tdx-verify.src}/testing/testdata";
    IMA_RTMR_VALIDATE = "${imaRtmrSrc}/validate.py";
    TDX_ATTEST = tdxAttestSource;
    IMA_TEST_FIXTURES = ./assets;
  }
  ''
    test-platform-evidence -v
    touch "$out"
  ''
