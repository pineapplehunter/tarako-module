{ pkgs }:
let
  tdx-verify = pkgs.callPackage ../../tdx/verify.nix { };
in
pkgs.runCommand "quote-tools-tests"
  {
    nativeBuildInputs = [
      pkgs.python3
      tdx-verify
    ];
    TDX_VERIFY_TESTDATA = "${tdx-verify.src}/testing/testdata";
  }
  ''
    cp -r ${../.} test
    python3 test/quote-tools/test.py -v
    touch "$out"
  ''
