{ pkgs }:
let
  tdx-verify = pkgs.callPackage ../../tdx/verify.nix { };
  sources = pkgs.lib.fileset.toSource {
    root = ../.;
    fileset = pkgs.lib.fileset.unions [
      ../quote-bench.py
      ../tarako-quote.py
      ../tdx-attest.py
    ];
  };
  suite = pkgs.writers.writePython3Bin "test-quote-tools" { doCheck = false; } ./test.py;
in
pkgs.runCommand "quote-tools-tests"
  {
    nativeBuildInputs = [ suite tdx-verify ];
    TDX_VERIFY_TESTDATA = "${tdx-verify.src}/testing/testdata";
    TARAKO_QUOTE_SOURCES = sources;
  }
  ''
    test-quote-tools -v
    touch "$out"
  ''
