{ lib, ... }:
{
  imports = [
    ../quote-benchmark
    ../tdx.nix
  ];

  name = lib.mkForce "tarako-quote-benchmark-tdx";
  testScript = lib.mkForce ''
    TDX = True
    ${lib.readFile ../quote-benchmark/test.py}
  '';
}
