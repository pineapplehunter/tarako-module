{ lib, ... }:
{
  imports = [
    ../attestation
    ../tdx.nix
  ];

  name = lib.mkForce "tarako-attestation-tdx";
  testScript = lib.mkForce ''
    TDX = True
    ${lib.readFile ../attestation/test.py}
  '';
}
