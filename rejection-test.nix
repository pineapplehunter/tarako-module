{ lib, testers }:
testers.runNixOSTest {
  name = "signer-rejected";

  nodes.machine =
    { pkgs, ... }:
    let
      signer-mod = pkgs.linuxPackages_latest.callPackage ./package.nix { };
    in
    {
      boot.kernelPackages = pkgs.linuxPackages_latest;
      boot.extraModulePackages = [ signer-mod ];
      environment.systemPackages = [ pkgs.python3 ];
      virtualisation = {
        tpm.enable = true;
        useEFIBoot = true;
      };
    };

  testScript = lib.readFile ./test/rejection.py;
}
