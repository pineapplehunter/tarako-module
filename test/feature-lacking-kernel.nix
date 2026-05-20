{ lib, testers }:
testers.runNixOSTest {
  name = "signer-rejected";

  nodes.machine =
    { config, pkgs, ... }:
    let
      signer-mod = config.boot.kernelPackages.callPackage ../driver/package.nix { };
    in
    {
      boot.kernelPackages = pkgs.linuxPackages;
      boot.extraModulePackages = [ signer-mod ];
      environment.systemPackages = [ pkgs.python3 ];
      virtualisation = {
        tpm.enable = true;
        useEFIBoot = true;
      };
    };

  testScript = lib.readFile ./feature-lacking-kernel.py;
}
