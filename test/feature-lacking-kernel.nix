{ lib, testers }:
testers.runNixOSTest {
  name = "signer-feature-lacking-kernel";

  nodes.machine =
    { config, pkgs, ... }:
    let
      signer-mod = config.boot.kernelPackages.callPackage ../driver/package.nix { };
    in
    {
      boot.kernelPackages = pkgs.linuxPackages;
      boot.extraModulePackages = [ signer-mod ];
      environment.systemPackages = [
        pkgs.python3
        (pkgs.pkgsStatic.callPackage ../app/package.nix { })
      ];
      virtualisation = {
        tpm.enable = true;
        useEFIBoot = true;
      };
    };

  testScript = lib.readFile ./feature-lacking-kernel.py;
}
