{ lib, testers }:
testers.runNixOSTest {
  name = "tarako-feature-lacking-kernel";

  nodes.machine =
    { config, pkgs, ... }:
    let
      tarako-mod = config.boot.kernelPackages.callPackage ../driver/package.nix { };
    in
    {
      boot.kernelPackages = pkgs.linuxPackages;
      boot.extraModulePackages = [ tarako-mod ];
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
