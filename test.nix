{ testers }:
let
  testPy = ./test/test.py;
in
testers.runNixOSTest {
  name = "signer";

  extraPythonPackages = p: [ p.cryptography ];
  skipTypeCheck = true;

  nodes = {
    attester =
      { config, pkgs, ... }:
      let
        signer-mod = (config.boot.kernelPackages.callPackage ./package.nix { });
        signer-app = pkgs.callPackage ./app/package.nix { };
      in
      {
        imports = [
          ./modules/fsverity.nix
          ./modules/ima.nix
        ];

        custom.fsverity.enable = true;
        custom.ima.enable = true;

        boot.kernelPackages = pkgs.linuxPackages_latest;
        boot.extraModulePackages = [
          signer-mod
        ];
        boot.initrd.kernelModules = [
          "ecc"
          "signer"
        ];
        environment.systemPackages = [
          signer-app
          pkgs.openssl
          pkgs.python3
        ];

        networking.firewall.allowedTCPPorts = [ 9999 ];

        virtualisation = {
          tpm.enable = true;
          cores = 4;
          useEFIBoot = true;
        };
      };

    verifier =
      { pkgs, ... }:
      {
        environment.systemPackages = [
          pkgs.python3
        ];

        virtualisation = {
          cores = 2;
        };
      };
  };

  testScript = builtins.readFile testPy;
}
