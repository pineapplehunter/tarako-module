{ lib, testers }:
testers.runNixOSTest {
  name = "signer";

  nodes = {
    attester =
      { config, pkgs, ... }:
      let
        signer-mod = config.boot.kernelPackages.callPackage ../driver/package.nix { };
        signer-app = pkgs.pkgsStatic.callPackage ../app/package.nix { };

        signer-responder = pkgs.writers.writePython3Bin "signer-responder" {
          libraries = [ pkgs.python3Packages.flask ];
        } ./responder.py;
      in
      {
        imports = [
          ../modules/fsverity.nix
          ../modules/ima.nix
        ];

        custom.fsverity.enable = true;
        custom.ima.enable = true;

        boot.kernelPackages = pkgs.linuxPackages_latest;
        boot.extraModulePackages = [ signer-mod ];
        boot.kernelParams = [ "ima_policy=critical_data" ];
        # signer is loaded manually in the test after IMA policy is set
        environment.systemPackages = [
          signer-app
          signer-responder
          pkgs.openssl
          pkgs.python3
        ];

        networking.firewall.allowedTCPPorts = [ 5000 ];

        virtualisation = {
          tpm.enable = true;
          useEFIBoot = true;
        };
      };

    verifier =
      { pkgs, ... }:
      let
        signer-client = pkgs.writers.writePython3Bin "signer-client" {
          libraries = [ pkgs.python3Packages.requests ];
        } (builtins.readFile ./client.py);
      in
      {
        environment.systemPackages = [ signer-client ];
      };
  };

  testScript = lib.readFile ./attestation.py;
}
