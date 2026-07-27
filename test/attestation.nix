{ lib, testers }:
testers.runNixOSTest {
  name = "tarako-attestation";

  nodes = {
    attester =
      { config, pkgs, ... }:
      let
        tarako-mod = config.boot.kernelPackages.callPackage ../driver/package.nix { };
        tarako-app = pkgs.pkgsStatic.callPackage ../app/package.nix { };

        tarako-responder = pkgs.writers.writePython3Bin "tarako-responder" {
          libraries = [ pkgs.python3Packages.flask ];
        } ./responder.py;
      in
      {
        boot.kernelPackages = pkgs.linuxPackages_latest;
        boot.extraModulePackages = [ tarako-mod ];
        boot.kernelParams = [ "ima_policy=critical_data" ];
        # tarako is loaded manually in the test after IMA policy is set
        environment.systemPackages = [
          tarako-app
          tarako-responder
          pkgs.fsverity-utils
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
        tarako-client = pkgs.writers.writePython3Bin "tarako-client" {
          libraries = [ pkgs.python3Packages.requests ];
        } (builtins.readFile ./client.py);
      in
      {
        environment.systemPackages = [ tarako-client ];
      };
  };

  testScript = lib.readFile ./attestation.py;
}
