{ lib, ... }:
{
  name = "tarako-attestation";

  nodes = {
    attester = import ../attester.nix;

    verifier =
      { pkgs, ... }:
      let
        tarako-verifier = pkgs.writers.writePython3Bin "tarako-verifier" {
          libraries = with pkgs.python3Packages; [
            cryptography
            flask
          ];
        } ./verifier.py;
      in
      {
        environment = {
          systemPackages = [
            tarako-verifier
            pkgs.xxd
          ];
          etc = {
            "tarako/verifier.crt".source = ./verifier.crt;
            "tarako/verifier-key.pem" = {
              source = ./verifier-key.pem;
              mode = "0400";
            };
          };
        };
        networking.firewall.allowedTCPPorts = [ 5001 ];

        systemd.services.tarako-verifier = {
          description = "Tarako Quote Verifier";
          wantedBy = [ "multi-user.target" ];
          after = [ "network.target" ];
          serviceConfig = {
            ExecStart = lib.concatStringsSep " " [
              "${tarako-verifier}/bin/tarako-verifier"
              "--policy-directory /var/lib/tarako"
              "--certificate /etc/tarako/verifier.crt"
              "--signing-key /etc/tarako/verifier-key.pem"
            ];
            Restart = "on-failure";
            RestartSec = 1;
          };
        };
      };

    client =
      { pkgs, ... }:
      let
        tarako-client = pkgs.writers.writePython3Bin "tarako-client" {
          libraries = with pkgs.python3Packages; [
            cryptography
            requests
          ];
        } ./client.py;
      in
      {
        environment = {
          systemPackages = [
            tarako-client
            pkgs.openssl
          ];
          etc."tarako/root-ca.crt".source = ./root-ca.crt;
        };
      };
  };

  testScript = ''
    TDX = False
    ${lib.readFile ./test.py}
  '';
}
