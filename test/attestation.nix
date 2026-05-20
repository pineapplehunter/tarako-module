# NixOS VM integration test for the signer kernel module.
#
# Two-machine remote attestation scenario:
#   - attester: runs the signer kernel module, exposes a TCP responder on port
#               9999 that accepts a nonce and returns an ECDSA signature.
#   - verifier: sends a random nonce over the network and receives the response.
#
# The test driver (host) cryptographically verifies the result.
{ lib, testers }:
testers.runNixOSTest {
  name = "signer";

  nodes = {
    attester =
      { config, pkgs, ... }:
      let
        # Build the kernel module against the running kernel
        signer-mod = (config.boot.kernelPackages.callPackage ../driver/package.nix { });
        # Build the userspace signer-app binary
        signer-app = pkgs.pkgsStatic.callPackage ../app/package.nix { };
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
        boot.kernelModules = [ "signer" ];
        environment.systemPackages = [
          signer-app # /mnt/signer-app — the fs-verity protected binary
          pkgs.openssl
          pkgs.python3 # for the TCP responder
        ];

        # The TCP responder listens on 9999 for nonces from the verifier
        networking.firewall.allowedTCPPorts = [ 9999 ];

        virtualisation = {
          tpm.enable = true;
          useEFIBoot = true;
        };
      };

    # Verifier only needs Python to send the nonce over TCP
    verifier =
      { pkgs, ... }:
      {
        environment.systemPackages = [ pkgs.python3 ];
      };
  };

  testScript = lib.readFile ./attestation.py;
}
