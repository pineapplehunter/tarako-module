{ self, config, ... }:
let
  inherit (config.flake) nixosModules;
in
{
  flake.nixosModules = {
    tarakoImaRtmr = import ./guest/ima-rtmr-kernel.nix;
    tarakoTdxVerifier = { lib, pkgs, ... }: {
      imports = [ ./verifier/module.nix ];
      services.tarakoTdxVerifier.package =
        lib.mkDefault
          self.packages.${pkgs.stdenv.hostPlatform.system}.live-tdx-verifier;
    };
    tarakoTdxImaLog = { lib, pkgs, ... }: {
      imports = [ ./guest/module.nix ];
      services.tarakoTdxImaLog.package =
        lib.mkDefault
          self.packages.${pkgs.stdenv.hostPlatform.system}.live-tdx-ima-log;
    };
  };

  perSystem =
    { config, ... }:
    let
      inherit (config.tarako) pkgs;
      realHardwareTest =
        test:
        pkgs.testers.runNixOSTest {
          imports = [
            test
            ./guest/vm.nix
          ];
          nodes.attester.imports = with nixosModules; [
            tarakoKernelModule
            tarakoImaRtmr
          ];
        };
      testAttesterModules = [
        ./guest/test-attester.nix
        nixosModules.tarakoTdxImaLog
      ];
      singleAttesterDriver =
        test:
        (realHardwareTest {
          imports = [ test ];
          nodes.attester.imports = testAttesterModules ++ [ ./guest/external-network.nix ];
        }).driver;
    in
    {
      packages = {
        inherit (pkgs)
          tdx-firmware
          tdx-client
          dcap-verify
          live-tdx-verifier
          live-tdx-ima-log
          live-tdx-candidate-policy
          tdx-tls-client-check
          ;
        real-hardware-basics = (realHardwareTest ./tests/basics).driver;
        real-hardware-tls-attestation =
          (realHardwareTest {
            imports = [ ./tests/tls-attestation ];
            tarako.qcnlConfigFile = ./verifier/intel-pcs.json;
            nodes.attester.imports = testAttesterModules;
            nodes.verifier.imports = [ nixosModules.tarakoTdxVerifier ];
          }).driver;
        real-hardware-attester-only = singleAttesterDriver ./tests/attester-only;
        real-hardware-export-policy = singleAttesterDriver ./tests/export-policy;
      };
    };
}
