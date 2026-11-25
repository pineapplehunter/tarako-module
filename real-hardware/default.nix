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
    { config, lib, ... }:
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
      realHardwareDriver =
        attesterOnly:
        (realHardwareTest {
          imports = [ ./tests/attestation ];
          tarako.attesterOnly = attesterOnly;
          tarako.qcnlConfigFile = ./verifier/intel-pcs.json;
          nodes = {
            attester.imports = [ nixosModules.tarakoTdxImaLog ];
          }
          // lib.optionalAttrs (!attesterOnly) {
            verifier.imports = [ nixosModules.tarakoTdxVerifier ];
          };
        }).driver;
    in
    {
      packages = {
        inherit (pkgs)
          tdx-firmware
          dcap-verify
          live-tdx-verifier
          live-tdx-ima-log
          live-tdx-candidate-policy
          live-tdx-smoke
          ;
        real-hardware-basics = (realHardwareTest ./tests/basics).driver;
        real-hardware-test-driver = realHardwareDriver false;
        real-hardware-attester-driver = realHardwareDriver true;
      };
    };
}
