{
  lib,
  pkgs,
  testers,
  benchmark ? false,
  tdx ? false,
}:
testers.runNixOSTest {
  name =
    if tdx && benchmark then
      "tarako-quote-benchmark-tdx"
    else if tdx then
      "tarako-attestation-tdx"
    else if benchmark then
      "tarako-quote-benchmark"
    else
      "tarako-attestation";

  qemu = lib.mkIf tdx {
    package = lib.mkDefault pkgs.qemu;
    forceAccel = true;
  };

  nodes = {
    attester =
      { config, pkgs, ... }:
      let
        tarako-mod = config.boot.kernelPackages.callPackage ../driver/package.nix { };
        tarako-app = pkgs.pkgsStatic.callPackage ../app/package.nix { };

        tarako-responder = pkgs.writers.writePython3Bin "tarako-responder" {
          libraries = [ pkgs.python3Packages.flask ];
        } ./responder.py;

        tdx-attest = pkgs.writers.writePython3Bin "tdx-attest" { } ./tdx-attest.py;
        tpm-quote = pkgs.writers.writePython3Bin "tpm-quote" { } ./tpm-quote.py;
        tarako-quote = pkgs.writers.writePython3Bin "tarako-quote" { } ./tarako-quote.py;
        quote-bench = pkgs.writers.writePython3Bin "quote-bench" { } ./quote-bench.py;

        bench-tdx-quote = pkgs.writeShellScriptBin "bench-tdx-quote" ''
          exec ${quote-bench}/bin/quote-bench tdx "$@"
        '';
        bench-tpm-quote = pkgs.writeShellScriptBin "bench-tpm-quote" ''
          exec ${quote-bench}/bin/quote-bench tpm "$@"
        '';
        bench-tarako-quote = pkgs.writeShellScriptBin "bench-tarako-quote" ''
          exec ${quote-bench}/bin/quote-bench tarako "$@"
        '';
      in
      {
        imports = lib.optionals tdx [ ../kernel/ima-rtmr-kernel.nix ];

        boot.kernelPackages = pkgs.linuxPackages_latest;
        boot.kernelParams = [
          "ima_policy=critical_data"
          "ima_policy=tcb"
        ];
        boot.extraModulePackages = [ tarako-mod ];
        boot.kernelModules = [ "tarako" ] ++ lib.optional tdx "tdx_guest";

        environment = {
          systemPackages = [
            tarako-app
            tarako-responder
            pkgs.fsverity-utils
            pkgs.openssl
            pkgs.python3
            pkgs.xxd
          ]
          ++ lib.optionals (tdx || benchmark) [
            bench-tarako-quote
            bench-tpm-quote
            tarako-quote
            tpm-quote
            pkgs.hyperfine
            pkgs.time
            pkgs.tpm2-tools
          ]
          ++ lib.optionals tdx [
            bench-tdx-quote
            quote-bench
            tdx-attest
          ];
          etc."ima/ima-policy".text = ''
            measure func=MODULE_CHECK
            measure func=FIRMWARE_CHECK
            measure func=POLICY_CHECK
            measure func=CRITICAL_DATA
          '';
        };

        networking.firewall.allowedTCPPorts = [ 5000 ];

        virtualisation = {
          cores = lib.mkIf tdx 4;
          memorySize = lib.mkIf tdx 4096;

          # qemu-vm.nix puts the kernel, initrd and NixOS closure registration
          # on QEMU's command line, so no bootable disk image is needed. TDX
          # still requires TDVF to initialize the trust domain, supplied by
          # the packaged OVMF-inteltdx image below.
          directBoot.enable = lib.mkIf tdx true;
          useBootLoader = lib.mkIf tdx false;
          useEFIBoot = !tdx;

          tpm = {
            enable = true;
            deviceModel = "tpm-crb";
          };

          qemu = lib.mkIf tdx {
            enableSharedMemory = false;
            options = [
              "-machine q35,kernel-irqchip=split,confidential-guest-support=tdx0"
              "-cpu host,+x2apic"
              "-bios ${pkgs.OVMF-inteltdx.firmware}"
              "-device vhost-vsock-pci,guest-cid=3"
              "-object '{\"qom-type\":\"tdx-guest\",\"id\":\"tdx0\",\"quote-generation-socket\":{\"type\":\"vsock\",\"cid\":\"2\",\"port\":\"4050\"}}'"
            ];
          };
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

  testScript =
    if benchmark then
      ''
        TDX = ${if tdx then "True" else "False"}
        ${lib.readFile ./benchmark.py}
      ''
    else
      lib.readFile ./attestation.py;
}
