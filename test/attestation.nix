{
  lib,
  pkgs,
  testers,
  tdx ? false,
}:
let
  # The TDX-enabled QEMU is built outside nixpkgs.  Keep qemu-img from
  # nixpkgs for the test driver's scratch disks, but select QEMU itself at
  # runtime so the driver output can be copied to a TDX host.
  tdxQemu =
    pkgs.runCommand "tdx-qemu-wrapper"
      {
        meta.mainProgram = "qemu-system-x86_64";
      }
      ''
        mkdir -p $out/bin
        ln -s ${lib.getExe' pkgs.qemu "qemu-img"} $out/bin/qemu-img
        cat > $out/bin/qemu-system-x86_64 <<'EOF'
        #!${pkgs.runtimeShell}
        set -eu
        qemu="''${TDX_QEMU:-/home/takata/tdx/qemu/build/qemu-system-x86_64}"
        if [ ! -x "$qemu" ]; then
          echo "TDX QEMU is not executable: $qemu" >&2
          echo "Set TDX_QEMU to the TDX-enabled qemu-system-x86_64 binary." >&2
          exit 1
        fi
        exec "$qemu" "$@"
        EOF
        chmod +x $out/bin/qemu-system-x86_64
      '';
in
testers.runNixOSTest {
  name = if tdx then "tarako-attestation-tdx" else "tarako-attestation";

  qemu = lib.mkIf tdx {
    package = tdxQemu;
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
      in
      {
        imports = lib.optionals tdx [ ../kernel/ima-rtmr-kernel.nix ];

        boot.kernelPackages = pkgs.linuxPackages_latest;
        boot.kernelParams = [ "ima_policy=critical_data" ];
        boot.extraModulePackages = [ tarako-mod ];
        boot.kernelModules = [ "tarako" ];

        environment.systemPackages = [
          tarako-app
          tarako-responder
          pkgs.fsverity-utils
          pkgs.openssl
          pkgs.python3
          pkgs.xxd
        ];

        networking.firewall.allowedTCPPorts = [ 5000 ];

        virtualisation = {
          cores = lib.mkIf tdx 4;
          memorySize = lib.mkIf tdx 4096;

          # qemu-vm.nix puts the kernel, initrd and NixOS closure registration
          # on QEMU's command line.  TDX therefore does not need OVMF or a
          # bootable disk image.
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
              "-device vhost-vsock-pci,guest-cid=3"
              ''-object '{"qom-type":"tdx-guest","id":"tdx0","quote-generation-socket":{"type":"vsock","cid":"2","port":"4050"}}''
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

  testScript = lib.readFile ./attestation.py;
}
