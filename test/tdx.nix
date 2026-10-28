# Shared TDX test-driver and attester configuration.
{ lib, pkgs, ... }:
{
  qemu = {
    package = lib.mkDefault pkgs.qemu;
    forceAccel = true;
  };

  nodes.attester =
    { pkgs, ... }:
    let
      vendor-qemu = pkgs.callPackage ../tdx/qemu.nix { };
      tdvf = pkgs.callPackage ../tdx/firmware.nix { };
      # Default to pinned vendor QEMU and source-built TDVF, retaining overrides.
      tdx-qemu = pkgs.symlinkJoin {
        name = "tarako-tdx-qemu";
        paths = [ vendor-qemu ];
        passthru.stdenv = vendor-qemu.stdenv;
        postBuild = ''
          rm "$out/bin/qemu-system-x86_64"
          ln -s ${pkgs.writeShellScript "tarako-tdx-qemu" ''
            exec "''${TARAKO_TDX_QEMU:-${vendor-qemu}/bin/qemu-system-x86_64}" "$@"
          ''} "$out/bin/qemu-system-x86_64"
        '';
      };

      tdx-verify = pkgs.callPackage ../tdx/verify.nix { };
      tdx-attest = pkgs.symlinkJoin {
        name = "tdx-attest";
        paths = [ (pkgs.writers.writePython3Bin "tdx-attest" { } ./tdx-attest.py) ];
        nativeBuildInputs = [ pkgs.makeWrapper ];
        postBuild = ''
          wrapProgram "$out/bin/tdx-attest" \
            --prefix PATH : ${lib.makeBinPath [ tdx-verify ]}
        '';
      };
      quote-bench = pkgs.writers.writePython3Bin "quote-bench" { } ./quote-bench.py;
      bench-tdx-quote = pkgs.writeShellScriptBin "bench-tdx-quote" ''
        exec ${quote-bench}/bin/quote-bench tdx "$@"
      '';
    in
    {
      imports = [
        ../kernel/ima-rtmr-kernel.nix
        ./quote-tools.nix
      ];

      boot.kernelModules = [ "tdx_guest" ];
      environment.systemPackages = [
        bench-tdx-quote
        tdx-attest
        tdx-verify
      ];

      virtualisation = {
        cores = 4;
        memorySize = 4096;
        graphics = false;

        # vhost-user virtiofs cannot handle TDX's required access-platform bit.
        # Put the store on a block device and remove all host shared folders.
        useNixStoreImage = true;
        mountHostNixStore = false;
        sharedDirectories = lib.mkForce { };

        # qemu-vm.nix puts the kernel, initrd and NixOS closure registration
        # on QEMU's command line, so no bootable disk image is needed. TDX
        # still requires TDVF to initialize the trust domain. Build the dedicated
        # IntelTdxX64 firmware from source, retaining a runtime override.
        directBoot.enable = true;
        useBootLoader = false;
        useEFIBoot = lib.mkForce false;
        # qemu-vm adds smm=on for its default OVMFFull even without EFI boot.
        # Use non-SMM OVMF metadata; the actual TDVF is supplied via -bios.
        efi.OVMF = pkgs.OVMF;

        qemu = {
          package = lib.mkForce tdx-qemu;
          enableSharedMemory = false;
          options = [
            "-machine q35,smm=off,kernel-irqchip=split,confidential-guest-support=tdx0"
            "-cpu host,+x2apic"
            # -nographic alone leaves VGA present; its emulation can attempt
            # register access forbidden for production TDX guests.
            "-nodefaults"
            "-vga none"
            ''-bios "''${TARAKO_TDX_FIRMWARE:-${tdvf.firmware}}"''
            "-device vhost-vsock-pci,guest-cid=3"
            "-object '{\"qom-type\":\"tdx-guest\",\"id\":\"tdx0\",\"quote-generation-socket\":{\"type\":\"vsock\",\"cid\":\"2\",\"port\":\"4050\"}}'"
          ];
        };
      };
    };
}
