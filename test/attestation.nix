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

  # Benchmarks use only the attester's test backdoor and QGS over vsock.
  # Avoid requiring a VDE-capable QEMU when no inter-VM network is used.
  nodeDefaults.virtualisation.vlans = lib.mkIf benchmark [ ];

  nodes = {
    attester =
      { config, pkgs, ... }:
      let
        tarako-mod = config.boot.kernelPackages.callPackage ../driver/package.nix { };
        tarako-app = pkgs.pkgsStatic.callPackage ../app/package.nix { };
        tarako-attester = pkgs.callPackage ../attester/package.nix { };

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
          "sysctl.kernel.yama.ptrace_scope=3"
        ];
        boot.extraModulePackages = [ tarako-mod ];
        boot.kernelModules = [ "tarako" ] ++ lib.optional tdx "tdx_guest";

        # Load stage-2 requirements before locking module loading. Dependencies
        # are pulled in by modprobe; these networking modules normally autoload
        # only when the stage-2 firewall, network stack, or test backdoor starts.
        boot.initrd.kernelModules = config.boot.kernelModules ++ [
          "virtio_net"
          "af_packet"
          "vmw_vsock_virtio_transport"
          "sch_fq_codel"
          "nf_tables"
          "nft_compat"
          "xt_conntrack"
          "xt_pkttype"
          "xt_tcpudp"
          "ipt_rpfilter"
          "ip6t_rpfilter"
        ];
        boot.initrd.systemd.services.disable-module-loading = {
          description = "Disable module loading before switching root";
          after = [
            "systemd-modules-load.service"
            "initrd-switch-root.target"
          ];
          requiredBy = [ "initrd-switch-root.service" ];
          before = [ "initrd-switch-root.service" ];
          unitConfig.DefaultDependencies = false;
          serviceConfig.Type = "oneshot";
          path = [ pkgs.coreutils ];
          script = ''
            test -e /etc/initrd-release
            test -d /sys/module/tarako
            echo 1 > /proc/sys/kernel/modules_disabled
            cut -d ' ' -f1 /proc/modules | sort > /run/tarako-initrd-modules
          '';
        };

        environment = {
          systemPackages = [
            tarako-app
            tarako-attester
            pkgs.e2fsprogs
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
            tdx-verify
          ];
          etc."ima/ima-policy".text = ''
            measure func=MODULE_CHECK
            measure func=FIRMWARE_CHECK
            measure func=POLICY_CHECK
            measure func=CRITICAL_DATA
          '';
        };

        networking.firewall.allowedTCPPorts = [ 5000 ];

        # Deliberately has no wantedBy: the test starts it after enabling the
        # root filesystem's verity feature. The service itself installs and
        # protects the exact executable that becomes the main process.
        systemd.services.tarako-attester = {
          description = "Tarako Quote Attester";
          after = [ "network.target" ];
          path = [
            pkgs.coreutils
            pkgs.fsverity-utils
          ];
          script = ''
            install -Dm755 \
              ${tarako-attester}/bin/tarako-attester \
              /var/lib/tarako/tarako-attester.new
            fsverity enable --block-size=1024 \
              /var/lib/tarako/tarako-attester.new
            mv -f \
              /var/lib/tarako/tarako-attester.new \
              /var/lib/tarako/tarako-attester
            exec /var/lib/tarako/tarako-attester
          '';
          serviceConfig = {
            Restart = "on-failure";
            RestartSec = 1;
          };
        };

        virtualisation = {
          cores = lib.mkIf tdx 4;
          memorySize = lib.mkIf tdx 4096;
          graphics = lib.mkIf tdx false;

          # vhost-user virtiofs cannot handle TDX's required access-platform bit.
          # Put the store on a block device and remove all host shared folders.
          useNixStoreImage = lib.mkIf tdx true;
          mountHostNixStore = lib.mkIf tdx false;
          sharedDirectories = lib.mkIf tdx (lib.mkForce { });

          # qemu-vm.nix puts the kernel, initrd and NixOS closure registration
          # on QEMU's command line, so no bootable disk image is needed. TDX
          # still requires TDVF to initialize the trust domain. Build the dedicated
          # IntelTdxX64 firmware from source, retaining a runtime override.
          directBoot.enable = lib.mkIf tdx true;
          useBootLoader = lib.mkIf tdx false;
          useEFIBoot = !tdx;
          # qemu-vm adds smm=on for its default OVMFFull even without EFI boot.
          # Use non-SMM OVMF metadata; the actual TDVF is supplied via -bios.
          efi.OVMF = lib.mkIf tdx pkgs.OVMF;

          tpm = {
            enable = true;
            deviceModel = "tpm-crb";
          };

          qemu = lib.mkIf tdx {
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
    TDX = ${if tdx then "True" else "False"}
    ${lib.readFile (if benchmark then ./benchmark.py else ./attestation.py)}
  '';
}
