# Shared attester VM configuration for attestation and quote benchmarks.
{ config, pkgs, ... }:
let
  tarako-mod = config.boot.kernelPackages.callPackage ../driver/package.nix { };
  tarako-attester = pkgs.callPackage ../attester/package.nix { };
in
{
  boot.kernelPackages = pkgs.linuxPackages_latest;
  boot.kernelParams = [
    "ima_policy=critical_data"
    "ima_policy=tcb"
    "sysctl.kernel.yama.ptrace_scope=3"
  ];
  boot.extraModulePackages = [ tarako-mod ];
  boot.kernelModules = [ "tarako" ];

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
      tarako-attester
      pkgs.e2fsprogs
      pkgs.fsverity-utils
      pkgs.openssl
      pkgs.python3
      pkgs.xxd
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
    useEFIBoot = true;
    tpm = {
      enable = true;
      deviceModel = "tpm-crb";
    };
  };
}
