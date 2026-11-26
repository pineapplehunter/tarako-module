{ config, pkgs, ... }:
{
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
}
