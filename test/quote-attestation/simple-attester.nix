# Simple attester VM for the attestation test.
{ pkgs, ... }:
{
  boot.kernelPackages = pkgs.linuxPackages_latest;
  boot.kernelParams = [
    "ima_policy=critical_data"
    "ima_policy=tcb"
    "sysctl.kernel.yama.ptrace_scope=3"
  ];
  boot.kernelModules = [ "tarako" ];
  boot.initrd.kernelModules = [ "loop" ];

  environment = {
    systemPackages = [
      pkgs.e2fsprogs
      pkgs.fsverity-utils
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
  # verity-enabled volume at /var/lib/tarako. The service itself installs and
  # protects the exact executable that becomes the main process.
  systemd.services.tarako-simple-attester = {
    description = "Tarako Quote Attester";
    after = [ "network.target" ];
    path = [
      pkgs.coreutils
      pkgs.fsverity-utils
    ];
    script = ''
      app=/var/lib/tarako/tarako-simple-attester
      install -Dm755 ${pkgs.simple-attester}/bin/tarako-simple-attester "$app.new"
      fsverity enable --block-size=1024 "$app.new"
      mv -f "$app.new" "$app"
      exec "$app"
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
