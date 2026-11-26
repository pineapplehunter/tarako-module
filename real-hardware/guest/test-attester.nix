{ lib, pkgs, ... }:
let
  state = "/run/tarako-live-tdx";
  measured = "/mnt/tarako-live-tdx";
in
{
  boot.kernelPackages = pkgs.linuxPackages_latest;
  boot.kernelParams = [ "ima_policy=critical_data" ];
  environment.systemPackages = [ pkgs.live-tdx-candidate-policy ];

  services.tarakoTdxImaLog = {
    enable = true;
    listen = "0.0.0.0";
  };
  systemd.services.tarako-tdx-ima-log.wantedBy = lib.mkForce [ ];
  networking.firewall.allowedTCPPorts = [
    8080
    8443
  ];
  # Set ACCESS_PLATFORM so virtio networking uses shared buffers.
  virtualisation.qemu.options = [ "-global virtio-net-pci.iommu_platform=on" ];

  systemd.services.tarako-tdx-prepare-attester = {
    path = [
      pkgs.e2fsprogs
      pkgs.fsverity-utils
      pkgs.kmod
      pkgs.util-linux
    ];
    serviceConfig = {
      Type = "oneshot";
      RemainAfterExit = true;
    };
    script = ''
      modprobe tarako
      test -c /dev/tarako
      install -d -m 0700 ${state}
      mkdir -p ${measured}
      # A separate verity filesystem avoids changing the root or rebooting the TD.
      truncate -s 128M ${state}/verity.img
      mkfs.ext4 -q -F -O verity ${state}/verity.img
      mount -o loop ${state}/verity.img ${measured}
      install -m755 ${lib.getExe' pkgs.tls-attester "tarako-tdx-attester"} ${measured}/attester
      fsverity enable --hash-alg=sha256 --block-size=1024 ${measured}/attester
    '';
  };

  systemd.services.tarako-tdx-attester = {
    requires = [ "tarako-tdx-prepare-attester.service" ];
    after = [ "tarako-tdx-prepare-attester.service" ];
    path = [ pkgs.openssl ];
    preStart = ''
      cd ${state}
      tls_name=attester
      if test -r tls-name; then
        tls_name=$(cat tls-name)
      fi
      umask 077
      openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -noenc \
        -days 1 -subj '/CN=Live TDX Test CA' -addext 'basicConstraints=critical,CA:TRUE' \
        -keyout ca.key -out ca.pem
      openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -noenc \
        -subj '/CN=attester' -keyout server.key -out server.csr
      printf '%s\n' "subjectAltName=DNS:$tls_name" 'extendedKeyUsage=serverAuth' > server.ext
      openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial \
        -days 1 -extfile server.ext -out server.pem
      rm -f ca.key ca.srl server.csr server.ext
    '';
    serviceConfig = {
      Type = "exec";
      ExecStart = "${measured}/attester 0.0.0.0:8443 ${state}/server.pem ${state}/server.key";
    };
  };
}
