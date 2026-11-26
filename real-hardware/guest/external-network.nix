{ lib, ... }:
{
  # Single-guest runners use the same measured guest configuration.
  networking.interfaces.eth0.ipv4.addresses = [
    {
      address = "10.0.2.15";
      prefixLength = 24;
    }
  ];
  virtualisation.vlans = lib.mkForce [ ];
  virtualisation.forwardPorts =
    map
      (port: {
        host = {
          address = "127.0.0.1";
          inherit port;
        };
        guest = { inherit port; };
      })
      [
        8443
        8080
      ];
  # SLiRP must use a modern virtio NIC to negotiate ACCESS_PLATFORM.
  virtualisation.qemu.options = [ "-global virtio-net-pci.disable-legacy=on" ];
}
