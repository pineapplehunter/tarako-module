{ lib, ... }:
{
  name = "tarako-quote-benchmark";

  # Benchmarks use only the attester's test backdoor and QGS over vsock.
  # Avoid requiring a VDE-capable QEMU when no inter-VM network is used.
  nodeDefaults.virtualisation.vlans = [ ];

  nodes.attester.imports = [
    ../attester.nix
    ../quote-tools.nix
  ];

  testScript = ''
    TDX = False
    ${lib.readFile ./test.py}
  '';
}
