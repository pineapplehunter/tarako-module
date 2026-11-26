final: prev: {
  # IntelTdxX64 TDVF.
  tdx-firmware = final.OVMF-inteltdx.fd;
  tdx-client = final.callPackage ./client/package.nix { };
  dcap-verify = final.callPackage ./verifier/dcap/package.nix { };
  live-tdx-verifier = final.callPackage ./verifier/package.nix { };
  live-tdx-ima-log = final.writers.writePython3Bin "tarako-tdx-ima-log" { } ./guest/serve-ima.py;
  live-tdx-candidate-policy = final.writers.writePython3Bin "tarako-tdx-candidate-policy" {
    makeWrapperArgs = [
      "--prefix"
      "PATH"
      ":"
      (prev.lib.makeBinPath [ final.fsverity-utils ])
    ];
  } ./guest/candidate-policy.py;
  real-hardware-tls-client-check =
    final.writers.writePython3Bin "tarako-tdx-tls-client-check" { }
      ./tests/tls-attestation/check-tls-client.py;
}
