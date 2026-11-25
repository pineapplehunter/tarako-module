final: prev: {
  # Vendor QEMU for the 6.8 -intel host kernel and IntelTdxX64 TDVF.
  tdx-qemu = final.callPackage ./host/qemu.nix { };
  tdx-firmware = final.callPackage ./host/firmware.nix { };
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
  live-tdx-smoke = final.writers.writePython3Bin "tarako-tdx-smoke" {
    makeWrapperArgs = [
      "--prefix"
      "PATH"
      ":"
      (prev.lib.makeBinPath [ final.tls-client ])
    ];
  } ./tests/attestation/smoke.py;
}
