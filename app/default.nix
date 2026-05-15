{ lib, rustPlatform }:

rustPlatform.buildRustPackage {
  pname = "signer-app";
  version = "0.1.0";

  src = ./.;

  cargoLock.lockFile = ./Cargo.lock;

  meta = {
    description = "Userspace test app for the signer kernel module";
    license = lib.licenses.gpl2Only;
    platforms = lib.platforms.linux;
  };
}
