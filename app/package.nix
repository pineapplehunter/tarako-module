{ rustPlatform, lib }:
rustPlatform.buildRustPackage {
  pname = "tarako-app";
  version = "0.1.0";
  src = lib.fileset.toSource {
    root = ./.;
    fileset = lib.fileset.unions [
      ./src
      ./Cargo.toml
      ./Cargo.lock
    ];
  };
  cargoLock.lockFile = ./Cargo.lock;
  doCheck = false;
}
