{
  kernel,
  stdenv,
  lib,
}:
stdenv.mkDerivation {
  pname = "tarako-module";
  version = kernel.version;

  src = lib.fileset.toSource {
    root = ./.;
    fileset = lib.fileset.unions [
      ./Kbuild
      ./Makefile
      ./src
    ];
  };

  nativeBuildInputs = kernel.moduleBuildDependencies;

  makeFlags = [
    "KDIR=${kernel.dev}/lib/modules/${kernel.modDirVersion}/build"
  ];

  installFlags = [ "INSTALL_MOD_PATH=${placeholder "out"}" ];
  installTargets = [ "modules_install" ];

  enableParallelBuilding = true;

  meta = {
    description = "A simple Hello World Rust kernel module";
    license = lib.licenses.gpl2Only;
    platforms = lib.platforms.linux;
    broken = !kernel.withRust;
  };
}
