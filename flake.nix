{
  description = "Rust kernel module example";

  inputs.nixpkgs.url = "github:nixos/nixpkgs?ref=nixos-unstable";
  inputs.flake-parts.url = "github:hercules-ci/flake-parts";
  inputs.rust-overlay = {
    url = "github:oxalica/rust-overlay?ref=stable";
    inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs =
    { flake-parts, ... }@inputs:
    flake-parts.lib.mkFlake { inherit inputs; } {
      systems = [
        "aarch64-darwin"
        "aarch64-linux"
        "x86_64-linux"
      ];

      perSystem =
        { pkgs, system, ... }:
        let
          linuxPkgs = pkgs.linuxKernel.packageAliases.linux_latest;
          kernel = linuxPkgs.kernel;
        in
        {
          _module.args.pkgs = import inputs.nixpkgs {
            inherit system;
            overlays = [
              inputs.rust-overlay.overlays.default
            ];
          };

          packages.kernel-module = kernel.stdenv.mkDerivation {
            pname = "hello-world-module";
            version = kernel.version;

            src = ./.;

            nativeBuildInputs = kernel.moduleBuildDependencies;

            makeFlags = linuxPkgs.kernelModuleMakeFlags ++ [
              "KDIR=${kernel.dev}/lib/modules/${kernel.modDirVersion}/build"
            ];

            installFlags = [ "INSTALL_MOD_PATH=${placeholder "out"}" ];
            installTargets = [ "modules_install" ];

            enableParallelBuilding = true;

            meta = {
              description = "A simple Hello World Rust kernel module";
              license = pkgs.lib.licenses.gpl2Only;
              platforms = pkgs.lib.platforms.linux;
              broken = !kernel.withRust;
            };
          };

          packages.default = pkgs.callPackage ./app {
            inherit (pkgs) rustPlatform;
          };

          devShells.default = pkgs.mkShell {
            packages = with pkgs; [
              rustPlatform.bindgenHook
              (rust-bin.stable.latest.default.override {
                extensions = [
                  "rust-src"
                  "rust-analyzer"
                ];
                targets = [ ];
              })
            ] ++ kernel.moduleBuildDependencies;
          };

          formatter = pkgs.nixfmt-tree;
        };
    };
}
