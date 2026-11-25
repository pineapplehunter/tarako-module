{
  description = "TARAKO application attestation";

  inputs.nixpkgs.url = "github:nixos/nixpkgs?ref=nixos-unstable";
  inputs.flake-parts.url = "github:hercules-ci/flake-parts";
  inputs.rust-overlay = {
    url = "github:oxalica/rust-overlay?ref=stable";
    inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs =
    { self, flake-parts, ... }@inputs:
    flake-parts.lib.mkFlake { inherit inputs; } (
      { config, lib, ... }:
      {
        imports = [ ./real-hardware ];
        systems = [ "x86_64-linux" ];

        flake.overlays.default = lib.composeExtensions (finale: prev: {
          tarako-module = finale.linuxPackages.callPackage ./driver/package.nix { };
          tarako-module-latest = finale.linuxPackages_latest.callPackage ./driver/package.nix { };
          libtarako = finale.callPackage ./tools/libtarako/package.nix { };
          simple-attester = finale.pkgsStatic.callPackage ./tools/simple-attester/package.nix { };
          tls-attester = finale.pkgsStatic.callPackage ./tools/tls-attester/package.nix { };
          tls-client = finale.callPackage ./tools/tls-client/package.nix { };
          tls-mock-services = finale.callPackage ./test/tls-attestation/mock-services/package.nix { };

          tdx-verify = finale.callPackage ./tools/tdx-verify/package.nix { };
          tdx-attest = finale.writers.writePython3Bin "tdx-attest" {
            makeWrapperArgs = [
              "--prefix"
              "PATH"
              ":"
              (prev.lib.makeBinPath [ finale.tdx-verify ])
            ];
          } ./tools/tdx-verify/tdx-attest.py;

          generate-rust-analyzer = finale.writers.writePython3Bin "generate-rust-analyzer" {
            doCheck = false; # Keep the existing generator's formatting.
          } ./dev/generate_rust_analyzer.py;
          verify-model = finale.writers.writePython3Bin "tarako-verify-model" {
            doCheck = false; # The check runs the model and every negative case.
            makeWrapperArgs = [
              "--set-default"
              "TARAKO_MODEL"
              "${./formal-verification/tarako-attestation.pv}"
              "--prefix"
              "PATH"
              ":"
              (prev.lib.makeBinPath [ finale.proverif ])
            ];
          } ./formal-verification/test-negative-models.py;

          # Minimal kernel source tree with just the Rust files (~4.7 MB).
          kernel-src =
            finale.runCommand "linux-src-${finale.linuxPackages.kernel.modDirVersion}"
              { src = finale.linuxPackages.kernel.src; }
              ''
                mkdir -p $out
                tar xf "$src" --strip-components=1 -C "$out" --wildcards '*/rust/*'
              '';

        }) (import ./real-hardware/overlay.nix);

        flake.nixosModules = {
          tarakoKernelModule = { config, ... }: {
            boot.extraModulePackages = [
              (config.boot.kernelPackages.callPackage ./driver/package.nix { })
            ];
          };
          tarakoTestModuleLockdown = import ./test/common/module-lockdown.nix;
        };

        perSystem =
          { lib, system, ... }:
          let
            pkgs = import inputs.nixpkgs {
              inherit system;
              overlays = [
                inputs.rust-overlay.overlays.default
                self.overlays.default
              ];
            };
            inherit (config.flake) nixosModules;
            runAttestationTest =
              test:
              pkgs.testers.runNixOSTest {
                imports = [ test ];
                nodes.attester.imports = [ nixosModules.tarakoKernelModule ];
              };
            withModuleLockdown = test: {
              imports = [ test ];
              nodes.attester.imports = [ nixosModules.tarakoTestModuleLockdown ];
            };
          in
          {
            options.tarako.pkgs = lib.mkOption {
              type = lib.types.pkgs;
              internal = true;
              description = "The shared nixpkgs instance with TARAKO overlays applied.";
            };

            config = {
              tarako.pkgs = pkgs;
              packages = {
                inherit (pkgs)
                  libtarako
                  simple-attester
                  tls-attester
                  tls-client
                  tls-mock-services
                  tdx-verify
                  generate-rust-analyzer
                  verify-model
                  kernel-src
                  ;
                default = pkgs.tarako-module;
                latest = pkgs.tarako-module-latest;
              };

              checks = {
                attestation = runAttestationTest (withModuleLockdown ./test/attestation);
                tarako-basics = runAttestationTest (withModuleLockdown ./test/tarako-basics);
                tls-attestation = runAttestationTest ./test/tls-attestation;
                platform-evidence = pkgs.callPackage ./test/platform-evidence {
                  tdxAttestSource = ./tools/tdx-verify/tdx-attest.py;
                };
                formal-verification =
                  pkgs.runCommand "tarako-formal-verification"
                    {
                      nativeBuildInputs = [ pkgs.verify-model ];
                    }
                    ''
                      tarako-verify-model
                      touch "$out"
                    '';
                clippy = pkgs.tarako-module.overrideAttrs (old: {
                  nativeBuildInputs = old.nativeBuildInputs ++ [ pkgs.clippy ];
                  makeFlags = old.makeFlags ++ [
                    "CLIPPY=1"
                    "W=e"
                  ];
                });
              };

              devShells = {
                # Run protocol checks without building kernel/Rust development inputs.
                formal-verification = pkgs.mkShell {
                  packages = with pkgs; [
                    proverif
                    verify-model
                  ];
                };
                default = pkgs.mkShell {
                  packages = with pkgs; [
                    (python3.withPackages (ps: [ ps.cryptography ]))
                    generate-rust-analyzer
                    proverif
                    rustPlatform.bindgenHook
                    (rust-bin.stable.latest.default.override {
                      extensions = [
                        "rust-src"
                        "rust-analyzer"
                      ];
                      targets = [ ];
                    })
                  ];

                  RUST_KERNEL_SRCTREE = "${pkgs.kernel-src}";
                  RUST_KERNEL_OBJTREE = "${pkgs.linuxPackages.kernel.dev}/lib/modules/${pkgs.linuxPackages.kernel.modDirVersion}/build";

                  shellHook = ''
                    export RUST_SYSROOT="$(rustc --print sysroot)"
                    export RUST_LIB_SRC="$RUST_SYSROOT/lib/rustlib/src/rust/library"
                  '';
                };
                localbuild = pkgs.mkShell { packages = [ pkgs.rustc ]; };
              };

              formatter = pkgs.nixfmt-tree;
            };
          };
      }
    );
}
