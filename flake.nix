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
    flake-parts.lib.mkFlake { inherit inputs; } {
      systems = [ "x86_64-linux" ];

      flake.overlays.default = final: _: {
        libtarako = final.callPackage ./tools/libtarako/package.nix { };
        simple-attester = final.pkgsStatic.callPackage ./tools/simple-attester/package.nix { };
        tls-attester = final.pkgsStatic.callPackage ./tools/tls-attester/package.nix { };
        tls-client = final.callPackage ./tools/tls-client/package.nix { };
        tls-mock-services = final.callPackage ./test/tls-attestation/mock-services/package.nix { };
      };

      imports = [
        {
          perSystem =
            {
              lib,
              pkgs,
              self',
              system,
              ...
            }:
            let
              liveTdxDriver =
                {
                  attesterOnly ? false,
                }:
                (pkgs.testers.runNixOSTest {
                  imports = [ ./test/live-tdx ];
                  tarakoAttesterOnly = attesterOnly;
                  node.specialArgs.tarakoTools = {
                    inherit (self'.packages)
                      tls-attester
                      live-tdx-candidate-policy
                      live-tdx-ima-log
                      live-tdx-smoke
                      ;
                    verifier = self'.packages.live-tdx-verifier;
                  };
                }).driver;
            in
            lib.mkIf (system == "x86_64-linux") {
              packages.dcap-verify = pkgs.callPackage ./live-tdx/dcap/package.nix { };
              packages.live-tdx-verifier = pkgs.callPackage ./live-tdx/verifier/package.nix {
                dcapVerifier = self'.packages.dcap-verify;
              };
              packages.live-tdx-test-driver = liveTdxDriver { };
              packages.live-tdx-attester-driver = liveTdxDriver { attesterOnly = true; };
            };
        }
      ];

      flake.nixosModules = {
        tarakoKernelModule = { config, ... }: {
          boot.extraModulePackages = [ (config.boot.kernelPackages.callPackage ./driver/package.nix { }) ];
        };
        tarakoTestModuleLockdown = import ./test/common/module-lockdown.nix;
        tarakoTdxVerifier = { lib, pkgs, ... }: {
          imports = [ ./live-tdx/module.nix ];
          services.tarakoTdxVerifier.package =
            lib.mkDefault
              self.packages.${pkgs.stdenv.hostPlatform.system}.live-tdx-verifier;
        };
        tarakoTdxImaLog = { lib, pkgs, ... }: {
          imports = [ ./live-tdx/guest-module.nix ];
          services.tarakoTdxImaLog.package =
            lib.mkDefault
              self.packages.${pkgs.stdenv.hostPlatform.system}.live-tdx-ima-log;
        };
      };

      perSystem =
        {
          pkgs,
          self',
          system,
          ...
        }:
        {
          _module.args.pkgs = import inputs.nixpkgs {
            inherit system;
            overlays = [
              inputs.rust-overlay.overlays.default
              self.overlays.default
            ];
          };

          packages.default = pkgs.linuxPackages.callPackage ./driver/package.nix { };
          packages.latest = pkgs.linuxPackages_latest.callPackage ./driver/package.nix { };
          packages.libtarako = pkgs.libtarako;
          packages.simple-attester = pkgs.simple-attester;
          packages.tls-attester = pkgs.tls-attester;
          packages.tls-client = pkgs.tls-client;
          packages.tls-mock-services = pkgs.tls-mock-services;
          packages.generate-rust-analyzer = pkgs.writers.writePython3Bin "generate-rust-analyzer" {
            doCheck = false; # Keep the existing generator's formatting.
          } ./dev/generate_rust_analyzer.py;
          packages.generate-platform-fixtures = pkgs.writers.writePython3Bin "generate-platform-fixtures" {
            makeWrapperArgs = [
              "--prefix"
              "PATH"
              ":"
              (pkgs.lib.makeBinPath [ pkgs.openssl ])
            ];
          } ./test/platform-evidence/generate-fixtures.py;
          packages.verify-model = pkgs.writers.writePython3Bin "tarako-verify-model" {
            doCheck = false; # The check runs the model and every negative case.
            makeWrapperArgs = [
              "--set-default"
              "TARAKO_MODEL"
              "${./formal-verification/tarako-attestation.pv}"
              "--prefix"
              "PATH"
              ":"
              (pkgs.lib.makeBinPath [ pkgs.proverif ])
            ];
          } ./formal-verification/test-negative-models.py;
          packages.live-tdx-ima-log =
            pkgs.writers.writePython3Bin "tarako-tdx-ima-log" { }
              ./live-tdx/serve-ima.py;
          packages.live-tdx-candidate-policy = pkgs.writers.writePython3Bin "tarako-tdx-candidate-policy" {
            makeWrapperArgs = [
              "--prefix"
              "PATH"
              ":"
              (pkgs.lib.makeBinPath [ pkgs.fsverity-utils ])
            ];
          } ./live-tdx/candidate-policy.py;
          packages.live-tdx-smoke = pkgs.writers.writePython3Bin "tarako-tdx-smoke" {
            makeWrapperArgs = [
              "--prefix"
              "PATH"
              ":"
              (pkgs.lib.makeBinPath [ pkgs.tls-client ])
            ];
          } ./live-tdx/smoke.py;
          checks.tls-attestation = pkgs.testers.runNixOSTest {
            imports = [ ./test/tls-attestation ];
            nodes.attester.imports = [ self.nixosModules.tarakoKernelModule ];
          };

          # Minimal kernel source tree with just the Rust files (~4.7 MB).
          packages.kernel-src =
            pkgs.runCommand "linux-src-${pkgs.linuxPackages.kernel.modDirVersion}"
              {
                src = pkgs.linuxPackages.kernel.src;
              }
              ''
                mkdir -p $out
                tar xf "$src" --strip-components=1 -C "$out" --wildcards '*/rust/*'
              '';

          checks.attestation = pkgs.testers.runNixOSTest {
            imports = [ ./test/attestation ];
            nodes.attester.imports = with self.nixosModules; [ tarakoKernelModule tarakoTestModuleLockdown ];
          };
          checks.tarako-basics = pkgs.testers.runNixOSTest {
            imports = [ ./test/tarako-basics ];
            nodes.attester.imports = with self.nixosModules; [ tarakoKernelModule tarakoTestModuleLockdown ];
          };
          checks.formal-verification =
            pkgs.runCommand "tarako-formal-verification"
              {
                nativeBuildInputs = [ self'.packages.verify-model ];
              }
              ''
                tarako-verify-model
                touch "$out"
              '';
          checks.clippy = self'.packages.default.overrideAttrs (old: {
            nativeBuildInputs = old.nativeBuildInputs ++ [ pkgs.clippy ];
            makeFlags = old.makeFlags ++ [
              "CLIPPY=1"
              "W=e"
            ];
          });
          checks.platform-evidence = pkgs.callPackage ./test/platform-evidence {
            tdx-verify = self'.packages.tdx-verify;
            tdxAttestSource = ./test/tdx-attest.py;
          };

          # Build these on any machine, then run the resulting test driver on
          # the TDX host (outside the Nix build sandbox). Pin vendor QEMU for
          # the 6.8 -intel host kernel and build IntelTdxX64 TDVF from source.
          packages.tdx-qemu = pkgs.callPackage ./tdx/qemu.nix { };
          packages.tdx-firmware = pkgs.callPackage ./tdx/firmware.nix { };
          packages.tdx-verify = pkgs.callPackage ./tdx/verify.nix { };

          devShells = {
            # Run protocol checks without building kernel/Rust development inputs.
            formal-verification = pkgs.mkShell {
              packages = [
                pkgs.proverif
                self'.packages.verify-model
              ];
            };
            default = pkgs.mkShell {
              packages = with pkgs; [
                (python3.withPackages (ps: [ ps.cryptography ]))
                self'.packages.generate-rust-analyzer
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

              RUST_KERNEL_SRCTREE = "${self'.packages.kernel-src}";
              RUST_KERNEL_OBJTREE = "${pkgs.linuxPackages.kernel.dev}/lib/modules/${pkgs.linuxPackages.kernel.modDirVersion}/build";

              shellHook = ''
                export RUST_SYSROOT="$(rustc --print sysroot)"
                export RUST_LIB_SRC="$RUST_SYSROOT/lib/rustlib/src/rust/library"
              '';
            };
            localbuild = pkgs.mkShell {
              packages = with pkgs; [ rustc ];
            };
          };

          formatter = pkgs.nixfmt-tree;
        };
    };
}
