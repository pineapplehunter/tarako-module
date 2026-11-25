{
  description = "Rust kernel module example";

  inputs.nixpkgs.url = "github:nixos/nixpkgs?ref=nixos-unstable";
  inputs.flake-parts.url = "github:hercules-ci/flake-parts";
  inputs.rust-overlay = {
    url = "github:oxalica/rust-overlay?ref=stable";
    inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs =
    { self, flake-parts, ... }@inputs:
    flake-parts.lib.mkFlake { inherit inputs; } {
      systems = [
        "aarch64-linux"
        "x86_64-linux"
      ];

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
              checks.live-tdx-verifier = self'.packages.live-tdx-verifier;
              packages.live-tdx-test-driver = liveTdxDriver { };
              packages.live-tdx-attester-driver = liveTdxDriver { attesterOnly = true; };
            };
        }
      ];

      flake.nixosModules = {
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
            ];
          };

          packages.default = pkgs.linuxPackages.callPackage ./driver/package.nix { };
          packages.latest = pkgs.linuxPackages_latest.callPackage ./driver/package.nix { };
          packages.attester = pkgs.callPackage ./attester/package.nix { };
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
          packages.tls-attester = pkgs.callPackage ./tls-attester/package.nix { };
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
              (pkgs.lib.makeBinPath [ self'.packages.tls-attester ])
            ];
          } ./live-tdx/smoke.py;
          checks.tls-loopback = self'.packages.tls-attester;
          checks.tls-attestation = pkgs.testers.runNixOSTest ./test/tls-attestation;

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

          checks.attestation = pkgs.testers.runNixOSTest ./test/attestation;
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
          checks.quote-benchmark = pkgs.testers.runNixOSTest ./test/quote-benchmark;
          checks.quote-tools = pkgs.callPackage ./test/quote-tools { };
          checks.platform-evidence = pkgs.callPackage ./test/platform-evidence { };
          packages.tls-mock-services = pkgs.callPackage ./test/tls-attestation/package.nix { };
          checks.tls-services = self'.packages.tls-mock-services;

          # Build these on any machine, then run the resulting test driver on
          # the TDX host (outside the Nix build sandbox). Pin vendor QEMU for
          # the 6.8 -intel host kernel and build IntelTdxX64 TDVF from source.
          packages.tdx-qemu = pkgs.callPackage ./tdx/qemu.nix { };
          packages.tdx-firmware = pkgs.callPackage ./tdx/firmware.nix { };
          packages.tdx-verify = pkgs.callPackage ./tdx/verify.nix { };
          packages.tdx-test-driver = (pkgs.testers.runNixOSTest ./test/attestation-tdx).driver;
          packages.tdx-test-driver-interactive =
            (pkgs.testers.runNixOSTest ./test/attestation-tdx).driverInteractive;
          packages.tdx-quote-benchmark-driver = (pkgs.testers.runNixOSTest ./test/quote-benchmark-tdx).driver;

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
