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
        "aarch64-linux"
        "x86_64-linux"
      ];

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
                nativeBuildInputs = [
                  pkgs.proverif
                  pkgs.python3
                ];
              }
              ''
                cp -r ${./formal-verification} formal-verification
                python3 formal-verification/test-negative-models.py
                touch $out
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
                pkgs.python3
              ];
            };
            default = pkgs.mkShell {
              packages = with pkgs; [
                (python3.withPackages (ps: [ ps.cryptography ]))
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
