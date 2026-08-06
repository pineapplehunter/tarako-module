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
          packages.app = pkgs.pkgsStatic.callPackage ./app/package.nix { };

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

          checks.attestation = pkgs.callPackage ./test/attestation.nix { };
          checks.quote-benchmark = pkgs.callPackage ./test/attestation.nix { benchmark = true; };

          # Build these on any machine, then run the resulting test driver on
          # the TDX host (outside the Nix build sandbox). OVMF-inteltdx follows
          # edk2's IntelTdxX64 (Config-B) build documented upstream.
          packages.tdx-firmware = pkgs.OVMF-inteltdx.fd;
          packages.tdx-test-driver = (pkgs.callPackage ./test/attestation.nix { tdx = true; }).driver;
          packages.tdx-test-driver-interactive =
            (pkgs.callPackage ./test/attestation.nix { tdx = true; }).driverInteractive;
          packages.tdx-quote-benchmark-driver =
            (pkgs.callPackage ./test/attestation.nix {
              benchmark = true;
              tdx = true;
            }).driver;

          devShells = {
            default = pkgs.mkShell {
              packages = with pkgs; [
                (python3.withPackages (ps: [ ps.cryptography ]))
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
