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
        {
          _module.args.pkgs = import inputs.nixpkgs {
            inherit system;
            overlays = [
              inputs.rust-overlay.overlays.default
            ];
          };

          packages.kernel-module = pkgs.linuxPackages_latest.callPackage ./package.nix { };

          packages.default = pkgs.callPackage ./app/package.nix { };

          checks.nixos-test = pkgs.callPackage ./test.nix { };

          devShells.default = pkgs.mkShell {
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
          };

          formatter = pkgs.nixfmt-tree;
        };
    };
}
