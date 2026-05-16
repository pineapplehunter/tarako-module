{ testers }:
testers.runNixOSTest {
  name = "signer";
  nodes.machine =
    { config, pkgs, ... }:
    let
      signer-mod = (config.boot.kernelPackages.callPackage ./package.nix { });
      signer-app = pkgs.callPackage ./app/package.nix { };
    in
    {
      imports = [
        ./modules/fsverity.nix
        ./modules/ima.nix
      ];

      custom.fsverity.enable = true;
      custom.ima.enable = true;

      boot.kernelPackages = pkgs.linuxPackages_latest;
      boot.extraModulePackages = [
        signer-mod
      ];
      boot.kernelModules = [
        "ecc"
        "signer"
      ];
      environment.systemPackages = [ signer-app ];
    };
  testScript = ''
    machine.wait_for_unit("default.target")

    machine.succeed("modprobe ecc")
    machine.succeed("modprobe signer")

    assert "Signer: loading" in machine.succeed("dmesg")
    assert "Signer: key pair generated" in machine.succeed("dmesg")

    # Set up a filesystem with fs-verity support
    machine.succeed("dd if=/dev/zero of=/tmp/verity.img bs=1M count=64")
    machine.succeed("mkfs.ext4 -O verity /tmp/verity.img")
    machine.succeed("mkdir -p /mnt && mount /tmp/verity.img /mnt")

    # Copy the app to the verity-enabled filesystem and enable fs-verity
    machine.succeed("cp $(which signer-app) /mnt/")
    machine.succeed("fsverity enable --block-size=1024 /mnt/signer-app")

    out = machine.succeed("/mnt/signer-app")
    print(out)

    assert "SIGNER_HELLO" in out
    assert "SIGNER_GET_CERT" in out
    assert "SIGNER_SIGN_DATA" in out
    assert "certificate" in out
    assert "signature" in out
  '';
}
