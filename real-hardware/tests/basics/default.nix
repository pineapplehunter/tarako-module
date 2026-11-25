{ lib, ... }:
{
  name = "tarako-real-hardware-basics";

  nodes.attester = { pkgs, ... }: {
    boot.kernelPackages = pkgs.linuxPackages_latest;
    boot.kernelParams = [ "ima_policy=critical_data" ];
    virtualisation.vlans = lib.mkForce [ ];
    virtualisation.qemu.options = [
      "-global virtio-pci.iommu_platform=on"
      "-global virtio-net-pci.disable-legacy=on"
    ];
  };

  testScript = ''
    from datetime import timedelta
    import hashlib

    start_all()
    attester.wait_for_unit("multi-user.target", timeout=timedelta(minutes=2))

    with subtest("TARAKO key is committed to TDX RTMR2"):
        # The synchronous sink exports the baseline before the boot aggregate.
        attester.succeed("test -d /sys/kernel/config/tsm/report")
        status, _ = attester.execute("test -r /sys/kernel/ima_rtmr2/initial")
        if status != 0:
            print(attester.succeed("dmesg | grep -Ei 'ima_rtmr|tdx_guest|ima:' || true"))
            raise AssertionError("built-in IMA-to-RTMR extender is not active")
        ima_log = "/sys/kernel/security/ima/ascii_runtime_measurements_sha384"
        status, _ = attester.execute(f"test -r {ima_log}")
        if status != 0:
            print(attester.succeed("ls -l /sys/kernel/security/ima/; cat /proc/cmdline"))
            raise AssertionError("guest kernel did not export the SHA-384 IMA measurement log")
        attester.succeed("modprobe tarako && test -c /dev/tarako")
        attester.succeed(f"grep -q 'ima-buf .* public-key-generate ' {ima_log}")
        # Snapshot the register first: later log appends cannot change its prefix.
        mr = "/sys/class/misc/tdx_guest/measurements/rtmr2:sha384"
        target = bytes.fromhex(attester.succeed(f"od -An -v -tx1 {mr}"))
        current = bytes.fromhex(attester.succeed("cat /sys/kernel/ima_rtmr2/initial"))
        assert len(target) == len(current) == 48
        lines = attester.succeed(f"cat {ima_log}").splitlines()
        assert "boot_aggregate" in lines[0], "expected a fresh IMA boot"
        saw_key = False
        for line in lines:
            fields = line.split()
            bank = bytes.fromhex(fields[1].removeprefix("sha384:"))
            assert len(bank) == 48
            current = hashlib.sha384(current + (bank if any(bank) else bytes([255]) * 48)).digest()
            saw_key |= fields[2] == "ima-buf" and fields[4] == "public-key-generate"
            if current == target:
                break
        assert current == target and saw_key, "RTMR2 does not cover IMA from boot through TAK"

    with subtest("TDX quote binds a fresh nonce and verifies offline"):
        output = attester.succeed(
            "tdx-attest quote --output /tmp/tdx-quote.bin",
            timeout=timedelta(minutes=2),
        )
        assert "TDX verification: OK" in output, output
  '';
}
