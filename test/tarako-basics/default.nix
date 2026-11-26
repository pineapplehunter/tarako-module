{
  name = "tarako-basics";

  nodes.attester = { pkgs, ... }: {
    boot.kernelPackages = pkgs.linuxPackages_latest;
    boot.kernelModules = [ "tarako" ];
    boot.kernelParams = [
      "ima_policy=critical_data"
      "sysctl.kernel.yama.ptrace_scope=3"
    ];
    boot.initrd.kernelModules = [ "loop" ];
    environment.etc."tarako/check-ptrace.py".source = ./check-ptrace.py;
    environment.systemPackages = [
      pkgs.simple-attester
      pkgs.e2fsprogs
      pkgs.fsverity-utils
      pkgs.openssl
      pkgs.python3
      pkgs.xxd
    ];
  };

  testScript = ''
    from datetime import timedelta
    import hashlib
    import json

    start_all()
    attester.wait_for_unit("multi-user.target")

    IMA_LOG = "/sys/kernel/security/integrity/ima/ascii_runtime_measurements"
    PUBKEY_EVENT = "public-key-generate"
    SPKI_P256_PREFIX_HEX = "3039301306072a8648ce3d020106082a8648ce3d030107032200"

    with subtest("module loading locked in initramfs, even for root"):
        assert attester.succeed("id -u").strip() == "0"
        caps = attester.succeed("grep '^CapEff:' /proc/self/status").split()[1]
        assert int(caps, 16) & (1 << 16), "probe must have CAP_SYS_MODULE"
        assert attester.succeed("sysctl -n kernel.modules_disabled").strip() == "1"
        initrd_modules = set(attester.succeed("cat /run/tarako-initrd-modules").split())
        loaded_modules = {
            line.split()[0] for line in attester.succeed("cat /proc/modules").splitlines()
        }
        assert "tarako" in initrd_modules, "Tarako was not loaded in initramfs"
        assert loaded_modules == initrd_modules, "module set changed after initramfs"

        # dummy exists on disk but was not preloaded: failure must be EPERM,
        # not a missing module. Also confirm unloading and undoing the lock fail.
        assert "dummy" not in loaded_modules
        attester.succeed("modinfo -n dummy")
        assert "Operation not permitted" in attester.fail("modprobe dummy 2>&1")
        assert "Operation not permitted" in attester.fail("rmmod tarako 2>&1")
        attester.fail("sysctl -w kernel.modules_disabled=0")
        assert attester.succeed("sysctl -n kernel.modules_disabled").strip() == "1"

    with subtest("TARAKO signs only fs-verity-protected executables"):
        attester.succeed(
            "mkdir -p /mnt/verity; truncate -s 128M /tmp/verity.img; "
            "mkfs.ext4 -q -F -O verity /tmp/verity.img && "
            "mount -o loop /tmp/verity.img /mnt/verity"
        )
        app = "/mnt/verity/attester"
        attester.succeed(f"install -m755 $(command -v tarako-simple-attester) {app}")
        nonce = "ab" * 32
        command = f"{app} quote {nonce}"
        assert "TARAKO_SIGN_DATA" in attester.fail(command + " 2>&1")

        attester.succeed(f"fsverity enable --hash-alg=sha256 --block-size=1024 {app}")
        measurement = attester.succeed(f"fsverity measure {app}").split()[0]
        algorithm, digest = measurement.split(":")
        assert algorithm == "sha256" and len(bytes.fromhex(digest)) == 32
        quote = json.loads(attester.succeed(command).splitlines()[-1])
        user_data = bytes.fromhex(nonce).ljust(128, b"\0")
        assert quote["user_data"] == user_data.hex()
        assert quote["hash"] == hashlib.sha256(bytes.fromhex(digest) + user_data).hexdigest()

    with subtest("root cannot ptrace or read Attester memory"):
        assert attester.succeed("sysctl -n kernel.yama.ptrace_scope").strip() == "3"
        attester.succeed(f"systemd-run --unit=tarako-ptrace-probe {app} --listen 127.0.0.1:5000")
        attester.wait_for_open_port(5000, timeout=timedelta(seconds=30))
        pid = int(attester.succeed("systemctl show -p MainPID --value tarako-ptrace-probe.service"))
        assert pid > 0, "Attester is not running"
        attester.succeed(f"python3 /etc/tarako/check-ptrace.py {pid}")

    def read_measured_pubkey():
        ima_log = attester.wait_until_succeeds(
            f"grep -q '{PUBKEY_EVENT}' {IMA_LOG} && cat {IMA_LOG}",
            timeout=30,
        )
        event = next(line for line in ima_log.splitlines() if PUBKEY_EVENT in line)
        fields = event.split()
        # Format: PCR template_hash ima-buf algo:digest event_name event_data
        assert fields[2] == "ima-buf", f"unexpected IMA template: {fields[2]}"
        algorithm, digest = fields[3].split(":", 1)
        pubkey = bytes.fromhex(fields[fields.index(PUBKEY_EVENT) + 1])

        assert len(pubkey) == 33, f"IMA public key has {len(pubkey)} bytes, expected 33"
        assert pubkey[0] in (0x02, 0x03), "IMA key is not a compressed SEC1 point"
        expected_digest = hashlib.new(algorithm, pubkey).hexdigest()
        assert digest == expected_digest, f"IMA digest mismatch: {digest} != {expected_digest}"
        return pubkey

    with subtest("IMA records a fresh TARAKO key on every boot"):
        first_pubkey = read_measured_pubkey()
        attester.shutdown()
        attester.start()
        attester.wait_for_unit("multi-user.target")
        pubkey = read_measured_pubkey()
        assert pubkey != first_pubkey, "public key was reused across boots"
        attester.succeed(
            f"printf %s '{SPKI_P256_PREFIX_HEX}{pubkey.hex()}' | xxd -r -p > /tmp/ima-pubkey.der"
        )
        attester.succeed("openssl pkey -pubin -inform DER -in /tmp/ima-pubkey.der -text -noout")
  '';
}
