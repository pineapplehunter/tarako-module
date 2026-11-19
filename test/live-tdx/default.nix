{ lib, pkgs, ... }:
let
  state = "/run/tarako-live-tdx";
  measured = "/mnt/tarako-live-tdx";
  policies = {
    live = 5102;
    wrong-digest = 5103;
    wrong-ima = 5104;
  };
  qcnlDefault = pkgs.writeText "tarako-intel-pcs.json" (
    builtins.toJSON {
      collateral_service = "https://api.trustedservices.intel.com/sgx/certification/v4/";
      pccs_url = "https://api.trustedservices.intel.com/sgx/certification/v4/";
      use_secure_cert = true;
    }
  );
in
{
  name = "tarako-live-tdx";
  imports = [ ../tdx.nix ];

  nodes.attester = { config, pkgs, ... }: {
    imports = [ ../../live-tdx/guest-module.nix ];
    boot.kernelPackages = pkgs.linuxPackages_latest;
    boot.kernelParams = [
      "ima_hash=sha384"
      "ima_policy=critical_data"
    ];
    boot.extraModulePackages = [
      (config.boot.kernelPackages.callPackage ../../driver/package.nix { })
    ];
    environment.systemPackages = [
      (pkgs.callPackage ../../tls-attester/package.nix { })
      (pkgs.writers.writePython3Bin "tarako-tdx-candidate-policy" {
        makeWrapperArgs = [
          "--prefix"
          "PATH"
          ":"
          (lib.makeBinPath [ pkgs.fsverity-utils ])
        ];
      } ../../live-tdx/candidate-policy.py)
      pkgs.e2fsprogs
      pkgs.fsverity-utils
      pkgs.openssl
    ];
    services.tarakoTdxImaLog = {
      enable = true;
      listen = "0.0.0.0";
      package = pkgs.writers.writePython3Bin "tarako-tdx-ima-log" { } ../../live-tdx/serve-ima.py;
    };
    networking.firewall.allowedTCPPorts = [
      8080
      8443
    ];
    # Set ACCESS_PLATFORM on virtio NICs so their DMA uses shared buffers.
    virtualisation.qemu.options = [ "-global virtio-net-pci.iommu_platform=on" ];
    systemd.services.tarako-tdx-attester.serviceConfig = {
      Type = "exec";
      ExecStart = "${measured}/attester 0.0.0.0:8443 ${state}/server.pem ${state}/server.key";
    };
  };

  nodes.verifier = { pkgs, ... }: {
    imports = [ ../../live-tdx/module.nix ];
    # Only this VM needs outbound DNS and HTTPS for Intel collateral.
    virtualisation.restrictNetwork = false;
    services.tarakoTdxVerifier = {
      enable = true;
      package = pkgs.callPackage ../../live-tdx/verifier/package.nix {
        dcapVerifier = pkgs.callPackage ../../live-tdx/dcap/package.nix { };
      };
      qcnlConfigFile = "${state}/qcnl.json";
      instances = lib.mapAttrs (name: port: {
        inherit port;
        policyFile = "${state}/${name}.json";
        signingKeyFile = "${state}/verifier.key";
      }) policies;
    };
    # The test driver provisions credentials before activating these units.
    systemd.services = lib.mapAttrs' (
      name: _:
      lib.nameValuePair "tarako-tdx-verifier-${name}" {
        wantedBy = lib.mkForce [ ];
      }
    ) policies;
    environment.systemPackages = [
      pkgs.openssl
      (pkgs.writers.writePython3Bin "tarako-tdx-smoke" {
        makeWrapperArgs = [
          "--prefix"
          "PATH"
          ":"
          (lib.makeBinPath [ (pkgs.callPackage ../../tls-attester/package.nix { }) ])
        ];
      } ../../live-tdx/smoke.py)
    ];
  };

  testScript = ''
    import json
    import os
    from datetime import timedelta
    from pathlib import Path
    from shlex import quote

    state = "${state}"
    measured = "${measured}"
    timeout = timedelta(seconds=30)

    def put(machine, destination, contents):
        machine.succeed(f"printf %s {quote(contents)} > {quote(destination)}")

    def prepare_attester():
        attester.start(allow_reboot=False)
        attester.wait_for_unit("multi-user.target", timeout=timedelta(minutes=2))
        # Ensure the RTMR extender is attached before Tarako measures its key.
        attester.succeed("test -d /sys/kernel/config/tsm/report")
        attester.succeed("test \"$(cat /sys/kernel/ima_rtmr/disabled)\" = 0")
        attester.succeed("modprobe tarako && test -c /dev/tarako")
        log = "/sys/kernel/security/ima/ascii_runtime_measurements_sha384"
        attester.wait_until_succeeds(f"grep -q 'ima-buf .* public-key-generate ' {log}", timeout=timeout)
        # An independent verity filesystem avoids changing the root or rebooting the TD.
        attester.succeed(f"install -d -m 0700 {state}; mkdir -p {measured}")
        attester.succeed(f"truncate -s 128M {state}/verity.img; mkfs.ext4 -q -F -O verity {state}/verity.img")
        attester.succeed(f"mount -o loop {state}/verity.img {measured}")
        attester.succeed(f"install -m755 $(command -v tarako-tdx-attester) {measured}/attester")
        attester.succeed(f"fsverity enable --hash-alg=sha256 {measured}/attester")

    def start_https():
        attester.succeed(f"""
            set -e
            cd {state}
            umask 077
            openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -noenc \\
                -days 1 -subj '/CN=Live TDX Test CA' -addext 'basicConstraints=critical,CA:TRUE' \\
                -keyout ca.key -out ca.pem
            openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -noenc \\
                -subj '/CN=attester' -keyout server.key -out server.csr
            printf '%s\\n' 'subjectAltName=DNS:attester' 'extendedKeyUsage=serverAuth' > server.ext
            openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial \\
                -days 1 -extfile server.ext -out server.pem
            rm -f ca.key
        """)
        put(verifier, f"{state}/ca.pem", attester.succeed(f"cat {state}/ca.pem"))
        attester.succeed("systemctl start tarako-tdx-attester.service")
        attester.wait_for_open_port(8443, timeout=timeout)
        attester.wait_for_open_port(8080, timeout=timeout)

    def start_verifiers(policy):
        qc_config = os.environ.get("TARAKO_TDX_QCNL_CONFIG", "${qcnlDefault}")
        verifier.copy_from_host(qc_config, f"{state}/qcnl.json")
        verifier.succeed(f"""
            set -e
            cd {state}
            umask 077
            openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out verifier.key
            openssl pkey -in verifier.key -pubout -out verifier.pub
        """)
        # The two negative instances keep all other approved inputs intact.
        def flipped(field):
            original = policy[field]
            return {**policy, field: ("0" if original[0] != "0" else "1") + original[1:]}

        for name, port, value in (
            ("live", 5102, policy),
            ("wrong-digest", 5103, flipped("fsverity_digest")),
            ("wrong-ima", 5104, flipped("ima_start_rtmr2")),
        ):
            put(verifier, f"{state}/{name}.json", json.dumps(value))
            verifier.succeed(f"systemctl start tarako-tdx-verifier-{name}.service")
            verifier.wait_for_open_port(port, timeout=timeout)

    def main():
        candidate_path = os.environ.get("TARAKO_TDX_WRITE_CANDIDATE")
        policy_path = os.environ.get("TARAKO_TDX_POLICY")
        if bool(candidate_path) == bool(policy_path):
            raise RuntimeError("Set exactly one of TARAKO_TDX_WRITE_CANDIDATE or TARAKO_TDX_POLICY")
        if candidate_path:
            prepare_attester()
            candidate = attester.succeed(f"tarako-tdx-candidate-policy {measured}/attester 2>{state}/candidate-notice")
            with Path(candidate_path).open("x") as output:
                output.write(candidate)
            print(f"Wrote unapproved candidate to {candidate_path}; no attestation test ran.")
            return

        assert policy_path is not None
        policy = json.loads(Path(policy_path).read_text())
        prepare_attester()
        verifier.start()
        verifier.wait_for_unit("multi-user.target", timeout=timedelta(minutes=2))
        verifier.succeed(f"install -d -m 0700 {state}")
        start_verifiers(policy)
        start_https()
        with subtest("real TDX quote, IMA replay and TARAKO over TLS"):
            status, result = verifier.execute(
                f"tarako-tdx-smoke --ca {state}/ca.pem --verifier-key {state}/verifier.pub "
                "--ima-log-url http://attester:8080/ima.log "
                "--wrong-digest-verifier http://127.0.0.1:5103/verify "
                "--wrong-ima-verifier http://127.0.0.1:5104/verify https://attester:8443/",
                timeout=timedelta(minutes=5),
            )
            print(result, end="")
            if status != 0:
                print(verifier.succeed("journalctl --no-pager -n 80 -u 'tarako-tdx-verifier-*.service'"))
                print(attester.succeed("journalctl --no-pager -n 40 -u tarako-tdx-attester.service"))
                raise AssertionError(f"live TDX smoke suite failed (exit {status})")

    main()
  '';
}
