{
  config,
  lib,
  ...
}:
let
  state = "/run/tarako-live-tdx";
  measured = "/mnt/tarako-live-tdx";
  attesterOnly = config.tarako.attesterOnly;
  policies = {
    live = 5102;
    wrong-digest = 5103;
    wrong-ima = 5104;
  };
in
{
  options.tarako = {
    attesterOnly = lib.mkEnableOption "serving the attester without a verifier VM";
    qcnlConfigFile = lib.mkOption {
      type = lib.types.path;
      description = "Default Intel QCNL configuration for the verifier.";
    };
  };

  config = {
    name = "tarako-real-hardware" + lib.optionalString attesterOnly "-attester";

    nodes = {
      attester =
        { pkgs, ... }:
        {
          boot.kernelPackages = pkgs.linuxPackages_latest;
          boot.kernelParams = [
            "ima_policy=critical_data"
          ];
          environment.systemPackages = [
            pkgs.tls-attester
            pkgs.live-tdx-candidate-policy
            pkgs.e2fsprogs
            pkgs.fsverity-utils
            pkgs.openssl
          ];
          services.tarakoTdxImaLog = {
            enable = true;
            listen = "0.0.0.0";
            package = pkgs.live-tdx-ima-log;
          };
          networking.firewall.allowedTCPPorts = [
            8080
            8443
          ];
          # SLiRP forwards on the first NIC; no VLAN peer or default route is needed.
          networking.interfaces.eth0.ipv4.addresses = lib.mkIf attesterOnly [
            {
              address = "10.0.2.15";
              prefixLength = 24;
            }
          ];
          virtualisation.vlans = lib.mkIf attesterOnly (lib.mkForce [ ]);
          virtualisation.forwardPorts = lib.optionals attesterOnly (
            map
              (port: {
                host = {
                  address = "127.0.0.1";
                  inherit port;
                };
                guest = {
                  address = "10.0.2.15";
                  inherit port;
                };
              })
              [
                8443
                8080
              ]
          );
          # Set ACCESS_PLATFORM on virtio NICs so their DMA uses shared buffers.
          # The SLiRP NIC must be modern-only to negotiate ACCESS_PLATFORM.
          virtualisation.qemu.options = [
            "-global virtio-net-pci.iommu_platform=on"
          ]
          ++ lib.optional attesterOnly "-global virtio-net-pci.disable-legacy=on";
          systemd.services.tarako-tdx-attester.serviceConfig = {
            Type = "exec";
            ExecStart = "${measured}/attester 0.0.0.0:8443 ${state}/server.pem ${state}/server.key";
          };
        };
    }
    // lib.optionalAttrs (!attesterOnly) {
      verifier = { pkgs, ... }: {
        # Only this VM needs outbound DNS and HTTPS for Intel collateral.
        virtualisation.restrictNetwork = false;
        services.tarakoTdxVerifier = {
          enable = true;
          package = pkgs.live-tdx-verifier;
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
          pkgs.live-tdx-smoke
        ];
      };
    };

    testScript =
      (
        if attesterOnly then
          ''
            import os
            import re
            from urllib.request import urlopen
          ''
        else
          ''
            import json
            import os
            from pathlib import Path
            from shlex import quote
          ''
      )
      + ''
        from datetime import timedelta

        start_all()

        state = "${state}"
        measured = "${measured}"
        timeout = timedelta(seconds=30)

        def prepare_attester():
            attester.wait_for_unit("multi-user.target", timeout=timedelta(minutes=2))
            attester.succeed("modprobe tarako && test -c /dev/tarako")
            # An independent verity filesystem avoids changing the root or rebooting the TD.
            attester.succeed(f"install -d -m 0700 {state}; mkdir -p {measured}")
            attester.succeed(f"truncate -s 128M {state}/verity.img; mkfs.ext4 -q -F -O verity {state}/verity.img")
            attester.succeed(f"mount -o loop {state}/verity.img {measured}")
            attester.succeed(f"install -m755 $(command -v tarako-tdx-attester) {measured}/attester")
            # The small ext4 image uses 1 KiB blocks, not fsverity's default 4 KiB.
            attester.succeed(f"fsverity enable --hash-alg=sha256 --block-size=1024 {measured}/attester")

        def start_https(tls_name="attester"):
            attester.succeed(f"""
                set -e
                cd {state}
                umask 077
                openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -noenc \\
                    -days 1 -subj '/CN=Live TDX Test CA' -addext 'basicConstraints=critical,CA:TRUE' \\
                    -keyout ca.key -out ca.pem
                openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -noenc \\
                    -subj '/CN=attester' -keyout server.key -out server.csr
                printf '%s\\n' 'subjectAltName=DNS:{tls_name}' 'extendedKeyUsage=serverAuth' > server.ext
                openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial \\
                    -days 1 -extfile server.ext -out server.pem
                rm -f ca.key ca.srl server.csr server.ext
            """)
            attester.succeed("systemctl start tarako-tdx-attester.service")
            attester.wait_for_open_port(8443, timeout=timeout)
            attester.wait_for_open_port(8080, timeout=timeout)
            return attester.succeed(f"cat {state}/ca.pem")

        def candidate_policy():
            return attester.succeed(f"tarako-tdx-candidate-policy {measured}/attester")
      ''
      + (
        if attesterOnly then
          ''
            output = driver.out_dir
            ca = output / "https-ca.pem"
            candidate = output / "candidate.json"
            tls_name_file = output / "tls-name"
            if any(path.exists() for path in (ca, candidate, tls_name_file)):
                raise SystemExit("Use a fresh --output_directory; refusing to overwrite attester files.")

            tls_name = os.environ.get("TARAKO_TDX_TLS_NAME", "attester")
            label = r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
            if (len(tls_name) > 253 or not re.search(r"[A-Za-z]", tls_name)
                    or not re.fullmatch(rf"{label}(?:\.{label})*", tls_name)):
                raise SystemExit("TARAKO_TDX_TLS_NAME must be a DNS hostname, not an IP or URL.")

            prepare_attester()
            ca_pem = start_https(tls_name)
            with urlopen("http://127.0.0.1:8080/ima.log", timeout=5) as response:
                assert response.read(), "IMA log is empty through the host forward"
            candidate_json = candidate_policy()
            with ca.open("x") as file:
                file.write(ca_pem)
            with candidate.open("x") as file:
                file.write(candidate_json)
            with tls_name_file.open("x") as file:
                file.write(tls_name + "\n")
            print(f"Attester ready on host loopback: HTTPS 8443 (TLS name {tls_name}), IMA 8080", flush=True)
            print(f"Wrote {ca.name}, unapproved {candidate.name}, and {tls_name_file.name} to {output}. Press Ctrl-C to stop.", flush=True)
            attester.wait_for_shutdown()
          ''
        else
          ''
            def put(machine, destination, contents):
                machine.succeed(f"printf %s {quote(contents)} > {quote(destination)}")

            def start_verifiers(policy):
                qc_config = os.environ.get("TARAKO_TDX_QCNL_CONFIG", "${config.tarako.qcnlConfigFile}")
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
                    raise SystemExit(
                        "Choose exactly one mode:\n"
                        "  Collect a candidate: TARAKO_TDX_WRITE_CANDIDATE=./candidate.json nix run .#real-hardware-test-driver\n"
                        "  Test a reviewed policy: TARAKO_TDX_POLICY=./reviewed.json nix run .#real-hardware-test-driver"
                    )
                if candidate_path:
                    prepare_attester()
                    with Path(candidate_path).open("x") as output:
                        output.write(candidate_policy())
                    print(f"Wrote unapproved candidate to {candidate_path}; no attestation test ran.")
                    return

                assert policy_path is not None
                policy = json.loads(Path(policy_path).read_text())
                prepare_attester()
                verifier.wait_for_unit("multi-user.target", timeout=timedelta(minutes=2))
                verifier.succeed(f"install -d -m 0700 {state}")
                start_verifiers(policy)
                put(verifier, f"{state}/ca.pem", start_https())
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
          ''
      );
  };
}
