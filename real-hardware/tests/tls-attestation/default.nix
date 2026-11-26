{ config, lib, ... }:
let
  state = "/run/tarako-live-tdx";
  measured = "/mnt/tarako-live-tdx";
  policies = {
    live = 5102;
    wrong-digest = 5103;
    wrong-ima = 5104;
  };
in
{
  options.tarako.qcnlConfigFile = lib.mkOption {
    type = lib.types.path;
    description = "Default Intel QCNL configuration for the verifier.";
  };

  config = {
    name = "tarako-real-hardware-tls-attestation";

    nodes.verifier = { pkgs, ... }: {
      # Only the verifier VM needs outbound DNS and HTTPS for Intel collateral.
      virtualisation.restrictNetwork = false;
      services.tarakoTdxVerifier = {
        enable = true;
        qcnlConfigFile = "${state}/qcnl.json";
        instances = lib.mapAttrs (name: port: {
          inherit port;
          policyFile = "${state}/${name}.json";
          signingKeyFile = "${state}/verifier.key";
        }) policies;
      };
      # The test provisions policy and credentials before activating the units.
      systemd.services = lib.mapAttrs' (
        name: _:
        lib.nameValuePair "tarako-tdx-verifier-${name}" {
          wantedBy = lib.mkForce [ ];
        }
      ) policies;
      environment.systemPackages = [
        pkgs.openssl
        pkgs.tdx-client
      ];
    };

    testScript = ''
      from datetime import timedelta
      import json
      import os
      from shlex import quote

      start_all()
      state = "${state}"
      timeout = timedelta(seconds=30)
      for machine in (attester, verifier):
          machine.wait_for_unit("multi-user.target", timeout=timedelta(minutes=2))

      # Trust the image we just booted for this isolated test only. This does
      # not enroll the guest for use by an external verifier.
      attester.succeed("systemctl start tarako-tdx-prepare-attester.service")
      policy = json.loads(attester.succeed("tarako-tdx-candidate-policy ${measured}/attester"))

      def put(machine, destination, contents):
          machine.succeed(f"printf %s {quote(contents)} > {quote(destination)}")

      verifier.succeed(f"install -d -m 0700 {state}")
      qc_config = os.environ.get("TARAKO_TDX_QCNL_CONFIG", "${config.tarako.qcnlConfigFile}")
      verifier.copy_from_host(qc_config, f"{state}/qcnl.json")
      verifier.succeed(f"""
          set -e
          cd {state}
          umask 077
          openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out verifier.key
          openssl pkey -in verifier.key -pubout -out verifier.pub
      """)

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

      attester.succeed("systemctl start tarako-tdx-attester.service tarako-tdx-ima-log.service")
      attester.wait_for_open_port(8443, timeout=timeout)
      attester.wait_for_open_port(8080, timeout=timeout)
      put(verifier, f"{state}/ca.pem", attester.succeed(f"cat {state}/ca.pem"))

      def https_get(port=5102, options=""):
          return (
              f"tarako-tdx-client -v --ca {state}/ca.pem --verifier-key {state}/verifier.pub "
              f"--ima-log-url http://attester:8080/ima.log --verifier http://127.0.0.1:{port}/verify "
              f"{options} https://attester:8443/"
          )

      request_timeout = timedelta(seconds=65)

      def check_rejection(command, reason):
          body = verifier.fail(f"{command} 2>{state}/client.log", timeout=request_timeout)
          log = verifier.succeed(f"cat {state}/client.log")
          print(log.rstrip(), flush=True)
          assert not body and reason in log, (body, log)
          assert "* TLS handshake passed;" not in log, log

      try:
          with subtest("verified HTTPS GET"):
              body = verifier.succeed(https_get(), timeout=request_timeout)
              print(body, flush=True)
              assert body == "Tarako OK", body
          with subtest("wrong TLS hostname rejected"):
              check_rejection(https_get(options="--tls-name not-the-attester.invalid"), "TLS authentication:")
          with subtest("wrong approved digest rejected"):
              check_rejection(https_get(port=5103), "verifier rejected: tarako")
          with subtest("IMA replay mismatch rejected"):
              check_rejection(https_get(port=5104), "verifier rejected: ima_replay")
      except Exception:
          print(verifier.succeed("journalctl --no-pager -n 80 -u 'tarako-tdx-verifier-*.service'"))
          print(attester.succeed("journalctl --no-pager -n 40 -u tarako-tdx-attester.service"))
          raise
    '';
  };
}
