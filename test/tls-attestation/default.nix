{ lib, ... }:
let
  # Tests provision keys and policy first, then start these units explicitly.
  service = command: {
    after = [ "network.target" ];
    serviceConfig = {
      Type = "exec";
      ExecStart = lib.concatStringsSep " " command;
    };
  };
  setupCertificate =
    { writeShellApplication, openssl }:
    writeShellApplication {
      name = "setup-certificate";
      runtimeInputs = [ openssl ];
      text = builtins.readFile ./setup-certificate.sh;
    };
in
{
  name = "tarako-tls-attestation";

  nodes = {
    attester =
      { pkgs, ... }:
      {
        boot.kernelPackages = pkgs.linuxPackages_latest;
        boot.kernelModules = [
          "tarako"
          "loop"
        ];
        boot.kernelParams = [ "ima_policy=critical_data" ];
        virtualisation = {
          useEFIBoot = true;
          tpm = {
            enable = true;
            deviceModel = "tpm-crb";
          };
        };
        environment.systemPackages = [
          pkgs.openssl
          (pkgs.writeShellApplication {
            name = "setup-attester-binary-fsverity";
            runtimeInputs = [
              pkgs.e2fsprogs
              pkgs.fsverity-utils
              pkgs.tls-attester
              pkgs.util-linux
            ];
            text = builtins.readFile ./setup-attester-binary-fsverity.sh;
          })
          (pkgs.callPackage setupCertificate { })
        ];
        networking.firewall.allowedTCPPorts = [ 8443 ];
        systemd.services."tls-attester@" = service [
          "/mnt/tls-attestation/tarako-tls-attester"
          "0.0.0.0:8443"
          "/run/tls-attestation/%i.pem"
          "/run/tls-attestation/%i.key"
          "http://mock:5101/quote"
        ];
        systemd.services."tls-attester-fault@" = service [
          "/mnt/tls-attestation/tarako-tls-attester-test"
          "0.0.0.0:8443"
          "/run/tls-attestation/server.pem"
          "/run/tls-attestation/server.key"
          "http://mock:5101/quote"
          "%i"
        ];
      };
    client =
      { pkgs, ... }:
      {
        environment.systemPackages = [
          pkgs.tls-client
          pkgs.curl
        ];
      };
    mock =
      { pkgs, ... }:
      {
        environment.systemPackages = [
          pkgs.xxd
          (pkgs.callPackage setupCertificate { })
        ];
        networking.firewall.allowedTCPPorts = [ 5101 ];
        systemd.services.mock-quote = service [
          "${lib.getExe' pkgs.tls-mock-services "tarako-mock-platform-signer"}"
          "--signing-key"
          "/run/tls-attestation/signing.key"
          "--signing-cert"
          "/run/tls-attestation/signing-cert.pem"
          "--tak-file"
          "/run/tls-attestation/tak.bin"
        ];
      };
    verifier =
      { pkgs, ... }:
      {
        environment.systemPackages = [
          pkgs.openssl
          pkgs.xxd
          (pkgs.writers.writePython3Bin "tarako-measured-tak" { } ./measured-tak.py)
        ];
        networking.firewall.allowedTCPPorts = [ 5102 ];
        systemd.services.quote-verifier = service [
          "${lib.getExe' pkgs.tls-mock-services "tarako-tls-verifier"}"
          "--signing-key"
          "/run/tls-attestation/signing.key"
          "--tak-file"
          "/run/tls-attestation/tak.bin"
          "--platform-ca"
          "/run/tls-attestation/platform-ca.pem"
          "--digest-file"
          "/run/tls-attestation/digest"
        ];
      };
  };

  testScript = ''
    """Exercise real Tarako ioctls and TLS, with a mock (not TDX) platform signer."""
    from datetime import timedelta
    from itertools import product
    import json
    from shlex import quote

    IMA_LOG = "/sys/kernel/security/integrity/ima/ascii_runtime_measurements_sha256"

    start_all()

    with subtest("prepare the VM state directories"):
        for machine in (attester, client, verifier, mock):
            machine.succeed("install -d -m 0700 /run/tls-attestation")

    with subtest("enable fs-verity and measure the attester binaries"):
        measurements = attester.succeed(
            "setup-attester-binary-fsverity /run/tls-attestation /mnt/tls-attestation"
        )
        digests = dict(line.split() for line in measurements.splitlines())

    # Supply the known-good PCR snapshot and log to the verifier VM. Replay
    # there once to provision the key used by the mock services.
    with subtest("verifier replays IMA to vTPM PCR 10 and extracts the TARAKO key"):
        attester.succeed("test -c /dev/tarako")
        # Read PCR first: later measurements may append to the log, but the
        # key must be in the prefix that matches this snapshot.
        pcr = json.loads(attester.succeed("systemd-analyze --json=short pcrs 10"))[0]["sha256"]
        ima_log = attester.succeed(f"cat {IMA_LOG}")
        tak = verifier.succeed(f"printf %s {quote(ima_log)} | tarako-measured-tak {quote(pcr)}").strip()

    with subtest("provision the mock platform signer and verifier trust"):
        for machine in (mock, verifier):
            machine.succeed(f"printf %s {quote(tak)} | xxd -r -p > /run/tls-attestation/tak.bin")
        mock.succeed("setup-certificate mock /run/tls-attestation")
        platform_ca = mock.succeed("cat /run/tls-attestation/platform-ca.pem")
        verifier.succeed(f"printf %s {quote(platform_ca)} > /run/tls-attestation/platform-ca.pem")

    with subtest("generate the verifier signing key and give its public key to the client"):
        verifier.succeed(
            "umask 077; openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 "
            "-out /run/tls-attestation/signing.key && openssl pkey -in /run/tls-attestation/signing.key "
            "-pubout -out /run/tls-attestation/signing.pem"
        )
        verifier_key = verifier.succeed("cat /run/tls-attestation/signing.pem")
        client.succeed(f"printf %s {quote(verifier_key)} > /run/tls-attestation/verifier-public.pem")

    with subtest("generate the attester's HTTPS certificates and give the client the CA"):
        attester.succeed("setup-certificate attester /run/tls-attestation")
        tls_ca = attester.succeed("cat /run/tls-attestation/ca.pem")
        client.succeed(f"printf %s {quote(tls_ca)} > /run/tls-attestation/ca.pem")

    port_timeout = timedelta(seconds=30)


    def start_verifier(binary):
        verifier.succeed(f"printf %s {quote(digests[binary])} > /run/tls-attestation/digest")
        verifier.succeed("systemctl start quote-verifier.service")
        verifier.wait_for_open_port(5102, timeout=port_timeout)


    request_timeout = timedelta(seconds=20)
    client_args = "/run/tls-attestation/ca.pem http://verifier:5102/verify /run/tls-attestation/verifier-public.pem"
    with subtest("start the mock signer, verifier, and attester"):
        mock.succeed("systemctl start mock-quote.service")
        mock.wait_for_open_port(5101, timeout=port_timeout)
        start_verifier("tarako-tls-attester")
        attester.succeed("systemctl start tls-attester@server.service")
        attester.wait_for_open_port(8443, timeout=port_timeout)

    with subtest("attested HTTP/2 succeeds"):
        result = client.succeed(
            f"tarako-tls-client attester:8443 localhost {client_args}",
            timeout=request_timeout,
        )
        print(result, flush=True)
        assert result == "Tarako OK", result
    with subtest("offering h2 alone cannot skip attestation"):
        result = client.fail(
            "curl --silent --show-error --http2-prior-knowledge --tlsv1.3 --tls-max 1.3 "
            "--tls13-ciphers TLS_AES_128_GCM_SHA256 --connect-to localhost:8443:attester:8443 "
            "--cacert /run/tls-attestation/ca.pem https://localhost:8443/ 2>&1",
            timeout=request_timeout,
        )
        assert "curl: (35)" in result and "alert handshake failure" in result.lower(), result
    with subtest("verifier unavailable: no fallback to TLS alone"):
        verifier.succeed("systemctl stop quote-verifier.service")
        verifier.wait_until_fails("ss -Hlt 'sport = :5102' | grep -q .", timeout=port_timeout)
        result = client.fail(
            f"tarako-tls-client attester:8443 localhost {client_args} 2>&1",
            timeout=request_timeout,
        )
        print(result.rstrip(), flush=True)
        assert "verifier unavailable" in result, result
        start_verifier("tarako-tls-attester")
        result = client.succeed(
            f"tarako-tls-client attester:8443 localhost {client_args}",
            timeout=request_timeout,
        )
        print(result, flush=True)
        assert result == "Tarako OK", result
    with subtest("same-name certificate and key rotation"):
        attester.succeed("systemctl stop tls-attester@server.service")
        assert attester.succeed("openssl x509 -in /run/tls-attestation/server.pem -pubkey -noout") != (
            attester.succeed("openssl x509 -in /run/tls-attestation/rotated.pem -pubkey -noout")
        )
        attester.succeed("systemctl start tls-attester@rotated.service")
        attester.wait_for_open_port(8443, timeout=port_timeout)
        result = client.succeed(
            f"tarako-tls-client attester:8443 localhost {client_args}",
            timeout=request_timeout,
        )
        print(result, flush=True)
        assert result == "Tarako OK", result
        attester.succeed("systemctl stop tls-attester@rotated.service")

    with subtest("configure the verifier for the fault-test attester"):
        verifier.succeed("systemctl stop quote-verifier.service")
        start_verifier("tarako-tls-attester-test")

    with subtest("fault-test attester succeeds without faults"):
        attester.succeed("systemctl start tls-attester-fault@valid.service")
        attester.wait_for_open_port(8443, timeout=port_timeout)
        result = client.succeed(
            f"tarako-tls-client attester:8443 localhost {client_args}",
            timeout=request_timeout,
        )
        print(result, flush=True)
        assert result == "Tarako OK", result
        attester.succeed("systemctl stop tls-attester-fault@valid.service")

    # The fault-test binary modifies the evidence after obtaining real TARAKO
    # and mock platform quotes. All cases use the same certificate and key.
    evidence_errors = {
        "valid": None,
        "tarako": "verifier rejected: tarako",
        "platform": "verifier rejected: platform",
        "both": "verifier rejected: platform",  # Platform is checked first.
    }
    for mode, hostname in product(evidence_errors, ("localhost", "wrong.example")):
        reason = evidence_errors[mode] if hostname == "localhost" else "TLS authentication:"
        if reason is None:
            continue  # The all-valid case already ran above.
        with subtest(f"reject evidence mode={mode}, hostname={hostname}"):
            unit = f"tls-attester-fault@{mode}"
            attester.succeed(f"systemctl start {unit}.service")
            attester.wait_for_open_port(8443, timeout=port_timeout)
            result = client.fail(
                f"tarako-tls-client attester:8443 {hostname} {client_args} 2>&1",
                timeout=request_timeout,
            )
            print(result.rstrip(), flush=True)
            assert reason in result, result
            attester.succeed(f"systemctl stop {unit}.service")
  '';
}
