{ lib, ... }:
{
  name = "tarako-quote-attestation";

  nodes = {
    attester = import ./simple-attester.nix;

    verifier =
      { pkgs, ... }:
      let
        tarako-verifier = pkgs.writers.writePython3Bin "tarako-verifier" {
          libraries = with pkgs.python3Packages; [
            cryptography
            flask
          ];
        } ./verifier.py;
      in
      {
        environment = {
          systemPackages = [ pkgs.xxd ];
          etc = {
            "tarako/verifier.crt".source = ./assets/verifier.crt;
            "tarako/verifier-key.pem" = {
              source = ./assets/verifier-key.pem;
              mode = "0400";
            };
          };
        };
        networking.firewall.allowedTCPPorts = [ 5001 ];

        systemd.services.tarako-verifier = {
          description = "Tarako Quote Verifier";
          wantedBy = [ "multi-user.target" ];
          after = [ "network.target" ];
          serviceConfig = {
            ExecStart = lib.concatStringsSep " " [
              "${tarako-verifier}/bin/tarako-verifier"
              "--policy-directory /var/lib/tarako"
              "--certificate /etc/tarako/verifier.crt"
              "--signing-key /etc/tarako/verifier-key.pem"
            ];
            Restart = "on-failure";
            RestartSec = 1;
          };
        };
      };

    client =
      { pkgs, ... }:
      let
        tarako-client = pkgs.writers.writePython3Bin "tarako-client" {
          libraries = with pkgs.python3Packages; [
            cryptography
            requests
          ];
        } ./client.py;
      in
      {
        environment.systemPackages = [
          tarako-client
          pkgs.openssl
        ];
        security.pki.certificateFiles = [ ./assets/root-ca.crt ];
      };
  };

  testScript = ''
    # Remote attestation integration test.
    #
    # Enroll the measured key and executable digest, then exercise the
    # Background-Check flow through a separate Client/Relying Party.
    import hashlib
    import json

    IMA_LOG = "/sys/kernel/security/integrity/ima/ascii_runtime_measurements"


    def write_hex(machine, path, data_hex):
        machine.succeed(f"printf %s '{data_hex}' | xxd -r -p > {path}")


    def expected_request_binding(request_value, nonce_hex):
        context = json.dumps(
            {"nonce": nonce_hex, "request": request_value},
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode()
        return hashlib.sha256(b"TARAKO-TQ-REQUEST-V1\0" + context).digest()


    start_all()

    with subtest("wait for the quote verifier"):
        verifier.wait_for_unit("tarako-verifier.service")

    with subtest("read the TARAKO key from the attester's IMA log"):
        pubkey = attester.succeed(
            f"awk '$5 == \"public-key-generate\" {{print $6; exit}}' {IMA_LOG}"
        ).strip()
        assert pubkey, "TARAKO public key is missing from IMA"

    with subtest("prepare the fs-verity filesystem and start the quote attester"):
        # Give the service a verity-enabled volume without changing the root filesystem.
        attester.succeed(
            "mkdir -p /var/lib/tarako && truncate -s 128M /tmp/verity.img && "
            "mkfs.ext4 -q -F -O verity /tmp/verity.img && "
            "mount -o loop /tmp/verity.img /var/lib/tarako"
        )

        # Start the disabled-at-boot Attester service. Its service script copies the
        # webserver to mutable storage, enables fs-verity, and execs that same file as
        # the long-running process that invokes TARAKO_SIGN_DATA.
        attester.succeed("systemctl start tarako-simple-attester.service")
        attester.wait_for_unit("tarako-simple-attester.service")
        fsverity_output = attester.wait_until_succeeds(
            "fsverity measure /var/lib/tarako/tarako-simple-attester",
            timeout=30,
        )
        fsverity_digest = bytes.fromhex(fsverity_output.split()[0].split(":", 1)[1])

    with subtest("provision the verifier with the measured key and approved digest"):
        # Provision the approved executable digest and measured TAK public key as the
        # appraisal policy of the already-running Verifier. TDX/IMA appraisal is
        # outside this test; the network flow tests only nonce-bound Tarako Quotes.
        verifier.succeed("install -d -m 700 /var/lib/tarako")
        write_hex(verifier, "/var/lib/tarako/trusted-tak.bin", pubkey)
        verifier.succeed(
            f"printf '%s\\n' '{fsverity_digest.hex()}' "
            "> /var/lib/tarako/approved-digest"
        )

    with subtest("verify fresh nonces and bindings for identical requests"):
        # Repeat identical Client requests. The Verifier must generate a distinct nonce
        # and request binding for each one, verify D || U and TAKpriv's signature, and
        # return an accepted result. The Client never selects a nonce; it relays the
        # Verifier-generated nonce to the Attester with the application request.
        request_value = "repeatable-client-request"
        client_command = f"tarako-client verifier attester {request_value}"
        first = json.loads(client.succeed(client_command))
        second = json.loads(client.succeed(client_command))
        print("first result:", first)
        print("second result:", second)

        for result in (first, second):
            assert result["accepted"] is True
            assert result["request"] == request_value
            assert result["digest"] == fsverity_digest.hex()
            assert len(bytes.fromhex(result["nonce"])) == 32

            binding = expected_request_binding(request_value, result["nonce"])
            assert result["request_binding"] == binding.hex()
            user_data = binding + bytes(128 - len(binding))
            expected_hash = hashlib.sha256(fsverity_digest + user_data).hexdigest()
            assert result["kernel_hash"] == expected_hash

        assert first["nonce"] != second["nonce"], "Verifier reused a request nonce"
        assert first["request_binding"] != second["request_binding"], (
            "identical requests were not bound to distinct Verifier nonces"
        )
  '';
}
