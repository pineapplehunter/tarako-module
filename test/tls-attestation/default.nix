{ lib, ... }:
let
  state = "/run/tls-attestation";
  measured = "/mnt/tls-attestation";
  # Tests provision keys and policy first, then start these units explicitly.
  service = command: {
    after = [ "network.target" ];
    serviceConfig = {
      Type = "exec";
      ExecStart = lib.concatStringsSep " " command;
    };
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
          pkgs.tls-attester
          pkgs.e2fsprogs
          pkgs.fsverity-utils
          pkgs.openssl
          pkgs.tpm2-tools
        ];
        networking.firewall.allowedTCPPorts = [ 8443 ];
        systemd.services."tls-attester@" = service [
          "${measured}/tarako-tls-attester"
          "0.0.0.0:8443"
          "${state}/%i.pem"
          "${state}/%i.key"
          "http://mock:5101/quote"
        ];
        systemd.services."tls-attester-fault@" = service [
          "${measured}/tarako-tls-attester-test"
          "0.0.0.0:8443"
          "${state}/server.pem"
          "${state}/server.key"
          "http://mock:5101/quote"
          "%i"
        ];
      };
    client =
      { pkgs, ... }:
      {
        environment.systemPackages = [
          pkgs.tls-client
          pkgs.openssl
        ];
      };
    mock =
      { pkgs, ... }:
      {
        environment.systemPackages = [
          pkgs.openssl
          pkgs.xxd
        ];
        networking.firewall.allowedTCPPorts = [ 5101 ];
        systemd.services.mock-quote = service [
          "${lib.getExe' pkgs.tls-mock-services "tarako-mock-platform-signer"}"
          "--signing-key"
          "${state}/signing.key"
          "--signing-cert"
          "${state}/signing-cert.pem"
          "--tak-file"
          "${state}/tak.bin"
        ];
      };
    verifier =
      { pkgs, ... }:
      {
        environment.systemPackages = [
          pkgs.openssl
          pkgs.xxd
        ];
        networking.firewall.allowedTCPPorts = [ 5102 ];
        systemd.services.quote-verifier = service [
          "${lib.getExe' pkgs.tls-mock-services "tarako-tls-verifier"}"
          "--signing-key"
          "${state}/signing.key"
          "--tak-file"
          "${state}/tak.bin"
          "--platform-ca"
          "${state}/platform-ca.pem"
          "--digest-file"
          "${state}/digest"
        ];
      };
  };

  testScript = ''
    """Exercise real Tarako ioctls and TLS, with a mock (not TDX) platform signer."""
    from datetime import timedelta
    from hashlib import new, sha256
    from itertools import product
    from shlex import quote
    from struct import pack

    start_all()

    STATE = "/run/tls-attestation"
    MEASURED = "/mnt/tls-attestation"
    IMA_LOG = "/sys/kernel/security/integrity/ima/ascii_runtime_measurements_sha256"


    def measured_tak(log, expected_pcr):
        pcr = bytes(32)
        tak = None
        for line in log.splitlines():
            index, digest, template, *fields = line.split()
            if index != "10":
                continue
            bank_digest = bytes.fromhex(digest)
            assert len(bank_digest) == 32, "expected a SHA-256 IMA bank digest"
            if template == "ima-buf" and len(fields) >= 2 and fields[1] == "public-key-generate":
                assert tak is None, "multiple TARAKO public-key events in IMA"
                hash_field, event_name, payload = fields
                algorithm, inner_digest = hash_field.split(":", 1)
                tak = bytes.fromhex(payload)
                assert len(tak) == 33 and tak[0] in (2, 3), "invalid compressed TARAKO public key"
                inner = new(algorithm, tak).digest()
                assert inner.hex() == inner_digest, "TARAKO public-key payload digest mismatch"
                # Rebuild ima-buf so the PCR match also commits to the displayed key.
                data = (algorithm.encode() + b":\0" + inner, event_name.encode() + b"\0", tak)
                encoded = b"".join(pack("<I", len(field)) + field for field in data)
                assert sha256(encoded).digest() == bank_digest, "TARAKO IMA template digest mismatch"
            pcr = sha256(pcr + (bank_digest if any(bank_digest) else b"\xff" * 32)).digest()
            if pcr == expected_pcr:
                assert tak is not None, "TARAKO public key is outside the matching IMA prefix"
                return tak.hex()
        raise AssertionError("SHA-256 IMA log did not replay to vTPM PCR 10")


    def write_public(machine, name, contents):
        machine.succeed(f"printf %s {quote(contents)} > {STATE}/{name}")


    def start_service(machine, unit, port):
        machine.succeed(f"systemctl start {unit}.service")
        machine.wait_for_open_port(port, timeout=timedelta(seconds=30))


    def server_log(unit):
        attester.succeed("journalctl --sync")
        return attester.succeed(f"journalctl -u {unit}.service -o cat --no-pager")


    def request_count(unit):
        return server_log(unit).count("HTTP request accepted")


    def check_request(unit, hostname="localhost", rejection=None):
        before = request_count(unit)
        status, output = client.execute(
            f"timeout 20s tarako-tls-client attester:8443 {hostname} {STATE}/ca.pem "
            f"http://verifier:5102/verify {STATE}/verifier-public.pem 2>&1"
        )
        if rejection is None:
            assert status == 0 and output == "Tarako OK", output
            assert request_count(unit) == before + 1, output
        else:
            assert request_count(unit) == before, output
            assert 0 < status < 124, (status, output)
            if rejection:
                assert rejection in output, output


    for machine in (attester, client, verifier, mock):
        machine.wait_for_unit("multi-user.target")
        machine.succeed(f"install -d -m 0700 {STATE}")

    # Format a private ext4 filesystem with verity from the outset. This does not
    # change the VM's root filesystem and does not require a reboot.
    attester.succeed(
        f"mkdir -p {MEASURED} && truncate -s 128M {STATE}/verity.img && "
        f"mkfs.ext4 -q -F -O verity {STATE}/verity.img && "
        f"mount -o loop {STATE}/verity.img {MEASURED}"
    )

    digests = {}
    for binary in ("tarako-tls-attester", "tarako-tls-attester-test"):
        path = f"{MEASURED}/{binary}"
        attester.succeed(
            f"install -m755 $(command -v {binary}) {path} && "
            f"fsverity enable --hash-alg=sha256 --block-size=1024 {path}"
        )
        measured = attester.succeed(f"fsverity measure {path}").split()[0]
        algorithm, digest = measured.split(":")
        assert algorithm == "sha256" and len(bytes.fromhex(digest)) == 32, measured
        digests[binary] = digest

    # Check the boot log before using its key to bootstrap the mock services.
    with subtest("IMA replay to vTPM PCR 10 binds the TARAKO public key"):
        attester.succeed("test -c /dev/tarako")
        # Read PCR first: later measurements may append to the log, but the
        # key must be in the prefix that matches this snapshot.
        pcr = bytes.fromhex(attester.succeed(
            f"tpm2_pcrread -T device:/dev/tpmrm0 -o {STATE}/ima.pcr sha256:10 >/dev/null && "
            f"od -An -v -tx1 {STATE}/ima.pcr"
        ))
        assert len(pcr) == 32, "expected one SHA-256 PCR value"
        tak = measured_tak(attester.succeed(f"cat {IMA_LOG}"), pcr)
    for machine in (mock, verifier):
        machine.succeed(f"printf %s {quote(tak)} | xxd -r -p > {STATE}/tak.bin")
    # The platform root stands in for Intel's CA. The signer gets a leaf, not the
    # root key. These certificates never participate in web TLS authentication.
    mock.succeed(f"""
        set -e
        cd {STATE}
        umask 077
        openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -noenc \\
            -days 2 -subj '/CN=Mock Platform CA' -keyout platform-ca.key -out platform-ca.pem \\
            -addext 'basicConstraints=critical,CA:TRUE,pathlen:0' \\
            -addext 'keyUsage=critical,keyCertSign,cRLSign'
        openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -noenc \\
            -subj '/CN=Mock Platform Quote Signer' -keyout signing.key -out signing.csr
        printf '%s\\n' 'basicConstraints=critical,CA:FALSE' 'keyUsage=critical,digitalSignature' > signing.ext
        openssl x509 -req -in signing.csr -CA platform-ca.pem -CAkey platform-ca.key \\
            -CAcreateserial -days 1 -extfile signing.ext -out signing-cert.pem
        rm platform-ca.key
    """)
    platform_ca = mock.succeed(f"cat {STATE}/platform-ca.pem")
    for machine in (attester, client, verifier):
        write_public(machine, "platform-ca.pem", platform_ca)

    verifier.succeed(
        f"umask 077; openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 "
        f"-out {STATE}/signing.key && openssl pkey -in {STATE}/signing.key "
        f"-pubout -out {STATE}/signing.pem"
    )
    write_public(client, "verifier-public.pem", verifier.succeed(f"cat {STATE}/signing.pem"))

    attester.succeed(f"""
        set -e
        cd {STATE}
        umask 077
        openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \\
            -days 2 -subj '/CN=HTTPS Test CA' -keyout ca.key -out ca.pem \\
            -addext 'basicConstraints=critical,CA:TRUE,pathlen:0' \\
            -addext 'keyUsage=critical,keyCertSign,cRLSign'
        printf '%s\\n' 'subjectAltName=DNS:localhost' 'extendedKeyUsage=serverAuth' > server.ext
        for cert in server rotated; do
            openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \\
                -subj /CN=localhost -keyout "$cert.key" -out "$cert.csr"
            openssl x509 -req -in "$cert.csr" -CA ca.pem -CAkey ca.key \\
                -CAcreateserial -days 1 -extfile server.ext -out "$cert.pem"
        done
        rm ca.key
    """)
    write_public(client, "ca.pem", attester.succeed(f"cat {STATE}/ca.pem"))
    assert attester.succeed(f"openssl x509 -in {STATE}/server.pem -pubkey -noout") != (
        attester.succeed(f"openssl x509 -in {STATE}/rotated.pem -pubkey -noout")
    )

    start_service(mock, "mock-quote", 5101)


    def start_verifier(binary):
        write_public(verifier, "digest", digests[binary])
        start_service(verifier, "quote-verifier", 5102)


    normal = "tarako-tls-attester"
    faultable = "tarako-tls-attester-test"
    baseline = "tls-attester@server"
    rotated = "tls-attester@rotated"
    start_verifier(normal)
    start_service(attester, baseline, 8443)
    with subtest("attested HTTP/2 succeeds"):
        check_request(baseline)
    with subtest("offering h2 alone cannot skip attestation"):
        before = request_count(baseline)
        status, output = client.execute(
            f"timeout 20s openssl s_client -connect attester:8443 -servername localhost "
            f"-verify_hostname localhost -verify_return_error -CAfile {STATE}/ca.pem "
            "-tls1_3 -alpn h2 -ciphersuites TLS_AES_128_GCM_SHA256 </dev/null 2>&1"
        )
        assert status == 1 and "no peer certificate available" in output, (status, output)
        log = server_log(baseline)
        assert "missing required attestation offer" in log, log
        assert log.count("HTTP request accepted") == before, output
    with subtest("verifier unavailable: no fallback to TLS alone"):
        verifier.succeed("systemctl stop quote-verifier.service")
        verifier.wait_until_fails("ss -Hlt 'sport = :5102' | grep -q .", timeout=timedelta(seconds=30))
        check_request(baseline, rejection="verifier unavailable")
        start_verifier(normal)
        check_request(baseline)
    attester.succeed(f"systemctl stop {baseline}.service")
    with subtest("same-name certificate and key rotation"):
        start_service(attester, rotated, 8443)
        check_request(rotated)
        attester.succeed(f"systemctl stop {rotated}.service")

    verifier.succeed("systemctl stop quote-verifier.service")
    start_verifier(faultable)
    # The test binary applies these faults after the real ioctl and mock quote.
    # Both hostname rows use the exact same certificate and key for each mode.
    for mode, tls_ok in product(("valid", "tarako", "platform", "both"), (True, False)):
        with subtest(f"TLS valid={tls_ok}, evidence mode={mode}"):
            unit = f"tls-attester-fault@{mode}"
            start_service(attester, unit, 8443)
            if not tls_ok:
                hostname, rejection = "wrong.example", "TLS authentication:"
            else:
                hostname = "localhost"
                rejection = {
                    "valid": None,
                    "tarako": "verifier rejected: tarako",
                    "platform": "verifier rejected: platform",
                    "both": "verifier rejected: platform",  # Checked first.
                }[mode]
            check_request(unit, hostname, rejection)
            attester.succeed(f"systemctl stop {unit}.service")
  '';
}
