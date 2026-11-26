# Real-hardware TDX attestation

This directory contains the TDX guest configuration (`guest/`), verifier
(`verifier/`), and hardware runners (`tests/`). The regular
[`nix flake check` suites](../test/README.md) do not boot TDX guests.

The attested connection requires HTTP/2. Use the client and server from the
same checkout. When the server binary changes, collect and review its new
fs-verity digest before updating the policy.

## Run from the TDX host with the NixOS test driver

Run the driver on an x86-64 Ubuntu 26.04 LTS TDX host **outside** the Nix build
sandbox. The driver uses upstream QEMU from nixpkgs. The host must provide
KVM, vhost-vsock, and a working Intel QGS on
vsock CID 2, port 4050. The driver boots a TDX attester and a regular VM that
runs both the verifier and the client. No preconfigured guest or SSH tunnel
is needed. The verifier VM needs network access to your collateral source.

To check hardware setup without starting a verifier or contacting Intel PCS,
run the single-guest sanity test:

```sh
nix run .#real-hardware-basics
```

It checks that RTMR2 commits to the TARAKO key and that a fresh TDX quote
verifies offline against its nonce.

Run the complete TLS attestation test with:

```sh
nix run .#real-hardware-tls-attestation
```

The test collects a candidate from the guest it just booted and uses it only
for that run. It does not need a reviewed policy file or export one for reuse.
This tests the attestation flow, not whether the guest build should be trusted
by an external verifier. Strict Intel DCAP appraisal still applies.

The driver sets up fs-verity, test HTTPS credentials, the IMA log service, and
three loopback verifier instances. The four subtests check a successful GET
and rejection of a wrong TLS hostname, a wrong application digest, and an IMA
replay mismatch. The verifier uses Intel PCS by default; set
`TARAKO_TDX_QCNL_CONFIG` to the absolute path of an operator-supplied QCNL JSON
file to use a different collateral source.
Set `TARAKO_TDX_QEMU` to the path of a different TDX-capable QEMU binary
or `TARAKO_TDX_FIRMWARE` to a different TDVF image if needed.

## Export a candidate policy

On the TDX host, run:

```sh
policy_out=$(mktemp -d /tmp/tarako-policy.XXXXXX)
nix run .#real-hardware-export-policy -- --output_directory "$policy_out"
```

This boots one guest, writes an unreviewed `candidate.json` into the output
directory, and exits. It does not start a TLS server or verifier. Use the same
checkout and firmware for the export and attester-only runners. If the
measured boot or executable changes, collect and review a new candidate.

## Boot only the attester for external testing

This two-machine setup runs just the attester VM on the TDX host and runs
both the verifier and the client on a separate x86-64 Linux machine. Use the
same TARAKO checkout on both machines. The client machine needs Nix, OpenSSL,
SSH access to the TDX host, and HTTPS access to Intel PCS.

### Attester side (TDX host)

1. From the TARAKO checkout, choose the DNS name for the attester's HTTPS
   certificate. It can match the physical host's hostname or be different;
   it does not rename the host or need to resolve over DNS in this setup.

   ```sh
   out=$(mktemp -d /tmp/tarako-attester.XXXXXX)
   printf 'Attester output directory: %s\n' "$out"
   TARAKO_TDX_TLS_NAME=tdxbox.example.net \
     nix run .#real-hardware-attester-only -- --output_directory "$out"
   ```

2. Leave the driver running after it prints `Attester ready`. It exports
   `https-ca.pem` and `tls-name` to the printed directory. The separate
   policy runner above exports `candidate.json`. The attester stops on
   Ctrl-C, guest shutdown, or the one-hour test timeout.

### Client side (includes the verifier)

1. In a terminal in the TARAKO checkout, set the **SSH destination** for your
   physical TDX host and the output directories from the two runs. Copy the
   three files into a fresh directory **outside the checkout**:

   ```sh
   TDX_HOST=alice@tdxbox.example.net
   ATTESTER_OUT=/tmp/tarako-attester.REPLACE_ME
   POLICY_OUT=/tmp/tarako-policy.REPLACE_ME
   lab=$(mktemp -d /tmp/tarako-client.XXXXXX)
   printf 'Client work directory: %s\n' "$lab"
   scp "$TDX_HOST:$ATTESTER_OUT/https-ca.pem" \
       "$TDX_HOST:$POLICY_OUT/candidate.json" \
       "$TDX_HOST:$ATTESTER_OUT/tls-name" "$lab/"
   ```

2. Review the candidate against the guest build and boot you intend to trust.
   If approved, copy it to `reviewed.json`. Generate a separate verifier
   signing key here; **do not put it in the checkout or Nix store**:

   ```sh
   cp "$lab/candidate.json" "$lab/reviewed.json"
   (umask 077; openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 \
     -out "$lab/verifier.key")
   openssl pkey -in "$lab/verifier.key" -pubout -out "$lab/verifier.pub"
   ```

3. In the same terminal, configure Intel PCS and start the verifier on
   loopback:

   ```sh
   QCNL_CONF_PATH="$PWD/real-hardware/verifier/intel-pcs.json" \
     nix run .#live-tdx-verifier -- \
       --listen 127.0.0.1 --port 5102 \
       --policy "$lab/reviewed.json" --signing-key "$lab/verifier.key"
   ```

   Leave it running. If you use a PCCS, use your own QCNL config with TLS
   validation enabled.

4. In a second terminal on the client machine, open the tunnel to the TDX
   host. No SSH to the guest or to a separate verifier VM is needed:

   ```sh
   TDX_HOST=alice@tdxbox.example.net
   ssh -N -o ExitOnForwardFailure=yes \
     -L 127.0.0.1:8443:127.0.0.1:8443 -L 127.0.0.1:8080:127.0.0.1:8080 \
     "$TDX_HOST"
   ```

5. In a third terminal in the TARAKO checkout, use the printed client work
   directory. The client connects through loopback but still checks the
   configured DNS name in the attester certificate:

   ```sh
   lab=/tmp/tarako-client.REPLACE_ME
   nix shell .#tdx-client --command tarako-tdx-client -v \
     --ca "$lab/https-ca.pem" --verifier-key "$lab/verifier.pub" \
     --verifier http://127.0.0.1:5102/verify --tls-name "$(cat "$lab/tls-name")" \
     --ima-log-url http://127.0.0.1:8080/ima.log https://127.0.0.1:8443/
   ```

   Expect `Tarako OK` on stdout.

## Manual split-host setup

Use this setup if you already operate a TDX guest or want the verifier on its
own VM. Only the client contacts the guest; it relays the SHA-384 IMA log to
the verifier.

## TDX guest

Use a measured guest kernel with TARAKO and the pinned IMA-to-RTMR2 extender
(see `real-hardware/guest/ima-rtmr-kernel.nix`). Boot with `ima_hash=sha384` and ensure the
kernel exports `/sys/kernel/security/ima/ascii_runtime_measurements_sha384`
even when the guest has no TPM. Ensure the extender is active **before**
TARAKO records its key. The build and boot you approve must protect the TARAKO
signer and enable the intended measurement policy. A fresh Intel quote is
required on each handshake: mount configfs, ensure the TDX guest driver is
active, and provision your TDX host's working quote/QGS path. The guest attester
uses `/sys/kernel/config/tsm/report`, not a network mock signer or a local
TDREPORT.

Copy the packaged `tarako-tdx-attester` to an fs-verity-capable filesystem,
enable fs-verity on that copy, and run that exact copy with access to
`/dev/tarako` and configfs. `attester.crt` and `attester.key` are the HTTPS
server credential; the CA, hostname, and TLS proof of possession are checked
normally, independently of Intel's quote PKI. Use a SAN matching the client's
URL and include intermediates in the certificate file as needed.

```sh
nix shell .#tls-attester nixpkgs#fsverity-utils
install -m755 "$(command -v tarako-tdx-attester)" /srv/tarako/attester
fsverity enable --hash-alg=sha256 --block-size=1024 /srv/tarako/attester
/srv/tarako/attester 192.0.2.10:8443 attester.crt attester.key
```

Replace the example address with a private guest address. Also import
`tarako.nixosModules.tarakoTdxImaLog` in the guest, and set:

```nix
services.tarakoTdxImaLog = {
  enable = true;
  listen = "192.0.2.10";
};
```

Or, for a manual test, run `nix run .#live-tdx-ima-log -- --listen 192.0.2.10`
in a separate terminal. The service exposes only `/ima.log`. Limit access to
the client through your private network/firewall; the module opens no ports.
RTMR replay protects the integrity of the **matched prefix**, not confidentiality
or availability of the plain HTTP response.

Collect and review candidate values from a **known-good** build and boot:

```sh
nix run .#live-tdx-candidate-policy -- /srv/tarako/attester > candidate.json
```

Transfer only the reviewed policy to the verifier through a trusted path. Do
not generate an allowlist from the first untrusted quote. A different boot
configuration or executable build may require updated reference values. The
boot-specific TARAKO public key does not go into this policy.

## Verifier VM (x86-64 NixOS)

Import `tarako.nixosModules.tarakoTdxVerifier`. Prepare an operator-reviewed
policy, a P-256 signing private key, and an Intel QCNL config outside the store:

```nix
services.tarakoTdxVerifier = {
  enable = true;
  qcnlConfigFile = "/etc/tarako/qcnl.conf";
  instances.live = {
    port = 5102;
    policyFile = "/etc/tarako/reviewed-policy.json";
    signingKeyFile = "/var/lib/tarako/verifier.key";
  };
};
```

For example, use `openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256`
for the signing key and `openssl pkey -in verifier.key -pubout` for the
client's trusted copy of its public key. Keep the private key in the VM and
restrict file permissions. Use an operator-managed PCCS or Intel PCS collateral
with TLS validation enabled. See the DCAP package's
`share/tarako-dcap-verify/sgx_default_qcnl.conf` for Intel's sample, and the
[Intel PCS documentation](https://api.portal.trustedservices.intel.com/content/documentation.html).
The verifier requires current collateral and software QVL `OK`; it cannot fall
back to signature-only verification. Its wall clock must be trustworthy.

For DCAP `OUT_OF_DATE` (`0xa002`), follow Intel's
[TCB recovery guidance](https://www.intel.com/content/www/us/en/developer/topic-technology/software-security-guidance/trusted-computing-base-recovery-attestation.html)
and test a fresh quote after updating the host.

Forward host loopback to VM loopback, e.g. on the client machine run
`ssh -N -L 127.0.0.1:5102:127.0.0.1:5102 verifier-vm`. This is **not** SSH to the
TDX guest. Do not expose the verifier API on the LAN.

## Client and split-host TLS checks

```sh
nix shell .#tdx-client --command tarako-tdx-client -v \
  --ca https-ca.pem --verifier-key verifier.pub \
  --ima-log-url http://192.0.2.10:8080/ima.log \
  https://tdx-guest.test:8443/
```

During the TLS handshake, the client relays the fresh TDX and TARAKO evidence,
its expected TLS binder and leaf public-key hash, and the fetched IMA log. The
verifier checks boot references and REPORTDATA, replays the log to the quoted
RTMR2, and accepts a TARAKO key only from the matched prefix. A replay mismatch
can trigger a bounded client refetch; any final failure blocks the application
GET. The signed result is short-lived and bound to the exact handshake CMW.
Only the response body goes to stdout; `-v` sends progress and failure stages to
stderr, not raw evidence. The demo supports `GET /` and does not follow redirects.

For negative tests, add separate verifier instances with the **same signing
key**: `wrong-digest` on port 5103 with only `fsverity_digest` changed to a wrong
value, and `wrong-ima` on port 5104 with only `ima_start_rtmr2` changed to a
wrong value. Forward both ports on loopback like 5102. Leave the production or
positive-test policy untouched. Run the check on the client machine, which
does not need TDX hardware. The check expects `tarako-tdx-client` on `PATH`;
use both tools from the same checkout:

```sh
nix shell .#tdx-client .#tdx-tls-client-check \
  --command tarako-tdx-tls-client-check \
  --ca https-ca.pem --verifier-key verifier.pub \
  --ima-log-url http://192.0.2.10:8080/ima.log \
  --wrong-digest-verifier http://127.0.0.1:5103/verify \
  --wrong-ima-verifier http://127.0.0.1:5104/verify \
  https://tdx-guest.test:8443/
```

The suite checks success, a wrong TLS hostname, a wrong approved application
digest, and an IMA replay mismatch, without touching the attester machine.
It is not a hardware-free `nix flake check`; the verifier package's unit tests
mock only the output of DCAP to exercise IMA and TARAKO appraisal separately.
