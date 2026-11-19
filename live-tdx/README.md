# Live TDX attestation

## Run from the TDX host with the NixOS test driver

Run the driver on an x86-64 TDX host **outside** the Nix build sandbox.
The host must provide KVM, vhost-vsock and a working Intel QGS on
vsock CID 2, port 4050. The driver boots a TDX attester and a regular VM that
runs both the verifier and the client. No preconfigured guest or SSH tunnel
is needed. The verifier VM needs network access to your collateral source.

Choose exactly one mode. First collect candidate reference values from the
test image on a known-good host. This does **not** enroll those values or run
the attestation test:

```sh
TARAKO_TDX_WRITE_CANDIDATE=./candidate.json nix run .#live-tdx-test-driver
```

Review the candidate and save the approved values separately as `reviewed.json`.
Then run:

```sh
TARAKO_TDX_POLICY=./reviewed.json nix run .#live-tdx-test-driver
```

The driver sets up fs-verity, test HTTPS credentials, the IMA log service, and
three loopback verifier instances. Expect four `PASS` lines: valid GET, wrong
TLS hostname, wrong application digest, and IMA replay mismatch. The verifier
uses Intel PCS by default; set `TARAKO_TDX_QCNL_CONFIG` to the absolute path of
an operator-supplied QCNL JSON file to use a different collateral source.
The existing `TARAKO_TDX_QEMU` and `TARAKO_TDX_FIRMWARE` overrides also apply.

## Manual split-host setup

This opt-in suite connects to your **already running Intel TDX guest**. It does
not provision the guest, SSH into it, or use the four-VM mock signer. The host
of the verifier VM runs the one-shot client. The verifier VM never contacts the
TDX guest. Only the client fetches its plain HTTP IMA log.

## TDX guest

Use a measured guest kernel with TARAKO, the SHA-384 IMA bank and the pinned
IMA-to-RTMR2 extender (see `kernel/ima-rtmr-kernel.nix`). Ensure the extender is
active **before** TARAKO records its key. The build and boot you approve must
protect the TARAKO signer and enable the intended measurement policy. A fresh
Intel quote is required on each handshake: mount configfs, ensure the TDX
guest driver is active, and provision your TDX host's working quote/QGS path. The guest attester uses
`/sys/kernel/config/tsm/report`, not a network mock signer or a local TDREPORT.

Copy the packaged `tarako-tdx-attester` to an fs-verity-capable filesystem,
enable fs-verity on that copy, and run that exact copy with access to
`/dev/tarako` and configfs. `attester.crt` and `attester.key` are the HTTPS
server credential; the CA, hostname, and TLS proof of possession are checked
normally, independently of Intel's quote PKI. Use a SAN matching the client's
URL and include intermediates in the certificate file as needed.

```sh
nix shell .#tls-attester nixpkgs#fsverity-utils
install -m755 "$(command -v tarako-tdx-attester)" /srv/tarako/attester
fsverity enable --hash-alg=sha256 /srv/tarako/attester
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

Forward host loopback to VM loopback, e.g. on the client machine run
`ssh -N -L 127.0.0.1:5102:127.0.0.1:5102 verifier-vm`. This is **not** SSH to the
TDX guest. Do not expose the verifier API on the LAN.

## Client and live suite

```sh
nix shell .#tls-attester --command tarako-tdx-client -v \
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
positive-test policy untouched. Then run:

```sh
nix run .#live-tdx-smoke -- \
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
