# Remote attestation integration test.
#
# The attester generates a fresh kernel-held ECDSA P-256 key on every boot,
# records its compressed public key in IMA, and signs an fs-verity-protected
# application's response to a verifier nonce. The test validates the IMA
# record, key freshness, signed inputs, ECDSA signature, and Background-Check
# routing through a separate Client/Relying Party.
import hashlib
import json

IMA_LOG = "/sys/kernel/security/integrity/ima/ascii_runtime_measurements"
PUBKEY_EVENT = "public-key-generate"
SPKI_P256_PREFIX_HEX = "3039301306072a8648ce3d020106082a8648ce3d030107032200"


def wait_for_tarako():
    attester.wait_until_succeeds("grep -q '^tarako ' /proc/modules", timeout=30)


def read_measured_pubkey():
    ima_log = attester.wait_until_succeeds(
        f"grep -q '{PUBKEY_EVENT}' {IMA_LOG} && cat {IMA_LOG}",
        timeout=30,
    )
    print("IMA log:\n" + ima_log)

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


def write_hex(machine, path, data_hex):
    machine.succeed(f"printf %s '{data_hex}' | xxd -r -p > {path}")


def expected_request_binding(request_value, nonce_hex):
    context = json.dumps(
        {"nonce": nonce_hex, "request": request_value},
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    return hashlib.sha256(b"TARAKO-TQ-REQUEST-V1\0" + context).digest()


attester.start(allow_reboot=True)
verifier.start()
client.start()
verifier.wait_for_unit("tarako-verifier.service")

# Verify that key generation is fresh across boots.
attester.wait_for_unit("default.target")
wait_for_tarako()
first_pubkey = read_measured_pubkey()

# NixOS VM roots are ext4, but their default mkfs feature set does not include
# fs-verity. Enable it on the existing root filesystem; the reboot needed for
# the key-freshness check also makes the kernel observe the new feature.
root_device = attester.succeed("findmnt -n -o SOURCE /").strip()
attester.succeed(f"tune2fs -O verity {root_device}")

attester.reboot()
attester.wait_for_unit("default.target")
wait_for_tarako()
pubkey = read_measured_pubkey()
assert pubkey != first_pubkey, "public key was reused across boots"

# Wrap the raw compressed point in a P-256 SubjectPublicKeyInfo and ensure
# OpenSSL accepts it. The fixed prefix contains the EC and prime256v1 OIDs.
write_hex(attester, "/tmp/ima-pubkey.der", SPKI_P256_PREFIX_HEX + pubkey.hex())
attester.succeed(
    "openssl pkey -pubin -inform DER -in /tmp/ima-pubkey.der -text -noout"
)

# Start the disabled-at-boot Attester service. Its service script copies the Go
# webserver to mutable storage, enables fs-verity, and execs that same file as
# the long-running process that invokes TARAKO_SIGN_DATA.
attester.succeed("systemctl start tarako-attester.service")
attester.wait_for_unit("tarako-attester.service")
fsverity_output = attester.wait_until_succeeds(
    "fsverity measure /var/lib/tarako/tarako-attester",
    timeout=30,
)
fsverity_digest = bytes.fromhex(fsverity_output.split()[0].split(":", 1)[1])

# Provision the approved executable digest and measured TAK public key as the
# appraisal policy of the already-running Verifier. TDX/IMA appraisal is
# outside this test; the network flow tests only nonce-bound Tarako Quotes.
verifier.succeed("install -d -m 700 /var/lib/tarako")
write_hex(verifier, "/var/lib/tarako/trusted-tak.bin", pubkey.hex())
verifier.succeed(
    f"printf '%s\\n' '{fsverity_digest.hex()}' "
    "> /var/lib/tarako/approved-digest"
)

# Repeat identical Client requests. The Verifier must generate a distinct nonce
# and request binding for each one, verify D || U and TAKpriv's signature, and
# return an accepted result. The Client never selects a nonce; it relays the
# Verifier-generated nonce to the Attester with the application request.
request_value = "repeatable-client-request"
client_command = (
    "tarako-client "
    "--trusted-root-ca /etc/tarako/root-ca.crt "
    f"verifier attester {request_value}"
)
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
