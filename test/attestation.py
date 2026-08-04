# Remote attestation integration test.
#
# The attester generates a fresh kernel-held ECDSA P-256 key on every boot,
# records its compressed public key in IMA, and signs an fs-verity-protected
# application's response to a verifier nonce. The test validates the IMA
# record, key freshness, signed inputs, and ECDSA signature.
import hashlib
import os

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


def value_after_heading(output, heading):
    lines = output.splitlines()
    index = next(i for i, line in enumerate(lines) if line.startswith(heading))
    return next(line.strip() for line in lines[index + 1:] if line.strip())


def value_on_line(output, label):
    line = next(line for line in output.splitlines() if line.startswith(label))
    return line.removeprefix(label).strip()


def write_hex(path, data_hex):
    attester.succeed(f"printf %s '{data_hex}' | xxd -r -p > {path}")


attester.start(allow_reboot=True)
verifier.start()

# Verify that key generation is fresh across boots.
attester.wait_for_unit("default.target")
wait_for_tarako()
first_pubkey = read_measured_pubkey()

attester.reboot()
attester.wait_for_unit("default.target")
wait_for_tarako()
pubkey = read_measured_pubkey()
assert pubkey != first_pubkey, "public key was reused across boots"

# Wrap the raw compressed point in a P-256 SubjectPublicKeyInfo and ensure
# OpenSSL accepts it. The fixed prefix contains the EC and prime256v1 OIDs.
write_hex("/tmp/ima-pubkey.der", SPKI_P256_PREFIX_HEX + pubkey.hex())
attester.succeed(
    "openssl pkey -pubin -inform DER -in /tmp/ima-pubkey.der -text -noout"
)

# Create an fs-verity-protected copy of the client. The driver rejects signing
# requests from executables without fs-verity protection.
attester.succeed(
    "dd if=/dev/zero of=/tmp/verity.img bs=1M count=64 && "
    "mkfs.ext4 -O verity /tmp/verity.img && "
    "mkdir -p /mnt && mount /tmp/verity.img /mnt && "
    "cp $(which tarako-app) /mnt/ && "
    "fsverity enable --block-size=1024 /mnt/tarako-app"
)
fsverity_output = attester.succeed("fsverity measure /mnt/tarako-app")
fsverity_digest = bytes.fromhex(fsverity_output.split()[0].split(":", 1)[1])

attester.succeed("nohup tarako-responder > /tmp/responder.log 2>&1 &")

# Send a fresh challenge through the verifier VM.
nonce = os.urandom(32)
out = verifier.succeed(f"tarako-client attester {nonce.hex()}")
print(out)

for heading in ("TARAKO_HELLO", "TARAKO_GET_PUBKEY", "TARAKO_SIGN_DATA"):
    assert heading in out

# Verify the exact input hashed and signed by the kernel.
user_data = nonce + bytes(128 - len(nonce))
response_user_data = bytes.fromhex(value_on_line(out, "user data:"))
assert response_user_data == user_data, "nonce or zero padding changed"

message = fsverity_digest + user_data
kernel_hash = value_on_line(out, "hash:")
expected_hash = hashlib.sha256(message).hexdigest()
assert kernel_hash == expected_hash, f"kernel hash mismatch: {kernel_hash} != {expected_hash}"

# Verify that IMA and the ioctl expose the same key, then verify the signature.
pubkey_der_hex = value_after_heading(out, "public key (33 bytes) DER:")
signature_der_hex = value_after_heading(out, "signature DER:")
assert bytes.fromhex(pubkey_der_hex).endswith(pubkey), (
    "IMA key differs from the ioctl public key"
)

write_hex("/tmp/pubkey.der", pubkey_der_hex)
write_hex("/tmp/signature.der", signature_der_hex)
write_hex("/tmp/message.bin", message.hex())
verification = attester.succeed(
    "openssl dgst -sha256 -verify /tmp/pubkey.der -keyform DER "
    "-signature /tmp/signature.der /tmp/message.bin"
)
assert "Verified OK" in verification, f"signature verification failed: {verification}"
