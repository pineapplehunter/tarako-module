# Remote attestation integration test.
#
# Flow:
#   1. Attester VM boots, loads the tarako module, creates a verity-protected
#      copy of tarako-app, and starts a TCP responder on port 9999.
#   2. Verifier VM boots, generates a random 32-byte nonce, and sends it to
#      the attester over TCP.
#   3. Attester's responder runs `/mnt/tarako-app <nonce_hex>`, which zero-pads
#      the nonce to 1024-bit opaque user data and calls TARAKO_SIGN_DATA. The
#      kernel signs SHA256(fsverity_digest || user_data) and returns
#      (hash, sig_r, sig_s, pubkey).
#   4. Verifier prints the response, which the test driver captures.
#   5. Test driver verifies:
#      - The user data contains the nonce followed by zero padding.
#      - The ECDSA signature verifies against the public key via openssl.
import os, binascii, hashlib, base64

start_all()

# ===== Phase 1: Attester setup =====
attester.wait_for_unit("default.target")

attester.succeed("modprobe ecc 2>/dev/null || true")
attester.succeed("modprobe tarako")

dmesg = attester.succeed("dmesg")
for line in dmesg.split("\n"):
    if "loading, generating ECDSA P-256 key pair" in line or "key pair generated, public key ready" in line:
        print(line)

assert "loading, generating ECDSA P-256 key pair" in dmesg
assert "key pair generated, public key ready" in dmesg

# Critical-data measurements use ima-buf (d-ng|n-ng|buf), even when ima-ng is
# the default template. Verify that buf contains the compressed SEC1 public key
# and that d-ng is its digest using the configured IMA hash.
import time
time.sleep(1)
ima_log = attester.succeed("cat /sys/kernel/security/integrity/ima/ascii_runtime_measurements")
print("IMA log:")
for line in ima_log.strip().split("\n"):
    print("  " + line)
assert "public-key-generate" in ima_log, "public-key-generate event not found in IMA log"

pkg_line = next(line for line in ima_log.strip().split("\n") if "public-key-generate" in line)
parts = pkg_line.split()
# Format: PCR template_hash ima-buf algo:digest event_name event_data
assert parts[2] == "ima-buf", f"unexpected IMA template: {parts[2]}"
ima_digest_full = parts[3]
ima_algorithm, ima_digest_hex = ima_digest_full.split(":", 1)
event_data_idx = parts.index("public-key-generate") + 1
compressed_pubkey = bytes.fromhex(parts[event_data_idx])
assert len(compressed_pubkey) == 33, (
    f"IMA public key has {len(compressed_pubkey)} bytes, expected 33"
)
assert compressed_pubkey[0] in (0x02, 0x03), "IMA public key is not a compressed SEC1 point"
ref_digest = hashlib.new(ima_algorithm, compressed_pubkey).hexdigest()
assert ima_digest_hex == ref_digest, f"IMA digest mismatch: {ima_digest_hex} != {ref_digest}"
print(f"IMA digest matches {ima_algorithm} of the raw public key")

# Set up fs-verity protected binary on attester.
# The kernel module rejects ioctls from non-verity processes, so tarako-app
# must be on a verity-protected filesystem.
attester.succeed("dd if=/dev/zero of=/tmp/verity.img bs=1M count=64")
attester.succeed("mkfs.ext4 -O verity /tmp/verity.img")
attester.succeed("mkdir -p /mnt && mount /tmp/verity.img /mnt")
attester.succeed("cp $(which tarako-app) /mnt/")
attester.succeed("fsverity enable --block-size=1024 /mnt/tarako-app")

fsverity_out = attester.succeed("fsverity measure /mnt/tarako-app")
fsverity_digest_hex = fsverity_out.strip().split()[0].split(":")[1]
print("fs-verity digest hex:", fsverity_digest_hex)

# Start TCP responder on attester (background).
attester.succeed("nohup tarako-responder > /tmp/responder.log 2>&1 &")

# Attester is reachable by its node name in the VM network
attester_ip = "attester"
print("attester hostname:", attester_ip)

# ===== Phase 2: Remote attestation =====
# Verifier generates a random nonce and sends it over the network.

nonce = os.urandom(32)
nonce_hex = binascii.hexlify(nonce).decode()
print("verifier nonce:", nonce_hex)

out = verifier.succeed(f"tarako-client {attester_ip} {nonce_hex}")
print(out)

# ===== Phase 3: Cryptographic verification via openssl =====

assert "TARAKO_HELLO" in out
assert "TARAKO_GET_PUBKEY" in out
assert "TARAKO_SIGN_DATA" in out
assert "public key (33 bytes) DER:" in out

# Verify the 32-byte nonce was preserved and padded to 1024-bit user data.
user_data = nonce + bytes(128 - len(nonce))
user_data_line = next(line for line in out.split("\n") if line.startswith("user data:"))
response_user_data_hex = user_data_line[len("user data:"):].strip()
expected_user_data_hex = user_data.hex()
assert response_user_data_hex == expected_user_data_hex, (
    f"user data mismatch: {response_user_data_hex} != {expected_user_data_hex}"
)
print("Nonce input and zero padding verified")

# Print reference hash for debugging
msg_raw = binascii.unhexlify(fsverity_digest_hex) + user_data
hash_line = next(line for line in out.split("\n") if line.startswith("hash:"))
kernel_hash_hex = hash_line[5:].strip()
ref_hash = hashlib.sha256(msg_raw).hexdigest()
print("kernel hash:", kernel_hash_hex)
print("reference hash:", ref_hash)
assert kernel_hash_hex == ref_hash, (
    f"kernel hash mismatch: {kernel_hash_hex} != {ref_hash}"
)
print("Hash matches")

# Extract hex DER public key and signature from output
out_lines = out.split("\n")
pubkey_idx = next(i for i, l in enumerate(out_lines) if l.startswith("public key (33 bytes) DER:"))
pubkey_hex = next(l for l in out_lines[pubkey_idx + 1:] if l.strip())
sig_idx = next(i for i, l in enumerate(out_lines) if l.startswith("signature DER:"))
sig_hex = next(l for l in out_lines[sig_idx + 1:] if l.strip())
print("=== Public key DER (hex) ===")
print(pubkey_hex)
print("=== Signature DER (hex) ===")
print(sig_hex)

# Write message and DER files to attester, then verify via openssl
pubkey_der_bytes = bytes.fromhex(pubkey_hex)
# The SubjectPublicKeyInfo BIT STRING ends with the compressed SEC1 point.
assert pubkey_der_bytes.endswith(compressed_pubkey), "IMA key differs from the ioctl public key"
sig_der_bytes = bytes.fromhex(sig_hex)
attester.succeed('echo "{}" | base64 -d > /tmp/pubkey.der'.format(base64.b64encode(pubkey_der_bytes).decode()))
attester.succeed('echo "{}" | base64 -d > /tmp/sig.der'.format(base64.b64encode(sig_der_bytes).decode()))
attester.succeed('echo "{}" | base64 -d > /tmp/msg.bin'.format(base64.b64encode(msg_raw).decode()))
vout = attester.succeed("openssl dgst -sha256 -verify /tmp/pubkey.der -keyform DER -signature /tmp/sig.der /tmp/msg.bin")
assert "Verified OK" in vout, f"openssl verification failed: {vout}"
print("ECDSA signature verified OK")
