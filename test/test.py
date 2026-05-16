import binascii, hashlib
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

nonce = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"

machine.wait_for_unit("default.target")

machine.succeed("modprobe ecc")
machine.succeed("modprobe signer")

dmesg = machine.succeed("dmesg")
for line in dmesg.split("\n"):
    if "Signer:" in line:
        print(line)
# Also dump all lines with hex-looking content to capture raw words
for line in dmesg.split("\n"):
    if "raw words" in line or "pubkey" in line or "curve N" in line:
        print("DMESG:", line)

assert "Signer: loading" in dmesg
assert "Signer: key pair generated" in dmesg

machine.succeed("dd if=/dev/zero of=/tmp/verity.img bs=1M count=64")
machine.succeed("mkfs.ext4 -O verity /tmp/verity.img")
machine.succeed("mkdir -p /mnt && mount /tmp/verity.img /mnt")

machine.succeed("cp $(which signer-app) /mnt/")
machine.succeed("fsverity enable --block-size=1024 /mnt/signer-app")

fsverity_out = machine.succeed("fsverity measure /mnt/signer-app")
fsverity_digest_hex = fsverity_out.strip().split()[0].split(":")[1]
print("fs-verity digest hex:", fsverity_digest_hex)

out = machine.succeed("/mnt/signer-app")
print(out)

assert "SIGNER_HELLO" in out
assert "SIGNER_GET_CERT" in out
assert "SIGNER_SIGN_DATA" in out
assert "certificate" in out

# Parse kernel's hash output
hash_line = next(line for line in out.split("\n") if line.startswith("hash:"))
kernel_hash_hex = hash_line[5:].strip()
print("kernel hash:", kernel_hash_hex)

# Compute reference hash
msg_raw = binascii.unhexlify(fsverity_digest_hex) + binascii.unhexlify(nonce)
ref_hash = hashlib.sha256(msg_raw).hexdigest()
print("reference hash:", ref_hash)

if kernel_hash_hex == ref_hash:
    print("Hash verified OK")
else:
    print("Hash MISMATCH!")
    print("Kernel hash:", kernel_hash_hex)
    print("Reference:", ref_hash)
    raise Exception("Hash mismatch")

# Parse ECDSA signature from output
sig_r_line = next(line for line in out.split("\n") if line.startswith("sig_r:"))
sig_s_line = next(line for line in out.split("\n") if line.startswith("sig_s:"))
sig_r_hex = sig_r_line[6:].strip()
sig_s_hex = sig_s_line[6:].strip()

# Parse public key from output (raw uncompressed EC point, 65 bytes)
pubkey_line = next(line for line in out.split("\n") if line.startswith("pubkey:"))
pubkey_hex = pubkey_line[7:].strip()
print("pubkey hex:", pubkey_hex)
pubkey_bytes = binascii.unhexlify(pubkey_hex)
print("pubkey len:", len(pubkey_bytes))
print("pubkey[0]:", hex(pubkey_bytes[0]))
public_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), pubkey_bytes)

# Recover DER-encoded ECDSA signature from raw (r, s)
r = int.from_bytes(binascii.unhexlify(sig_r_hex), 'big')
s = int.from_bytes(binascii.unhexlify(sig_s_hex), 'big')
signature_der = encode_dss_signature(r, s)

# Verify the signature — kernel signed SHA256(fsverity_digest || nonce)
public_key.verify(signature_der, msg_raw, ec.ECDSA(hashes.SHA256()))
print("ECDSA signature verified OK")
