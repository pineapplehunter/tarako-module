import os, binascii, hashlib, time, base64
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

start_all()

attester.wait_for_unit("default.target")
attester.succeed("modprobe ecc")
attester.succeed("modprobe signer")

dmesg = attester.succeed("dmesg")
for line in dmesg.split("\n"):
    if "Signer:" in line:
        print(line)

assert "Signer: loading" in dmesg
assert "Signer: key pair generated" in dmesg

# Set up fs-verity protected binary on attester
attester.succeed("dd if=/dev/zero of=/tmp/verity.img bs=1M count=64")
attester.succeed("mkfs.ext4 -O verity /tmp/verity.img")
attester.succeed("mkdir -p /mnt && mount /tmp/verity.img /mnt")
attester.succeed("cp $(which signer-app) /mnt/")
attester.succeed("fsverity enable --block-size=1024 /mnt/signer-app")

fsverity_out = attester.succeed("fsverity measure /mnt/signer-app")
fsverity_digest_hex = fsverity_out.strip().split()[0].split(":")[1]
print("fs-verity digest hex:", fsverity_digest_hex)

# Start TCP responder on attester (Python TCP server)
responder_code = r"""
import socket, subprocess

s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('0.0.0.0', 9999))
s.listen(5)

while True:
    conn, addr = s.accept()
    data = b''
    while True:
        ch = conn.recv(1)
        if ch == b'\n' or not ch:
            break
        data += ch
    nonce_hex = data.decode()
    result = subprocess.check_output(['/mnt/signer-app', nonce_hex])
    conn.sendall(result)
    conn.close()
"""

b64 = base64.b64encode(responder_code.encode()).decode()
attester.succeed(f"echo {b64} | base64 -d > /tmp/responder.py")
attester.succeed("nohup python3 /tmp/responder.py > /tmp/responder.log 2>&1 &")
time.sleep(1)

# Get attester's IP
attester_ip = attester.succeed("ip -4 addr show eth1 | grep -oP '(?<=inet )\\S+' | cut -d/ -f1").strip()
print("attester IP:", attester_ip)

# ===== Remote attestation =====
# Verifier generates a random nonce and sends it over the network

verifier.wait_for_unit("default.target")

nonce = os.urandom(32)
nonce_hex = binascii.hexlify(nonce).decode()
print("verifier nonce:", nonce_hex)

client_code = f"""
import socket, time
for attempt in range(5):
    try:
        s = socket.socket()
        s.settimeout(5)
        s.connect(('{attester_ip}', 9999))
        s.sendall(b'{nonce_hex}' + b'\\x0a')
        data = b''
        while True:
            try:
                chunk = s.recv(4096)
                if not chunk:
                    break
                data += chunk
            except:
                break
        s.close()
        print(data.decode())
        break
    except Exception as e:
        if attempt < 4:
            time.sleep(1)
        else:
            raise
"""

client_b64 = base64.b64encode(client_code.encode()).decode()
out = verifier.succeed(f"echo {client_b64} | base64 -d | python3")
print(out)

# ===== Verification =====

assert "SIGNER_HELLO" in out
assert "SIGNER_GET_CERT" in out
assert "SIGNER_SIGN_DATA" in out
assert "certificate" in out

# Verify nonce in response matches what verifier sent
nonce_line = next(line for line in out.split("\n") if line.startswith("nonce:"))
response_nonce_hex = nonce_line[6:].strip()
assert response_nonce_hex == nonce_hex, f"nonce mismatch: {response_nonce_hex} != {nonce_hex}"
print("Nonce match verified")

# Verify hash
hash_line = next(line for line in out.split("\n") if line.startswith("hash:"))
kernel_hash_hex = hash_line[5:].strip()
msg_raw = binascii.unhexlify(fsverity_digest_hex) + nonce
ref_hash = hashlib.sha256(msg_raw).hexdigest()
print("kernel hash:", kernel_hash_hex)
print("reference hash:", ref_hash)

if kernel_hash_hex == ref_hash:
    print("Hash verified OK")
else:
    print("Hash MISMATCH!")
    raise Exception("Hash mismatch")

# Verify ECDSA signature
sig_r_line = next(line for line in out.split("\n") if line.startswith("sig_r:"))
sig_s_line = next(line for line in out.split("\n") if line.startswith("sig_s:"))
sig_r_hex = sig_r_line[6:].strip()
sig_s_hex = sig_s_line[6:].strip()

pubkey_line = next(line for line in out.split("\n") if line.startswith("pubkey:"))
pubkey_hex = pubkey_line[7:].strip()
pubkey_bytes = binascii.unhexlify(pubkey_hex)
public_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), pubkey_bytes)

r = int.from_bytes(binascii.unhexlify(sig_r_hex), 'big')
s = int.from_bytes(binascii.unhexlify(sig_s_hex), 'big')
signature_der = encode_dss_signature(r, s)

public_key.verify(signature_der, msg_raw, ec.ECDSA(hashes.SHA256()))
print("ECDSA signature verified OK")
