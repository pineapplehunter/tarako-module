# Remote attestation integration test.
#
# Flow:
#   1. Attester VM boots, loads the signer module, creates a verity-protected
#      copy of signer-app, and starts a TCP responder on port 9999.
#   2. Verifier VM boots, generates a random 32-byte nonce, and sends it to
#      the attester over TCP.
#   3. Attester's responder runs `/mnt/signer-app <nonce_hex>`, which calls the
#      SIGNER_SIGN_DATA ioctl.  The kernel signs SHA256(fsverity_digest || nonce)
#      and returns (hash, sig_r, sig_s, pubkey).
#   4. Verifier prints the response, which the test driver captures.
#   5. Test driver verifies:
#      - The nonce in the response matches what was sent.
#      - The ECDSA signature verifies against the public key via openssl.
import os, binascii, hashlib, time, base64

start_all()

# ===== Phase 1: Attester setup =====
attester.wait_for_unit("default.target")
attester.succeed("modprobe ecc")
attester.succeed("modprobe signer")

dmesg = attester.succeed("dmesg")
for line in dmesg.split("\n"):
    if "Signer:" in line:
        print(line)

assert "Signer: loading" in dmesg
assert "Signer: key pair generated" in dmesg

# Set up fs-verity protected binary on attester.
# The kernel module rejects ioctls from non-verity processes, so signer-app
# must be on a verity-protected filesystem.
attester.succeed("dd if=/dev/zero of=/tmp/verity.img bs=1M count=64")
attester.succeed("mkfs.ext4 -O verity /tmp/verity.img")
attester.succeed("mkdir -p /mnt && mount /tmp/verity.img /mnt")
attester.succeed("cp $(which signer-app) /mnt/")
attester.succeed("fsverity enable --block-size=1024 /mnt/signer-app")

fsverity_out = attester.succeed("fsverity measure /mnt/signer-app")
fsverity_digest_hex = fsverity_out.strip().split()[0].split(":")[1]
print("fs-verity digest hex:", fsverity_digest_hex)

# Start TCP responder on attester.
# Protocol: reads a hex nonce line, runs signer-app, sends back the full output.
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

# Get attester's eth1 (inter-machine network) IP
attester_ip = attester.succeed("ip -4 addr show eth1 | grep -oP '(?<=inet )\\S+' | cut -d/ -f1").strip()
print("attester IP:", attester_ip)

# ===== Phase 2: Remote attestation =====
# Verifier generates a random nonce and sends it over the network.

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

# ===== Phase 3: Cryptographic verification via openssl =====

assert "SIGNER_HELLO" in out
assert "SIGNER_GET_PUBKEY" in out
assert "SIGNER_SIGN_DATA" in out
assert "BEGIN KERNEL PUBLIC KEY" in out

# Verify nonce in response matches what verifier sent
nonce_line = next(line for line in out.split("\n") if line.startswith("nonce:"))
response_nonce_hex = nonce_line[6:].strip()
assert response_nonce_hex == nonce_hex, f"nonce mismatch: {response_nonce_hex} != {nonce_hex}"
print("Nonce match verified")

# Parse signature from sign data response
sig_r_line = next(line for line in out.split("\n") if line.startswith("sig_r:"))
sig_s_line = next(line for line in out.split("\n") if line.startswith("sig_s:"))
sig_r_hex = sig_r_line[6:].strip()
sig_s_hex = sig_s_line[6:].strip()

# Parse public key from sign data response
pubkey_line = next(line for line in out.split("\n") if line.startswith("pubkey:"))
pubkey_hex = pubkey_line[7:].strip()
pubkey_bytes = binascii.unhexlify(pubkey_hex)

# Build raw message (fsverity_digest || nonce)
msg_raw = binascii.unhexlify(fsverity_digest_hex) + nonce

# Print reference hash for debugging
hash_line = next(line for line in out.split("\n") if line.startswith("hash:"))
kernel_hash_hex = hash_line[5:].strip()
ref_hash = hashlib.sha256(msg_raw).hexdigest()
print("kernel hash:", kernel_hash_hex)
print("reference hash:", ref_hash)
if kernel_hash_hex != ref_hash:
    print("Hash MISMATCH!")
else:
    print("Hash matches")

# Build DER-encoded ECDSA signature (SEQUENCE { INTEGER r, INTEGER s })
def der_int_bytes(val):
    if val[0] & 0x80:
        val = b'\x00' + val
    return bytes([0x02, len(val)]) + val

r_bytes = binascii.unhexlify(sig_r_hex)
s_bytes = binascii.unhexlify(sig_s_hex)
sig_der = (bytes([0x30, len(der_int_bytes(r_bytes)) + len(der_int_bytes(s_bytes))])
           + der_int_bytes(r_bytes) + der_int_bytes(s_bytes))

# Build DER-encoded SubjectPublicKeyInfo for EC P-256
spki_der = (b'\x30\x59' b'\x30\x13'
            b'\x06\x07\x2a\x86\x48\xce\x3d\x02\x01'
            b'\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07'
            b'\x03\x42\x00') + pubkey_bytes

# Transfer files to attester VM and verify with openssl
for name, data in [("/tmp/msg.bin", msg_raw),
                   ("/tmp/sig.der", sig_der),
                   ("/tmp/pubkey.der", spki_der)]:
    b = base64.b64encode(data).decode()
    attester.succeed(f'echo "{b}" | base64 -d > {name}')

attester.succeed("openssl ec -pubin -inform DER -in /tmp/pubkey.der -out /tmp/pubkey.pem 2>/dev/null")
vout = attester.succeed("openssl dgst -sha256 -verify /tmp/pubkey.pem -signature /tmp/sig.der /tmp/msg.bin")
assert "Verified OK" in vout, f"openssl verification failed: {vout}"
print("ECDSA signature verified OK")
