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
assert "public key (65 bytes) DER:" in out

# Verify nonce in response matches what verifier sent
nonce_line = next(line for line in out.split("\n") if line.startswith("nonce:"))
response_nonce_hex = nonce_line[6:].strip()
assert response_nonce_hex == nonce_hex, f"nonce mismatch: {response_nonce_hex} != {nonce_hex}"
print("Nonce match verified")

# Print reference hash for debugging
msg_raw = binascii.unhexlify(fsverity_digest_hex) + nonce
hash_line = next(line for line in out.split("\n") if line.startswith("hash:"))
kernel_hash_hex = hash_line[5:].strip()
ref_hash = hashlib.sha256(msg_raw).hexdigest()
print("kernel hash:", kernel_hash_hex)
print("reference hash:", ref_hash)
if kernel_hash_hex != ref_hash:
    print("Hash MISMATCH!")
else:
    print("Hash matches")

# Extract hex DER public key and signature from output
out_lines = out.split("\n")
pubkey_idx = next(i for i, l in enumerate(out_lines) if l.startswith("public key (65 bytes) DER:"))
pubkey_hex = next(l for l in out_lines[pubkey_idx + 1:] if l.strip())
sig_idx = next(i for i, l in enumerate(out_lines) if l.startswith("signature DER:"))
sig_hex = next(l for l in out_lines[sig_idx + 1:] if l.strip())
print("=== Public key DER (hex) ===")
print(pubkey_hex)
print("=== Signature DER (hex) ===")
print(sig_hex)

# Write message and DER files to attester, then verify via openssl
pubkey_der_bytes = bytes.fromhex(pubkey_hex)
sig_der_bytes = bytes.fromhex(sig_hex)
attester.succeed('echo "{}" | base64 -d > /tmp/pubkey.der'.format(base64.b64encode(pubkey_der_bytes).decode()))
attester.succeed('echo "{}" | base64 -d > /tmp/sig.der'.format(base64.b64encode(sig_der_bytes).decode()))
attester.succeed('echo "{}" | base64 -d > /tmp/msg.bin'.format(base64.b64encode(msg_raw).decode()))
vout = attester.succeed("openssl dgst -sha256 -verify /tmp/pubkey.der -keyform DER -signature /tmp/sig.der /tmp/msg.bin")
assert "Verified OK" in vout, f"openssl verification failed: {vout}"
print("ECDSA signature verified OK")
