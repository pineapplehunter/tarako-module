#!/usr/bin/env python3
import struct, sys
from cryptography.hazmat.primitives.asymmetric import ec

P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
A = P - 3
B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B

def is_on_curve(x, y):
    lhs = (y * y) % P
    rhs = (x * x * x + A * x + B) % P
    return lhs == rhs

def words_to_bytes(words, limb_reverse, byte_swap):
    order = [3, 2, 1, 0] if limb_reverse else [0, 1, 2, 3]
    out = b''
    for idx in order:
        out += words[idx].to_bytes(8, 'big' if byte_swap else 'little')
    return out

def try_all(words_x, words_y, label=""):
    print(f"\n=== {label} ===")
    print(f"X: {[hex(w) for w in words_x]}")
    print(f"Y: {[hex(w) for w in words_y]}")
    for name, lr, bs in [
        ("LE limb, BE/u64", False, True),
        ("BE limb, BE/u64", True, True),
        ("LE limb, LE/u64", False, False),
        ("BE limb, LE/u64", True, False),
    ]:
        xb = words_to_bytes(words_x, lr, bs)
        yb = words_to_bytes(words_y, lr, bs)
        x = int.from_bytes(xb, 'big')
        y = int.from_bytes(yb, 'big')
        if is_on_curve(x, y):
            try:
                ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), b'\x04' + xb + yb)
                print(f"  {name}: VALID ✓")
            except ValueError:
                print(f"  {name}: on curve but crypto rejected")
        else:
            print(f"  {name}: INVALID")

def ecc_swap_digits_output(le_limbs):
    """Simulate what the kernel's ecc_swap_digits produces from LE limbs."""
    return [int.from_bytes(le_limbs[3 - i].to_bytes(8, 'little'), 'big') for i in range(len(le_limbs))]

def words_to_bytes_raw(words):
    """memcpy: just read native memory bytes (equivalent to transmute<[u64;4],[u8;32]>)."""
    return b''.join(w.to_bytes(8, 'little') for w in words)

if __name__ == "__main__":
    Gx = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
    Gy = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5
    
    Gx_le = [(Gx >> (64*i)) & 0xFFFFFFFFFFFFFFFF for i in range(4)]
    Gy_le = [(Gy >> (64*i)) & 0xFFFFFFFFFFFFFFFF for i in range(4)]
    
    # Simulate what ecc_make_pub_key outputs after ecc_swap_digits
    Gx_out = ecc_swap_digits_output(Gx_le)
    Gy_out = ecc_swap_digits_output(Gy_le)
    
    print("=== Simulate ecc_make_pub_key output ===")
    print(f"Gx LE limbs: {[hex(w) for w in Gx_le]}")
    print(f"After ecc_swap_digits: {[hex(w) for w in Gx_out]}")
    
    # Test raw memcpy of the output
    xb = words_to_bytes_raw(Gx_out)
    yb = words_to_bytes_raw(Gy_out)
    print(f"Raw x bytes: {xb.hex()}")
    print(f"Expected:     {Gx.to_bytes(32, 'big').hex()}")
    print(f"Match: {xb == Gx.to_bytes(32, 'big')}")
    
    if xb == Gx.to_bytes(32, 'big') and yb == Gy.to_bytes(32, 'big'):
        print("✓ Raw memcpy of ecc_make_pub_key output gives correct BE bytes!")
    
    # Also verify on curve + cryptography
    on_curve = is_on_curve(int.from_bytes(xb, 'big'), int.from_bytes(yb, 'big'))
    print(f"Point on curve: {on_curve}")
    if on_curve:
        try:
            ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), b'\x04' + xb + yb)
            print("✓ Cryptography accepts the point!")
        except ValueError as e:
            print(f"✗ Cryptography rejected: {e}")
    
    try_all(Gx_out, Gy_out, "Generator (after ecc_swap_digits)")
    
    print("\nEnter 8 hex words X0 X1 X2 X3 Y0 Y1 Y2 Y3 (as from ecc_make_pub_key output):")
    for line in sys.stdin:
        line = line.strip()
        if not line: break
        vals = [int(p, 16) for p in line.replace('(',' ').replace(')',' ').split() if len(p) == 16]
        if len(vals) >= 8:
            xb = words_to_bytes_raw(vals[:4])
            yb = words_to_bytes_raw(vals[4:8])
            on_curve = is_on_curve(int.from_bytes(xb, 'big'), int.from_bytes(yb, 'big'))
            print(f"raw memcpy: on curve={on_curve}")
            if on_curve:
                try:
                    ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), b'\x04' + xb + yb)
                    print("✓ Cryptography accepts!")
                except ValueError as e:
                    print(f"✗ Cryptography rejected: {e}")
            try_all(vals[:4], vals[4:8], "Input")
