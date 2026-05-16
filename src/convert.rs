// SPDX-License-Identifier: GPL-2.0

// Byte-order conversion helpers for ECC limbs.
//
// Kernel crypto helpers work with little-endian u64 arrays ("limbs").
// Wire formats (certificate, signature R/S, ioctl buffers) are big-endian
// byte strings.  These routines bridge the two worlds.

use kernel::prelude::*;

/// Assemble a 65-byte uncompressed EC point (0x04 || X || Y) from
/// the swapped-format coordinates output by ecc_make_pub_key.
pub(crate) fn uncompressed_pubkey_bytes(pub_x: &[u64; 4], pub_y: &[u64; 4]) -> [u8; 65] {
    let mut out = [0u8; 65];
    out[0] = 0x04;
    let xb = digits_to_be_bytes(pub_x);
    let yb = digits_to_be_bytes(pub_y);
    out[1..33].copy_from_slice(&xb);
    out[33..65].copy_from_slice(&yb);
    out
}

/// Convert swapped-format u64 limbs (output of ecc_make_pub_key) to
/// big-endian bytes by raw-memcpy.  On x86_64 the ecc_swap_digits output
/// already arranges the limbs in big-endian memory order.
pub(crate) fn digits_to_be_bytes(digits: &[u64; 4]) -> [u8; 32] {
    let mut out = [0u8; 32];
    unsafe {
        core::ptr::copy_nonoverlapping(digits.as_ptr() as *const u8, out.as_mut_ptr(), 32);
    }
    pr_info!(
        "Signer: raw words {:016x}{:016x}{:016x}{:016x}\n",
        digits[0], digits[1], digits[2], digits[3],
    );
    out
}

/// Reverse ecc_swap_digits: convert swapped format back to LE-limb.
pub(crate) fn unswap_digits(swapped: &[u64; 4]) -> [u64; 4] {
    let mut out = [0u64; 4];
    for i in 0..4 {
        out[i] = u64::from_be(swapped[3 - i]);
    }
    out
}

/// Convert LE-limb u64 to big-endian bytes (for DER signature encoding).
/// Used for r, s output from ecdsa_sign where all arithmetic is in LE-limb.
pub(crate) fn le_limbs_to_be_bytes(digits: &[u64; 4]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for i in 0..4 {
        out[i * 8..(i + 1) * 8].copy_from_slice(&digits[3 - i].to_be_bytes());
    }
    out
}
