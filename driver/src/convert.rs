// SPDX-License-Identifier: GPL-2.0

// Byte-order conversion helpers for ECC limbs.
//
// Kernel crypto helpers work with little-endian u64 arrays ("limbs").
// Wire formats (certificate, signature R/S, ioctl buffers) are big-endian
// byte strings.  These routines bridge the two worlds.

use crate::ecc;
use kernel::prelude::*;

const DIGITS: usize = ecc::P256_DIGITS as usize;
const BYTES: usize = ecc::P256_BYTES as usize;
const PUBKEY_BYTES: usize = ecc::P256_PUBKEY_BYTES;

/// Assemble a 65-byte uncompressed EC point (0x04 || X || Y) from
/// the swapped-format coordinates output by ecc_make_pub_key.
pub(crate) fn uncompressed_pubkey_bytes(
    pub_x: &[u64; DIGITS],
    pub_y: &[u64; DIGITS],
) -> [u8; PUBKEY_BYTES] {
    let mut out = [0u8; PUBKEY_BYTES];
    out[0] = 0x04;
    let xb = digits_to_be_bytes(pub_x);
    let yb = digits_to_be_bytes(pub_y);
    out[1..1 + BYTES].copy_from_slice(&xb);
    out[1 + BYTES..PUBKEY_BYTES].copy_from_slice(&yb);
    out
}

/// Convert swapped-format u64 limbs (output of ecc_make_pub_key) to
/// big-endian bytes by raw-memcpy.  On x86_64 the ecc_swap_digits output
/// already arranges the limbs in big-endian memory order.
pub(crate) fn digits_to_be_bytes(digits: &[u64; DIGITS]) -> [u8; BYTES] {
    let mut out = [0u8; BYTES];
    unsafe {
        core::ptr::copy_nonoverlapping(digits.as_ptr() as *const u8, out.as_mut_ptr(), BYTES);
    }
    pr_info!(
        "Signer: raw words {:016x}{:016x}{:016x}{:016x}\n",
        digits[0],
        digits[1],
        digits[2],
        digits[3],
    );
    out
}

/// Reverse ecc_swap_digits: convert swapped format back to LE-limb.
pub(crate) fn unswap_digits(swapped: &[u64; DIGITS]) -> [u64; DIGITS] {
    let mut out = [0u64; DIGITS];
    for i in 0..DIGITS {
        out[i] = u64::from_be(swapped[DIGITS - 1 - i]);
    }
    out
}
