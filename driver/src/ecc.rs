// SPDX-License-Identifier: GPL-2.0

// FFI declarations for kernel-internal ECC / crypto helpers.
//
// All vli / ecc functions use LE-limb format (native u64 on x86_64).
// EXCEPT ecc_make_pub_key, which calls ecc_swap_digits on its output.

use core::ffi::{c_int, c_uint, c_ulong};
use kernel::prelude::*;

#[repr(C)]
pub(crate) struct Point {
    pub(crate) x: *mut u64,
    pub(crate) y: *mut u64,
    pub(crate) ndigits: u8,
}

#[repr(C)]
pub(crate) struct Curve {
    pub(crate) name: *const i8,
    pub(crate) nbits: u32,
    pub(crate) g: Point,
    pub(crate) p: *mut u64,
    pub(crate) n: *mut u64,
    pub(crate) a: *mut u64,
    pub(crate) b: *mut u64,
}

// From include/crypto/ecdh.h: ECC_CURVE_NIST_P256 = 0x0002
pub(crate) const P256: u32 = 0x0002;
// From include/crypto/internal/ecc.h: ECC_CURVE_NIST_P256_DIGITS = 4
pub(crate) const DIGITS: u32 = 4;

extern "C" {
    // LE-limb input, LE-limb output
    pub(crate) fn ecc_gen_privkey(curve_id: c_uint, ndigits: c_uint, key: *mut u64) -> c_int;
    // LE-limb input, SWAPPED output (ecc_swap_digits applied internally)
    pub(crate) fn ecc_make_pub_key(
        curve_id: c_uint,
        ndigits: c_uint,
        privkey: *const u64,
        pubkey: *mut u64,
    ) -> c_int;
    pub(crate) fn ecc_get_curve(curve_id: c_uint) -> *const Curve;
    // Big-endian bytes -> LE-limb
    pub(crate) fn ecc_digits_from_bytes(inp: *const u8, nbytes: c_uint, out: *mut u64, ndigits: c_uint);
    pub(crate) fn vli_mod_inv(result: *mut u64, input: *const u64, modulus: *const u64, ndigits: c_uint);
    pub(crate) fn vli_mod_mult_slow(
        result: *mut u64,
        left: *const u64,
        right: *const u64,
        modulus: *const u64,
        ndigits: c_uint,
    );
    pub(crate) fn vli_sub(result: *mut u64, left: *const u64, right: *const u64, ndigits: c_uint) -> u64;
    pub(crate) fn vli_cmp(left: *const u64, right: *const u64, ndigits: c_uint) -> c_int;
    pub(crate) fn vli_is_zero(vli: *const u64, ndigits: c_uint) -> bool;
    pub(crate) fn sha256(data: *const u8, len: c_ulong, out: *mut u8);
    pub(crate) fn ima_measure_critical_data(
        event_label: *const i8,
        event_name: *const i8,
        buf: *const u8,
        buf_len: c_ulong,
        hash: bool,
        digest: *mut u8,
        digest_len: c_ulong,
    ) -> c_int;
    pub(crate) fn fsverity_get_digest(
        inode: *mut u8,
        raw_digest: *mut u8,
        alg: *mut u8,
        halg: *mut u32,
    ) -> c_int;
}

pub(crate) fn get_curve_n() -> Option<[u64; 4]> {
    let curve = unsafe { ecc_get_curve(P256) };
    if curve.is_null() {
        return None;
    }
    let n_ptr = unsafe { (*curve).n };
    if n_ptr.is_null() {
        return None;
    }
    Some(unsafe { core::ptr::read(n_ptr as *const [u64; 4]) })
}

/// Generate a random ECDSA P-256 private key.
pub(crate) fn generate_private_key() -> Result<[u64; 4]> {
    let mut key = [0u64; 4];
    let ret = unsafe { ecc_gen_privkey(P256, DIGITS, key.as_mut_ptr()) };
    if ret < 0 {
        return Err(EINVAL);
    }
    Ok(key)
}

/// Compute the public key from a private key.
/// Returns 8 u64s in swapped format (X then Y, each byte-swapped per ecc_swap_digits).
pub(crate) fn make_public_key(privkey: &[u64; 4]) -> Result<[u64; 8]> {
    let mut pubkey = [0u64; 8];
    let ret = unsafe { ecc_make_pub_key(P256, DIGITS, privkey.as_ptr(), pubkey.as_mut_ptr()) };
    if ret < 0 {
        return Err(EINVAL);
    }
    Ok(pubkey)
}

/// Compute SHA-256 hash of `data`.
pub(crate) fn sha256_hash(data: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    unsafe { sha256(data.as_ptr(), data.len() as c_ulong, out.as_mut_ptr()) };
    out
}

/// Convert big-endian bytes to LE-limb representation.
pub(crate) fn digits_from_be_bytes(bytes: &[u8; 32]) -> [u64; 4] {
    let mut out = [0u64; 4];
    unsafe { ecc_digits_from_bytes(bytes.as_ptr(), 32, out.as_mut_ptr(), DIGITS) };
    out
}

/// Compute modular inverse: `result = input^(-1) mod modulus`.
pub(crate) fn vli_mod_inv_result(input: &[u64; 4], modulus: &[u64; 4]) -> [u64; 4] {
    let mut result = [0u64; 4];
    unsafe {
        vli_mod_inv(
            result.as_mut_ptr(),
            input.as_ptr(),
            modulus.as_ptr(),
            DIGITS,
        )
    };
    result
}

/// Compute modular multiplication: `result = left * right mod modulus`.
pub(crate) fn vli_mod_mult(left: &[u64; 4], right: &[u64; 4], modulus: &[u64; 4]) -> [u64; 4] {
    let mut result = [0u64; 4];
    unsafe {
        vli_mod_mult_slow(
            result.as_mut_ptr(),
            left.as_ptr(),
            right.as_ptr(),
            modulus.as_ptr(),
            DIGITS,
        )
    };
    result
}

/// Subtract two LE-limb numbers: `result = left - right`.
/// Returns `(result, borrow)` where `borrow` is non-zero if underflow occurred.
pub(crate) fn vli_sub_result(left: &[u64; 4], right: &[u64; 4]) -> ([u64; 4], u64) {
    let mut result = *left;
    let borrow = unsafe { vli_sub(result.as_mut_ptr(), left.as_ptr(), right.as_ptr(), DIGITS) };
    (result, borrow)
}

/// Compare two LE-limb numbers.
pub(crate) fn vli_compare(left: &[u64; 4], right: &[u64; 4]) -> core::cmp::Ordering {
    let ret = unsafe { vli_cmp(left.as_ptr(), right.as_ptr(), DIGITS) };
    ret.cmp(&0)
}

/// Check if an LE-limb number is zero.
pub(crate) fn is_vli_zero(vli: &[u64; 4]) -> bool {
    unsafe { vli_is_zero(vli.as_ptr(), DIGITS) }
}

/// Record the public key via IMA. Returns Ok or Err with negative error number.
pub(crate) fn ima_measure_pubkey(pubkey: &[u8; 65]) -> Result {
    let result = unsafe {
        ima_measure_critical_data(
            c"signer_key".as_ptr() as *const i8,
            c"public-key-generate".as_ptr() as *const i8,
            pubkey.as_ptr(),
            pubkey.len() as c_ulong,
            true,
            core::ptr::null_mut(),
            0,
        )
    };
    if result < 0 {
        Err(Error::from_errno(result))
    } else {
        Ok(())
    }
}
