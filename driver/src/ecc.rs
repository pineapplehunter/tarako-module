// SPDX-License-Identifier: GPL-2.0

// Safe wrappers around kernel-internal ECC / crypto helpers.
//
// All vli / ecc functions use LE-limb format (native u64 on x86_64).
// EXCEPT ecc_make_pub_key, which calls ecc_swap_digits on its output.

use super::ffi;
use core::ffi::c_ulong;
use kernel::prelude::*;

/// NIST P-256 curve identifier for kernel ECC helpers (`include/crypto/ecdh.h`).
pub(crate) const P256: u32 = 0x0002;

/// Number of 64-bit limbs in a P-256 scalar (`include/crypto/internal/ecc.h`).
pub(crate) const P256_DIGITS: u32 = 4;

/// Byte length of a P-256 scalar / coordinate (256 bits).
pub(crate) const P256_BYTES: u32 = P256_DIGITS * 8;

/// Byte length of an uncompressed P-256 public key (0x04 || X || Y).
pub(crate) const P256_PUBKEY_BYTES: usize = 1 + 2 * P256_BYTES as usize;

pub(crate) fn get_curve_n() -> Option<[u64; P256_DIGITS as usize]> {
    let curve = unsafe { ffi::ecc_get_curve(P256) };
    if curve.is_null() {
        return None;
    }
    let n_ptr = unsafe { (*curve).n };
    if n_ptr.is_null() {
        return None;
    }
    Some(unsafe { core::ptr::read(n_ptr as *const [u64; P256_DIGITS as usize]) })
}

pub(crate) fn generate_private_key() -> Result<[u64; P256_DIGITS as usize]> {
    let mut key = [0u64; P256_DIGITS as usize];
    let ret = unsafe { ffi::ecc_gen_privkey(P256, P256_DIGITS, key.as_mut_ptr()) };
    if ret < 0 {
        return Err(EINVAL);
    }
    Ok(key)
}

pub(crate) fn make_public_key(privkey: &[u64; P256_DIGITS as usize]) -> Result<[u64; 2 * P256_DIGITS as usize]> {
    let mut pubkey = [0u64; 2 * P256_DIGITS as usize];
    let ret = unsafe { ffi::ecc_make_pub_key(P256, P256_DIGITS, privkey.as_ptr(), pubkey.as_mut_ptr()) };
    if ret < 0 {
        return Err(EINVAL);
    }
    Ok(pubkey)
}

pub(crate) fn sha256_hash(data: &[u8]) -> [u8; P256_BYTES as usize] {
    let mut out = [0u8; P256_BYTES as usize];
    unsafe { ffi::sha256(data.as_ptr(), data.len() as c_ulong, out.as_mut_ptr()) };
    out
}

pub(crate) fn digits_from_be_bytes(bytes: &[u8; P256_BYTES as usize]) -> [u64; P256_DIGITS as usize] {
    let mut out = [0u64; P256_DIGITS as usize];
    unsafe { ffi::ecc_digits_from_bytes(bytes.as_ptr(), P256_BYTES, out.as_mut_ptr(), P256_DIGITS) };
    out
}

pub(crate) fn vli_mod_inv_result(input: &[u64; P256_DIGITS as usize], modulus: &[u64; P256_DIGITS as usize]) -> [u64; P256_DIGITS as usize] {
    let mut result = [0u64; P256_DIGITS as usize];
    unsafe {
        ffi::vli_mod_inv(
            result.as_mut_ptr(),
            input.as_ptr(),
            modulus.as_ptr(),
            P256_DIGITS,
        )
    };
    result
}

pub(crate) fn vli_mod_mult(left: &[u64; P256_DIGITS as usize], right: &[u64; P256_DIGITS as usize], modulus: &[u64; P256_DIGITS as usize]) -> [u64; P256_DIGITS as usize] {
    let mut result = [0u64; P256_DIGITS as usize];
    unsafe {
        ffi::vli_mod_mult_slow(
            result.as_mut_ptr(),
            left.as_ptr(),
            right.as_ptr(),
            modulus.as_ptr(),
            P256_DIGITS,
        )
    };
    result
}

pub(crate) fn vli_sub_result(left: &[u64; P256_DIGITS as usize], right: &[u64; P256_DIGITS as usize]) -> ([u64; P256_DIGITS as usize], u64) {
    let mut result = *left;
    let borrow = unsafe { ffi::vli_sub(result.as_mut_ptr(), left.as_ptr(), right.as_ptr(), P256_DIGITS) };
    (result, borrow)
}

pub(crate) fn vli_compare(left: &[u64; P256_DIGITS as usize], right: &[u64; P256_DIGITS as usize]) -> core::cmp::Ordering {
    let ret = unsafe { ffi::vli_cmp(left.as_ptr(), right.as_ptr(), P256_DIGITS) };
    ret.cmp(&0)
}

pub(crate) fn is_vli_zero(vli: &[u64; P256_DIGITS as usize]) -> bool {
    unsafe { ffi::vli_is_zero(vli.as_ptr(), P256_DIGITS) }
}

pub(crate) fn ima_measure_pubkey(pubkey: &[u8; P256_PUBKEY_BYTES]) -> Result {
    let result = unsafe {
        ffi::ima_measure_critical_data(
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
