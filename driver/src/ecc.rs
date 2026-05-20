// SPDX-License-Identifier: GPL-2.0

// Safe wrappers around kernel-internal ECC / crypto helpers.
//
// All vli / ecc functions use LE-limb format (native u64 on x86_64).
// EXCEPT ecc_make_pub_key, which calls ecc_swap_digits on its output.

use super::ffi;
use core::ffi::c_ulong;
use kernel::prelude::*;

// From include/crypto/ecdh.h: ECC_CURVE_NIST_P256 = 0x0002
pub(crate) const P256: u32 = 0x0002;
// From include/crypto/internal/ecc.h: ECC_CURVE_NIST_P256_DIGITS = 4
pub(crate) const DIGITS: u32 = 4;

pub(crate) fn get_curve_n() -> Option<[u64; 4]> {
    let curve = unsafe { ffi::ecc_get_curve(P256) };
    if curve.is_null() {
        return None;
    }
    let n_ptr = unsafe { (*curve).n };
    if n_ptr.is_null() {
        return None;
    }
    Some(unsafe { core::ptr::read(n_ptr as *const [u64; 4]) })
}

pub(crate) fn generate_private_key() -> Result<[u64; 4]> {
    let mut key = [0u64; 4];
    let ret = unsafe { ffi::ecc_gen_privkey(P256, DIGITS, key.as_mut_ptr()) };
    if ret < 0 {
        return Err(EINVAL);
    }
    Ok(key)
}

pub(crate) fn make_public_key(privkey: &[u64; 4]) -> Result<[u64; 8]> {
    let mut pubkey = [0u64; 8];
    let ret = unsafe { ffi::ecc_make_pub_key(P256, DIGITS, privkey.as_ptr(), pubkey.as_mut_ptr()) };
    if ret < 0 {
        return Err(EINVAL);
    }
    Ok(pubkey)
}

pub(crate) fn sha256_hash(data: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    unsafe { ffi::sha256(data.as_ptr(), data.len() as c_ulong, out.as_mut_ptr()) };
    out
}

pub(crate) fn digits_from_be_bytes(bytes: &[u8; 32]) -> [u64; 4] {
    let mut out = [0u64; 4];
    unsafe { ffi::ecc_digits_from_bytes(bytes.as_ptr(), 32, out.as_mut_ptr(), DIGITS) };
    out
}

pub(crate) fn vli_mod_inv_result(input: &[u64; 4], modulus: &[u64; 4]) -> [u64; 4] {
    let mut result = [0u64; 4];
    unsafe {
        ffi::vli_mod_inv(
            result.as_mut_ptr(),
            input.as_ptr(),
            modulus.as_ptr(),
            DIGITS,
        )
    };
    result
}

pub(crate) fn vli_mod_mult(left: &[u64; 4], right: &[u64; 4], modulus: &[u64; 4]) -> [u64; 4] {
    let mut result = [0u64; 4];
    unsafe {
        ffi::vli_mod_mult_slow(
            result.as_mut_ptr(),
            left.as_ptr(),
            right.as_ptr(),
            modulus.as_ptr(),
            DIGITS,
        )
    };
    result
}

pub(crate) fn vli_sub_result(left: &[u64; 4], right: &[u64; 4]) -> ([u64; 4], u64) {
    let mut result = *left;
    let borrow = unsafe { ffi::vli_sub(result.as_mut_ptr(), left.as_ptr(), right.as_ptr(), DIGITS) };
    (result, borrow)
}

pub(crate) fn vli_compare(left: &[u64; 4], right: &[u64; 4]) -> core::cmp::Ordering {
    let ret = unsafe { ffi::vli_cmp(left.as_ptr(), right.as_ptr(), DIGITS) };
    ret.cmp(&0)
}

pub(crate) fn is_vli_zero(vli: &[u64; 4]) -> bool {
    unsafe { ffi::vli_is_zero(vli.as_ptr(), DIGITS) }
}

pub(crate) fn ima_measure_pubkey(pubkey: &[u8; 65]) -> Result {
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
