// SPDX-License-Identifier: GPL-2.0

// Safe wrappers around kernel-internal ECC / crypto helpers.
//
// All vli / ecc functions use LE-limb format (native u64 on x86_64).
// EXCEPT ecc_make_pub_key, which calls ecc_swap_digits on its output.

use super::ffi;
use crate::vli::{Scalar, XY};
use core::ffi::{c_uint, c_ulong};
use kernel::prelude::*;

/// NIST P-256 curve identifier for kernel ECC helpers (`include/crypto/ecdh.h`).
pub(crate) const P256: u32 = 0x0002;

/// Number of 64-bit limbs in a P-256 scalar (`include/crypto/internal/ecc.h`).
pub(crate) const P256_DIGITS: usize = 4;

/// Byte length of a P-256 scalar / coordinate (256 bits).
pub(crate) const P256_BYTES: usize = P256_DIGITS * 8;

/// Byte length of an uncompressed P-256 public key (0x04 || X || Y).
pub(crate) const P256_PUBKEY_BYTES: usize = 1 + 2 * P256_BYTES;

pub(crate) fn get_curve_n() -> Option<Scalar> {
    let curve = unsafe { ffi::ecc_get_curve(P256) };
    if curve.is_null() {
        return None;
    }
    let n_ptr = unsafe { (*curve).n };
    if n_ptr.is_null() {
        return None;
    }
    let n: [u64; P256_DIGITS] = unsafe { core::ptr::read(n_ptr as *const [u64; P256_DIGITS]) };
    Some(Scalar::from_limbs(n))
}

pub(crate) fn generate_private_key() -> Result<Scalar> {
    let mut key = Scalar::zero();
    let ret = unsafe { ffi::ecc_gen_privkey(P256, P256_DIGITS as c_uint, key.as_mut_ptr()) };
    if ret < 0 {
        return Err(EINVAL);
    }
    Ok(key)
}

pub(crate) fn make_public_key(privkey: &Scalar) -> Result<XY> {
    let mut pubkey = XY::zero();
    let ret = unsafe {
        ffi::ecc_make_pub_key(P256, P256_DIGITS as c_uint, privkey.as_ptr(), pubkey.as_mut_ptr())
    };
    if ret < 0 {
        return Err(EINVAL);
    }
    Ok(pubkey)
}

pub(crate) fn sha256_hash(data: &[u8]) -> [u8; P256_BYTES] {
    let mut out = [0u8; P256_BYTES];
    unsafe { ffi::sha256(data.as_ptr(), data.len() as c_ulong, out.as_mut_ptr()) };
    out
}

pub(crate) fn ima_measure_pubkey(pubkey: &crate::convert::UncompressedPubkey) -> Result {
    let bytes = pubkey.as_bytes();
    let result = unsafe {
        ffi::ima_measure_critical_data(
            c"signer_key".as_ptr() as *const i8,
            c"public-key-generate".as_ptr() as *const i8,
            bytes.as_ptr(),
            bytes.len() as c_ulong,
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
