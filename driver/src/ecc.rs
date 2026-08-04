// SPDX-License-Identifier: GPL-2.0

// Safe wrappers around kernel-internal ECC / crypto helpers.
//
// All vli / ecc functions use LE-limb format (native u64 on x86_64).
// EXCEPT ecc_make_pub_key, which calls ecc_swap_digits on its output.

use super::ffi;
use crate::vli::Scalar;
use core::ffi::{c_uint, c_ulong};
use core::ptr::NonNull;
use kernel::prelude::*;

/// NIST P-256 curve identifier for kernel ECC helpers (`include/crypto/ecdh.h`).
pub(crate) const P256: u32 = 0x0002;

/// Number of 64-bit limbs in a P-256 scalar
/// (`include/crypto/internal/ecc.h`: `ECC_CURVE_NIST_P256_DIGITS`).
pub(crate) const P256_DIGITS: usize = (256 + 64 - 1) / 64; // DIV_ROUND_UP(256, 64) = 4

/// Byte length of a P-256 scalar / coordinate (256 bits).
pub(crate) const P256_BYTES: usize = P256_DIGITS * 8;

/// Byte length of an uncompressed P-256 public key (0x04 || X || Y, 65 bytes).
pub(crate) const P256_PUBKEY_BYTES: usize = 1 + 2 * P256_BYTES;

/// Kernel-allocated ECC point (separate x/y buffers, managed via
/// `ecc_alloc_point` / `ecc_free_point`).  Freed and zeroed on drop.
pub(crate) struct Point {
    inner: NonNull<ffi::Point>,
}

impl Point {
    fn inner(&self) -> &ffi::Point {
        unsafe { self.inner.as_ref() }
    }

    /// Return the X coordinate as a copy-on-write Scalar.
    /// The limbs are in the *swapped* format output by `ecc_make_pub_key`;
    /// call `.unswap()` to convert to native LE limbs.
    pub(crate) fn x_scalar(&self) -> Scalar {
        unsafe { Scalar::from_limbs(core::ptr::read(self.inner().x as *const [u64; P256_DIGITS])) }
    }

    /// Raw bytes of the X coordinate (big-endian wire format, 32 bytes).
    pub(crate) fn x_as_bytes(&self) -> [u8; P256_BYTES] {
        unsafe { core::ptr::read(self.inner().x as *const [u8; P256_BYTES]) }
    }

    /// Raw bytes of the Y coordinate (big-endian wire format, 32 bytes).
    pub(crate) fn y_as_bytes(&self) -> [u8; P256_BYTES] {
        unsafe { core::ptr::read(self.inner().y as *const [u8; P256_BYTES]) }
    }
}

impl Drop for Point {
    fn drop(&mut self) {
        unsafe { ffi::ecc_free_point(self.inner.as_ptr()) };
    }
}

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
        return Err(Error::from_errno(ret));
    }
    Ok(key)
}

/// Allocate a kernel `ecc_point`, compute P = privkey·G via
/// `ecc_make_pub_key`, and copy the swapped output into the point's
/// x / y buffers.
pub(crate) fn make_public_key(privkey: &Scalar) -> Result<Point> {
    let p = NonNull::new(unsafe { ffi::ecc_alloc_point(P256_DIGITS as c_uint) }).ok_or(ENOMEM)?;
    let point = unsafe { p.as_ref() };
    if point.x.is_null() || point.y.is_null() {
        unsafe { ffi::ecc_free_point(p.as_ptr()) };
        return Err(EFAULT);
    }

    let mut raw = [0u64; 2 * P256_DIGITS];
    let ret = unsafe {
        ffi::ecc_make_pub_key(
            P256,
            P256_DIGITS as c_uint,
            privkey.as_ptr(),
            raw.as_mut_ptr(),
        )
    };
    if ret < 0 {
        unsafe { ffi::ecc_free_point(p.as_ptr()) };
        return Err(Error::from_errno(ret));
    }

    unsafe {
        core::ptr::copy_nonoverlapping(raw.as_ptr(), point.x, P256_DIGITS);
        core::ptr::copy_nonoverlapping(raw.as_ptr().add(P256_DIGITS), point.y, P256_DIGITS);
    }

    Ok(Point { inner: p })
}

pub(crate) fn sha256_hash(data: &[u8]) -> [u8; P256_BYTES] {
    let mut out = [0u8; P256_BYTES];
    unsafe { ffi::sha256(data.as_ptr(), data.len() as c_ulong, out.as_mut_ptr()) };
    out
}

pub(crate) fn ima_measure_pubkey(bytes: &[u8]) -> Result {
    let result = unsafe {
        ffi::ima_measure_critical_data(
            c"tarako_pubkey".as_ptr() as *const i8,
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
