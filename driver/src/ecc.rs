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
pub(crate) const P256_DIGITS: usize = 256_usize.div_ceil(64);

/// Byte length of a P-256 scalar / coordinate (256 bits).
pub(crate) const P256_BYTES: usize = P256_DIGITS * 8;

/// Byte length of a compressed P-256 public key (0x02/0x03 || X, 33 bytes).
pub(crate) const P256_PUBKEY_BYTES: usize = 1 + P256_BYTES;

/// Kernel-allocated ECC point (separate x/y buffers, managed via
/// `ecc_alloc_point` / `ecc_free_point`).  Freed and zeroed on drop.
pub(crate) struct Point {
    inner: NonNull<ffi::Point>,
}

impl Point {
    fn inner(&self) -> &ffi::Point {
        // SAFETY: `inner` is non-null and remains allocated until `Point::drop`.
        unsafe { self.inner.as_ref() }
    }

    /// Return the X coordinate as a copy-on-write Scalar.
    /// The limbs are in the *swapped* format output by `ecc_make_pub_key`;
    /// call `.unswap()` to convert to native LE limbs.
    pub(crate) fn x_scalar(&self) -> Scalar {
        // SAFETY: construction verifies that `x` points to `P256_DIGITS`
        // initialized limbs owned by this point.
        unsafe { Scalar::from_limbs(core::ptr::read(self.inner().x.cast())) }
    }

    /// Raw bytes of the X coordinate (big-endian wire format, 32 bytes).
    pub(crate) fn x_as_bytes(&self) -> [u8; P256_BYTES] {
        // SAFETY: construction verifies that `x` points to a complete P-256
        // coordinate, whose allocation is live for the duration of this read.
        unsafe { core::ptr::read(self.inner().x.cast()) }
    }

    /// Raw bytes of the Y coordinate (big-endian wire format, 32 bytes).
    pub(crate) fn y_as_bytes(&self) -> [u8; P256_BYTES] {
        // SAFETY: construction verifies that `y` points to a complete P-256
        // coordinate, whose allocation is live for the duration of this read.
        unsafe { core::ptr::read(self.inner().y.cast()) }
    }
}

impl Drop for Point {
    fn drop(&mut self) {
        // SAFETY: `inner` was returned by `ecc_alloc_point` and ownership has
        // not been transferred, so this is its unique matching free.
        unsafe { ffi::ecc_free_point(self.inner.as_ptr()) };
    }
}

pub(crate) fn get_curve_n() -> Option<Scalar> {
    // SAFETY: `P256` is a kernel-supported curve identifier. The returned
    // pointer is checked before it is dereferenced.
    let curve = unsafe { ffi::ecc_get_curve(P256) };
    if curve.is_null() {
        return None;
    }
    // SAFETY: `curve` was checked above and points to a static kernel curve.
    let n_ptr = unsafe { (*curve).n };
    if n_ptr.is_null() {
        return None;
    }
    // SAFETY: a P-256 curve's `n` buffer contains `P256_DIGITS` limbs.
    let n: [u64; P256_DIGITS] = unsafe { core::ptr::read(n_ptr.cast()) };
    Some(Scalar::from_limbs(n))
}

pub(crate) fn generate_private_key() -> Result<Scalar> {
    let mut key = Scalar::zero();
    // SAFETY: `key` provides the required writable `P256_DIGITS` limbs.
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
    // SAFETY: the digit count is the kernel-defined size for P-256.
    let p = NonNull::new(unsafe { ffi::ecc_alloc_point(P256_DIGITS as c_uint) }).ok_or(ENOMEM)?;
    // SAFETY: `p` is non-null and remains owned by this function.
    let point = unsafe { p.as_ref() };
    if point.x.is_null() || point.y.is_null() {
        // SAFETY: `p` is an allocation returned by `ecc_alloc_point`.
        unsafe { ffi::ecc_free_point(p.as_ptr()) };
        return Err(EFAULT);
    }

    let mut raw = [0u64; 2 * P256_DIGITS];
    // SAFETY: `privkey` has `P256_DIGITS` readable limbs and `raw` has twice
    // that many writable limbs, as required for the two coordinates.
    let ret = unsafe {
        ffi::ecc_make_pub_key(
            P256,
            P256_DIGITS as c_uint,
            privkey.as_ptr(),
            raw.as_mut_ptr(),
        )
    };
    if ret < 0 {
        // SAFETY: `p` is an allocation returned by `ecc_alloc_point`.
        unsafe { ffi::ecc_free_point(p.as_ptr()) };
        return Err(Error::from_errno(ret));
    }

    // SAFETY: both point buffers were checked for null and each has
    // `P256_DIGITS` limbs; the source halves are initialized and disjoint.
    unsafe {
        core::ptr::copy_nonoverlapping(raw.as_ptr(), point.x, P256_DIGITS);
        core::ptr::copy_nonoverlapping(raw.as_ptr().add(P256_DIGITS), point.y, P256_DIGITS);
    }

    Ok(Point { inner: p })
}

pub(crate) fn sha256_hash(data: &[u8]) -> [u8; P256_BYTES] {
    let mut out = [0u8; P256_BYTES];
    // SAFETY: `data` is readable for its length and `out` is a writable
    // SHA-256-sized buffer; neither pointer escapes the call.
    unsafe { ffi::sha256(data.as_ptr(), data.len() as c_ulong, out.as_mut_ptr()) };
    out
}

pub(crate) fn ima_measure_pubkey(bytes: &[u8]) -> Result {
    // SAFETY: labels are static NUL-terminated strings, `bytes` is readable
    // for the supplied length, and no digest output is requested.
    let result = unsafe {
        ffi::ima_measure_critical_data(
            c"tarako_pubkey".as_ptr(),
            c"public-key-generate".as_ptr(),
            bytes.as_ptr(),
            bytes.len() as c_ulong,
            // Critical-data measurements use the ima-buf template. Passing
            // false records the buffer itself; true would record only its
            // digest in the template's `buf` field.
            false,
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
