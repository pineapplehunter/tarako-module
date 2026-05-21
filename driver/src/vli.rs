// SPDX-License-Identifier: GPL-2.0
//
// Variable-Length Integer type wrapping `[u64; N]` limbs for ECC arithmetic.

use crate::ffi;
use core::cmp::Ordering;
use core::ffi::{c_int, c_uint};
use core::ops::{Add, Sub};

/// P-256 scalar / coordinate (4 limbs, 256 bits).
pub(crate) type Scalar = Vli<{ crate::ecc::P256_DIGITS }>;

/// A variable-length integer represented as N 64-bit limbs in LE order.
#[repr(transparent)]
pub(crate) struct Vli<const N: usize>([u64; N]);

// ── Constructors and raw access ──

impl<const N: usize> Vli<N> {
    pub(crate) const fn zero() -> Self {
        Vli([0u64; N])
    }

    pub(crate) const fn from_limbs(limbs: [u64; N]) -> Self {
        Vli(limbs)
    }

    pub(crate) fn as_ptr(&self) -> *const u64 {
        self.0.as_ptr()
    }

    pub(crate) fn as_mut_ptr(&mut self) -> *mut u64 {
        self.0.as_mut_ptr()
    }

    pub(crate) fn is_zero(&self) -> bool {
        unsafe { ffi::vli_is_zero(self.as_ptr(), N as c_uint) }
    }

    /// Add `right` with an initial `carry`, returning (sum, overflow).
    pub(crate) fn carrying_add(&self, right: &Self, mut carry: u64) -> (Self, u64) {
        let mut limbs = [0u64; N];
        for i in 0..N {
            let (s, c1) = self.0[i].overflowing_add(right.0[i]);
            let (s, c2) = s.overflowing_add(carry);
            limbs[i] = s;
            carry = (c1 as u64) + (c2 as u64);
        }
        (Vli(limbs), carry)
    }

    /// Subtract `right` returning (difference, borrow).
    pub(crate) fn sub_with_borrow(&self, right: &Self) -> (Self, u64) {
        let mut result = Vli::zero();
        let borrow = unsafe {
            ffi::vli_sub(
                result.as_mut_ptr(),
                self.as_ptr(),
                right.as_ptr(),
                N as c_uint,
            )
        };
        (result, borrow)
    }

    /// Reverse ecc_swap_digits: convert BE limb order back to LE.
    pub(crate) fn unswap(&self) -> Self {
        let mut out = Vli::zero();
        for i in 0..N {
            out.0[i] = u64::from_be(self.0[N - 1 - i]);
        }
        out
    }

    // ── FFI-based operations (work for any N) ──

    /// Convert big-endian bytes to LE limbs.  `bytes` must be exactly `N * 8` bytes.
    pub(crate) fn from_be_bytes(bytes: &[u8]) -> Self {
        let mut out = Vli::zero();
        unsafe {
            ffi::ecc_digits_from_bytes(
                bytes.as_ptr(),
                (N * 8) as c_uint,
                out.as_mut_ptr(),
                N as c_uint,
            )
        };
        out
    }

    /// Modular inverse: `self^(-1) mod modulus`.
    pub(crate) fn mod_inv(&self, modulus: &Self) -> Self {
        let mut result = Vli::zero();
        unsafe {
            ffi::vli_mod_inv(
                result.as_mut_ptr(),
                self.as_ptr(),
                modulus.as_ptr(),
                N as c_uint,
            )
        };
        result
    }

    /// Modular multiplication: `self * right mod modulus`.
    pub(crate) fn mod_mult(&self, right: &Self, modulus: &Self) -> Self {
        let mut result = Vli::zero();
        unsafe {
            ffi::vli_mod_mult_slow(
                result.as_mut_ptr(),
                self.as_ptr(),
                right.as_ptr(),
                modulus.as_ptr(),
                N as c_uint,
            )
        };
        result
    }
}

// ── Zeroize on drop ──

impl<const N: usize> Drop for Vli<N> {
    fn drop(&mut self) {
        for limb in self.0.iter_mut() {
            unsafe { core::ptr::write_volatile(limb, 0) };
        }
    }
}

// ── Clone (NOT Copy) ──

impl<const N: usize> Clone for Vli<N> {
    fn clone(&self) -> Self {
        Vli(self.0)
    }
}

// ── Deref ──

impl<const N: usize> core::ops::Deref for Vli<N> {
    type Target = [u64; N];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<const N: usize> core::ops::DerefMut for Vli<N> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

// ── Equality / Ordering ──

fn vli_cmp_to_ordering(r: c_int) -> Ordering {
    match r {
        0 => Ordering::Equal,
        r if r < 0 => Ordering::Less,
        _ => Ordering::Greater,
    }
}

impl<const N: usize> Vli<N> {
    fn cmp_ffi(&self, other: &Self) -> Ordering {
        let r = unsafe { ffi::vli_cmp(self.as_ptr(), other.as_ptr(), N as c_uint) };
        vli_cmp_to_ordering(r)
    }
}

impl<const N: usize> PartialEq for Vli<N> {
    fn eq(&self, other: &Self) -> bool {
        self.cmp_ffi(other) == Ordering::Equal
    }
}

impl<const N: usize> Eq for Vli<N> {}

impl<const N: usize> Ord for Vli<N> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.cmp_ffi(other)
    }
}

impl<const N: usize> PartialOrd for Vli<N> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp_ffi(other))
    }
}

impl<const N: usize> PartialOrd<&Self> for Vli<N> {
    fn partial_cmp(&self, other: &&Self) -> Option<Ordering> {
        Some(self.cmp_ffi(*other))
    }
}

impl<const N: usize> PartialEq<&Self> for Vli<N> {
    fn eq(&self, other: &&Self) -> bool {
        self.cmp_ffi(*other) == Ordering::Equal
    }
}

impl<const N: usize> core::ops::Sub<&Self> for Vli<N> {
    type Output = Self;
    fn sub(self, rhs: &Self) -> Self {
        let (result, _) = self.sub_with_borrow(rhs);
        result
    }
}

// ── Arithmetic ──

impl<const N: usize> Add for Vli<N> {
    type Output = Self;

    fn add(self, rhs: Self) -> Self {
        let (result, _) = self.carrying_add(&rhs, 0);
        result
    }
}

impl<const N: usize> Sub for Vli<N> {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self {
        let (result, _) = self.sub_with_borrow(&rhs);
        result
    }
}
