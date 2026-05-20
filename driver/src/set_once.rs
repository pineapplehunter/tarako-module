// SPDX-License-Identifier: GPL-2.0

use core::{cell::UnsafeCell, mem::MaybeUninit};
use kernel::sync::atomic::{
    ordering::{Acquire, Relaxed, Release},
    Atomic,
};

/// A container that can be populated at most once. Thread safe.
///
/// Once the a [`SetOnce`] is populated, it remains populated by the same object for the
/// lifetime `Self`.
///
/// # Invariants
///
/// - `init` may only increase in value.
/// - `init` may only assume values in the range `0..=2`.
/// - `init == 0` if and only if `value` is uninitialized.
/// - `init == 1` if and only if there is exactly one thread with exclusive
///   access to `self.value`.
/// - `init == 2` if and only if `value` is initialized and valid for shared
///   access.
pub struct SetOnce<T> {
    init: Atomic<u32>,
    value: UnsafeCell<MaybeUninit<T>>,
}

impl<T> Default for SetOnce<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> SetOnce<T> {
    /// Create a new [`SetOnce`].
    ///
    /// The returned instance will be empty.
    pub const fn new() -> Self {
        Self {
            value: UnsafeCell::new(MaybeUninit::uninit()),
            init: Atomic::new(0),
        }
    }

    /// Get a reference to the contained object.
    ///
    /// Returns [`None`] if this [`SetOnce`] is empty.
    pub fn as_ref(&self) -> Option<&T> {
        if self.init.load(Acquire) == 2 {
            Some(unsafe { &*self.value.get().cast() })
        } else {
            None
        }
    }

    /// Populate the [`SetOnce`].
    ///
    /// Returns `true` if the [`SetOnce`] was successfully populated.
    pub fn populate(&self, value: T) -> bool {
        if let Ok(0) = self.init.cmpxchg(0, 1, Relaxed) {
            unsafe { core::ptr::write(self.value.get().cast(), value) };
            self.init.store(2, Release);
            true
        } else {
            false
        }
    }

    /// Get a copy of the contained object.
    ///
    /// Returns [`None`] if the [`SetOnce`] is empty.
    pub fn copy(&self) -> Option<T>
    where
        T: Copy,
    {
        self.as_ref().copied()
    }
}

impl<T> Drop for SetOnce<T> {
    fn drop(&mut self) {
        if *self.init.get_mut() == 2 {
            let value = self.value.get_mut();
            unsafe { value.assume_init_drop() };
        }
    }
}

unsafe impl<T: Send> Send for SetOnce<T> {}

unsafe impl<T: Send + Sync> Sync for SetOnce<T> {}
