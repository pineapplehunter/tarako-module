// SPDX-License-Identifier: GPL-2.0

use core::{cell::UnsafeCell, mem::MaybeUninit};
use kernel::sync::atomic::{
    ordering::{Acquire, Relaxed, Release},
    Atomic,
};

pub(crate) struct SetOnce<T> {
    init: Atomic<u32>,
    value: UnsafeCell<MaybeUninit<T>>,
}

impl<T> Default for SetOnce<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> SetOnce<T> {
    pub(crate) const fn new() -> Self {
        Self {
            value: UnsafeCell::new(MaybeUninit::uninit()),
            init: Atomic::new(0),
        }
    }

    pub(crate) fn as_ref(&self) -> Option<&T> {
        if self.init.load(Acquire) == 2 {
            // SAFETY: state 2 is published with release ordering only after
            // `value` is initialized, and values are never mutated while set.
            Some(unsafe { &*self.value.get().cast() })
        } else {
            None
        }
    }

    pub(crate) fn populate(&self, value: T) -> bool {
        if let Ok(0) = self.init.cmpxchg(0, 1, Relaxed) {
            // SAFETY: changing state from 0 to 1 gives this thread exclusive
            // access to the uninitialized storage.
            unsafe { core::ptr::write(self.value.get().cast(), value) };
            self.init.store(2, Release);
            true
        } else {
            false
        }
    }

    /// Drops the stored value and makes the cell empty again.
    ///
    /// # Safety
    ///
    /// The caller must ensure that no references returned by [`Self::as_ref`]
    /// exist and that no other thread can access the cell until this method
    /// returns.
    pub(crate) unsafe fn clear(&self) {
        if let Ok(2) = self.init.cmpxchg(2, 1, Acquire) {
            // SAFETY: the caller guarantees exclusive access, and state 2
            // means the storage contains an initialized `T`.
            unsafe { core::ptr::drop_in_place(self.value.get().cast::<T>()) };
            self.init.store(0, Release);
        }
    }
}

impl<T> Drop for SetOnce<T> {
    fn drop(&mut self) {
        if *self.init.get_mut() == 2 {
            let value = self.value.get_mut();
            // SAFETY: mutable access excludes other users, and state 2 means
            // the storage contains an initialized `T`.
            unsafe { value.assume_init_drop() };
        }
    }
}

// SAFETY: ownership of the stored value can cross threads only when `T` can.
unsafe impl<T: Send> Send for SetOnce<T> {}

// SAFETY: shared references are exposed only after release publication and
// the stored value is immutable; cross-thread sharing therefore requires
// both `Send` and `Sync` from `T`.
unsafe impl<T: Send + Sync> Sync for SetOnce<T> {}
