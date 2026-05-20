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
            Some(unsafe { &*self.value.get().cast() })
        } else {
            None
        }
    }

    pub(crate) fn populate(&self, value: T) -> bool {
        if let Ok(0) = self.init.cmpxchg(0, 1, Relaxed) {
            unsafe { core::ptr::write(self.value.get().cast(), value) };
            self.init.store(2, Release);
            true
        } else {
            false
        }
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
