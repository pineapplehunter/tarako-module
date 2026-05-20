// SPDX-License-Identifier: GPL-2.0

use core::ffi::{c_int, c_uint, c_ulong};

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

extern "C" {
    pub(crate) fn ecc_gen_privkey(curve_id: c_uint, ndigits: c_uint, key: *mut u64) -> c_int;
    pub(crate) fn ecc_make_pub_key(
        curve_id: c_uint,
        ndigits: c_uint,
        privkey: *const u64,
        pubkey: *mut u64,
    ) -> c_int;
    pub(crate) fn ecc_get_curve(curve_id: c_uint) -> *const Curve;
    pub(crate) fn ecc_digits_from_bytes(
        inp: *const u8,
        nbytes: c_uint,
        out: *mut u64,
        ndigits: c_uint,
    );
    pub(crate) fn vli_mod_inv(
        result: *mut u64,
        input: *const u64,
        modulus: *const u64,
        ndigits: c_uint,
    );
    pub(crate) fn vli_mod_mult_slow(
        result: *mut u64,
        left: *const u64,
        right: *const u64,
        modulus: *const u64,
        ndigits: c_uint,
    );
    pub(crate) fn vli_sub(
        result: *mut u64,
        left: *const u64,
        right: *const u64,
        ndigits: c_uint,
    ) -> u64;
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
