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
    // Generate ECDSA private key (crypto/ecc.c:1513)
    pub(crate) fn ecc_gen_privkey(curve_id: c_uint, ndigits: c_uint, key: *mut u64) -> c_int;
    // Derive public key from private key (crypto/ecc.c:1552)
    pub(crate) fn ecc_make_pub_key(
        curve_id: c_uint,
        ndigits: c_uint,
        privkey: *const u64,
        pubkey: *mut u64,
    ) -> c_int;
    // Get curve parameters by ID (crypto/ecc.c:53)
    pub(crate) fn ecc_get_curve(curve_id: c_uint) -> *const Curve;
    // Convert big-endian bytes to LE u64 limbs (crypto/ecc.c:71)
    pub(crate) fn ecc_digits_from_bytes(
        inp: *const u8,
        nbytes: c_uint,
        out: *mut u64,
        ndigits: c_uint,
    );
    // Modular inverse: result = input^(-1) mod modulus (crypto/ecc.c:1030)
    pub(crate) fn vli_mod_inv(
        result: *mut u64,
        input: *const u64,
        modulus: *const u64,
        ndigits: c_uint,
    );
    // Modular multiplication: result = left * right mod modulus (crypto/ecc.c:995)
    pub(crate) fn vli_mod_mult_slow(
        result: *mut u64,
        left: *const u64,
        right: *const u64,
        modulus: *const u64,
        ndigits: c_uint,
    );
    // SHA-256 hash (lib/crypto/sha256.c:262)
    pub(crate) fn sha256(data: *const u8, len: c_ulong, out: *mut u8);
    // Log a critical data measurement to IMA (security/integrity/ima/ima_main.c:1209)
    pub(crate) fn ima_measure_critical_data(
        event_label: *const i8,
        event_name: *const i8,
        buf: *const u8,
        buf_len: c_ulong,
        hash: bool,
        digest: *mut u8,
        digest_len: c_ulong,
    ) -> c_int;
    // Get fs-verity digest for an inode (fs/verity/measure.c:86)
    pub(crate) fn fsverity_get_digest(
        inode: *mut core::ffi::c_void,
        raw_digest: *mut u8,
        alg: *mut u8,
        halg: *mut u32,
    ) -> c_int;
}
