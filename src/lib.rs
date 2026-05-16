// SPDX-License-Identifier: GPL-2.0

//! A kernel module that creates an ECDSA P-256 key pair on load, generates a
//! self-signed X.509 certificate, and exposes it via a miscdevice with ioctls.

use core::ffi::c_ulong;
use kernel::{
    alloc::{flags::GFP_KERNEL, KBox},
    device::Device,
    fs::File,
    ioctl::{_IO, _IOC_SIZE, _IOR, _IOWR},
    miscdevice::{MiscDevice, MiscDeviceOptions, MiscDeviceRegistration},
    prelude::*,
    sync::{aref::ARef, rcu},
    uaccess::{UserPtr, UserSlice},
};

/* ------------------------------------------------------------------ */
/* FFI declarations                                                    */
/* ------------------------------------------------------------------ */

#[allow(dead_code, unreachable_pub)]
mod ecc {
    use core::ffi::{c_int, c_uint, c_ulong};

    #[repr(C)]
    pub struct Point {
        pub x: *mut u64,
        pub y: *mut u64,
        pub ndigits: u8,
    }

    #[repr(C)]
    pub struct Curve {
        pub name: *const i8,
        pub nbits: u32,
        pub g: Point,
        pub p: *mut u64,
        pub n: *mut u64,
        pub a: *mut u64,
        pub b: *mut u64,
    }

    // From include/crypto/ecdh.h: ECC_CURVE_NIST_P256 = 0x0002
    pub const P256: u32 = 0x0002;
    // From include/crypto/internal/ecc.h: ECC_CURVE_NIST_P256_DIGITS = 4
    pub const DIGITS: u32 = 4;

    extern "C" {
        pub fn ecc_gen_privkey(curve_id: c_uint, ndigits: c_uint, key: *mut u64) -> c_int;
        pub fn ecc_make_pub_key(
            curve_id: c_uint,
            ndigits: c_uint,
            privkey: *const u64,
            pubkey: *mut u64,
        ) -> c_int;
        pub fn ecc_get_curve(curve_id: c_uint) -> *const Curve;
        pub fn ecc_digits_from_bytes(
            inp: *const u8,
            nbytes: c_uint,
            out: *mut u64,
            ndigits: c_uint,
        );
        pub fn vli_mod_inv(
            result: *mut u64,
            input: *const u64,
            modulus: *const u64,
            ndigits: c_uint,
        );
        pub fn vli_mod_mult_slow(
            result: *mut u64,
            left: *const u64,
            right: *const u64,
            modulus: *const u64,
            ndigits: c_uint,
        );
        pub fn vli_sub(
            result: *mut u64,
            left: *const u64,
            right: *const u64,
            ndigits: c_uint,
        ) -> u64;
        pub fn vli_cmp(left: *const u64, right: *const u64, ndigits: c_uint) -> c_int;
        pub fn vli_is_zero(vli: *const u64, ndigits: c_uint) -> bool;
        pub fn get_random_bytes(buf: *mut u8, len: c_ulong);
        pub fn sha256(data: *const u8, len: c_ulong, out: *mut u8);
        pub fn ima_measure_critical_data(
            event_label: *const i8,
            event_name: *const i8,
            buf: *const u8,
            buf_len: c_ulong,
            hash: bool,
            digest: *mut u8,
            digest_len: c_ulong,
        ) -> c_int;
        pub fn fsverity_get_digest(
            inode: *mut u8,
            raw_digest: *mut u8,
            alg: *mut u8,
            halg: *mut u32,
        ) -> c_int;
    }

    pub fn get_curve_n() -> Option<[u64; 4]> {
        let curve = unsafe { ecc_get_curve(P256) };
        if curve.is_null() {
            return None;
        }
        let n_ptr = unsafe { (*curve).n };
        if n_ptr.is_null() {
            return None;
        }
        Some(unsafe { core::ptr::read(n_ptr as *const [u64; 4]) })
    }
}

fn uncompressed_pubkey_bytes(pub_x: &[u64; 4], pub_y: &[u64; 4]) -> [u8; 65] {
    let mut out = [0u8; 65];
    out[0] = 0x04;
    let xb = digits_to_be_bytes(pub_x);
    let yb = digits_to_be_bytes(pub_y);
    out[1..33].copy_from_slice(&xb);
    out[33..65].copy_from_slice(&yb);
    out
}

fn digits_to_be_bytes(digits: &[u64; 4]) -> [u8; 32] {
    let mut out = [0u8; 32];
    unsafe {
        core::ptr::copy_nonoverlapping(digits.as_ptr() as *const u8, out.as_mut_ptr(), 32);
    }
    pr_info!(
        "Signer: raw words {:016x}{:016x}{:016x}{:016x}\n",
        digits[0], digits[1], digits[2], digits[3],
    );
    out
}

fn be_bytes_to_digits(bytes: &[u8; 32]) -> [u64; 4] {
    let mut digits = [0u64; 4];
    for i in 0..4 {
        let mut word = [0u8; 8];
        word.copy_from_slice(&bytes[i * 8..(i + 1) * 8]);
        digits[3 - i] = u64::from_be_bytes(word);
    }
    digits
}

fn unswap_digits(swapped: &[u64; 4]) -> [u64; 4] {
    let mut out = [0u64; 4];
    for i in 0..4 {
        out[i] = u64::from_be(swapped[3 - i]);
    }
    out
}

fn le_limbs_to_be_bytes(digits: &[u64; 4]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for i in 0..4 {
        out[i * 8..(i + 1) * 8].copy_from_slice(&digits[3 - i].to_be_bytes());
    }
    out
}

/* ------------------------------------------------------------------ */
/* DER encoder helpers                                                 */
/* ------------------------------------------------------------------ */

struct DerBuf {
    buf: KBox<[u8; 2048]>,
    pos: usize,
}

impl DerBuf {
    fn new() -> Result<Self> {
        let buf = KBox::new([0u8; 2048], GFP_KERNEL).map_err(|_| ENOMEM)?;
        Ok(DerBuf { buf, pos: 0 })
    }

    fn as_slice(&self) -> &[u8] {
        &self.buf[..self.pos]
    }

    fn push(&mut self, b: u8) {
        self.buf[self.pos] = b;
        self.pos += 1;
    }

    fn extend(&mut self, data: &[u8]) {
        self.buf[self.pos..self.pos + data.len()].copy_from_slice(data);
        self.pos += data.len();
    }

    fn encode_length(&mut self, len: usize) {
        if len <= 0x7f {
            self.push(len as u8);
        } else if len <= 0xff {
            self.push(0x81);
            self.push(len as u8);
        } else if len <= 0xffff {
            self.push(0x82);
            self.push((len >> 8) as u8);
            self.push((len & 0xff) as u8);
        }
    }

    fn tag(&mut self, class: u8, constructed: bool, tag: u8, contents: &[u8]) {
        self.push((class << 6) | ((constructed as u8) << 5) | tag);
        self.encode_length(contents.len());
        self.extend(contents);
    }

    fn sequence(&mut self, contents: &[u8]) {
        self.tag(0, true, 0x10, contents);
    }
    fn set(&mut self, contents: &[u8]) {
        self.tag(0, true, 0x11, contents);
    }

    fn integer(&mut self, val: i64) {
        if val == 0 {
            self.buf[self.pos..self.pos + 3].copy_from_slice(&[0x02, 0x01, 0x00]);
            self.pos += 3;
            return;
        }
        let mut tmp = [0u8; 9];
        let mut n = 0usize;
        let mut v = val;
        while v != 0 {
            tmp[8 - n] = (v & 0xff) as u8;
            v >>= 8;
            n += 1;
        }
        let bytes = &tmp[9 - n..9];
        let (start, extra) = if bytes[0] & 0x80 != 0 {
            (0usize, 1usize)
        } else {
            (0usize, 0usize)
        };
        let data = &bytes[start..];
        self.push(0x02);
        self.encode_length(data.len() + extra);
        if extra > 0 {
            self.push(0x00);
        }
        self.extend(data);
    }

    fn integer_bytes(&mut self, val: &[u8]) {
        let start = val.iter().position(|&b| b != 0).unwrap_or(0);
        let data = &val[start..];
        self.push(0x02);
        if data.is_empty() || data[0] & 0x80 != 0 {
            self.encode_length(data.len() + 1);
            self.push(0x00);
        } else {
            self.encode_length(data.len());
        }
        self.extend(data);
    }

    fn oid(&mut self, oid: &[u32]) {
        let mut enc = [0u8; 64];
        let mut epos = 0usize;
        if oid.len() >= 2 {
            enc[epos] = (oid[0] * 40 + oid[1]) as u8;
            epos += 1;
        }
        for &val in &oid[2..] {
            if val < 128 {
                enc[epos] = val as u8;
                epos += 1;
            } else {
                let mut v = val;
                let mut tmp = [0u8; 5];
                let mut tn = 0usize;
                tmp[tn] = (v & 0x7f) as u8;
                tn += 1;
                v >>= 7;
                while v > 0 {
                    tmp[tn] = ((v & 0x7f) | 0x80) as u8;
                    tn += 1;
                    v >>= 7;
                }
                for j in (0..tn).rev() {
                    enc[epos] = tmp[j];
                    epos += 1;
                }
            }
        }
        self.push(0x06);
        self.encode_length(epos);
        self.extend(&enc[..epos]);
    }

    fn bit_string(&mut self, unused: u8, contents: &[u8]) {
        self.push(0x03);
        self.encode_length(1 + contents.len());
        self.push(unused);
        self.extend(contents);
    }

    fn utf8_string(&mut self, s: &[u8]) {
        self.push(0x0c);
        self.encode_length(s.len());
        self.extend(s);
    }

    fn utctime(&mut self, s: &[u8]) {
        self.push(0x17);
        self.encode_length(s.len());
        self.extend(s);
    }

    fn tagged_explicit(&mut self, tag: u8, contents: &[u8]) {
        self.tag(2, true, tag, contents);
    }
}

module! {
    type: SignerModule,
    name: "signer",
    authors: ["Shogo Takata"],
    description: "A signer kernel module with chrdev and ioctl",
    license: "GPL",
}

/* ------------------------------------------------------------------ */
/* Constants                                                           */
/* ------------------------------------------------------------------ */

// OID 1.2.840.10045.2.1 — id-ecPublicKey (ANSI X9.62, RFC 5480 sec 2.1.1)
const OID_EC_PUBKEY: [u32; 6] = [1, 2, 840, 10045, 2, 1];
// OID 1.2.840.10045.3.1.7 — secp256r1 / prime256v1 (ANSI X9.62, SEC 2)
const OID_SECP256R1: [u32; 7] = [1, 2, 840, 10045, 3, 1, 7];
// OID 1.2.840.10045.4.3.2 — ecdsa-with-SHA256 (ANSI X9.62, RFC 5758)
const OID_ECDSA_WITH_SHA256: [u32; 7] = [1, 2, 840, 10045, 4, 3, 2];
// OID 2.5.4.3 — commonName (ITU-T X.520 / RFC 4519 sec 2.3)
const OID_CN: [u32; 4] = [2, 5, 4, 3];

// ioctl command numbers: type 'S' (0x53), sequence 0..2
const SIGNER_HELLO: u32 = _IO('S' as u32, 0x00);
const SIGNER_GET_CERT: u32 = _IOR::<[u8; 2048]>('S' as u32, 0x01);
const SIGNER_SIGN_DATA: u32 = _IOWR::<SignDataReq>('S' as u32, 0x02);

#[repr(C)]
struct SignDataReq {
    nonce: [u8; 32],
    hash: [u8; 32],
    sig_r: [u8; 32],
    sig_s: [u8; 32],
    pubkey: [u8; 65],
}

// Arbitrary validity period for the self-signed cert (UTC, format YYMMDDHHMMSSZ)
const CURR_TIME: &[u8] = b"250101000000Z";
const EXPIRE_TIME: &[u8] = b"350101000000Z";
// X.509 subject commonName
const SUBJECT: &[u8] = b"signer";

/* ------------------------------------------------------------------ */
/* Key pair storage                                                    */
/* ------------------------------------------------------------------ */

struct KeyPair {
    private: [u64; ecc::DIGITS as usize],
    pubkey: [u8; 65],
    cert: [u8; 2048],
    cert_len: usize,
}

kernel::sync::global_lock! {
    unsafe(uninit) static KEY_PAIR: Mutex<Option<KeyPair>> = None;
}

/* ------------------------------------------------------------------ */
/* ECDSA operations                                                    */
/* ------------------------------------------------------------------ */

fn ecdsa_sign(data: &[u8], privkey: &[u64; 4]) -> Result<([u8; 32], [u8; 32])> {
    let curve_n = ecc::get_curve_n().ok_or(EINVAL)?;
    let ndigits = ecc::DIGITS;
    let mut data_hash = [0u8; 32];
    unsafe { ecc::sha256(data.as_ptr(), data.len() as c_ulong, data_hash.as_mut_ptr()) };

    loop {
        let mut k = [0u64; 4];
        let ret = unsafe { ecc::ecc_gen_privkey(ecc::P256, ndigits, k.as_mut_ptr()) };
        if ret < 0 {
            return Err(EINVAL);
        }

        let mut pubk = [0u64; 8];
        let ret = unsafe {
            ecc::ecc_make_pub_key(ecc::P256, ndigits, k.as_ptr(), pubk.as_mut_ptr())
        };
        if ret < 0 {
            return Err(EINVAL);
        }

        let mut r_swapped = [0u64; 4];
        r_swapped.copy_from_slice(&pubk[..4]);
        let mut r_digits = unswap_digits(&r_swapped);
        if unsafe { ecc::vli_cmp(r_digits.as_ptr(), curve_n.as_ptr(), ndigits) } >= 0 {
            let r_copy = r_digits;
            unsafe {
                ecc::vli_sub(
                    r_digits.as_mut_ptr(),
                    r_copy.as_ptr(),
                    curve_n.as_ptr(),
                    ndigits,
                );
            }
        }

        if unsafe { ecc::vli_is_zero(r_digits.as_ptr(), ndigits) } {
            continue;
        }

        let mut s_digits = [0u64; 4];
        unsafe {
            ecc::vli_mod_mult_slow(
                s_digits.as_mut_ptr(),
                r_digits.as_ptr(),
                privkey.as_ptr(),
                curve_n.as_ptr(),
                ndigits,
            );
        }

        let mut z = [0u64; 4];
        unsafe {
            ecc::ecc_digits_from_bytes(data_hash.as_ptr(), 32, z.as_mut_ptr(), ndigits);
        }

        let mut z_plus_rs = z;
        let mut carry = 0u64;
        for i in 0..4 {
            let (s, c1) = z_plus_rs[i].overflowing_add(s_digits[i]);
            let (s, c2) = s.overflowing_add(carry);
            z_plus_rs[i] = s;
            carry = (c1 as u64) + (c2 as u64);
        }
        if carry != 0 || unsafe { ecc::vli_cmp(z_plus_rs.as_ptr(), curve_n.as_ptr(), ndigits) } >= 0
        {
            let tmp = z_plus_rs;
            unsafe {
                ecc::vli_sub(
                    z_plus_rs.as_mut_ptr(),
                    tmp.as_ptr(),
                    curve_n.as_ptr(),
                    ndigits,
                );
            }
        }

        let mut k_inv = [0u64; 4];
        unsafe {
            ecc::vli_mod_inv(k_inv.as_mut_ptr(), k.as_ptr(), curve_n.as_ptr(), ndigits);
        }

        unsafe {
            ecc::vli_mod_mult_slow(
                s_digits.as_mut_ptr(),
                z_plus_rs.as_ptr(),
                k_inv.as_ptr(),
                curve_n.as_ptr(),
                ndigits,
            );
        }

        if unsafe { ecc::vli_is_zero(s_digits.as_ptr(), ndigits) } {
            continue;
        }

        let sig_r_bytes = le_limbs_to_be_bytes(&r_digits);
        let sig_s_bytes = le_limbs_to_be_bytes(&s_digits);

        return Ok((sig_r_bytes, sig_s_bytes));
    }
}

/* ------------------------------------------------------------------ */
/* Self-signed X.509 certificate builder                               */
/* ------------------------------------------------------------------ */

fn build_certificate(privkey: &[u64; 4], pub_x: &[u64; 4], pub_y: &[u64; 4]) -> Result<([u8; 2048], usize)> {
    let pubkey_bytes = uncompressed_pubkey_bytes(pub_x, pub_y);

    let mut spki = DerBuf::new()?;
    {
        let mut algo = DerBuf::new()?;
        algo.oid(&OID_EC_PUBKEY);
        algo.oid(&OID_SECP256R1);

        spki.sequence(algo.as_slice());
        spki.bit_string(0, &pubkey_bytes);
    }
    let spki_seq = {
        let mut s = DerBuf::new()?;
        s.sequence(spki.as_slice());
        s
    };

    let mut sig_algo = DerBuf::new()?;
    sig_algo.oid(&OID_ECDSA_WITH_SHA256);
    let sig_algo_seq = {
        let mut s = DerBuf::new()?;
        s.sequence(sig_algo.as_slice());
        s
    };

    let mut validity = DerBuf::new()?;
    validity.utctime(CURR_TIME);
    validity.utctime(EXPIRE_TIME);
    let validity_seq = {
        let mut s = DerBuf::new()?;
        s.sequence(validity.as_slice());
        s
    };

    let mut name = DerBuf::new()?;
    {
        let mut attr = DerBuf::new()?;
        attr.oid(&OID_CN);
        attr.utf8_string(SUBJECT);
        let mut attr_seq = DerBuf::new()?;
        attr_seq.sequence(attr.as_slice());
        let mut set = DerBuf::new()?;
        set.set(attr_seq.as_slice());
        name.sequence(set.as_slice());
    }

    let mut version = DerBuf::new()?;
    version.integer(2);
    let mut version_tagged = DerBuf::new()?;
    version_tagged.tagged_explicit(0, version.as_slice());

    let mut tbs = DerBuf::new()?;
    tbs.extend(version_tagged.as_slice());
    tbs.integer(1);
    tbs.extend(sig_algo_seq.as_slice());
    tbs.extend(name.as_slice());
    tbs.extend(validity_seq.as_slice());
    tbs.extend(name.as_slice());
    tbs.extend(spki_seq.as_slice());

    let tbs_cert = {
        let mut s = DerBuf::new()?;
        s.sequence(tbs.as_slice());
        let mut out = [0u8; 2048];
        let len = s.pos;
        if len > 2048 {
            return Err(ENOSPC);
        }
        out[..len].copy_from_slice(&s.buf[..len]);
        (out, len)
    };
    let tbs_bytes = &tbs_cert.0[..tbs_cert.1];
    let (sig_r, sig_s) = ecdsa_sign(tbs_bytes, privkey)?;

    let mut sig_der = DerBuf::new()?;
    sig_der.integer_bytes(&sig_r);
    sig_der.integer_bytes(&sig_s);
    let sig_seq = {
        let mut s = DerBuf::new()?;
        s.sequence(sig_der.as_slice());
        s
    };

    let mut cert = DerBuf::new()?;
    cert.extend(tbs_bytes);
    cert.extend(sig_algo_seq.as_slice());
    cert.bit_string(0, sig_seq.as_slice());

    let mut out = [0u8; 2048];
    let cert_seq = {
        let mut s = DerBuf::new()?;
        s.sequence(cert.as_slice());
        s
    };
    let len = cert_seq.pos;
    if len > 2048 {
        return Err(ENOSPC);
    }
    out[..len].copy_from_slice(&cert_seq.buf[..len]);
    Ok((out, len))
}

fn generate_key_pair() -> Result<KeyPair> {
    let mut private = [0u64; ecc::DIGITS as usize];
    let mut public = [0u64; ecc::DIGITS as usize * 2];

    let ret = unsafe {
        ecc::ecc_gen_privkey(ecc::P256, ecc::DIGITS, private.as_mut_ptr())
    };
    if ret < 0 {
        return Err(EINVAL);
    }

    let ret = unsafe {
        ecc::ecc_make_pub_key(ecc::P256, ecc::DIGITS, private.as_ptr(), public.as_mut_ptr())
    };
    if ret < 0 {
        return Err(EINVAL);
    }

    let mut pub_x = [0u64; ecc::DIGITS as usize];
    let mut pub_y = [0u64; ecc::DIGITS as usize];
    pub_x.copy_from_slice(&public[..ecc::DIGITS as usize]);
    pub_y.copy_from_slice(&public[ecc::DIGITS as usize..]);

    let pubkey_bytes = uncompressed_pubkey_bytes(&pub_x, &pub_y);

    if let Some(n) = ecc::get_curve_n() {
        pr_info!("Signer: curve N words ({:016x}{:016x}{:016x}{:016x})\n",
            n[0], n[1], n[2], n[3]);
    }
    pr_info!("Signer: pubkey X words ({:016x}{:016x}{:016x}{:016x})\n",
        pub_x[0], pub_x[1], pub_x[2], pub_x[3]);
    pr_info!("Signer: pubkey Y words ({:016x}{:016x}{:016x}{:016x})\n",
        pub_y[0], pub_y[1], pub_y[2], pub_y[3]);
    {
        let mut hex = [0u8; 130];
        for i in 0..65 {
            let v = pubkey_bytes[i];
            let hi = v >> 4;
            let lo = v & 0xf;
            hex[i * 2] = if hi < 10 { b'0' + hi } else { b'a' + hi - 10 };
            hex[i * 2 + 1] = if lo < 10 { b'0' + lo } else { b'a' + lo - 10 };
        }
        pr_info!("Signer: pubkey hex ({})\n", core::str::from_utf8(&hex).unwrap_or("???"));
    }

    let _ima_ret = unsafe {
        ecc::ima_measure_critical_data(
            c"signer_key".as_ptr() as *const i8,
            c"public".as_ptr() as *const i8,
            pubkey_bytes.as_ptr(),
            pubkey_bytes.len() as c_ulong,
            true,
            core::ptr::null_mut(),
            0,
        )
    };

    let (cert, cert_len) = build_certificate(&private, &pub_x, &pub_y)?;

    Ok(KeyPair {
        private,
        pubkey: pubkey_bytes,
        cert,
        cert_len,
    })
}

/* ------------------------------------------------------------------ */
/* fs-verity check helper                                              */
/* ------------------------------------------------------------------ */

// From include/uapi/linux/fs.h: FS_VERITY_FL = 0x00100000
const S_VERITY: u32 = 1 << 16;

fn current_exe_has_fsverity() -> bool {
    let current = crate::current!();
    let Some(mm) = current.mm() else {
        return false;
    };
    let mm_ptr = mm.as_raw();
    if mm_ptr.is_null() {
        return false;
    }
    let guard = rcu::read_lock();
    let exe_file = unsafe { (*mm_ptr).__bindgen_anon_1.exe_file };
    if exe_file.is_null() {
        return false;
    }
    let inode = unsafe { *(*exe_file).f_inode };
    let has_verity = inode.i_flags as u32 & S_VERITY != 0;
    drop(guard);
    has_verity
}

fn current_exe_fsverity_digest() -> Result<(usize, [u8; 64])> {
    let current = crate::current!();
    let mm = current.mm().ok_or(EPERM)?;
    let mm_ptr = mm.as_raw();
    if mm_ptr.is_null() {
        return Err(EPERM);
    }
    let _guard = rcu::read_lock();
    let exe_file = unsafe { (*mm_ptr).__bindgen_anon_1.exe_file };
    if exe_file.is_null() {
        return Err(EPERM);
    }
    let inode = unsafe { (*exe_file).f_inode as *mut u8 };
    let mut digest = [0u8; 64];
    let ret = unsafe {
        ecc::fsverity_get_digest(inode, digest.as_mut_ptr(), core::ptr::null_mut(), core::ptr::null_mut())
    };
    if ret <= 0 {
        return Err(EPERM);
    }
    Ok((ret as usize, digest))
}

/* ------------------------------------------------------------------ */
/* Module                                                              */
/* ------------------------------------------------------------------ */

#[pin_data]
struct SignerModule {
    #[pin]
    _miscdev: MiscDeviceRegistration<SignerDevice>,
}

impl kernel::InPlaceModule for SignerModule {
    fn init(_module: &'static ThisModule) -> impl PinInit<Self, Error> {
        pr_info!("Signer: loading, generating ECDSA P-256 key pair\n");

        unsafe { KEY_PAIR.init() };

        match generate_key_pair() {
            Ok(kp) => {
                let mut guard = KEY_PAIR.lock();
                *guard = Some(kp);
                let len = guard.as_ref().map(|k| k.cert_len).unwrap_or(0);
                pr_info!(
                    "Signer: key pair generated, certificate ready ({} bytes)\n",
                    len
                );
            }
            Err(_) => {
                pr_info!("Signer: failed to generate key pair\n");
            }
        }

        let options = MiscDeviceOptions { name: c"signer" };
        try_pin_init!(Self {
            _miscdev <- MiscDeviceRegistration::register(options),
        })
    }
}

/* ------------------------------------------------------------------ */
/* Device                                                              */
/* ------------------------------------------------------------------ */

#[pin_data(PinnedDrop)]
struct SignerDevice {
    dev: ARef<Device>,
}

#[vtable]
impl MiscDevice for SignerDevice {
    type Ptr = Pin<KBox<Self>>;

    fn open(_file: &File, misc: &MiscDeviceRegistration<Self>) -> Result<Pin<KBox<Self>>> {
        let dev = ARef::from(misc.device());
        pr_info!("Signer: opened\n");
        KBox::try_pin_init(try_pin_init! { SignerDevice { dev: dev } }, GFP_KERNEL)
    }

    fn ioctl(_me: Pin<&SignerDevice>, _file: &File, cmd: u32, arg: usize) -> Result<isize> {
        if !current_exe_has_fsverity() {
            pr_info!("Signer: rejected ioctl from non-fsverity binary\n");
            return Err(EPERM);
        }

        match cmd {
            SIGNER_HELLO => {
                pr_info!("Signer: hello from ioctl\n");
                Ok(0)
            }
            SIGNER_GET_CERT => {
                let guard = KEY_PAIR.lock();
                let kp = guard.as_ref().ok_or(ENXIO)?;
                let ptr = UserPtr::from_addr(arg);
                let buf_size = _IOC_SIZE(cmd);
                let write_len = core::cmp::min(kp.cert_len, buf_size);
                let mut writer = UserSlice::new(ptr, buf_size).writer();
                writer.write_slice(&kp.cert[..write_len])?;
                pr_info!("Signer: returned certificate ({} bytes)\n", write_len);
                Ok(write_len as isize)
            }
            SIGNER_SIGN_DATA => {
                let ptr = UserPtr::from_addr(arg);
                let buf_size = _IOC_SIZE(cmd);
                let mut reader = UserSlice::new(ptr, buf_size).reader();

                let mut req = SignDataReq {
                    nonce: [0u8; 32],
                    hash: [0u8; 32],
                    sig_r: [0u8; 32],
                    sig_s: [0u8; 32],
                    pubkey: [0u8; 65],
                };
                {
                    let req_ptr = &mut req as *mut SignDataReq as *mut u8;
                    let req_slice = unsafe {
                        core::slice::from_raw_parts_mut(
                            req_ptr,
                            core::mem::size_of::<SignDataReq>(),
                        )
                    };
                    reader.read_slice(req_slice)?;
                }

                let (digest_len, fsverity_digest) = current_exe_fsverity_digest()?;

                let to_sign_len = digest_len + 32;
                let mut to_sign = [0u8; 96];
                to_sign[..digest_len].copy_from_slice(&fsverity_digest[..digest_len]);
                to_sign[digest_len..to_sign_len].copy_from_slice(&req.nonce);

                unsafe {
                    ecc::sha256(to_sign.as_ptr(), to_sign_len as c_ulong, req.hash.as_mut_ptr());
                }

                let guard = KEY_PAIR.lock();
                let kp = guard.as_ref().ok_or(ENXIO)?;
                let (sig_r, sig_s) = ecdsa_sign(&to_sign[..to_sign_len], &kp.private)?;
                req.sig_r.copy_from_slice(&sig_r);
                req.sig_s.copy_from_slice(&sig_s);
                req.pubkey.copy_from_slice(&kp.pubkey);
                drop(guard);

                let mut writer = UserSlice::new(ptr, buf_size).writer();
                let req_ptr = &req as *const SignDataReq as *const u8;
                let req_slice = unsafe {
                    core::slice::from_raw_parts(req_ptr, core::mem::size_of::<SignDataReq>())
                };
                writer.write_slice(req_slice)?;

                pr_info!("Signer: computed signature\n");
                Ok(0)
            }
            _ => {
                pr_info!("Signer: unknown ioctl 0x{:x}\n", cmd);
                Err(ENOTTY)
            }
        }
    }
}

#[pinned_drop]
impl PinnedDrop for SignerDevice {
    fn drop(self: Pin<&mut Self>) {
        pr_info!("Signer: goodbye!\n");
    }
}
