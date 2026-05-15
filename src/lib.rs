// SPDX-License-Identifier: GPL-2.0

//! A kernel module that creates an ECDSA P-256 key pair on load, generates a
//! self-signed X.509 certificate, and exposes it via a miscdevice with ioctls.

use core::ffi::c_ulong;
use kernel::{
    device::Device,
    fs::File,
    ioctl::{_IO, _IOC_SIZE, _IOR, _IOWR},
    miscdevice::{MiscDevice, MiscDeviceOptions, MiscDeviceRegistration},
    prelude::*,
    sync::aref::ARef,
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

    const P256: u32 = 0x0002;
    const DIGITS: u32 = 4;

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
    }

    pub fn p256_ndigits() -> u32 {
        DIGITS
    }
    pub fn p256_curve_id() -> u32 {
        P256
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

fn digits_to_be_bytes(digits: &[u64; 4]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for i in 0..4 {
        let bytes = digits[3 - i].to_be_bytes();
        out[i * 8..(i + 1) * 8].copy_from_slice(&bytes);
    }
    out
}

/* ------------------------------------------------------------------ */
/* DER encoder helpers                                                 */
/* ------------------------------------------------------------------ */

struct DerBuf {
    buf: [u8; 4096],
    pos: usize,
}

impl DerBuf {
    fn new() -> Self {
        DerBuf {
            buf: [0u8; 4096],
            pos: 0,
        }
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

const P256_DIGITS: usize = 4;

const OID_EC_PUBKEY: [u32; 6] = [1, 2, 840, 10045, 2, 1];
const OID_SECP256R1: [u32; 7] = [1, 2, 840, 10045, 3, 1, 7];
const OID_ECDSA_WITH_SHA256: [u32; 7] = [1, 2, 840, 10045, 4, 3, 2];
const OID_CN: [u32; 4] = [2, 5, 4, 3];

const SIGNER_HELLO: u32 = _IO('S' as u32, 0x00);
const SIGNER_GET_CERT: u32 = _IOR::<[u8; 2048]>('S' as u32, 0x01);
const SIGNER_SIGN_DATA: u32 = _IOWR::<SignDataReq>('S' as u32, 0x02);

#[repr(C)]
struct SignDataReq {
    data_len: u32,
    data: [u8; 256],
    sig_r: [u8; 32],
    sig_s: [u8; 32],
}

const CURR_TIME: &[u8] = b"250101000000Z";
const EXPIRE_TIME: &[u8] = b"350101000000Z";
const SUBJECT: &[u8] = b"signer";

/* ------------------------------------------------------------------ */
/* Key pair storage                                                    */
/* ------------------------------------------------------------------ */

struct KeyPair {
    private: [u64; P256_DIGITS],
    cert: [u8; 2048],
    cert_len: usize,
}

kernel::sync::global_lock! {
    unsafe(uninit) static KEY_PAIR: Mutex<Option<KeyPair>> = None;
}

/* ------------------------------------------------------------------ */
/* SHA-256 helper                                                      */
/* ------------------------------------------------------------------ */

fn sha256_digest(data: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    unsafe { ecc::sha256(data.as_ptr(), data.len() as c_ulong, out.as_mut_ptr()) };
    out
}

/* ------------------------------------------------------------------ */
/* Big integer helpers for u64[4] (P-256)                              */
/* ------------------------------------------------------------------ */

fn cmp_u64(a: &[u64; 4], b: &[u64; 4]) -> i32 {
    for i in (0..4).rev() {
        if a[i] > b[i] {
            return 1;
        }
        if a[i] < b[i] {
            return -1;
        }
    }
    0
}

fn u64_sub(r: &mut [u64; 4], a: &[u64; 4], b: &[u64; 4]) -> u64 {
    let mut borrow = 0u64;
    for i in 0..4 {
        let (d, b1) = a[i].overflowing_sub(b[i]);
        let (d, b2) = d.overflowing_sub(borrow);
        r[i] = d;
        borrow = (b1 as u64) + (b2 as u64);
    }
    borrow
}

fn mod_sub_n(r: &mut [u64; 4], n: &[u64; 4]) {
    let tmp = *r;
    u64_sub(r, &tmp, n);
}

fn mod_add_n(a: &[u64; 4], b: &[u64; 4], n: &[u64; 4]) -> [u64; 4] {
    let mut r = *a;
    let mut carry = 0u64;
    for i in 0..4 {
        let (s, c1) = r[i].overflowing_add(b[i]);
        let (s, c2) = s.overflowing_add(carry);
        r[i] = s;
        carry = (c1 as u64) + (c2 as u64);
    }
    if carry != 0 || cmp_u64(&r, n) >= 0 {
        mod_sub_n(&mut r, n);
    }
    r
}

/* ------------------------------------------------------------------ */
/* ECDSA operations                                                    */
/* ------------------------------------------------------------------ */

fn ecdsa_sign(data: &[u8], privkey: &[u64; 4]) -> Result<([u8; 32], [u8; 32])> {
    let curve_n = ecc::get_curve_n().ok_or(EINVAL)?;
    let ndigits = ecc::p256_ndigits();
    let data_hash = sha256_digest(data);

    loop {
        let mut k = [0u64; 4];
        let ret = unsafe { ecc::ecc_gen_privkey(ecc::p256_curve_id(), ndigits, k.as_mut_ptr()) };
        if ret < 0 {
            return Err(EINVAL);
        }

        let mut pubk = [0u64; 8];
        let ret = unsafe {
            ecc::ecc_make_pub_key(ecc::p256_curve_id(), ndigits, k.as_ptr(), pubk.as_mut_ptr())
        };
        if ret < 0 {
            return Err(EINVAL);
        }

        let mut r_digits = [0u64; 4];
        r_digits.copy_from_slice(&pubk[..4]);
        let r_gt_n = cmp_u64(&r_digits, &curve_n) >= 0;
        if r_gt_n {
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

        let z_plus_rs = mod_add_n(&z, &s_digits, &curve_n);

        unsafe {
            ecc::vli_mod_mult_slow(
                s_digits.as_mut_ptr(),
                z_plus_rs.as_ptr(),
                k.as_ptr(),
                curve_n.as_ptr(),
                ndigits,
            );
        }

        if unsafe { ecc::vli_is_zero(s_digits.as_ptr(), ndigits) } {
            continue;
        }

        let sig_r_bytes = digits_to_be_bytes(&r_digits);
        let sig_s_bytes = digits_to_be_bytes(&s_digits);

        return Ok((sig_r_bytes, sig_s_bytes));
    }
}

/* ------------------------------------------------------------------ */
/* Self-signed X.509 certificate builder                               */
/* ------------------------------------------------------------------ */

fn encode_integer_val(buf: &mut DerBuf, val: &[u8; 32]) {
    let mut start = 0usize;
    while start < 32 && val[start] == 0 {
        start += 1;
    }
    let data = &val[start..];
    let extra_byte = if data.is_empty() || data[0] & 0x80 != 0 {
        1
    } else {
        0
    };
    buf.push(0x02);
    buf.encode_length(data.len() + extra_byte);
    if extra_byte > 0 {
        buf.push(0x00);
    }
    buf.extend(data);
}

fn build_certificate(privkey: &[u64; 4], pub_x: &[u64; 4], pub_y: &[u64; 4]) -> Result<[u8; 2048]> {
    let mut pubkey_bytes = [0u8; 65];
    pubkey_bytes[0] = 0x04;
    let x_bytes = digits_to_be_bytes(pub_x);
    let y_bytes = digits_to_be_bytes(pub_y);
    pubkey_bytes[1..33].copy_from_slice(&x_bytes);
    pubkey_bytes[33..65].copy_from_slice(&y_bytes);

    let mut spki = DerBuf::new();
    {
        let mut algo = DerBuf::new();
        algo.oid(&OID_EC_PUBKEY);
        algo.oid(&OID_SECP256R1);
        let mut algo_seq = DerBuf::new();
        algo_seq.sequence(algo.as_slice());

        let mut key = DerBuf::new();
        key.bit_string(0, &pubkey_bytes);

        spki.sequence(algo_seq.as_slice());
        spki.sequence(key.as_slice());
    }
    let spki_seq = {
        let mut s = DerBuf::new();
        s.sequence(spki.as_slice());
        s
    };

    let mut sig_algo = DerBuf::new();
    sig_algo.oid(&OID_ECDSA_WITH_SHA256);
    let sig_algo_seq = {
        let mut s = DerBuf::new();
        s.sequence(sig_algo.as_slice());
        s
    };

    let mut validity = DerBuf::new();
    validity.utctime(CURR_TIME);
    validity.utctime(EXPIRE_TIME);
    let validity_seq = {
        let mut s = DerBuf::new();
        s.sequence(validity.as_slice());
        s
    };

    let mut name = DerBuf::new();
    {
        let mut attr = DerBuf::new();
        attr.oid(&OID_CN);
        attr.utf8_string(SUBJECT);
        let mut attr_seq = DerBuf::new();
        attr_seq.sequence(attr.as_slice());
        let mut set = DerBuf::new();
        set.set(attr_seq.as_slice());
        name.sequence(set.as_slice());
    }

    let mut version = DerBuf::new();
    version.integer(2);
    let mut version_tagged = DerBuf::new();
    version_tagged.tagged_explicit(0, version.as_slice());

    let mut tbs = DerBuf::new();
    tbs.extend(version_tagged.as_slice());
    tbs.integer(1);
    tbs.extend(sig_algo_seq.as_slice());
    tbs.extend(name.as_slice());
    tbs.extend(validity_seq.as_slice());
    tbs.extend(name.as_slice());
    tbs.extend(spki_seq.as_slice());

    let tbs_cert = {
        let mut s = DerBuf::new();
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

    let mut sig_der = DerBuf::new();
    encode_integer_val(&mut sig_der, &sig_r);
    encode_integer_val(&mut sig_der, &sig_s);
    let sig_seq = {
        let mut s = DerBuf::new();
        s.sequence(sig_der.as_slice());
        s
    };

    let mut cert = DerBuf::new();
    cert.extend(tbs_bytes);
    cert.extend(sig_algo_seq.as_slice());
    cert.bit_string(0, sig_seq.as_slice());

    let mut out = [0u8; 2048];
    let len = cert.pos;
    if len > 2048 {
        return Err(ENOSPC);
    }
    out[..len].copy_from_slice(&cert.buf[..len]);
    Ok(out)
}

fn generate_key_pair() -> Result<KeyPair> {
    let mut private = [0u64; P256_DIGITS];
    let mut public = [0u64; P256_DIGITS * 2];

    let ret = unsafe {
        ecc::ecc_gen_privkey(
            ecc::p256_curve_id(),
            ecc::p256_ndigits(),
            private.as_mut_ptr(),
        )
    };
    if ret < 0 {
        return Err(EINVAL);
    }

    let ret = unsafe {
        ecc::ecc_make_pub_key(
            ecc::p256_curve_id(),
            ecc::p256_ndigits(),
            private.as_ptr(),
            public.as_mut_ptr(),
        )
    };
    if ret < 0 {
        return Err(EINVAL);
    }

    let mut pub_x = [0u64; P256_DIGITS];
    let mut pub_y = [0u64; P256_DIGITS];
    pub_x.copy_from_slice(&public[..P256_DIGITS]);
    pub_y.copy_from_slice(&public[P256_DIGITS..]);

    let mut pubkey_bytes = [0u8; 65];
    pubkey_bytes[0] = 0x04;
    let x_bytes = digits_to_be_bytes(&pub_x);
    let y_bytes = digits_to_be_bytes(&pub_y);
    pubkey_bytes[1..33].copy_from_slice(&x_bytes);
    pubkey_bytes[33..65].copy_from_slice(&y_bytes);

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

    let cert = build_certificate(&private, &pub_x, &pub_y)?;
    let cert_len = cert.iter().position(|&b| b == 0).unwrap_or(cert.len());

    Ok(KeyPair {
        private,
        cert,
        cert_len,
    })
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
                    data_len: 0,
                    data: [0u8; 256],
                    sig_r: [0u8; 32],
                    sig_s: [0u8; 32],
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

                if req.data_len > 256 {
                    return Err(EINVAL);
                }

                let guard = KEY_PAIR.lock();
                let kp = guard.as_ref().ok_or(ENXIO)?;

                let (sig_r, sig_s) = ecdsa_sign(&req.data[..req.data_len as usize], &kp.private)?;
                req.sig_r = sig_r;
                req.sig_s = sig_s;

                let mut writer = UserSlice::new(ptr, buf_size).writer();
                let req_ptr = &req as *const SignDataReq as *const u8;
                let req_slice = unsafe {
                    core::slice::from_raw_parts(req_ptr, core::mem::size_of::<SignDataReq>())
                };
                writer.write_slice(req_slice)?;

                pr_info!("Signer: signed data ({} bytes)\n", req.data_len);
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
