// SPDX-License-Identifier: GPL-2.0

// ioctl commands, global key-pair storage, ECDSA signing, key generation,
// and fs-verity helpers.

use crate::convert;
use crate::ecc;
use crate::ffi;
use kernel::ioctl::{_IO, _IOR, _IOWR};
use kernel::prelude::*;
use kernel::sync::rcu;
use kernel::uaccess::{UserPtr, UserSlice};

const DIGITS: usize = ecc::P256_DIGITS as usize;
const BYTES: usize = ecc::P256_BYTES as usize;
const PUBKEY_BYTES: usize = ecc::P256_PUBKEY_BYTES;

// ioctl command numbers: type 'S' (0x53), sequence 0..2
pub(crate) const SIGNER_HELLO: u32 = _IO('S' as u32, 0x00);
pub(crate) const SIGNER_GET_PUBKEY: u32 = _IOR::<[u8; PUBKEY_BYTES]>('S' as u32, 0x01);
pub(crate) const SIGNER_SIGN_DATA: u32 = _IOWR::<SignDataReq>('S' as u32, 0x02);

#[repr(C)]
pub(crate) struct SignDataReq {
    pub nonce: [u8; BYTES],
    pub hash: [u8; BYTES],
    pub sig_r: [u8; BYTES],
    pub sig_s: [u8; BYTES],
    pub pubkey: [u8; PUBKEY_BYTES],
}

pub(crate) struct KeyPair {
    pub private: [u64; DIGITS],
    pub pubkey: [u8; PUBKEY_BYTES],
}

pub(crate) fn ecdsa_sign(
    data: &[u8],
    privkey: &[u64; DIGITS],
) -> Result<([u64; DIGITS], [u64; DIGITS])> {
    let curve_n = ecc::get_curve_n().ok_or(EINVAL)?;
    let data_hash = ecc::sha256_hash(data);

    loop {
        let k = ecc::generate_private_key()?;
        let pubk = ecc::make_public_key(&k)?;

        let mut r_swapped = [0u64; DIGITS];
        r_swapped.copy_from_slice(&pubk[..DIGITS]);
        let mut r_digits = convert::unswap_digits(&r_swapped);
        if ecc::vli_compare(&r_digits, &curve_n).is_ge() {
            let r_copy = r_digits;
            (r_digits, _) = ecc::vli_sub_result(&r_copy, &curve_n);
        }

        if ecc::is_vli_zero(&r_digits) {
            continue;
        }

        let mut s_digits = ecc::vli_mod_mult(&r_digits, privkey, &curve_n);
        let z = ecc::digits_from_be_bytes(&data_hash);

        let mut z_plus_rs = z;
        let mut carry = 0u64;
        for i in 0..DIGITS {
            let (s, c1) = z_plus_rs[i].overflowing_add(s_digits[i]);
            let (s, c2) = s.overflowing_add(carry);
            z_plus_rs[i] = s;
            carry = (c1 as u64) + (c2 as u64);
        }
        if carry != 0 || ecc::vli_compare(&z_plus_rs, &curve_n).is_ge() {
            let tmp = z_plus_rs;
            (z_plus_rs, _) = ecc::vli_sub_result(&tmp, &curve_n);
        }

        let k_inv = ecc::vli_mod_inv_result(&k, &curve_n);
        s_digits = ecc::vli_mod_mult(&z_plus_rs, &k_inv, &curve_n);

        if ecc::is_vli_zero(&s_digits) {
            continue;
        }

        return Ok((r_digits, s_digits));
    }
}

pub(crate) fn generate_key_pair() -> Result<KeyPair> {
    let private = ecc::generate_private_key()?;
    let public = ecc::make_public_key(&private)?;

    let mut pub_x = [0u64; DIGITS];
    let mut pub_y = [0u64; DIGITS];
    pub_x.copy_from_slice(&public[..DIGITS]);
    pub_y.copy_from_slice(&public[DIGITS..]);

    let pubkey_bytes = convert::uncompressed_pubkey_bytes(&pub_x, &pub_y);

    if let Some(n) = ecc::get_curve_n() {
        pr_info!(
            "Signer: curve N words ({:016x}{:016x}{:016x}{:016x})\n",
            n[0],
            n[1],
            n[2],
            n[3]
        );
    }
    pr_info!(
        "Signer: pubkey X words ({:016x}{:016x}{:016x}{:016x})\n",
        pub_x[0],
        pub_x[1],
        pub_x[2],
        pub_x[3]
    );
    pr_info!(
        "Signer: pubkey Y words ({:016x}{:016x}{:016x}{:016x})\n",
        pub_y[0],
        pub_y[1],
        pub_y[2],
        pub_y[3]
    );
    {
        let mut hex = [0u8; 2 * PUBKEY_BYTES];
        for i in 0..PUBKEY_BYTES {
            let v = pubkey_bytes[i];
            let hi = v >> 4;
            let lo = v & 0xf;
            hex[i * 2] = if hi < 10 { b'0' + hi } else { b'a' + hi - 10 };
            hex[i * 2 + 1] = if lo < 10 { b'0' + lo } else { b'a' + lo - 10 };
        }
        pr_info!(
            "Signer: pubkey hex ({})\n",
            core::str::from_utf8(&hex).unwrap_or("???")
        );
    }

    match ecc::ima_measure_pubkey(&pubkey_bytes) {
        Ok(_) => pr_info!("Signer: Public key successfully logged in IMA\n"),
        Err(e) => pr_err!("Signer: IMA measurement failed: {:?}\n", e),
    };

    Ok(KeyPair {
        private,
        pubkey: pubkey_bytes,
    })
}

/// taken from linux/fsverity.h
const FS_VERITY_MAX_DIGEST_SIZE: usize = 64;

pub(crate) struct FsverityDigest {
    size: usize,
    buffer: [u8; FS_VERITY_MAX_DIGEST_SIZE],
}

impl FsverityDigest {
    pub(crate) fn digest(&self) -> &[u8] {
        &self.buffer[..self.size]
    }
}

fn current_exe_fsverity_digest() -> Result<FsverityDigest> {
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
    let mut digest = FsverityDigest {
        size: 0,
        buffer: [0; FS_VERITY_MAX_DIGEST_SIZE],
    };
    let ret = unsafe {
        ffi::fsverity_get_digest(
            inode,
            digest.buffer.as_mut_ptr(),
            core::ptr::null_mut(),
            core::ptr::null_mut(),
        )
    };
    if ret < 0 {
        return Err(EPERM);
    } else if ret == 0 {
        return Err(ENOENT);
    }
    digest.size = ret as usize;
    Ok(digest)
}

fn sign_data_req_bytes_mut(req: &mut SignDataReq) -> &mut [u8] {
    let size = core::mem::size_of::<SignDataReq>();
    unsafe { core::slice::from_raw_parts_mut(req as *mut SignDataReq as *mut u8, size) }
}

fn sign_data_req_bytes(req: &SignDataReq) -> &[u8] {
    let size = core::mem::size_of::<SignDataReq>();
    unsafe { core::slice::from_raw_parts(req as *const SignDataReq as *const u8, size) }
}

fn read_sign_data_req(arg: usize, buf_size: usize) -> Result<SignDataReq> {
    let ptr = UserPtr::from_addr(arg);
    let mut reader = UserSlice::new(ptr, buf_size).reader();
    let mut req = SignDataReq {
        nonce: [0u8; BYTES],
        hash: [0u8; BYTES],
        sig_r: [0u8; BYTES],
        sig_s: [0u8; BYTES],
        pubkey: [0u8; PUBKEY_BYTES],
    };
    reader.read_slice(sign_data_req_bytes_mut(&mut req))?;
    Ok(req)
}

fn write_sign_data_req(arg: usize, buf_size: usize, req: &SignDataReq) -> Result {
    let ptr = UserPtr::from_addr(arg);
    let mut writer = UserSlice::new(ptr, buf_size).writer();
    writer.write_slice(sign_data_req_bytes(req))?;
    Ok(())
}

pub(crate) fn handle_get_pubkey(arg: usize, cmd: u32) -> Result<isize> {
    let kp = crate::KEY_PAIR.as_ref().ok_or(ENXIO)?;
    let ptr = UserPtr::from_addr(arg);
    let buf_size = kernel::ioctl::_IOC_SIZE(cmd);
    let write_len = core::cmp::min(kp.pubkey.len(), buf_size);
    let mut writer = UserSlice::new(ptr, buf_size).writer();
    writer.write_slice(&kp.pubkey[..write_len])?;
    pr_info!("Signer: returned public key ({} bytes)\n", write_len);
    Ok(write_len as isize)
}

pub(crate) fn handle_sign_data(arg: usize, cmd: u32) -> Result<isize> {
    let buf_size = kernel::ioctl::_IOC_SIZE(cmd);

    let digest = current_exe_fsverity_digest()?;
    let digest = digest.digest();

    let mut req = read_sign_data_req(arg, buf_size)?;
    let to_sign_len = digest.len() + BYTES;
    let mut to_sign = [0u8; FS_VERITY_MAX_DIGEST_SIZE + BYTES];
    to_sign[..digest.len()].copy_from_slice(&digest);
    to_sign[digest.len()..to_sign_len].copy_from_slice(&req.nonce);

    req.hash = ecc::sha256_hash(&to_sign[..to_sign_len]);

    let kp = crate::KEY_PAIR.as_ref().ok_or(ENXIO)?;
    let (sig_r_limbs, sig_s_limbs) = ecdsa_sign(&to_sign[..to_sign_len], &kp.private)?;
    for (i, limb) in sig_r_limbs.iter().enumerate() {
        req.sig_r[i * core::mem::size_of::<u64>()..(i + 1) * core::mem::size_of::<u64>()]
            .copy_from_slice(&limb.to_ne_bytes());
    }
    for (i, limb) in sig_s_limbs.iter().enumerate() {
        req.sig_s[i * core::mem::size_of::<u64>()..(i + 1) * core::mem::size_of::<u64>()]
            .copy_from_slice(&limb.to_ne_bytes());
    }
    req.pubkey.copy_from_slice(&kp.pubkey);

    write_sign_data_req(arg, buf_size, &req)?;

    pr_info!("Signer: computed signature\n");
    Ok(0)
}

pub(crate) fn check_fsverity() -> Result {
    current_exe_fsverity_digest().map(|_| ())
}
