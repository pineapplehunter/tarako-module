// SPDX-License-Identifier: GPL-2.0

// ioctl commands, global key-pair storage, ECDSA signing, key generation,
// and fs-verity helpers.

use crate::convert;
use crate::ecc;
use crate::ffi;
use crate::set_once::SetOnce;
use crate::vli::Scalar;
use kernel::ioctl::{_IO, _IOR, _IOWR};
use kernel::prelude::*;
use kernel::sync::rcu;
use kernel::uaccess::{UserPtr, UserSlice};

#[cfg(target_endian = "big")]
compile_error!("signer module requires little-endian target");

const DIGITS: usize = ecc::P256_DIGITS as usize;
const BYTES: usize = ecc::P256_BYTES as usize;
const PUBKEY_BYTES: usize = ecc::P256_PUBKEY_BYTES;

const _: () = assert!(PUBKEY_BYTES == 1 + 2 * BYTES);

pub(crate) static CURVE_N: SetOnce<Scalar> = SetOnce::new();

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
    pub private: Scalar,
    pub pubkey: convert::UncompressedPubkey,
}

pub(crate) fn ecdsa_sign(data: &[u8], privkey: &Scalar) -> Result<(Scalar, Scalar)> {
    let curve_n = CURVE_N.as_ref().ok_or(EINVAL)?;
    let data_hash = ecc::sha256_hash(data);

    for _ in 0..100 {
        let k = ecc::generate_private_key()?;
        let pubk = ecc::make_public_key(&k)?;

        let mut r_swapped = Scalar::zero();
        r_swapped.copy_from_slice(&pubk[..DIGITS]);
        let mut r = r_swapped.unswap();
        if r >= curve_n {
            r = r - curve_n;
        }

        if r.is_zero() {
            continue;
        }

        let mut z = Scalar::from_be_bytes(&data_hash);
        if z >= curve_n {
            z = z - curve_n;
        }
        let s = r.mod_mult(privkey, curve_n);

        let (z_plus_rs, carry) = z.carrying_add(&s, 0);
        let z_plus_rs = if carry != 0 || z_plus_rs >= curve_n {
            z_plus_rs - curve_n
        } else {
            z_plus_rs
        };

        let k_inv = k.mod_inv(curve_n);
        let s = z_plus_rs.mod_mult(&k_inv, curve_n);

        if s.is_zero() {
            continue;
        }

        return Ok((r, s));
    }

    Err(EINVAL)
}

pub(crate) fn generate_key_pair() -> Result<KeyPair> {
    let private = ecc::generate_private_key()?;
    let public = ecc::make_public_key(&private)?;
    let mut pubkey = convert::UncompressedPubkey([0u8; PUBKEY_BYTES]);
    pubkey.0[0] = 0x04;
    let bytes: [u8; 2 * BYTES] = unsafe { core::mem::transmute(*public) };
    pubkey.0[1..].copy_from_slice(&bytes);

    match ecc::ima_measure_pubkey(&pubkey) {
        Ok(_) => pr_info!("Public key successfully logged in IMA\n"),
        Err(e) => pr_err!("IMA measurement failed: {:?}\n", e),
    };

    let curve_n = ecc::get_curve_n().ok_or(EINVAL)?;
    CURVE_N.populate(curve_n);

    Ok(KeyPair { private, pubkey })
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
    let _guard = kernel::sync::rcu::read_lock();
    let exe_file = unsafe { (*mm_ptr).__bindgen_anon_1.exe_file };
    if exe_file.is_null() {
        return Err(EPERM);
    }
    let inode = unsafe { (*exe_file).f_inode as *mut kernel::bindings::inode };
    if inode.is_null() {
        return Err(EPERM);
    }
    let mut digest = FsverityDigest {
        size: 0,
        buffer: [0; FS_VERITY_MAX_DIGEST_SIZE],
    };
    let ret = unsafe {
        ffi::fsverity_get_digest(
            inode as *mut core::ffi::c_void,
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
    let buf_size = kernel::ioctl::_IOC_SIZE(cmd);
    if buf_size < PUBKEY_BYTES {
        return Err(E2BIG);
    }
    let ptr = UserPtr::from_addr(arg);
    let mut writer = UserSlice::new(ptr, buf_size).writer();
    writer.write_slice(kp.pubkey.as_bytes())?;
    pr_info!("returned public key ({} bytes)\n", PUBKEY_BYTES);
    Ok(PUBKEY_BYTES as isize)
}

pub(crate) fn handle_sign_data(arg: usize, cmd: u32) -> Result<isize> {
    let buf_size = kernel::ioctl::_IOC_SIZE(cmd);

    let digest = current_exe_fsverity_digest()?;
    let digest = digest.digest();

    let mut req = read_sign_data_req(arg, buf_size)?;
    let to_sign_len = digest.len().checked_add(BYTES).ok_or(EINVAL)?;
    let mut to_sign = [0u8; FS_VERITY_MAX_DIGEST_SIZE + BYTES];
    to_sign[..digest.len()].copy_from_slice(&digest);
    to_sign[digest.len()..to_sign_len].copy_from_slice(&req.nonce);

    req.hash = ecc::sha256_hash(&to_sign[..to_sign_len]);

    let kp = crate::KEY_PAIR.as_ref().ok_or(ENXIO)?;
    let (sig_r_limbs, sig_s_limbs) = ecdsa_sign(&to_sign[..to_sign_len], &kp.private)?;
    for (i, limb) in sig_r_limbs.iter().rev().enumerate() {
        req.sig_r[i * core::mem::size_of::<u64>()..(i + 1) * core::mem::size_of::<u64>()]
            .copy_from_slice(&limb.to_be_bytes());
    }
    for (i, limb) in sig_s_limbs.iter().rev().enumerate() {
        req.sig_s[i * core::mem::size_of::<u64>()..(i + 1) * core::mem::size_of::<u64>()]
            .copy_from_slice(&limb.to_be_bytes());
    }
    req.pubkey.copy_from_slice(kp.pubkey.as_bytes());

    write_sign_data_req(arg, buf_size, &req)?;

    pr_info!("computed signature\n");
    Ok(0)
}
