// SPDX-License-Identifier: GPL-2.0

// ioctl commands, global key-pair storage, ECDSA signing, key generation,
// and fs-verity helpers.

use crate::ecc::{self, P256_BYTES, P256_PUBKEY_BYTES};
use crate::ffi;
use crate::vli::Scalar;
use crate::KEY_PAIR;
use kernel::ioctl::{_IO, _IOR, _IOWR};
use kernel::prelude::*;
use kernel::uaccess::{UserPtr, UserSlice};

#[cfg(target_endian = "big")]
compile_error!("tarako module requires little-endian target");

/// Size of the opaque data supplied by userspace to the signing ioctl.
pub(crate) const USER_DATA_BYTES: usize = 1024 / 8;

// ioctl command numbers: type 'S' (0x53), sequence 0..2
pub(crate) const TARAKO_HELLO: u32 = _IO('S' as u32, 0x00);
pub(crate) const TARAKO_GET_PUBKEY: u32 = _IOR::<[u8; P256_PUBKEY_BYTES]>('S' as u32, 0x01);
pub(crate) const TARAKO_SIGN_DATA: u32 = _IOWR::<SignDataReq>('S' as u32, 0x02);

#[repr(C)]
pub(crate) struct SignDataReq {
    pub user_data: [u8; USER_DATA_BYTES],
    pub hash: [u8; P256_BYTES],
    pub sig_r: [u8; P256_BYTES],
    pub sig_s: [u8; P256_BYTES],
    pub pubkey: [u8; P256_PUBKEY_BYTES],
}

const _: () = assert!(core::mem::size_of::<SignDataReq>() == 289);

pub(crate) struct KeyPair {
    pub private: Scalar,
    pub pubkey: [u8; P256_PUBKEY_BYTES],
    curve_n: Scalar,
    ima_measured: bool,
}

impl KeyPair {
    fn sign(&self, data: &[u8]) -> Result<(Scalar, Scalar)> {
        ecdsa_sign(data, &self.private, &self.curve_n)
    }
}

fn ecdsa_sign(data: &[u8], privkey: &Scalar, curve_n: &Scalar) -> Result<(Scalar, Scalar)> {
    let data_hash = ecc::sha256_hash(data);

    for _ in 0..100 {
        let k = ecc::generate_private_key()?;
        let pubk = ecc::make_public_key(&k)?;

        let r_swapped = pubk.x_scalar();
        let mut r = r_swapped.unswap();
        if r >= curve_n {
            r = r - curve_n;
        }

        if r.is_zero() {
            continue;
        }

        let mut z = Scalar::from_be_bytes(&data_hash)?;
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
    let mut pubkey_sec1 = [0u8; P256_PUBKEY_BYTES];
    pubkey_sec1[0] = 0x04;
    pubkey_sec1[1..][..P256_BYTES].copy_from_slice(&public.x_as_bytes());
    pubkey_sec1[1 + P256_BYTES..].copy_from_slice(&public.y_as_bytes());

    let curve_n = ecc::get_curve_n().ok_or(EINVAL)?;

    let ima_measured = match ecc::ima_measure_pubkey(&pubkey_sec1) {
        Ok(()) => {
            pr_info!(
                "public key successfully measured by IMA: {:x?}\n",
                pubkey_sec1
            );
            true
        }
        Err(error) => {
            // Keep the module available on kernels without an active IMA
            // policy, but never allow such an unmeasured key to sign evidence.
            pr_warn!(
                "IMA measurement of public key failed; signing disabled: {:?}\n",
                error
            );
            false
        }
    };

    Ok(KeyPair {
        private,
        pubkey: pubkey_sec1,
        curve_n,
        ima_measured,
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
    let current = current!();
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
        return Err(Error::from_errno(ret));
    }
    let size = ret as usize;
    if size == 0 {
        return Err(ENOENT);
    }
    if size > digest.buffer.len() {
        return Err(EOVERFLOW);
    }
    digest.size = size;
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
        user_data: [0u8; USER_DATA_BYTES],
        hash: [0u8; P256_BYTES],
        sig_r: [0u8; P256_BYTES],
        sig_s: [0u8; P256_BYTES],
        pubkey: [0u8; P256_PUBKEY_BYTES],
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
    let kp = KEY_PAIR.as_ref().ok_or(ENXIO)?;
    let buf_size = kernel::ioctl::_IOC_SIZE(cmd);
    if buf_size < P256_PUBKEY_BYTES {
        return Err(E2BIG);
    }
    let ptr = UserPtr::from_addr(arg);
    let mut writer = UserSlice::new(ptr, buf_size).writer();
    writer.write_slice(&kp.pubkey)?;
    Ok(P256_PUBKEY_BYTES as isize)
}

pub(crate) fn handle_sign_data(arg: usize, cmd: u32) -> Result<isize> {
    let buf_size = kernel::ioctl::_IOC_SIZE(cmd);
    let kp = KEY_PAIR.as_ref().ok_or(ENXIO)?;
    if !kp.ima_measured {
        return Err(EPERM);
    }

    let digest = current_exe_fsverity_digest()?;
    let digest = digest.digest();

    let mut req = read_sign_data_req(arg, buf_size)?;
    let to_sign_len = digest.len().checked_add(USER_DATA_BYTES).ok_or(EINVAL)?;
    let mut to_sign = [0u8; FS_VERITY_MAX_DIGEST_SIZE + USER_DATA_BYTES];
    to_sign[..digest.len()].copy_from_slice(&digest);
    to_sign[digest.len()..to_sign_len].copy_from_slice(&req.user_data);

    req.hash = ecc::sha256_hash(&to_sign[..to_sign_len]);

    let (sig_r_limbs, sig_s_limbs) = kp.sign(&to_sign[..to_sign_len])?;
    for (i, limb) in sig_r_limbs.iter().rev().enumerate() {
        req.sig_r[i * core::mem::size_of::<u64>()..(i + 1) * core::mem::size_of::<u64>()]
            .copy_from_slice(&limb.to_be_bytes());
    }
    for (i, limb) in sig_s_limbs.iter().rev().enumerate() {
        req.sig_s[i * core::mem::size_of::<u64>()..(i + 1) * core::mem::size_of::<u64>()]
            .copy_from_slice(&limb.to_be_bytes());
    }
    req.pubkey.copy_from_slice(&kp.pubkey);

    write_sign_data_req(arg, buf_size, &req)?;

    Ok(0)
}
