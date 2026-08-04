// SPDX-License-Identifier: GPL-2.0

//! A kernel module for remote attestation using ECDSA P-256 signatures.
//!
//! # Security model
//!
//! The kernel is the only trusted entity. On load it generates an ECDSA P-256
//! key pair and exposes it through `/dev/tarako` via three ioctls:
//!
//! 1. `TARAKO_HELLO` (0x0000_5300) - sanity check.
//! 2. `TARAKO_GET_PUBKEY` (0x8021_5301) - return the compressed ECDSA P-256 public key.
//! 3. `TARAKO_SIGN_DATA` (0xC101_5302) - remote attestation: read the calling
//!    process's fs-verity digest, compute
//!    `ECDSA-SHA256(sk, digest || user_data)` for 1024 bits of opaque user data,
//!    and return the signature together with the public key.
//!
//! The signing ioctl is enabled only when IMA measures the generated public
//! key, and rejects callers whose executable is not protected by fs-verity.

pub(crate) mod ecc {
    include!("ecc.rs");
}
pub(crate) mod ffi {
    include!("ffi.rs");
}
pub(crate) mod ioctl {
    include!("ioctl.rs");
}
pub(crate) mod set_once {
    include!("set_once.rs");
}
pub(crate) mod vli {
    include!("vli.rs");
}

use kernel::alloc::flags::GFP_KERNEL;
use kernel::device::Device;
use kernel::fs::File;
use kernel::miscdevice::{MiscDevice, MiscDeviceOptions, MiscDeviceRegistration};
use kernel::prelude::*;
use kernel::sync::aref::ARef;

use crate::ioctl::{
    generate_key_pair, handle_get_pubkey, handle_sign_data, KeyPair, TARAKO_GET_PUBKEY,
    TARAKO_HELLO, TARAKO_SIGN_DATA,
};
use crate::set_once::SetOnce;

module! {
    type: TarakoModule,
    name: "tarako",
    authors: ["Shogo Takata"],
    description: "A tarako kernel module with chrdev and ioctl",
    license: "GPL",
}

struct KeyCleanup;

impl Drop for KeyCleanup {
    fn drop(&mut self) {
        // `_miscdev` is declared before this field and is therefore dropped
        // first, preventing concurrent file operations during key destruction.
        unsafe { KEY_PAIR.clear() };
    }
}

#[pin_data]
struct TarakoModule {
    #[pin]
    _miscdev: MiscDeviceRegistration<TarakoDevice>,
    _key_cleanup: KeyCleanup,
}

impl kernel::InPlaceModule for TarakoModule {
    fn init(_module: &'static ThisModule) -> impl PinInit<Self, Error> {
        pr_info!("loading, generating ECDSA P-256 key pair\n");

        let options = MiscDeviceOptions {
            name: kernel::c_str!("tarako"),
        };
        try_pin_init!(Self {
            _miscdev <- {
                let kp = generate_key_pair().map_err(|error| {
                    pr_err!("failed to initialize ECDSA key pair: {:?}\n", error);
                    error
                })?;
                MiscDeviceRegistration::register(options).pin_chain(move |_| {
                    if !KEY_PAIR.populate(kp) {
                        pr_err!("key pair was already initialized\n");
                        return Err(EBUSY);
                    }
                    pr_info!("key pair generated, public key ready\n");
                    Ok(())
                })
            },
            _key_cleanup: KeyCleanup,
        })
    }
}

// ── /dev/tarako miscdevice ──

#[pin_data]
pub(crate) struct TarakoDevice {
    _dev: ARef<Device>,
}

#[vtable]
impl MiscDevice for TarakoDevice {
    type Ptr = Pin<KBox<Self>>;

    fn open(_file: &File, misc: &MiscDeviceRegistration<Self>) -> Result<Pin<KBox<Self>>> {
        let dev = ARef::from(misc.device());
        KBox::try_pin_init(try_pin_init! { TarakoDevice { _dev: dev } }, GFP_KERNEL)
    }

    fn ioctl(_me: Pin<&TarakoDevice>, _file: &File, cmd: u32, arg: usize) -> Result<isize> {
        match cmd {
            TARAKO_HELLO => Ok(0),
            TARAKO_GET_PUBKEY => handle_get_pubkey(arg, cmd),
            TARAKO_SIGN_DATA => handle_sign_data(arg, cmd),
            _ => Err(ENOTTY)
        }
    }
}

pub(crate) static KEY_PAIR: SetOnce<KeyPair> = SetOnce::new();
