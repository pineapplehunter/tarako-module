// SPDX-License-Identifier: GPL-2.0

//! A kernel module for remote attestation using ECDSA P-256 signatures.
//!
//! # Security model
//!
//! The kernel is the only trusted entity. On load it generates an ECDSA P-256
//! key pair and exposes it through `/dev/signer` via three ioctls:
//!
//! 1. `SIGNER_HELLO` (0x0000_5300) - sanity check.
//! 2. `SIGNER_GET_PUBKEY` (0x8041_5301) - return the raw ECDSA P-256 public key.
//! 3. `SIGNER_SIGN_DATA` (0xC0C1_5302) - remote attestation: read the calling
//!    process's fs-verity digest, compute `ECDSA-SHA256(sk, SHA256(digest || nonce))`,
//!    and return the signature together with the public key.
//!
//! The ioctl handler rejects callers whose executable is NOT protected by
//! fs-verity, ensuring the measured code path cannot be tampered with.

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
    generate_key_pair, handle_get_pubkey, handle_sign_data, KeyPair, SIGNER_GET_PUBKEY,
    SIGNER_HELLO, SIGNER_SIGN_DATA,
};
use crate::set_once::SetOnce;

module! {
    type: SignerModule,
    name: "signer",
    authors: ["Shogo Takata"],
    description: "A signer kernel module with chrdev and ioctl",
    license: "GPL",
}

#[pin_data]
struct SignerModule {
    #[pin]
    _miscdev: MiscDeviceRegistration<SignerDevice>,
}

impl kernel::InPlaceModule for SignerModule {
    fn init(_module: &'static ThisModule) -> impl PinInit<Self, Error> {
        pr_info!("loading, generating ECDSA P-256 key pair\n");

        let options = MiscDeviceOptions {
            name: kernel::c_str!("signer"),
        };
        try_pin_init!(Self {
            _miscdev <- {
                let kp = generate_key_pair().map_err(|_| {
                    pr_err!("failed to generate ECDSA key pair, aborting load\n");
                    EINVAL
                })?;
                KEY_PAIR.populate(kp);
                pr_info!("key pair generated, public key ready\n");
                MiscDeviceRegistration::register(options)
            },
        })
    }
}

// ── /dev/signer miscdevice ──

#[pin_data(PinnedDrop)]
pub(crate) struct SignerDevice {
    dev: ARef<Device>,
}

#[vtable]
impl MiscDevice for SignerDevice {
    type Ptr = Pin<KBox<Self>>;

    fn open(_file: &File, misc: &MiscDeviceRegistration<Self>) -> Result<Pin<KBox<Self>>> {
        let dev = ARef::from(misc.device());
        pr_info!("opened\n");
        KBox::try_pin_init(try_pin_init! { SignerDevice { dev: dev } }, GFP_KERNEL)
    }

    fn ioctl(_me: Pin<&SignerDevice>, _file: &File, cmd: u32, arg: usize) -> Result<isize> {
        match cmd {
            SIGNER_HELLO => {
                pr_info!("hello from ioctl\n");
                Ok(0)
            }
            SIGNER_GET_PUBKEY => handle_get_pubkey(arg, cmd),
            SIGNER_SIGN_DATA => handle_sign_data(arg, cmd),
            _ => {
                pr_info!("unknown ioctl 0x{:x}\n", cmd);
                Err(ENOTTY)
            }
        }
    }
}

#[pinned_drop]
impl PinnedDrop for SignerDevice {
    fn drop(self: Pin<&mut Self>) {
        pr_info!("goodbye!\n");
    }
}

pub(crate) static KEY_PAIR: SetOnce<KeyPair> = SetOnce::new();
