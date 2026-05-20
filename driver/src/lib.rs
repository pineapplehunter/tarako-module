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

pub(crate) mod convert {
    include!("convert.rs");
}
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
pub(crate) mod signer_dev {
    include!("signer_dev.rs");
}

use kernel::miscdevice::{MiscDeviceOptions, MiscDeviceRegistration};
use kernel::prelude::*;

use crate::ioctl::generate_key_pair;
use crate::ioctl::KeyPair;
use crate::set_once::SetOnce;
use crate::signer_dev::SignerDevice;

pub(crate) static KEY_PAIR: SetOnce<KeyPair> = SetOnce::new();

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

        match generate_key_pair() {
            Ok(kp) => {
                KEY_PAIR.populate(kp);
                pr_info!("key pair generated, public key ready\n");
            }
            Err(_) => {
                pr_info!("failed to generate key pair\n");
            }
        }

        let options = MiscDeviceOptions {
            name: kernel::c_str!("signer"),
        };
        try_pin_init!(Self {
            _miscdev <- MiscDeviceRegistration::register(options),
        })
    }
}
