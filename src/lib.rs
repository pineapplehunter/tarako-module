// SPDX-License-Identifier: GPL-2.0

//! A kernel module for remote attestation using ECDSA P-256 signatures.
//!
//! # Security model
//!
//! The kernel is the only trusted entity. On load it generates an ECDSA P-256
//! key pair and a self-signed X.509 certificate, then exposes them through
//! `/dev/signer` via three ioctls:
//!
//! 1. `SIGNER_HELLO` (0x0000_5300) - sanity check.
//! 2. `SIGNER_GET_CERT` (0x8800_5301) - return the self-signed certificate.
//! 3. `SIGNER_SIGN_DATA` (0xC0C1_5302) - remote attestation: read the calling
//!    process's fs-verity digest, compute `ECDSA-SHA256(sk, SHA256(digest || nonce))`,
//!    and return the signature together with the public key.
//!
//! The ioctl handler rejects callers whose executable is NOT protected by
//! fs-verity, ensuring the measured code path cannot be tampered with.

pub(crate) mod cert {
    include!("cert.rs");
}
pub(crate) mod convert {
    include!("convert.rs");
}
#[allow(dead_code, unreachable_pub)]
pub(crate) mod ecc {
    include!("ecc.rs");
}
pub(crate) mod ioctl {
    include!("ioctl.rs");
}
pub(crate) mod signer_dev {
    include!("signer_dev.rs");
}

use kernel::miscdevice::{MiscDeviceOptions, MiscDeviceRegistration};
use kernel::prelude::*;

use crate::ioctl::{generate_key_pair, KEY_PAIR};
use crate::signer_dev::SignerDevice;

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
