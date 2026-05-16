// SPDX-License-Identifier: GPL-2.0

// The `/dev/signer` miscdevice and its file_operations / ioctl dispatch.

use crate::ioctl;
use kernel::device::Device;
use kernel::fs::File;
use kernel::miscdevice::{MiscDevice, MiscDeviceRegistration};
use kernel::prelude::*;
use kernel::alloc::flags::GFP_KERNEL;
use kernel::sync::aref::ARef;

#[pin_data(PinnedDrop)]
pub(crate) struct SignerDevice {
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

    // ioctl dispatch: gate everything behind an fs-verity check.
    // Only processes whose executable is protected by fs-verity
    // may call any of these ioctls.
    fn ioctl(_me: Pin<&SignerDevice>, _file: &File, cmd: u32, arg: usize) -> Result<isize> {
        ioctl::check_fsverity()?;

        match cmd {
            ioctl::SIGNER_HELLO => {
                pr_info!("Signer: hello from ioctl\n");
                Ok(0)
            }
            ioctl::SIGNER_GET_CERT => ioctl::handle_get_cert(arg, cmd),
            ioctl::SIGNER_SIGN_DATA => ioctl::handle_sign_data(arg, cmd),
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
