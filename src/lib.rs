// SPDX-License-Identifier: GPL-2.0

//! A chrdev node called "signer" that accepts ioctl syscalls and returns garbage data.

use kernel::{
    device::Device,
    fs::File,
    ioctl::{_IO, _IOC_SIZE, _IOR},
    miscdevice::{MiscDevice, MiscDeviceOptions, MiscDeviceRegistration},
    prelude::*,
    sync::aref::ARef,
    uaccess::{UserPtr, UserSlice},
};

const SIGNER_HELLO: u32 = _IO('S' as u32, 0x00);
const SIGNER_GET_GARBAGE: u32 = _IOR::<[u8; 64]>('S' as u32, 0x01);

module! {
    type: SignerModule,
    name: "signer",
    authors: ["Your Name"],
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
        pr_info!("Loading Signer Module\n");

        let options = MiscDeviceOptions {
            name: c"signer",
        };

        try_pin_init!(Self {
            _miscdev <- MiscDeviceRegistration::register(options),
        })
    }
}

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

        KBox::try_pin_init(
            try_pin_init! {
                SignerDevice {
                    dev: dev,
                }
            },
            GFP_KERNEL,
        )
    }

    fn ioctl(me: Pin<&SignerDevice>, _file: &File, cmd: u32, arg: usize) -> Result<isize> {
        match cmd {
            SIGNER_HELLO => {
                pr_info!("Signer: hello from ioctl\n");
                Ok(0)
            }
            SIGNER_GET_GARBAGE => {
                let ptr = UserPtr::from_addr(arg);
                let size = _IOC_SIZE(cmd);
                let mut writer = UserSlice::new(ptr, size).writer();

                let mut garbage = [0u8; 64];
                let self_ptr = &me as *const _ as usize;
                let mut state = (self_ptr ^ 0xdead_beef_cafe_babe) as u64;
                for byte in garbage.iter_mut() {
                    state = state.wrapping_mul(6364136223846793005)
                        .wrapping_add(1442695040888963407);
                    *byte = state as u8;
                }

                writer.write_slice(&garbage)?;
                pr_info!("Signer: returned garbage ({} bytes)\n", size);
                Ok(0)
            }
            _ => {
                pr_err!("Signer: unknown ioctl 0x{:x}\n", cmd);
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
