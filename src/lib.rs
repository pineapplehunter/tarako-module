// SPDX-License-Identifier: GPL-2.0

//! A simple "Hello, world!" kernel module written in Rust.

use kernel::prelude::*;

module! {
    type: HelloWorld,
    name: "hello_world",
    authors: ["Your Name"],
    description: "A simple hello world kernel module",
    license: "GPL",
}

struct HelloWorld;

impl kernel::Module for HelloWorld {
    fn init(_module: &'static ThisModule) -> Result<Self> {
        pr_info!("Hello, world!\n");
        Ok(HelloWorld)
    }
}

impl Drop for HelloWorld {
    fn drop(&mut self) {
        pr_info!("Goodbye, world!\n");
    }
}
