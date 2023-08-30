//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE.md` file in the Veracruz root directory
//! for information on licensing and copyright.

use std::fs::File;
use std::os::wasi::io::{FromRawFd, RawFd};

mod veracruz_si_import {
    #[link(wasm_import_module = "veracruz_si")]
    extern "C" {
        pub fn fd_create(x: u32) -> u32;
    }
}

mod veracruz_si {
    pub fn fd_create(fd: *mut crate::RawFd) -> u32 {
        unsafe { crate::veracruz_si_import::fd_create(fd as u32) }
    }
}

/// Return a file descriptor for a newly created temporary file,
/// for which there is no file path. There are no failure modes.
pub fn fd_create() -> std::io::Result<File> {
    let mut fd: RawFd = 0;
    let ret = veracruz_si::fd_create(&mut fd);
    if ret == 0 {
        Ok(unsafe { File::from_raw_fd(fd) })
    } else {
        // Insert code to convert error code here,
        // though fd_create should never fail.
        panic!("unexpected")
    }
}
