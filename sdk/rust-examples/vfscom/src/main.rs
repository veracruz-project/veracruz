#![feature(wasi_ext)]

use std::fs::File;
use std::io::prelude::*;
use std::io::SeekFrom;
use std::os::wasi::io::{FromRawFd, RawFd};

////////////////////////////////////////////////////////////////////////////
// This part should probably be in a Veracruz library.

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

fn fd_create() -> std::io::Result<File> {
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

////////////////////////////////////////////////////////////////////////////
// A simple test.

fn main() -> std::io::Result<()> {
    // Create the temporary file.
    let mut file = fd_create()?;

    // Write some data to the file.
    const LEN: usize = 10000;
    let mut data: [u8; LEN] = [0; LEN];
    for i in 0..LEN {
        data[i] = (i % 251) as u8
    }
    file.write(&data)?;

    // Seek to an offset.
    let off = LEN / 3;
    file.seek(SeekFrom::Start(off as u64))?;

    // Read data from file and compare.
    let mut buf: [u8; LEN] = [0; LEN];
    let n = file.read(&mut buf)?;
    if n != LEN - off {
        println!("ERROR: wrong return value from read")
    } else if buf[0..LEN - off] != data[off..LEN] {
        println!("ERROR: wrong data returned by read")
    } else {
        println!("PASS");
    }

    Ok(())
}
