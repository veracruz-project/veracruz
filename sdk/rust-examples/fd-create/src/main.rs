//! Test of fd-create function.
//!
//! ## Context
//!
//! An anonymous temporary file is written to and read from.
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE_MIT.markdown` file in the Veracruz root directory
//! for information on licensing and copyright.

use libveracruz;
use std::fs;
use std::io::prelude::*;
use std::io::SeekFrom;

fn main() -> anyhow::Result<()> {
    // Create the temporary file.
    let mut file = libveracruz::fd_create()?;

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
        // Any non-empty output will satisfy the test harness:
        fs::write("/output/pass", "X")?;
    }

    Ok(())
}
