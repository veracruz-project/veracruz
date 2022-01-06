//! Echo
//!
//! ## Context
//!
//! Read from 'input.txt', encode then using postcard and write to 'output'.
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE_MIT.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

use anyhow;
use std::{fs, io::Write};

/// Read from 'input.txt', encode then using postcard and write to 'output'.
fn main() -> anyhow::Result<()> {
    let input = "/input/hello-world-1.dat";
    let output = "/output/hello-world-1.dat";

    let mut input_string = fs::read(input)?;

    println!("hello");
    std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open("/output/test/test.txt")?
        .write(&postcard::to_allocvec("hello")?)?;
    println!("rust");

    input_string.append(&mut "\"read_dir on '/output':".as_bytes().to_vec());
    for file in fs::read_dir("/output/")? {
        if let Ok(file) = file {
            input_string.append(&mut file.path().to_str().unwrap().as_bytes().to_vec());
        }
    }
    input_string.append(&mut "\"".as_bytes().to_vec());

    let rst = postcard::to_allocvec(&input_string)?;
    std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(output)?
        .write(&rst)?;
    Ok(())
}
