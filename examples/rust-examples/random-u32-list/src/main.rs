//! Test of the trusted random source platform service.
//!
//! ## Context
//!
//! Test program for generate comma-separated random u32 numbers.
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Copyright
//!
//! See the file `LICENSING.markdown` in the Veracruz root directory for licensing
//! and copyright information.

use anyhow;
use rand::Rng;
use std::fs;

fn main() -> anyhow::Result<()> {
    let output = "/output/unsorted_numbers.txt";
    let bytes = rand::thread_rng().gen::<[u32; 32]>().iter().map(|n| n.to_string()).collect::<Vec<String>>().join(",");
    println!("{}", bytes);
    fs::write(output, bytes)?;
    Ok(())
}
