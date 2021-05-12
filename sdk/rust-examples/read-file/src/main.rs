//! Echo
//!
//! ## Context
//!
//! Read from 'input.txt', encode then using pinecone and write to 'output'.
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

use std::{fs, process::exit};
use wasi_types::ErrNo;

/// Read from 'input.txt', encode then using pinecone and write to 'output'.
fn compute() -> Result<(), ErrNo> {
    let input = "/input.txt";
    let output = "/output";

    let f = fs::read(input)?;
    let rst = pinecone::to_vec(&f).map_err(|_| ErrNo::Proto)?;
    fs::write(output, rst)?;
    Ok(())
}

fn main() {
    if let Err(e) = compute() {
        exit((e as u16).into());
    }
}
