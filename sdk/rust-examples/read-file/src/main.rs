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

/// Read from 'input.txt', encode then using pinecone and write to 'output'.
fn compute() -> Result<(), i32> {
    let input = "/input.txt";
    let output = "/output";

    let f = fs::read(input).map_err(|_| 1)?;
    let rst = pinecone::to_vec(&f).map_err(|_| 1)?;
    fs::write(output, rst).map_err(|_| 1)?;
    Ok(())
}

fn main() {
    if let Err(e) = compute() {
        exit(e);
    }
}
