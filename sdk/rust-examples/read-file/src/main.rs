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
//! See the `LICENSE_MIT.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

use std::fs;
use anyhow;

/// Read from 'input.txt', encode then using pinecone and write to 'output'.
fn main() -> anyhow::Result<()> {
    let input = "/input.txt";
    let output = "/output";

    let mut input_string = fs::read(input)?;

    for file in fs::read_dir("/")? {
        input_string.append(&mut file?.path().to_str().ok_or(ErrNo::Proto)?.as_bytes().to_vec())
    }

    let rst = pinecone::to_vec(&input_string).map_err(|_| ErrNo::Proto)?;
    fs::write(output, rst)?;
    Ok(())
}
