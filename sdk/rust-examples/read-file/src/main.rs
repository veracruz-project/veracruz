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

    let f = fs::read(input)?;
    let rst = pinecone::to_vec(&f)?;
    fs::write(output, rst)?;

    fs::read_dir("/")?;

    Ok(())
}
