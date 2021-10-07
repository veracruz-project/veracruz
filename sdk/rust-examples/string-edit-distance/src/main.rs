//! String edit distance of two UTF-8 strings.
//!
//! ## Context
//!
//! Inputs:                  2.
//! Assumed form of inputs:  UTF-8 strings to compare.
//! Ensured form of outputs: A Pinecone-encoded `usize` which captures the
//!                          Damerau-Lehventstein edit distance between the two
//!                          strings.
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
use std::fs;
use strsim::jaro_winkler;

/// Reads two input strings via the H-call mechanism.  Fails
///
/// - with `return_code::ErrorCode::BadInput` if the strings are not encoded
///   in `pinecone` and therefore cannot be decoded,
/// - with `return_code::ErrorCode::DataSourceCount` if the number of inputs
///   provided to the program is not exactly 2.
///
fn read_inputs() -> anyhow::Result<(String, String)> {
    let this = String::from_utf8(fs::read("/input/hello-world-1.dat")?)?;
    let that = String::from_utf8(fs::read("/input/hello-world-2.dat")?)?;

    Ok((this, that))
}

/// Entry point: assumes that the program has been supplied with two data sets,
/// which are Rust strings encoded with Pinecone.  Fails if these assumptions
/// are not met with an error code.  Writes a Pinecone-encoded `usize`, the
/// distance between the two strings, back as output.
fn main() -> anyhow::Result<()> {
    let (left, right) = read_inputs()?;
    let distance = jaro_winkler(&left, &right);
    let result_encode = pinecone::to_vec::<f64>(&distance)?;
    fs::write("/output/string-edit-distance.dat", result_encode)?;
    Ok(())
}
