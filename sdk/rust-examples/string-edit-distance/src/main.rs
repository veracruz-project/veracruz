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

use std::{fs, process::exit, result::Result};
use strsim::jaro_winkler;

/// Reads two input strings via the H-call mechanism.  Fails
///
/// - with `return_code::ErrorCode::BadInput` if the strings are not encoded
///   in `pinecone` and therefore cannot be decoded,
/// - with `return_code::ErrorCode::DataSourceCount` if the number of inputs
///   provided to the program is not exactly 2.
///
fn read_inputs() -> Result<(String, String), i32> {
    let this = String::from_utf8(fs::read("/input-0").map_err(|_| 1)?).map_err(|_| 1)?;
    let that = String::from_utf8(fs::read("/input-1").map_err(|_| 1)?).map_err(|_| 1)?;

    Ok((this, that))
}

/// Entry point: assumes that the program has been supplied with two data sets,
/// which are Rust strings encoded with Pinecone.  Fails if these assumptions
/// are not met with an error code.  Writes a Pinecone-encoded `usize`, the
/// distance between the two strings, back as output.
fn compute() -> Result<(), i32> {
    let (left, right) = read_inputs()?;
    let distance = jaro_winkler(&left, &right);
    let result_encode = pinecone::to_vec::<f64>(&distance).map_err(|_| 1)?;
    fs::write("/output", result_encode).map_err(|_| 1)?;
    Ok(())
}

fn main() {
    if let Err(e) = compute() {
        exit(e);
    }
}
