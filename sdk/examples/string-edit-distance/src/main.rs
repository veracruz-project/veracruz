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

use libveracruz::{data_description::write_result, host, return_code};
use strsim::jaro_winkler;

/// Reads two input strings via the H-call mechanism.  Fails
///
/// - with `return_code::ErrorCode::BadInput` if the strings are not encoded
///   in `pinecone` and therefore cannot be decoded,
/// - with `return_code::ErrorCode::DataSourceCount` if the number of inputs
///   provided to the program is not exactly 2.
///
fn read_inputs() -> Result<(String, String), i32> {
    if host::input_count() != 2 {
        return_code::fail_data_source_count()
    } else {
        let this = match String::from_utf8(host::read_input(0).unwrap()) {
            Ok(s) => s,
            _otherwise => return return_code::fail_bad_input(),
        };
        let that = match String::from_utf8(host::read_input(1).unwrap()) {
            Ok(s) => s,
            _otherwise => return return_code::fail_bad_input(),
        };

        Ok((this, that))
    }
}

/// Entry point: assumes that the program has been supplied with two data sets,
/// which are Rust strings encoded with Pinecone.  Fails if these assumptions
/// are not met with an error code.  Writes a Pinecone-encoded `usize`, the
/// distance between the two strings, back as output.
fn main() -> return_code::Veracruz {
    let (left, right) = read_inputs()?;
    let distance = jaro_winkler(&left, &right);
    write_result::<f64>(distance)
}
