//! Test of the trusted random source platform service.
//!
//! ## Context
//!
//! Test program for random number generation.
//!
//! Inputs:                  0.
//! Assumed form of inputs:  Not applicable.
//! Ensured form of outputs: A Pinecone-encoded vector of 32 `u8` values taken
//!                          from a random source provided by the underlying
//!                          platform.
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Copyright
//!
//! See the file `LICENSING.markdown` in the Veracruz root directory for licensing
//! and copyright information.

use rand::Rng;
use std::{fs, process::exit, result::Result};

/// Entry point: generates a four-element long random vector of `u8` values and
/// writes this back as the result.
fn main() {
    if let Err(e) = random() {
        exit(e);
    }
    //NOTE: it is not necessary to explicitly call exit(0).
    exit(0);
}

/// Write 32 random bytes to 'output'. The result is a Pinecone-encoded vector of u8.
fn random() -> Result<(), i32> {
    let output = "/output";
    let bytes = rand::thread_rng().gen::<[u8; 32]>();
    let rst = pinecone::to_vec(&bytes.to_vec()).map_err(|_| -1)?;
    fs::write(output, rst).map_err(|_| -1)?;
    Ok(())
}
