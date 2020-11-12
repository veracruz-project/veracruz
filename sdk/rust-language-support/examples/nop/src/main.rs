//! A trivial, no-operation example.
//!
//! ## Context
//!
//! A basic test for Veracruz.
//!
//! Inputs:                  N/A.
//! Assumed form of inputs:  N/A.
//! Ensured form of outputs: N/A.
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Copyright
//!
//! See the file `LICENSE.markdown` in the Veracruz root directory for licensing
//! and copyright information.

use libveracruz::return_code;

/// Entry point: immediately returns success.
fn main() -> return_code::Veracruz {
    return_code::success()
}
