//! The Veracruz host-call interface, and its implementation.
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Copyright
//!
//! See the file `LICENSE.markdown` in the Veracruz root directory for licensing
//! and copyright information.

pub mod common;
pub mod wasmi;
#[cfg(feature = "std")]
pub mod wasmtime;
pub mod buffer;
