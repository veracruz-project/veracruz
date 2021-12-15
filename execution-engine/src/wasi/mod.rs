//! An implementation of the WASI API for Execution Engine.
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE_MIT.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

pub mod common;
pub(crate) mod wasmi;
#[cfg(any(feature = "std", feature = "icecap"))]
pub(crate) mod wasmtime;
