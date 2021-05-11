//! An implementation of the WASI API for Execution Engine.
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

pub mod common;
pub(crate) mod wasmi;
#[cfg(feature = "std")]
pub(crate) mod wasmtime;
