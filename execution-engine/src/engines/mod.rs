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
pub mod strace;
pub(crate) mod wasmi;
#[cfg(feature = "std")]
pub(crate) mod wasmtime;
#[cfg(feature = "icecap")]
pub mod icecap;
#[cfg(feature = "icecap-cca")]
pub mod icecap_cca;
#[cfg(feature = "linux")]
pub mod linux;
#[cfg(feature = "nitro")]
pub mod nitro;
