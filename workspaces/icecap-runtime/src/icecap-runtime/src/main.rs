//! The Runtime Manager enclave
//!
//! Includes the entry point for the Nitro and Linux backends.
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE_MIT.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

#![no_main]
#![feature(rustc_private)]
#![feature(format_args_nl)]

#[cfg(feature = "icecap")]
pub use runtime_manager::platforms::icecap;
#[cfg(feature = "icecap")]
pub use runtime_manager::platforms::icecap::*;
