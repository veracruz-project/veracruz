//! The Durango library
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

// NB: added to avoid a compile-failure in Rust's futures library.
#![feature(proc_macro_hygiene)]

pub mod durango;
pub use self::durango::*;
pub mod attestation;
pub mod error;
pub use self::error::*;

#[cfg(test)]
mod tests;
