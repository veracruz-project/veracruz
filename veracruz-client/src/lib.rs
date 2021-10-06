//! The Veracruz client's library
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE_MIT.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

// NB: added to avoid a compile-failure in Rust's futures library.
#![feature(proc_macro_hygiene)]

pub mod veracruz_client;
pub use self::veracruz_client::*;
pub mod admin_client;
pub use self::admin_client::*;
pub mod attestation;
pub mod error;
pub use self::error::*;

#[cfg(test)]
mod tests;
