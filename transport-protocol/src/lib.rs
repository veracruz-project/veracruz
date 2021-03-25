//! The transport protocol library
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

#![crate_name = "transport_protocol"]
#![crate_type = "staticlib"]
#![cfg_attr(feature = "sgx", no_std)]
#![cfg_attr(feature = "sgx", feature(rustc_private))]

#[cfg(feature = "sgx")]
#[macro_use]
extern crate sgx_tstd as std;

// The protocol buffer generator generates some deprecated code.
// I cannot fix this, but the warnings are cluttering my output.
// Disabling warnings means I don't see these issues for things
// that I cannot fix.
// It would be better to do this for a specific file, but there
// does not appear to be a way to do this
#[allow(warnings)]
pub mod transport_protocol;
pub mod custom;
pub use crate::transport_protocol::*;
pub use crate::custom::*;
