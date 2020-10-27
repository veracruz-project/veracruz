//! The Mexico City enclave
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

#![crate_name = "mexico_city_enclave"]
#![cfg_attr(feature = "sgx", no_std)]
#![feature(rustc_private)]

#[cfg(feature = "sgx")]
#[macro_use]
extern crate sgx_tstd as std;

#[cfg(feature = "sgx")]
pub mod mc_sgx;
#[cfg(feature = "sgx")]
pub use crate::mc_sgx::*;
pub mod managers;
