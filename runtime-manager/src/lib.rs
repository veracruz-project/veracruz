//! The Runtime Manager enclave
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

#![crate_name = "runtime_manager_enclave"]
#![cfg_attr(feature = "sgx", no_std)]
#![feature(rustc_private)]

#[cfg(feature = "sgx")]
#[macro_use]
extern crate sgx_tstd as std;

#[cfg(feature = "sgx")]
pub mod runtime_manager_sgx;
#[cfg(feature = "sgx")]
pub use crate::runtime_manager_sgx::*;
pub mod managers;

mod runtime_manager;
