//! The Veracruz WASM execution engine
//!
//! This module executes the WASM binary, and manages its execution, using two
//! *execution strategies*.  These are:
//!
//! 1. Interpretation, using the WASMI interpreter,
//! 2. JIT compilation, using the Wasmtime JIT.
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

#![cfg_attr(feature = "sgx", no_std)]

#[cfg(feature = "sgx")]
#[macro_use]
extern crate sgx_tstd as std;

#[cfg(feature = "std")]
#[macro_use]
extern crate std;

extern crate lazy_static;

#[macro_use]
extern crate num_derive;
extern crate num_traits;

pub mod factory;
pub mod hcall;
pub mod fs;
