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

#![cfg_attr(any(feature = "icecap"), no_main)]
#![crate_name = "runtime_manager_enclave"]
#![feature(rustc_private)]
#![cfg_attr(any(feature = "icecap"), feature(format_args_nl))]

#[cfg(feature = "linux")]
pub mod runtime_manager_linux;

#[cfg(feature = "icecap")]
pub mod runtime_manager_icecap;
#[cfg(feature = "icecap")]
pub use crate::runtime_manager_icecap::*;

#[cfg(feature = "nitro")]
pub mod runtime_manager_nitro;

pub mod managers;
mod runtime_manager;

#[cfg(feature = "nitro")]
fn main() -> Result<(), String> {
    runtime_manager_nitro::nitro_main()
        .map_err(|err| format!("Runtime Manager::main nitro_main returned error: {:?}", err))
}

#[cfg(feature = "linux")]
fn main() -> Result<(), String> {
    runtime_manager_linux::linux_main()
        .map_err(|err| format!("Runtime Manager::main linux_main returned error: {:?}", err))
}
