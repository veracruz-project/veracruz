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

#![cfg_attr(feature = "tz", no_main)]
#![crate_name = "runtime_manager_enclave"]
#![feature(rustc_private)]

#[cfg(feature = "tz")]
pub mod runtime_manager_trustzone;
#[cfg(feature = "linux")]
pub mod runtime_manager_linux;
#[cfg(feature = "tz")]
pub use crate::runtime_manager_trustzone::*;
#[cfg(feature = "nitro")]
pub mod runtime_manager_nitro;

mod runtime_manager;
pub mod managers;

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
