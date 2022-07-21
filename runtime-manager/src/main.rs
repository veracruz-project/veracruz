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
#![cfg_attr(any(feature = "icecap"), feature(rustc_private))]
#![cfg_attr(any(feature = "icecap"), feature(format_args_nl))]

pub mod managers;
pub mod platforms;

#[cfg(feature = "linux")]
pub use platforms::linux;
#[cfg(feature = "icecap")]
pub use platforms::icecap;
#[cfg(feature = "icecap")]
pub use crate::platforms::icecap::*;
#[cfg(feature = "nitro")]
pub use platforms::nitro;

#[cfg(feature = "nitro")]
fn main() -> Result<(), String> {
    nitro::nitro_main()
        .map_err(|err| format!("Runtime Manager::main nitro_main returned error: {:?}", err))
}

#[cfg(feature = "linux")]
fn main() -> Result<(), String> {
    linux::linux_main()
        .map_err(|err| format!("Runtime Manager::main linux_main returned error: {:?}", err))
}
