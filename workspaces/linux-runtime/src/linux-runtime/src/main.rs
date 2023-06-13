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

pub use runtime_manager::platforms::linux;

fn main() -> Result<(), String> {
    linux::linux_main()
        .map_err(|err| format!("Runtime Manager::main linux_main returned error: {:?}", err))
}
