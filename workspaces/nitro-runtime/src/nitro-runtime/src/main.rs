//! The Runtime Manager enclave
//!
//! Includes the entry point for the Nitro backend.
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE_MIT.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

pub use runtime_manager::platforms::nitro;

fn main() -> Result<(), String> {
    nitro::nitro_main()
        .map_err(|err| format!("Runtime Manager::main nitro_main returned error: {:?}", err))
}
