//! The Veracruz utility library
//!
//! Material that doesn't fit anywhere else, or is common across many modules.
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE_MIT.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

#![cfg_attr(feature = "sgx", no_std)]

#[cfg(feature = "sgx")]
#[macro_use]
extern crate sgx_tstd as std;

/// I/O related material, such as VSocket types and material relating to FDs,
/// that is shared across the Veracruz codebase.
pub mod io;
/// Platform-specific material, or material that is common to all
/// platforms/backends that Veracruz supports and does not fit elsewhere.
pub mod platform;

#[cfg(feature = "nitro")]
pub use crate::platform::nitro::*;

#[cfg(feature = "nitro")]
pub use self::io::vsocket::*;

#[cfg(feature = "nitro")]
pub use self::platform::nitro::nitro_enclave::*;

pub mod csr;

/// The ID of the Veracruz Runtime Hash Extension.
/// This value was made up, and can be changed to pretty much any valid
/// ID as long as it doesn't collide with the ID of an extension in our
/// certificates.
pub static VERACRUZ_RUNTIME_HASH_EXTENSION_ID: [u8; 4] = [2, 5, 30, 1];
