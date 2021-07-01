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
//! See the `LICENSE.markdown` file in the Veracruz root directory for
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
/// Types and definitions relating to the Veracruz global policy file.
pub mod policy;
pub use crate::policy::*;

#[cfg(feature = "nitro")]
pub use crate::platform::nitro::*;

#[cfg(feature = "nitro")]
pub use self::io::vsocket::*;

#[cfg(feature = "nitro")]
pub use self::platform::nitro::nitro_enclave::*;

pub mod csr;
