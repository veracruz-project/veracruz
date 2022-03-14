//! Platform-specific material.
//!
//! Material specific to a particular platform that Veracruz supports, and which
//! does not fit elsewhere.
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE_MIT.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

pub mod error;
#[cfg(feature = "icecap")]
pub mod icecap;
#[cfg(feature = "nitro")]
pub mod nitro;
#[cfg(any(feature = "nitro", feature = "linux"))]
pub mod vm;
