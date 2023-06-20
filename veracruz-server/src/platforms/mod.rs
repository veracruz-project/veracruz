//! Veracruz Server on Specific Platforms.
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE_MIT.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

#[cfg(feature = "icecap")]
pub mod icecap;
#[cfg(feature = "nitro")]
pub mod nitro;
