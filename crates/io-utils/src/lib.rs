//! IO-related functionality
//!
//! This is input/output-related functionality that is useful in many places
//! across the Veracruz codebase.  The material consists of socket- and RawFD
//! utility functions.
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE.md` file in the Veracruz root directory for
//! information on licensing and copyright.

/// IO-related error type.
pub mod error;
#[cfg(any(feature = "nitro", feature = "linux"))]
/// FD-related material.
pub mod fd;
#[cfg(feature = "linux")]
/// TCP-socket related material.
pub mod tcp;
