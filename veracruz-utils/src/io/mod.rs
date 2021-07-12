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
//! See the `LICENSE_MIT.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

/// IO-related error type.
#[cfg(feature = "nitro")]
pub mod error;
/// Buffer send- and receive-related functionality for raw file descriptors.
#[cfg(feature = "nitro")]
pub mod raw_fd;
/// A Nitro-specific abstraction over sockets.
#[cfg(feature = "nitro")]
pub mod vsocket;
