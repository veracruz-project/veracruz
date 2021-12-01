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
pub mod error;
#[cfg(any(feature = "nitro", feature = "linux"))]
/// FD-related material.
pub mod fd;
/// HTTP-related material.
#[cfg(any(
    feature = "nitro",
    feature = "linux",
    feature = "icecap",
))]
pub mod http;
#[cfg(feature = "nitro")]
pub mod nitro;
/// Buffer send- and receive-related functionality for raw file descriptors.
#[cfg(feature = "nitro")]
pub mod raw_fd;
#[cfg(feature = "linux")]
/// TCP-socket related material.
pub mod tcp;
/// A Nitro-specific abstraction over sockets.
#[cfg(feature = "nitro")]
pub mod vsocket;
