//! Error types associated with platform types.
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

use err_derive::Error;

////////////////////////////////////////////////////////////////////////////////
// Error type.
////////////////////////////////////////////////////////////////////////////////

/// A generic catch-all error type for functionality related to platforms.
#[derive(Debug, Error)]
pub enum PlatformError {
    #[cfg(feature = "std")]
    #[error(display = "PlatformError: Enclave platform not supported: {:?}.", _0)]
    InvalidPlatform(String),
}
