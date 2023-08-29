//! Error types associated with the global policy.
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE_MIT.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

use err_derive::Error;
use std::string::String;

////////////////////////////////////////////////////////////////////////////////
// Policy-related errors.
////////////////////////////////////////////////////////////////////////////////

/// A generic catch-all error type for functionality related to platforms.
#[derive(Debug, Error)]
pub enum PlatformError {
    #[cfg(feature = "std")]
    #[error(display = "PlatformError: Enclave platform not supported: {:?}.", _0)]
    InvalidPlatform(String),
}

/// A generic catch-all error type for functionality related to policies.  This
/// error type contains more constructors when compiling for clients or hosts.
#[derive(Debug, Error)]
pub enum PolicyError {
    #[error(display = "PolicyError: TLSError: invalid cyphersuite: {:?}.", _0)]
    TLSInvalidCiphersuiteError(String),
    #[error(display = "PolicyError: unauthorized client certificate: {}.", _0)]
    InvalidClientCertificateError(String),
    #[error(display = "PolicyError: format error.")]
    FormatError,
    #[error(display = "PolicyError: Invalid path.")]
    InvalidPath,
    #[error(display = "PolicyError: Invalid platform.")]
    InvalidPlatform,
    #[error(
        display = "PolicyError: Parsing failure when trying to parse pipeline: {:?}.",
        _0
    )]
    PipelineParsingFailure(String),
}
