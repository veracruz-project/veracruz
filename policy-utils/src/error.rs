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
#[cfg(feature = "std")]
use rustls::{CipherSuite, Error as TLSError};
use std::{string::String, time::SystemTimeError};
#[cfg(feature = "std")]
use x509_parser::error::PEMError;

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
    #[error(display = "PolicyError: SerdeJsonError: {:?}.", _0)]
    SerdeJsonError(#[error(source)] serde_json::Error),
    // NOTE: PENError and X509Error do not implement Error trait, cannot use error(source).
    #[cfg(feature = "std")]
    #[error(display = "PolicyError: X509Error: {:?}.", _0)]
    X509ParserPEMError(PEMError),
    // NOTE: it is strange to work with nom::Err, which disallows unwrap.
    #[error(display = "PolicyError: X509Error: {:?}.", _0)]
    X509ParserError(String),
    #[cfg(feature = "std")]
    #[error(display = "PolicyError: TLSError: {:?}.", _0)]
    TLSError(#[error(source)] TLSError),
    #[error(display = "PolicyError: TLSError: invalid cyphersuite: {:?}.", _0)]
    TLSInvalidCiphersuiteError(String),
    #[error(display = "PolicyError: SystemTimeError: {:?}.", _0)]
    SystemTimeError(#[error(source)] SystemTimeError),
    #[error(display = "PolicyError: unauthorized client certificate: {}.", _0)]
    InvalidClientCertificateError(String),
    #[error(display = "PolicyError: HexDecodeError: {:?}.", _0)]
    HexDecodeError(hex::FromHexError),
    #[error(display = "PolicyError: Enclave expired.")]
    EnclaveExpireError,
    #[error(display = "PolicyError: Certificate expired: {:?}.", _0)]
    CertificateExpireError(String),
    #[cfg(feature = "std")]
    #[error(display = "PolicyError: TLSError: Unsupported cyphersuite {:?}.", _0)]
    TLSUnsupportedCyphersuiteError(CipherSuite),
    #[error(display = "PolicyError: Certificate format error: {:?}.", _0)]
    CertificateFormatError(String),
    #[error(display = "PolicyError: Duplicated client ID {}.", _0)]
    DuplicatedClientIDError(u64),
    #[error(display = "PolicyError: Client {} has no role.", _0)]
    EmptyRoleError(u64),
    #[error(display = "PolicyError: Policy is missing a field: {:?}", _0)]
    MissingPolicyFieldError(String),
    #[error(display = "VeracruzUtil: Policy has no program file: {:?}.", _0)]
    NoProgramFileError(String),
    #[error(display = "VeracruzUtil: IOError: {:?}.", _0)]
    IOError(#[error(source)] std::io::Error),
}

////////////////////////////////////////////////////////////////////////////////
// Trait implementations.
////////////////////////////////////////////////////////////////////////////////

#[cfg(feature = "std")]
impl From<x509_parser::error::PEMError> for PolicyError {
    #[inline]
    fn from(error: PEMError) -> Self {
        PolicyError::X509ParserPEMError(error)
    }
}

impl From<hex::FromHexError> for PolicyError {
    #[inline]
    fn from(error: hex::FromHexError) -> Self {
        PolicyError::HexDecodeError(error)
    }
}
