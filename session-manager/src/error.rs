//! Session manager error
//!
//! Various errors produced by the session and contexts, and operations on them.
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

/// The various different error modes associated with the session manager
/// module.
///
/// NOTE: `protobuf` does not implement `Clone`, so deriving `Clone` for this
/// type is impossible.
#[derive(Debug, Error)]
pub enum SessionManagerError {
    /// A TLS error originating in the `RusTLS` library occurred, with an
    /// accompanying error code.
    #[error(display = "Session manager: a TLS error occurred: {:?}.", _0)]
    TLSError(#[error(source)] rustls::Error),
    /// A generic, unspecified TLS error occurred.
    #[error(display = "Session manager: an unspecified or unknown TLS error occurred.")]
    TLSUnspecifiedError,
    /// An invalid, or unknown, ciphersuite was requested.
    #[error(
        display = "Session manager: an invalid cyphersuite was requested in the TLS handshake: {:?}.",
        _0
    )]
    TLSInvalidCiphersuiteError(std::string::String),
    /// An unsupported ciphersuite was requested.
    #[error(
        display = "Session manager: an unsupported cyphersuite was requested in the TLS handshake: {:?}.",
        _0
    )]
    TLSUnsupportedCyphersuiteError(rustls::CipherSuite),
    /// An IO error occurred, with an accompanying error code.
    #[error(display = "Session manager: an IO error occurred: {:?}.", _0)]
    IOError(#[error(source)] std::io::Error),
    /// A generic error occurred in the Ring library.
    #[error(
        display = "Session manager: an unspecified error occurred in the Ring library: {:?}.",
        _0
    )]
    RingUnspecifiedError(#[error(source)] ring::error::Unspecified),
    /// A cryptographic key was rejected by the Ring library.
    #[error(
        display = "Session manager: the Ring library rejected a cryptographic key: {:?}.",
        _0
    )]
    RingKeyRejectedError(#[error(source)] ring::error::KeyRejected),
    /// A WebPKI error occurred with an accompanying error code.
    #[error(display = "Session manager: a WebPKI error occurred: {:?}.", _0)]
    WebpkiError(#[error(source)] webpki::Error),
    /// The runtime failed to obtain the peer certificates from the TLS session.
    #[error(display = "Session manager: failed to retrieve peer certificates.")]
    PeerCertificateError,
    /// The length of a variable (e.g. the number of expected peer certificates)
    /// did not match expectations.
    #[error(
        display = "Session manager: invalid length of variable `{}`, expected {}",
        _0,
        _1
    )]
    InvalidLengthError(&'static str, usize),
    /// A principal has not been assigned any roles in the Veracruz computation.
    #[error(
        display = "Session manager: principal {} has not been assigned any role in the computation.",
        _0
    )]
    EmptyRoleError(u64),
    /// A cryptographic certificate was missing.
    #[error(display = "Session manager: no certificate was found.")]
    NoCertificateError,
    /// Invalid state (an Option was None when it should not be, for example)
    #[error(display = "Session manager: invalid state")]
    InvalidStateError,
}
