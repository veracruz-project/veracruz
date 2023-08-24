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
//! See the `LICENSE.md` file in the Veracruz root directory for
//! information on licensing and copyright.

use err_derive::Error;

/// The various different error modes associated with the session manager
/// module.
#[derive(Debug, Error)]
pub enum SessionManagerError {
    /// An invalid, or unknown, ciphersuite was requested.
    #[error(
        display = "Session manager: an invalid cyphersuite was requested in the TLS handshake: {:?}.",
        _0
    )]
    TLSInvalidCiphersuiteError(std::string::String),
    /// The runtime failed to obtain the peer certificates from the TLS session.
    #[error(display = "Session manager: failed to retrieve peer certificates.")]
    PeerCertificateError,
    /// A cryptographic certificate was missing.
    #[error(display = "Session manager: no certificate was found.")]
    NoCertificateError,
    /// Invalid state (an Option was None when it should not be, for example)
    #[error(display = "Session manager: invalid state")]
    InvalidStateError,
    /// Failed to obtain lock (internal error).
    #[error(display = "Session manager: shared buffer lock failed")]
    SharedBufferLock,
}
