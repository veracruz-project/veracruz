//! Veracruz client error
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

#[derive(Debug, Error)]
pub enum VeracruzClientError {
    #[error(display = "VeracruzClient: Received non-success status: {:?}", _0)]
    ResponseStatus(transport_protocol::ResponseStatus),
    #[error(display = "VeracruzClient: Received no result from the Veracruz server")]
    ResponseNoResult,
    #[error(display = "VeracruzClient: No Peer certificates received")]
    NoPeerCertificates,
    #[error(display = "VeracruzClient: Unexpected certificate error")]
    UnexpectedCertificate,
    #[error(display = "VeracruzClient: Unexpected key error")]
    UnexpectedKey,
    #[error(display = "VeracruzClient: Unexpected policy error")]
    UnexpectedPolicy,
    #[error(display = "VeracruzClient: Unexpected ciphersuite error")]
    UnexpectedCiphersuite,
    #[error(
        display = "VeracruzClient: Runtime enclave hash extension is not present in the peer certificate"
    )]
    RuntimeHashExtensionMissing,
    #[error(display = "VeracruzClient: Unexpected runtime hash")]
    UnexpectedRuntimeHash,
    #[error(display = "VeracruzClient: Unvalid path")]
    InvalidPath,
    #[error(display = "VeracruzClient: Lock session failed")]
    LockSessionFailed,
}
