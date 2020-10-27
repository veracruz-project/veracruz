//! Baja error
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

use err_derive::Error;

#[derive(Debug, Error)]
pub enum BajaError {
    // NOTE: Protobuf does not implement clone, hence derive(clone) is impossible.
    #[error(display = "Baja: TLSError: {:?}.", _0)]
    TLSError(#[error(source)] rustls::TLSError),
    #[error(display = "Baja: TLSError: unspecified.")]
    TLSUnspecifiedError,
    #[error(display = "Baja: TLSError: invalid cyphersuite {:?}.", _0)]
    TLSInvalidCyphersuiteError(std::string::String),
    #[error(display = "Baja: TLSError: unsupported cyphersuite {:?}.", _0)]
    TLSUnsupportedCyphersuiteError(rustls::CipherSuite),
    #[error(display = "Baja: IOError: {:?}.", _0)]
    IOError(#[error(source)] std::io::Error),
    #[error(display = "Baja: RingUnspecifiedError: {:?}.", _0)]
    RingUnspecifiedError(#[error(source)] ring::error::Unspecified),
    #[error(display = "Baja: RingKeyRejectedError: {:?}.", _0)]
    RingKeyRejectedError(#[error(source)] ring::error::KeyRejected),
    #[error(display = "Baja: Webpki: {:?}.", _0)]
    WebpkiError(#[error(source)] webpki::Error),
    #[error(display = "Baja: Failed to retrieve peer certificates.")]
    PeerCertificateError,
    #[error(display = "Baja: Invalid length of variable `{}`, expected {}", _0, _1)]
    InvalidLengthError(&'static str, usize),
    #[error(display = "Baja: Client {} has no role.", _0)]
    EmptyRoleError(u64),
    #[error(display = "Baja: No certificate")]
    NoCertificateError,
}
