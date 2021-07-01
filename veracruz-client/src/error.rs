//! Veracruz client error
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

#[derive(Debug, Error)]
pub enum VeracruzClientError {
    // NOTE: Protobuf does not implement clone, hence derive(clone) is impossible.
    #[error(display = "VeracruzClient: HexError: {:?}.", _0)]
    HexError(#[error(source)] hex::FromHexError),
    #[error(display = "VeracruzClient: Base64Error: {:?}.", _0)]
    Base64Error(#[error(source)] base64::DecodeError),
    #[error(display = "VeracruzClient: Utf8Error: {:?}.", _0)]
    Utf8Error(#[error(source)] std::str::Utf8Error),
    #[error(display = "VeracruzClient: Reqwest: {:?}.", _0)]
    ReqwestError(#[error(source)] reqwest::Error),
    #[error(display = "VeracruzClient: Invalid reqwest estatus {:?}.", _0)]
    InvalidReqwestError(reqwest::StatusCode),
    #[error(display = "VeracruzClient: IOError: {:?}.", _0)]
    IOError(#[error(source)] std::io::Error),
    #[error(display = "VeracruzClient: TLSError: {:?}.", _0)]
    TLSError(#[error(source)] rustls::TLSError),
    #[error(display = "VeracruzClient: TLSError: unsupported cyphersuite {:?}.", _0)]
    TLSUnsupportedCyphersuiteError(rustls::CipherSuite),
    #[error(display = "VeracruzClient: TLSError: unspecified.")]
    TLSUnspecifiedError,
    #[error(display = "VeracruzClient: TLSError: invalid cyphersuite {:?}.", _0)]
    TLSInvalidCyphersuiteError(std::string::String),
    #[error(display = "VeracruzClient: RingError: {:?}", _0)]
    RingError(std::string::String),
    #[error(display = "VeracruzClient: SerdeJsonError: {:?}.", _0)]
    SerdeJsonError(#[error(source)] serde_json::error::Error),
    #[error(display = "VeracruzClient: X509Error: {:?}.", _0)]
    X509ParserPEMError(x509_parser::error::PEMError),
    #[error(display = "VeracruzClient: X509Error: {:?}.", _0)]
    X509ParserError(String),
    #[error(display = "VeracruzClient: WebpkiError: {:?}.", _0)]
    WebpkiError(#[error(source)] webpki::Error),
    #[error(display = "VeracruzClient: WebpkiError: {:?}.", _0)]
    WebpkiDNSError(#[error(source)] webpki::InvalidDNSNameError),
    #[error(display = "VeracruzClient: TryIntoError: {}.", _0)]
    TryIntoError(#[error(source)] std::num::TryFromIntError),
    #[error(display = "VeracruzClient: ParseIntError: {}.", _0)]
    ParseIntError(#[error(source)] std::num::ParseIntError),
    #[error(display = "VeracruzClient: TransportProtocolError: {:?}.", _0)]
    TransportProtocolError(#[error(source)] transport_protocol::TransportProtocolError),
    #[error(display = "VeracruzClient: PolicyError: {:?}.", _0)]
    VeracruzUtilError(#[error(source)] veracruz_utils::policy::error::PolicyError),
    #[error(display = "VeracruzClient: Certificate expired: {:?}.", _0)]
    CertificateExpireError(String),
    #[error(
        display = "VeracruzClient: MismatchError: variable `{}` mismatch, expected {:?} but received {:?}.",
        variable,
        expected,
        received
    )]
    MismatchError {
        variable: &'static str,
        expected: std::vec::Vec<u8>,
        received: std::vec::Vec<u8>,
    },
    #[error(
        display = "VeracruzClient: Invalid length of variable `{}`, expected {}",
        _0,
        _1
    )]
    InvalidLengthError(&'static str, usize),
    #[error(
        display = "VeracruzClient: Function {} received non-success status: {:?}",
        _0,
        _1
    )]
    ResponseError(&'static str, transport_protocol::ResponseStatus),
    #[error(display = "VeracruzClient: Received no result from the Veracruz server")]
    VeracruzServerResponseNoResultError,
    #[error(display = "VeracruzClient: Too many interation: {:?}", _0)]
    ExcessiveIterationError(&'static str),
    #[error(display = "VeracruzClient: Unauthorized client certificate: {}.", _0)]
    InvalidClientCertificateError(String),
    #[error(display = "VeracruzClient: No Peer certificates received")]
    NoPeerCertificatesError,
    #[error(display = "VeracruzClient: Runtime enclave hash extension is not present in the peer certificate")]
    RuntimeHashExtensionMissingError,
    #[error(display = "VeracruzClient: Direct message: {}.", _0)]
    DirectMessage(String),
    #[error(display = "VeracruzClient: Unable to read")]
    UnableToReadError,
    #[error(display = "VeracruzClient: No match found for runtime isolate hash")]
    NoMatchingRuntimeIsolateHash,
}

impl From<x509_parser::error::PEMError> for VeracruzClientError {
    fn from(error: x509_parser::error::PEMError) -> Self {
        VeracruzClientError::X509ParserPEMError(error)
    }
}
