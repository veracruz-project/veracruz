//! The Durango error
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
pub enum DurangoError {
    // NOTE: Protobuf does not implement clone, hence derive(clone) is impossible.
    #[error(display = "Durango: HexError: {:?}.", _0)]
    HexError(#[error(source)] hex::FromHexError),
    #[error(display = "Durango: Base64Error: {:?}.", _0)]
    Base64Error(#[error(source)] base64::DecodeError),
    #[error(display = "Durango: Utf8Error: {:?}.", _0)]
    Utf8Error(#[error(source)] std::str::Utf8Error),
    #[error(display = "Durango: Reqwest: {:?}.", _0)]
    ReqwestError(#[error(source)] reqwest::Error),
    #[error(display = "Durango: Invalid reqwest estatus {:?}.", _0)]
    InvalidReqwestError(reqwest::StatusCode),
    #[error(display = "Durango: IOError: {:?}.", _0)]
    IOError(#[error(source)] std::io::Error),
    #[error(display = "Durango: TLSError: {:?}.", _0)]
    TLSError(#[error(source)] rustls::TLSError),
    #[error(display = "Durango: TLSError: unsupported cyphersuite {:?}.", _0)]
    TLSUnsupportedCyphersuiteError(rustls::CipherSuite),
    #[error(display = "Durango: TLSError: unspecified.")]
    TLSUnspecifiedError,
    #[error(display = "Durango: TLSError: invalid cyphersuite {:?}.", _0)]
    TLSInvalidCyphersuiteError(std::string::String),
    #[error(display = "Durango: RingError: {:?}", _0)]
    RingError(std::string::String),
    #[error(display = "Durango: SerdeJsonError: {:?}.", _0)]
    SerdeJsonError(#[error(source)] serde_json::error::Error),
    #[error(display = "Durango: X509Error: {:?}.", _0)]
    X509ParserPEMError(x509_parser::error::PEMError),
    #[error(display = "Durango: X509Error: {:?}.", _0)]
    X509ParserError(String),
    #[error(display = "Durango: WebpkiError: {:?}.", _0)]
    WebpkiError(#[error(source)] webpki::Error),
    #[error(display = "Durango: WebpkiError: {:?}.", _0)]
    WebpkiDNSError(#[error(source)] webpki::InvalidDNSNameError),
    #[error(display = "Durango: TryIntoError: {}.", _0)]
    TryIntoError(#[error(source)] std::num::TryFromIntError),
    #[error(display = "Durango: ParseIntError: {}.", _0)]
    ParseIntError(#[error(source)] std::num::ParseIntError),
    #[error(display = "Durango: TransportProtocolError: {:?}.", _0)]
    TransportProtocolError(#[error(source)] transport_protocol::TransportProtocolError),
    #[error(display = "Durango: VeracruzUtilError: {:?}.", _0)]
    VeracruzUtilError(#[error(source)] veracruz_utils::policy::VeracruzUtilError),
    #[error(display = "Durango: Certificate expired: {:?}.", _0)]
    CertificateExpireError(String),
    #[error(
        display = "Durango: MismatchError: variable `{}` mismatch, expected {:?} but received {:?}.",
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
        display = "Durango: Invalid length of variable `{}`, expected {}",
        _0,
        _1
    )]
    InvalidLengthError(&'static str, usize),
    #[error(
        display = "Durango: Function {} received non-success status: {:?}",
        _0,
        _1
    )]
    ResponseError(&'static str, transport_protocol::ResponseStatus),
    #[error(display = "Durango: Received no result from Sinaloa")]
    VeracruzServerResponseNoResultError,
    #[error(display = "Durango: Too many interation: {:?}", _0)]
    ExcessiveIterationError(&'static str),
    #[error(
        display = "Durango: client with certificate {:?} has no role of {:?}.",
        _0,
        _1
    )]
    InvalidRoleError(Vec<u8>, veracruz_utils::VeracruzRole),
    #[error(display = "Durango: Unauthorized client certificate: {}.", _0)]
    InvalidClientCertificateError(String),
    #[error(display = "Durango: Direct message: {}.", _0)]
    DirectMessage(String),
}

impl From<x509_parser::error::PEMError> for DurangoError {
    fn from(error: x509_parser::error::PEMError) -> Self {
        DurangoError::X509ParserPEMError(error)
    }
}
