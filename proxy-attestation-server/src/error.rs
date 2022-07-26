//! Error messages for the Veracruz proxy attestation server
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE_MIT.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

use actix_web::{error, http::StatusCode, HttpResponse, HttpResponseBuilder};
use coset::CoseError;
use err_derive::Error;

pub type ProxyAttestationServerResponder = Result<String, ProxyAttestationServerError>;

#[derive(Debug, Error)]
pub enum ProxyAttestationServerError {
    #[error(display = "ProxyAttestationServer: Base64Error: {:?}.", _0)]
    Base64Error(#[error(source)] base64::DecodeError),
    #[error(
        display = "ProxyAttestationServer: OpenSSLError (an error stack): {:#?}.",
        _0
    )]
    OpenSSLError(#[error(source)] openssl::error::ErrorStack),
    #[error(
        display = "ProxyAttestationServer: PSACrypto Error: {:#?}",
        _0
    )]
    PSACryptoError(String),
    #[error(
        display = "ProxyAttestationServer: CoseError: {:#?}",
        _0
    )]
    CoseError(CoseError),
    #[error(
        display = "ProxyAttestationServer: CiboriumError: {:#?}",
        _0
    )]
    CiboriumError(ciborium::de::Error<std::io::Error>),
    #[error(display = "ProxyAttestationServer: CurlError: {:?}.", _0)]
    CurlError(#[error(source)] curl::Error),
    #[error(display = "ProxyAttestationServer: Failed to obtain lock {:?}.", _0)]
    LockError(String),
    #[error(
        display = "ProxyAttestationServer: MismatchError: variable `{}` mismatch, expected {:?} but received {:?}.",
        variable,
        expected,
        received
    )]
    MismatchError {
        variable: &'static str,
        expected: std::vec::Vec<u8>,
        received: std::vec::Vec<u8>,
    },
    #[error(display = "ProxyAttestationServer: No proxy PSA attestation token.")]
    NoProxyPSAAttestationTokenError,
    #[error(
        display = "ProxyAttestationServer: Failed to obtain device with ID {}.",
        _0
    )]
    NoDeviceError(i32),
    #[error(
        display = "ProxyAttestationServer: Missing {}, which is caused by non-existence, empty field, null, etc.",
        _0
    )]
    MissingFieldError(&'static str),
    #[error(display = "ProxyAttestationServer: Unknown attestation protocol.")]
    UnknownAttestationTokenError,
    #[error(
        display = "ProxyAttestationServer: Unsupported request (not implemented in this platform)."
    )]
    UnimplementedRequestError,
    #[error(display = "ProxyAttestationServer: Unsupported request (not found).")]
    UnsupportedRequestError,
    #[error(display = "ProxyAttestationServer: Direct message {}.", _0)]
    DirectMessageError(String, StatusCode),
    #[error(display = "ProxyAttestationServer: CSR Verify failed")]
    CsrVerifyError,
    #[error(display = "ProxyAttestationServer: IOError {}.", _0)]
    IOError(#[error(source)] std::io::Error),
    #[error(display = "ProxyAttestationServer: BadState error")]
    BadStateError,
    #[error(display = "ProxyAttestationServer: IntConversionError")]
    IntConversionError,
    #[error(display = "ProxyAttestationServer: Http Error {}.", _0)]
    HttpError(io_utils::http::HttpError)
    #[error(display = "ProxyAttestationServer: Anyhow error {:?}", _0)]
    Anyhow(anyhow::Error),
}

impl<T> From<std::sync::PoisonError<T>> for ProxyAttestationServerError {
    fn from(error: std::sync::PoisonError<T>) -> Self {
        ProxyAttestationServerError::LockError(format!("{:?}", error))
    }
}

impl From<anyhow::Error> for ProxyAttestationServerError {
    fn from(error: anyhow::Error) -> Self {
        ProxyAttestationServerError::Anyhow(error)
    }
}

impl error::ResponseError for ProxyAttestationServerError {
    fn error_response(&self) -> HttpResponse {
        HttpResponseBuilder::new(self.status_code()).body(format!("{:?}", self))
    }
    fn status_code(&self) -> StatusCode {
        match self {
            ProxyAttestationServerError::DirectMessageError(_, e) => *e,
            ProxyAttestationServerError::UnimplementedRequestError
            | ProxyAttestationServerError::UnknownAttestationTokenError => {
                StatusCode::NOT_IMPLEMENTED
            }
            ProxyAttestationServerError::UnsupportedRequestError => StatusCode::NOT_FOUND,
            _otherwise => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}
