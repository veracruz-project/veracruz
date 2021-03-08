//! Error messages for the Veracruz proxy attestation server
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

use actix_http::ResponseBuilder;
use actix_web::{error, http::StatusCode, HttpResponse};
use err_derive::Error;

pub type ProxyAttestationServerResponder = Result<String, ProxyAttestationServerError>;

#[derive(Debug, Error)]
pub enum ProxyAttestationServerError {
    #[error(display = "ProxyAttestationServer: HexError: {:?}.", _0)]
    HexError(#[error(source)] hex::FromHexError),
    #[error(display = "ProxyAttestationServer: Base64Error: {:?}.", _0)]
    Base64Error(#[error(source)] base64::DecodeError),
    #[error(display = "ProxyAttestationServer: TransportProtocolError: {:?}.", _0)]
    TransportProtocolError(#[error(source)] transport_protocol::TransportProtocolError),
    #[error(display = "ProxyAttestationServer: DieselError: {:?}.", _0)]
    DieselError(#[error(source)] diesel::result::Error),
    #[error(display = "ProxyAttestationServer: DieselError: {:?}.", _0)]
    DieselConnectionError(#[error(source)] diesel::ConnectionError),
    #[error(display = "ProxyAttestationServer: Utf8Error: {:?}.", _0)]
    Utf8Error(#[error(source)] std::str::Utf8Error),
    #[error(display = "ProxyAttestationServer: SerdeJsonError: {:?}.", _0)]
    SerdeJsonError(#[error(source)] serde_json::Error),
    #[error(display = "ProxyAttestationServer: OpenSSLError (an error stack): {:#?}.", _0)]
    OpenSSLError(#[error(source)] openssl::error::ErrorStack),
    #[error(display = "ProxyAttestationServer: CurlError: {:?}.", _0)]
    CurlError(#[error(source)] curl::Error),
    #[cfg(feature = "sgx")]
    #[error(display = "ProxyAttestationServer: SGXError: {:?}.", _0)]
    SGXError(sgx_types::sgx_status_t),
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
    #[error(display = "ProxyAttestationServer: {} failed with error code {:?}.", _0, _1)]
    UnsafeCallError(&'static str, u32),
    #[error(display = "ProxyAttestationServer: No proxy PSA attestation token.")]
    NoProxyPSAAttestationTokenError,
    #[error(display = "ProxyAttestationServer: No SGX attestation token.")]
    NoSGXAttestationTokenError,
    #[error(display = "ProxyAttestationServer: Failed to obtain device with ID {}.", _0)]
    NoDeviceError(i32),
    #[error(
        display = "ProxyAttestationServer: Missing {}, which is caused by non-existence, empty field, null, etc.",
        _0
    )]
    MissingFieldError(&'static str),
    #[error(display = "ProxyAttestationServer: Failed to verify {}.", _0)]
    FailedToVerifyError(&'static str),
    #[error(display = "ProxyAttestationServer: Unknown attestation protocol.")]
    UnknownAttestationTokenError,
    #[error(display = "ProxyAttestationServer: Unsupported request (not implemented in this platform).")]
    UnimplementedRequestError,
    #[error(display = "ProxyAttestationServer: Unsupported request (not found).")]
    UnsupportedRequestError,
    #[error(display = "ProxyAttestationServer: Direct message {}.", _0)]
    DirectMessageError(String, StatusCode),
    #[error(display = "ProxyAttestationServer: cbor error {}.", _0)]
    CborError(String),
    #[error(display = "ProxyAttestationServer: Mutex error {}.", _0)]
    MutexError(String),
}

#[cfg(feature = "sgx")]
impl From<sgx_types::sgx_status_t> for ProxyAttestationServerError {
    fn from(error: sgx_types::sgx_status_t) -> Self {
        match error {
            sgx_types::sgx_status_t::SGX_SUCCESS => {
                panic!("Expected an error code but received an success status")
            }
            e => ProxyAttestationServerError::SGXError(e),
        }
    }
}

impl<T> From<std::sync::PoisonError<T>> for ProxyAttestationServerError {
    fn from(error: std::sync::PoisonError<T>) -> Self {
        ProxyAttestationServerError::LockError(format!("{:?}", error))
    }
}

impl error::ResponseError for ProxyAttestationServerError {
    fn error_response(&self) -> HttpResponse {
        ResponseBuilder::new(self.status_code()).body(format!("{:?}", self))
    }
    fn status_code(&self) -> StatusCode {
        match self {
            ProxyAttestationServerError::DirectMessageError(_, e) => e.clone(),
            ProxyAttestationServerError::UnimplementedRequestError
            | ProxyAttestationServerError::UnknownAttestationTokenError => StatusCode::NOT_IMPLEMENTED,
            ProxyAttestationServerError::UnsupportedRequestError => StatusCode::NOT_FOUND,
            _otherwise => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}
