//! Tabasco error
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

pub type TabascoResponder = Result<String, TabascoError>;

#[derive(Debug, Error)]
pub enum TabascoError {
    #[error(display = "Tabasco: HexError: {:?}.", _0)]
    HexError(#[error(source)] hex::FromHexError),
    #[error(display = "Tabasco: Base64Error: {:?}.", _0)]
    Base64Error(#[error(source)] base64::DecodeError),
    #[error(display = "Tabasco: ColimaError: {:?}.", _0)]
    ColimaError(#[error(source)] colima::ColimaError),
    #[error(display = "Tabasco: DieselError: {:?}.", _0)]
    DieselError(#[error(source)] diesel::result::Error),
    #[error(display = "Tabasco: DieselError: {:?}.", _0)]
    DieselConnectionError(#[error(source)] diesel::ConnectionError),
    #[error(display = "Tabasco: Utf8Error: {:?}.", _0)]
    Utf8Error(#[error(source)] std::str::Utf8Error),
    #[error(display = "Tabasco: SerdeJsonError: {:?}.", _0)]
    SerdeJsonError(#[error(source)] serde_json::Error),
    #[error(display = "Tabasco: OpenSSLError (an error stack): {:#?}.", _0)]
    OpenSSLError(#[error(source)] openssl::error::ErrorStack),
    #[error(display = "Tabasco: CurlError: {:?}.", _0)]
    CurlError(#[error(source)] curl::Error),
    #[cfg(feature = "sgx")]
    #[error(display = "Tabasco: SGXError: {:?}.", _0)]
    SGXError(sgx_types::sgx_status_t),
    #[error(display = "Tabasco: Failed to obtain lock {:?}.", _0)]
    LockError(String),
    #[error(
        display = "Tabasco: MismatchError: variable `{}` mismatch, expected {:?} but received {:?}.",
        variable,
        expected,
        received
    )]
    MismatchError {
        variable: &'static str,
        expected: std::vec::Vec<u8>,
        received: std::vec::Vec<u8>,
    },
    #[error(display = "Tabasco: {} failed with error code {:?}.", _0, _1)]
    UnsafeCallError(&'static str, u32),
    #[error(display = "Tabasco: No proxy PSA attestation token.")]
    NoProxyPSAAttestationTokenError,
    #[error(display = "Tabasco: No SGX attestation token.")]
    NoSGXAttestationTokenError,
    #[error(display = "Tabasco: Failed to obtain device with ID {}.", _0)]
    NoDeviceError(i32),
    #[error(
        display = "Tabasco: Missing {}, which is caused by non-existence, empty field, null, etc.",
        _0
    )]
    MissingFieldError(&'static str),
    #[error(display = "Tabasco: Failed to verify {}.", _0)]
    FailedToVerifyError(&'static str),
    #[error(display = "Tabasco: Unknown attestation protocol.")]
    UnknownAttestationTokenError,
    #[error(display = "Tabasco: Unsupported request (not implemented in this platform).")]
    UnimplementedRequestError,
    #[error(display = "Tabasco: Unsupported request (not found).")]
    UnsupportedRequestError,
    #[error(display = "Tabasco: Direct message {}.", _0)]
    DirectMessageError(String, StatusCode),
    #[error(display = "Tabasco: cbor error {}.", _0)]
    CborError(String),
    #[error(display = "Tabasco: Mutex error {}.", _0)]
    MutexError(String),
}

#[cfg(feature = "sgx")]
impl From<sgx_types::sgx_status_t> for TabascoError {
    fn from(error: sgx_types::sgx_status_t) -> Self {
        match error {
            sgx_types::sgx_status_t::SGX_SUCCESS => {
                panic!("Expected an error code but received an success status")
            }
            e => TabascoError::SGXError(e),
        }
    }
}

impl<T> From<std::sync::PoisonError<T>> for TabascoError {
    fn from(error: std::sync::PoisonError<T>) -> Self {
        TabascoError::LockError(format!("{:?}", error))
    }
}

impl error::ResponseError for TabascoError {
    fn error_response(&self) -> HttpResponse {
        ResponseBuilder::new(self.status_code()).body(format!("{:?}", self))
    }
    fn status_code(&self) -> StatusCode {
        match self {
            TabascoError::DirectMessageError(_, e) => e.clone(),
            TabascoError::UnimplementedRequestError
            | TabascoError::UnknownAttestationTokenError => StatusCode::NOT_IMPLEMENTED,
            TabascoError::UnsupportedRequestError => StatusCode::NOT_FOUND,
            _otherwise => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}
