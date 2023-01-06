//! Veracruz server
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE_MIT.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

#[cfg(feature = "icecap")]
use crate::platforms::icecap::IceCapError;
use err_derive::Error;
#[cfg(feature = "nitro")]
use io_utils::nitro::NitroError;
use reqwest;

pub type VeracruzServerResponder = Result<String, VeracruzServerError>;

#[derive(Debug, Error)]
pub enum VeracruzServerError {
    #[error(display = "VeracruzServer: SerdeJsonError: {:?}.", _0)]
    SerdeJsonError(#[error(source)] serde_json::Error),
    #[error(display = "VeracruzServer: IOError: {:?}.", _0)]
    IOError(#[error(source)] std::io::Error),
    #[error(display = "VeracruzServer: Base64Error: {:?}.", _0)]
    Base64Error(#[error(source)] base64::DecodeError),
    #[error(display = "VeracruzServer: Failed to obtain lock {:?}.", _0)]
    LockError(String),
    #[error(display = "VeracruzServer: ParseIntError: {}.", _0)]
    ParseIntError(#[error(source)] std::num::ParseIntError),
    #[cfg(any(feature = "linux", feature = "nitro"))]
    #[error(display = "VeracruzServer: BincodeError: {:?}", _0)]
    BincodeError(bincode::ErrorKind),
    #[cfg(any(feature = "nitro", feature = "linux"))]
    #[error(display = "VeracruzServer: Status: {:?}", _0)]
    Status(veracruz_utils::runtime_manager_message::Status),
    #[cfg(any(feature = "linux", feature = "nitro"))]
    #[error(
        display = "VeracruzServer: Received Invalid Runtime Manager response: {:?}",
        _0
    )]
    InvalidRuntimeManagerResponse(veracruz_utils::runtime_manager_message::RuntimeManagerResponse),
    #[cfg(feature = "nitro")]
    #[error(display = "VeracruzServer: Received Invalid Protocol Buffer Message")]
    InvalidProtoBufMessage,
    #[cfg(feature = "nitro")]
    #[error(display = "VeracruzServer: Nix Error: {:?}", _0)]
    NixError(#[error(source)] nix::Error),
    #[cfg(feature = "nitro")]
    #[error(display = "VeracruzServer: Veracruz Socket Error:{:?}", _0)]
    VeracruzSocketError(#[error(source)] io_utils::error::SocketError),
    #[cfg(feature = "nitro")]
    #[error(display = "VeracruzServer: Nitro Error:{:?}", _0)]
    NitroError(#[error(source)] NitroError),
    #[cfg(feature = "icecap")]
    #[error(display = "VeracruzServer: IceCap error: {:?}", _0)]
    IceCapError(#[error(source)] IceCapError),
    #[error(display = "VeracruzServer: TransportProtocolError: {:?}.", _0)]
    TransportProtocolError(#[error(source)] transport_protocol::TransportProtocolError),
    #[error(display = "VeracruzServer: Join Error: {:?}.", _0)]
    JoinError(std::boxed::Box<dyn std::any::Any + Send + 'static>),
    #[error(display = "VeracruzServer: Uninitialized enclave.")]
    UninitializedEnclaveError,
    #[error(display = "VeracruzServer: Invalid request format")]
    InvalidRequestFormatError,
    #[error(display = "VeracruzServer: Unimplemented")]
    UnimplementedError,
    /// Runtime manager did not start up correctly.
    #[error(display = "Runtime manager did not start up correctly")]
    RuntimeManagerFailed,
    /// Return the anyhow.
    #[error(display = "Runtime manager did not start up correctly")]
    Anyhow(anyhow::Error),
    #[error(display = "VeracruzServer: Reqwest Error: {:?}", _0)]
    ReqwestError(reqwest::Error),
}

impl<T> From<std::sync::PoisonError<T>> for VeracruzServerError {
    fn from(error: std::sync::PoisonError<T>) -> Self {
        VeracruzServerError::LockError(format!("{:?}", error))
    }
}

impl From<anyhow::Error> for VeracruzServerError {
    fn from(error: anyhow::Error) -> Self {
        VeracruzServerError::Anyhow(error)
    }
}

#[cfg(feature = "nitro")]
impl From<std::boxed::Box<bincode::ErrorKind>> for VeracruzServerError {
    fn from(error: std::boxed::Box<bincode::ErrorKind>) -> Self {
        VeracruzServerError::BincodeError(*error)
    }
}

pub type VeracruzServerResult<T> = Result<T, VeracruzServerError>;

// Import and reexport the platform-specific enclave types.
#[cfg(feature = "icecap")]
pub use crate::platforms::icecap::{VeracruzServer, VeracruzSession};
#[cfg(feature = "linux")]
pub use crate::platforms::linux::{VeracruzServer, VeracruzSession};
#[cfg(feature = "nitro")]
pub use crate::platforms::nitro::{VeracruzServer, VeracruzSession};
