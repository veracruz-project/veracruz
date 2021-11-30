//! Runtime Manager errors
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
#[cfg(feature = "nitro")]
use nix;
#[cfg(feature = "linux")]
use std::io::Error as IOError;
#[cfg(any(feature = "linux", feature = "nitro", feature = "icecap"))]
use std::sync::PoisonError;

use veracruz_utils::csr::CertError;

#[cfg(feature = "nitro")]
use io_utils::error::SocketError;
#[cfg(feature = "nitro")]
use veracruz_utils::platform::nitro::nitro::NitroRootEnclaveMessage;

#[derive(Debug, Error)]
pub enum RuntimeManagerError {
    #[cfg(feature = "linux")]
    #[error(display = "RuntimeManager: CommandLineArguments")]
    CommandLineArguments,
    #[error(display = "RuntimeManager: SessionManagerError: {:?}.", _0)]
    SessionManagerError(#[error(source)] session_manager::SessionManagerError),
    #[error(display = "RuntimeManager: TransportProtocolError: {:?}.", _0)]
    TransportProtocolError(#[error(source)] transport_protocol::TransportProtocolError),
    #[error(display = "RuntimeManager: VeracruzUtilError: {:?}.", _0)]
    VeracruzUtilError(#[error(source)] policy_utils::error::PolicyError),
    #[error(display = "RuntimeManager: FatalEngineError: {:?}.", _0)]
    FatalHostError(#[error(source)] execution_engine::FatalEngineError),
    #[error(display = "RuntimeManager: FileSystem Error: {:?}.", _0)]
    FileSystemError(#[error(source)] wasi_types::ErrNo),
    #[error(display = "RuntimeManager: Failed to obtain lock {:?}.", _0)]
    LockError(std::string::String),
    #[error(display = "RuntimeManager: Uninitialized session in function {}.", _0)]
    UninitializedSessionError(&'static str),
    #[error(display = "RuntimeManager: ParseIntError: {:?}", _0)]
    ParseIntError(#[error(source)] core::num::ParseIntError),
    #[error(display = "RuntimeManager: {} failed with error code {:?}.", _0, _1)]
    UnsafeCallError(&'static str, u32),
    #[error(display = "RuntimeManager: Received no data.")]
    NoDataError,
    #[error(
        display = "RuntimeManager: Global policy requested an execution strategy unavailable on this platform."
    )]
    InvalidExecutionStrategyError,
    #[error(display = "RuntimeManager: Unavailable session with ID {}.", _0)]
    UnavailableSessionError(u64),
    #[error(display = "RuntimeManager: Unavailable protocol state.")]
    UninitializedProtocolState,
    #[error(display = "RuntimeManager: Unavailable income buffer with ID {}.", _0)]
    UnavailableIncomeBufferError(u64),
    #[cfg(feature = "nitro")]
    #[error(display = "RuntimeManager: Socket Error: {:?}", _0)]
    SocketError(nix::Error),
    #[cfg(feature = "nitro")]
    #[error(display = "RuntimeManager: Veracruz Socket error: {:?}", _0)]
    VeracruzSocketError(SocketError),
    #[cfg(any(feature = "linux", feature = "nitro", feature = "icecap"))]
    #[error(display = "RuntimeManager: Bincode error: {:?}", _0)]
    BincodeError(bincode::Error),
    #[cfg(feature = "nitro")]
    #[error(display = "RuntimeManager: NSM Lib error: {:?}", _0)]
    NsmLibError(i32),
    #[cfg(feature = "nitro")]
    #[error(display = "RuntimeManager: NSM Error code: {:?}", _0)]
    NsmErrorCode(nsm_io::ErrorCode),
    #[cfg(feature = "nitro")]
    #[error(display = "RuntimeManager: wrong message type received: {:?}", _0)]
    WrongMessageTypeError(NitroRootEnclaveMessage),
    #[error(
        display = "RuntimeManager: Data wrong size for field {:?}. Wanted:{:?}, got:{:?}",
        _0,
        _1,
        _2
    )]
    DataWrongSizeForField(std::string::String, usize, usize),
    #[error(display = "RuntimeManager: RingKeyRejected error:{:?}", _0)]
    RingKeyRejected(ring::error::KeyRejected),
    #[error(display = "RuntimeManager: Certificate error:{:?}", _0)]
    CertError(CertError),
    #[cfg(feature = "linux")]
    #[error(display = "RuntimeManager: IO error: {:?}", _0)]
    IOError(IOError),
}

impl<T> From<PoisonError<T>> for RuntimeManagerError {
    fn from(error: PoisonError<T>) -> Self {
        RuntimeManagerError::LockError(format!("{:?}", error))
    }
}
