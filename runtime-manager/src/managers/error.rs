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
use io_utils::error::SocketError;
#[cfg(feature = "nitro")]
use nix;

#[derive(Debug, Error)]
pub enum RuntimeManagerError {
    #[cfg(feature = "linux")]
    #[error(display = "RuntimeManager: CommandLineArguments")]
    CommandLineArguments,
    #[error(display = "RuntimeManager: FileSystem Error: {:?}.", _0)]
    FileSystemError(#[error(source)] wasi_types::ErrNo),
    #[error(display = "RuntimeManager: Uninitialized session in function {}.", _0)]
    UninitializedSessionError(&'static str),
    #[cfg(feature = "linux")]
    #[error(display = "RuntimeManager: {} failed with error code {:?}.", _0, _1)]
    UnsafeCallError(&'static str, u32),
    #[error(display = "RuntimeManager: Unavailable session with ID {}.", _0)]
    UnavailableSessionError(u64),
    #[error(display = "RuntimeManager: Unavailable protocol state.")]
    UninitializedProtocolState,
    #[cfg(feature = "nitro")]
    #[error(display = "RuntimeManager: Socket Error: {:?}", _0)]
    SocketError(nix::Error),
    #[cfg(feature = "nitro")]
    #[error(display = "RuntimeManager: Veracruz Socket error: {:?}", _0)]
    VeracruzSocketError(SocketError),
    #[cfg(feature = "nitro")]
    #[error(display = "RuntimeManager: NSM Lib error: {:?}", _0)]
    NsmLibError(i32),
    #[cfg(feature = "nitro")]
    #[error(display = "RuntimeManager: NSM Error code: {:?}", _0)]
    NsmErrorCode(nsm_api::api::ErrorCode),
    #[error(display = "RuntimeManager: Execution denied.")]
    ExecutionDenied,
    #[error(display = "RuntimeManager: Failed to obtain lock on protocol state.")]
    LockProtocolState,
    #[error(display = "RuntimeManager: Failed to obtain lock on session manager.")]
    LockSessionManager,
    #[error(display = "RuntimeManager: Failed to obtain lock on session table.")]
    LockSessionTable,
    #[error(display = "RuntimeManager: Firmware error")]
    FirmwareError,
}
