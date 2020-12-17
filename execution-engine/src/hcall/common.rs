//! Common code for any implementation of WASI.
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
use serde::{Deserialize, Serialize};
use wasi_types::{ErrNo, Fd, FileSize, Advice, FdStat, FdFlags, Rights, FileStat, Timestamp, Size, Prestat, IoVec, DirCookie, FileDelta, Whence, LookupFlags, OpenFlags};
use veracruz_util::policy::principal::{Principal, FileOperation};
use std::{
    borrow::Borrow,
    cmp::Ord,
    collections::{HashMap,HashSet},
    convert::TryFrom,
    fmt::{Display, Error, Formatter},
    path::{Path, PathBuf},
    string::{String, ToString},
    fmt::{Formatter, Display, Error},
    string::{String, ToString},
};
use crate::hcall::buffer::VFSError;
#[cfg(any(feature = "std", feature = "tz", feature = "nitro"))]
use std::sync::Mutex;
#[cfg(feature = "sgx")]
use std::sync::SgxMutex as Mutex;
use super::{fs::FileSystem, fs::FileSystemError};

////////////////////////////////////////////////////////////////////////////////
// Common constants.
////////////////////////////////////////////////////////////////////////////////

/// The directory in the synthetic filesystem where all inputs will be stored.
pub(crate) const INPUT_DIRECTORY: &str = "/vcrz/in/";
/// The directory in the synthetic filesystem where the WASM program will write
/// its outputs.
pub(crate) const OUTPUT_DIRECTORY: &str = "/vcrz/out";
/// The directory, under `INPUT_DIRECTORY`, in the synthetic filesystem where
/// block-oriented inputs will be stored and can be read by the WASM program.
pub(crate) const BLOCK_INPUT_DIRECTORY_NAME: &str = "block";
/// The directory, under `INPUT_DIRECTORY`, in the synthetic filesystem where
/// stream-oriented inputs will be stored and can be read by the WASM program.
pub(crate) const STREAM_INPUT_DIRECTORY_NAME: &str = "stream";

/// Name of the WASI `args_get` function.
pub(crate) const WASI_ARGS_GET_NAME: &str = "args_get";
/// Name of the WASI `args_get` function.
pub(crate) const WASI_ARGS_SIZES_GET_NAME: &str = "args_sizes_get";
/// Name of the WASI `environ_get` function.
pub(crate) const WASI_ENVIRON_GET_NAME: &str = "environ_get";
/// Name of the WASI `environ_sizes_get` function.
pub(crate) const WASI_ENVIRON_SIZES_GET_NAME: &str = "environ_sizes_get";
/// Name of the WASI `clock_res_get` function.
pub(crate) const WASI_CLOCK_RES_GET_NAME: &str = "clock_res_get";
/// Name of the WASI `clock_time_get` function.
pub(crate) const WASI_CLOCK_TIME_GET_NAME: &str = "clock_time_get";
/// Name of the WASI `fd_advise` function.
pub(crate) const WASI_FD_ADVISE_NAME: &str = "fd_advise";
/// Name of the WASI `fd_allocate` function.
pub(crate) const WASI_FD_ALLOCATE_NAME: &str = "fd_allocate";
/// Name of the WASI `fd_close` function.
pub(crate) const WASI_FD_CLOSE_NAME: &str = "fd_close";
/// Name of the WASI `fd_datasync` function.
pub(crate) const WASI_FD_DATASYNC_NAME: &str = "fd_datasync";
/// Name of the WASI `fd_fdstat_get` function.
pub(crate) const WASI_FD_FDSTAT_GET_NAME: &str = "fd_fdstat_get";
/// Name of the WASI `fd_filestat_set_flags` function.
pub(crate) const WASI_FD_FDSTAT_SET_FLAGS_NAME: &str = "fd_fdstat_set_flags";
/// Name of the WASI `fd_filestat_set_rights` function.
pub(crate) const WASI_FD_FDSTAT_SET_RIGHTS_NAME: &str = "fd_fdstat_set_rights";
/// Name of the WASI `fd_filestat_get` function.
pub(crate) const WASI_FD_FILESTAT_GET_NAME: &str = "fd_filestat_get";
/// Name of the WASI `fd_filestat_set_size` function.
pub(crate) const WASI_FD_FILESTAT_SET_SIZE_NAME: &str = "fd_filestat_set_size";
/// Name of the WASI `fd_filestat_set_times` function.
pub(crate) const WASI_FD_FILESTAT_SET_TIMES_NAME: &str = "fd_filestat_set_times";
/// Name of the WASI `fd_pread` function.
pub(crate) const WASI_FD_PREAD_NAME: &str = "fd_pread";
/// Name of the WASI `fd_prestat_get_name` function.
pub(crate) const WASI_FD_PRESTAT_GET_NAME: &str = "fd_prestat_get";
/// Name of the WASI `fd_prestat_dir_name` function.
pub(crate) const WASI_FD_PRESTAT_DIR_NAME_NAME: &str = "fd_prestat_dir_name";
/// Name of the WASI `fd_pwrite` function.
pub(crate) const WASI_FD_PWRITE_NAME: &str = "fd_pwrite";
/// Name of the WASI `fd_read` function.
pub(crate) const WASI_FD_READ_NAME: &str = "fd_read";
/// Name of the WASI `fd_readdir` function.
pub(crate) const WASI_FD_READDIR_NAME: &str = "fd_readdir";
/// Name of the WASI `fd_renumber` function.
pub(crate) const WASI_FD_RENUMBER_NAME: &str = "fd_renumber";
/// Name of the WASI `fd_seek` function.
pub(crate) const WASI_FD_SEEK_NAME: &str = "fd_seek";
/// Name of the WASI `fd_sync` function.
pub(crate) const WASI_FD_SYNC_NAME: &str = "fd_sync";
/// Name of the WASI `fd_tell` function.
pub(crate) const WASI_FD_TELL_NAME: &str = "fd_tell";
/// Name of the WASI `fd_write` function.
pub(crate) const WASI_FD_WRITE_NAME: &str = "fd_write";
/// Name of the WASI `path_crate_directory` function.
pub(crate) const WASI_PATH_CREATE_DIRECTORY_NAME: &str = "path_create_directory";
/// Name of the WASI `path_filestat_get` function.
pub(crate) const WASI_PATH_FILESTAT_GET_NAME: &str = "path_filestat_get";
/// Name of the WASI `path_filestat_set_times` function.
pub(crate) const WASI_PATH_FILESTAT_SET_TIMES_NAME: &str = "path_filestat_set_times";
/// Name of the WASI `path_link` function.
pub(crate) const WASI_PATH_LINK_NAME: &str = "path_link";
/// Name of the WASI `path_open` function.
pub(crate) const WASI_PATH_OPEN_NAME: &str = "path_open";
/// Name of the WASI `path_readlink` function.
pub(crate) const WASI_PATH_READLINK_NAME: &str = "path_readlink";
/// Name of the WASI `path_remove_directory` function.
pub(crate) const WASI_PATH_REMOVE_DIRECTORY_NAME: &str = "path_remove_directory";
/// Name of the WASI `path_rename` function.
pub(crate) const WASI_PATH_RENAME_NAME: &str = "path_rename";
/// Name of the WASI `path_symlink` function.
pub(crate) const WASI_PATH_SYMLINK_NAME: &str = "path_symlink";
/// Name of the WASI `path_unlink_file` function.
pub(crate) const WASI_PATH_UNLINK_FILE_NAME: &str = "path_unlink_file";
/// Name of the WASI `poll_oneoff` function.
pub(crate) const WASI_POLL_ONEOFF_NAME: &str = "poll_oneoff";
/// Name of the WASI `proc_exit` function.
pub(crate) const WASI_PROC_EXIT_NAME: &str = "proc_exit";
/// Name of the WASI `proc_raise` function.
pub(crate) const WASI_PROC_RAISE_NAME: &str = "proc_raise";
/// Name of the WASI `sched_yield` function.
pub(crate) const WASI_SCHED_YIELD_NAME: &str = "sched_yield";
/// Name of the WASI `random_get` function.
pub(crate) const WASI_RANDOM_GET_NAME: &str = "random_get";
/// Name of the WASI `sock_recv` function.
pub(crate) const WASI_SOCK_RECV_NAME: &str = "sock_recv";
/// Name of the WASI `sock_send` function.
pub(crate) const WASI_SOCK_SEND_NAME: &str = "sock_send";
/// Name of the WASI `sock_shutdown` function.
pub(crate) const WASI_SOCK_SHUTDOWN_NAME: &str = "sock_shutdown";

////////////////////////////////////////////////////////////////////////////////
// Miscellanea that doesn't fit elsewhere.
////////////////////////////////////////////////////////////////////////////////

/// Computes a SHA-256 digest of the bytes passed to it in `buffer`.
pub(crate) fn sha_256_digest(buffer: &[u8]) -> Vec<u8> {
    ring::digest::digest(&ring::digest::SHA256, buffer)
        .as_ref()
        .to_vec()
}

////////////////////////////////////////////////////////////////////////////////
// The machine lifecycle state.
////////////////////////////////////////////////////////////////////////////////

/// The lifecycle state of the Veracruz host.
#[derive(Clone, Eq, PartialEq, Debug)]
pub enum LifecycleState {
    /// The initial state: nothing yet has been provisioned into the Veracruz
    /// machine.  The state is essentially "pristine", having just been created.
    Initial,
    /// The program has been provisioned into the machine, and now the data
    /// sources are in the process of being provisioned.  Not all data sources
    /// are yet provisioned, per the global policy.
    DataSourcesLoading,
    /// The program and (initial) data have been provisioned into the machine,
    /// and now the stream sources are in the process of being provisioned.
    /// Not all stream sources are yet provisioned, per the global policy.
    StreamSourcesLoading,
    /// All data sources (and the program) have now been provisioned according
    /// to the global policy.  The machine is now ready to execute.
    ReadyToExecute,
    /// The machine has executed, and finished successfully.  The result of the
    /// machine's execution can now be extracted.
    FinishedExecuting,
    /// An error occurred during the provisioning or machine execution process.
    Error,
}

////////////////////////////////////////////////////////////////////////////////
// Provisioning errors.
////////////////////////////////////////////////////////////////////////////////

/// Errors that can occur during host provisioning.  These are errors that may
/// be reported back to principals in the Veracruz computation over the Veracruz
/// wire protocols, for example if somebody tries to provision data when that is
/// not expected, or similar.  Some may be recoverable errors, some may be fatal
/// errors due to programming bugs.
#[derive(Debug, Error, Serialize, Deserialize)]
pub enum HostProvisioningError {
    /// The host state was in an unexpected, or invalid, lifecycle state and
    /// there is a mismatch between actual provisioning state and what was
    /// expected.
    #[error(
        display = "ProvisioningError: Invalid host state, found {:?}, expected {:?}.",
        found,
        expected
    )]
    InvalidLifeCycleState {
        found: LifecycleState,
        expected: Vec<LifecycleState>,
    },
    /// The WASM module supplied by the program supplier was invalid and could
    /// not be parsed.
    #[error(display = "ProvisioningError: Invalid WASM program (e.g. failed to parse it).")]
    InvalidWASMModule,
    /// No linear memory/heap could be identified in the WASM module.
    #[error(
        display = "ProvisioningError: No linear memory could be found in the supplied WASM module."
    )]
    NoLinearMemoryFound,
    /// No wasm memory registered in the execution engine
    #[error(display = "HostProvisioningError: No WASM memory registered.")]
    NoMemoryRegistered,
    /// The program module could not be properly instantiated by the WASM engine
    /// for some reason.
    #[error(display = "ProvisioningError: Failed to instantiate the WASM module.")]
    ModuleInstantiationFailure,
    /// A lock could not be obtained for some reason.
    #[error(display = "ProvisioningError: Failed to obtain lock {:?}.", _0)]
    FailedToObtainLock(String),
    #[error(display = "HostProvisioningError: Wasmi Error: {}.", _0)]
    WasmiError(String),
    /// The host provisioning state has not been initialized.  This should never
    /// happen and is a bug.
    #[error(
        display = "ProvisioningError: Uninitialized host provisioning state (this is a potential bug)."
    )]
    HostProvisioningStateNotInitialized,
    /// The runtime was trying to register two inputs at the same path in the
    /// synthetic filesystem.
    #[error(
        display = "ProvisioningError: The global policy ascribes two inputs the same filename {}.",
        _0
    )]
    CannotSortDataOrStream,
    #[error(display = "HostProvisioningError: VFS Error {}.", _0)]
    VFSError(#[error(source)] crate::hcall::buffer::VFSError),
    #[error(display = "HostProvisioningError: File {} cannot be found.", _0)]
    FileNotFound(String),
    #[error(
        display = "HostProvisioningError: Principal or program {:?} cannot be found.",_0
    )]
    PrincipalNotFound(Principal),
    #[error(
        display = "HostProvisioningError: Client {:?} is disallowed to {:?}.",client_id,operation
    )]
    CapabilityDenial {
        client_id: Principal,
        operation : FileOperation,
    },
    #[error(
        display = "ProvisioningError: The global policy ascribes two inputs the same filename {}.",
        _0
    )]
    InputNameClash(String),
}

// Convertion from any error raised by any mutex of type <T> to HostProvisioningError.
impl<T> From<std::sync::PoisonError<T>> for HostProvisioningError {
    fn from(error: std::sync::PoisonError<T>) -> Self {
        HostProvisioningError::FailedToObtainLock(format!("{:?}", error))
    }
}

impl From<wasmi::Error> for HostProvisioningError {
    fn from(error: wasmi::Error) -> Self {
        HostProvisioningError::WasmiError(format!("{:?}", error))
    }
}

////////////////////////////////////////////////////////////////////////////////
// Fatal host errors
////////////////////////////////////////////////////////////////////////////////

/// A fatal, runtime error that terminates the Veracruz host immediately.  This
/// is akin to a "kernel panic" for Veracruz: these errors are not passed to the
/// WASM program running on the platform, but are instead fundamental issues
/// that require immediate shutdown as they cannot be fixed.
///
/// *NOTE*: care should be taken when presenting these errors to users when in
/// release (e.g. not in debug) mode: they can give away a lot of information
/// about what is going on inside the enclave.
#[derive(Debug, Error, Serialize, Deserialize)]
pub enum FatalEngineError {
    /// The WASM program called `proc_exit`, or similar, to signal an early exit
    /// from the program, returning a specific error code.
    #[error(
        display = "RuntimePanic: Early exit requested by program, error code returned: '{}'.",
        _0
    )]
    EarlyExit(i32),
    /// The Veracruz host was passed bad arguments by the WASM program running
    /// on the platform.  This should never happen if the WASM program uses
    /// `libveracruz` as the platform should ensure H-Calls are always
    /// well-formed.  Seeing this either indicates a bug in `libveracruz` or a
    /// programming error in the source that originated the WASM programming if
    /// `libveracruz` was not used.
    #[error(
        display = "RuntimePanic: Bad arguments passed to host function '{}'.",
        function_name
    )]
    BadArgumentsToHostFunction {
        //NOTE: use `String` instead of `&'static str` to make serde happy.
        /// The name of the host function that was being invoked.
        function_name: String,
    },
    /// The WASM program tried to invoke an unknown H-call on the Veracruz host.
    #[error(display = "RuntimePanic: Unknown H-call invoked: '{}'.", index)]
    UnknownHostFunction {
        /// The host call index of the unknown function that was invoked.
        index: usize,
    },
    /// The host failed to read a range of bytes, starting at a base address,
    /// from the running WASM program's linear memory.
    #[error(
        display = "RuntimePanic: Failed to read {} byte(s) from WASM memory at address {}.",
        bytes_to_be_read,
        memory_address
    )]
    MemoryReadFailed {
        /// The base memory address that was being read.
        memory_address: usize,
        /// The number of bytes that were being read.
        bytes_to_be_read: usize,
    },
    /// The host failed to write a range of bytes, starting from a base address,
    /// to the running WASM program's linear memory.
    #[error(
        display = "RuntimePanic: Failed to write {} byte(s) to WASM memory at address {}.",
        bytes_to_be_written,
        memory_address
    )]
    MemoryWriteFailed {
        /// The base memory address that was being written.
        memory_address: usize,
        /// The number of bytes that were being written.
        bytes_to_be_written: usize,
    },
    /// No linear memory was registered: this is a programming error (a bug)
    /// that should be fixed.
    #[error(display = "RuntimePanic: No WASM memory registered.")]
    NoMemoryRegistered,
    /// No program module was registered: this is a programming error (a bug)
    /// that should be fixed.
    #[error(display = "RuntimePanic: No WASM program module registered.")]
    NoProgramModuleRegistered,
    /// The WASM program's entry point was missing or malformed.
    #[error(display = "RuntimePanic: Failed to find the entry point in the WASM program.")]
    NoProgramEntryPoint,
    /// The WASM program's entry point was missing or malformed.
    #[error(display = "RuntimePanic: Execution engine is not ready.")]
    EngineIsNotReady,
    /// Wrapper for direct error message.
    #[error(display = "RuntimePanic: WASM program returns code other than i32.")]
    ReturnedCodeError,
    /// Wrapper for WASI Trap.
    #[error(display = "RuntimePanic: WASMIError: Trap: {:?}.", _0)]
    WASMITrapError(#[source(error)] wasmi::Trap),
    /// Wrapper for WASI Error other than Trap.
    #[error(display = "RuntimePanic: WASMIError {:?}.", _0)]
    WASMIError(#[source(error)] wasmi::Error),
    /// Program cannot be found in VFS, when any principal (programs or participants) try to access
    /// the `file_name`.
    #[error(
        display = "FatalVeracruzHostError: Program {} cannot be found.",
        file_name
    )]
    ProgramCannotFound { file_name: String },
    /// Wrapper for Virtual FS Error.
    #[error(display = "FatalVeracruzHostError: VFS Error: {:?}.", _0)]
    VFSError(#[error(source)] crate::hcall::buffer::VFSError),
    /// Wrapper for direct error message.
    #[error(display = "RuntimePanic: Error message {:?}.", _0)]
    DirectErrorMessage(String),
    #[error(display = "FatalVeracruzHostError: provisioning error {:?}.", _0)]
    ProvisionError(#[error(source)] HostProvisioningError),
    /// Something unknown or unexpected went wrong, and there's no more detailed
    /// information.
    #[error(display = "RuntimePanic: Unknown error.")]
    Generic,
}

impl From<String> for FatalEngineError {
    fn from(err: String) -> Self {
        FatalEngineError::DirectErrorMessage(err)
    }
}

impl From<&str> for FatalEngineError {
    fn from(err: &str) -> Self {
        FatalEngineError::DirectErrorMessage(err.to_string())
    }
}

////////////////////////////////////////////////////////////////////////////////
// Implementation of the H-calls.
////////////////////////////////////////////////////////////////////////////////

/// The return type for H-Call implementations.
///
/// From *the viewpoint of the host* a H-call can either fail spectacularly
/// with a runtime trap, in which case `Err(err)` is returned, with `err`
/// detailing what went wrong, and the Veracruz host thereafter terminating
/// or otherwise entering an error state, or succeeds with `Ok(())`.
///
/// From *the viewpoint of the WASM program* a H-call can either fail
/// spectacularly, as above, in which case WASM program execution is aborted
/// with the WASM program itself not being able to do anything about this,
/// succeeds with the desired effect and a success error code returned, or
/// fails with a recoverable error in which case the error code details what
/// went wrong and what can be done to fix it.
pub(crate) type WASIError = Result<ErrNo, RuntimePanic>;

/// Details the arguments expected by the module's entry point, if any is found.
pub(crate) enum EntrySignature {
    /// The expected entry point (e.g. "main") is not found in the WASM module
    /// or it was found and it did not have a recognisable type signature.
    NoEntryFound,
    /// The entry point does not expect any parameters.
    NoParameters,
    /// The entry point expects a dummy `argv` and an `argc` to be supplied.
    ArgvAndArgc,
}

////////////////////////////////////////////////////////////////////////////////
// The strategy trait.
////////////////////////////////////////////////////////////////////////////////

/// This is what an execution strategy exposes to clients outside of this
/// library.  This functionality is sufficient to implement both
/// `freestanding-execution-engine` and `runtime-manager` and if any functionality is
/// missing that these components require then it should be added to this trait
/// and implemented for all supported implementation strategies.
///
/// Note that a factory method, in the file `hcall/factory.rs` will return an
/// opaque instance of this trait depending on the
pub trait ExecutionEngine: Send {
    /// Invokes the entry point of the WASM program `file_name`.  Will fail if
    /// the WASM program fails at runtime.  On success, returns the succ/error code
    /// returned by the WASM program entry point as an `i32` value.
    fn invoke_entry_point(&mut self, file_name: &str)
        -> Result<EngineReturnCode, FatalEngineError>;
}

////////////////////////////////////////////////////////////////////////////////
// H-call return codes.
////////////////////////////////////////////////////////////////////////////////

/// These are return codes that the host passes back to the Veracruz WASM program
/// when something goes wrong with a host-call.  Any error is assumed to be
/// recoverable by the WASM program, if it cares to, and are distinct from execution engine
/// errors which are akin to kernel panics and are always fatal.
///
/// Note that both the host and any Veracruz program need to agree on how these
/// errors are encoded.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EngineReturnCode {
    /// The H-call completed successfully.
    Success,
    /// Generic failure: no more-specific information about the cause of the
    /// error can be given.
    Generic,
    /// The H-call failed because an index was passed that exceeded the number
    /// of data sources.
    DataSourceCount,
    /// The H-call failed because it was passed a buffer whose size did not
    /// match the size of the data source.
    DataSourceSize,
    /// The H-call failed because it was passed bad inputs.
    BadInput,
    /// The H-call failed because an index was passed that exceeded the number
    /// of stream sources.
    StreamSourceCount,
    /// The H-call failed because it was passed a buffer whose size did not
    /// match the size of the stream source.
    StreamSourceSize,
    /// The H-call failed because it was passed bad streams.
    BadStream,
    /// The H-call failed because it was passed a buffer whose size did not
    /// match the size of the previous result.
    PreviousResultSize,
    /// An internal invariant was violated (i.e. we are morally "panicking").
    InvariantFailed,
    /// The H-call failed because a result had already previously been written.
    ResultAlreadyWritten,
    /// The H-call failed because the platform service backing it is not
    /// available on this platform.
    ServiceUnavailable,
}

////////////////////////////////////////////////////////////////////////////////
// Trait implementations.
////////////////////////////////////////////////////////////////////////////////

/// Pretty printing for `EngineReturnCode`.
impl Display for EngineReturnCode {
    fn fmt(&self, f: &mut Formatter) -> Result<(), Error> {
        match self {
            EngineReturnCode::Success => write!(f, "Success"),
            EngineReturnCode::Generic => write!(f, "Generic"),
            EngineReturnCode::DataSourceSize => write!(f, "DataSourceSize"),
            EngineReturnCode::DataSourceCount => write!(f, "DataSourceCount"),
            EngineReturnCode::BadInput => write!(f, "BadInput"),
            EngineReturnCode::InvariantFailed => write!(f, "InvariantFailed"),
            EngineReturnCode::ResultAlreadyWritten => write!(f, "ResultAlreadyWritten"),
            EngineReturnCode::ServiceUnavailable => write!(f, "ServiceUnavailable"),
            EngineReturnCode::StreamSourceSize => write!(f, "StreamSourceSize"),
            EngineReturnCode::StreamSourceCount => write!(f, "StreamSourceCount"),
            EngineReturnCode::BadStream => write!(f, "BadStream"),
            EngineReturnCode::PreviousResultSize => write!(f, "PreviousResultSize"),
        }
    }
}

/// Serializes a `EngineReturnCode` to an `i32` value.
///
/// The Veracruz host passes error codes back to the WASM value encoded as an
/// `i32` value.  These are deserialized by the WASM program.
impl From<EngineReturnCode> for i32 {
    fn from(error: EngineReturnCode) -> i32 {
        match error {
            EngineReturnCode::Success => 0,
            EngineReturnCode::Generic => -1,
            EngineReturnCode::DataSourceCount => -2,
            EngineReturnCode::DataSourceSize => -3,
            EngineReturnCode::BadInput => -4,
            EngineReturnCode::InvariantFailed => -5,
            EngineReturnCode::ResultAlreadyWritten => -6,
            EngineReturnCode::ServiceUnavailable => -7,
            EngineReturnCode::StreamSourceCount => -8,
            EngineReturnCode::StreamSourceSize => -9,
            EngineReturnCode::BadStream => -10,
            EngineReturnCode::PreviousResultSize => -11,
        }
    }
}

/// Deserializes a `EngineReturnCode` from an `i32` value.
impl TryFrom<i32> for EngineReturnCode {
    type Error = FatalEngineError;

    fn try_from(i: i32) -> Result<Self, Self::Error> {
        match i {
            0 => Ok(EngineReturnCode::Success),
            -1 => Ok(EngineReturnCode::Generic),
            -2 => Ok(EngineReturnCode::DataSourceCount),
            -3 => Ok(EngineReturnCode::DataSourceSize),
            -4 => Ok(EngineReturnCode::BadInput),
            -5 => Ok(EngineReturnCode::InvariantFailed),
            -6 => Ok(EngineReturnCode::ResultAlreadyWritten),
            -7 => Ok(EngineReturnCode::ServiceUnavailable),
            -8 => Ok(EngineReturnCode::StreamSourceCount),
            -9 => Ok(EngineReturnCode::StreamSourceSize),
            -10 => Ok(EngineReturnCode::BadStream),
            -11 => Ok(EngineReturnCode::PreviousResultSize),
            _otherwise => Err(FatalEngineError::ReturnedCodeError),
        }
    }
}

/// Pretty printing for `LifecycleState`.
impl Display for LifecycleState {
    fn fmt(&self, f: &mut Formatter) -> Result<(), Error> {
        match self {
            LifecycleState::Initial => write!(f, "Initial"),
            LifecycleState::DataSourcesLoading => write!(f, "DataSourcesLoading"),
            LifecycleState::StreamSourcesLoading => write!(f, "StreamSourcesLoading"),
            LifecycleState::ReadyToExecute => write!(f, "ReadyToExecute"),
            LifecycleState::FinishedExecuting => write!(f, "FinishedExecuting"),
            LifecycleState::Error => write!(f, "Error"),
        }
    }
}

// Conversion from any error raised by any `Mutex<T>` to `ProvisioningError`.
impl<T> From<std::sync::PoisonError<T>> for ProvisioningError {
    fn from(error: std::sync::PoisonError<T>) -> Self {
        ProvisioningError::FailedToObtainLock(format!("{:?}", error))
    }
}

/// Lifting string error messages into `RuntimePanic`.
impl From<String> for RuntimePanic {
    fn from(err: String) -> Self {
        RuntimePanic::DirectErrorMessage(err)
    }
}

/// Lifting string error messages into `RuntimePanic`.
impl From<&str> for RuntimePanic {
    fn from(err: &str) -> Self {
        RuntimePanic::DirectErrorMessage(err.to_string())
    }
}
