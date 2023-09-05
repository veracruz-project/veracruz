//! Common code for any implementation of WASI
//!
//! This module contains:
//! - An interface for handling memory access.
//! - An interface for executing a program.
//! - A Wasi wrapper which wraps the strictly Wasi-like API in the virtual file
//!   system, and converts Wasm number- and address-based parameters to
//!   properly-typed parameters with Rust-style error handling (and vice versa).
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE.md` file in the Veracruz root directory for
//! information on licensing and copyright.

#![allow(non_camel_case_types, clippy::too_many_arguments)]

use anyhow::Result;
use err_derive::Error;
use serde::{Deserialize, Serialize};
use std::{
    string::String, vec::Vec,
};
use strum_macros::{EnumString, IntoStaticStr};

////////////////////////////////////////////////////////////////////////////////
// Common constants.
////////////////////////////////////////////////////////////////////////////////

/// List of WASI API function names.
/// These can be converted between primitive numbers and enum values via
/// `primitive` derive macros, and between lowercase string and enum values via
/// `strum`.
#[derive(
    IntoStaticStr,
    EnumString,
    Debug,
    PartialEq,
    Clone,
    FromPrimitive,
    ToPrimitive,
    Serialize,
    Deserialize,
    Copy,
)]
#[strum(serialize_all = "lowercase")]
pub enum WasiAPIName {
    ARGS_GET = 1,
    ARGS_SIZES_GET,
    ENVIRON_GET,
    ENVIRON_SIZES_GET,
    CLOCK_RES_GET,
    CLOCK_TIME_GET,
    FD_ADVISE,
    FD_ALLOCATE,
    FD_CLOSE,
    FD_DATASYNC,
    FD_FDSTAT_GET,
    FD_FDSTAT_SET_FLAGS,
    FD_FDSTAT_SET_RIGHTS,
    FD_FILESTAT_GET,
    FD_FILESTAT_SET_SIZE,
    FD_FILESTAT_SET_TIMES,
    FD_PREAD,
    FD_PRESTAT_GET,
    FD_PRESTAT_DIR_NAME,
    FD_PWRITE,
    FD_READ,
    FD_READDIR,
    FD_RENUMBER,
    FD_SEEK,
    FD_SYNC,
    FD_TELL,
    FD_WRITE,
    PATH_CREATE_DIRECTORY,
    PATH_FILESTAT_GET,
    PATH_FILESTAT_SET_TIMES,
    PATH_LINK,
    PATH_OPEN,
    PATH_READLINK,
    PATH_REMOVE_DIRECTORY,
    PATH_RENAME,
    PATH_SYMLINK,
    PATH_UNLINK_FILE,
    POLL_ONEOFF,
    PROC_EXIT,
    PROC_RAISE,
    SCHED_YIELD,
    RANDOM_GET,
    SOCK_RECV,
    SOCK_SEND,
    SOCK_SHUTDOWN,
    #[strum(disabled)]
    _LAST,
}

/// List of Veracruz API function names.
#[derive(
    IntoStaticStr,
    EnumString,
    Debug,
    PartialEq,
    Clone,
    FromPrimitive,
    ToPrimitive,
    Serialize,
    Deserialize,
    Copy,
)]
#[strum(serialize_all = "lowercase")]
pub enum VeracruzAPIName {
    FD_CREATE,
}

////////////////////////////////////////////////////////////////////////////////
// Miscellanea that doesn't fit elsewhere.
////////////////////////////////////////////////////////////////////////////////

////////////////////////////////////////////////////////////////////////////////
// The host runtime state.
////////////////////////////////////////////////////////////////////////////////

/// A wrapper on VFS for WASI, which provides common API used by wasm execution
/// engine.
#[derive(Clone)]
pub struct WasiWrapper {
    ///// The synthetic filesystem associated with this machine.
    /////
    ///// Note: Veracruz runtime should hold the root `FileSystem` handler.
    /////       The `FileSystem` handler here should be a non-root handler spawned
    /////       from the root one.  Both the Veracruz runtime and this
    /////       `WasiWrapper` can update, i.e. mutate, the file system internal
    /////       state, if their local `FileSystem` handlers have the appropriate
    /////       capabilities.
    /////       ---------------------------
    /////           Runtime  |  WasiWrapper
    ///// FileSystem(handler)| FileSystem(handler)
    /////               v    |   v
    /////       ---------------------------
    /////            |  ^        ^  |
    /////            |  Internal    |
    /////            ----------------
    //filesystem: FileSystem,
    ///// The environment variables currently set, and their bindings.
    //environment_variables: Vec<(String, String)>,
    ///// The program arguments of the executable being executed.
    //program_arguments: Vec<String>,
    ///// The exit code returned by the last executing program.
    //exit_code: Option<u32>,
    ///// Whether clock functions (`clock_getres()`, `clock_gettime()`) should be
    ///// enabled.
    //pub(crate) enable_clock: bool,
    ///// Whether strace is enabled.
    //pub(crate) enable_strace: bool,
}


////////////////////////////////////////////////////////////////////////////////
// Fatal execution errors/runtime panics.
////////////////////////////////////////////////////////////////////////////////

/// A fatal, runtime error that terminates the Veracruz execution immediately.
/// This is akin to a "kernel panic" for Veracruz: these errors are not passed
/// to the WASM program running on the platform, but are instead fundamental
/// issues that require immediate shutdown as they cannot be fixed.
///
/// *NOTE*: care should be taken when presenting these errors to users when in
/// release (e.g. not in debug) mode: they can give away a lot of information
/// about what is going on inside the enclave.
#[derive(Debug, Error, Serialize, Deserialize)]
pub enum FatalEngineError {
    /// The WASM module supplied by the program supplier was invalid and could
    /// not be parsed.
    #[error(display = "FatalEngineError: Invalid WASM program (e.g. failed to parse it).")]
    InvalidWASMModule,
    /// The Veracruz engine was passed bad arguments by the WASM program running
    /// on the platform.  This should never happen if the WASM program uses
    /// `libveracruz` as the platform should ensure H-Calls are always
    /// well-formed.  Seeing this either indicates a bug in `libveracruz` or a
    /// programming error in the source that originated the WASM programming if
    /// `libveracruz` was not used.
    #[error(
        display = "FatalEngineError: Bad arguments passed to host function '{:?}'.",
        function_name
    )]
    BadArgumentsToHostFunction {
        /// The name of the host function that was being invoked.
        function_name: WasiAPIName,
    },
    /// The WASM program tried to invoke an unknown H-call on the Veracruz engine.
    #[error(display = "FatalEngineError: Unknown Host call invoked: '{:?}'.", _0)]
    UnknownHostFunction(HostFunctionIndexOrName),
    /// No linear memory was registered: this is a programming error (a bug)
    /// that should be fixed.
    #[error(display = "FatalEngineError: No WASM memory registered.")]
    NoMemoryRegistered,
    /// No program module was registered: this is a programming error (a bug)
    /// that should be fixed.
    #[error(display = "FatalEngineError: No WASM program module registered.")]
    NoProgramModuleRegistered,
    /// The WASM program's entry point was missing or malformed.
    #[error(display = "FatalEngineError: Failed to find the entry point in the WASM program.")]
    NoProgramEntryPoint,
    /// The WASM program's entry point was missing or malformed.
    #[error(display = "FatalEngineError: Execution engine is not ready.")]
    EngineIsNotReady,
    /// Wrapper for direct error message.
    #[error(display = "FatalEngineError: WASM program returns code other than wasi ErrNo.")]
    ReturnedCodeError,
    /// The lock to engine could not be obtained.
    #[error(
        display = "FatalEngineError: Failed to obtain lock on the engine or components of the engine."
    )]
    FailedLockEngine,
    /// The lock to file system could not be obtained.
    #[error(display = "FatalEngineError: Failed to obtain lock on the file system.")]
    FailedLockFileSystem,
    /// Engine trap.
    #[error(display = "FatalEngineError: Wasm engine trap: {:?}", _0)]
    Trap(String),
}

/// Either the index or the name of a host call
#[derive(Debug, Serialize, Deserialize)]
pub enum HostFunctionIndexOrName {
    Index(usize),
    Name(String),
}

////////////////////////////////////////////////////////////////////////////////
// Implementation of the H-calls.
////////////////////////////////////////////////////////////////////////////////

///// Details the arguments expected by the module's entry point, if any is found.
//pub(crate) enum EntrySignature {
    ///// The expected entry point (e.g. "main") is not found in the WASM module
    ///// or it was found and it did not have a recognisable type signature.
    //NoEntryFound,
    ///// The entry point does not expect any parameters.
    //NoParameters,
    ///// The entry point expects a dummy `argv` and an `argc` to be supplied.
    //ArgvAndArgc,
//}

////////////////////////////////////////////////////////////////////////////////
// The strategy trait.
////////////////////////////////////////////////////////////////////////////////

/// This is what an execution strategy exposes to clients outside of this
/// library.  This functionality is sufficient to implement both
/// `freestanding-execution-engine` and `runtime-manager` and if any
/// functionality is missing that these components require then it should be
/// added to this trait and implemented for all supported implementation
/// strategies.
pub trait ExecutionEngine: Send {
    /// Entry point for the execution engine: invokes the `program` binary,
    /// Returns `Ok(c)` if it successfully executed and returned a
    /// success/error code, `c`, or returns `Err(e)` if some fatal execution
    /// engine error occurred at runtime causing the pipeline to abort.
    fn invoke_entry_point(&mut self, program: Vec<u8>) -> Result<u32>;
}
