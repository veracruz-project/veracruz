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

use std::{
    borrow::Borrow,
    cmp::Ord,
    collections::HashMap,
    convert::TryFrom,
    fmt::{Display, Error, Formatter},
    path::Path,
    string::{String, ToString},
    vec::Vec,
};

use super::_types::ErrNo;

////////////////////////////////////////////////////////////////////////////////
// Common types and utility functions that don't fit elsewhere.
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
// Metadata for data sources.
////////////////////////////////////////////////////////////////////////////////

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
#[derive(Debug, Error)]
pub enum ProvisioningError {
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
    /// The program module could not be properly instantiated by the WASM engine
    /// for some reason.
    #[error(display = "ProvisioningError: Failed to instantiate the WASM module.")]
    ModuleInstantiationFailure,
    /// A lock could not be obtained for some reason.
    #[error(display = "ProvisioningError: Failed to obtain lock {:?}.", _0)]
    FailedToObtainLock(String),
    /// The host provisioning state has not been initialized.  This should never
    /// happen and is a bug.
    #[error(
    display = "ProvisioningError: Uninitialized host provisioning state (this is a potential bug)."
    )]
    HostProvisioningStateNotInitialized,
}

////////////////////////////////////////////////////////////////////////////////
// The host runtime state.
////////////////////////////////////////////////////////////////////////////////

/// The state of the Veracruz machine, which captures metadata as the Veracruz
/// state is gradually "provisioned" by the data and program providers.  Also
/// contains enough data to properly implement the subset of WASI that we have
/// adopted as our ABI.
#[derive(Clone)]
pub struct RuntimeState<Module, Memory> {
    /// The data sources that have been provisioned into the machine.
    filesystem: HashMap<FileName, DataNode>,
    /// The expected number of data sources, derived from the global policy
    /// parameterising the computation.  This is included as a sanity check.  By
    /// the time the program is ready to execute, the filesystem should contain
    /// `expected_data_source_count` + `expected_stream_source_count` entries.
    expected_data_source_count: usize,
    /// The expected number of stream sources, derived from the global policy
    /// parameterising the computation.  This is included as a sanity check.  By
    /// the time the program is ready to execute, the filesystem should contain
    /// `expected_stream_source_count` + `expected_data_source_count` entries.
    expected_stream_source_count: usize,
    /// The number of data sources that have currently been registered with the
    /// state.  Again, this is really only a sanity-checking mechanism.
    registered_data_source_count: usize,
    /// The number of stream sources that have currently been registered with
    /// the state.  Again, this is really only a sanity-checking mechanism.
    registered_stream_source_count: usize,
    /// The current lifecycle state of the machine.
    lifecycle_state: LifecycleState,
    /// A reference to the WASM program module that will actually execute on
    /// the input data sources.
    program_module: Option<Module>,
    /// The SHA-256 digest of the bytes of the loaded program, if any.
    program_digest: Option<Vec<u8>>,
    /// A reference to the WASM program's linear memory (or "heap").
    memory: Option<Memory>,
    /// The filename where the program will write the result.  This is specified
    /// in the global policy.  A value of `None` indicates that the program is
    /// not expected to produce a result.
    result_filename: Option<String>,
    /// The list of clients (their IDs) that can request shutdown of the
    /// Veracruz platform.
    expected_shutdown_sources: Vec<u64>,
}

impl<Module, Memory> RuntimeState<Module, Memory> {
    ////////////////////////////////////////////////////////////////////////////
    // Creating and modifying runtime states.
    ////////////////////////////////////////////////////////////////////////////

    /// Creates a new `RuntimeState` with an empty filesystem and no memory or
    /// program module registered.
    #[inline]
    pub fn new() -> Self {
        Self {
            filesystem: HashMap::new(),
            expected_data_source_count: 0usize,
            expected_stream_source_count: 0usize,
            registered_data_source_count: 0usize,
            registered_stream_source_count: 0usize,
            lifecycle_state: LifecycleState::Initial,
            program_module: None,
            program_digest: None,
            memory: None,
            result_filename: None,
            expected_shutdown_sources: Vec::new()
        }
    }

    /// Sets the runtime state's limit on the number of expected data sources
    /// that are to be pre-provisioned into the runtime state's filesystem.
    #[inline]
    fn set_expected_data_source_count(&mut self, sources: usize) -> &mut Self {
        self.expected_data_source_count = sources;
        self
    }

    /// Sets the runtime state's limit on the number of expected stream sources
    /// that are to be pre-provisioned into the runtime state's filesystem.
    #[inline]
    fn set_expected_stream_source_count(&mut self, sources: usize) -> &mut Self {
        self.expected_stream_source_count = sources;
        self
    }

    /// Sets the runtime state's list of IDs of clients who are able to request
    /// a runtime shutdown to `client_ids`.
    #[inline]
    fn set_expected_shutdown_sources(&mut self, client_ids: Vec<u64>) -> &mut Self {
        self.expected_shutdown_sources = client_ids;
        self
    }

    /// Sets the runtime state's program module to `module`.
    ///
    /// **PANICS**: will panic if a module has already been registered, as this
    /// seems inherently suspicious.  The state transition system/rest of the
    /// Veracruz runtime should only allow these sorts of registration acts to
    /// happen once.
    #[inline]
    fn set_program_module(&mut self, module: Module) -> &mut Self {
        // The program module should really never change, once it is set.  If it
        // does then something suspicious is happening, and should be examined.
        assert_eq!(self.program_digest, None);
        self.program_module = Some(module);
        self
    }

    /// Sets the runtime state's measurement of the program to `digest`.
    ///
    /// **PANICS**: will panic if a digest has already been registered, as this
    /// seems inherently suspicious.  The state transition system/rest of the
    /// Veracruz runtime should only allow these sorts of registration acts to
    /// happen once.
    #[inline]
    fn set_program_digest(&mut self, digest: Vec<u8>) -> &mut Self {
        // The program digest should really never change, once it is set.  If it
        // does then something suspicious is happening, and should be examined.
        assert_eq!(self.program_digest, None);
        self.program_digest = Some(digest);
        self
    }

    /// Sets the runtime state's memory to `memory`.
    ///
    /// **PANICS**: will panic if a memory has already been registered, as this
    /// seems inherently suspicious.  The state transition system/rest of the
    /// Veracruz runtime should only allow these sorts of registration acts to
    /// happen once.
    #[inline]
    fn set_memory(&mut self, memory: Memory) -> &mut Self {
        // The program memory should really never change, once it is set.  If it
        // does then something suspicious is happening, and should be examined.
        assert_eq!(self.program_digest, None);
        self.memory = Some(memory);
        self
    }

    /// Moves the runtime state's transition state into `LifecycleState::Error`.
    /// Once this state is entered, the machine cannot escape, and no further
    /// state transitions can be made.
    #[inline]
    pub(crate) fn error(&mut self) -> &mut Self {
        self.lifecycle_state = LifecycleState::Error;
        self
    }

    ////////////////////////////////////////////////////////////////////////////
    // Filesystem actions.
    ////////////////////////////////////////////////////////////////////////////

    /// Writes a new entry to the filesystem, consisting of `d` a metadata
    /// frame, at location `fname`.
    #[inline]
    pub(crate) fn write_filesystem(&mut self, fname: Filename, d: DataNode) -> &mut Self {
        self.filesystem.insert(fname, d);
        self
    }

    /// Reads from the filesystem at `fname`.  Returns `None` iff no such file
    /// exists in the filesystem.  Returns `Some(data)`, for `data` a metadata
    /// frame, otherwise.
    #[inline]
    pub(crate) fn read_filesystem(&self, fname: Filename) -> Option<&DataNode> {
        self.filesystem.get(fname)
    }

    /// Returns `true` iff all of the file names in `fnames` have been written
    /// to the filesystem in the trusted runtime.
    #[inline]
    pub(crate) fn files_exist(&self, fnames: &[Filename]) -> bool {
        fnames.iter().all(|f| {
            self.filesystem.get(f).is_some()
        })
    }

    ////////////////////////////////////////////////////////////////////////////
    // Querying the host state.
    ////////////////////////////////////////////////////////////////////////////

    /// Queries the current lifecycle transition system state of the runtime
    /// state.
    #[inline]
    pub(crate) fn lifecycle_state(&self) -> &LifecycleState {
        &self.lifecycle_state
    }

    /// Returns the number of expected data sources that we are expecting.  This
    /// is specified in the global policy file.
    #[inline]
    pub(crate) fn expected_data_source_count(&self) -> usize {
        self.expected_data_source_count
    }

    /// Returns the number of expected stream sources that we are expecting.
    /// This is specified in the global policy file.
    #[inline]
    pub(crate) fn expected_stream_source_count(&self) -> usize {
        self.expected_data_source_count
    }

    /// Returns the number of data sources that have so far been registered with
    /// the runtime state.  This value should never exceed
    /// `expected_data_source_count`.
    #[inline]
    pub(crate) fn registered_data_source_count(&self) -> usize {
        self.registered_data_source_count
    }

    /// Returns the number of stream sources that have so far been registered
    /// with the runtime state.  This value should never exceed
    /// `expected_stream_source_count`.
    #[inline]
    pub(crate) fn registered_stream_source_count(&self) -> usize {
        self.registered_stream_source_count
    }

    /// Returns `Some(digest)`, for `digest` a SHA-256 digest of the program
    /// module, iff a digest has been registered with the runtime state.
    #[inline]
    pub(crate) fn program_digest(&self) -> Option<&Vec<u8>> {
        self.program_digest.as_ref()
    }

    /// Returns `Some(memory)`, for `memory` a WASM heap or "linear memory", iff
    /// a memory has been registered with the runtime state.
    #[inline]
    pub(crate) fn memory(&self) -> Option<&Memory> {
        self.memory.as_ref()
    }

    /// Returns `Some(module)`, for `module` a WASM program module, iff a module
    /// has been registered with the runtime state.
    #[inline]
    pub(crate) fn program_module(&self) -> Option<&Module> {
        self.program_module.as_ref()
    }

    /// Returns the IDs of clients who must request that the trusted runtime is
    /// to shutdown before it is able to do so.
    #[inline]
    pub(crate) fn expected_shutdown_sources(&self) -> &Vec<u64> {
        &self.expected_shutdown_sources
    }

    /// Returns `true` iff the program module has been registered.
    #[inline]
    pub(crate) fn is_program_module_registered(&self) -> bool {
        self.program_module.is_some()
    }

    /// Returns `true` iff the program memory/heap has been registered.
    #[inline]
    pub(crate) fn is_memory_registered(&self) -> bool {
        self.memory.is_some()
    }

    /// Returns `true` iff the digest of the program module has been registered.
    #[inline]
    pub(crate) fn is_program_digest_registered(&self) -> bool {
        self.program_digest.is_some()
    }

    /// Returns `true` iff all clients who must request shutdown, before the
    /// trusted runtime is able to shutdown, have done so.
    #[inline]
    pub(crate) fn is_able_to_shutdown(&self) -> bool {
        self.expected_shutdown_sources.is_empty()
    }

    ////////////////////////////////////////////////////////////////////////////
    // Progressing through the state machine.
    ////////////////////////////////////////////////////////////////////////////

    ////////////////////////////////////////////////////////////////////////////
    // Requesting shutdown.
    ////////////////////////////////////////////////////////////////////////////

    /// Signals to the provisioning host that a client, with ID `client_id`, has
    /// requested that the trusted runtime shutdown.
    #[inline]
    pub(crate) fn request_shutdown(&mut self, client_id: &u64) -> &mut self {
        self.expected_shutdown_sources.retain(|v| v != client_id);
        self
    }
}

////////////////////////////////////////////////////////////////////////////////
// Fatal host errors/runtime panics.
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
pub enum RuntimePanic {
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
    #[error(
    display = "RuntimePanic: Unknown H-call invoked: '{}'.",
    index
    )]
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
    #[error(
    display = "RuntimePanic: Failed to find the entry point in the WASM program."
    )]
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
    /// Wrapper for direct error message.
    #[error(display = "RuntimePanic: Error message {:?}.", _0)]
    DirectErrorMessage(String),
    /// Something unknown or unexpected went wrong, and there's no more detailed
    /// information.
    #[error(display = "RuntimePanic: Unknown error.")]
    Generic,
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
pub(crate) type HCallError = Result<ErrNo, RuntimePanic>;

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
/// `freestanding-chihuahua` and `mexico-city` and if any functionality is
/// missing that these components require then it should be added to this trait
/// and implemented for all supported implementation strategies.
///
/// Note that a factory method will return an opaque instance of this trait
/// depending on the backend chosen.
pub trait Chihuahua: Send {
    /// Loads a raw WASM program from a buffer of received or parsed bytes.
    /// Will fail if the lifecycle state is not in `LifecycleState::Initial` or
    /// if the buffer cannot be parsed.  On success bumps the lifecycle state to
    /// `LifecycleState::ReadyToExecute` in cases where no data sources are
    /// expected (i.e. we are a pure delegate) or
    /// `LifecycleState::DataSourcesLoading` in cases where we are expecting
    /// data to be provisioned.
    fn load_program(&mut self, buffer: &[u8]) -> Result<(), ProvisioningError>;

    /// Provisions a new block-oriented data source into the machine state,
    /// storing the `buffer` in the block-oriented input directory at filename
    /// `fname` in the synthetic filesystem.  Will fail if the lifecycle state
    /// is not `LifecycleState::DataSourcesLoading` or if the file already
    /// exists.  Will bump the lifecycle state to
    /// `LifecycleState::ReadyToExecute` when the call represents the last data
    /// source to be loaded (including streams), switches into
    /// `LifecycleState::StreamSourcesLoading` if `buffer` represented the last
    /// block-oriented input to load but more stream-oriented inputs are
    /// expected, or maintains the current lifecycle state.
    fn add_data_source(
        &mut self,
        fname: String,
        buffer: Vec<u8>
    ) -> Result<(), ProvisioningError>;

    /// Provisions a new stream-oriented data source into the machine state,
    /// storing the `buffer` in the block-oriented input directory at filename
    /// `fname` in the synthetic filesystem.  Will fail if the lifecycle state
    /// is not `LifecycleState::StreamSourcesLoading` or if the file already
    /// exists.  Will bump the lifecycle state to
    /// `LifecycleState::ReadyToExecute` when the call represents the last data
    /// source to be loaded, or otherwise maintains the current lifecycle state.
    fn add_stream_source(
        &mut self,
        fname: String,
        buffer: Vec<u8>
    ) -> Result<(), ProvisioningError>;

    /// Invokes the entry point of the provisioned WASM program.  Will fail if
    /// the current lifecycle state is not `LifecycleState::ReadyToExecute` or
    /// if the WASM program fails at runtime.  On success, bumps the lifecycle
    /// state to `LifecycleState::FinishedExecuting` and returns the error code
    /// returned by the WASM program entry point as an `i32` value.
    fn invoke_entry_point(&mut self) -> Result<i32, RuntimePanic>;

    /// Returns `true` iff a program module has been registered in the host
    /// provisioning state.
    fn is_program_registered(&self) -> bool;

    /// Returns `true` iff a result has been registered with the host
    /// provisioning state by a WASM program.
    fn is_result_registered(&self) -> bool;

    /// Returns `true` iff a memory is registered with the host provisioning
    /// state from the program module.
    fn is_memory_registered(&self) -> bool;

    /// Returns `true` iff all clients who must request shutdown have now done
    /// so.
    fn is_able_to_shutdown(&self) -> bool;

    /// Returns the current lifecycle state that the host provisioning state is
    /// in.
    fn lifecycle_state(&self) -> LifecycleState;

    /// Returns the current number of data sources provisioned into the host
    /// provisioning state.
    fn current_data_source_count(&self) -> usize;

    /// Returns the current number of stream sources provisioned into the host
    /// provisioning state.
    fn current_stream_source_count(&self) -> usize;

    /// Returns the expected data sources, as identified by their client IDs,
    /// that we expect to be provisioned into the host state.
    fn expected_data_sources(&self) -> usize;

    /// Returns the expected stream sources, as identified by their client IDs,
    /// that we expect to be provisioned into the host state.
    fn expected_stream_sources(&self) -> usize;

    /// Returns the list of client IDs of clients who can request shutdown of
    /// the platform.
    fn expected_shutdown_sources(&self) -> Vec<u64>;

    /// Returns a result of a WASM computation that has executed on the host
    /// provisioning state.  Returns `None` iff no such result has been
    /// registered.
    fn result(&self) -> Option<Vec<u8>>;

    /// Returns an SHA-256 digest of the bytes loaded into the host provisioning
    /// state.  Returns `None` iff no such program has yet been loaded.
    fn program_digest(&self) -> Option<Vec<u8>>;

    /// Sets the expected data sources, through a list of their source IDs, that
    /// this computation is expecting.
    fn set_expected_data_sources(&mut self, sources: usize) -> &mut dyn Chihuahua;

    /// Sets the expected stream sources, through a list of their source IDs, that
    /// this computation is expecting.
    fn set_expected_stream_sources(&mut self, sources: usize) -> &mut dyn Chihuahua;

    /// Sets the expected shutdown sources, through a list of their source IDs, that
    /// this computation is expecting.
    fn set_expected_shutdown_sources(&mut self, sources: &[u64]) -> &mut dyn Chihuahua;

    /// Registers the previous result.
    fn set_previous_result(&mut self, result: &Option<Vec<u8>>) -> &mut dyn Chihuahua;

    /// Moves the host provisioning state's lifecycle state into
    /// `LifecycleState::Error`, a state which it cannot ever escape,
    /// effectively invalidating it.
    fn error(&mut self);

    /// Signals that a client would like to shutdown the platform.  Has no
    /// effect is `client_id` does not correspond to a client with the shutdown
    /// role.
    fn request_shutdown(&mut self, client_id: u64);

    ////////////////////////////////////////////////////////////////////////////
    // Derived code.
    ////////////////////////////////////////////////////////////////////////////

    /// Returns `true` iff the host state is in one of a number of expected
    /// states passed as the second argument, `states`.
    #[inline]
    fn is_in_expected_state(&self, states: &[LifecycleState]) -> bool {
        states
            .iter()
            .any(|sigma| sigma == &self.get_lifecycle_state())
    }

    /// Requests shutdown on behalf of a client, as identified by their client
    /// ID, and then checks if this request was sufficient to reach a threshold
    /// of requests wherein the platform can finally shutdown.
    fn request_and_check_shutdown(&mut self, client_id: u64) -> bool {
        self.request_shutdown(client_id);
        self.is_able_to_shutdown()
    }
}

////////////////////////////////////////////////////////////////////////////////
// Trait implementations
////////////////////////////////////////////////////////////////////////////////

/// Pretty-printing for `DataSourceMetadata`.
impl Display for DataNode {
    fn fmt(&self, f: &mut Formatter) -> Result<(), Error> {
        write!(
            f,
            "Data source (client ID: {}, package ID: {}) bytes:\n",
            self.client_id, self.package_id
        )?;
        write!(f, "  {:?}", self.data)
    }
}

/// Serialize a `LifecycleState` value to a `u8`.
///
/// This is needed for responding to the Veracruz protocol "query enclave state"
/// request from a computation principal.  The current state is encoded as a
/// `u8` and forwarded to the requestor.
impl From<LifecycleState> for u8 {
    fn from(state: LifecycleState) -> Self {
        match state {
            LifecycleState::Initial => 0,
            LifecycleState::DataSourcesLoading => 1,
            LifecycleState::StreamSourcesLoading => 2,
            LifecycleState::ReadyToExecute => 3,
            LifecycleState::FinishedExecuting => 4,
            LifecycleState::Error => 5,
        }
    }
}

/// Serialize a `&LifecycleState` value to a `u8`.
///
/// This is needed for responding to the Veracruz protocol "query enclave state"
/// request from a computation principal.  The current state is encoded as a
/// `u8` and forwarded to the requestor.
impl From<&LifecycleState> for u8 {
    fn from(state: &LifecycleState) -> Self {
        match state {
            LifecycleState::Initial => 0,
            LifecycleState::DataSourcesLoading => 1,
            LifecycleState::StreamSourcesLoading => 2,
            LifecycleState::ReadyToExecute => 3,
            LifecycleState::FinishedExecuting => 4,
            LifecycleState::Error => 5,
        }
    }
}

/// Converts a `u8` value to a `LifecycleState`, if possible.
///
/// This is needed for understanding the response to the Veracruz protocol
/// "query enclave state" message made by a computation principal.  The current
/// state is encoded as a `u8` and forwarded, which can then be decoded using
/// this.
impl TryFrom<u8> for LifecycleState {
    type Error = ();

    fn try_from(code: u8) -> Result<Self, ()> {
        match code {
            0 => Ok(LifecycleState::Initial),
            1 => Ok(LifecycleState::DataSourcesLoading),
            2 => Ok(LifecycleState::StreamSourcesLoading),
            3 => Ok(LifecycleState::ReadyToExecute),
            4 => Ok(LifecycleState::FinishedExecuting),
            5 => Ok(LifecycleState::Error),
            _otherwise => Err(()),
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
