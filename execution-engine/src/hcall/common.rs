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
use wasi_types::{
    Advice, DirCookie, ErrNo, Fd, FdFlags, FdStat, FileDelta, FileSize, FileStat, LookupFlags,
    OpenFlags, Prestat, Rights, Size, Whence, IoVec, DirEnt
};
use veracruz_utils::policy::principal::{Principal, FileOperation};
use std::{
    convert::TryFrom,
    fmt::{Display, Error, Formatter},
    mem::size_of,
    slice::from_raw_parts,
    string::{String, ToString},
    vec::Vec,
};
use crate::hcall::buffer::VFSError;
#[cfg(any(feature = "std", feature = "tz", feature = "nitro"))]
use std::sync::{Arc, Mutex};
#[cfg(feature = "sgx")]
use std::sync::{Arc, SgxMutex as Mutex};
use super::{fs::FileSystem, fs::FileSystemError};
use crate::hcall::buffer::VFS;

////////////////////////////////////////////////////////////////////////////////
// Common constants.
////////////////////////////////////////////////////////////////////////////////

/// The directory in the synthetic filesystem where all inputs will be stored.
/// TODO REMOVE ?
pub(crate) const INPUT_DIRECTORY: &str = "/vcrz/in/";
/// The directory in the synthetic filesystem where the WASM program will write
/// its outputs.
/// TODO REMOVE ?
pub(crate) const OUTPUT_DIRECTORY: &str = "/vcrz/out";
/// The directory, under `INPUT_DIRECTORY`, in the synthetic filesystem where
/// block-oriented inputs will be stored and can be read by the WASM program.
/// TODO REMOVE ?
pub(crate) const BLOCK_INPUT_DIRECTORY_NAME: &str = "block";
/// The directory, under `INPUT_DIRECTORY`, in the synthetic filesystem where
/// stream-oriented inputs will be stored and can be read by the WASM program.
/// TODO REMOVE ?
pub(crate) const STREAM_INPUT_DIRECTORY_NAME: &str = "stream";
/// The root directory. It will be pre-opened for any wasm program
pub(crate) const ROOT_DIRECTORY: &str = "/";

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

/// A generic function that takes any reference to a sized type and returns a
/// byte-representation of that type.
unsafe fn pack_sized_as_bytes<T>(element: &T) -> Vec<u8>
where
    T: Sized,
{
    println!("pack_sized_as_bytes: {}",size_of::<T>());
    let slice: &[u8] = from_raw_parts((element as *const T) as *const u8, size_of::<T>());

    slice.to_vec()
}

/// Packs an `FdStat` type into a vector of bytes.  For writing `FdStat`
/// structures into memory, across the ABI boundary.
#[inline]
pub(crate) fn pack_fdstat(fdstat: &FdStat) -> Vec<u8> {
    unsafe { pack_sized_as_bytes(fdstat) }
}

/// Packs a `FileStat` type into a vector of bytes.  For writing `FileStat`
/// structures into memory, across the ABI boundary.
#[inline]
pub(crate) fn pack_filestat(stat: &FileStat) -> Vec<u8> {
    unsafe { pack_sized_as_bytes(stat) }
}

/// Packs a `PreStat` type into a vector of bytes.  For writing `PreStat`
/// structures into memory, across the ABI boundary.
#[inline]
pub(crate) fn pack_prestat(stat: &Prestat) -> Vec<u8> {
    unsafe { pack_sized_as_bytes(stat) }
}

/// Packs a `DirEnt` type into a vector of bytes.  For writing `DirEnt`
/// structures into memory, across the ABI boundary.
#[inline]
pub(crate) fn pack_dirent(dirent: &DirEnt) -> Vec<u8> {
    unsafe { pack_sized_as_bytes(dirent) }
}

//TODO CHANGE TYPE WITH RESULT
/// Unpacks an `IoVec` structure from a series of bytes, starting at the offset,
/// `offset`.  Returns `None` iff the structure cannot be unpacked, for example
/// if `offset` lies too close to the end of `bytes`.
fn unpack_iovec(bytes: &[u8]) -> Option<IoVec> {
    println!("unpack_iovec : {:?}",bytes);
    if bytes.len() != 8 {
        return None;
    }

    let mut buf_bytes: [u8; 4] = Default::default();
    let mut len_bytes: [u8; 4] = Default::default();
    buf_bytes.copy_from_slice(&bytes[0..4]);
    len_bytes.copy_from_slice(&bytes[4..8]);
    let buf = u32::from_le_bytes(buf_bytes);
    let len = u32::from_le_bytes(len_bytes);    

    let rst = IoVec{
        buf,
        len,
    };
    println!("unpack_iovec rst {:?}",rst);
    Some(rst)
}

//TODO CHANGE TYPE WITH RESULT
/// Reads a list of `IoVec` structures from a byte buffer.  Fails if reading of
/// any `IoVec` fails, for any reason.
pub(crate) fn unpack_iovec_array(bytes: &[u8]) -> Option<Vec<IoVec>> {
    let mut offset = 0;
    let mut iovecs = Vec::new();

    for iovec_byte in bytes.chunks(8) {
        iovecs.push(unpack_iovec(iovec_byte).unwrap());
    }

    println!("unpack_iovec_array rst {:?}",iovecs);

    Some(iovecs)

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
    /// TODO doc 
    #[error(
        display = "HostProvisioningError: VFS Error {}.", _0
    )]
    VFSError(#[error(source)]VFSError),
    #[error(
        display = "HostProvisioningError: File {} cannot be found.", _0
    )]
    FileNotFound(String),
    /// TODO doc
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
// The host runtime state.
////////////////////////////////////////////////////////////////////////////////

/// A wrapper on VFS for WASI, which provides common API used by wasm execution engine.
#[derive(Clone)]
pub struct WASIWrapper {
    // TODO REMOVE REMOVE
    vfs : Arc<Mutex<VFS>>,
    /// The synthetic filesystem associated with this machine.
    filesystem: FileSystem,
    /// The environment variables that have been passed to this program from the
    /// global policy file.  These are stored as a key-value mapping from
    /// variable name to value.
    environment_variables: Vec<(String, String)>,
    /// The array of program arguments that have been passed to this program,
    /// again from the global policy file.
    program_arguments: Vec<String>,
}

impl WASIWrapper {
    ////////////////////////////////////////////////////////////////////////////
    // Creating and modifying runtime states.
    ////////////////////////////////////////////////////////////////////////////
    
    /// Creates a new initial `HostProvisioningState`.
    pub fn new(
        vfs : Arc<Mutex<VFS>>,
    ) -> Self {
        Self { 
            vfs,
            filesystem : FileSystem::new(),
            environment_variables : Vec::new(),
            program_arguments : Vec::new(),
        }
    }


    // TODO REMOVE REMOVE
    pub(crate) fn write_file_base(&mut self, client_id: &Principal, file_name: &str, data: &[u8]) -> Result<(), HostProvisioningError> {
        self.vfs.lock()?.write(client_id,file_name,data)?;
        Ok(())
    }

    pub(crate) fn append_file_base(&mut self, client_id: &Principal, file_name: &str, data: &[u8]) -> Result<(), HostProvisioningError> {
        self.vfs.lock()?.append(client_id,file_name,data)?;
        Ok(())
    }

    pub(crate) fn read_file_base(&self, client_id: &Principal, file_name: &str) -> Result<Option<Vec<u8>>, HostProvisioningError> {
        Ok(self.vfs.lock()?.read(client_id,file_name)?)
    }

    pub(crate) fn count_file_base(&self, prefix: &str) -> Result<u64, HostProvisioningError> {
        Ok(self.vfs.lock()?.count(prefix)?)
    }

    // TODO REMOVE REMOVE

    ////////////////////////////////////////////////////////////////////////////
    // The program's environment.
    ////////////////////////////////////////////////////////////////////////////

    /// Pushes a new argument, `argument`, to the list of program arguments that
    /// will be made available to the program.
    #[inline]
    pub(crate) fn push_program_argument<U>(&mut self, argument: U) -> &mut Self
    where
        U: Into<String>,
    {
        self.program_arguments.push(argument.into());
        self
    }

    /// Implementation of the WASI `args_sizes_get` function.
    pub(crate) fn args_sizes_get(&self) -> (Size, Size) {
        let argc = self.program_arguments.len();
        let size: usize = self
            .program_arguments
            .iter()
            .map(|s| s.as_bytes().len())
            .sum();

        (argc as Size, size as Size)
    }

    /// Implementation of the WASI `args_get` function.  Returns a list of
    /// program arguments encoded as bytes.
    #[inline]
    pub(crate) fn args_get(&self) -> Vec<Vec<u8>> {
        let mut buffer = Vec::new();

        for arg in self.program_arguments.iter() {
            let arg = format!("{}\0", arg);
            let bytes = arg.into_bytes();
            buffer.push(bytes);
        }

        buffer.reverse();

        buffer
    }

    /// Registers a new environment variable, `key`, with a particular value,
    /// `value`, in the program's environment.  Returns `None` iff the key was
    /// already associated with a value (in which case the key-value pair are
    /// not registered in the environment), and `Some(state)`, for `state` a
    /// modified runtime state with the pair registered, otherwise.
    #[inline]
    pub(super) fn register_environment_variable<U>(&mut self, key: U, value: U) -> Option<&mut Self>
    where
        U: Into<String>,
    {
        let keys: Vec<String> = self
            .environment_variables
            .iter()
            .map(|(k, _v)| k)
            .cloned()
            .collect();

        let k = key.into();

        if keys.contains(&k) {
            None
        } else {
            self.environment_variables.push((k, value.into()));
            Some(self)
        }
    }

    /// Implementation of the WASI `environ_sizes_get` function.
    pub(crate) fn environ_sizes_get(&self) -> (Size, Size) {
        println!("environ_sizes_get is called");
        let environc = self.environment_variables.len();
        let mut environ_buf_size = 0usize;

        for (key, value) in self.environment_variables.iter() {
            let entry = format!("{}={}\0", key, value);
            environ_buf_size += entry.as_bytes().len();
        }

        (environc as Size, environ_buf_size as Size)
    }

    /// Implementation of the WASI `environ_get` function.
    pub(crate) fn environ_get(&self) -> Vec<Vec<u8>> {
        println!("environ_get is called");
        let environc = self.environment_variables.len();
        let mut buffer = Vec::new();

        for (key, value) in self.environment_variables.iter() {
            let environ = format!("{}={}\0", key, value);
            let bytes = environ.into_bytes();
            buffer.push(bytes);
        }

        buffer.reverse();

        buffer
    }

    ////////////////////////////////////////////////////////////////////////////
    // Filesystem operations.
    ////////////////////////////////////////////////////////////////////////////

    #[inline]
    pub(crate) fn fd_close(&mut self, fd: &Fd) -> ErrNo {
        match self.filesystem.fd_close(fd) {
            Ok(_) => ErrNo::Success,
            Err(e) => e,
        }
    }

    #[inline]
    pub(crate) fn fd_advise(
        &mut self,
        fd: &Fd,
        offset: FileSize,
        len: FileSize,
        advice: Advice,
    ) -> ErrNo {
        self.filesystem.fd_advise(fd, offset, len, advice)
    }

    #[inline]
    pub(crate) fn fd_fdstat_get(&self, fd: &Fd) -> FileSystemError<FdStat> {
        self.filesystem.fd_fdstat_get(fd)
    }

    #[inline]
    pub(crate) fn fd_fdstat_set_flags(&mut self, fd: &Fd, flags: FdFlags) -> ErrNo {
        self.filesystem.fd_fdstat_set_flags(fd, flags)
    }

    #[inline]
    pub(crate) fn fd_fdstat_set_rights(
        &mut self,
        fd: &Fd,
        rights_base: Rights,
        rights_inheriting: Rights,
    ) -> ErrNo {
        self.filesystem
            .fd_fdstat_set_rights(fd, rights_base, rights_inheriting)
    }

    #[inline]
    pub(crate) fn fd_filestat_get(&self, fd: &Fd) -> FileSystemError<FileStat> {
        self.filesystem.fd_filestat_get(fd)
    }

    #[inline]
    pub(crate) fn fd_filestat_set_size(&mut self, fd: &Fd, size: FileSize) -> ErrNo {
        self.filesystem.fd_filestat_set_size(fd, size)
    }

    #[inline]
    pub(crate) fn fd_pread_base(
        &mut self,
        fd: &Fd,
        len: usize,
        offset: &FileSize,
    ) -> FileSystemError<Vec<u8>> {
        self.filesystem.fd_pread_base(fd, len, offset)
    }

    #[inline]
    pub(crate) fn fd_prestat_get(&mut self, fd: &Fd) -> FileSystemError<Prestat> {
        self.filesystem.fd_prestat_get(fd)
    }

    #[inline]
    pub(crate) fn fd_prestat_dir_name(&mut self, fd: &Fd) -> FileSystemError<String> {
        self.filesystem.fd_prestat_dir_name(fd)
    }

    #[inline]
    pub(crate) fn fd_pwrite_base(
        &mut self,
        fd: &Fd,
        buf: Vec<u8>,
        offset: &FileSize,
    ) -> FileSystemError<Size> {
        self.filesystem.fd_pwrite_base(fd, buf, *offset)
    }

    #[inline]
    pub(crate) fn fd_read_base(&mut self, fd: &Fd, len: usize) -> FileSystemError<Vec<u8>> {
        self.filesystem.fd_read_base(fd, len)
    }

    #[inline]
    pub(crate) fn fd_readdir(
        &mut self,
        fd: &Fd,
        cookie: &DirCookie,
    ) -> FileSystemError<Vec<DirEnt>> {
        self.filesystem.fd_readdir(fd, cookie)
    }

    #[inline]
    pub(crate) fn fd_renumber(&mut self, old_fd: &Fd, new_fd: Fd) -> ErrNo {
        self.filesystem.fd_renumber(old_fd, new_fd)
    }

    #[inline]
    pub(crate) fn fd_seek(
        &mut self,
        fd: &Fd,
        offset: FileDelta,
        whence: Whence,
    ) -> FileSystemError<FileSize> {
        self.filesystem.fd_seek(fd, offset, whence)
    }

    #[inline]
    pub(crate) fn fd_tell(&self, fd: &Fd) -> FileSystemError<&FileSize> {
        self.filesystem.fd_tell(fd)
    }

    #[inline]
    pub(crate) fn fd_write_base(&mut self, fd: &Fd, buf: Vec<u8>) -> FileSystemError<Size> {
        self.filesystem.fd_write_base(fd, buf)
    }

    #[inline]
    pub(crate) fn path_create_directory(&mut self, fd: &Fd, path: String) -> ErrNo {
        self.filesystem.path_create_directory(fd, path)
    }

    #[inline]
    pub(crate) fn path_filestat_get(
        &mut self,
        fd: &Fd,
        flags: &LookupFlags,
        path: &String,
    ) -> FileSystemError<FileStat> {
        self.filesystem.path_filestat_get(fd, flags, path)
    }

    #[inline]
    pub(crate) fn path_open(
        &mut self,
        fd: &Fd,
        dirflags: LookupFlags,
        path: String,
        oflags: OpenFlags,
        fs_rights_base: Rights,
        fs_rights_inheriting: Rights,
        fdflags: FdFlags,
    ) -> FileSystemError<Fd> {
        self.filesystem.path_open(
            fd,
            dirflags,
            path,
            oflags,
            fs_rights_base,
            fs_rights_inheriting,
            fdflags,
        )
    }

    #[inline]
    pub(crate) fn path_remove_directory(&mut self, fd: &Fd, path: &String) -> ErrNo {
        self.filesystem.path_remove_directory(fd, path)
    }

    #[inline]
    pub(crate) fn path_rename(
        &mut self,
        old_fd: &Fd,
        old_path: &String,
        new_fd: &Fd,
        new_path: String,
    ) -> ErrNo {
        self.filesystem
            .path_rename(old_fd, old_path, new_fd, new_path)
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
pub enum FatalEngineError {
    /// The WASM program called `proc_exit`, or similar, to signal an early exit
    /// from the program, returning a specific error code.
    #[error(
        display = "FatalEngineError: Early exit requested by program, error code returned: '{}'.",
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
        display = "FatalEngineError: Bad arguments passed to host function '{}'.",
        function_name
    )]
    BadArgumentsToHostFunction {
        /// The name of the host function that was being invoked.
        function_name: String,
    },
    /// The WASM program tried to invoke an unknown H-call on the Veracruz host.
    #[error(display = "FatalEngineError: Unknown H-call invoked: '{}'.", index)]
    UnknownHostFunction {
        /// The host call index of the unknown function that was invoked.
        index: usize,
    },
    /// The host failed to read a range of bytes, starting at a base address,
    /// from the running WASM program's linear memory.
    #[error(
        display = "FatalEngineError: Failed to read {} byte(s) from WASM memory at address {}.",
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
        display = "FatalEngineError: Failed to write {} byte(s) to WASM memory at address {}.",
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
    #[error(display = "FatalEngineError: WASM program returns code other than i32.")]
    ReturnedCodeError,
    /// Wrapper for WASI Trap.
    #[error(display = "FatalEngineError: WASMIError: Trap: {:?}.", _0)]
    WASMITrapError(#[source(error)] wasmi::Trap),
    /// Wrapper for WASI Error other than Trap.
    #[error(display = "FatalEngineError: WASMIError {:?}.", _0)]
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
    VFSError(#[error(source)] VFSError),
    #[error(display = "FatalEngineError: Wasi-ErrNo {:?}.", _0)]
    WASIError(#[source(error)] wasi_types::ErrNo),
    /// Wrapper for direct error message.
    #[error(display = "FatalEngineError: Error message {:?}.", _0)]
    DirectErrorMessage(String),
    #[error(display = "FatalVeracruzHostError: provisioning error {:?}.", _0)]
    ProvisionError(#[error(source)] HostProvisioningError),
    /// Something unknown or unexpected went wrong, and there's no more detailed
    /// information.
    #[error(display = "FatalEngineError: Unknown error.")]
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

impl FatalEngineError {
    /// Constructs a `FatalEngineError::DirectErrorMessage` out of anything that can
    /// be converted into a string.
    #[inline]
    pub fn direct_error_message<T>(message: T) -> Self
    where
        T: Into<String>,
    {
        FatalEngineError::DirectErrorMessage(message.into())
    }

    /// Constructs a `FatalEngineError::BadArgumentsToHostFunction` out of anything
    /// that can be converted into a string.
    pub fn bad_arguments_to_host_function<T>(fname: T) -> Self
    where
        T: Into<String>,
    {
        FatalEngineError::BadArgumentsToHostFunction {
            function_name: fname.into(),
        }
    }
}

////////////////////////////////////////////////////////////////////////////////
// Implementation of the H-calls.
////////////////////////////////////////////////////////////////////////////////

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

