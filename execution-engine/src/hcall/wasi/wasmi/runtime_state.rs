//! An implementation of the ExecutionEngine runtime state for WASMI.
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Copyright
//!
//! See the file `LICENSE.markdown` in the Veracruz root directory for licensing
//! and copyright information.

use std::{convert::{TryInto, TryFrom}, string::{String, ToString}, vec::Vec, boxed::Box};
use crate::{
    fs::FileSystem,
    hcall::common::{
        pack_dirent, pack_fdstat, pack_filestat, pack_prestat,
        ExecutionEngine, EntrySignature, HostProvisioningError, FatalEngineError, EngineReturnCode,
        WASIWrapper, MemoryHandler, WASIAPIName
    }
};
use platform_services::{getrandom, result};
use wasi_types::{
    Advice, ErrNo, Fd, FdFlags, FdStat, FileDelta, FileSize, FileStat, IoVec, LookupFlags, Rights,
    Size, Whence,
};
use wasmi::{
    Error, ExternVal, Externals, FuncInstance, FuncRef, GlobalDescriptor, GlobalRef,
    MemoryDescriptor, MemoryRef, Module, ModuleImportResolver, ModuleInstance, ModuleRef,
    RuntimeArgs, RuntimeValue, Signature, TableDescriptor, TableRef, Trap, ValueType,
    HostError, TrapKind,
};
use veracruz_utils::policy::principal::Principal;
#[cfg(any(feature = "std", feature = "tz", feature = "nitro"))]
use std::sync::{Mutex, Arc};
#[cfg(feature = "sgx")]
use std::sync::{SgxMutex as Mutex, Arc};
use num::FromPrimitive;

////////////////////////////////////////////////////////////////////////////////
// Veracruz host errors.
////////////////////////////////////////////////////////////////////////////////

#[typetag::serde]
impl HostError for FatalEngineError {}

////////////////////////////////////////////////////////////////////////////////
// The WASMI host provisioning state.
////////////////////////////////////////////////////////////////////////////////

/// Impl the MemoryHandler for MemoryRef.
/// This allows passing the MemoryRef to WASIWrapper on any VFS call.
impl MemoryHandler for MemoryRef {
    /// Writes a buffer of bytes, `buffer`, to the runtime state's memory at
    /// address, `address`.  Success on returing ErrNo::Success, 
    /// Fails with `ErrNo::NoMem` if no memory is registered in the runtime state.
    fn write_buffer(&mut self, address: u32, buffer: &[u8]) -> ErrNo {
            if let Err(_e) = self.set(address, buffer) {
                return ErrNo::NoMem;
            }
            ErrNo::Success
    }

    /// Read a buffer of bytes from the runtime state's memory at
    /// address, `address`. Return the bytes or Err with ErrNo,
    /// e.g. `Err(ErrNo::NoMem)` if no memory is registered in the runtime state.
    fn read_buffer(&self, address: u32, length: u32) -> Result<Vec<u8>, ErrNo> {
        self
            .get(address, length as usize)
            .map_err(|_e| ErrNo::Fault)
            .map(|buf| buf.to_vec())
    }
}

/// The WASMI host provisioning state: the `HostProvisioningState` with the
/// Module and Memory type-variables specialised to WASMI's `ModuleRef` and
/// `MemoryRef` type.
pub(crate) struct WASMIRuntimeState {
    vfs : WASIWrapper,
    /// A reference to the WASM program module that will actually execute on
    /// the input data sources.
    program_module: Option<ModuleRef>,
    /// A reference to the WASM program's linear memory (or "heap").
    memory: Option<MemoryRef>,
    /// Ref to the program that is executed
    program: Principal,
}
pub(crate) type WASIError = Result<ErrNo, FatalEngineError>;

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

////////////////////////////////////////////////////////////////////////////////
// Constants.
////////////////////////////////////////////////////////////////////////////////

/// The representation type of the WASI `Advice` type.
const REPRESENTATION_WASI_ADVICE: ValueType = ValueType::I32;
/// The base pointer representation type of the WASI `CIOVecArray` type, which
/// is passed as a pair of base address and length.
const REPRESENTATION_WASI_CIOVEC_ARRAY_BASE: ValueType = ValueType::I32;
/// The length representation type of the WASI `CIOVecArray` type, which is
/// passed as a pair of base address and length.
const REPRESENTATION_WASI_CIOVEC_ARRAY_LENGTH: ValueType = ValueType::I32;
/// The representation type of the WASI `ClockID` type.
const REPRESENTATION_WASI_CLOCKID: ValueType = ValueType::I32;
/// The representation type of the WASI `DirCookie` type.
const REPRESENTATION_WASI_DIRCOOKIE: ValueType = ValueType::I64;
/// The representation type of the WASI `ErrNo` type.
const REPRESENTATION_WASI_ERRNO: ValueType = ValueType::I32;
/// The representation type of the WASI `ExitCode` type.
const REPRESENTATION_WASI_EXITCODE: ValueType = ValueType::I32;
/// The representation type of the WASI `FD` type.
const REPRESENTATION_WASI_FD: ValueType = ValueType::I32;
/// The representation type of the WASI `FDFlags` type.
const REPRESENTATION_WASI_FDFLAGS: ValueType = ValueType::I32;
/// The representation type of the WASI `FileDelta` type.
const REPRESENTATION_WASI_FILEDELTA: ValueType = ValueType::I64;
/// The representation type of the WASI `FileSize` type.
const REPRESENTATION_WASI_FILESIZE: ValueType = ValueType::I32;
/// The representation type of the WASI `FSTFlags` type.
const REPRESENTATION_WASI_FSTFLAGS: ValueType = ValueType::I32;
/// The base pointer representation type of the WASI `IOVecArray` type, which
/// is passed as a pair of base address and length.
const REPRESENTATION_WASI_IOVEC_ARRAY_BASE: ValueType = ValueType::I32;
/// The length representation type of the WASI `IOVecArray` type, which is
/// passed as a pair of base address and length.
const REPRESENTATION_WASI_IOVEC_ARRAY_LENGTH: ValueType = ValueType::I32;
/// The representation type of the WASI `LookupFlags` type.
const REPRESENTATION_WASI_LOOKUP_FLAGS: ValueType = ValueType::I32;
/// The representation type of the WASI `OFlags` type.
const REPRESENTATION_WASI_OFLAGS: ValueType = ValueType::I32;
/// The representation type of the WASI `Rights` type.
const REPRESENTATION_WASI_RIGHTS: ValueType = ValueType::I64;
/// The representation type of the WASI `SDFlags` type.
const REPRESENTATION_WASI_SDFLAGS: ValueType = ValueType::I32;
/// The representation type of the WASI `SIFlags` type.
const REPRESENTATION_WASI_SIFLAGS: ValueType = ValueType::I32;
/// The representation type of the WASI `RIFlags` type.
const REPRESENTATION_WASI_RIFLAGS: ValueType = ValueType::I32;
/// The representation type of the WASI `Signal` type.
const REPRESENTATION_WASI_SIGNAL: ValueType = ValueType::I32;
/// The representation type of the WASI `Size` type.
const REPRESENTATION_WASI_SIZE: ValueType = ValueType::I32;
/// The representation type of the WASI `Timestamp` type.
const REPRESENTATION_WASI_TIMESTAMP: ValueType = ValueType::I32;
/// The representation type of the WASI `Whence` type.
const REPRESENTATION_WASI_WHENCE: ValueType = ValueType::I32;

/// The representation type of WASM `const` pointers (assuming `wasm32`).
const REPRESENTATION_WASM_CONST_POINTER: ValueType = ValueType::I32;
/// The representation type of WASM pointers (assuming `wasm32`).
const REPRESENTATION_WASM_POINTER: ValueType = ValueType::I32;
/// The representation type of WASM buffer length (assuming `wasm32`).
const REPRESENTATION_WASM_SIZE_T: ValueType = ValueType::I32;

////////////////////////////////////////////////////////////////////////////////
// Function well-formedness checks.
////////////////////////////////////////////////////////////////////////////////

/// Checks the signature of the WASI `args_get` function:
///
/// ```Rust
/// args_get(argv: Pointer<Pointer<u8>>, argv_buf: Pointer<u8>) -> errno
/// ```
#[inline]
fn check_args_get_signature(signature: &Signature) -> bool {
    let params = signature.params();
    let return_type = signature.return_type();

    params == &[REPRESENTATION_WASM_POINTER, REPRESENTATION_WASM_POINTER]
        && return_type == Some(REPRESENTATION_WASI_ERRNO)
}

/// Checks the signature of the WASI `args_sizes_get` function:
///
/// ```Rust
/// args_sizes_get() -> (errno, size, size)
/// ```
fn check_args_sizes_get_signature(signature: &Signature) -> bool {
    let params = signature.params();
    let return_type = signature.return_type();

    params == &[REPRESENTATION_WASM_POINTER, REPRESENTATION_WASM_POINTER]
        && return_type == Some(REPRESENTATION_WASI_ERRNO)
}

/// Checks the signature of the WASI `environ_get` function:
///
/// ```Rust
/// environ_get(environ: Pointer<Pointer<u8>>, environ_buf: Pointer<u8>) -> errno
/// ```
fn check_environ_get_signature(signature: &Signature) -> bool {
    let params = signature.params();
    let return_type = signature.return_type();

    params == &[REPRESENTATION_WASM_POINTER, REPRESENTATION_WASM_POINTER]
        && return_type == Some(REPRESENTATION_WASI_ERRNO)
}

/// Checks the signature of the WASI `environ_sizes_get` function:
///
/// ```Rust
/// environ_sizes_get() -> (errno, size, size)
/// ```
fn check_environ_sizes_get_signature(signature: &Signature) -> bool {
    let params = signature.params();
    let return_type = signature.return_type();

    params == &[REPRESENTATION_WASM_POINTER, REPRESENTATION_WASM_POINTER]
        && return_type == Some(REPRESENTATION_WASI_ERRNO)
}

/// Checks the signature of the WASI `clock_res_get` function:
///
/// ```Rust
/// clock_res_get(id: clockid) -> (errno, timestamp)
/// ```
fn check_clock_res_get_signature(signature: &Signature) -> bool {
    let params = signature.params();
    let return_type = signature.return_type();

    params == &[REPRESENTATION_WASI_CLOCKID, REPRESENTATION_WASM_POINTER]
        && return_type == Some(REPRESENTATION_WASI_ERRNO)
}

/// Checks the signature of the WASI `clock_time_get` function:
///
/// ```Rust
/// clock_time_get(id: clockid, precision: timestamp) -> (errno, timestamp)
/// ```
fn check_clock_time_get_signature(signature: &Signature) -> bool {
    let params = signature.params();
    let return_type = signature.return_type();

    params
        == &[
            REPRESENTATION_WASI_CLOCKID,
            REPRESENTATION_WASI_TIMESTAMP,
            REPRESENTATION_WASM_POINTER,
        ]
        && return_type == Some(REPRESENTATION_WASI_ERRNO)
}

/// Checks the signature of the WASI `fd_advise` function:
///
/// ```Rust
/// fd_advise(fd: fd, offset: filesize, len: filesize, advice: advice) -> errno
/// ```
fn check_fd_advise_signature(signature: &Signature) -> bool {
    let params = signature.params();
    let return_type = signature.return_type();

    params
        == &[
            REPRESENTATION_WASI_FD,
            REPRESENTATION_WASI_FILESIZE,
            REPRESENTATION_WASI_FILESIZE,
            REPRESENTATION_WASI_ADVICE,
        ]
        && return_type == Some(REPRESENTATION_WASI_ERRNO)
}

/// Checks the signature of the WASI `fd_allocate` function:
///
/// ```Rust
/// fd_allocate(fd: fd, offset: filesize, len: filesize) -> errno
/// ```
fn check_fd_allocate_signature(signature: &Signature) -> bool {
    let params = signature.params();
    let return_type = signature.return_type();

    params
        == &[
            REPRESENTATION_WASI_FD,
            REPRESENTATION_WASI_FILESIZE,
            REPRESENTATION_WASI_FILESIZE,
        ]
        && return_type == Some(REPRESENTATION_WASI_ERRNO)
}

/// Checks the signature of the WASI `fd_close` function:
///
/// ```Rust
/// fd_close(fd: fd) -> errno
/// ```
fn check_fd_close_signature(signature: &Signature) -> bool {
    let params = signature.params();
    let return_type = signature.return_type();

    params == &[REPRESENTATION_WASI_FD] && return_type == Some(REPRESENTATION_WASI_ERRNO)
}

/// Checks the signature of the WASI `fd_datasync` function:
///
/// ```Rust
/// fd_datasync(fd: fd) -> errno
/// ```
fn check_fd_datasync_signature(signature: &Signature) -> bool {
    let params = signature.params();
    let return_type = signature.return_type();

    params == &[REPRESENTATION_WASI_FD] && return_type == Some(REPRESENTATION_WASI_ERRNO)
}

/// Checks the signature of the WASI `fd_fdstat_get` function:
///
/// ```Rust
/// fd_fdstat_get(fd: fd) -> (errno, fdstat)
/// ```
fn check_fd_fdstat_get_signature(signature: &Signature) -> bool {
    let params = signature.params();
    let return_type = signature.return_type();

    params == &[REPRESENTATION_WASI_FD, REPRESENTATION_WASM_POINTER]
        && return_type == Some(REPRESENTATION_WASI_ERRNO)
}

/// Checks the signature of the WASI `fd_fdstat_set_flags` function:
///
/// ```Rust
/// fd_fdstat_set_flags(fd: fd, flags: fdflags) -> errno
/// ```
fn check_fd_fdstat_set_flags_signature(signature: &Signature) -> bool {
    let params = signature.params();
    let return_type = signature.return_type();

    params == &[REPRESENTATION_WASI_FD, REPRESENTATION_WASI_FDFLAGS]
        && return_type == Some(REPRESENTATION_WASI_ERRNO)
}

/// Checks the signature of the WASI `fd_fdstat_set_rights` function:
///
/// ```Rust
/// fd_fdstat_set_rights(fd: fd, fs_rights_base: rights, fs_rights_inheriting: rights) -> errno
/// ```
fn check_fd_fdstat_set_rights_signature(signature: &Signature) -> bool {
    let params = signature.params();
    let return_type = signature.return_type();

    params
        == &[
            REPRESENTATION_WASI_FD,
            REPRESENTATION_WASI_RIGHTS,
            REPRESENTATION_WASI_RIGHTS,
        ]
        && return_type == Some(REPRESENTATION_WASI_ERRNO)
}

/// Checks the signature of the WASI `fd_filestat_get` function:
///
/// ```Rust
/// fd_filestat_get(fd: fd) -> (errno, filestat)
/// ```
fn check_fd_filestat_get_signature(signature: &Signature) -> bool {
    let params = signature.params();
    let return_type = signature.return_type();

    params == &[REPRESENTATION_WASI_FD, REPRESENTATION_WASM_POINTER]
        && return_type == Some(REPRESENTATION_WASI_ERRNO)
}

/// Checks the signature of the WASI `fd_filestat_set_size` function:
///
/// ```Rust
/// fd_filestat_set_size(fd: fd, size: filesize) -> errno
/// ```
fn check_fd_filestat_set_size_signature(signature: &Signature) -> bool {
    let params = signature.params();
    let return_type = signature.return_type();

    params == &[REPRESENTATION_WASI_FD, REPRESENTATION_WASI_FILESIZE]
        && return_type == Some(REPRESENTATION_WASI_ERRNO)
}

/// Checks the signature of the WASI `fd_filestat_set_size` function:
///
/// ```Rust
/// fd_filestat_set_size(fd: fd, atim: timestamp, mtim: timestamp, fst_flags: fstflags) -> errno
/// ```
fn check_fd_filestat_set_times_signature(signature: &Signature) -> bool {
    let params = signature.params();
    let return_type = signature.return_type();

    params
        == &[
            REPRESENTATION_WASI_FD,
            REPRESENTATION_WASI_TIMESTAMP,
            REPRESENTATION_WASI_TIMESTAMP,
            REPRESENTATION_WASI_FSTFLAGS,
        ]
        && return_type == Some(REPRESENTATION_WASI_ERRNO)
}

/// Checks the signature of the WASI `fd_pread` function:
///
/// ```Rust
/// fd_pread(fd: fd, iovs: iovec_array, offset: filesize) -> (errno, size)
/// ```
fn check_fd_pread_signature(signature: &Signature) -> bool {
    let params = signature.params();
    let return_type = signature.return_type();

    params
        == &[
            REPRESENTATION_WASI_FD,
            REPRESENTATION_WASI_IOVEC_ARRAY_BASE,
            REPRESENTATION_WASI_IOVEC_ARRAY_LENGTH,
            REPRESENTATION_WASI_FILESIZE,
            REPRESENTATION_WASM_POINTER,
        ]
        && return_type == Some(REPRESENTATION_WASI_ERRNO)
}

/// Checks the signature of the WASI `fd_prestat_get` function:
///
/// ```Rust
/// fd_prestat_get(fd: fd) -> (errno, prestat)
/// ```
fn check_fd_prestat_get_signature(signature: &Signature) -> bool {
    let params = signature.params();
    let return_type = signature.return_type();

    params == &[REPRESENTATION_WASI_FD, REPRESENTATION_WASM_POINTER]
        && return_type == Some(REPRESENTATION_WASI_ERRNO)
}

/// Checks the signature of the WASI `fd_prestat_dir_name` function:
///
/// ```Rust
/// fd_prestat_dir_name(fd: fd, path: Pointer<u8>, path_len: size) -> errno
/// ```
fn check_fd_prestat_dir_name_signature(signature: &Signature) -> bool {
    let params = signature.params();
    let return_type = signature.return_type();

    params
        == &[
            REPRESENTATION_WASI_FD,
            REPRESENTATION_WASM_POINTER,
            REPRESENTATION_WASI_SIZE,
        ]
        && return_type == Some(REPRESENTATION_WASI_ERRNO)
}

/// Checks the signature of the WASI `fd_pwrite` function:
///
/// ```Rust
/// fd_pwrite(fd: fd, iovs: ciovec_array, offset: filesize) -> (errno, size)
/// ```
fn check_fd_pwrite_signature(signature: &Signature) -> bool {
    let params = signature.params();
    let return_type = signature.return_type();

    params
        == &[
            REPRESENTATION_WASI_FD,
            REPRESENTATION_WASI_CIOVEC_ARRAY_BASE,
            REPRESENTATION_WASI_CIOVEC_ARRAY_LENGTH,
            REPRESENTATION_WASI_FILESIZE,
            REPRESENTATION_WASM_POINTER,
        ]
        && return_type == Some(REPRESENTATION_WASI_ERRNO)
}

/// Checks the signature of the WASI `fd_read` function:
///
/// ```Rust
/// fd_read(fd: fd, iovs: iovec_array) -> (errno, size)
/// ```
fn check_fd_read_signature(signature: &Signature) -> bool {
    let params = signature.params();
    let return_type = signature.return_type();

    params
        == &[
            REPRESENTATION_WASI_FD,
            REPRESENTATION_WASI_IOVEC_ARRAY_BASE,
            REPRESENTATION_WASI_IOVEC_ARRAY_LENGTH,
            REPRESENTATION_WASM_POINTER,
        ]
        && return_type == Some(REPRESENTATION_WASI_ERRNO)
}

/// Checks the signature of the WASI `fd_readdir` function:
///
/// ```Rust
/// fd_readdir(fd: fd, buf: Pointer<u8>, buf_len: size, cookie: dircookie) -> (errno, size)
/// ```
fn check_fd_readdir_signature(signature: &Signature) -> bool {
    let params = signature.params();
    let return_type = signature.return_type();

    params
        == &[
            REPRESENTATION_WASI_FD,
            REPRESENTATION_WASM_POINTER,
            REPRESENTATION_WASI_SIZE,
            REPRESENTATION_WASI_DIRCOOKIE,
            REPRESENTATION_WASM_POINTER,
        ]
        && return_type == Some(REPRESENTATION_WASI_ERRNO)
}

/// Checks the signature of the WASI `fd_renumber` function:
///
/// ```Rust
/// fd_renumber(fd: fd, to: fd) -> errno
/// ```
fn check_fd_renumber_signature(signature: &Signature) -> bool {
    let params = signature.params();
    let return_type = signature.return_type();

    params == &[REPRESENTATION_WASI_FD, REPRESENTATION_WASI_FD]
        && return_type == Some(REPRESENTATION_WASI_ERRNO)
}

/// Checks the signature of the WASI `fd_seek` function:
///
/// ```Rust
/// fd_seek(fd: fd, offset: filedelta, whence: whence) -> (errno, filesize)
/// ```
fn check_fd_seek_signature(signature: &Signature) -> bool {
    let params = signature.params();
    let return_type = signature.return_type();

    params
        == &[
            REPRESENTATION_WASI_FD,
            REPRESENTATION_WASI_FILEDELTA,
            REPRESENTATION_WASI_WHENCE,
            REPRESENTATION_WASM_POINTER,
        ]
        && return_type == Some(REPRESENTATION_WASI_ERRNO)
}

/// Checks the signature of the WASI `fd_sync` function:
///
/// ```Rust
/// fd_sync(fd: fd) -> errno
/// ```
fn check_fd_sync_signature(signature: &Signature) -> bool {
    let params = signature.params();
    let return_type = signature.return_type();

    params == &[REPRESENTATION_WASI_FD] && return_type == Some(REPRESENTATION_WASI_ERRNO)
}

/// Checks the signature of the WASI `fd_tell` function:
///
/// ```Rust
/// fd_tell(fd: fd) -> (errno, filesize)
/// ```
fn check_fd_tell_signature(signature: &Signature) -> bool {
    let params = signature.params();
    let return_type = signature.return_type();

    params == &[REPRESENTATION_WASI_FD, REPRESENTATION_WASM_POINTER]
        && return_type == Some(REPRESENTATION_WASI_ERRNO)
}

/// Checks the signature of the WASI `fd_write` function:
///
/// ```Rust
/// fd_write(fd: fd, iovs: ciovec_array) -> (errno, size)
/// ```
fn check_fd_write_signature(signature: &Signature) -> bool {
    let params = signature.params();
    let return_type = signature.return_type();

    params
        == &[
            REPRESENTATION_WASI_FD,
            REPRESENTATION_WASI_CIOVEC_ARRAY_BASE,
            REPRESENTATION_WASI_CIOVEC_ARRAY_LENGTH,
            REPRESENTATION_WASM_POINTER,
        ]
        && return_type == Some(REPRESENTATION_WASI_ERRNO)
}

/// Checks the signature of the WASI `path_create_directory` function:
///
/// ```Rust
/// path_create_directory(fd: fd, path: string) -> errno
/// ```
fn check_path_create_directory_signature(signature: &Signature) -> bool {
    let params = signature.params();
    let return_type = signature.return_type();

    params == &[REPRESENTATION_WASI_FD, REPRESENTATION_WASM_POINTER]
        && return_type == Some(REPRESENTATION_WASI_ERRNO)
}

/// Checks the signature of the WASI `path_filestat_get` function:
///
/// ```Rust
/// path_filestat_get(fd: fd, flags: lookupflags, path: string) -> (errno, filestat)
/// ```
fn check_path_filestat_get_signature(signature: &Signature) -> bool {
    let params = signature.params();
    let return_type = signature.return_type();

    params
        == &[
            REPRESENTATION_WASI_FD,
            REPRESENTATION_WASI_LOOKUP_FLAGS,
            REPRESENTATION_WASM_POINTER,
            REPRESENTATION_WASM_POINTER,
        ]
        && return_type == Some(REPRESENTATION_WASI_ERRNO)
}

/// Checks the signature of the WASI `path_filestat_set_times` function:
///
/// ```Rust
/// path_filestat_set_times(fd: fd, flags: lookupflags, path: string, atim: timestamp,
///     mtim: timestamp, fst_flags: fstflags) -> errno
/// ```
fn check_path_filestat_set_times_signature(signature: &Signature) -> bool {
    let params = signature.params();
    let return_type = signature.return_type();

    params
        == &[
            REPRESENTATION_WASI_FD,
            REPRESENTATION_WASI_LOOKUP_FLAGS,
            REPRESENTATION_WASM_POINTER,
            REPRESENTATION_WASI_TIMESTAMP,
            REPRESENTATION_WASI_TIMESTAMP,
            REPRESENTATION_WASI_FSTFLAGS,
        ]
        && return_type == Some(REPRESENTATION_WASI_ERRNO)
}

/// Checks the signature of the WASI `path_link` function:
///
/// ```Rust
/// path_link(old_fd: fd, old_flags: lookupflags, old_path: string,
///     new_fd: fd, new_path: string) -> errno
/// ```
fn check_path_link_signature(signature: &Signature) -> bool {
    let params = signature.params();
    let return_type = signature.return_type();

    params
        == &[
            REPRESENTATION_WASI_FD,
            REPRESENTATION_WASI_LOOKUP_FLAGS,
            REPRESENTATION_WASM_POINTER,
            REPRESENTATION_WASI_FD,
            REPRESENTATION_WASM_POINTER,
        ]
        && return_type == Some(REPRESENTATION_WASI_ERRNO)
}

/// Checks the signature of the WASI `path_open` function:
///
/// ```Rust
/// path_open(fd: fd, dirflags: lookupflags, path: string, oflags: oflags,
///     fs_rights_base: rights, fs_rights_inheriting: rights, fdflags: fdflags) -> (errno, fd)
/// ```
fn check_path_open_signature(signature: &Signature) -> bool {
    let params = signature.params();
    let return_type = signature.return_type();

    params
        == &[
            REPRESENTATION_WASI_FD,
            REPRESENTATION_WASI_LOOKUP_FLAGS,
            REPRESENTATION_WASM_POINTER,
            REPRESENTATION_WASM_SIZE_T,
            REPRESENTATION_WASI_OFLAGS,
            REPRESENTATION_WASI_RIGHTS,
            REPRESENTATION_WASI_RIGHTS,
            REPRESENTATION_WASI_FDFLAGS,
            REPRESENTATION_WASM_POINTER,
        ]
        && return_type == Some(REPRESENTATION_WASI_ERRNO)
}

/// Checks the signature of the WASI `path_readlink` function:
///
/// ```Rust
/// path_readlink(fd: fd, path: string, buf: Pointer<u8>,
///     buf_len: size) -> (errno, size)
/// ```
fn check_path_readlink_signature(signature: &Signature) -> bool {
    let params = signature.params();
    let return_type = signature.return_type();

    params
        == &[
            REPRESENTATION_WASI_FD,
            REPRESENTATION_WASM_POINTER,
            REPRESENTATION_WASM_POINTER,
            REPRESENTATION_WASI_SIZE,
            REPRESENTATION_WASM_POINTER,
        ]
        && return_type == Some(REPRESENTATION_WASI_ERRNO)
}

/// Checks the signature of the WASI `path_remove_directory` function:
///
/// ```Rust
/// path_remove_directory(fd: fd, path: string) -> errno
/// ```
fn check_path_remove_directory_signature(signature: &Signature) -> bool {
    let params = signature.params();
    let return_type = signature.return_type();

    params == &[REPRESENTATION_WASI_FD, REPRESENTATION_WASM_POINTER]
        && return_type == Some(REPRESENTATION_WASI_ERRNO)
}

/// Checks the signature of the WASI `path_rename` function:
///
/// ```Rust
/// path_rename(fd: fd, old_path: string, new_fd: fd, new_path: string) -> errno
/// ```
fn check_path_rename_signature(signature: &Signature) -> bool {
    let params = signature.params();
    let return_type = signature.return_type();

    params
        == &[
            REPRESENTATION_WASI_FD,
            REPRESENTATION_WASM_POINTER,
            REPRESENTATION_WASI_FD,
            REPRESENTATION_WASM_POINTER,
        ]
        && return_type == Some(REPRESENTATION_WASI_ERRNO)
}

/// Checks the signature of the WASI `path_symlink` function:
///
/// ```Rust
/// path_symlink(old_path: string, fd: fd, new_path: string) -> errno
/// ```
fn check_path_symlink_signature(signature: &Signature) -> bool {
    let params = signature.params();
    let return_type = signature.return_type();

    params
        == &[
            REPRESENTATION_WASM_POINTER,
            REPRESENTATION_WASI_FD,
            REPRESENTATION_WASM_POINTER,
        ]
        && return_type == Some(REPRESENTATION_WASI_ERRNO)
}

/// Checks the signature of the WASI `path_unlink_file` function:
///
/// ```Rust
/// path_unlink_file(fd: fd, path: string) -> errno
/// ```
fn check_path_unlink_file_signature(signature: &Signature) -> bool {
    let params = signature.params();
    let return_type = signature.return_type();

    params == &[REPRESENTATION_WASI_FD, REPRESENTATION_WASM_POINTER]
        && return_type == Some(REPRESENTATION_WASI_ERRNO)
}

/// Checks the signature of the WASI `poll_oneoff` function:
///
/// ```Rust
/// poll_oneoff(in: ConstPointer<subscription>, out: Pointer<event>,
///     nsubscription: size) -> (errno, size)
/// ```
fn check_poll_oneoff_signature(signature: &Signature) -> bool {
    let params = signature.params();
    let return_type = signature.return_type();

    params
        == &[
            REPRESENTATION_WASM_CONST_POINTER,
            REPRESENTATION_WASM_POINTER,
            REPRESENTATION_WASI_SIZE,
            REPRESENTATION_WASM_POINTER,
        ]
        && return_type == Some(REPRESENTATION_WASI_ERRNO)
}

/// Checks the signature of the WASI `proc_exit` function:
///
/// ```Rust
/// proc_exit(rval: exitcode)
/// ```
fn check_proc_exit_signature(signature: &Signature) -> bool {
    let params = signature.params();
    let return_type = signature.return_type();

    params == &[REPRESENTATION_WASI_EXITCODE] && return_type == None
}

/// Checks the signature of the WASI `proc_raise` function:
///
/// ```Rust
/// proc_raise(sig: signal) -> errno
/// ```
fn check_proc_raise_signature(signature: &Signature) -> bool {
    let params = signature.params();
    let return_type = signature.return_type();

    params == &[REPRESENTATION_WASI_SIGNAL] && return_type == Some(REPRESENTATION_WASI_ERRNO)
}

/// Checks the signature of the WASI `sched_yield` function:
///
/// ```Rust
/// sched_yield() -> errno
/// ```
fn check_sched_yield_signature(signature: &Signature) -> bool {
    let params = signature.params();
    let return_type = signature.return_type();

    params == &[] && return_type == Some(REPRESENTATION_WASI_ERRNO)
}

/// Checks the signature of the WASI `random_get` function:
///
/// ```Rust
/// random_get(buf: Pointer<u8>, buf_len: size) -> errno
/// ```
fn check_random_get_signature(signature: &Signature) -> bool {
    let params = signature.params();
    let return_type = signature.return_type();

    params == &[REPRESENTATION_WASM_POINTER, REPRESENTATION_WASI_SIZE]
        && return_type == Some(REPRESENTATION_WASI_ERRNO)
}

/// Checks the signature of the WASI `sock_recv` function:
///
/// ```Rust
/// sock_recv(fd: fd, ri_data: iovec_array, ri_flags: riflags) -> (errno, size, roflags)
/// ```
fn check_sock_recv_signature(signature: &Signature) -> bool {
    let params = signature.params();
    let return_type = signature.return_type();

    params
        == &[
            REPRESENTATION_WASI_FD,
            REPRESENTATION_WASI_IOVEC_ARRAY_BASE,
            REPRESENTATION_WASI_IOVEC_ARRAY_LENGTH,
            REPRESENTATION_WASI_RIFLAGS,
            REPRESENTATION_WASM_POINTER,
            REPRESENTATION_WASM_POINTER,
        ]
        && return_type == Some(REPRESENTATION_WASI_ERRNO)
}

/// Checks the signature of the WASI `sock_send` function:
///
/// ```Rust
/// sock_send(fd: fd, si_data: ciovec_array, si_flags: siflags) -> (errno, size)
/// ```
fn check_sock_send_signature(signature: &Signature) -> bool {
    let params = signature.params();
    let return_type = signature.return_type();

    params
        == &[
            REPRESENTATION_WASI_FD,
            REPRESENTATION_WASI_CIOVEC_ARRAY_BASE,
            REPRESENTATION_WASI_CIOVEC_ARRAY_LENGTH,
            REPRESENTATION_WASI_SIFLAGS,
            REPRESENTATION_WASM_POINTER,
        ]
        && return_type == Some(REPRESENTATION_WASI_ERRNO)
}

/// Checks the signature of the WASI `sock_shutdown` function:
///
/// ```Rust
/// sock_shutdown(fd: fd, how: sdflags) -> errno
/// ```
fn check_sock_shutdown_signature(signature: &Signature) -> bool {
    let params = signature.params();
    let return_type = signature.return_type();

    params == &[REPRESENTATION_WASI_FD, REPRESENTATION_WASI_SDFLAGS]
        && return_type == Some(REPRESENTATION_WASI_ERRNO)
}

/// Checks the function signature, `signature`, has the correct type for the
/// host call coded by `index`.
fn check_signature(index: WASIAPIName, signature: &Signature) -> bool {
    match index {
        WASIAPIName::ARGS_GET => check_args_get_signature(signature),
        WASIAPIName::ARGS_SIZES_GET => check_args_sizes_get_signature(signature),
        WASIAPIName::ENVIRON_GET => check_environ_get_signature(signature),
        WASIAPIName::ENVIRON_SIZES_GET => check_environ_sizes_get_signature(signature),
        WASIAPIName::CLOCK_RES_GET => check_clock_res_get_signature(signature),
        WASIAPIName::CLOCK_TIME_GET => check_clock_time_get_signature(signature),
        WASIAPIName::FD_ADVISE => check_fd_advise_signature(signature),
        WASIAPIName::FD_ALLOCATE => check_fd_allocate_signature(signature),
        WASIAPIName::FD_CLOSE => check_fd_close_signature(signature),
        WASIAPIName::FD_DATASYNC => check_fd_datasync_signature(signature),
        WASIAPIName::FD_FDSTAT_GET => check_fd_fdstat_get_signature(signature),
        WASIAPIName::FD_FDSTAT_SET_FLAGS => check_fd_fdstat_set_flags_signature(signature),
        WASIAPIName::FD_FDSTAT_SET_RIGHTS => check_fd_fdstat_set_rights_signature(signature),
        WASIAPIName::FD_FILESTAT_GET => check_fd_filestat_get_signature(signature),
        WASIAPIName::FD_FILESTAT_SET_SIZE => check_fd_filestat_set_size_signature(signature),
        WASIAPIName::FD_FILESTAT_SET_TIMES => check_fd_filestat_set_times_signature(signature),
        WASIAPIName::FD_PREAD => check_fd_pread_signature(signature),
        WASIAPIName::FD_PRESTAT_GET => check_fd_prestat_get_signature(signature),
        WASIAPIName::FD_PRESTAT_DIR_NAME => check_fd_prestat_dir_name_signature(signature),
        WASIAPIName::FD_PWRITE => check_fd_pwrite_signature(signature),
        WASIAPIName::FD_READ => check_fd_read_signature(signature),
        WASIAPIName::FD_READDIR => check_fd_readdir_signature(signature),
        WASIAPIName::FD_RENUMBER => check_fd_renumber_signature(signature),
        WASIAPIName::FD_SEEK => check_fd_seek_signature(signature),
        WASIAPIName::FD_SYNC => check_fd_sync_signature(signature),
        WASIAPIName::FD_TELL => check_fd_tell_signature(signature),
        WASIAPIName::FD_WRITE => check_fd_write_signature(signature),
        WASIAPIName::PATH_CREATE_DIRECTORY => check_path_create_directory_signature(signature),
        WASIAPIName::PATH_FILESTAT_GET => check_path_filestat_get_signature(signature),
        WASIAPIName::PATH_FILESTAT_SET_TIMES => check_path_filestat_set_times_signature(signature),
        WASIAPIName::PATH_LINK => check_path_link_signature(signature),
        WASIAPIName::PATH_OPEN => check_path_open_signature(signature),
        WASIAPIName::PATH_READLINK => check_path_readlink_signature(signature),
        WASIAPIName::PATH_REMOVE_DIRECTORY => check_path_remove_directory_signature(signature),
        WASIAPIName::PATH_RENAME => check_path_rename_signature(signature),
        WASIAPIName::PATH_SYMLINK => check_path_symlink_signature(signature),
        WASIAPIName::PATH_UNLINK_FILE => check_path_unlink_file_signature(signature),
        WASIAPIName::POLL_ONEOFF => check_poll_oneoff_signature(signature),
        WASIAPIName::PROC_EXIT => check_proc_exit_signature(signature),
        WASIAPIName::PROC_RAISE => check_proc_raise_signature(signature),
        WASIAPIName::SCHED_YIELD => check_sched_yield_signature(signature),
        WASIAPIName::RANDOM_GET => check_random_get_signature(signature),
        WASIAPIName::SOCK_RECV => check_sock_recv_signature(signature),
        WASIAPIName::SOCK_SEND => check_sock_send_signature(signature),
        WASIAPIName::SOCK_SHUTDOWN => check_sock_shutdown_signature(signature),
    }
}

/// Checks the signature of the module's entry point, `signature`, against the
/// templates described above for the `EntrySignature` enum type, and returns
/// an instance of that type as appropriate.
fn check_main_signature(signature: &Signature) -> EntrySignature {
    let params = signature.params();
    let return_type = signature.return_type();

    if params == [] && return_type == None {
        EntrySignature::NoParameters
    } else if params == [ValueType::I32, ValueType::I32] && return_type == Some(ValueType::I32) {
        EntrySignature::ArgvAndArgc
    } else {
        EntrySignature::NoEntryFound
    }
}

/// Finds the entry point of the WASM module, `module`, and extracts its
/// signature template.  If no entry is found returns
/// `EntrySignature::NoEntryFound`.
fn check_main(module: &ModuleInstance) -> EntrySignature {
    match module.export_by_name(WASIWrapper::ENTRY_POINT_NAME) {
        Some(ExternVal::Func(funcref)) => check_main_signature(&funcref.signature()),
        _otherwise => EntrySignature::NoEntryFound,
    }
}

/// Finds the linear memory of the WASM module, `module`, and returns it,
/// otherwise creating a fatal host error that will kill the Veracruz instance.
fn get_module_memory(module: &ModuleRef) -> Result<MemoryRef, HostProvisioningError> {
    match module.export_by_name(WASIWrapper::LINEAR_MEMORY_NAME) {
        Some(ExternVal::Memory(memoryref)) => Ok(memoryref),
        _otherwise => Err(HostProvisioningError::NoMemoryRegistered),
    }
}

////////////////////////////////////////////////////////////////////////////////
// The H-call interface.
////////////////////////////////////////////////////////////////////////////////

impl ModuleImportResolver for WASMIRuntimeState {
    /// "Resolves" a H-call by translating from a H-call name, `field_name` to
    /// the corresponding H-call code, and dispatching appropriately.
    fn resolve_func(&self, field_name: &str, signature: &Signature) -> Result<FuncRef, Error> {
        let index = WASIAPIName::try_from(field_name).map_err(|e|Error::Instantiation(format!(
                "Unknown function {} with signature: {:?}.",
                field_name, signature
        )))?;

        if !check_signature(index.clone(), signature) {
            Err(Error::Instantiation(format!(
                "Function {} has an unexpected type-signature: {:?}.",
                field_name, signature
            )))
        } else {
            Ok(FuncInstance::alloc_host(signature.clone(), index as usize))
        }
    }

    fn resolve_global(
        &self,
        field_name: &str,
        _descriptor: &GlobalDescriptor,
    ) -> Result<GlobalRef, Error> {
        Err(Error::Instantiation(field_name.to_string()))
    }

    fn resolve_memory(
        &self,
        field_name: &str,
        _descriptor: &MemoryDescriptor,
    ) -> Result<MemoryRef, Error> {
        Err(Error::Instantiation(field_name.to_string()))
    }

    fn resolve_table(
        &self,
        field_name: &str,
        _descriptor: &TableDescriptor,
    ) -> Result<TableRef, Error> {
        Err(Error::Instantiation(field_name.to_string()))
    }
}

impl Externals for WASMIRuntimeState {
    fn invoke_index(
        &mut self,
        index: usize,
        args: RuntimeArgs,
    ) -> Result<Option<RuntimeValue>, Trap> {

        let wasi_call_index = match WASIAPIName::from_u32(index as u32) {
            Some(s) => s,
            None => return mk_host_trap(FatalEngineError::UnknownHostFunction { index }),
        };

        let result = match wasi_call_index {
            WASIAPIName::ARGS_GET => self.wasi_args_get(args),
            WASIAPIName::ARGS_SIZES_GET => self.wasi_args_sizes_get(args),
            WASIAPIName::ENVIRON_GET => self.wasi_environ_get(args),
            WASIAPIName::ENVIRON_SIZES_GET => self.wasi_environ_sizes_get(args),
            WASIAPIName::CLOCK_RES_GET => self.wasi_clock_res_get(args),
            WASIAPIName::CLOCK_TIME_GET => self.wasi_clock_time_get(args),
            WASIAPIName::FD_ADVISE => self.wasi_fd_advise(args),
            WASIAPIName::FD_ALLOCATE => self.wasi_fd_allocate(args),
            WASIAPIName::FD_CLOSE => self.wasi_fd_close(args),
            WASIAPIName::FD_DATASYNC => self.wasi_fd_datasync(args),
            WASIAPIName::FD_FDSTAT_GET => self.wasi_fd_fdstat_get(args),
            WASIAPIName::FD_FDSTAT_SET_FLAGS => self.wasi_fd_fdstat_set_flags(args),
            WASIAPIName::FD_FDSTAT_SET_RIGHTS => self.wasi_fd_fdstat_set_rights(args),
            WASIAPIName::FD_FILESTAT_GET => self.wasi_fd_filestat_get(args),
            WASIAPIName::FD_FILESTAT_SET_SIZE => self.wasi_fd_filestat_set_size(args),
            WASIAPIName::FD_FILESTAT_SET_TIMES => self.wasi_fd_filestat_set_times(args),
            WASIAPIName::FD_PREAD => self.wasi_fd_pread(args),
            WASIAPIName::FD_PRESTAT_GET => self.wasi_fd_prestat_get(args),
            WASIAPIName::FD_PRESTAT_DIR_NAME => self.wasi_fd_prestat_dir_name(args),
            WASIAPIName::FD_PWRITE => self.wasi_fd_pwrite(args),
            WASIAPIName::FD_READ => self.wasi_fd_read(args),
            WASIAPIName::FD_READDIR => self.wasi_fd_readdir(args),
            WASIAPIName::FD_RENUMBER => self.wasi_fd_renumber(args),
            WASIAPIName::FD_SEEK => self.wasi_fd_seek(args),
            WASIAPIName::FD_SYNC => self.wasi_fd_sync(args),
            WASIAPIName::FD_TELL => self.wasi_fd_tell(args),
            WASIAPIName::FD_WRITE => self.wasi_fd_write(args),
            WASIAPIName::PATH_CREATE_DIRECTORY => self.wasi_path_create_directory(args),
            WASIAPIName::PATH_FILESTAT_GET => self.wasi_path_filestat_get(args),
            WASIAPIName::PATH_FILESTAT_SET_TIMES => self.wasi_path_filestat_set_times(args),
            WASIAPIName::PATH_LINK => self.wasi_path_link(args),
            WASIAPIName::PATH_OPEN => self.wasi_path_open(args),
            WASIAPIName::PATH_READLINK => self.wasi_path_readlink(args),
            WASIAPIName::PATH_REMOVE_DIRECTORY => self.wasi_path_remove_directory(args),
            WASIAPIName::PATH_RENAME => self.wasi_path_rename(args),
            WASIAPIName::PATH_SYMLINK => self.wasi_path_symlink(args),
            WASIAPIName::PATH_UNLINK_FILE => self.wasi_path_unlink_file(args),
            WASIAPIName::POLL_ONEOFF => self.wasi_poll_oneoff(args),
            WASIAPIName::PROC_EXIT => self.wasi_proc_exit(args),
            WASIAPIName::PROC_RAISE => self.wasi_proc_raise(args),
            WASIAPIName::SCHED_YIELD => self.wasi_sched_yield(args),
            WASIAPIName::RANDOM_GET => self.wasi_random_get(args),
            WASIAPIName::SOCK_RECV => self.wasi_sock_recv(args),
            WASIAPIName::SOCK_SEND => self.wasi_sock_send(args),
            WASIAPIName::SOCK_SHUTDOWN => self.wasi_sock_shutdown(args),
        };

        match result {
            Ok(return_code) => mk_error_code(return_code),
            Err(host_trap) => mk_host_trap(host_trap),
        }
    }
}

/// Functionality of the `WASMIRuntimeState` type that relies on it satisfying
/// the `Externals` and `ModuleImportResolver` constraints.
impl WASMIRuntimeState {

    /// Creates a new initial `HostProvisioningState`.
    pub fn new(
        filesystem : Arc<Mutex<FileSystem>>,
        program_name: &str,
    ) -> Self {
        Self {
            vfs : WASIWrapper::new(filesystem, Principal::Program(program_name.to_string())),
            program: Principal::NoCap,
            program_module: None,
            memory: None,
        }
    }

    /// Returns an optional reference to the WASM program module.
    #[inline]
    pub(crate) fn get_program(&self) -> Option<&ModuleRef> {
        self.program_module.as_ref()
    }

    /// Returns `Some(memory)`, for `memory` a WASM heap or "linear memory", iff
    /// a memory has been registered with the runtime state.
    #[inline]
    pub(crate) fn memory(&self) -> Option<&MemoryRef> {
        self.memory.as_ref()
    }

    #[inline]
    /// Returns the ref to the wasm memory or the ErrNo if fails.
    pub(crate) fn deref_memory(&self) -> Result<MemoryRef, FatalEngineError> {
        match &self.memory {
            Some(m) => Ok(m.clone()),
            None => Err(FatalEngineError::NoMemoryRegistered),
        }
    }

    ////////////////////////////////////////////////////////////////////////////
    // Provisioning and program execution-related material.
    ////////////////////////////////////////////////////////////////////////////

    /// Loads a compiled program into the host state.  Tries to parse `buffer`
    /// to obtain a WASM `Module` struct.  Returns an appropriate error if this
    /// fails.
    ///
    /// The provisioning process must be in the `LifecycleState::Initial` state
    /// otherwise an error is returned.  Progresses the provisioning process to
    /// the state `LifecycleState::DataSourcesLoading` or
    /// `LifecycleState::ReadyToExecute` on success, depending on how many
    /// sources of input data are expected.
    fn load_program(&mut self, buffer: &[u8]) -> Result<(), HostProvisioningError> {
        let module = Module::from_buffer(buffer)?;
        let env_resolver = wasmi::ImportsBuilder::new().with_resolver(WASIWrapper::WASI_SNAPSHOT_MODULE_NAME, self);

        let not_started_module_ref = ModuleInstance::new(&module, &env_resolver)?;
        if not_started_module_ref.has_start() {
            return Err(HostProvisioningError::InvalidWASMModule);
        }

        let module_ref = not_started_module_ref.assert_no_start();

        let linear_memory = get_module_memory(&module_ref)?;
        self.program_module = Some(module_ref);
        self.memory = Some(linear_memory);
        Ok(())
    }


    /// Invokes an exported entry point function with a given name,
    /// `export_name`, in the WASM program provisioned into the Veracruz host
    /// state.
    ///
    /// TODO: some awkwardness with the borrow checker here --- revisit.
    fn invoke_export(&mut self, export_name: &str) -> Result<Option<RuntimeValue>, Error> {
        // Eliminate this .cloned() call, if possible
        let (not_started, program_arguments) = match self.get_program().cloned() {
            None => {
                return Err(Error::Host(Box::new(
                    FatalEngineError::NoProgramModuleRegistered,
                )))
            }
            Some(not_started) => match check_main(&not_started) {
                EntrySignature::NoEntryFound => {
                    return Err(Error::Host(Box::new(FatalEngineError::NoProgramEntryPoint)))
                }
                EntrySignature::ArgvAndArgc => (
                    not_started,
                    vec![RuntimeValue::I32(0), RuntimeValue::I32(0)],
                ),
                EntrySignature::NoParameters => (not_started, Vec::new()),
            },
        };

        not_started.invoke_export(export_name, &program_arguments, self)
    }

    ////////////////////////////////////////////////////////////////////////////
    // The WASI host call implementations.
    ////////////////////////////////////////////////////////////////////////////
    
    /// Implementation of the WASI `args_get` function.  Returns a list of
    /// program arguments encoded as bytes.
    #[inline]
    pub(crate) fn args_get(&self) -> Vec<Vec<u8>> {
        self.vfs.args_get()
    }

    /// The implementation of the WASI `args_get` function.
    fn wasi_args_get(&mut self, args: RuntimeArgs) -> WASIError {
        println!("call wasi_args_get");
        if args.len() != 2 {
            return Err(FatalEngineError::bad_arguments_to_host_function(
                WASIAPIName::ARGS_GET,
            ));
        }

        //let mut argv_address: u32 = args.nth(0);
        //let mut argv_buff_address: u32 = args.nth(1);

        //for argument in self.args_get() {
            //let length = argument.len() as u32;
            //self.write_buffer(argv_address, &argument)?;
            //self.write_buffer(argv_buff_address, &u32::to_le_bytes(length))?;

            //argv_address += length;
            //argv_buff_address += 4;
        //}

        Ok(ErrNo::Success)
    }

    /// The implementation of the WASI `args_sizes_get` function.
    fn wasi_args_sizes_get(&mut self, args: RuntimeArgs) -> WASIError {
        println!("call wasi_args_sizes_get");
        //if args.len() != 2 {
            //return Err(FatalEngineError::bad_arguments_to_host_function(
                //WASI_ARGS_SIZES_GET_NAME,
            //));
        //}

        //let argc_address: u32 = args.nth(0);
        //let argv_buff_size_address: u32 = args.nth(1);

        //let (argc, argv_buff_size) = self.vfs.args_sizes_get();

        //self.write_buffer(argc_address, &u32::to_le_bytes(argc))?;
        //self.write_buffer(argv_buff_size_address, &u32::to_le_bytes(argv_buff_size))?;

        Ok(ErrNo::Success)
    }

    /// The implementation of the WASI `environ_get` function.
    fn wasi_environ_get(&mut self, args: RuntimeArgs) -> WASIError {
        println!("call wasi_environ_get");
        if args.len() != 2 {
            return Err(FatalEngineError::bad_arguments_to_host_function(
                WASIAPIName::ENVIRON_GET,
            ));
        }

        let environ_address = args.nth::<u32>(0);
        let environ_buf_address = args.nth::<u32>(1);
        Ok(self.vfs.environ_get(&mut self.deref_memory()?, environ_address, environ_buf_address))
    }

    /// The implementation of the WASI `environ_sizes_get` function.
    fn wasi_environ_sizes_get(&mut self, args: RuntimeArgs) -> WASIError {
        println!("call wasi_environ_sizes_get");
        if args.len() != 2 {
            return Err(FatalEngineError::bad_arguments_to_host_function(
                WASIAPIName::ENVIRON_SIZES_GET,
            ));
        }

        let environc_address: u32 = args.nth(0);
        let environ_buf_size_address: u32 = args.nth(1);
        Ok(self.vfs.environ_sizes_get(&mut self.deref_memory()?,environc_address, environ_buf_size_address))
    }

    /// The implementation of the WASI `clock_res_get` function.  This is not
    /// supported by Veracruz.  We write `0` as the resolution and return
    /// `ErrNo::NoSys`.
    fn wasi_clock_res_get(&mut self, args: RuntimeArgs) -> WASIError {
        println!("call wasi_clock_res_get");
        //if args.len() != 2 {
            //return Err(FatalEngineError::bad_arguments_to_host_function(
                //WASI_CLOCK_RES_GET_NAME,
            //));
        //}

        //let address: u32 = args.nth(1);

        //self.write_buffer(address, &i64::to_le_bytes(0i64))?;

        Ok(ErrNo::NoSys)
    }

    /// The implementation of the WASI `clock_time_get` function.  This is not
    /// supported by Veracruz.  We write `0` as the timestamp and return
    /// `ErrNo::NoSys`.
    fn wasi_clock_time_get(&mut self, args: RuntimeArgs) -> WASIError {
        println!("call wasi_clock_time_get");
        //if args.len() != 3 {
            //return Err(FatalEngineError::bad_arguments_to_host_function(
                //WASI_CLOCK_TIME_GET_NAME,
            //));
        //}

        //let address: u32 = args.nth(2);
        //self.write_buffer(address, &u32::to_le_bytes(0u32))?;

        Ok(ErrNo::NoSys)
    }

    /// The implementation of the WASI `fd_advise` function.
    fn wasi_fd_advise(&mut self, args: RuntimeArgs) -> WASIError {
        println!("call wasi_fd_advise");
        if args.len() != 4 {
            return Err(FatalEngineError::bad_arguments_to_host_function(
                WASIAPIName::FD_ADVISE,
            ));
        }

        let fd: Fd = args.nth::<u32>(0).into();
        let offset: FileSize = args.nth::<u64>(1);
        let len: FileSize = args.nth::<u64>(2);
        let advice: Advice = match args.nth::<u8>(3).try_into() {
            Err(_err) => return Ok(ErrNo::Inval),
            Ok(advice) => advice,
        };

        Ok(self.vfs.fd_advise(&fd, offset, len, advice))
    }

    /// The implementation of the WASI `fd_allocate` function.  This function is
    /// not supported by Veracruz so we simply return `ErrNo::NoSys`.
    fn wasi_fd_allocate(&mut self, args: RuntimeArgs) -> WASIError {
        println!("call wasi_fd_allocate");
        if args.len() != 3 {
            return Err(FatalEngineError::bad_arguments_to_host_function(
                WASIAPIName::FD_ALLOCATE,
            ));
        }

        Ok(ErrNo::NoSys)
    }

    /// The implementation of the WASI `fd_close` function.
    fn wasi_fd_close(&mut self, args: RuntimeArgs) -> WASIError {
        println!("call wasi_fd_close");
        if args.len() != 1 {
            return Err(FatalEngineError::bad_arguments_to_host_function(
                WASIAPIName::FD_CLOSE,
            ));
        }

        let fd = args.nth::<u32>(0);

        Ok(self.vfs.fd_close(fd))
    }

    /// The implementation of the WASI `fd_datasync` function.  This is not
    /// supported by Veracruz and we simply return `ErrNo::NotSup`.
    ///
    /// TODO: consider whether this should just return `ErrNo::Success`,
    /// instead.
    fn wasi_fd_datasync(&mut self, args: RuntimeArgs) -> WASIError {
        println!("call wasi_fd_datasync");
        if args.len() != 1 {
            return Err(FatalEngineError::bad_arguments_to_host_function(
                WASIAPIName::FD_DATASYNC,
            ));
        }

        Ok(ErrNo::NotSup)
    }

    /// The implementation of the WASI `fd_fdstat_get` function.
    fn wasi_fd_fdstat_get(&mut self, args: RuntimeArgs) -> WASIError {
        println!("call wasi_fd_fdstat_get");
        //if args.len() != 2 {
            //return Err(FatalEngineError::bad_arguments_to_host_function(
                //WASI_FD_FDSTAT_GET_NAME,
            //));
        //}

        //let fd: Fd = args.nth::<u32>(0).into();
        //let address: u32 = args.nth(1);

        //let result: FdStat = self.vfs.fd_fdstat_get(&fd)?;

        //self.write_buffer(address, &pack_fdstat(&result))?;

        Ok(ErrNo::Success)
    }

    /// The implementation of the WASI `fd_fdstat_set_flags` function.
    fn wasi_fd_fdstat_set_flags(&mut self, args: RuntimeArgs) -> WASIError {
        println!("call wasi_fd_fdstat_set_flags");
        if args.len() != 2 {
            return Err(FatalEngineError::bad_arguments_to_host_function(
                WASIAPIName::FD_FDSTAT_SET_FLAGS,
            ));
        }

        let fd: Fd = args.nth::<u32>(0).into();
        let flags: FdFlags = match args.nth::<u16>(1).try_into() {
            Err(_err) => return Ok(ErrNo::Inval),
            Ok(flags) => flags,
        };

        Ok(self.vfs.fd_fdstat_set_flags(&fd, flags))
    }

    /// The implementation of the WASI `fd_fdstat_set_rights` function.
    fn wasi_fd_fdstat_set_rights(&mut self, args: RuntimeArgs) -> WASIError {
        println!("call wasi_fd_fdstat_set_rights");
        if args.len() != 3 {
            return Err(FatalEngineError::bad_arguments_to_host_function(
                WASIAPIName::FD_FDSTAT_SET_RIGHTS,
            ));
        }

        let fd: Fd = args.nth::<u32>(0).into();
        let rights_base: Rights = match args.nth::<u64>(1).try_into() {
            Err(_err) => return Ok(ErrNo::Inval),
            Ok(rights) => rights,
        };
        let rights_inheriting: Rights = match args.nth::<u64>(2).try_into() {
            Err(_err) => return Ok(ErrNo::Inval),
            Ok(rights) => rights,
        };

        Ok(self.vfs.fd_fdstat_set_rights(&fd, rights_base, rights_inheriting))
    }

    /// The implementation of the WASI `fd_filestat_get` function.
    fn wasi_fd_filestat_get(&mut self, args: RuntimeArgs) -> WASIError {
        println!("call wasi_fd_filestat_get");
        //if args.len() != 2 {
            //return Err(FatalEngineError::bad_arguments_to_host_function(
                //WASI_FD_FILESTAT_GET_NAME,
            //));
        //}

        //let fd: Fd = args.nth::<u32>(0).into();
        //let address: u32 = args.nth(1);

        //let result: FileStat = self.vfs.fd_filestat_get(&fd)?;

        //self.write_buffer(address, &pack_filestat(&result))?;

        Ok(ErrNo::Success)
    }

    /// The implementation of the WASI `fd_filestat_set_size` function.
    fn wasi_fd_filestat_set_size(&mut self, args: RuntimeArgs) -> WASIError {
        println!("call wasi_fd_filestat_set_size");
        if args.len() != 2 {
            return Err(FatalEngineError::bad_arguments_to_host_function(
                WASIAPIName::FD_FILESTAT_SET_SIZE,
            ));
        }

        let fd: Fd = args.nth::<u32>(0).into();
        let size: FileSize = args.nth::<u64>(1).into();

        Ok(self.vfs.fd_filestat_set_size(&fd, size))
    }

    /// The implementation of the WASI `fd_filestat_set_times` function.  This
    /// is not supported by Veracruz and we simply return `ErrNo::NotSup`.
    fn wasi_fd_filestat_set_times(&mut self, args: RuntimeArgs) -> WASIError {
        println!("call wasi_fd_filestat_set_times");
        if args.len() != 4 {
            return Err(FatalEngineError::bad_arguments_to_host_function(
                WASIAPIName::FD_FILESTAT_SET_TIMES,
            ));
        }

        Ok(ErrNo::NotSup)
    }

    /// The implementation of the WASI `fd_pread` function.
    fn wasi_fd_pread(&mut self, args: RuntimeArgs) -> WASIError {
        println!("call wasi_fd_pread");
        if args.len() != 5 {
            return Err(FatalEngineError::bad_arguments_to_host_function(
                WASIAPIName::FD_PREAD,
            ));
        }

        //let fd: Fd = args.nth::<u32>(0).into();
        //let iovec_base: u32 = args.nth(1);
        //let iovec_length: u32 = args.nth(2);
        //let offset: FileSize = args.nth(3);
        //let address: u32 = args.nth(4);

        //let buffer = self.read_buffer(iovec_base, iovec_length as usize)?;
        //let iovec_array = unpack_iovec_array(&buffer).ok_or(ErrNo::Inval)?;

        //let mut size_written = 0;

        //for iovec in iovec_array.iter() {
            //let to_write = self.vfs.fd_pread_base(&fd, iovec.len as usize, &offset)?;
            //self.write_buffer(iovec.buf, &to_write)?;
            //size_written += iovec.len;
        //}

        //self.write_buffer(address, &u32::to_le_bytes(size_written))?;

        Ok(ErrNo::Success)
    }

    /// The implementation of the WASI `fd_prestat_get` function.
    fn wasi_fd_prestat_get(&mut self, args: RuntimeArgs) -> WASIError {
        println!("call wasi_fd_prestat_get");
        if args.len() != 2 {
            return Err(FatalEngineError::bad_arguments_to_host_function(
                WASIAPIName::FD_PRESTAT_GET,
            ));
        }

        let fd = args.nth::<u32>(0);
        let address = args.nth::<u32>(1);

        Ok(self.vfs.fd_prestat_get(&mut self.deref_memory()?,fd,address)) 
    }

    /// The implementation of the WASI `fd_prestat_dir_name` function.
    fn wasi_fd_prestat_dir_name(&mut self, args: RuntimeArgs) -> WASIError {
        println!("call wasi_fd_prestat_dir_name");
        if args.len() != 3 {
            return Err(FatalEngineError::bad_arguments_to_host_function(
                WASIAPIName::FD_PRESTAT_DIR_NAME,
            ));
        }

        let fd = args.nth::<u32>(0);
        let address = args.nth::<u32>(1);
        let size = args.nth::<u32>(2);
        Ok(self.vfs.fd_prestat_dir_name(&mut self.deref_memory()?,fd,address,size))

    }

    /// The implementation of the WASI `fd_pwrite` function.
    fn wasi_fd_pwrite(&mut self, args: RuntimeArgs) -> WASIError {
        println!("call wasi_fd_pwrite");
        //if args.len() != 5 {
            //return Err(FatalEngineError::bad_arguments_to_host_function(
                //WASI_FD_PWRITE_NAME,
            //));
        //}

        //let fd: Fd = args.nth::<u32>(0).into();
        //let iovec_base = args.nth::<u32>(1);
        //let iovec_length = args.nth::<u32>(2);
        //let filesize: FileSize = match args.nth::<u64>(3).try_into() {
            //Err(_err) => return Ok(ErrNo::Inval),
            //Ok(filesize) => filesize,
        //};
        //let address: u32 = args.nth(4);

        //let buffer = self.read_buffer(iovec_base, iovec_length as usize)?;
        //let iovec_array = unpack_iovec_array(&buffer).ok_or(ErrNo::Inval)?;

        //let scatters = self.read_iovec_scattered(&iovec_array)?;

        //let mut size_written = 0;

        //for to_write in scatters.iter().cloned() {
            //size_written += self.vfs.fd_pwrite_base(&fd, to_write, &filesize)?;
        //}

        //self.write_buffer(address, &u32::to_le_bytes(size_written))?;

        Ok(ErrNo::Success)
    }

    /// The implementation of the WASI `fd_read` function.
    fn wasi_fd_read(&mut self, args: RuntimeArgs) -> WASIError {
        println!("call wasi_fd_read");
        if args.len() != 4 {
            return Err(FatalEngineError::bad_arguments_to_host_function(
                WASIAPIName::FD_READ,
            ));
        }

        let fd = args.nth::<u32>(0);
        let iovec_base: u32 = args.nth::<u32>(1);
        let iovec_len: u32 = args.nth::<u32>(2);
        let address: u32 = args.nth::<u32>(3);
        Ok(self.vfs.fd_read(&mut self.deref_memory()?,fd, iovec_base, iovec_len, address))
    }

    /// The implementation of the WASI `fd_readdir` function.
    ///
    /// TODO: complete this.
    fn wasi_fd_readdir(&mut self, args: RuntimeArgs) -> WASIError {
        println!("call wasi_fd_readdir");
        //if args.len() != 5 {
            //return Err(FatalEngineError::bad_arguments_to_host_function(
                //WASI_FD_READDIR_NAME,
            //));
        //}

        //let fd: Fd = args.nth::<u32>(0).into();
        //let dirent_base: u32 = args.nth::<u32>(1);
        //let dirent_length: u32 = args.nth::<u32>(2);
        //let cookie = match args.nth::<u32>(3).try_into() {
            //Err(_err) => return Ok(ErrNo::Inval),
            //Ok(cookie) => cookie,
        //};
        //let address: u32 = args.nth(4);

        //let dirents = self.vfs.fd_readdir(&fd, &cookie)?;

        //let mut size_written = 0u32;

        //for dirent in dirents.iter() {
            //let packed = pack_dirent(dirent);

            //if (size_written as usize) <= (dirent_length as usize) - packed.len() {
                //self.write_buffer(dirent_base + size_written, &packed)?;
                //size_written += packed.len() as u32;
            //} else {
                //let diff = size_written - dirent_length;
                //let packed = &packed[0..diff as usize];
                //self.write_buffer(dirent_base + size_written, packed)?;
                //size_written += diff;
                //break;
            //}
        //}

        //self.write_buffer(address, &u32::to_le_bytes(size_written))?;

        Ok(ErrNo::Success)
    }

    /// The implementation of the WASI `fd_renumber` function.
    fn wasi_fd_renumber(&mut self, args: RuntimeArgs) -> WASIError {
        println!("call wasi_fd_renumber");
        if args.len() != 2 {
            return Err(FatalEngineError::bad_arguments_to_host_function(
                WASIAPIName::FD_RENUMBER,
            ));
        }

        let old_fd: Fd = args.nth::<u32>(0).into();
        let new_fd: Fd = args.nth::<u32>(1).into();

        Ok(self.vfs.fd_renumber(&old_fd, new_fd))
    }

    /// The implementation of the WASI `fd_seek` function.
    fn wasi_fd_seek(&mut self, args: RuntimeArgs) -> WASIError {
        println!("call wasi_fd_seek");
        //if args.len() != 4 {
            //return Err(FatalEngineError::bad_arguments_to_host_function(
                //WASI_FD_SEEK_NAME,
            //));
        //}

        //let fd: Fd = args.nth::<u32>(0).into();
        //let offset: FileDelta = args.nth::<i64>(1);
        //let whence: Whence = match args.nth::<u8>(2).try_into() {
            //Ok(whence) => whence,
            //Err(_err) => return Ok(ErrNo::Inval),
        //};
        //let address: u32 = args.nth(3);

        //let result = self.vfs.fd_seek(&fd, offset, whence)?;

        //self.write_buffer(address, &u64::to_le_bytes(result))?;

        Ok(ErrNo::Success)
    }

    /// The implementation of the WASI `fd_sync` function.  This is not
    /// supported by Veracruz.  We simply return `ErrNo::NotSup`.
    ///
    /// TODO: consider whether this should just return `ErrNo::Success`,
    /// instead.
    fn wasi_fd_sync(&mut self, args: RuntimeArgs) -> WASIError {
        println!("call wasi_fd_sync");
        if args.len() != 1 {
            return Err(FatalEngineError::bad_arguments_to_host_function(
                WASIAPIName::FD_SEEK,
            ));
        }

        Ok(ErrNo::NotSup)
    }

    /// The implementation of the WASI `fd_tell` function.
    fn wasi_fd_tell(&mut self, args: RuntimeArgs) -> WASIError {
        println!("call wasi_fd_tell");
        //if args.len() != 2 {
            //return Err(FatalEngineError::bad_arguments_to_host_function(
                //WASI_FD_TELL_NAME,
            //));
        //}

        //let fd: Fd = args.nth::<u32>(0).into();
        //let address: u32 = args.nth(1);

        //let result = self.vfs.fd_tell(&fd)?.clone();

        //self.write_buffer(address, &u64::to_le_bytes(result))?;

        Ok(ErrNo::Success)
    }

    /// The implementation of the WASI `fd_write` function.
    fn wasi_fd_write(&mut self, args: RuntimeArgs) -> WASIError {
        println!("call wasi_fd_write");
        if args.len() != 4 {
            return Err(FatalEngineError::bad_arguments_to_host_function(
                WASIAPIName::FD_WRITE,
            ));
        }

        let fd = args.nth::<u32>(0);
        let iovec_base = args.nth::<u32>(1);
        let iovec_len = args.nth::<u32>(2);
        let address = args.nth::<u32>(3);
        println!("wasi_fd_write para: fd {:?} iovec_base {:?} iovec_len {:?} address {:?}", fd,iovec_base,iovec_len,address);
        Ok(self.vfs.fd_write(&mut self.deref_memory()?,fd,iovec_base,iovec_len,address))
    }

    /// The implementation of the WASI `path_create_directory` function.
    fn wasi_path_create_directory(&mut self, args: RuntimeArgs) -> WASIError {
        println!("call wasi_path_create_directory");
        //if args.len() != 2 {
            //return Err(FatalEngineError::bad_arguments_to_host_function(
                //WASI_PATH_CREATE_DIRECTORY_NAME,
            //));
        //}

        //let fd: Fd = args.nth::<u32>(0).into();
        //let path_address: u32 = args.nth::<u32>(1);

        ////TODO: change !!!!!
        //let path = self.read_cstring(path_address,1)?;

        //Ok(self.vfs.path_create_directory(&fd, path))
        Ok(ErrNo::NotSup)
    }

    /// The implementation of the WASI `path_filestat_get` function.
    fn wasi_path_filestat_get(&mut self, args: RuntimeArgs) -> WASIError {
        println!("call wasi_path_filestat_get");
        //if args.len() != 4 {
            //return Err(FatalEngineError::bad_arguments_to_host_function(
                //WASI_PATH_FILESTAT_GET_NAME,
            //));
        //}

        //let fd: Fd = args.nth::<u32>(0).into();
        //let flags: LookupFlags = match args.nth::<u32>(1).try_into() {
            //Ok(flags) => flags,
            //Err(_err) => return Ok(ErrNo::Inval),
        //};
        //let path_address = args.nth::<u32>(2);
        ////TODO: change !!!!!
        //let path = self.read_cstring(path_address,1)?;

        //let address = args.nth::<u32>(3);

        //let result = self.vfs.path_filestat_get(&fd, &flags, &path)?;

        //self.write_buffer(address, &pack_filestat(&result))?;

        Ok(ErrNo::Success)
    }

    /// The implementation of the WASI `path_filestat_set_times` function.  This
    /// is not supported by Veracruz.  We simply return `ErrNo::NotSup`.
    fn wasi_path_filestat_set_times(&mut self, args: RuntimeArgs) -> WASIError {
        println!("call wasi_path_filestat_set_times");
        if args.len() != 6 {
            return Err(FatalEngineError::bad_arguments_to_host_function(
                WASIAPIName::PATH_FILESTAT_SET_TIMES,
            ));
        }

        Ok(ErrNo::NotSup)
    }

    /// The implementation of the WASI `path_readlink` function.  This
    /// is not supported by Veracruz.  We simply return `ErrNo::NotSup`.
    fn wasi_path_link(&mut self, args: RuntimeArgs) -> WASIError {
        println!("call wasi_path_link");
        if args.len() != 5 {
            return Err(FatalEngineError::bad_arguments_to_host_function(
                WASIAPIName::PATH_LINK,
            ));
        }

        Ok(ErrNo::NotSup)
    }

    /// The implementation of the WASI `path_open` function.
    fn wasi_path_open(&mut self, args: RuntimeArgs) -> WASIError {
        println!("call wasi_path_open");
        if args.len() != 9 {
            return Err(FatalEngineError::bad_arguments_to_host_function(
                WASIAPIName::PATH_OPEN,
            ));
        }

        let fd = args.nth::<u32>(0);
        let dirflags = args.nth::<u32>(1);
        let path_address = args.nth::<u32>(2);
        let path_length = args.nth::<u32>(3);
        let oflags = args.nth::<u32>(4);
        let fs_rights_base = args.nth::<u64>(5);
        let fs_rights_inheriting = args.nth::<u64>(6);
        let fd_flags = args.nth::<u32>(7);
        let address = args.nth::<u32>(8);
        Ok(self.vfs.path_open(
            &mut self.deref_memory()?,
            fd,
            dirflags,
            path_address,
            path_length,
            oflags,
            fs_rights_base,
            fs_rights_inheriting,
            fd_flags,
            address,
        ))
    }

    /// The implementation of the WASI `path_readlink` function.  This
    /// is not supported by Veracruz.  We simply return `ErrNo::NotSup`.
    ///
    /// TODO: re-assess whether we want to support this.
    fn wasi_path_readlink(&mut self, args: RuntimeArgs) -> WASIError {
        println!("call wasi_path_readlink");
        if args.len() != 5 {
            return Err(FatalEngineError::bad_arguments_to_host_function(
                WASIAPIName::PATH_READLINK,
            ));
        }

        Ok(ErrNo::NotSup)
    }

    /// The implementation of the WASI `path_remove_directory` function.
    fn wasi_path_remove_directory(&mut self, args: RuntimeArgs) -> WASIError {
        println!("call wasi_path_remove_directory");
        //if args.len() != 2 {
            //return Err(FatalEngineError::bad_arguments_to_host_function(
                //WASI_PATH_REMOVE_DIRECTORY_NAME,
            //));
        //}

        //let fd: Fd = args.nth::<u32>(0).into();
        //let path_address: u32 = args.nth::<u32>(1).into();

        ////TODO: change !!!!!!!
        //let path = self.read_cstring(path_address,1)?;

        //Ok(self.vfs.path_remove_directory(&fd, &path))
        Ok(ErrNo::NotSup)
    }

    /// The implementation of the WASI `path_rename` function.
    fn wasi_path_rename(&mut self, args: RuntimeArgs) -> WASIError {
        println!("call wasi_path_rename");
        //if args.len() != 4 {
            //return Err(FatalEngineError::bad_arguments_to_host_function(
                //WASI_PATH_RENAME_NAME,
            //));
        //}

        //let old_fd: Fd = args.nth::<u32>(0).into();
        //let old_path_address: u32 = args.nth::<u32>(1);
        //let new_fd: Fd = args.nth::<u32>(2).into();
        //let new_path_address = args.nth::<u32>(3);

        ////TODO: change !!!!!!!
        //let old_path = self.read_cstring(old_path_address,1)?;
        //let new_path = self.read_cstring(new_path_address,1)?;

        //Ok(self.vfs.path_rename(&old_fd, &old_path, &new_fd, new_path))
        Ok(ErrNo::NotSup)
    }

    /// The implementation of the WASI `path_symlink` function.  This is not
    /// supported by Veracruz.  We simply return `ErrNo::NotSup`.
    ///
    /// TODO: re-assess whether we want to support this.
    fn wasi_path_symlink(&mut self, args: RuntimeArgs) -> WASIError {
        println!("call wasi_path_symlink");
        if args.len() != 3 {
            return Err(FatalEngineError::bad_arguments_to_host_function(
                WASIAPIName::PATH_SYMLINK,
            ));
        }

        Ok(ErrNo::NotSup)
    }

    /// The implementation of the WASI `path_unlink_file` function.  This is not
    /// supported by Veracruz.  We simply return `ErrNo::NotSup`.
    ///
    /// TODO: re-assess whether we want to support this.
    fn wasi_path_unlink_file(&mut self, args: RuntimeArgs) -> WASIError {
        println!("call wasi_path_unlink_file");
        if args.len() != 2 {
            return Err(FatalEngineError::bad_arguments_to_host_function(
                WASIAPIName::PATH_UNLINK_FILE,
            ));
        }

        Ok(ErrNo::NotSup)
    }

    /// The implementation of the WASI `poll_oneoff` function.  This is not
    /// supported by Veracruz.  We write `0` as the number of subscriptions that
    /// were registered and return `ErrNo::NotSup`.
    fn wasi_poll_oneoff(&mut self, args: RuntimeArgs) -> WASIError {
        println!("call wasi_poll_oneoff");
        //if args.len() != 4 {
            //return Err(FatalEngineError::bad_arguments_to_host_function(
                //WASI_POLL_ONEOFF_NAME,
            //));
        //}

        //let address: u32 = args.nth(3);
        //self.write_buffer(address, &u32::to_le_bytes(0u32))?;

        Ok(ErrNo::NotSup)
    }

    /// The implementation of the WASI `proc_raise` function.  This halts
    /// termination of the interpreter, returning an error code.  No return code
    /// is returned to the calling WASM process.
    fn wasi_proc_exit(&mut self, args: RuntimeArgs) -> WASIError {
        println!("call wasi_proc_exit");
        if args.len() != 1 {
            return Err(FatalEngineError::bad_arguments_to_host_function(
                WASIAPIName::PROC_EXIT,
            ));
        }

        let exit_code: i32 = args.nth(0);

        // NB: this gets routed to the runtime, not the calling WASM program,
        // for handling.
        Err(FatalEngineError::EarlyExit(exit_code))
    }

    /// The implementation of the WASI `proc_raise` function.  This is not
    /// supported by Veracruz and implemented as a no-op, simply returning
    /// `ErrNo::NotSup`.
    fn wasi_proc_raise(&mut self, args: RuntimeArgs) -> WASIError {
        println!("proc exit is called");
        if args.len() != 1 {
            return Err(FatalEngineError::bad_arguments_to_host_function(
                WASIAPIName::PROC_RAISE,
            ));
        }

        Ok(ErrNo::NotSup)
    }

    /// The implementation of the WASI `sched_yield` function.  This is
    /// not supported by Veracruz and simply returns `ErrNo::NotSup`.
    fn wasi_sched_yield(&mut self, args: RuntimeArgs) -> WASIError {
        println!("call wasi_sched_yield");
        if args.len() != 0 {
            return Err(FatalEngineError::bad_arguments_to_host_function(
                WASIAPIName::SCHED_YIELD,
            ));
        }

        Ok(ErrNo::NotSup)
    }

    /// The implementation of the WASI `random_get` function, which calls
    /// through to the random number generator provided by `platform_services`.
    /// Returns `ErrNo::Success` on successful execution of the random number
    /// generator, or `ErrNo::NoSys` if a random number generator is not
    /// available on this platform, or if the call to the random number
    /// generator fails for some reason.
    fn wasi_random_get(&mut self, args: RuntimeArgs) -> WASIError {
        println!("call wasi_random_get");
        //if args.len() != 2 {
            //return Err(FatalEngineError::bad_arguments_to_host_function(
                //WASI_RANDOM_GET_NAME,
            //));
        //}

        //let address: u32 = args.nth(0);
        //let size: u32 = args.nth(1);
        //let mut buffer = vec![0; size as usize];

        //if let result::Result::Success = getrandom(&mut buffer) {
            //self.write_buffer(address, &buffer)?;

            //Ok(ErrNo::Success)
        //} else {
            //Ok(ErrNo::NoSys)
        //}

        Ok(ErrNo::Success)
    }

    /// The implementation of the WASI `sock_send` function.  This is not
    /// supported by Veracruz and returns `ErrNo::NotSup`, writing back
    /// `0` as the length of the transmission.
    fn wasi_sock_send(&mut self, args: RuntimeArgs) -> WASIError {
        println!("call wasi_sock_send");
        //if args.len() != 5 {
            //return Err(FatalEngineError::bad_arguments_to_host_function(
                //WASI_SOCK_SEND_NAME,
            //));
        //}

        //let address = args.nth(4);
        //self.write_buffer(address, &u32::to_le_bytes(0u32))?;

        Ok(ErrNo::NotSup)
    }

    /// The implementation of the WASI `sock_recv` function.  This is not
    /// supported by Veracruz and returns `ErrNo::NotSup`, writing back
    /// `0` as the length of the transmission.
    fn wasi_sock_recv(&mut self, args: RuntimeArgs) -> WASIError {
        println!("call wasi_sock_recv");
        //if args.len() != 6 {
            //return Err(FatalEngineError::bad_arguments_to_host_function(
                //WASI_SOCK_RECV_NAME,
            //));
        //}

        //let datalen_address: u32 = args.nth(3);
        //let flags_address: u32 = args.nth(4);

        //self.write_buffer(datalen_address, &u32::to_le_bytes(0u32))?;
        //self.write_buffer(flags_address, &u16::to_le_bytes(0u16))?;

        Ok(ErrNo::NotSup)
    }

    /// The implementation of the WASI `sock_shutdown` function.  This is
    /// not supported by Veracruz and simply returns `ErrNo::NotSup`.
    fn wasi_sock_shutdown(&mut self, args: RuntimeArgs) -> WASIError {
        println!("call wasi_sock_shutdown");
        if args.len() != 2 {
            return Err(FatalEngineError::bad_arguments_to_host_function(
                WASIAPIName::SOCK_SHUTDOWN,
            ));
        }

        Ok(ErrNo::NotSup)
    }
}

////////////////////////////////////////////////////////////////////////////////
// The ExecutionEngine trait implementation.
////////////////////////////////////////////////////////////////////////////////

/// The `WASMIRuntimeState` implements everything needed to create a
/// compliant instance of `ExecutionEngine`.
impl ExecutionEngine for WASMIRuntimeState {

    /// Executes the entry point of the WASM program provisioned into the
    /// Veracruz host.
    ///
    /// Returns an error if no program is registered, the program registered
    /// does not have an appropriate entry point, or if the machine is not
    /// in the `LifecycleState::ReadyToExecute` state prior to being called.
    ///
    /// Also returns an error if the WASM program or the Veracruz instance
    /// create a runtime trap during program execution (e.g. if the program
    /// executes an abort instruction, or passes bad parameters to the Veracruz
    /// host).
    ///
    /// Otherwise, returns the return value of the entry point function of the
    /// program, along with a host state capturing the result of the program's
    /// execution.
    fn invoke_entry_point(&mut self, file_name: &str) -> Result<EngineReturnCode, FatalEngineError> {
        //TODO change error type
        let program = self.vfs.read_file_by_filename(file_name)?;
        self.load_program(program.as_slice())?;
        self.program = Principal::Program(file_name.to_string());

        match self.invoke_export(WASIWrapper::ENTRY_POINT_NAME) {
            Ok(None) => {
                // TODO ADD correct return
                EngineReturnCode::try_from(0)
            }
            Ok(Some(_)) => {
                Err(FatalEngineError::ReturnedCodeError)
            }
            Err(Error::Trap(trap)) => {
                Err(FatalEngineError::WASMITrapError(trap))
            }
            Err(err) => {
                Err(FatalEngineError::WASMIError(err))
            }
        }
    }
}

////////////////////////////////////////////////////////////////////////////////
// Utility functions.
////////////////////////////////////////////////////////////////////////////////

/// Utility function which simplifies building a serialized Veracruz error code
/// to be passed back to the running WASM program executing on the WASMI engine.
#[inline]
pub(crate) fn mk_error_code<T>(e: ErrNo) -> Result<Option<RuntimeValue>, T> {
    Ok(Some(RuntimeValue::I32((e as i16).into())))
}

/// Utility function which simplifies building a Veracruz host trap.
#[inline]
pub(crate) fn mk_host_trap<T>(trap: FatalEngineError) -> Result<T, Trap> {
    Err(Trap::new(TrapKind::Host(Box::new(trap))))
}

