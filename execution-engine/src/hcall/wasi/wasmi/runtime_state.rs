//! An implementation of the Chihuahua runtime state for WASMI.
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Copyright
//!
//! See the file `LICENSE.markdown` in the Veracruz root directory for licensing
//! and copyright information.

use super::error::{mk_error_code, mk_host_trap};
use crate::hcall::common::{
    sha_256_digest, Chihuahua, EntrySignature, LifecycleState, ProvisioningError, RuntimePanic,
    RuntimeState, WASIError, WASI_ARGS_GET_NAME, WASI_ARGS_SIZES_GET_NAME, WASI_CLOCK_RES_GET_NAME,
    WASI_CLOCK_TIME_GET_NAME, WASI_ENVIRON_GET_NAME, WASI_ENVIRON_SIZES_GET_NAME,
    WASI_FD_ADVISE_NAME, WASI_FD_ALLOCATE_NAME, WASI_FD_CLOSE_NAME, WASI_FD_DATASYNC_NAME,
    WASI_FD_FDSTAT_GET_NAME, WASI_FD_FDSTAT_SET_FLAGS_NAME, WASI_FD_FDSTAT_SET_RIGHTS_NAME,
    WASI_FD_FILESTAT_GET_NAME, WASI_FD_FILESTAT_SET_SIZE_NAME, WASI_FD_FILESTAT_SET_TIMES_NAME,
    WASI_FD_PREAD_NAME, WASI_FD_PRESTAT_DIR_NAME_NAME, WASI_FD_PRESTAT_GET_NAME,
    WASI_FD_PWRITE_NAME, WASI_FD_READDIR_NAME, WASI_FD_READ_NAME, WASI_FD_RENUMBER_NAME,
    WASI_FD_SEEK_NAME, WASI_FD_SYNC_NAME, WASI_FD_TELL_NAME, WASI_FD_WRITE_NAME,
    WASI_PATH_CREATE_DIRECTORY_NAME, WASI_PATH_FILESTAT_GET_NAME,
    WASI_PATH_FILESTAT_SET_TIMES_NAME, WASI_PATH_LINK_NAME, WASI_PATH_OPEN_NAME,
    WASI_PATH_READLINK_NAME, WASI_PATH_REMOVE_DIRECTORY_NAME, WASI_PATH_RENAME_NAME,
    WASI_PATH_SYMLINK_NAME, WASI_PATH_UNLINK_FILE_NAME, WASI_POLL_ONEOFF_NAME, WASI_PROC_EXIT_NAME,
    WASI_PROC_RAISE_NAME, WASI_RANDOM_GET_NAME, WASI_SCHED_YIELD_NAME, WASI_SOCK_RECV_NAME,
    WASI_SOCK_SEND_NAME, WASI_SOCK_SHUTDOWN_NAME,
};
use platform_services::{getrandom, result};
use std::{convert::TryFrom, mem::size_of};
use wasi_types::{Advice, ErrNo, Fd, FdFlags, FdStat, FileSize, FileStat, IoVec, Rights, Size};
use wasmi::{
    Error, ExternVal, Externals, FuncInstance, FuncRef, GlobalDescriptor, GlobalRef,
    LittleEndianConvert, MemoryDescriptor, MemoryRef, Module, ModuleImportResolver, ModuleInstance,
    ModuleRef, RuntimeArgs, RuntimeValue, Signature, TableDescriptor, TableRef, Trap, ValueType,
};
use std::convert::TryInto;

////////////////////////////////////////////////////////////////////////////////
// The WASMI host provisioning state.
////////////////////////////////////////////////////////////////////////////////

/// The WASMI runtime state: the `RuntimeState` with the `Module` and `Memory`
/// type-variables specialised to WASMI's `ModuleRef` and `MemoryRef` type.
pub(crate) type WASMIRuntimeState = RuntimeState<ModuleRef, MemoryRef>;

////////////////////////////////////////////////////////////////////////////////
// Constants.
////////////////////////////////////////////////////////////////////////////////

/// The name of the WASM program's entry point.
const ENTRY_POINT_NAME: &str = "main";
/// The name of the WASM program's linear memory.
const LINEAR_MEMORY_NAME: &str = "memory";
/// The name of the containing module for all WASI imports.
const WASI_SNAPSHOT_MODULE_NAME: &str = "wasi_snapshot_preview1";

/// Index of the WASI `args_get` function.
const WASI_ARGS_GET_INDEX: usize = 0;
/// Index of the WASI `args_get` function.
const WASI_ARGS_SIZES_GET_INDEX: usize = 1;
/// Index of the WASI `environ_get` function.
const WASI_ENVIRON_GET_INDEX: usize = 2;
/// Index of the WASI `environ_sizes_get` function.
const WASI_ENVIRON_SIZES_GET_INDEX: usize = 3;
/// Index of the WASI `clock_res_get` function.
const WASI_CLOCK_RES_GET_INDEX: usize = 4;
/// Index of the WASI `clock_time_get` function.
const WASI_CLOCK_TIME_GET_INDEX: usize = 5;
/// Index of the WASI `fd_advise` function.
const WASI_FD_ADVISE_INDEX: usize = 6;
/// Index of the WASI `fd_allocate` function.
const WASI_FD_ALLOCATE_INDEX: usize = 7;
/// Index of the WASI `fd_close` function.
const WASI_FD_CLOSE_INDEX: usize = 8;
/// Index of the WASI `fd_datasync` function.
const WASI_FD_DATASYNC_INDEX: usize = 9;
/// Index of the WASI `fd_fdstat_get` function.
const WASI_FD_FDSTAT_GET_INDEX: usize = 10;
/// Index of the WASI `fd_filestat_set_flags` function.
const WASI_FD_FDSTAT_SET_FLAGS_INDEX: usize = 11;
/// Index of the WASI `fd_filestat_set_rights` function.
const WASI_FD_FDSTAT_SET_RIGHTS_INDEX: usize = 12;
/// Index of the WASI `fd_filestat_get` function.
const WASI_FD_FILESTAT_GET_INDEX: usize = 13;
/// Index of the WASI `fd_filestat_set_size` function.
const WASI_FD_FILESTAT_SET_SIZE_INDEX: usize = 14;
/// Index of the WASI `fd_filestat_set_times` function.
const WASI_FD_FILESTAT_SET_TIMES_INDEX: usize = 15;
/// Index of the WASI `fd_pread` function.
const WASI_FD_PREAD_INDEX: usize = 16;
/// Index of the WASI `fd_prestat_get_name` function.
const WASI_FD_PRESTAT_GET_INDEX: usize = 17;
/// Index of the WASI `fd_prestat_dir_name` function.
const WASI_FD_PRESTAT_DIR_NAME_INDEX: usize = 18;
/// Index of the WASI `fd_pwrite` function.
const WASI_FD_PWRITE_INDEX: usize = 19;
/// Index of the WASI `fd_read` function.
const WASI_FD_READ_INDEX: usize = 20;
/// Index of the WASI `fd_readdir` function.
const WASI_FD_READDIR_INDEX: usize = 21;
/// Index of the WASI `fd_renumber` function.
const WASI_FD_RENUMBER_INDEX: usize = 22;
/// Index of the WASI `fd_seek` function.
const WASI_FD_SEEK_INDEX: usize = 23;
/// Index of the WASI `fd_sync` function.
const WASI_FD_SYNC_INDEX: usize = 24;
/// Index of the WASI `fd_tell` function.
const WASI_FD_TELL_INDEX: usize = 25;
/// Index of the WASI `fd_write` function.
const WASI_FD_WRITE_INDEX: usize = 26;
/// Index of the WASI `path_crate_directory` function.
const WASI_PATH_CREATE_DIRECTORY_INDEX: usize = 27;
/// Index of the WASI `path_filestat_get` function.
const WASI_PATH_FILESTAT_GET_INDEX: usize = 28;
/// Index of the WASI `path_filestat_set_times` function.
const WASI_PATH_FILESTAT_SET_TIMES_INDEX: usize = 29;
/// Index of the WASI `path_link` function.
const WASI_PATH_LINK_INDEX: usize = 30;
/// Index of the WASI `path_open` function.
const WASI_PATH_OPEN_INDEX: usize = 31;
/// Index of the WASI `path_readlink` function.
const WASI_PATH_READLINK_INDEX: usize = 32;
/// Index of the WASI `path_remove_directory` function.
const WASI_PATH_REMOVE_DIRECTORY_INDEX: usize = 33;
/// Index of the WASI `path_rename` function.
const WASI_PATH_RENAME_INDEX: usize = 34;
/// Index of the WASI `path_symlink` function.
const WASI_PATH_SYMLINK_INDEX: usize = 35;
/// Index of the WASI `path_unlink_file` function.
const WASI_PATH_UNLINK_FILE_INDEX: usize = 36;
/// Index of the WASI `poll_oneoff` function.
const WASI_POLL_ONEOFF_INDEX: usize = 37;
/// Index of the WASI `proc_exit` function.
const WASI_PROC_EXIT_INDEX: usize = 38;
/// Index of the WASI `proc_raise` function.
const WASI_PROC_RAISE_INDEX: usize = 39;
/// Index of the WASI `sched_yield` function.
const WASI_SCHED_YIELD_INDEX: usize = 40;
/// Index of the WASI `random_get` function.
const WASI_RANDOM_GET_INDEX: usize = 41;
/// Index of the WASI `sock_recv` function.
const WASI_SOCK_RECV_INDEX: usize = 42;
/// Index of the WASI `sock_send` function.
const WASI_SOCK_SEND_INDEX: usize = 43;
/// Index of the WASI `sock_shutdown` function.
const WASI_SOCK_SHUTDOWN_INDEX: usize = 44;

/// The representation type of the WASI `Advice` type.
const REPRESENTATION_WASI_ADVICE: ValueType = ValueType::I32;
/// The representation type of the WASI `CIOVecArray` type.
const REPRESENTATION_WASI_CIOVEC_ARRAY: ValueType = ValueType::I64;
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
/// The representation type of the WASI `IOVecArray` type.
const REPRESENTATION_WASI_IOVEC_ARRAY: ValueType = ValueType::I64;
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
            REPRESENTATION_WASI_IOVEC_ARRAY,
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
            REPRESENTATION_WASI_CIOVEC_ARRAY,
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
            REPRESENTATION_WASI_IOVEC_ARRAY,
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
            REPRESENTATION_WASI_CIOVEC_ARRAY,
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
            REPRESENTATION_WASI_IOVEC_ARRAY,
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
            REPRESENTATION_WASI_CIOVEC_ARRAY,
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
fn check_signature(index: usize, signature: &Signature) -> bool {
    match index {
        WASI_ARGS_GET_INDEX => check_args_get_signature(signature),
        WASI_ARGS_SIZES_GET_INDEX => check_args_sizes_get_signature(signature),
        WASI_ENVIRON_GET_INDEX => check_environ_get_signature(signature),
        WASI_ENVIRON_SIZES_GET_INDEX => check_environ_sizes_get_signature(signature),
        WASI_CLOCK_RES_GET_INDEX => check_clock_res_get_signature(signature),
        WASI_CLOCK_TIME_GET_INDEX => check_clock_time_get_signature(signature),
        WASI_FD_ADVISE_INDEX => check_fd_advise_signature(signature),
        WASI_FD_ALLOCATE_INDEX => check_fd_allocate_signature(signature),
        WASI_FD_CLOSE_INDEX => check_fd_close_signature(signature),
        WASI_FD_DATASYNC_INDEX => check_fd_datasync_signature(signature),
        WASI_FD_FDSTAT_GET_INDEX => check_fd_fdstat_get_signature(signature),
        WASI_FD_FDSTAT_SET_FLAGS_INDEX => check_fd_fdstat_set_flags_signature(signature),
        WASI_FD_FDSTAT_SET_RIGHTS_INDEX => check_fd_fdstat_set_rights_signature(signature),
        WASI_FD_FILESTAT_GET_INDEX => check_fd_filestat_get_signature(signature),
        WASI_FD_FILESTAT_SET_SIZE_INDEX => check_fd_filestat_set_size_signature(signature),
        WASI_FD_FILESTAT_SET_TIMES_INDEX => check_fd_filestat_set_times_signature(signature),
        WASI_FD_PREAD_INDEX => check_fd_pread_signature(signature),
        WASI_FD_PRESTAT_GET_INDEX => check_fd_prestat_get_signature(signature),
        WASI_FD_PRESTAT_DIR_NAME_INDEX => check_fd_prestat_dir_name_signature(signature),
        WASI_FD_PWRITE_INDEX => check_fd_pwrite_signature(signature),
        WASI_FD_READ_INDEX => check_fd_read_signature(signature),
        WASI_FD_READDIR_INDEX => check_fd_readdir_signature(signature),
        WASI_FD_RENUMBER_INDEX => check_fd_renumber_signature(signature),
        WASI_FD_SEEK_INDEX => check_fd_seek_signature(signature),
        WASI_FD_SYNC_INDEX => check_fd_sync_signature(signature),
        WASI_FD_TELL_INDEX => check_fd_tell_signature(signature),
        WASI_FD_WRITE_INDEX => check_fd_write_signature(signature),
        WASI_PATH_CREATE_DIRECTORY_INDEX => check_path_create_directory_signature(signature),
        WASI_PATH_FILESTAT_GET_INDEX => check_path_filestat_get_signature(signature),
        WASI_PATH_FILESTAT_SET_TIMES_INDEX => check_path_filestat_set_times_signature(signature),
        WASI_PATH_LINK_INDEX => check_path_link_signature(signature),
        WASI_PATH_OPEN_INDEX => check_path_open_signature(signature),
        WASI_PATH_READLINK_INDEX => check_path_readlink_signature(signature),
        WASI_PATH_REMOVE_DIRECTORY_INDEX => check_path_remove_directory_signature(signature),
        WASI_PATH_RENAME_INDEX => check_path_rename_signature(signature),
        WASI_PATH_SYMLINK_INDEX => check_path_symlink_signature(signature),
        WASI_PATH_UNLINK_FILE_INDEX => check_path_unlink_file_signature(signature),
        WASI_POLL_ONEOFF_INDEX => check_poll_oneoff_signature(signature),
        WASI_PROC_EXIT_INDEX => check_proc_exit_signature(signature),
        WASI_PROC_RAISE_INDEX => check_proc_raise_signature(signature),
        WASI_SCHED_YIELD_INDEX => check_sched_yield_signature(signature),
        WASI_RANDOM_GET_INDEX => check_random_get_signature(signature),
        WASI_SOCK_RECV_INDEX => check_sock_recv_signature(signature),
        WASI_SOCK_SEND_INDEX => check_sock_send_signature(signature),
        WASI_SOCK_SHUTDOWN_INDEX => check_sock_shutdown_signature(signature),
        _otherwise => false,
    }
}

/// Checks the signature of the module's entry point, `signature`, against the
/// templates described above for the `EntrySignature` enum type, and returns
/// an instance of that type as appropriate.
fn check_main_signature(signature: &Signature) -> EntrySignature {
    let params = signature.params();
    let return_type = signature.return_type();

    if params == [] && return_type == Some(ValueType::I32) {
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
    match module.export_by_name(ENTRY_POINT_NAME) {
        Some(ExternVal::Func(funcref)) => check_main_signature(&funcref.signature()),
        _otherwise => EntrySignature::NoEntryFound,
    }
}

////////////////////////////////////////////////////////////////////////////////
// Finding important module exports.
////////////////////////////////////////////////////////////////////////////////

/// Finds the linear memory of the WASM module, `module`, and returns it,
/// otherwise creating a fatal runtime panic that will kill the Veracruz
/// instance.
fn get_module_memory(module: &ModuleRef) -> Result<MemoryRef, RuntimePanic> {
    match module.export_by_name(LINEAR_MEMORY_NAME) {
        Some(ExternVal::Memory(memoryref)) => Ok(memoryref),
        _otherwise => Err(RuntimePanic::NoMemoryRegistered),
    }
}

////////////////////////////////////////////////////////////////////////////////
// The H-call interface.
////////////////////////////////////////////////////////////////////////////////

impl ModuleImportResolver for WASMIRuntimeState {
    /// "Resolves" a H-call by translating from a H-call name, `field_name` to
    /// the corresponding H-call code, and dispatching appropriately.
    fn resolve_func(&self, field_name: &str, signature: &Signature) -> Result<FuncRef, Error> {
        let index = match field_name {
            WASI_ARGS_GET_NAME => WASI_ARGS_GET_INDEX,
            WASI_ARGS_SIZES_GET_NAME => WASI_ARGS_GET_INDEX,
            WASI_ENVIRON_GET_NAME => WASI_ARGS_GET_INDEX,
            WASI_ENVIRON_SIZES_GET_NAME => WASI_ARGS_GET_INDEX,
            WASI_CLOCK_RES_GET_NAME => WASI_ARGS_GET_INDEX,
            WASI_CLOCK_TIME_GET_NAME => WASI_ARGS_GET_INDEX,
            WASI_FD_ADVISE_NAME => WASI_ARGS_GET_INDEX,
            WASI_FD_ALLOCATE_NAME => WASI_ARGS_GET_INDEX,
            WASI_FD_CLOSE_NAME => WASI_ARGS_GET_INDEX,
            WASI_FD_DATASYNC_NAME => WASI_ARGS_GET_INDEX,
            WASI_FD_FDSTAT_GET_NAME => WASI_ARGS_GET_INDEX,
            WASI_FD_FDSTAT_SET_FLAGS_NAME => WASI_ARGS_GET_INDEX,
            WASI_FD_FDSTAT_SET_RIGHTS_NAME => WASI_ARGS_GET_INDEX,
            WASI_FD_FILESTAT_GET_NAME => WASI_ARGS_GET_INDEX,
            WASI_FD_FILESTAT_SET_SIZE_NAME => WASI_ARGS_GET_INDEX,
            WASI_FD_FILESTAT_SET_TIMES_NAME => WASI_ARGS_GET_INDEX,
            WASI_FD_PREAD_NAME => WASI_ARGS_GET_INDEX,
            WASI_FD_PRESTAT_GET_NAME => WASI_ARGS_GET_INDEX,
            WASI_FD_PRESTAT_DIR_NAME_NAME => WASI_ARGS_GET_INDEX,
            WASI_FD_PWRITE_NAME => WASI_ARGS_GET_INDEX,
            WASI_FD_READ_NAME => WASI_ARGS_GET_INDEX,
            WASI_FD_READDIR_NAME => WASI_ARGS_GET_INDEX,
            WASI_FD_RENUMBER_NAME => WASI_ARGS_GET_INDEX,
            WASI_FD_SEEK_NAME => WASI_ARGS_GET_INDEX,
            WASI_FD_SYNC_NAME => WASI_ARGS_GET_INDEX,
            WASI_FD_TELL_NAME => WASI_ARGS_GET_INDEX,
            WASI_FD_WRITE_NAME => WASI_ARGS_GET_INDEX,
            WASI_PATH_CREATE_DIRECTORY_NAME => WASI_ARGS_GET_INDEX,
            WASI_PATH_FILESTAT_GET_NAME => WASI_ARGS_GET_INDEX,
            WASI_PATH_FILESTAT_SET_TIMES_NAME => WASI_ARGS_GET_INDEX,
            WASI_PATH_LINK_NAME => WASI_ARGS_GET_INDEX,
            WASI_PATH_OPEN_NAME => WASI_ARGS_GET_INDEX,
            WASI_PATH_READLINK_NAME => WASI_ARGS_GET_INDEX,
            WASI_PATH_REMOVE_DIRECTORY_NAME => WASI_ARGS_GET_INDEX,
            WASI_PATH_RENAME_NAME => WASI_ARGS_GET_INDEX,
            WASI_PATH_SYMLINK_NAME => WASI_ARGS_GET_INDEX,
            WASI_PATH_UNLINK_FILE_NAME => WASI_ARGS_GET_INDEX,
            otherwise => {
                return Err(Error::Instantiation(format!(
                    "Unknown function {} with signature: {:?}.",
                    otherwise, signature
                )));
            }
        };

        if !check_signature(index, signature) {
            Err(Error::Instantiation(format!(
                "Function {} has an unexpected type-signature: {:?}.",
                field_name, signature
            )))
        } else {
            Ok(FuncInstance::alloc_host(signature.clone(), index))
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
        match index {
            WASI_ARGS_GET_INDEX => self
                .wasi_args_get(args)
                .and_then(|c| mk_error_code(c))
                .or_else(|e| mk_host_trap(e)),
            WASI_ARGS_SIZES_GET_INDEX => self
                .wasi_args_sizes_get(args)
                .and_then(|c| mk_error_code(c))
                .or_else(|e| mk_host_trap(e)),
            WASI_ENVIRON_GET_INDEX => self
                .wasi_environ_get(args)
                .and_then(|c| mk_error_code(c))
                .or_else(|e| mk_host_trap(e)),
            WASI_ENVIRON_SIZES_GET_INDEX => self
                .wasi_environ_sizes_get(args)
                .and_then(|c| mk_error_code(c))
                .or_else(|e| mk_host_trap(e)),
            WASI_CLOCK_RES_GET_INDEX => self
                .wasi_clock_res_get(args)
                .and_then(|c| mk_error_code(c))
                .or_else(|e| mk_host_trap(e)),
            WASI_CLOCK_TIME_GET_INDEX => self
                .wasi_clock_time_get(args)
                .and_then(|c| mk_error_code(c))
                .or_else(|e| mk_host_trap(e)),
            WASI_FD_ADVISE_INDEX => self
                .wasi_fd_advise(args)
                .and_then(|c| mk_error_code(c))
                .or_else(|e| mk_host_trap(e)),
            WASI_FD_ALLOCATE_INDEX => self
                .wasi_fd_allocate(args)
                .and_then(|c| mk_error_code(c))
                .or_else(|e| mk_host_trap(e)),
            WASI_FD_CLOSE_INDEX => self
                .wasi_fd_close(args)
                .and_then(|c| mk_error_code(c))
                .or_else(|e| mk_host_trap(e)),
            WASI_FD_DATASYNC_INDEX => self
                .wasi_fd_datasync(args)
                .and_then(|c| mk_error_code(c))
                .or_else(|e| mk_host_trap(e)),
            WASI_FD_FDSTAT_GET_INDEX => self
                .wasi_fd_fdstat_get(args)
                .and_then(|c| mk_error_code(c))
                .or_else(|e| mk_host_trap(e)),
            WASI_FD_FDSTAT_SET_FLAGS_INDEX => self
                .wasi_fd_fdstat_set_flags(args)
                .and_then(|c| mk_error_code(c))
                .or_else(|e| mk_host_trap(e)),
            WASI_FD_FDSTAT_SET_RIGHTS_INDEX => self
                .wasi_fd_fdstat_set_rights(args)
                .and_then(|c| mk_error_code(c))
                .or_else(|e| mk_host_trap(e)),
            WASI_FD_FILESTAT_GET_INDEX => self
                .wasi_fd_filestat_get(args)
                .and_then(|c| mk_error_code(c))
                .or_else(|e| mk_host_trap(e)),
            WASI_FD_FILESTAT_SET_SIZE_INDEX => self
                .wasi_fd_filestat_set_size(args)
                .and_then(|c| mk_error_code(c))
                .or_else(|e| mk_host_trap(e)),
            WASI_FD_FILESTAT_SET_TIMES_INDEX => self
                .wasi_fd_filestat_set_times(args)
                .and_then(|c| mk_error_code(c))
                .or_else(|e| mk_host_trap(e)),
            WASI_FD_PREAD_INDEX => self
                .wasi_fd_pread(args)
                .and_then(|c| mk_error_code(c))
                .or_else(|e| mk_host_trap(e)),
            WASI_FD_PRESTAT_GET_INDEX => self
                .wasi_fd_prestat_get(args)
                .and_then(|c| mk_error_code(c))
                .or_else(|e| mk_host_trap(e)),
            WASI_FD_PRESTAT_DIR_NAME_INDEX => self
                .wasi_fd_prestat_dir_name(args)
                .and_then(|c| mk_error_code(c))
                .or_else(|e| mk_host_trap(e)),
            WASI_FD_PWRITE_INDEX => self
                .wasi_fd_pwrite(args)
                .and_then(|c| mk_error_code(c))
                .or_else(|e| mk_host_trap(e)),
            WASI_FD_READ_INDEX => self
                .wasi_fd_read(args)
                .and_then(|c| mk_error_code(c))
                .or_else(|e| mk_host_trap(e)),
            WASI_FD_READDIR_INDEX => self
                .wasi_fd_readdir(args)
                .and_then(|c| mk_error_code(c))
                .or_else(|e| mk_host_trap(e)),
            WASI_FD_RENUMBER_INDEX => self
                .wasi_fd_renumber(args)
                .and_then(|c| mk_error_code(c))
                .or_else(|e| mk_host_trap(e)),
            WASI_FD_SEEK_INDEX => self
                .wasi_fd_seek(args)
                .and_then(|c| mk_error_code(c))
                .or_else(|e| mk_host_trap(e)),
            WASI_FD_SYNC_INDEX => self
                .wasi_fd_sync(args)
                .and_then(|c| mk_error_code(c))
                .or_else(|e| mk_host_trap(e)),
            WASI_FD_TELL_INDEX => self
                .wasi_fd_tell(args)
                .and_then(|c| mk_error_code(c))
                .or_else(|e| mk_host_trap(e)),
            WASI_FD_WRITE_INDEX => self
                .wasi_fd_write(args)
                .and_then(|c| mk_error_code(c))
                .or_else(|e| mk_host_trap(e)),
            WASI_PATH_CREATE_DIRECTORY_INDEX => self
                .wasi_path_create_directory(args)
                .and_then(|c| mk_error_code(c))
                .or_else(|e| mk_host_trap(e)),
            WASI_PATH_FILESTAT_GET_INDEX => self
                .wasi_path_filestat_get(args)
                .and_then(|c| mk_error_code(c))
                .or_else(|e| mk_host_trap(e)),
            WASI_PATH_FILESTAT_SET_TIMES_INDEX => self
                .wasi_path_filestat_set_times(args)
                .and_then(|c| mk_error_code(c))
                .or_else(|e| mk_host_trap(e)),
            WASI_PATH_LINK_INDEX => self
                .wasi_path_link(args)
                .and_then(|c| mk_error_code(c))
                .or_else(|e| mk_host_trap(e)),
            WASI_PATH_OPEN_INDEX => self
                .wasi_path_open(args)
                .and_then(|c| mk_error_code(c))
                .or_else(|e| mk_host_trap(e)),
            WASI_PATH_READLINK_INDEX => self
                .wasi_path_readlink(args)
                .and_then(|c| mk_error_code(c))
                .or_else(|e| mk_host_trap(e)),
            WASI_PATH_REMOVE_DIRECTORY_INDEX => self
                .wasi_path_remove_directory(args)
                .and_then(|c| mk_error_code(c))
                .or_else(|e| mk_host_trap(e)),
            WASI_PATH_RENAME_INDEX => self
                .wasi_path_rename(args)
                .and_then(|c| mk_error_code(c))
                .or_else(|e| mk_host_trap(e)),
            WASI_PATH_SYMLINK_INDEX => self
                .wasi_path_symlink(args)
                .and_then(|c| mk_error_code(c))
                .or_else(|e| mk_host_trap(e)),
            WASI_PATH_UNLINK_FILE_INDEX => self
                .wasi_path_unlink_file(args)
                .and_then(|c| mk_error_code(c))
                .or_else(|e| mk_host_trap(e)),
            WASI_POLL_ONEOFF_INDEX => self
                .wasi_poll_oneoff(args)
                .and_then(|c| mk_error_code(c))
                .or_else(|e| mk_host_trap(e)),
            WASI_PROC_EXIT_INDEX => self
                .wasi_proc_exit(args)
                .and_then(|c| mk_error_code(c))
                .or_else(|e| mk_host_trap(e)),
            WASI_PROC_RAISE_INDEX => self
                .wasi_proc_raise(args)
                .and_then(|c| mk_error_code(c))
                .or_else(|e| mk_host_trap(e)),
            WASI_SCHED_YIELD_INDEX => self
                .wasi_sched_yield(args)
                .and_then(|c| mk_error_code(c))
                .or_else(|e| mk_host_trap(e)),
            WASI_RANDOM_GET_INDEX => self
                .wasi_random_get(args)
                .and_then(|c| mk_error_code(c))
                .or_else(|e| mk_host_trap(e)),
            WASI_SOCK_RECV_INDEX => self
                .wasi_sock_recv(args)
                .and_then(|c| mk_error_code(c))
                .or_else(|e| mk_host_trap(e)),
            WASI_SOCK_SEND_INDEX => self
                .wasi_sock_send(args)
                .and_then(|c| mk_error_code(c))
                .or_else(|e| mk_host_trap(e)),
            WASI_SOCK_SHUTDOWN_INDEX => self
                .wasi_sock_shutdown(args)
                .and_then(|c| mk_error_code(c))
                .or_else(|e| mk_host_trap(e)),
            otherwise => mk_host_trap(RuntimePanic::UnknownHostFunction { index: otherwise }),
        }
    }
}

/// Functionality of the `WASMIRuntimeState` type that relies on it satisfying
/// the `Externals` and `ModuleImportResolver` constraints.
impl WASMIRuntimeState {
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
    fn load_program(&mut self, buffer: &[u8]) -> Result<(), ProvisioningError> {
        if self.lifecycle_state() == &LifecycleState::Initial {
            if let Ok(module) = Module::from_buffer(buffer) {
                let env_resolver =
                    wasmi::ImportsBuilder::new().with_resolver(WASI_SNAPSHOT_MODULE_NAME, self);

                if let Ok(not_started_module_ref) = ModuleInstance::new(&module, &env_resolver) {
                    if not_started_module_ref.has_start() {
                        self.error();
                        return Err(ProvisioningError::InvalidWASMModule);
                    }

                    let module_ref = not_started_module_ref.assert_no_start();

                    if let Ok(linear_memory) = get_module_memory(&module_ref) {
                        // Everything has now gone well, so register the module,
                        // linear memory, and the program digest, then work out
                        // which state we should be in.

                        self.set_program_module(module_ref)
                            .set_memory(linear_memory)
                            .set_program_digest(sha_256_digest(buffer));

                        if self.expected_data_source_count() == 0 {
                            if self.expected_stream_source_count() == 0 {
                                self.ready_to_execute();
                            } else {
                                self.stream_sources_loading();
                            }
                        } else {
                            self.data_sources_loading();
                        }
                        return Ok(());
                    }

                    self.error();
                    return Err(ProvisioningError::NoLinearMemoryFound);
                }

                self.error();
                Err(ProvisioningError::ModuleInstantiationFailure)
            } else {
                self.error();
                Err(ProvisioningError::InvalidWASMModule)
            }
        } else {
            self.error();
            Err(ProvisioningError::InvalidLifeCycleState {
                expected: vec![LifecycleState::Initial],
                found: self.lifecycle_state().clone(),
            })
        }
    }

    /// Invokes an exported entry point function with a given name,
    /// `export_name`, in the WASM program provisioned into the Veracruz host
    /// state.
    fn invoke_export(&mut self, export_name: &str) -> Result<Option<RuntimeValue>, Error> {
        match self.program_module() {
            None => {
                return Err(Error::Host(Box::new(
                    RuntimePanic::NoProgramModuleRegistered,
                )))
            }
            Some(not_started) => match check_main(not_started) {
                EntrySignature::NoEntryFound => {
                    return Err(Error::Host(Box::new(RuntimePanic::NoProgramEntryPoint)))
                }
                EntrySignature::ArgvAndArgc => {
                    let program_arguments = vec![RuntimeValue::I32(0), RuntimeValue::I32(0)];
                    not_started.invoke_export(export_name, &program_arguments, self)
                }
                EntrySignature::NoParameters => {
                    let program_arguments = Vec::new();
                    not_started.invoke_export(export_name, &program_arguments, self)
                }
            },
        }
    }

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
    pub(crate) fn invoke_entry_point(&mut self) -> Result<i32, RuntimePanic> {
        if self.lifecycle_state() == &LifecycleState::ReadyToExecute {
            match self.invoke_export(ENTRY_POINT_NAME) {
                Ok(Some(RuntimeValue::I32(return_code))) => {
                    self.finished_executing();
                    Ok(return_code)
                }
                Ok(_) => {
                    self.error();
                    Err(RuntimePanic::ReturnedCodeError)
                }
                Err(Error::Trap(trap)) => {
                    self.error();
                    Err(RuntimePanic::WASMITrapError(trap))
                }
                Err(err) => {
                    self.error();
                    Err(RuntimePanic::WASMIError(err))
                }
            }
        } else {
            Err(RuntimePanic::EngineIsNotReady)
        }
    }

    ////////////////////////////////////////////////////////////////////////////
    // Common code for implementating the WASI functionality.
    ////////////////////////////////////////////////////////////////////////////

    /// Writes any value, `value`, that can be converted into a little-endian
    /// byte representation to the runtime state's memory at address, `address`.
    /// Fails with `Err(RuntimePanic::NoMemoryRegistered)` if no memory is
    /// registered in the runtime state, or
    /// `Err(RuntimePanic::MemoryWriteFailed)` if the value could not be written
    /// to the address for some reason.
    fn write_value<T>(&mut self, address: u32, value: T) -> Result<(), RuntimePanic>
    where
        T: LittleEndianConvert,
    {
        match self.memory() {
            None => Err(RuntimePanic::NoMemoryRegistered),
            Some(memory) => {
                if let Err(_) = memory.set_value(address, value) {
                    Err(RuntimePanic::MemoryWriteFailed {
                        memory_address: address as usize,
                        bytes_to_be_written: size_of::<T>(),
                    })
                } else {
                    Ok(())
                }
            }
        }
    }

    /// Writes a buffer of bytes, `buffer`, to the runtime state's memory at
    /// address, `address`.  Fails with `Err(RuntimePanic::NoMemoryRegistered)`
    /// if no memory is registered in the runtime state, or
    /// `Err(RuntimePanic::MemoryWriteFailed)` if the value could not be written
    /// to the address for some reason.
    fn write_buffer(&mut self, address: u32, buffer: &[u8]) -> Result<(), RuntimePanic> {
        match self.memory() {
            None => Err(RuntimePanic::NoMemoryRegistered),
            Some(memory) => {
                if let Err(_) = memory.set(address, buffer) {
                    Err(RuntimePanic::MemoryWriteFailed {
                        memory_address: address as usize,
                        bytes_to_be_written: buffer.len(),
                    })
                } else {
                    Ok(())
                }
            }
        }
    }

    /// Read several IoVec.
    fn read_iovec(&mut self, address: u32, ciovec: Vec<IoVec>) -> Result<Vec<u8>, RuntimePanic> {
        ciovec.iter().fold(Ok(Vec::new()), |mut acc, IoVec{buf, len}| {
            match acc {
                Ok(mut rst) => {
                    let mut new_rst = self.read_buffer(*buf,*len as usize)?;
                    rst.append(&mut new_rst);
                    Ok(rst)
                }
                Err(e) => Err(e),
            }
        })
    }

    /// Read a buffer of bytes from the runtime state's memory at
    /// address, `address`.  Fails with `Err(RuntimePanic::NoMemoryRegistered)`
    /// if no memory is registered in the runtime state, or
    /// `Err(RuntimePanic::MemoryWriteFailed)` if the value could not be written
    /// to the address for some reason.
    fn read_buffer(&mut self, address: u32, length: usize) -> Result<Vec<u8>, RuntimePanic> {
        match self.memory() {
            None => Err(RuntimePanic::NoMemoryRegistered),
            Some(memory) => match memory.get(address, length) {
                Err(_) => Err(RuntimePanic::MemoryReadFailed {
                    memory_address: address as usize,
                    bytes_to_be_read: length,
                }),
                Ok(buf) => Ok(buf.to_vec()),
            },
        }
    }

    ////////////////////////////////////////////////////////////////////////////
    // The WASI host call implementations.
    ////////////////////////////////////////////////////////////////////////////

    /// The implementation of the WASI `args_get` function.
    ///
    /// TODO: complete this.
    fn wasi_args_get(&mut self, args: RuntimeArgs) -> WASIError {
        if args.len() != 2 {
            return Err(RuntimePanic::bad_arguments_to_host_function(
                WASI_ARGS_GET_NAME,
            ));
        }

        let address0: u32 = args.nth(0);
        let address1: u32 = args.nth(1);
        self.write_value(address0, 0u32)?;
        self.write_value(address1, 0u32)?;

        Ok(ErrNo::Success)
    }

    /// The implementation of the WASI `args_sizes_get` function.
    ///
    /// TODO: complete this.
    fn wasi_args_sizes_get(&mut self, args: RuntimeArgs) -> WASIError {
        if args.len() != 2 {
            return Err(RuntimePanic::bad_arguments_to_host_function(
                WASI_ARGS_SIZES_GET_NAME,
            ));
        }

        let address0: u32 = args.nth(0);
        let address1: u32 = args.nth(1);
        self.write_value(address0, 0u32)?;
        self.write_value(address1, 0u32)?;

        Ok(ErrNo::Success)
    }

    /// The implementation of the WASI `environ_get` function.
    ///
    /// TODO: complete this.
    fn wasi_environ_get(&mut self, args: RuntimeArgs) -> WASIError {
        if args.len() != 2 {
            return Err(RuntimePanic::bad_arguments_to_host_function(
                WASI_ENVIRON_GET_NAME,
            ));
        }

        let address0: u32 = args.nth(0);
        let address1: u32 = args.nth(1);
        self.write_value(address0, 0u32)?;
        self.write_value(address1, 0u32)?;

        Ok(ErrNo::Success)
    }

    /// The implementation of the WASI `environ_sizes_get` function.
    ///
    /// TODO: complete this.
    fn wasi_environ_sizes_get(&mut self, args: RuntimeArgs) -> WASIError {
        if args.len() != 2 {
            return Err(RuntimePanic::bad_arguments_to_host_function(
                WASI_ENVIRON_SIZES_GET_NAME,
            ));
        }

        let address0: u32 = args.nth(0);
        let address1: u32 = args.nth(1);
        self.write_value(address0, 0u32)?;
        self.write_value(address1, 0u32)?;

        Ok(ErrNo::Success)
    }

    /// The implementation of the WASI `clock_res_get` function.  This is not
    /// supported by Veracruz.  We write `0` as the resolution and return
    /// `ErrNo::NoSys`.
    fn wasi_clock_res_get(&mut self, args: RuntimeArgs) -> WASIError {
        if args.len() != 2 {
            return Err(RuntimePanic::bad_arguments_to_host_function(
                WASI_CLOCK_RES_GET_NAME,
            ));
        }

        let address: u32 = args.nth(1);
        self.write_value(address, 0i64)?;

        Ok(ErrNo::NoSys)
    }

    /// The implementation of the WASI `clock_time_get` function.  This is not
    /// supported by Veracruz.  We write `0` as the timestamp and return
    /// `ErrNo::NoSys`.
    fn wasi_clock_time_get(&mut self, args: RuntimeArgs) -> WASIError {
        if args.len() != 3 {
            return Err(RuntimePanic::bad_arguments_to_host_function(
                WASI_CLOCK_TIME_GET_NAME,
            ));
        }

        let address: u32 = args.nth(2);
        self.write_value(address, 0u32)?;

        Ok(ErrNo::NoSys)
    }

    /// The implementation of the WASI `fd_advise` function.
    fn wasi_fd_advise(&mut self, args: RuntimeArgs) -> WASIError {
        if args.len() != 4 {
            return Err(RuntimePanic::bad_arguments_to_host_function(
                WASI_FD_ADVISE_NAME,
            ));
        }

        let fd: Fd = args.nth::<u32>(0).into();
        let offset: FileSize = args.nth::<u64>(1);
        let len: FileSize = args.nth::<u64>(2);
        let advice: Advice =
            match args.nth::<u8>(3).try_into() {
                Err(_err) => return Ok(ErrNo::Inval),
                Ok(advice) => advice
            };

        Ok(self.fd_advise(&fd, offset, len, advice))
    }

    /// The implementation of the WASI `fd_allocate` function.  This function is
    /// not supported by Veracruz so we simply return `ErrNo::NoSys`.
    fn wasi_fd_allocate(&mut self, args: RuntimeArgs) -> WASIError {
        if args.len() != 3 {
            return Err(RuntimePanic::bad_arguments_to_host_function(
                WASI_FD_ALLOCATE_NAME,
            ));
        }

        Ok(ErrNo::NoSys)
    }

    /// The implementation of the WASI `fd_close` function.
    fn wasi_fd_close(&mut self, args: RuntimeArgs) -> WASIError {
        if args.len() != 1 {
            return Err(RuntimePanic::bad_arguments_to_host_function(
                WASI_FD_CLOSE_NAME,
            ));
        }

        let fd: Fd = args.nth::<u32>(0).into();

        Ok(self.fd_close(&fd))
    }

    /// The implementation of the WASI `fd_datasync` function.  This is not
    /// supported by Veracruz and we simply return `ErrNo::NotSup`.
    ///
    /// XXX: consider whether this should just return `ErrNo::Success`, instead.
    fn wasi_fd_datasync(&mut self, args: RuntimeArgs) -> WASIError {
        if args.len() != 1 {
            return Err(RuntimePanic::bad_arguments_to_host_function(
                WASI_FD_DATASYNC_NAME,
            ));
        }

        Ok(ErrNo::NotSup)
    }

    /// The implementation of the WASI `fd_fdstat_get` function.
    fn wasi_fd_fdstat_get(&mut self, args: RuntimeArgs) -> WASIError {
        if args.len() != 2 {
            return Err(RuntimePanic::bad_arguments_to_host_function(
                WASI_FD_FDSTAT_GET_NAME,
            ));
        }

        let fd: Fd = args.nth::<u32>(0).into();
        let address: u32 = args.nth(1);

        let result: FdStat = self.fd_fdstat_get(&fd)?;

        self.write_value(address, result)?;

        Ok(ErrNo::Success)
    }

    /// The implementation of the WASI `fd_fdstat_set_flags` function.
    fn wasi_fd_fdstat_set_flags(&mut self, args: RuntimeArgs) -> WASIError {
        if args.len() != 2 {
            return Err(RuntimePanic::bad_arguments_to_host_function(
                WASI_FD_FDSTAT_SET_FLAGS_NAME,
            ));
        }

        let fd: Fd = args.nth::<u32>(0).into();
        let flags: FdFlags = args.nth::<u16>(1).into();

        Ok(self.fd_fdstat_set_flags(&fd, flags))
    }

    /// The implementation of the WASI `fd_fdstat_set_rights` function.
    fn wasi_fd_fdstat_set_rights(&mut self, args: RuntimeArgs) -> WASIError {
        if args.len() != 3 {
            return Err(RuntimePanic::bad_arguments_to_host_function(
                WASI_FD_FDSTAT_SET_RIGHTS_NAME,
            ));
        }

        let fd: Fd = args.nth::<u32>(0).into();
        let rights_base: Rights = args.nth::<u64>(1).into();
        let rights_inheriting: Rights = args.nth::<u64>(2).into();

        Ok(self.fd_fdstat_set_rights(&fd, rights_base, rights_inheriting))
    }

    /// The implementation of the WASI `fd_filestat_get` function.
    fn wasi_fd_filestat_get(&mut self, args: RuntimeArgs) -> WASIError {
        if args.len() != 2 {
            return Err(RuntimePanic::bad_arguments_to_host_function(
                WASI_FD_FILESTAT_GET_NAME,
            ));
        }

        let fd: Fd = args.nth::<u32>(0).into();
        let address: u32 = args.nth(1);

        let result: FileStat = self.fd_filestat_get(&fd)?;

        self.write_value(address, result)?;

        Ok(ErrNo::Success)
    }

    /// The implementation of the WASI `fd_filestat_set_size` function.
    fn wasi_fd_filestat_set_size(&mut self, args: RuntimeArgs) -> WASIError {
        if args.len() != 2 {
            return Err(RuntimePanic::bad_arguments_to_host_function(
                WASI_FD_FILESTAT_SET_SIZE_NAME,
            ));
        }

        let fd: Fd = args.nth::<u32>(0).into();
        let size: FileSize = args.nth::<u64>(1).into();

        Ok(self.fd_filestat_set_size(&fd, size))
    }

    /// The implementation of the WASI `fd_filestat_set_times` function.  This
    /// is not supported by Veracruz and we simply return `ErrNo::NotSup`.
    fn wasi_fd_filestat_set_times(&mut self, args: RuntimeArgs) -> WASIError {
        if args.len() != 4 {
            return Err(RuntimePanic::bad_arguments_to_host_function(
                WASI_FD_FILESTAT_SET_TIMES_NAME,
            ));
        }

        Ok(ErrNo::NotSup)
    }

    /// The implementation of the WASI `fd_pread` function.
    fn wasi_fd_pread(&mut self, args: RuntimeArgs) -> WASIError {
        if args.len() != 4 {
            return Err(RuntimePanic::bad_arguments_to_host_function(
                WASI_FD_PREAD_NAME,
            ));
        }

        let fd: Fd = args.nth::<u32>(0).into();
        let IoVec { buf, len }: IoVec = args.nth(1).into();
        let offset: FileSize = args.nth(2).into();
        let address: u32 = args.nth(3).into();

        match self.fd_pread_base(&fd, len as usize, &offset) {
            Ok(content) => {
                self.write_buffer(buf, content.as_slice());
                //TODO: decide if we use i32 or u32 as err/succ code 
                self.write_value(address, ErrNo::Success as i32)?;
            }
            //TODO: decide if we use i32 or u32 as err/succ code 
            Err(e) => self.write_value(address, e as i32)?,
        };

        Ok(ErrNo::Success)
    }

    /// The implementation of the WASI `fd_prestat_get` function.
    fn wasi_fd_prestat_get(&mut self, args: RuntimeArgs) -> WASIError {
        if args.len() != 2 {
            return Err(RuntimePanic::bad_arguments_to_host_function(
                WASI_FD_PRESTAT_GET_NAME,
            ));
        }

        let fd: Fd = args.nth(0);
        let address: u32 = args.nth(1);

        let result = self.fd_prestat_get(&fd)?;
        self.write_value(address, result)?;

        Ok(ErrNo::Success)
    }

    /// The implementation of the WASI `fd_prestat_dir_name` function.
    ///
    /// XXX: may panic if `u32` and `usize` bitwidths are different!
    fn wasi_fd_prestat_dir_name(&mut self, args: RuntimeArgs) -> WASIError {
        if args.len() != 3 {
            return Err(RuntimePanic::bad_arguments_to_host_function(
                WASI_FD_PRESTAT_DIR_NAME_NAME,
            ));
        }

        let fd: Fd = args.nth(0);
        let address: u32 = args.nth(1);
        let size: Size = args.nth(2);

        let result = self.fd_prestat_dir_name(&fd)?;

        if result.len() > usize::try_from(size).unwrap() {
            Ok(ErrNo::NameTooLong)
        } else {
            self.write_value(address, result)?;
            Ok(ErrNo::Success)
        }
    }

    /// The implementation of the WASI `fd_pwrite` function.
    ///
    /// TODO: complete this.
    fn wasi_fd_pwrite(&mut self, args: RuntimeArgs) -> WASIError {
        if args.len() != 4 {
            return Err(RuntimePanic::bad_arguments_to_host_function(
                WASI_FD_PWRITE_NAME,
            ));
        }

        let address: u32 = args.nth(3);
        self.write_value(address, 0u32)?;

        Ok(ErrNo::Success)
    }

    /// The implementation of the WASI `fd_read` function.
    ///
    /// TODO: complete this.
    fn wasi_fd_read(&mut self, args: RuntimeArgs) -> WASIError {
        if args.len() != 3 {
            return Err(RuntimePanic::bad_arguments_to_host_function(
                WASI_FD_READ_NAME,
            ));
        }

        let fd: Fd = args.nth::<u32>(0).into();
        let IoVec { buf, len }: IoVec = args.nth(1).into();
        let address: u32 = args.nth(2).into();

        match self.fd_read_base(&fd, len as usize) {
            Ok(content) => {
                self.write_buffer(buf, content.as_slice());
                //TODO: decide if we use i32 or u32 as err/succ code 
                self.write_value(address, ErrNo::Success as i32)?;
            }
            //TODO: decide if we use i32 or u32 as err/succ code 
            Err(e) => self.write_value(address, e as i32)?,
        };

        Ok(ErrNo::Success)
    }

    /// The implementation of the WASI `fd_readdir` function.
    ///
    /// TODO: complete this.
    fn wasi_fd_readdir(&mut self, args: RuntimeArgs) -> WASIError {
        if args.len() != 5 {
            return Err(RuntimePanic::bad_arguments_to_host_function(
                WASI_FD_READDIR_NAME,
            ));
        }

        let address: u32 = args.nth(4);
        self.write_value(address, 0u32)?;

        Ok(ErrNo::Success)
    }

    /// The implementation of the WASI `fd_renumber` function.
    ///
    /// TODO: complete this.
    fn wasi_fd_renumber(&mut self, args: RuntimeArgs) -> WASIError {
        if args.len() != 2 {
            return Err(RuntimePanic::bad_arguments_to_host_function(
                WASI_FD_RENUMBER_NAME,
            ));
        }

        Ok(ErrNo::Success)
    }

    /// The implementation of the WASI `fd_sync` function.
    ///
    /// TODO: complete this.
    fn wasi_fd_seek(&mut self, args: RuntimeArgs) -> WASIError {
        if args.len() != 4 {
            return Err(RuntimePanic::bad_arguments_to_host_function(
                WASI_FD_SEEK_NAME,
            ));
        }

        let address: u32 = args.nth(3);
        self.write_value(address, 0i64)?;

        Ok(ErrNo::Success)
    }

    /// The implementation of the WASI `fd_sync` function.  This is not
    /// supported by Veracruz.  We simply return `ErrNo::NotSup`.
    ///
    /// XXX: consider whether this should just return `ErrNo::Success`, instead.
    fn wasi_fd_sync(&mut self, args: RuntimeArgs) -> WASIError {
        if args.len() != 1 {
            return Err(RuntimePanic::bad_arguments_to_host_function(
                WASI_FD_SEEK_NAME,
            ));
        }

        Ok(ErrNo::NotSup)
    }

    /// The implementation of the WASI `fd_tell` function.
    ///
    /// TODO: complete this.
    fn wasi_fd_tell(&mut self, args: RuntimeArgs) -> WASIError {
        if args.len() != 2 {
            return Err(RuntimePanic::bad_arguments_to_host_function(
                WASI_FD_TELL_NAME,
            ));
        }

        let address: u32 = args.nth(1);
        self.write_value(address, 0i64)?;

        Ok(ErrNo::Success)
    }

    /// The implementation of the WASI `fd_write` function.
    ///
    /// TODO: complete this.
    fn wasi_fd_write(&mut self, args: RuntimeArgs) -> WASIError {
        if args.len() != 3 {
            return Err(RuntimePanic::bad_arguments_to_host_function(
                WASI_FD_WRITE_NAME,
            ));
        }

        let address: u32 = args.nth(3);
        self.write_value(address, 0u32)?;

        Ok(ErrNo::Success)
    }

    /// The implementation of the WASI `path_create_directory` function.
    ///
    /// TODO: complete this.
    fn wasi_path_create_directory(&mut self, args: RuntimeArgs) -> WASIError {
        if args.len() != 2 {
            return Err(RuntimePanic::bad_arguments_to_host_function(
                WASI_PATH_CREATE_DIRECTORY_NAME,
            ));
        }

        Ok(ErrNo::Success)
    }

    /// The implementation of the WASI `path_filestat_get` function.
    ///
    /// TODO: complete this.
    fn wasi_path_filestat_get(&mut self, args: RuntimeArgs) -> WASIError {
        if args.len() != 4 {
            return Err(RuntimePanic::bad_arguments_to_host_function(
                WASI_PATH_FILESTAT_GET_NAME,
            ));
        }

        Ok(ErrNo::Success)
    }

    /// The implementation of the WASI `path_filestat_set_times` function.  This
    /// is not supported by Veracruz.  We simply return `ErrNo::NotSup`.
    fn wasi_path_filestat_set_times(&mut self, args: RuntimeArgs) -> WASIError {
        if args.len() != 6 {
            return Err(RuntimePanic::bad_arguments_to_host_function(
                WASI_PATH_FILESTAT_SET_TIMES_NAME,
            ));
        }

        Ok(ErrNo::NotSup)
    }

    /// The implementation of the WASI `path_readlink` function.  This
    /// is not supported by Veracruz.  We simply return `ErrNo::NotSup`.
    fn wasi_path_link(&mut self, args: RuntimeArgs) -> WASIError {
        if args.len() != 5 {
            return Err(RuntimePanic::bad_arguments_to_host_function(
                WASI_PATH_LINK_NAME,
            ));
        }

        Ok(ErrNo::NotSup)
    }

    /// The implementation of the WASI `path_open` function.
    ///
    /// TODO: complete this.
    fn wasi_path_open(&mut self, args: RuntimeArgs) -> WASIError {
        if args.len() != 8 {
            return Err(RuntimePanic::bad_arguments_to_host_function(
                WASI_PATH_OPEN_NAME,
            ));
        }

        let address: u32 = args.nth(7);
        self.write_value(address, 0u32)?;

        Ok(ErrNo::Success)
    }

    /// The implementation of the WASI `path_readlink` function.  This
    /// is not supported by Veracruz.  We simply return `ErrNo::NotSup`.
    ///
    /// XXX: re-assess whether we want to support this.
    fn wasi_path_readlink(&mut self, args: RuntimeArgs) -> WASIError {
        if args.len() != 5 {
            return Err(RuntimePanic::bad_arguments_to_host_function(
                WASI_PATH_READLINK_NAME,
            ));
        }

        Ok(ErrNo::NotSup)
    }

    /// The implementation of the WASI `path_remove_directory` function.
    ///
    /// TODO: complete this.
    fn wasi_path_remove_directory(&mut self, args: RuntimeArgs) -> WASIError {
        if args.len() != 2 {
            return Err(RuntimePanic::bad_arguments_to_host_function(
                WASI_PATH_REMOVE_DIRECTORY_NAME,
            ));
        }

        Ok(ErrNo::Success)
    }

    /// The implementation of the WASI `path_rename` function.
    ///
    /// TODO: complete this.
    fn wasi_path_rename(&mut self, args: RuntimeArgs) -> WASIError {
        if args.len() != 4 {
            return Err(RuntimePanic::bad_arguments_to_host_function(
                WASI_PATH_RENAME_NAME,
            ));
        }

        Ok(ErrNo::Success)
    }

    /// The implementation of the WASI `path_symlink` function.  This is not
    /// supported by Veracruz.  We simply return `ErrNo::NotSup`.
    ///
    /// XXX: re-assess whether we want to support this.
    fn wasi_path_symlink(&mut self, args: RuntimeArgs) -> WASIError {
        if args.len() != 3 {
            return Err(RuntimePanic::bad_arguments_to_host_function(
                WASI_PATH_SYMLINK_NAME,
            ));
        }

        Ok(ErrNo::NotSup)
    }

    /// The implementation of the WASI `path_unlink_file` function.  This is not
    /// supported by Veracruz.  We simply return `ErrNo::NotSup`.
    ///
    /// XXX: re-assess whether we want to support this.
    fn wasi_path_unlink_file(&mut self, args: RuntimeArgs) -> WASIError {
        if args.len() != 2 {
            return Err(RuntimePanic::bad_arguments_to_host_function(
                WASI_PATH_UNLINK_FILE_NAME,
            ));
        }

        Ok(ErrNo::NotSup)
    }

    /// The implementation of the WASI `poll_oneoff` function.  This is not
    /// supported by Veracruz.  We write `0` as the number of subscriptions that
    /// were registered and return `ErrNo::NotSup`.
    fn wasi_poll_oneoff(&mut self, args: RuntimeArgs) -> WASIError {
        if args.len() != 4 {
            return Err(RuntimePanic::bad_arguments_to_host_function(
                WASI_POLL_ONEOFF_NAME,
            ));
        }

        let address: u32 = args[3];
        self.write_value(address, 0u32)?;

        Ok(ErrNo::NotSup)
    }

    /// The implementation of the WASI `proc_raise` function.  This halts
    /// termination of the interpreter, returning an error code.  No return code
    /// is returned to the calling WASM process.
    fn wasi_proc_exit(&mut self, args: RuntimeArgs) -> WASIError {
        if args.len() != 1 {
            return Err(RuntimePanic::bad_arguments_to_host_function(
                WASI_PROC_EXIT_NAME,
            ));
        }

        let exit_code: i32 = args.nth(0);

        // NB: this gets routed to the runtime, not the calling WASM program,
        // for handling.
        Err(RuntimePanic::EarlyExit(exit_code))
    }

    /// The implementation of the WASI `proc_raise` function.  This is not
    /// supported by Veracruz and implemented as a no-op, simply returning
    /// `ErrNo::NotSup`.
    fn wasi_proc_raise(&mut self, args: RuntimeArgs) -> WASIError {
        if args.len() != 1 {
            return Err(RuntimePanic::bad_arguments_to_host_function(
                WASI_PROC_RAISE_NAME,
            ));
        }

        Ok(ErrNo::NotSup)
    }

    /// The implementation of the WASI `sched_yield` function.  This is
    /// not supported by Veracruz and simply returns `ErrNo::NotSup`.
    fn wasi_sched_yield(&mut self, args: RuntimeArgs) -> WASIError {
        if args.len() != 0 {
            return Err(RuntimePanic::bad_arguments_to_host_function(
                WASI_SCHED_YIELD_NAME,
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
        if args.len() != 2 {
            return Err(RuntimePanic::bad_arguments_to_host_function(
                WASI_RANDOM_GET_NAME,
            ));
        }

        let address: u32 = args.nth(0);
        let size: u32 = args.nth(1);
        let mut buffer = vec![0; size as usize];

        if let result::Result::Success = getrandom(&mut buffer) {
            self.write_buffer(address, &buffer)?;

            Ok(ErrNo::Success)
        } else {
            Ok(ErrNo::NoSys)
        }
    }

    /// The implementation of the WASI `sock_send` function.  This is not
    /// supported by Veracruz and returns `ErrNo::NotSup`, writing back
    /// `0` as the length of the transmission.
    fn wasi_sock_send(&mut self, args: RuntimeArgs) -> WASIError {
        if args.len() != 4 {
            return Err(RuntimePanic::bad_arguments_to_host_function(
                WASI_SOCK_SEND_NAME,
            ));
        }

        let address = args.nth(4);
        self.write_value(address, 0u32)?;

        Ok(ErrNo::NotSup)
    }

    /// The implementation of the WASI `sock_recv` function.  This is not
    /// supported by Veracruz and returns `ErrNo::NotSup`, writing back
    /// `0` as the length of the transmission.
    fn wasi_sock_recv(&mut self, args: RuntimeArgs) -> WASIError {
        if args.len() != 5 {
            return Err(RuntimePanic::bad_arguments_to_host_function(
                WASI_SOCK_RECV_NAME,
            ));
        }

        let datalen_address: u32 = args.nth(3);
        let flags_address: u32 = args.nth(4);

        self.write_value(datalen_address, 0u32)?;
        self.write_value(flags_address, 0u16)?;

        Ok(ErrNo::NotSup)
    }

    /// The implementation of the WASI `sock_shutdown` function.  This is
    /// not supported by Veracruz and simply returns `ErrNo::NotSup`.
    fn wasi_sock_shutdown(&mut self, args: RuntimeArgs) -> WASIError {
        if args.len() != 2 {
            return Err(RuntimePanic::bad_arguments_to_host_function(
                WASI_SOCK_SHUTDOWN_NAME,
            ));
        }

        Ok(ErrNo::NotSup)
    }
}

////////////////////////////////////////////////////////////////////////////////
// The Chihuahua trait implementation.
////////////////////////////////////////////////////////////////////////////////

impl Chihuahua for WASMIRuntimeState {
    #[inline]
    fn load_program(&mut self, buffer: &[u8]) -> Result<(), ProvisioningError> {
        self.load_program(buffer)
    }

    #[inline]
    fn add_data_source(&mut self, fname: String, buffer: Vec<u8>) -> Result<(), ProvisioningError> {
        self.add_data_source(fname, buffer)
    }

    #[inline]
    fn add_stream_source(
        &mut self,
        fname: String,
        buffer: Vec<u8>,
    ) -> Result<(), ProvisioningError> {
        self.add_stream_source(fname, buffer)
    }

    #[inline]
    fn invoke_entry_point(&mut self) -> Result<i32, RuntimePanic> {
        self.invoke_entry_point()
    }

    #[inline]
    fn is_program_module_registered(&self) -> bool {
        self.is_program_module_registered()
    }

    #[inline]
    fn is_memory_registered(&self) -> bool {
        self.is_memory_registered()
    }

    #[inline]
    fn is_able_to_shutdown(&self) -> bool {
        self.is_able_to_shutdown()
    }

    #[inline]
    fn lifecycle_state(&self) -> &LifecycleState {
        self.lifecycle_state()
    }

    #[inline]
    fn registered_data_source_count(&self) -> usize {
        self.registered_data_source_count()
    }

    #[inline]
    fn registered_stream_source_count(&self) -> usize {
        self.registered_stream_source_count()
    }

    #[inline]
    fn expected_data_source_count(&self) -> usize {
        self.expected_data_source_count()
    }

    #[inline]
    fn expected_stream_source_count(&self) -> usize {
        self.expected_stream_source_count()
    }

    #[inline]
    fn expected_shutdown_sources(&self) -> &Vec<u64> {
        self.expected_shutdown_sources()
    }

    #[inline]
    fn result_filename(&self) -> Option<&String> {
        self.result_filename()
    }

    #[inline]
    fn program_digest(&self) -> Option<&Vec<u8>> {
        self.program_digest()
    }

    #[inline]
    fn set_expected_data_source_count(&mut self, sources: usize) -> &mut dyn Chihuahua {
        self.set_expected_data_source_count(sources)
    }

    #[inline]
    fn set_expected_stream_source_count(&mut self, sources: usize) -> &mut dyn Chihuahua {
        self.set_expected_stream_source_count(sources)
    }

    #[inline]
    fn set_expected_shutdown_sources(&mut self, sources: Vec<u64>) -> &mut dyn Chihuahua {
        self.set_expected_shutdown_sources(sources)
    }

    #[inline]
    fn error(&mut self) -> &mut dyn Chihuahua {
        self.error()
    }

    #[inline]
    fn request_shutdown(&mut self, client_id: &u64) -> &mut dyn Chihuahua {
        self.request_shutdown(client_id)
    }
}
