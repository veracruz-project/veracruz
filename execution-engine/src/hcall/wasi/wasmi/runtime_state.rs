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

use crate::hcall::wasi::common::{EntrySignature, RuntimeState};
use wasmi::{
    Error, ExternVal, Externals, FuncInstance, FuncRef, GlobalDescriptor, GlobalRef,
    MemoryDescriptor, MemoryRef, Module, ModuleImportResolver, ModuleInstance, ModuleRef,
    RuntimeArgs, RuntimeValue, Signature, TableDescriptor, TableRef, Trap, ValueType,
};

////////////////////////////////////////////////////////////////////////////////
// The WASMI host provisioning state.
////////////////////////////////////////////////////////////////////////////////

/// The WASMI runtime state: the `RuntimeState` with the `Module` and `Memory`
/// type-variables specialised to WASMI's `ModuleRef` and `MemoryRef` type.
pub(crate) type WasmiHostProvisioningState = RuntimeState<ModuleRef, MemoryRef>;

////////////////////////////////////////////////////////////////////////////////
// Constants.
////////////////////////////////////////////////////////////////////////////////

/// The name of the WASM program's entry point.
const ENTRY_POINT_NAME: &str = "main";
/// The name of the WASM program's linear memory.
const LINEAR_MEMORY_NAME: &str = "memory";

/// Index of the WASI `args_get` function.
const WASI_ARGS_GET_NAME: usize = 0;
/// Index of the WASI `args_get` function.
const WASI_ARGS_SIZES_GET_NAME: usize = 1;
/// Index of the WASI `environ_get` function.
const WASI_ENVIRON_GET_NAME: usize = 2;
/// Index of the WASI `environ_sizes_get` function.
const WASI_ENVIRON_SIZES_GET_NAME: usize = 3;
/// Index of the WASI `clock_res_get` function.
const WASI_CLOCK_RES_GET_NAME: usize = 4;
/// Index of the WASI `clock_time_get` function.
const WASI_CLOCK_TIME_GET_NAME: usize = 5;
/// Index of the WASI `fd_advise` function.
const WASI_FD_ADVISE_NAME: usize = 6;
/// Index of the WASI `fd_allocate` function.
const WASI_FD_ALLOCATE_NAME: usize = 7;
/// Index of the WASI `fd_close` function.
const WASI_FD_CLOSE_NAME: usize = 8;
/// Index of the WASI `fd_datasync` function.
const WASI_FD_DATASYNC_NAME: usize = 9;
/// Index of the WASI `fd_fdstat_get` function.
const WASI_FD_FDSTAT_GET_NAME: usize = 10;
/// Index of the WASI `fd_filestat_set_flags` function.
const WASI_FD_FDSTAT_SET_FLAGS_NAME: usize = 11;
/// Index of the WASI `fd_filestat_set_rights` function.
const WASI_FD_FDSTAT_SET_RIGHTS_NAME: usize = 12;
/// Index of the WASI `fd_filestat_get` function.
const WASI_FD_FILESTAT_GET_NAME: usize = 13;
/// Index of the WASI `fd_filestat_set_size` function.
const WASI_FD_FILESTAT_SET_SIZE_NAME: usize = 14;
/// Index of the WASI `fd_filestat_set_times` function.
const WASI_FD_FILESTAT_SET_TIMES_NAME: usize = 15;
/// Index of the WASI `fd_pread` function.
const WASI_FD_PREAD_NAME: usize = 16;
/// Index of the WASI `fd_prestat_get_name` function.
const WASI_FD_PRESTAT_GET_NAME: usize = 17;
/// Index of the WASI `fd_prestat_dir_name` function.
const WASI_FD_PRESTAT_DIR_NAME_NAME: usize = 18;
/// Index of the WASI `fd_pwrite` function.
const WASI_FD_PWRITE_NAME: usize = 19;
/// Index of the WASI `fd_read` function.
const WASI_FD_READ_NAME: usize = 20;
/// Index of the WASI `fd_readdir` function.
const WASI_FD_READDIR_NAME: usize = 21;
/// Index of the WASI `fd_renumber` function.
const WASI_FD_RENUMBER_NAME: usize = 22;
/// Index of the WASI `fd_seek` function.
const WASI_FD_SEEK_NAME: usize = 23;
/// Index of the WASI `fd_sync` function.
const WASI_FD_SYNC_NAME: usize = 24;
/// Index of the WASI `fd_tell` function.
const WASI_FD_TELL_NAME: usize = 25;
/// Index of the WASI `fd_write` function.
const WASI_FD_WRITE_NAME: usize = 26;
/// Index of the WASI `path_crate_directory` function.
const WASI_PATH_CREATE_DIRECTORY_NAME: usize = 27;
/// Index of the WASI `path_filestat_get` function.
const WASI_PATH_FILESTAT_GET_NAME: usize = 28;
/// Index of the WASI `path_filestat_set_times` function.
const WASI_PATH_FILESTAT_SET_TIMES_NAME: usize = 29;
/// Index of the WASI `path_link` function.
const WASI_PATH_LINK_NAME: usize = 30;
/// Index of the WASI `path_open` function.
const WASI_PATH_OPEN_NAME: usize = 31;
/// Index of the WASI `path_readlink` function.
const WASI_PATH_READLINK_NAME: usize = 32;
/// Index of the WASI `path_remove_directory` function.
const WASI_PATH_REMOVE_DIRECTORY_NAME: usize = 33;
/// Index of the WASI `path_rename` function.
const WASI_PATH_RENAME_NAME: usize = 34;
/// Index of the WASI `path_symlink` function.
const WASI_PATH_SYMLINK_NAME: usize = 35;
/// Index of the WASI `path_unlink_file` function.
const WASI_PATH_UNLINK_FILE_NAME: usize = 36;
/// Index of the WASI `poll_oneoff` function.
const WASI_POLL_ONEOFF_NAME: usize = 37;
/// Index of the WASI `proc_exit` function.
const WASI_PROC_EXIT_NAME: usize = 38;
/// Index of the WASI `proc_raise` function.
const WASI_PROC_RAISE_NAME: usize = 39;
/// Index of the WASI `sched_yield` function.
const WASI_SCHED_YIELD_NAME: usize = 40;
/// Index of the WASI `random_get` function.
const WASI_RANDOM_GET_NAME: usize = 41;
/// Index of the WASI `sock_recv` function.
const WASI_SOCK_RECV_NAME: usize = 42;
/// Index of the WASI `sock_send` function.
const WASI_SOCK_SEND_NAME: usize = 43;
/// Index of the WASI `sock_shutdown` function.
const WASI_SOCK_SHUTDOWN_NAME: usize = 44;

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
        && return_type == &Some(REPRESENTATION_WASI_ERRNO)
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
        && return_type == &Some(REPRESENTATION_WASI_ERRNO)
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
        && return_type == &Some(REPRESENTATION_WASI_ERRNO)
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
        && return_type == &Some(REPRESENTATION_WASI_ERRNO)
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
        && return_type == &Some(REPRESENTATION_WASI_ERRNO)
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
        && return_type == &Some(REPRESENTATION_WASI_ERRNO)
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
        && return_type == &Some(REPRESENTATION_WASI_ERRNO)
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
        && return_type == &Some(REPRESENTATION_WASI_ERRNO)
}

/// Checks the signature of the WASI `fd_close` function:
///
/// ```Rust
/// fd_close(fd: fd) -> errno
/// ```
fn check_fd_close_signature(signature: &Signature) -> bool {
    let params = signature.params();
    let return_type = signature.return_type();

    params == &[REPRESENTATION_WASI_FD] && return_type == &Some(REPRESENTATION_WASI_ERRNO)
}

/// Checks the signature of the WASI `fd_datasync` function:
///
/// ```Rust
/// fd_datasync(fd: fd) -> errno
/// ```
fn check_fd_datasync_signature(signature: &Signature) -> bool {
    let params = signature.params();
    let return_type = signature.return_type();

    params == &[REPRESENTATION_WASI_FD] && return_type == &Some(REPRESENTATION_WASI_ERRNO)
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
        && return_type == &Some(REPRESENTATION_WASI_ERRNO)
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
        && return_type == &Some(REPRESENTATION_WASI_ERRNO)
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
        && return_type == &Some(REPRESENTATION_WASI_ERRNO)
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
        && return_type == &Some(REPRESENTATION_WASI_ERRNO)
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
        && return_type == &Some(REPRESENTATION_WASI_ERRNO)
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
        && return_type == &Some(REPRESENTATION_WASI_ERRNO)
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
        && return_type == &Some(REPRESENTATION_WASI_ERRNO)
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
        && return_type == &Some(REPRESENTATION_WASI_ERRNO)
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
        && return_type == &Some(REPRESENTATION_WASI_ERRNO)
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
        && return_type == &Some(REPRESENTATION_WASI_ERRNO)
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
        && return_type == &Some(REPRESENTATION_WASI_ERRNO)
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
        && return_type == &Some(REPRESENTATION_WASI_ERRNO)
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
        && return_type == &Some(REPRESENTATION_WASI_ERRNO)
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
        && return_type == &Some(REPRESENTATION_WASI_ERRNO)
}

/// Checks the signature of the WASI `fd_sync` function:
///
/// ```Rust
/// fd_sync(fd: fd) -> errno
/// ```
fn check_fd_sync_signature(signature: &Signature) -> bool {
    let params = signature.params();
    let return_type = signature.return_type();

    params == &[REPRESENTATION_WASI_FD] && return_type == &Some(REPRESENTATION_WASI_ERRNO)
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
        && return_type == &Some(REPRESENTATION_WASI_ERRNO)
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
        && return_type == &Some(REPRESENTATION_WASI_ERRNO)
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
        && return_type == &Some(REPRESENTATION_WASI_ERRNO)
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
        && return_type == &Some(REPRESENTATION_WASI_ERRNO)
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
        && return_type == &Some(REPRESENTATION_WASI_ERRNO)
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
        && return_type == &Some(REPRESENTATION_WASI_ERRNO)
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
        && return_type == &Some(REPRESENTATION_WASI_ERRNO)
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
        && return_type == &Some(REPRESENTATION_WASI_ERRNO)
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
        && return_type == &Some(REPRESENTATION_WASI_ERRNO)
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
        && return_type == &Some(REPRESENTATION_WASI_ERRNO)
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
        && return_type == &Some(REPRESENTATION_WASI_ERRNO)
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
        && return_type == &Some(REPRESENTATION_WASI_ERRNO)
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
        && return_type == &Some(REPRESENTATION_WASI_ERRNO)
}

/// Checks the signature of the WASI `proc_exit` function:
///
/// ```Rust
/// proc_exit(rval: exitcode)
/// ```
fn check_proc_exit_signature(signature: &Signature) -> bool {
    let params = signature.params();
    let return_type = signature.return_type();

    params == &[REPRESENTATION_WASI_EXITCODE] && return_type == &None
}

/// Checks the signature of the WASI `proc_raise` function:
///
/// ```Rust
/// proc_raise(sig: signal) -> errno
/// ```
fn check_proc_raise_signature(signature: &Signature) -> bool {
    let params = signature.params();
    let return_type = signature.return_type();

    params == &[REPRESENTATION_WASI_SIGNAL] && return_type == &Some(REPRESENTATION_WASI_ERRNO)
}

/// Checks the signature of the WASI `sched_yield` function:
///
/// ```Rust
/// sched_yield() -> errno
/// ```
fn check_sched_yield_signature(signature: &Signature) -> bool {
    let params = signature.params();
    let return_type = signature.return_type();

    params == &[] && return_type == &Some(REPRESENTATION_WASI_ERRNO)
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
        && return_type == &Some(REPRESENTATION_WASI_ERRNO)
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
        && return_type == &Some(REPRESENTATION_WASI_ERRNO)
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
        && return_type == &Some(REPRESENTATION_WASI_ERRNO)
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
        && return_type == &Some(REPRESENTATION_WASI_ERRNO)
}

/// Checks the function signature, `signature`, has the correct type for the
/// host call coded by `index`.
fn check_signature(index: usize, signature: &Signature) -> bool {
    match index {
        WASI_ARGS_GET_NAME => check_args_get_signature(signature),
        WASI_ARGS_SIZES_GET_NAME => check_args_sizes_get_signature(signature),
        WASI_ENVIRON_GET_NAME => check_environ_get_signature(signature),
        WASI_ENVIRON_SIZES_GET_NAME => check_environ_sizes_get_signature(signature),
        WASI_CLOCK_RES_GET_NAME => check_clock_res_get_signature(signature),
        WASI_CLOCK_TIME_GET_NAME => check_clock_time_get_signature(signature),
        WASI_FD_ADVISE_NAME => check_fd_advise_signature(signature),
        WASI_FD_ALLOCATE_NAME => check_fd_allocate_signature(signature),
        WASI_FD_CLOSE_NAME => check_fd_close_signature(signature),
        WASI_FD_DATASYNC_NAME => check_fd_datasync_signature(signature),
        WASI_FD_FDSTAT_GET_NAME => check_fd_fdstat_get_signature(signature),
        WASI_FD_FDSTAT_SET_FLAGS_NAME => check_fd_fdstat_set_flags_signature(signature),
        WASI_FD_FDSTAT_SET_RIGHTS_NAME => check_fd_fdstat_set_rights_signature(signature),
        WASI_FD_FILESTAT_GET_NAME => check_fd_filestat_get_name_signature(signature),
        WASI_FD_FILESTAT_SET_SIZE_NAME => check_fd_filestat_set_sizes_signature(signature),
        WASI_FD_FILESTAT_SET_TIMES_NAME => check_fd_filestat_set_times_signature(signature),
        WASI_FD_PREAD_NAME => check_fd_pread_signature(signature),
        WASI_FD_PRESTAT_GET_NAME => check_fd_prestat_get_signature(signature),
        WASI_FD_PRESTAT_DIR_NAME_NAME => check_fd_prestat_dir_name_signature(signature),
        WASI_FD_PWRITE_NAME => check_fd_pwrite_signature(signature),
        WASI_FD_READ_NAME => check_fd_read_signature(signature),
        WASI_FD_READDIR_NAME => check_fd_readdir_signature(signature),
        WASI_FD_RENUMBER_NAME => check_fd_renumber_signature(signature),
        WASI_FD_SEEK_NAME => check_fd_seek_signature(signature),
        WASI_FD_SYNC_NAME => check_fd_sync_signature(signature),
        WASI_FD_TELL_NAME => check_fd_tell_signature(signature),
        WASI_FD_WRITE_NAME => check_fd_write_signature(signature),
        WASI_PATH_CREATE_DIRECTORY_NAME => check_path_crate_directory_signature(signature),
        WASI_PATH_FILESTAT_GET_NAME => check_path_filestat_get_signature(signature),
        WASI_PATH_FILESTAT_SET_TIMES_NAME => check_path_filestat_set_times_signature(signature),
        WASI_PATH_LINK_NAME => check_path_link_signature(signature),
        WASI_PATH_OPEN_NAME => check_path_open_signature(signature),
        WASI_PATH_READLINK_NAME => check_path_readlink_signature(signature),
        WASI_PATH_REMOVE_DIRECTORY_NAME => check_path_remove_directory_signature(signature),
        WASI_PATH_RENAME_NAME => check_path_rename_signature(signature),
        WASI_PATH_SYMLINK_NAME => check_path_symlink_signature(signature),
        WASI_PATH_UNLINK_FILE_NAME => check_path_unlink_signature(signature),
        WASI_POLL_ONEOFF_NAME => check_poll_oneoff_signature(signature),
        WASI_PROC_EXIT_NAME => check_proc_exit_signature(signature),
        WASI_PROC_RAISE_NAME => check_proc_raise_signature(signature),
        WASI_SCHED_YIELD_NAME => check_sched_yield_signature(signature),
        WASI_RANDOM_GET_NAME => check_random_get_signature(signature),
        WASI_SOCK_RECV_NAME => check_sock_recv_signature(signature),
        WASI_SOCK_SEND_NAME => check_sock_send_signature(signature),
        WASI_SOCK_SHUTDOWN_NAME => check_sock_shutdown_signature(signature),
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
