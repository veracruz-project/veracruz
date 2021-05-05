//! An implementation of the ExecutionEngine runtime state for Wasmtime.
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Copyright
//!
//! See the file `LICENSE.markdown` in the Veracruz root directory for licensing
//! and copyright information.

use std::{vec::Vec, collections::HashMap};
use std::convert::TryFrom;
use crate::{
    fs::FileSystem,
    hcall::common::{
        ExecutionEngine, EntrySignature, FatalEngineError, HostFunctionIndexOrName, 
        WASIWrapper, MemoryHandler, WASIAPIName
    }
};
use lazy_static::lazy_static;
#[cfg(any(feature = "std", feature = "tz", feature = "nitro"))]
use std::sync::{Mutex, Arc};
#[cfg(feature = "sgx")]
use std::sync::{SgxMutex as Mutex, Arc};
use veracruz_utils::policy::principal::Principal;
use wasmtime::{Caller, Extern, ExternType, Func, Instance, Module, Store, ValType};
use wasi_types::ErrNo;

////////////////////////////////////////////////////////////////////////////////
// The Wasmtime runtime state.
////////////////////////////////////////////////////////////////////////////////


lazy_static! {
    // The initial value has NO use.
    static ref VFS_INSTANCE: Mutex<WASIWrapper> = Mutex::new(WASIWrapper::new(Arc::new(Mutex::new(FileSystem::new(HashMap::new()))), Principal::NoCap));
}

/// A macro for lock the global VFS and store the result in the variable, 
/// which will be captured by `$vfs` in the macro.
/// If the locks fails, it returns Busy error code.
macro_rules! lock_vfs {
    () => {
        match VFS_INSTANCE.lock() {
            Ok(v) => v,
            Err(_) => return ErrNo::Busy as u32,
        }
    }
}

/// A macro to call try_from on a untyped raw wasi parameter `$var`.
/// It converts `$var` to the typed version, `$t`, of the parameter as a value,
/// or returns from the function with the `Inval` error code.
macro_rules! convert_wasi_arg {
    ($var:ident, $t:ty) => {
        match <$t>::try_from($var) {
            Err(_) => return ErrNo::Inval as u32,
            Ok(o) => o,
        }
    }
}

/// Impl the MemoryHandler for Caller.
/// This allows passing the Caller to WASIWrapper on any VFS call.
impl<'a> MemoryHandler for Caller<'a> {
    fn write_buffer(&mut self, address: u32, buffer: &[u8]) -> ErrNo {
        let memory = match self
            .get_export(WASIWrapper::LINEAR_MEMORY_NAME)
            .and_then(|export| export.into_memory()) {
                Some(s) => s,
                None => return ErrNo::NoMem,
            };
        let address = address as usize;
        unsafe {
            std::slice::from_raw_parts_mut(memory.data_ptr().add(address), buffer.len())
                .copy_from_slice(buffer)
        };
        ErrNo::Success
    }

    fn read_buffer(&self, address: u32, length: u32) -> Result<Vec<u8>, ErrNo> {
        let length = length as usize;
        let memory = match self
            .get_export(WASIWrapper::LINEAR_MEMORY_NAME)
            .and_then(|export| export.into_memory()) {
                Some(s) => s,
                None => return Err(ErrNo::NoMem),
            };
        let mut bytes: Vec<u8> = vec![0; length];
        unsafe {
            bytes.copy_from_slice(std::slice::from_raw_parts(
                memory.data_ptr().add(address as usize),
                length,
            ))
        };
        Ok(bytes)
    }
}

////////////////////////////////////////////////////////////////////////////////
// Checking function well-formedness.
////////////////////////////////////////////////////////////////////////////////

/// Checks whether `main` was declared with `argc` and `argv` or without in the
/// WASM program.
fn check_main(tau: &ExternType) -> EntrySignature {
    match tau {
        ExternType::Func(tau) => {
            let params = tau.params();

            if params == &[ValType::I32, ValType::I32] {
                EntrySignature::ArgvAndArgc
            } else if params == &[] {
                EntrySignature::NoParameters
            } else {
                EntrySignature::NoEntryFound
            }
        }
        _otherwise => EntrySignature::NoEntryFound,
    }
}

////////////////////////////////////////////////////////////////////////////////
// The Wasmtime host provisioning state.
////////////////////////////////////////////////////////////////////////////////
/// The facade of WASMTIME host provisioning state.
pub struct WasmtimeRuntimeState{ }

////////////////////////////////////////////////////////////////////////////////
// Operations on the WasmtimeRuntimeState.
////////////////////////////////////////////////////////////////////////////////

impl WasmtimeRuntimeState {
    /// Creates a new initial `HostProvisioningState`.
    pub fn new(
        filesystem : Arc<Mutex<FileSystem>>,
        program_name: &str,
    ) -> Self {
        // Load the VFS ref to the global environment. This is required by Wasmtime.
        *VFS_INSTANCE.lock().unwrap() = WASIWrapper::new(filesystem, Principal::Program(program_name.to_string()));
        Self{}
    }

    /// Executes the entry point of the WASM program provisioned into the
    /// Veracruz host.
    ///
    /// Raises a panic if the global wasmtime host is unavailable.
    /// Returns an error if no program is registered, the program is invalid,
    /// the program contains invalid external function calls or if the machine is not
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
    pub(crate) fn invoke_entry_point(binary : Vec<u8>) -> Result<ErrNo, FatalEngineError> {
        let store = Store::default();
        let module = Module::new(store.engine(), binary)?;
        let mut exports: Vec<Extern> = Vec::new();

        for import in module.imports() {
            if import.module() != WASIWrapper::WASI_SNAPSHOT_MODULE_NAME {
                return Err(FatalEngineError::InvalidWASMModule);
            }

            let host_call_body = match WASIAPIName::try_from(import.name())
                .map_err(|_|{ FatalEngineError::UnknownHostFunction(HostFunctionIndexOrName::Name(import.name().to_string())) 
            })? {
                WASIAPIName::ARGS_GET => Func::wrap(&store, Self::wasi_arg_get),
                WASIAPIName::ARGS_SIZES_GET => Func::wrap(&store, Self::wasi_args_sizes_get),
                WASIAPIName::ENVIRON_GET => Func::wrap(&store, Self::wasi_environ_get),
                WASIAPIName::ENVIRON_SIZES_GET => Func::wrap(&store, Self::wasi_environ_size_get),
                WASIAPIName::CLOCK_RES_GET => Func::wrap(&store, Self::wasi_clock_res_get),
                WASIAPIName::CLOCK_TIME_GET => Func::wrap(&store, Self::wasi_clock_time_get),
                WASIAPIName::FD_ADVISE => Func::wrap(&store, Self::wasi_fd_advise),
                WASIAPIName::FD_ALLOCATE => Func::wrap(&store, Self::wasi_fd_allocate),
                WASIAPIName::FD_CLOSE => Func::wrap(&store, Self::wasi_fd_close),
                WASIAPIName::FD_DATASYNC => Func::wrap(&store, Self::wasi_fd_datasync),
                WASIAPIName::FD_FDSTAT_GET => Func::wrap(&store, Self::wasi_fd_fdstat_get),
                WASIAPIName::FD_FDSTAT_SET_FLAGS => Func::wrap(&store, Self::wasi_fd_fdstat_set_flags),
                WASIAPIName::FD_FDSTAT_SET_RIGHTS => Func::wrap(&store, Self::wasi_fd_fdstat_set_rights),
                WASIAPIName::FD_FILESTAT_GET => Func::wrap(&store, Self::wasi_fd_filestat_get),
                WASIAPIName::FD_FILESTAT_SET_SIZE => Func::wrap(&store, Self::wasi_fd_filestat_set_size),
                WASIAPIName::FD_FILESTAT_SET_TIMES => Func::wrap(&store, Self::wasi_fd_filestat_set_times),
                WASIAPIName::FD_PREAD => Func::wrap(&store, Self::wasi_fd_pread),
                WASIAPIName::FD_PRESTAT_GET => Func::wrap(&store, Self::wasi_fd_prestat_get),
                WASIAPIName::FD_PRESTAT_DIR_NAME => Func::wrap(&store, Self::wasi_fd_prestat_dir_name),
                WASIAPIName::FD_PWRITE => Func::wrap(&store, Self::wasi_fd_pwrite),
                WASIAPIName::FD_READ => Func::wrap(&store, Self::wasi_fd_read),
                WASIAPIName::FD_READDIR => Func::wrap(&store, Self::wasi_fd_readdir),
                WASIAPIName::FD_RENUMBER => Func::wrap(&store, Self::wasi_fd_renumber),
                WASIAPIName::FD_SEEK => Func::wrap(&store, Self::wasi_fd_seek),
                WASIAPIName::FD_SYNC => Func::wrap(&store, Self::wasi_fd_sync),
                WASIAPIName::FD_TELL => Func::wrap(&store, Self::wasi_fd_tell),
                WASIAPIName::FD_WRITE => Func::wrap(&store, Self::wasi_fd_write),
                WASIAPIName::PATH_CREATE_DIRECTORY => Func::wrap(&store, Self::wasi_path_create_directory),
                WASIAPIName::PATH_FILESTAT_GET => Func::wrap(&store, Self::wasi_path_filestat_get),
                WASIAPIName::PATH_FILESTAT_SET_TIMES => Func::wrap(&store, Self::wasi_path_filestat_set_times),
                WASIAPIName::PATH_LINK => Func::wrap(&store, Self::wasi_path_link),
                WASIAPIName::PATH_OPEN => Func::wrap(&store, Self::wasi_path_open),
                WASIAPIName::PATH_READLINK => Func::wrap(&store, Self::wasi_path_readlink),
                WASIAPIName::PATH_REMOVE_DIRECTORY => Func::wrap(&store, Self::wasi_path_remove_directory),
                WASIAPIName::PATH_RENAME => Func::wrap(&store, Self::wasi_path_rename),
                WASIAPIName::PATH_SYMLINK => Func::wrap(&store, Self::wasi_path_symlink),
                WASIAPIName::PATH_UNLINK_FILE => Func::wrap(&store, Self::wasi_path_unlink_file),
                WASIAPIName::POLL_ONEOFF => Func::wrap(&store, Self::wasi_poll_oneoff),
                WASIAPIName::PROC_EXIT => Func::wrap(&store, Self::wasi_proc_exit),
                WASIAPIName::PROC_RAISE => Func::wrap(&store, Self::wasi_proc_raise),
                WASIAPIName::SCHED_YIELD => Func::wrap(&store, Self::wasi_sched_yield),
                WASIAPIName::RANDOM_GET => Func::wrap(&store, Self::wasi_random_get),
                WASIAPIName::SOCK_RECV => Func::wrap(&store, Self::wasi_sock_recv),
                WASIAPIName::SOCK_SEND => Func::wrap(&store, Self::wasi_sock_send),
                WASIAPIName::SOCK_SHUTDOWN => Func::wrap(&store, Self::wasi_sock_shutdown),
            };
            exports.push(Extern::Func(host_call_body))
        }

        let instance = Instance::new(&store, &module, &exports)?;
        let export = instance.get_export(WASIWrapper::ENTRY_POINT_NAME).ok_or(FatalEngineError::NoProgramEntryPoint)?; 
        let return_from_main = match check_main(&export.ty()) {
            EntrySignature::ArgvAndArgc => {
                let main =
                    export
                        .into_func()
                        .ok_or(FatalEngineError::NoProgramEntryPoint)?
                        .get2::<i32, i32, ()>()?;
                main(0, 0)
            }
            EntrySignature::NoParameters => {
                let main =
                    export
                        .into_func()
                        .ok_or(FatalEngineError::NoProgramEntryPoint)?
                        .get0::<()>()?;
                main()
            }
            EntrySignature::NoEntryFound => {
                return Err(FatalEngineError::NoProgramEntryPoint)
            }
        };

        // NOTE: Surpress the trap, if `proc_exit` is called.
        //       In this case, the error code is in .exit_code().
        //
        let exit_code = VFS_INSTANCE.lock()?.exit_code(); 
        let return_code = match exit_code {
            Some(e) => e,
            // If proc_exit is not call, return possible error and trap, 
            // otherwise success code `0`.
            None => {return_from_main?; 0},
        };
        let return_code = u16::try_from(return_code).map_err(|_|FatalEngineError::ReturnedCodeError)?;
        Ok(ErrNo::try_from(return_code).map_err(|_|FatalEngineError::ReturnedCodeError)?)
    }

    fn wasi_arg_get(mut caller: Caller, string_ptr_address: u32, buf_address:u32) -> u32 {
        let vfs = lock_vfs!();
        vfs.args_get(&mut caller, string_ptr_address, buf_address) as u32
    }

    fn wasi_args_sizes_get(mut caller: Caller, count_address: u32, size_address:u32) -> u32 {
        let vfs = lock_vfs!();
        vfs.args_sizes_get(&mut caller, count_address, size_address) as u32
    }

    fn wasi_environ_get(mut caller: Caller, string_ptr_address: u32, buf_address:u32) -> u32 {
        let vfs = lock_vfs!();
        vfs.environ_get(&mut caller, string_ptr_address, buf_address) as u32
    }

    fn wasi_environ_size_get(mut caller: Caller, environc_address: u32, environ_buf_size_address: u32) -> u32 {
        let vfs = lock_vfs!();
        vfs.environ_sizes_get(&mut caller, environc_address, environ_buf_size_address) as u32
    }

    fn wasi_clock_res_get(mut caller: Caller, clock_id: u32, address: u32) -> u32 {
        let mut vfs = lock_vfs!();
        vfs.clock_res_get(&mut caller, clock_id, address) as u32
    }

    fn wasi_clock_time_get(mut caller: Caller, clock_id: u32, precision: u64, address: u32) -> u32 {
        let mut vfs = lock_vfs!();
        vfs.clock_time_get(&mut caller, clock_id, precision, address) as u32
    }

    fn wasi_fd_advise(mut caller: Caller, fd: u32, offset: u64, len: u64, advice: u32) -> u32 {
        let advice = convert_wasi_arg!(advice, u8);
        let mut vfs = lock_vfs!();
        vfs.fd_advise(&mut caller, fd, offset, len, advice) as u32
    }

    fn wasi_fd_allocate(mut caller: Caller, fd : u32, offset: u64, len: u64) -> u32 {
        let mut vfs = lock_vfs!();
        vfs.fd_allocate(&mut caller, fd, offset, len) as u32
    }

    fn wasi_fd_close(_caller: Caller, fd: u32) -> u32 {
        let mut vfs = lock_vfs!();
        vfs.fd_close(fd) as u32
    }

    fn wasi_fd_datasync(mut caller: Caller, fd: u32) -> u32 {
        let mut vfs = lock_vfs!();
        vfs.fd_datasync(&mut caller, fd) as u32
    }

    fn wasi_fd_fdstat_get(mut caller: Caller, fd: u32, address: u32) -> u32 {
        let vfs = lock_vfs!();
        vfs.fd_fdstat_get(&mut caller, fd, address) as u32
    }

    fn wasi_fd_fdstat_set_flags(mut caller: Caller, fd: u32, flag: u32) -> u32 {
        let flag = convert_wasi_arg!(flag, u16);
        let mut vfs = lock_vfs!();
        vfs.fd_fdstat_set_flags(&mut caller, fd, flag) as u32
    }

    fn wasi_fd_fdstat_set_rights(mut caller: Caller, fd: u32, rights_base: u64, rights_inheriting: u64) -> u32 {
        let mut vfs = lock_vfs!();
        vfs.fd_fdstat_set_rights(&mut caller, fd, rights_base, rights_inheriting) as u32
    }

    fn wasi_fd_filestat_get(mut caller: Caller, fd: u32, address: u32) -> u32 {
        let vfs = lock_vfs!();
        vfs.fd_filestat_get(&mut caller, fd, address) as u32
    }

    fn wasi_fd_filestat_set_size(mut caller: Caller, fd: u32, size: u64) -> u32 {
        let mut vfs = lock_vfs!();
        vfs.fd_filestat_set_size(&mut caller, fd, size) as u32
    }

    fn wasi_fd_filestat_set_times(mut caller: Caller, fd: u32, atime: u64, mtime: u64, fst_flags: u32) -> u32 {
        let fst_flags = convert_wasi_arg!(fst_flags, u16);
        let mut vfs = lock_vfs!();
        vfs.fd_filestat_set_times(&mut caller, fd, atime, mtime, fst_flags) as u32
    }

    fn wasi_fd_pread(mut caller: Caller, fd: u32, iovec_base: u32, iovec_count:u32, offset: u64, address: u32) -> u32 {
        let mut vfs = lock_vfs!();
        vfs.fd_pread(&mut caller, fd, iovec_base, iovec_count, offset, address) as u32
    }

    fn wasi_fd_prestat_get(mut caller: Caller, fd: u32, address: u32) -> u32 {
        let mut vfs = lock_vfs!();
        vfs.fd_prestat_get(&mut caller, fd, address) as u32
    }

    fn wasi_fd_prestat_dir_name(mut caller: Caller, fd: u32, address: u32, size: u32) -> u32 {
        let mut vfs = lock_vfs!();
        vfs.fd_prestat_dir_name(&mut caller, fd,address,size) as u32
    }

    fn wasi_fd_pwrite(mut caller: Caller, fd: u32, iovec_base: u32, iovec_number: u32, offset: u64, address: u32) -> u32 {
        let mut vfs = lock_vfs!();
        vfs.fd_pwrite(&mut caller, fd, iovec_base, iovec_number,offset, address) as u32
    }

    fn wasi_fd_read(mut caller: Caller, fd: u32, iovec_base: u32, iovec_count:u32, address: u32) -> u32 {
        let mut vfs = lock_vfs!();
        vfs.fd_read(&mut caller, fd, iovec_base, iovec_count, address) as u32
    }

    fn wasi_fd_readdir(mut caller: Caller, fd: u32, dirent_base: u32, dirent_length: u32, cookie: u64, address: u32) -> u32 {
        let mut vfs = lock_vfs!();
        vfs.fd_readdir(&mut caller, fd, dirent_base, dirent_length, cookie, address) as u32
    }

    fn wasi_fd_renumber(mut caller: Caller, fd: u32, to_fd: u32) -> u32 {
        let mut vfs = lock_vfs!();
        vfs.fd_renumber(&mut caller, fd, to_fd) as u32
    }

    fn wasi_fd_seek(mut caller: Caller, fd: u32, offset: i64, whence: u32, address: u32) -> u32 {
        let whence = convert_wasi_arg!(whence, u8);
        let mut vfs = lock_vfs!();
        vfs.fd_seek(&mut caller, fd, offset, whence, address) as u32
    }

    fn wasi_fd_sync(mut caller: Caller, fd: u32) -> u32 {
        let mut vfs = lock_vfs!();
        vfs.fd_sync(&mut caller, fd) as u32
    }

    fn wasi_fd_tell(mut caller: Caller, fd: u32, address: u32) -> u32 {
        let vfs = lock_vfs!();
        vfs.fd_tell(&mut caller, fd, address) as u32
    }

    fn wasi_fd_write(mut caller: Caller, fd: u32, iovec_base: u32, iovec_number: u32, address: u32) -> u32 {
        let mut vfs = lock_vfs!();
        vfs.fd_write(&mut caller, fd, iovec_base, iovec_number, address) as u32
    }

    fn wasi_path_create_directory(mut caller: Caller, fd: u32, path: u32, path_len: u32) -> u32 {
        let mut vfs = lock_vfs!();
        vfs.path_create_directory(&mut caller, fd, path, path_len) as u32
    }

    fn wasi_path_filestat_get(mut caller: Caller, fd: u32, flag: u32, path: u32, path_len: u32, address: u32) -> u32 {
        let mut vfs = lock_vfs!();
        vfs.path_filestat_get(&mut caller, fd, flag, path, path_len, address) as u32
    }

    fn wasi_path_filestat_set_times(mut caller: Caller, fd: u32, flag: u32, path: u32, path_len: u32, atime: u64, mtime: u64, fst_flags: u32) -> u32 {
        let fst_flags = convert_wasi_arg!(fst_flags, u16);
        let mut vfs = lock_vfs!();
        vfs.path_filestat_set_times(&mut caller, fd, flag, path, path_len, atime, mtime, fst_flags) as u32
    }

    fn wasi_path_link(mut caller: Caller, old_fd: u32, old_flags: u32, old_address: u32, old_path_len: u32, new_fd: u32, new_address: u32, new_path_len: u32) -> u32 {
        let mut vfs = lock_vfs!();
        vfs.path_link(&mut caller, old_fd, old_flags, old_address, old_path_len, new_fd, new_address, new_path_len) as u32
    }

    fn wasi_path_open(mut caller: Caller, fd: u32, dir_flags: u32, path_address: u32, path_length: u32, oflags : u32, fs_rights_base: u64, fs_rights_inheriting: u64, fd_flags: u32, address: u32) -> u32 {
        let oflags = convert_wasi_arg!(oflags, u16);
        let fd_flags = convert_wasi_arg!(fd_flags, u16);
        let mut vfs = lock_vfs!();
        vfs.path_open(
            &mut caller,
            fd,
            dir_flags,
            path_address,
            path_length,
            oflags,
            fs_rights_base,
            fs_rights_inheriting,
            fd_flags,
            address,
        ) as u32
    }

    fn wasi_path_readlink(mut caller: Caller, fd: u32, path: u32, path_len: u32, buf: u32, buf_len: u32, address: u32) -> u32 {
        let mut vfs = lock_vfs!();
        vfs.path_readlink(&mut caller, fd, path, path_len, buf, buf_len, address) as u32
    }

    fn wasi_path_remove_directory(mut caller: Caller, fd: u32, path: u32, path_len: u32,) -> u32 {
        let mut vfs = lock_vfs!();
        vfs.path_remove_directory(&mut caller, fd, path, path_len) as u32
    }

    fn wasi_path_rename(mut caller: Caller, old_fd: u32, old_path: u32, old_len: u32, new_fd: u32, new_path: u32, new_len: u32) -> u32 {
        let mut vfs = lock_vfs!();
        vfs.path_rename(&mut caller, old_fd, old_path, old_len, new_fd, new_path, new_len) as u32
    }

    fn wasi_path_symlink(mut caller: Caller, old_address: u32, old_path_len: u32, fd: u32, new_address: u32, new_path_len: u32) -> u32 {
        let mut vfs = lock_vfs!();
        vfs.path_symlink(&mut caller, old_address, old_path_len, fd, new_address, new_path_len) as u32
    }

    fn wasi_path_unlink_file(mut caller: Caller,fd: u32,  path: u32, path_len: u32) -> u32 {
        let mut vfs = lock_vfs!();
        vfs.path_unlink_file(&mut caller, fd, path, path_len) as u32
    }

    fn wasi_poll_oneoff(mut caller: Caller, subscriptions: u32, events: u32, size:u32, address:u32) -> u32 {
        let mut vfs = lock_vfs!();
        vfs.poll_oneoff(&mut caller, subscriptions, events,size, address) as u32
    }

    fn wasi_proc_exit(mut caller: Caller, exit_code: u32) {
        let mut vfs = match VFS_INSTANCE.lock() {
            Ok(v) => v,
            // NOTE: We have no choice but panic here, since this function cannot return error!
            Err(e) => panic!(format!("Failed to lock return code variable, with error {}",e)),
        };
        vfs.proc_exit(&mut caller, exit_code);
    }

    fn wasi_proc_raise(mut caller: Caller, signal: u32) -> u32 {
        let signal = convert_wasi_arg!(signal, u8);
        let mut vfs = lock_vfs!();
        vfs.proc_raise(&mut caller, signal) as u32
    }

    fn wasi_sched_yield(mut caller: Caller) -> u32 {
        let mut vfs = lock_vfs!();
        vfs.sched_yield(&mut caller) as u32
    }

    fn wasi_random_get(mut caller: Caller, address: u32, length: u32) -> u32 {
        let mut vfs = lock_vfs!();
        vfs.random_get(&mut caller, address, length) as u32
    }

    fn wasi_sock_recv(mut caller: Caller, socket: u32, buf_address: u32, buf_len: u32, ri_flag: u32, ro_data_len: u32, ro_flag: u32) -> u32 {
        let ri_flag = convert_wasi_arg!(ri_flag, u16);
        let mut vfs = lock_vfs!();
        vfs.sock_recv(&mut caller, socket, buf_address, buf_len, ri_flag, ro_data_len, ro_flag) as u32
    }

    fn wasi_sock_send(mut caller: Caller, socket: u32, buf_address: u32, buf_len: u32, si_flag: u32, ro_data_len: u32) -> u32 {
        let si_flag = convert_wasi_arg!(si_flag, u16);
        let mut vfs = lock_vfs!();
        vfs.sock_send(&mut caller, socket, buf_address, buf_len, si_flag, ro_data_len) as u32
    }

    fn wasi_sock_shutdown(mut caller: Caller, socket: u32, sd_flag: u32) -> u32 {
        let sd_flag = convert_wasi_arg!(sd_flag, u8);
        let mut vfs = lock_vfs!();
        vfs.sock_shutdown(&mut caller, socket, sd_flag) as u32
    }
}

/// The `WasmtimeHostProvisioningState` implements everything needed to create a
/// compliant instance of `ExecutionEngine`.
impl ExecutionEngine for WasmtimeRuntimeState {

    /// ExecutionEngine wrapper of invoke_entry_point.
    /// Raises a panic if the global wasmtime host is unavailable.
    #[inline]
    fn invoke_entry_point(&mut self, file_name: &str) -> Result<ErrNo, FatalEngineError> {
        let program = VFS_INSTANCE.lock()?.read_file_by_filename(file_name)?;
        Self::invoke_entry_point(program.to_vec())
    }
}

