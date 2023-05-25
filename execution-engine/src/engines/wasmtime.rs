//! An implementation of the ExecutionEngine runtime state for Wasmtime.
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Copyright
//!
//! See the file `LICENSE_MIT.markdown` in the Veracruz root directory for licensing
//! and copyright information.

#![allow(clippy::too_many_arguments)]

use crate::{
    engines::common::{
        Bound, BoundMut, EntrySignature, ExecutionEngine, FatalEngineError, MemoryHandler,
        MemorySlice, MemorySliceMut, VeracruzAPIName, WasiAPIName, WasiWrapper,
    },
    fs::{FileSystem, FileSystemResult},
    Options,
};
use anyhow::{anyhow, Result};
use log::info;
use std::{
    convert::TryFrom,
    mem,
    sync::{Arc, Mutex},
    vec::Vec,
};
use wasi_types::ErrNo;
use wasmtime::{
    AsContext, AsContextMut, Caller, Config, Engine, ExternType, Linker, Memory, Module, Store,
    StoreContext, StoreContextMut, ValType,
};

////////////////////////////////////////////////////////////////////////////////
// The Wasmtime runtime state.
////////////////////////////////////////////////////////////////////////////////

type SharedMutableWasiWrapper = Arc<Mutex<WasiWrapper>>;
type CallerWrapper<'a> = Caller<'a, Arc<Mutex<WasiWrapper>>>;

/// A macro for lock and return the VFS.
/// If the locks fails, it returns Busy error code.
/// The macro need to pass a stub variable `$var2`.
macro_rules! lock_vfs {
    ($var:ident) => {
        match $var.lock() {
            Ok(v) => v,
            Err(_) => return ErrNo::Busy as u32,
        }
    };
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
    };
}

/// An implementation of MemorySlice for Wasmtime.
///
/// We use `data` function in Memory.
/// Conveniently, Memory is managed by internal reference counting, and already
/// isn't thread-safe, so we don't have to worry too much about the complex
/// lifetime requirements of MemorySlice.
pub struct WasmtimeSlice<'a, T> {
    store: StoreContext<'a, T>,
    memory: Memory,
    address: usize,
    length: usize,
}

/// An implementation of MemorySliceMut for Wasmtime.
///
/// We use `data_mut` function in Memory.
/// Conveniently, Memory is managed by internal reference counting, and already
/// isn't thread-safe, so we don't have to worry too much about the complex
/// lifetime requirements of MemorySlice.
pub struct WasmtimeSliceMut<'a, T> {
    store: StoreContextMut<'a, T>,
    memory: Memory,
    address: usize,
    length: usize,
}

/// Implementation of AsRef<u8> for  WasmtimeSlice. Implementation of Wasi is able to use this
/// function to access the linear memory in Wasmtime.
impl<'a, T> AsRef<[u8]> for WasmtimeSlice<'a, T> {
    fn as_ref(&self) -> &[u8] {
        // NOTE this is currently unsafe, but has a safe variant in recent
        // versions of wasmtime
        &(self.memory.data(&self.store))[self.address..self.address + self.length]
    }
}

/// Implementation of AsMut<u8> for  WasmtimeSlice. Implementation of Wasi is able to use this
/// function to access the linear memory in Wasmtime.
impl<'a, T> AsMut<[u8]> for WasmtimeSliceMut<'a, T> {
    fn as_mut(&mut self) -> &mut [u8] {
        // NOTE this is currently unsafe, but has a safe variant in recent
        // versions of wasmtime
        &mut (self.memory.data_mut(&mut self.store))[self.address..self.address + self.length]
    }
}

impl<T> MemorySlice for WasmtimeSlice<'_, T> {}
impl<T> MemorySliceMut for WasmtimeSliceMut<'_, T> {}

/// Impl the MemoryHandler for Caller.
/// This allows passing the Caller to WasiWrapper on any VFS call. Implementation
/// here is *NOT* thread-safe, if multiple threads manipulate this Wasmtime instance.
impl<'a, T: 'static> MemoryHandler for Caller<'a, T> {
    type Slice = WasmtimeSlice<'static, T>;
    type SliceMut = WasmtimeSliceMut<'static, T>;

    fn get_slice<'b>(
        &'b self,
        address: u32,
        length: u32,
    ) -> FileSystemResult<Bound<'b, Self::Slice>> {
        // NOTE: manually and temporarily change the mutability.
        // The unwrap will fail only if the raw pointer is null, which never happens here.
        let memory = match unsafe { (self as *const Self as *mut Self).as_mut() }
            .unwrap()
            .get_export(WasiWrapper::LINEAR_MEMORY_NAME)
            .and_then(|export| export.into_memory())
        {
            Some(s) => s,
            None => return Err(ErrNo::NoMem),
        };
        // Manually bend the lifetime to static. This can be improved when GAT
        // fully works in Rust standard.
        Ok(Bound::new(WasmtimeSlice {
            store: unsafe {
                mem::transmute::<StoreContext<'b, T>, StoreContext<'static, T>>(self.as_context())
            },
            memory,
            address: address as usize,
            length: length as usize,
        }))
    }

    fn get_slice_mut<'c>(
        &'c mut self,
        address: u32,
        length: u32,
    ) -> FileSystemResult<BoundMut<'c, Self::SliceMut>> {
        let memory = match self
            .get_export(WasiWrapper::LINEAR_MEMORY_NAME)
            .and_then(|export| export.into_memory())
        {
            Some(s) => s,
            None => return Err(ErrNo::NoMem),
        };
        // Manually bend the lifetime to static. This can be improved when GAT
        // fully works in Rust standard.
        Ok(BoundMut::new(WasmtimeSliceMut {
            store: unsafe {
                mem::transmute::<StoreContextMut<'c, T>, StoreContextMut<'static, T>>(
                    self.as_context_mut(),
                )
            },
            memory,
            address: address as usize,
            length: length as usize,
        }))
    }

    fn get_size(&self) -> FileSystemResult<u32> {
        // NOTE: manually and temporarily change the mutability.
        // Invocation of `unwrap` only fails if the raw pointer is NULL, but it never happens here.
        let memory = match unsafe { (self as *const Self as *mut Self).as_mut() }
            .unwrap()
            .get_export(WasiWrapper::LINEAR_MEMORY_NAME)
            .and_then(|export| export.into_memory())
        {
            Some(s) => s,
            None => return Err(ErrNo::NoMem),
        };
        Ok(u32::try_from(memory.data_size(&self)).unwrap())
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
            let params: Vec<ValType> = tau.params().collect();

            if params == [ValType::I32, ValType::I32] {
                EntrySignature::ArgvAndArgc
            } else if params == [] {
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
pub struct WasmtimeRuntimeState {
    /// The WASI file system wrapper. It is a sharable structure protected by lock.
    /// The common pattern is to clone it and try to lock it, to obtain the underlining
    /// WasiWrapper.
    filesystem: SharedMutableWasiWrapper,
}

////////////////////////////////////////////////////////////////////////////////
// Operations on the WasmtimeRuntimeState.
////////////////////////////////////////////////////////////////////////////////

impl WasmtimeRuntimeState {
    /// Creates a new initial `HostProvisioningState`.
    pub fn new(filesystem: FileSystem, options: Options) -> Result<Self> {
        Ok(Self {
            filesystem: Arc::new(Mutex::new(WasiWrapper::new(filesystem, options)?)),
        })
    }

    /// Executes the entry point of the WASM program provisioned into the
    /// Veracruz host.
    ///
    /// Raises a panic if the global Wasmtime host is unavailable.
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
    pub(crate) fn invoke_engine(&self, binary: Vec<u8>) -> Result<u32> {
        let mut config = Config::default();
        config.wasm_simd(true);

        let engine = Engine::new(&config)?;
        let module = Module::new(&engine, binary)?;
        let mut linker = Linker::new(&engine);

        info!("Initialized Wasmtime engine.");

        // Link all WASI functions
        let wasi_scope = WasiWrapper::WASI_SNAPSHOT_MODULE_NAME;
        linker.func_wrap(wasi_scope, WasiAPIName::ARGS_GET.into(), Self::wasi_arg_get)?;
        linker.func_wrap(
            wasi_scope,
            WasiAPIName::ARGS_SIZES_GET.into(),
            Self::wasi_args_sizes_get,
        )?;
        linker.func_wrap(
            wasi_scope,
            WasiAPIName::ENVIRON_GET.into(),
            Self::wasi_environ_get,
        )?;
        linker.func_wrap(
            wasi_scope,
            WasiAPIName::ENVIRON_SIZES_GET.into(),
            Self::wasi_environ_size_get,
        )?;
        linker.func_wrap(
            wasi_scope,
            WasiAPIName::CLOCK_RES_GET.into(),
            Self::wasi_clock_res_get,
        )?;
        linker.func_wrap(
            wasi_scope,
            WasiAPIName::CLOCK_TIME_GET.into(),
            Self::wasi_clock_time_get,
        )?;
        linker.func_wrap(
            wasi_scope,
            WasiAPIName::FD_ADVISE.into(),
            Self::wasi_fd_advise,
        )?;
        linker.func_wrap(
            wasi_scope,
            WasiAPIName::FD_ALLOCATE.into(),
            Self::wasi_fd_allocate,
        )?;
        linker.func_wrap(
            wasi_scope,
            WasiAPIName::FD_CLOSE.into(),
            Self::wasi_fd_close,
        )?;
        linker.func_wrap(
            wasi_scope,
            WasiAPIName::FD_DATASYNC.into(),
            Self::wasi_fd_datasync,
        )?;
        linker.func_wrap(
            wasi_scope,
            WasiAPIName::FD_FDSTAT_GET.into(),
            Self::wasi_fd_fdstat_get,
        )?;
        linker.func_wrap(
            wasi_scope,
            WasiAPIName::FD_FDSTAT_SET_FLAGS.into(),
            Self::wasi_fd_fdstat_set_flags,
        )?;
        linker.func_wrap(
            wasi_scope,
            WasiAPIName::FD_FDSTAT_SET_RIGHTS.into(),
            Self::wasi_fd_fdstat_set_rights,
        )?;
        linker.func_wrap(
            wasi_scope,
            WasiAPIName::FD_FILESTAT_GET.into(),
            Self::wasi_fd_filestat_get,
        )?;
        linker.func_wrap(
            wasi_scope,
            WasiAPIName::FD_FILESTAT_SET_SIZE.into(),
            Self::wasi_fd_filestat_set_size,
        )?;
        linker.func_wrap(
            wasi_scope,
            WasiAPIName::FD_FILESTAT_SET_TIMES.into(),
            Self::wasi_fd_filestat_set_times,
        )?;
        linker.func_wrap(
            wasi_scope,
            WasiAPIName::FD_PREAD.into(),
            Self::wasi_fd_pread,
        )?;
        linker.func_wrap(
            wasi_scope,
            WasiAPIName::FD_PRESTAT_GET.into(),
            Self::wasi_fd_prestat_get,
        )?;
        linker.func_wrap(
            wasi_scope,
            WasiAPIName::FD_PRESTAT_DIR_NAME.into(),
            Self::wasi_fd_prestat_dir_name,
        )?;
        linker.func_wrap(
            wasi_scope,
            WasiAPIName::FD_PWRITE.into(),
            Self::wasi_fd_pwrite,
        )?;
        linker.func_wrap(wasi_scope, WasiAPIName::FD_READ.into(), Self::wasi_fd_read)?;
        linker.func_wrap(
            wasi_scope,
            WasiAPIName::FD_READDIR.into(),
            Self::wasi_fd_readdir,
        )?;
        linker.func_wrap(
            wasi_scope,
            WasiAPIName::FD_RENUMBER.into(),
            Self::wasi_fd_renumber,
        )?;
        linker.func_wrap(wasi_scope, WasiAPIName::FD_SEEK.into(), Self::wasi_fd_seek)?;
        linker.func_wrap(wasi_scope, WasiAPIName::FD_SYNC.into(), Self::wasi_fd_sync)?;
        linker.func_wrap(wasi_scope, WasiAPIName::FD_TELL.into(), Self::wasi_fd_tell)?;
        linker.func_wrap(
            wasi_scope,
            WasiAPIName::FD_WRITE.into(),
            Self::wasi_fd_write,
        )?;
        linker.func_wrap(
            wasi_scope,
            WasiAPIName::PATH_CREATE_DIRECTORY.into(),
            Self::wasi_path_create_directory,
        )?;
        linker.func_wrap(
            wasi_scope,
            WasiAPIName::PATH_FILESTAT_GET.into(),
            Self::wasi_path_filestat_get,
        )?;
        linker.func_wrap(
            wasi_scope,
            WasiAPIName::PATH_FILESTAT_SET_TIMES.into(),
            Self::wasi_path_filestat_set_times,
        )?;
        linker.func_wrap(
            wasi_scope,
            WasiAPIName::PATH_LINK.into(),
            Self::wasi_path_link,
        )?;
        linker.func_wrap(
            wasi_scope,
            WasiAPIName::PATH_OPEN.into(),
            Self::wasi_path_open,
        )?;
        linker.func_wrap(
            wasi_scope,
            WasiAPIName::PATH_READLINK.into(),
            Self::wasi_path_readlink,
        )?;
        linker.func_wrap(
            wasi_scope,
            WasiAPIName::PATH_REMOVE_DIRECTORY.into(),
            Self::wasi_path_remove_directory,
        )?;
        linker.func_wrap(
            wasi_scope,
            WasiAPIName::PATH_RENAME.into(),
            Self::wasi_path_rename,
        )?;
        linker.func_wrap(
            wasi_scope,
            WasiAPIName::PATH_SYMLINK.into(),
            Self::wasi_path_symlink,
        )?;
        linker.func_wrap(
            wasi_scope,
            WasiAPIName::PATH_UNLINK_FILE.into(),
            Self::wasi_path_unlink_file,
        )?;
        linker.func_wrap(
            wasi_scope,
            WasiAPIName::POLL_ONEOFF.into(),
            Self::wasi_poll_oneoff,
        )?;
        linker.func_wrap(
            wasi_scope,
            WasiAPIName::PROC_EXIT.into(),
            Self::wasi_proc_exit,
        )?;
        linker.func_wrap(
            wasi_scope,
            WasiAPIName::PROC_RAISE.into(),
            Self::wasi_proc_raise,
        )?;
        linker.func_wrap(
            wasi_scope,
            WasiAPIName::SCHED_YIELD.into(),
            Self::wasi_sched_yield,
        )?;
        linker.func_wrap(
            wasi_scope,
            WasiAPIName::RANDOM_GET.into(),
            Self::wasi_random_get,
        )?;
        linker.func_wrap(
            wasi_scope,
            WasiAPIName::SOCK_RECV.into(),
            Self::wasi_sock_recv,
        )?;
        linker.func_wrap(
            wasi_scope,
            WasiAPIName::SOCK_SEND.into(),
            Self::wasi_sock_send,
        )?;
        linker.func_wrap(
            wasi_scope,
            WasiAPIName::SOCK_SHUTDOWN.into(),
            Self::wasi_sock_shutdown,
        )?;

        // link Veracruz custom functions
        linker.func_wrap(
            WasiWrapper::VERACRUZ_SI_MODULE_NAME,
            VeracruzAPIName::FD_CREATE.into(),
            Self::veracruz_si_fd_create,
        )?;

        info!("Link external functions.");

        // TODO: change
        let mut store = Store::new(&engine, self.filesystem.clone());
        let instance = linker.instantiate(&mut store, &module)?;

        info!("Linker instantiates.");

        let export = instance
            .get_export(&mut store, WasiWrapper::ENTRY_POINT_NAME)
            .ok_or(FatalEngineError::NoProgramEntryPoint)?;

        info!("Get the main function.");

        let return_from_main = match check_main(&export.ty(&store)) {
            EntrySignature::ArgvAndArgc => instance
                .get_typed_func::<(i32, i32), ()>(&mut store, WasiWrapper::ENTRY_POINT_NAME)?
                .call(&mut store, (0, 0)),
            EntrySignature::NoParameters => instance
                .get_typed_func::<(), ()>(&mut store, WasiWrapper::ENTRY_POINT_NAME)?
                .call(&mut store, ()),
            EntrySignature::NoEntryFound => {
                return Err(anyhow!(FatalEngineError::NoProgramEntryPoint))
            }
        };

        info!("Execution returns.");

        // NOTE: Surpress the trap, if `proc_exit` is called.
        //       In this case, the error code is in .exit_code().
        //
        let exit_code = store
            .into_data()
            .lock()
            .map_err(|_| anyhow!(FatalEngineError::FailedLockEngine))?
            .exit_code();
        info!("Exit code {:?}", exit_code);
        match exit_code {
            Some(e) => Ok(e),
            // If proc_exit is not call, return possible error and trap,
            // otherwise the actual return code or default success code `0`.
            None => {
                info!(
                    "The return trace: {:?}, (`proc_exit` is not called).",
                    return_from_main
                );
                return_from_main?;
                Ok(0)
            }
        }
    }

    fn convert_to_errno(input: FileSystemResult<()>) -> u32 {
        let errno = match input {
            Ok(_) => ErrNo::Success,
            Err(e) => e,
        };
        errno as u32
    }

    fn wasi_arg_get(
        mut caller: CallerWrapper<'_>,
        string_ptr_address: u32,
        buf_address: u32,
    ) -> u32 {
        let caller_data = caller.data().clone();
        let vfs = lock_vfs!(caller_data);
        Self::convert_to_errno(vfs.args_get(&mut caller, string_ptr_address, buf_address))
    }

    fn wasi_args_sizes_get(
        mut caller: CallerWrapper<'_>,
        count_address: u32,
        size_address: u32,
    ) -> u32 {
        let caller_data = caller.data().clone();
        let vfs = lock_vfs!(caller_data);
        Self::convert_to_errno(vfs.args_sizes_get(&mut caller, count_address, size_address))
    }

    fn wasi_environ_get(
        mut caller: CallerWrapper<'_>,
        string_ptr_address: u32,
        buf_address: u32,
    ) -> u32 {
        let caller_data = caller.data().clone();
        let vfs = lock_vfs!(caller_data);
        Self::convert_to_errno(vfs.environ_get(&mut caller, string_ptr_address, buf_address))
    }

    fn wasi_environ_size_get(
        mut caller: CallerWrapper<'_>,
        environc_address: u32,
        environ_buf_size_address: u32,
    ) -> u32 {
        let caller_data = caller.data().clone();
        let vfs = lock_vfs!(caller_data);
        Self::convert_to_errno(vfs.environ_sizes_get(
            &mut caller,
            environc_address,
            environ_buf_size_address,
        ))
    }

    fn wasi_clock_res_get(mut caller: CallerWrapper<'_>, clock_id: u32, address: u32) -> u32 {
        let caller_data = caller.data().clone();
        let mut vfs = lock_vfs!(caller_data);
        Self::convert_to_errno(vfs.clock_res_get(&mut caller, clock_id, address))
    }

    fn wasi_clock_time_get(
        mut caller: CallerWrapper<'_>,
        clock_id: u32,
        precision: u64,
        address: u32,
    ) -> u32 {
        let caller_data = caller.data().clone();
        let mut vfs = lock_vfs!(caller_data);
        Self::convert_to_errno(vfs.clock_time_get(&mut caller, clock_id, precision, address))
    }

    fn wasi_fd_advise(
        mut caller: CallerWrapper<'_>,
        fd: u32,
        offset: u64,
        len: u64,
        advice: u32,
    ) -> u32 {
        let advice = convert_wasi_arg!(advice, u8);
        let caller_data = caller.data().clone();
        let mut vfs = lock_vfs!(caller_data);
        Self::convert_to_errno(vfs.fd_advise(&mut caller, fd, offset, len, advice))
    }

    fn wasi_fd_allocate(mut caller: CallerWrapper<'_>, fd: u32, offset: u64, len: u64) -> u32 {
        let caller_data = caller.data().clone();
        let mut vfs = lock_vfs!(caller_data);
        Self::convert_to_errno(vfs.fd_allocate(&mut caller, fd, offset, len))
    }

    fn wasi_fd_close(caller: CallerWrapper<'_>, fd: u32) -> u32 {
        let caller_data = caller.data().clone();
        let mut vfs = lock_vfs!(caller_data);
        Self::convert_to_errno(vfs.fd_close(&caller, fd))
    }

    fn wasi_fd_datasync(mut caller: CallerWrapper<'_>, fd: u32) -> u32 {
        let caller_data = caller.data().clone();
        let mut vfs = lock_vfs!(caller_data);
        Self::convert_to_errno(vfs.fd_datasync(&mut caller, fd))
    }

    fn wasi_fd_fdstat_get(mut caller: CallerWrapper<'_>, fd: u32, address: u32) -> u32 {
        let caller_data = caller.data().clone();
        let vfs = lock_vfs!(caller_data);
        Self::convert_to_errno(vfs.fd_fdstat_get(&mut caller, fd, address))
    }

    fn wasi_fd_fdstat_set_flags(mut caller: CallerWrapper<'_>, fd: u32, flag: u32) -> u32 {
        let flag = convert_wasi_arg!(flag, u16);
        let caller_data = caller.data().clone();
        let mut vfs = lock_vfs!(caller_data);
        Self::convert_to_errno(vfs.fd_fdstat_set_flags(&mut caller, fd, flag))
    }

    fn wasi_fd_fdstat_set_rights(
        mut caller: CallerWrapper<'_>,
        fd: u32,
        rights_base: u64,
        rights_inheriting: u64,
    ) -> u32 {
        let caller_data = caller.data().clone();
        let mut vfs = lock_vfs!(caller_data);
        Self::convert_to_errno(vfs.fd_fdstat_set_rights(
            &mut caller,
            fd,
            rights_base,
            rights_inheriting,
        ))
    }

    fn wasi_fd_filestat_get(mut caller: CallerWrapper<'_>, fd: u32, address: u32) -> u32 {
        let caller_data = caller.data().clone();
        let vfs = lock_vfs!(caller_data);
        Self::convert_to_errno(vfs.fd_filestat_get(&mut caller, fd, address))
    }

    fn wasi_fd_filestat_set_size(mut caller: CallerWrapper<'_>, fd: u32, size: u64) -> u32 {
        let caller_data = caller.data().clone();
        let mut vfs = lock_vfs!(caller_data);
        Self::convert_to_errno(vfs.fd_filestat_set_size(&mut caller, fd, size))
    }

    fn wasi_fd_filestat_set_times(
        mut caller: CallerWrapper<'_>,
        fd: u32,
        atime: u64,
        mtime: u64,
        fst_flags: u32,
    ) -> u32 {
        let fst_flags = convert_wasi_arg!(fst_flags, u16);
        let caller_data = caller.data().clone();
        let mut vfs = lock_vfs!(caller_data);
        Self::convert_to_errno(vfs.fd_filestat_set_times(&mut caller, fd, atime, mtime, fst_flags))
    }

    fn wasi_fd_pread(
        mut caller: CallerWrapper<'_>,
        fd: u32,
        iovec_base: u32,
        iovec_count: u32,
        offset: u64,
        address: u32,
    ) -> u32 {
        let caller_data = caller.data().clone();
        let mut vfs = lock_vfs!(caller_data);
        Self::convert_to_errno(vfs.fd_pread(
            &mut caller,
            fd,
            iovec_base,
            iovec_count,
            offset,
            address,
        ))
    }

    fn wasi_fd_prestat_get(mut caller: CallerWrapper<'_>, fd: u32, address: u32) -> u32 {
        info!("prestat_get called");
        let caller_data = caller.data().clone();
        let mut vfs = lock_vfs!(caller_data);
        info!("succ lock");
        Self::convert_to_errno(vfs.fd_prestat_get(&mut caller, fd, address))
    }

    fn wasi_fd_prestat_dir_name(
        mut caller: CallerWrapper<'_>,
        fd: u32,
        address: u32,
        size: u32,
    ) -> u32 {
        let caller_data = caller.data().clone();
        let mut vfs = lock_vfs!(caller_data);
        Self::convert_to_errno(vfs.fd_prestat_dir_name(&mut caller, fd, address, size))
    }

    fn wasi_fd_pwrite(
        mut caller: CallerWrapper<'_>,
        fd: u32,
        iovec_base: u32,
        iovec_number: u32,
        offset: u64,
        address: u32,
    ) -> u32 {
        let caller_data = caller.data().clone();
        let mut vfs = lock_vfs!(caller_data);
        Self::convert_to_errno(vfs.fd_pwrite(
            &mut caller,
            fd,
            iovec_base,
            iovec_number,
            offset,
            address,
        ))
    }

    fn wasi_fd_read(
        mut caller: CallerWrapper<'_>,
        fd: u32,
        iovec_base: u32,
        iovec_count: u32,
        address: u32,
    ) -> u32 {
        let caller_data = caller.data().clone();
        let mut vfs = lock_vfs!(caller_data);
        Self::convert_to_errno(vfs.fd_read(&mut caller, fd, iovec_base, iovec_count, address))
    }

    fn wasi_fd_readdir(
        mut caller: CallerWrapper<'_>,
        fd: u32,
        dirent_base: u32,
        dirent_length: u32,
        cookie: u64,
        address: u32,
    ) -> u32 {
        let caller_data = caller.data().clone();
        let mut vfs = lock_vfs!(caller_data);
        Self::convert_to_errno(vfs.fd_readdir(
            &mut caller,
            fd,
            dirent_base,
            dirent_length,
            cookie,
            address,
        ))
    }

    fn wasi_fd_renumber(mut caller: CallerWrapper<'_>, fd: u32, to_fd: u32) -> u32 {
        let caller_data = caller.data().clone();
        let mut vfs = lock_vfs!(caller_data);
        Self::convert_to_errno(vfs.fd_renumber(&mut caller, fd, to_fd))
    }

    fn wasi_fd_seek(
        mut caller: CallerWrapper<'_>,
        fd: u32,
        offset: i64,
        whence: u32,
        address: u32,
    ) -> u32 {
        let whence = convert_wasi_arg!(whence, u8);
        let caller_data = caller.data().clone();
        let mut vfs = lock_vfs!(caller_data);
        Self::convert_to_errno(vfs.fd_seek(&mut caller, fd, offset, whence, address))
    }

    fn wasi_fd_sync(mut caller: CallerWrapper<'_>, fd: u32) -> u32 {
        let caller_data = caller.data().clone();
        let mut vfs = lock_vfs!(caller_data);
        Self::convert_to_errno(vfs.fd_sync(&mut caller, fd))
    }

    fn wasi_fd_tell(mut caller: CallerWrapper<'_>, fd: u32, address: u32) -> u32 {
        let caller_data = caller.data().clone();
        let vfs = lock_vfs!(caller_data);
        Self::convert_to_errno(vfs.fd_tell(&mut caller, fd, address))
    }

    fn wasi_fd_write(
        mut caller: CallerWrapper<'_>,
        fd: u32,
        iovec_base: u32,
        iovec_number: u32,
        address: u32,
    ) -> u32 {
        let caller_data = caller.data().clone();
        let mut vfs = lock_vfs!(caller_data);
        Self::convert_to_errno(vfs.fd_write(&mut caller, fd, iovec_base, iovec_number, address))
    }

    fn wasi_path_create_directory(
        mut caller: CallerWrapper<'_>,
        fd: u32,
        path: u32,
        path_len: u32,
    ) -> u32 {
        let caller_data = caller.data().clone();
        let mut vfs = lock_vfs!(caller_data);
        Self::convert_to_errno(vfs.path_create_directory(&mut caller, fd, path, path_len))
    }

    fn wasi_path_filestat_get(
        mut caller: CallerWrapper<'_>,
        fd: u32,
        flag: u32,
        path: u32,
        path_len: u32,
        address: u32,
    ) -> u32 {
        let caller_data = caller.data().clone();
        let mut vfs = lock_vfs!(caller_data);
        Self::convert_to_errno(vfs.path_filestat_get(
            &mut caller,
            fd,
            flag,
            path,
            path_len,
            address,
        ))
    }

    fn wasi_path_filestat_set_times(
        mut caller: CallerWrapper<'_>,
        fd: u32,
        flag: u32,
        path: u32,
        path_len: u32,
        atime: u64,
        mtime: u64,
        fst_flags: u32,
    ) -> u32 {
        let fst_flags = convert_wasi_arg!(fst_flags, u16);
        let caller_data = caller.data().clone();
        let mut vfs = lock_vfs!(caller_data);
        Self::convert_to_errno(vfs.path_filestat_set_times(
            &mut caller,
            fd,
            flag,
            path,
            path_len,
            atime,
            mtime,
            fst_flags,
        ))
    }

    fn wasi_path_link(
        mut caller: CallerWrapper<'_>,
        old_fd: u32,
        old_flags: u32,
        old_address: u32,
        old_path_len: u32,
        new_fd: u32,
        new_address: u32,
        new_path_len: u32,
    ) -> u32 {
        let caller_data = caller.data().clone();
        let mut vfs = lock_vfs!(caller_data);
        Self::convert_to_errno(vfs.path_link(
            &mut caller,
            old_fd,
            old_flags,
            old_address,
            old_path_len,
            new_fd,
            new_address,
            new_path_len,
        ))
    }

    fn wasi_path_open(
        mut caller: CallerWrapper<'_>,
        fd: u32,
        dir_flags: u32,
        path_address: u32,
        path_length: u32,
        oflags: u32,
        fs_rights_base: u64,
        fs_rights_inheriting: u64,
        fd_flags: u32,
        address: u32,
    ) -> u32 {
        let oflags = convert_wasi_arg!(oflags, u16);
        let fd_flags = convert_wasi_arg!(fd_flags, u16);
        let caller_data = caller.data().clone();
        let mut vfs = lock_vfs!(caller_data);
        Self::convert_to_errno(vfs.path_open(
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
        ))
    }

    fn wasi_path_readlink(
        mut caller: CallerWrapper<'_>,
        fd: u32,
        path: u32,
        path_len: u32,
        buf: u32,
        buf_len: u32,
        address: u32,
    ) -> u32 {
        let caller_data = caller.data().clone();
        let mut vfs = lock_vfs!(caller_data);
        Self::convert_to_errno(vfs.path_readlink(
            &mut caller,
            fd,
            path,
            path_len,
            buf,
            buf_len,
            address,
        ))
    }

    fn wasi_path_remove_directory(
        mut caller: CallerWrapper<'_>,
        fd: u32,
        path: u32,
        path_len: u32,
    ) -> u32 {
        let caller_data = caller.data().clone();
        let mut vfs = lock_vfs!(caller_data);
        Self::convert_to_errno(vfs.path_remove_directory(&mut caller, fd, path, path_len))
    }

    fn wasi_path_rename(
        mut caller: CallerWrapper<'_>,
        old_fd: u32,
        old_path: u32,
        old_len: u32,
        new_fd: u32,
        new_path: u32,
        new_len: u32,
    ) -> u32 {
        let caller_data = caller.data().clone();
        let mut vfs = lock_vfs!(caller_data);
        Self::convert_to_errno(vfs.path_rename(
            &mut caller,
            old_fd,
            old_path,
            old_len,
            new_fd,
            new_path,
            new_len,
        ))
    }

    fn wasi_path_symlink(
        mut caller: CallerWrapper<'_>,
        old_address: u32,
        old_path_len: u32,
        fd: u32,
        new_address: u32,
        new_path_len: u32,
    ) -> u32 {
        let caller_data = caller.data().clone();
        let mut vfs = lock_vfs!(caller_data);
        Self::convert_to_errno(vfs.path_symlink(
            &mut caller,
            old_address,
            old_path_len,
            fd,
            new_address,
            new_path_len,
        ))
    }

    fn wasi_path_unlink_file(
        mut caller: CallerWrapper<'_>,
        fd: u32,
        path: u32,
        path_len: u32,
    ) -> u32 {
        let caller_data = caller.data().clone();
        let mut vfs = lock_vfs!(caller_data);
        Self::convert_to_errno(vfs.path_unlink_file(&mut caller, fd, path, path_len))
    }

    fn wasi_poll_oneoff(
        mut caller: CallerWrapper<'_>,
        subscriptions: u32,
        events: u32,
        size: u32,
        address: u32,
    ) -> u32 {
        let caller_data = caller.data().clone();
        let mut vfs = lock_vfs!(caller_data);
        Self::convert_to_errno(vfs.poll_oneoff(&mut caller, subscriptions, events, size, address))
    }

    fn wasi_proc_exit(mut caller: CallerWrapper<'_>, exit_code: u32) {
        let caller_data = &caller.data().clone();
        let mut vfs = match caller_data.lock() {
            Ok(v) => v,
            Err(_) => panic!("unexpected failure"),
        };

        vfs.proc_exit(&mut caller, exit_code);
    }

    fn wasi_proc_raise(mut caller: CallerWrapper<'_>, signal: u32) -> u32 {
        let signal = convert_wasi_arg!(signal, u8);
        let caller_data = caller.data().clone();
        let mut vfs = lock_vfs!(caller_data);
        Self::convert_to_errno(vfs.proc_raise(&mut caller, signal))
    }

    fn wasi_sched_yield(mut caller: CallerWrapper<'_>) -> u32 {
        let caller_data = caller.data().clone();
        let mut vfs = lock_vfs!(caller_data);
        Self::convert_to_errno(vfs.sched_yield(&mut caller))
    }

    fn wasi_random_get(mut caller: CallerWrapper<'_>, address: u32, length: u32) -> u32 {
        let caller_data = caller.data().clone();
        let mut vfs = lock_vfs!(caller_data);
        Self::convert_to_errno(vfs.random_get(&mut caller, address, length))
    }

    fn wasi_sock_recv(
        mut caller: CallerWrapper<'_>,
        socket: u32,
        buf_address: u32,
        buf_len: u32,
        ri_flag: u32,
        ro_data_len: u32,
        ro_flag: u32,
    ) -> u32 {
        let ri_flag = convert_wasi_arg!(ri_flag, u16);
        let caller_data = caller.data().clone();
        let mut vfs = lock_vfs!(caller_data);
        Self::convert_to_errno(vfs.sock_recv(
            &mut caller,
            socket,
            buf_address,
            buf_len,
            ri_flag,
            ro_data_len,
            ro_flag,
        ))
    }

    fn wasi_sock_send(
        mut caller: CallerWrapper<'_>,
        socket: u32,
        buf_address: u32,
        buf_len: u32,
        si_flag: u32,
        ro_data_len: u32,
    ) -> u32 {
        let si_flag = convert_wasi_arg!(si_flag, u16);
        let caller_data = caller.data().clone();
        let mut vfs = lock_vfs!(caller_data);
        Self::convert_to_errno(vfs.sock_send(
            &mut caller,
            socket,
            buf_address,
            buf_len,
            si_flag,
            ro_data_len,
        ))
    }

    fn wasi_sock_shutdown(mut caller: CallerWrapper, socket: u32, sd_flag: u32) -> u32 {
        let sd_flag = convert_wasi_arg!(sd_flag, u8);
        let caller_data = caller.data().clone();
        let mut vfs = lock_vfs!(caller_data);
        Self::convert_to_errno(vfs.sock_shutdown(&mut caller, socket, sd_flag))
    }

    fn veracruz_si_fd_create(mut caller: CallerWrapper, address: u32) -> u32 {
        let caller_data = caller.data().clone();
        let mut vfs = lock_vfs!(caller_data);
        Self::convert_to_errno(vfs.fd_create(&mut caller, address))
    }

}

/// The `WasmtimeHostProvisioningState` implements everything needed to create a
/// compliant instance of `ExecutionEngine`.
impl ExecutionEngine for WasmtimeRuntimeState {
    /// ExecutionEngine wrapper of `invoke_engine`.  Raises a panic if
    /// the global Wasmtime host is unavailable.
    #[inline]
    fn invoke_entry_point(&mut self, program: Vec<u8>) -> Result<u32> {
        self.invoke_engine(program)
    }
}
