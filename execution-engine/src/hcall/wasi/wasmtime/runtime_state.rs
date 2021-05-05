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

use std::{time::Instant, vec::Vec, string::String, collections::HashMap};
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
use byteorder::{ByteOrder, LittleEndian};
use wasmtime::{Caller, Extern, ExternType, Func, Instance, Module, Store, Trap, ValType, Memory};
use wasi_types::{
    Advice, ErrNo, Fd, FdFlags, FdStat, FileDelta, FileSize, FileStat, IoVec, LookupFlags, Rights,
    Size, Whence, OpenFlags,
};
use std::str::FromStr;

////////////////////////////////////////////////////////////////////////////////
// The Wasmtime runtime state.
////////////////////////////////////////////////////////////////////////////////


lazy_static! {
    // The initial value has NO use.
    static ref VFS_INSTANCE: Mutex<WASIWrapper> = Mutex::new(WASIWrapper::new(Arc::new(Mutex::new(FileSystem::new(HashMap::new()))), Principal::NoCap));
    // The initial value has NO use.
    static ref CUR_PROGRAM: Mutex<Principal> = Mutex::new(Principal::NoCap);
    // Return code. It stores the code from proc_exit call.
    static ref RETURN_CODE: Mutex<Option<i32>> = Mutex::new(None);
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
    println!("check_main: {:?}",tau);
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
    pub(crate) fn invoke_entry_point_base(program_name : &str, binary : Vec<u8>) -> Result<ErrNo, FatalEngineError> {
        let start = Instant::now();

        let store = Store::default();

        *CUR_PROGRAM.lock()? = Principal::Program(program_name.to_string());

        let module = Module::new(store.engine(), binary)?;
        let mut exports: Vec<Extern> = Vec::new();

        for import in module.imports() {
            if import.module() != WASIWrapper::WASI_SNAPSHOT_MODULE_NAME {
                return Err(FatalEngineError::InvalidWASMModule);
            }

            let host_call_body = match WASIAPIName::try_from(import.name())
                // TODO CHANGE THE ERROR TYPE
                .map_err(|e|{ FatalEngineError::UnknownHostFunction(HostFunctionIndexOrName::Name(import.name().to_string())) 
            })? {
                WASIAPIName::PROC_EXIT => Func::wrap(&store, Self::wasi_proc_exit),
                WASIAPIName::FD_CLOSE => Func::wrap(&store, Self::wasi_fd_close),
                WASIAPIName::FD_WRITE => Func::wrap(&store, Self::wasi_fd_write),
                WASIAPIName::PATH_OPEN => Func::wrap(&store, Self::wasi_path_open),
                WASIAPIName::FD_PRESTAT_GET => Func::wrap(&store, Self::wasi_fd_prestat_get),
                WASIAPIName::FD_PRESTAT_DIR_NAME => Func::wrap(&store, Self::wasi_fd_prestat_dir_name),
                WASIAPIName::ENVIRON_GET => Func::wrap(&store, Self::wasi_environ_get),
                WASIAPIName::ENVIRON_SIZES_GET => Func::wrap(&store, Self::wasi_environ_size_get),
                WASIAPIName::FD_FILESTAT_GET => Func::wrap(&store, Self::wasi_fd_filestat_get),
                WASIAPIName::FD_READ => Func::wrap(&store, Self::wasi_fd_read),
                WASIAPIName::RANDOM_GET => Func::wrap(&store, Self::wasi_random_get),
                WASIAPIName::FD_SEEK => Func::wrap(&store, Self::wasi_fd_seek),
                // TODO: FILL IN THE FUNCTION CALL
                // TODO: FILL IN THE FUNCTION CALL
                // TODO: FILL IN THE FUNCTION CALL
                // TODO: FILL IN THE FUNCTION CALL
                // TODO: FILL IN THE FUNCTION CALL
                // TODO: FILL IN THE FUNCTION CALL
                // TODO: FILL IN THE FUNCTION CALL
                // TODO: FILL IN THE FUNCTION CALL
                // TODO: FILL IN THE FUNCTION CALL
                // TODO: FILL IN THE FUNCTION CALL
                // TODO: FILL IN THE FUNCTION CALL
                // TODO: FILL IN THE FUNCTION CALL
                otherwise => panic!(),
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

                println!(
                    ">>> invoke_main took {:?} to setup pre-main.",
                    start.elapsed()
                );
                main(0, 0)
            }
            EntrySignature::NoParameters => {
                let main =
                    export
                        .into_func()
                        .ok_or(FatalEngineError::NoProgramEntryPoint)?
                        .get0::<()>()?;

                println!(
                    ">>> invoke_main took {:?} to setup pre-main.",
                    start.elapsed()
                );
                main()
            }
            EntrySignature::NoEntryFound => {
                return Err(FatalEngineError::NoProgramEntryPoint)
            }
        };

        // NOTE: Surpress the trap, if `proc_exit` is called.
        //       In this case, the error code is RETURN_CODE.
        let return_code = match *RETURN_CODE.lock()? {
            Some(e) => e,
            // If proc_exit is not call, return possible error and trap, 
            // otherwise success code `0`.
            None => {return_from_main?; 0},
        };
        let return_code = u16::try_from(return_code).map_err(|_|FatalEngineError::ReturnedCodeError)?;
        Ok(ErrNo::try_from(return_code).map_err(|_|FatalEngineError::ReturnedCodeError)?)
    }

    fn wasi_proc_exit(_caller: Caller, exit_code: u32) {
        println!("call wasi_proc_exit: {}",exit_code);
        match RETURN_CODE.lock() {
            Ok(mut o) =>  *o = Some(exit_code as i32),
            // NOTE: We have no choice but panic here, since this function cannot return error!
            Err(e) => panic!(format!("Failed to lock return code variable, with error {}",e)),
        };
    }

    fn wasi_fd_close(_caller: Caller, fd: u32) -> u32 {
        println!("call wasi_fd_close");
        let mut vfs = lock_vfs!();
        vfs.fd_close(fd) as u32
    }

    fn wasi_fd_write(mut caller: Caller, fd: u32, iovec_base: u32, iovec_number: u32, address: u32) -> u32 {
        println!("call wasi_fd_write: fd {:?} iovec_base {:?} iovec_nunmber {:?} address {:?}", fd,iovec_base,iovec_number,address);
        let mut vfs = lock_vfs!();
        vfs.fd_write(&mut caller, fd, iovec_base, iovec_number, address) as u32
    }

    fn wasi_path_open(mut caller: Caller, fd: u32, dir_flags: u32, path_address: u32, path_length: u32, oflags : u32, fs_rights_base: u64, fs_rights_inheriting: u64, fd_flags: u32, address: u32) -> u32 {
        println!("call wasi_path_open");
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

    fn wasi_fd_prestat_get(mut caller: Caller, fd: u32, address: u32) -> u32 {
        println!("call wasi_fd_prestat_get");
        let mut vfs = lock_vfs!();
        vfs.fd_prestat_get(&mut caller, fd, address) as u32
    }

    fn wasi_fd_prestat_dir_name(mut caller: Caller, fd: u32, address: u32, size: u32) -> u32 {
        println!("call wasi_fd_prestat_dir_name");
        let mut vfs = lock_vfs!();
        vfs.fd_prestat_dir_name(&mut caller, fd,address,size) as u32
    }

    fn wasi_environ_get(mut caller: Caller, environ_address: u32, environ_buf_address: u32) -> u32 {
        println!("call wasi_environ_get");
        let mut vfs = lock_vfs!(); 
        vfs.environ_get(&mut caller, environ_address, environ_buf_address) as u32
    }

    fn wasi_environ_size_get(mut caller: Caller, environc_address: u32, environ_buf_size_address: u32) -> u32 {
        println!("call wasi_environ_size_get");
        let mut vfs = lock_vfs!();
        vfs.environ_sizes_get(&mut caller, environc_address, environ_buf_size_address) as u32
    }

    fn wasi_fd_filestat_get(caller: Caller, fd: u32, address: u32) -> u32 {
        //let memory = match caller
            //.get_export(LINEAR_MEMORY_NAME)
            //.and_then(|export| export.into_memory()) {
                //Some(s) => s,
                //None => return ErrNo::NoMem,
            //};
        //let mut vfs = match VFS_INSTANCE.lock() {
            //Ok(v) => v,
            //Err(_) => return ErrNo::Busy,
        //};
        //let result = match vfs.fd_filestat_get(&fd.into()){
            //Ok(o) => o,
            //Err(e) => return e,
        //};

        //Self::write_buffer(memory, address, &pack_filestat(&result));
        ErrNo::Success as u32
    }

    fn wasi_fd_read(mut caller: Caller, fd: u32, iovec_base: u32, iovec_count:u32, address: u32) -> u32 {
        println!("call wasi_fd_read");
        let mut vfs = lock_vfs!();
        vfs.fd_read(&mut caller, fd, iovec_base, iovec_count, address) as u32
    }

    fn wasi_random_get(mut caller: Caller, address: u32, length: u32) -> u32 {
        println!("call wasi_random_get");
        let mut vfs = lock_vfs!();
        vfs.random_get(&mut caller, address, length) as u32
    }

    fn wasi_fd_seek(mut caller: Caller, fd: u32, offset: i64, whence: u32, address: u32) -> u32 {
        println!("call wasi_fd_seek");
        let mut vfs = lock_vfs!();
        let whence = match u8::try_from(whence) {
            Ok(o) => o,
            Err(_) => return ErrNo::Inval as u32,
        };
        vfs.fd_seek(&mut caller, fd, offset, whence, address) as u32
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
        Self::invoke_entry_point_base(file_name, program.to_vec())
    }
}

