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
        pack_dirent, pack_fdstat, pack_filestat, pack_prestat,
        ExecutionEngine, EntrySignature, HostProvisioningError, FatalEngineError, EngineReturnCode,
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
    static ref VFS_INSTANCE: Mutex<WASIWrapper> = Mutex::new(WASIWrapper::new(Arc::new(Mutex::new(FileSystem::new()))));
    // The initial value has NO use.
    static ref CUR_PROGRAM: Mutex<Principal> = Mutex::new(Principal::NoCap);
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
type WasmtimeResult = Result<i32, Trap>;

/// The facade of WASMTIME host provisioning state.
pub struct WasmtimeRuntimeState{ }

////////////////////////////////////////////////////////////////////////////////
// Operations on the WasmtimeRuntimeState.
////////////////////////////////////////////////////////////////////////////////

impl WasmtimeRuntimeState {
    /// Creates a new initial `HostProvisioningState`.
    pub fn new(
        filesystem : Arc<Mutex<FileSystem>>,
    ) -> Self {
        // Load the VFS ref to the global environment. This is required by Wasmtime.
        *VFS_INSTANCE.lock().unwrap() = WASIWrapper::new(filesystem);
        Self{}
    }


    //TODO REMOVE REMOVE
    /// ExecutionEngine wrapper of append_file implementation in WasmiHostProvisioningState.
    #[inline]
    fn append_file(client_id: &Principal, file_name: &str, data: &[u8]) -> Result<(), HostProvisioningError> {
        Ok(())
        //VFS_INSTANCE.lock()?.append_file_base(client_id,file_name, data)
    }

    /// ExecutionEngine wrapper of write_file implementation in WasmiHostProvisioningState.
    #[inline]
    fn write_file(client_id: &Principal, file_name: &str, data: &[u8]) -> Result<(), HostProvisioningError> {
        Ok(())
        //VFS_INSTANCE.lock()?.write_file_base(client_id,file_name, data)
    }

    /// ExecutionEngine wrapper of read_file implementation in WasmiHostProvisioningState.
    #[inline]
    fn read_file(client_id: &Principal, file_name: &str) -> Result<Option<Vec<u8>>, HostProvisioningError> {
        Ok(None)
        //VFS_INSTANCE.lock()?.read_file_base(client_id,file_name)
    }

    #[inline]
    fn count_file(prefix: &str) -> Result<u64, HostProvisioningError> {
        Ok(0)
        //VFS_INSTANCE.lock()?.count_file_base(prefix)
    }
    //TODO REMOVE REMOVE


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
    pub(crate) fn invoke_entry_point_base(program_name : &str, binary : Vec<u8>) -> WasmtimeResult {
        let start = Instant::now();

        let store = Store::default();

        *CUR_PROGRAM.lock().map_err(|e|Trap::new(format!("Failed to load program {}, error: {:?} ", program_name, e)))? = Principal::Program(program_name.to_string());

        match Module::new(store.engine(), binary) {
            Err(_err) => return Err(Trap::new("Cannot create WASM module from input binary.")),
            Ok(module) => {
                let mut exports: Vec<Extern> = Vec::new();

                for import in module.imports() {
                    if import.module() != WASIWrapper::WASI_SNAPSHOT_MODULE_NAME {
                        return Err(Trap::new(format!("Veracruz programs support only the Veracruz host interface.  Unrecognised module import '{}'.", import.name())));
                    }

                    let host_call_body = match WASIAPIName::try_from(import.name())
                        .map_err(|_|{ Trap::new(format!("Veracruz programs support only the Veracruz host interface.  Unrecognised host call: '{}'.", import.name()))
                    })? {
                        WASIAPIName::PROC_EXIT => 
                            Func::wrap(&store, |caller: Caller, exit_code: u32| {
                                Self::wasi_proc_exit(caller, exit_code);
                            }),
                        WASIAPIName::FD_CLOSE => 
                            Func::wrap(&store, |caller: Caller, fd: u32| {
                                Self::wasi_fd_close(caller, fd) as i32
                            }),
                        WASIAPIName::FD_WRITE => 
                            Func::wrap(&store, |caller: Caller, fd: u32, iovec_base: u32, iovec_number: u32, address: u32| {
                                Self::wasi_fd_write(caller, fd, iovec_base, iovec_number, address) as i32
                            }),
                        WASIAPIName::PATH_OPEN => 
                            Func::wrap(&store, |caller: Caller, fd: u32, dir_flags: u32, path_address: u32, path_length: u32, oflags : u32, fs_rights_base: u64, fs_rights_inheriting: u64, fd_flags: u32, address: u32| {
                                Self::wasi_path_open(caller, fd, dir_flags, path_address, path_length, oflags, fs_rights_base, fs_rights_inheriting, fd_flags, address) as i32
                            }),
                        WASIAPIName::FD_PRESTAT_GET =>
                            Func::wrap(&store, |caller: Caller, fd: u32, address: u32| {
                                Self::wasi_fd_prestat_get(caller, fd, address) as i32
                            }),
                        WASIAPIName::FD_PRESTAT_DIR_NAME =>
                            Func::wrap(&store, |caller: Caller, fd: u32, address: u32, size:u32| {
                                Self::wasi_fd_prestat_dir_name(caller, fd, address, size) as i32
                            }),
                        WASIAPIName::ENVIRON_GET => 
                            Func::wrap(&store, |caller: Caller, address: u32, buf_address: u32| {
                                Self::wasi_environ_get(caller, address, buf_address) as i32
                            }),
                        WASIAPIName::ENVIRON_SIZES_GET => 
                            Func::wrap(&store, |caller: Caller, address: u32, bufsize_address: u32| {
                                Self::wasi_environ_size_get(caller, address, bufsize_address) as i32
                            }),
                        WASIAPIName::FD_FILESTAT_GET => 
                            Func::wrap(&store, |caller: Caller, fd: u32, address: u32| {
                                Self::wasi_fd_filestat_get(caller, fd, address) as i32
                            }),
                        WASIAPIName::FD_READ => 
                            Func::wrap(&store, |caller: Caller, fd: u32, iovec_base: u32, iovec_len: u32, address: u32| {
                                Self::wasi_fd_read(caller, fd, iovec_base, iovec_len, address) as i32
                            }),
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
                        otherwise => return Err(Trap::new(format!("Veracruz programs support only the Veracruz host interface")))
                    };

                    exports.push(Extern::Func(host_call_body))
                }

                let instance = Instance::new(&store, &module, &exports).map_err(|err| {
                    Trap::new(format!(
                        "Failed to create WASM module.  Error '{}' returned.",
                        err
                    ))
                })?;

                //let export = instance.get_export(ENTRY_POINT_NAME).ok_or(Trap::new("No export with name '{}' in WASM program."))?; 
                let export = instance.get_export(WASIWrapper::ENTRY_POINT_NAME).expect("No export with name '{}' in WASM program."); 
                match check_main(&export.ty()) {
                    EntrySignature::ArgvAndArgc => {
                        let main =
                            export
                                .into_func()
                                .expect("Internal invariant failed: entry point not convertible to callable function.")
                                .get2::<i32, i32, i32>()
                                .expect("Internal invariant failed: entry point type-checking bug.");

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
                                .expect("Internal invariant failed: entry point not convertible to callable function.")
                                .get0::<()>()
                                .expect("Internal invariant failed: entry point type-checking bug.");

                        println!(
                            ">>> invoke_main took {:?} to setup pre-main.",
                            start.elapsed()
                        );
                        main();
                        // TODO fill in correctly return info
                        Ok(0)

                    }
                    EntrySignature::NoEntryFound => {
                        return Err(Trap::new(format!(
                            "Entry point '{}' has a missing or incorrect type signature.",
                            WASIWrapper::ENTRY_POINT_NAME
                        )))
                    }
                }
            }
        }
    }

    // TODO the return type??
    fn wasi_proc_exit(_caller: Caller, _exit_code: u32) -> WasmtimeResult {
        Ok(i32::from(EngineReturnCode::Success))
    }

    fn wasi_fd_close(_caller: Caller, fd: u32) -> ErrNo {
        println!("call wasi_fd_close");
        let mut vfs = match VFS_INSTANCE.lock() {
            Ok(v) => v,
            Err(_) => return ErrNo::Busy,
        };

        vfs.fd_close(fd)
    }

    fn wasi_fd_write(mut caller: Caller, fd: u32, iovec_base: u32, iovec_number: u32, address: u32) -> ErrNo {
        println!("call wasi_fd_write: fd {:?} iovec_base {:?} iovec_nunmber {:?} address {:?}", fd,iovec_base,iovec_number,address);
        let mut vfs = match VFS_INSTANCE.lock() {
            Ok(v) => v,
            Err(_) => return ErrNo::Busy,
        };

        vfs.fd_write(&mut caller, fd, iovec_base, iovec_number, address)
    }

    fn wasi_path_open(mut caller: Caller, fd: u32, dir_flags: u32, path_address: u32, path_length: u32, oflags : u32, fs_rights_base: u64, fs_rights_inheriting: u64, fd_flags: u32, address: u32) -> ErrNo {
        println!("call wasi_path_open");
        let mut vfs = match VFS_INSTANCE.lock() {
            Ok(v) => v,
            Err(_) => return ErrNo::Busy,
        };
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
        )
    }

    fn wasi_fd_prestat_get(mut caller: Caller, fd: u32, address: u32) -> ErrNo {
        println!("call wasi_fd_prestat_get");
        let mut vfs = match VFS_INSTANCE.lock() {
            Ok(v) => v,
            Err(_) => return ErrNo::Busy,
        };
        vfs.fd_prestat_get(&mut caller, fd, address)
    }

    fn wasi_fd_prestat_dir_name(mut caller: Caller, fd: u32, address: u32, size: u32) -> ErrNo {
        println!("call wasi_fd_prestat_dir_name");
        let mut vfs = match VFS_INSTANCE.lock() {
            Ok(v) => v,
            Err(_) => return ErrNo::Busy,
        };

        vfs.fd_prestat_dir_name(&mut caller, fd,address,size) 
    }

    fn wasi_environ_get(mut caller: Caller, environ_address: u32, environ_buf_address: u32) -> ErrNo {
        println!("call wasi_environ_get");
        let mut vfs = match VFS_INSTANCE.lock() {
            Ok(v) => v,
            Err(_) => return ErrNo::Busy,
        };
        vfs.environ_get(&mut caller, environ_address, environ_buf_address)
    }

    fn wasi_environ_size_get(mut caller: Caller, environc_address: u32, environ_buf_size_address: u32) -> ErrNo {
        println!("call wasi_environ_size_get");
        let mut vfs = match VFS_INSTANCE.lock() {
            Ok(v) => v,
            Err(_) => return ErrNo::Busy,
        };
        vfs.environ_sizes_get(&mut caller, environc_address, environ_buf_size_address)
    }

    fn wasi_fd_filestat_get(caller: Caller, fd: u32, address: u32) -> ErrNo {
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
        ErrNo::Success
    }

    fn wasi_fd_read(mut caller: Caller, fd: u32, iovec_base: u32, iovec_count:u32, address: u32) -> ErrNo {
        println!("call wasi_fd_read");
        let mut vfs = match VFS_INSTANCE.lock() {
            Ok(v) => v,
            Err(_) => return ErrNo::Busy,
        };

        vfs.fd_read(&mut caller, fd, iovec_base, iovec_count, address)
    }
}

/// The `WasmtimeHostProvisioningState` implements everything needed to create a
/// compliant instance of `ExecutionEngine`.
impl ExecutionEngine for WasmtimeRuntimeState {

    /// ExecutionEngine wrapper of invoke_entry_point.
    /// Raises a panic if the global wasmtime host is unavailable.
    #[inline]
    fn invoke_entry_point(&mut self, file_name: &str) -> Result<EngineReturnCode, FatalEngineError> {

        //TODO check the permission XXX TODO XXX
        let program = VFS_INSTANCE.lock()?.read_file_by_filename(file_name)?;

        Self::invoke_entry_point_base(file_name, program.to_vec())
            .map_err(|e| {
                FatalEngineError::DirectErrorMessage(format!("WASM program issued trap: {}.", e))
            })
            .and_then(|r| EngineReturnCode::try_from(r))
    }
}

