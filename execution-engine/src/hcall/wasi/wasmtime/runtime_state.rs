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
use crate::hcall::{
    common::{
        pack_dirent, pack_fdstat, pack_filestat, pack_prestat, unpack_iovec_array,
        ExecutionEngine, EntrySignature, HostProvisioningError, FatalEngineError, EngineReturnCode,
        WASI_ARGS_GET_NAME, WASI_ARGS_SIZES_GET_NAME, WASI_CLOCK_RES_GET_NAME,
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
        WASI_PATH_SYMLINK_NAME, WASI_PATH_UNLINK_FILE_NAME, WASI_POLL_ONEOFF_NAME,
        WASI_PROC_EXIT_NAME, WASI_PROC_RAISE_NAME, WASI_RANDOM_GET_NAME, WASI_SCHED_YIELD_NAME,
        WASI_SOCK_RECV_NAME, WASI_SOCK_SEND_NAME, WASI_SOCK_SHUTDOWN_NAME,
        WASIWrapper,
    }
};
use lazy_static::lazy_static;
#[cfg(any(feature = "std", feature = "tz", feature = "nitro"))]
use std::sync::{Mutex, Arc};
#[cfg(feature = "sgx")]
use std::sync::{SgxMutex as Mutex, Arc};
use veracruz_utils::policy::principal::Principal;
use crate::hcall::buffer::VFS;
use byteorder::{ByteOrder, LittleEndian};
use wasmtime::{Caller, Extern, ExternType, Func, Instance, Module, Store, Trap, ValType, Memory};
use wasi_types::{
    Advice, ErrNo, Fd, FdFlags, FdStat, FileDelta, FileSize, FileStat, IoVec, LookupFlags, Rights,
    Size, Whence, OpenFlags,
};

////////////////////////////////////////////////////////////////////////////////
// The Wasmtime runtime state.
////////////////////////////////////////////////////////////////////////////////


lazy_static! {
    // The initial value has NO use.
    static ref VFS_INSTANCE: Mutex<WASIWrapper> = Mutex::new(WASIWrapper::new(Arc::new(Mutex::new(VFS::new(&HashMap::new(),&HashMap::new())))));
    // The initial value has NO use.
    static ref CUR_PROGRAM: Mutex<Principal> = Mutex::new(Principal::NoCap);
}

 /// The name of the WASM program's entry point.
const ENTRY_POINT_NAME: &'static str = "_start";
/// The name of the WASM program's linear memory.
const LINEAR_MEMORY_NAME: &'static str = "memory";

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
        vfs : Arc<Mutex<VFS>>,
    ) -> Self {
        // Load the VFS ref to the global environment. This is required by Wasmtime.
        *VFS_INSTANCE.lock().unwrap() = WASIWrapper::new(vfs);
        Self{}
    }


    //TODO REMOVE REMOVE
    /// ExecutionEngine wrapper of append_file implementation in WasmiHostProvisioningState.
    #[inline]
    fn append_file(client_id: &Principal, file_name: &str, data: &[u8]) -> Result<(), HostProvisioningError> {
        VFS_INSTANCE.lock()?.append_file_base(client_id,file_name, data)
    }

    /// ExecutionEngine wrapper of write_file implementation in WasmiHostProvisioningState.
    #[inline]
    fn write_file(client_id: &Principal, file_name: &str, data: &[u8]) -> Result<(), HostProvisioningError> {
        VFS_INSTANCE.lock()?.write_file_base(client_id,file_name, data)
    }

    /// ExecutionEngine wrapper of read_file implementation in WasmiHostProvisioningState.
    #[inline]
    fn read_file(client_id: &Principal, file_name: &str) -> Result<Option<Vec<u8>>, HostProvisioningError> {
        VFS_INSTANCE.lock()?.read_file_base(client_id,file_name)
    }

    #[inline]
    fn count_file(prefix: &str) -> Result<u64, HostProvisioningError> {
        VFS_INSTANCE.lock()?.count_file_base(prefix)
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
                    if import.module() != "wasi_snapshot_preview1" {
                        return Err(Trap::new(format!("Veracruz programs support only the Veracruz host interface.  Unrecognised module import '{}'.", import.name())));
                    }

                    let host_call_body = match import.name() {
                        WASI_PROC_EXIT_NAME => 
                            Func::wrap(&store, |caller: Caller, exit_code: u32| {
                                Self::wasi_proc_exit(caller, exit_code);
                            }),
                        WASI_FD_CLOSE_NAME => 
                            Func::wrap(&store, |caller: Caller, fd: u32| {
                                Self::wasi_fd_close(caller, fd) as i32
                            }),
                        WASI_FD_WRITE_NAME => 
                            Func::wrap(&store, |caller: Caller, fd: u32, iovec_base: u32, iovec_number: u32, address: u32| {
                                Self::wasi_fd_write(caller, fd, iovec_base, iovec_number, address) as i32
                            }),
                        WASI_PATH_OPEN_NAME => 
                            Func::wrap(&store, |caller: Caller, fd: u32, dir_flags: u32, path_address: u32, path_length: u32, oflags : u32, fs_rights_base: u64, fs_rights_inheriting: u64, fd_flags: u32, address: u32| {
                                Self::wasi_path_open(caller, fd, dir_flags, path_address, path_length, oflags, fs_rights_base, fs_rights_inheriting, fd_flags, address) as i32
                            }),
                        WASI_FD_PRESTAT_GET_NAME =>
                            Func::wrap(&store, |caller: Caller, fd: u32, address: u32| {
                                Self::wasi_fd_prestat_get(caller, fd, address) as i32
                            }),
                        WASI_FD_PRESTAT_DIR_NAME_NAME =>
                            Func::wrap(&store, |caller: Caller, fd: u32, address: u32, size:u32| {
                                Self::wasi_fd_prestat_dir_name(caller, fd, address, size) as i32
                            }),
                        WASI_ENVIRON_GET_NAME => 
                            Func::wrap(&store, |caller: Caller, address: u32, buf_address: u32| {
                                Self::wasi_environ_get(caller, address, buf_address) as i32
                            }),
                        WASI_ENVIRON_SIZES_GET_NAME => 
                            Func::wrap(&store, |caller: Caller, address: u32, bufsize_address: u32| {
                                Self::wasi_environ_size_get(caller, address, bufsize_address) as i32
                            }),
                        WASI_FD_FILESTAT_GET_NAME => 
                            Func::wrap(&store, |caller: Caller, fd: u32, address: u32| {
                                Self::wasi_fd_filestat_get(caller, fd, address) as i32
                            }),

                        WASI_FD_READ_NAME => 
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
                        otherwise => return Err(Trap::new(format!("Veracruz programs support only the Veracruz host interface.  Unrecognised host call: '{}'.", otherwise)))
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
                let export = instance.get_export(ENTRY_POINT_NAME).expect("No export with name '{}' in WASM program."); 
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
                            ENTRY_POINT_NAME
                        )))
                    }
                }
            }
        }
    }

    fn read_buffer(memory: Memory, address: u32, length: usize) -> Vec<u8> {
        let mut bytes: Vec<u8> = vec![0; length];
        unsafe {
            bytes.copy_from_slice(std::slice::from_raw_parts(
                memory.data_ptr().add(address as usize),
                length,
            ))
        };
        bytes
    }

    fn write_buffer(memory: Memory, address: u32, buffer: &[u8]) {
        let address = address as usize;
        unsafe {
            std::slice::from_raw_parts_mut(memory.data_ptr().add(address), buffer.len())
                .copy_from_slice(buffer)
        };
    }

    fn read_cstring(memory: Memory, address: u32, length: usize) -> Result<String, ErrNo> {
        let bytes = Self::read_buffer(memory, address, length);

        // TODO: erase the debug code
        let rst = String::from_utf8(bytes).map_err(|_e| ErrNo::IlSeq)?;
        println!("read_cstring: {}",rst);
        Ok(rst)
    }

    fn read_iovec_scattered(memory: Memory, scatters: &[IoVec]) -> Vec<Vec<u8>> {
        println!("called read_iovec_scattered: {:?}",scatters);
        scatters.iter().map(|IoVec{buf, len}|{
            Self::read_buffer(memory.clone(), *buf, *len as usize)
        }).collect()
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

        vfs.fd_close(&fd.into())
    }

    fn wasi_fd_write(caller: Caller, fd: u32, iovec_base: u32, iovec_number: u32, address: u32) -> ErrNo {
        println!("call wasi_fd_write: fd {:?} iovec_base {:?} iovec_nunmber {:?} address {:?}", fd,iovec_base,iovec_number,address);
        let memory = match caller
            .get_export(LINEAR_MEMORY_NAME)
            .and_then(|export| export.into_memory()) {
                Some(s) => s,
                None => return ErrNo::NoMem,
            };
        let mut vfs = match VFS_INSTANCE.lock() {
            Ok(v) => v,
            Err(_) => return ErrNo::Busy,
        };

        let io_bytes = Self::read_buffer(memory.clone(), iovec_base, (iovec_number as usize) * 8);
        let iovec_array = match unpack_iovec_array(&io_bytes){
            Some(o) => o,
            None => return ErrNo::Inval,
        };
        println!("iovec: {:?}",iovec_array);
        let bufs = Self::read_iovec_scattered(memory.clone(), &iovec_array);

        let mut size_written = 0;

        for buf in bufs.iter() {
            println!("write {:?} to fd {:?}", String::from_utf8(buf.clone()).unwrap(), fd);
            size_written += match vfs.fd_write_base(&fd.into(), buf.clone()){
                Ok(o) => o,
                Err(e) => return e,
            };
        }
        Self::write_buffer(memory, address, &u32::to_le_bytes(size_written));
        ErrNo::Success
    }

    fn wasi_path_open(caller: Caller, fd: u32, dir_flags: u32, path_address: u32, path_length: u32, oflags : u32, fs_rights_base: u64, fs_rights_inheriting: u64, fd_flags: u32, address: u32) -> ErrNo {
        println!("call wasi_path_open");
        let memory = match caller
            .get_export(LINEAR_MEMORY_NAME)
            .and_then(|export| export.into_memory()) {
                Some(s) => s,
                None => return ErrNo::NoMem,
            };
        let mut vfs = match VFS_INSTANCE.lock() {
            Ok(v) => v,
            Err(_) => return ErrNo::Busy,
        };
        let path = match Self::read_cstring(memory.clone(), path_address, path_length as usize) {
            Ok(o) => o,
            Err(e) => return e,
        };
        let dir_flags = match LookupFlags::from_bits(dir_flags) {
            Some(o) => o,
            None => return ErrNo::Inval,
        };
        let oflags = match OpenFlags::from_bits(oflags as u16) {
            Some(o) => o,
            None => return ErrNo::Inval,
        };
        let fs_rights_base = match Rights::from_bits(fs_rights_base) {
            Some(o) => o,
            None => return ErrNo::Inval
        };
        let fs_rights_inheriting = match Rights::from_bits(fs_rights_inheriting) {
            Some(o) => o,
            None => return ErrNo::Inval,
        };
        let fd_flags = match FdFlags::from_bits(fd_flags as u16) {
            Some(o) => o,
            None => return ErrNo::Inval,
        };
        println!("path_open {}",path);
        let result = match vfs.path_open(
            &fd.into(),
            dir_flags,
            path,
            oflags,
            fs_rights_base,
            fs_rights_inheriting,
            fd_flags,
        ){
            Ok(o) => o,
            Err(e) => return e,
        };
        Self::write_buffer(memory.clone(), address, &u32::to_le_bytes(result.into()));
        ErrNo::Success
    }

    fn wasi_fd_prestat_get(caller: Caller, fd: u32, address: u32) -> ErrNo {
        println!("call wasi_fd_prestat_get");
        let memory = match caller
            .get_export(LINEAR_MEMORY_NAME)
            .and_then(|export| export.into_memory()) {
                Some(s) => s,
                None => return ErrNo::NoMem,
            };
        let mut vfs = match VFS_INSTANCE.lock() {
            Ok(v) => v,
            Err(_) => return ErrNo::Busy,
        };

        let result = match vfs.fd_prestat_get(&fd.into()) {
            Ok(o) => o,
            // Pipe back the result to the wasm program. 
            // The wasm callee will iterate on file descriptor from Fd(3) 
            // and only stop until hit a BadF. 
            Err(e) => return e,
        };
        Self::write_buffer(memory, address, &pack_prestat(&result));
        ErrNo::Success
    }

    fn wasi_fd_prestat_dir_name(caller: Caller, fd: u32, address: u32, size: u32) -> ErrNo {
        println!("call wasi_fd_prestat_dir_name");
        let memory = match caller
            .get_export(LINEAR_MEMORY_NAME)
            .and_then(|export| export.into_memory()) {
                Some(s) => s,
                None => return ErrNo::NoMem,
            };
        let mut vfs = match VFS_INSTANCE.lock() {
            Ok(v) => v,
            Err(_) => return ErrNo::Busy,
        };

        let result = match vfs.fd_prestat_dir_name(&fd.into()) {
            Ok(o) => o,
            Err(e) => return e,
        };

        if result.len() > size as usize {
            return ErrNo::NameTooLong;
        }

        Self::write_buffer(memory, address, &result.into_bytes());
        ErrNo::Success
    }

    fn wasi_environ_get(caller: Caller, mut environ_address: u32, mut environ_buff_address: u32) -> ErrNo {
        println!("call wasi_environ_get");
        let memory = match caller
            .get_export(LINEAR_MEMORY_NAME)
            .and_then(|export| export.into_memory()) {
                Some(s) => s,
                None => return ErrNo::NoMem,
            };
        let mut vfs = match VFS_INSTANCE.lock() {
            Ok(v) => v,
            Err(_) => return ErrNo::Busy,
        };

        for environ in vfs.environ_get() {
            let length = environ.len() as u32;
            Self::write_buffer(memory.clone(), environ_address, &environ);
            Self::write_buffer(memory.clone(), environ_buff_address, &u32::to_le_bytes(length));

            environ_address += length;
            environ_buff_address += 4;
        }
        ErrNo::Success
    }

    fn wasi_environ_size_get(caller: Caller, environc_address: u32, environ_buff_size_address: u32) -> ErrNo {
        println!("call wasi_environ_size_get");
        let memory = match caller
            .get_export(LINEAR_MEMORY_NAME)
            .and_then(|export| export.into_memory()) {
                Some(s) => s,
                None => return ErrNo::NoMem,
            };
        let mut vfs = match VFS_INSTANCE.lock() {
            Ok(v) => v,
            Err(_) => return ErrNo::Busy,
        };
        let (environc, environ_buff_size) = vfs.environ_sizes_get();

        Self::write_buffer(memory.clone(),environc_address, &u32::to_le_bytes(environc));
        Self::write_buffer(
            memory.clone(),
            environ_buff_size_address,
            &u32::to_le_bytes(environ_buff_size),
        );
        ErrNo::Success
    }

    fn wasi_fd_filestat_get(caller: Caller, fd: u32, address: u32) -> ErrNo {
        let memory = match caller
            .get_export(LINEAR_MEMORY_NAME)
            .and_then(|export| export.into_memory()) {
                Some(s) => s,
                None => return ErrNo::NoMem,
            };
        let mut vfs = match VFS_INSTANCE.lock() {
            Ok(v) => v,
            Err(_) => return ErrNo::Busy,
        };
        let result = match vfs.fd_filestat_get(&fd.into()){
            Ok(o) => o,
            Err(e) => return e,
        };

        Self::write_buffer(memory, address, &pack_filestat(&result));
        ErrNo::Success
    }

    fn wasi_fd_read(caller: Caller, fd: u32, iovec_base: u32, iovec_number:u32, address: u32) -> ErrNo {
        let memory = match caller
            .get_export(LINEAR_MEMORY_NAME)
            .and_then(|export| export.into_memory()) {
                Some(s) => s,
                None => return ErrNo::NoMem,
            };
        let mut vfs = match VFS_INSTANCE.lock() {
            Ok(v) => v,
            Err(_) => return ErrNo::Busy,
        };

        let io_bytes = Self::read_buffer(memory.clone(), iovec_base, (iovec_number as usize) * 8);
        let iovecs = match unpack_iovec_array(&io_bytes){
            Some(o) => o,
            None => return ErrNo::Inval,
        };

        println!("call wasi_fd_read on iovecs {:?}", iovecs);

        let mut size_read = 0;

        for iovec in iovecs.iter() {
            let to_write = match vfs.fd_read_base(&fd.into(), iovec.len as usize){
                Ok(o) => o,
                Err(e) => return e,
            };
            println!("call wasi_fd_read on to_write {:?}", String::from_utf8(to_write.clone()).unwrap());
            Self::write_buffer(memory.clone(),iovec.buf, &to_write);
            size_read += to_write.len() as u32;
        }

        println!("call wasi_fd_read returned size {:?}", size_read);

        Self::write_buffer(memory.clone(),address, &u32::to_le_bytes(size_read));

        ErrNo::Success
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
        let program = Self::read_file(&Principal::InternalSuperUser,file_name)?.ok_or(format!("Program file {} cannot be found.",file_name))?;

        Self::invoke_entry_point_base(file_name, program.to_vec())
            .map_err(|e| {
                FatalEngineError::DirectErrorMessage(format!("WASM program issued trap: {}.", e))
            })
            .and_then(|r| EngineReturnCode::try_from(r))
    }
}

