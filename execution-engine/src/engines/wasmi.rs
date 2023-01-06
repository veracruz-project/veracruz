//! An implementation of the ExecutionEngine runtime state for WASMI.
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Copyright
//!
//! See the file `LICENSE_MIT.markdown` in the Veracruz root directory for licensing
//! and copyright information.

use crate::{
    engines::common::{
        Bound, BoundMut, EntrySignature, ExecutionEngine, FatalEngineError,
        HostFunctionIndexOrName, MemoryHandler, VeracruzAPIName, WasiAPIName, WasiWrapper,
    },
    fs::{FileSystem, FileSystemResult},
    Options,
};
use anyhow::{anyhow, Result};
use log::error;
use num::{FromPrimitive, ToPrimitive};
use std::{boxed::Box, convert::TryFrom, mem, str::FromStr, string::ToString, vec::Vec};
use wasi_types::ErrNo;
use wasmi::{
    Error, ExternVal, Externals, FuncInstance, FuncRef, GlobalDescriptor, GlobalRef, HostError,
    MemoryDescriptor, MemoryRef, Module, ModuleImportResolver, ModuleInstance, ModuleRef,
    RuntimeArgs, RuntimeValue, Signature, TableDescriptor, TableRef, Trap, ValueType,
};

#[derive(Debug, PartialEq, Clone, Copy)]
enum APIName {
    WasiAPIName(WasiAPIName),
    VeracruzAPIName(VeracruzAPIName),
}

impl FromPrimitive for APIName {
    fn from_i64(n: i64) -> Option<Self> {
        if n < 0 {
            None
        } else {
            Self::from_u64(n as u64)
        }
    }
    fn from_u64(n: u64) -> Option<Self> {
        if n == 0 {
            None
        } else if n < WasiAPIName::_LAST as u64 {
            Some(APIName::WasiAPIName(WasiAPIName::from_u64(n).unwrap()))
        } else {
            match VeracruzAPIName::from_u64(n - WasiAPIName::_LAST as u64) {
                Some(x) => Some(APIName::VeracruzAPIName(x)),
                None => None,
            }
        }
    }
}

impl ToPrimitive for APIName {
    fn to_i64(&self) -> Option<i64> {
        Some(self.to_u64().unwrap() as i64)
    }
    fn to_u64(&self) -> Option<u64> {
        match self {
            APIName::WasiAPIName(WasiAPIName::_LAST) => unreachable!(),
            APIName::WasiAPIName(x) => x.to_u64(),
            APIName::VeracruzAPIName(x) => Some(WasiAPIName::_LAST as u64 + x.to_u64().unwrap()),
        }
    }
}

////////////////////////////////////////////////////////////////////////////////
// Veracruz host errors.
////////////////////////////////////////////////////////////////////////////////

#[typetag::serde]
impl HostError for FatalEngineError {}

////////////////////////////////////////////////////////////////////////////////
// The WASMI host provisioning state.
////////////////////////////////////////////////////////////////////////////////

/// Impl the MemoryHandler for MemoryRef.
/// This allows passing the MemoryRef to WasiWrapper on any VFS call.
impl MemoryHandler for MemoryRef {
    type Slice = &'static [u8];
    type SliceMut = &'static mut [u8];

    fn get_slice(&self, address: u32, length: u32) -> FileSystemResult<Bound<Self::Slice>> {
        let address = usize::try_from(address).unwrap();
        let length = usize::try_from(length).unwrap();
        // NOTE in more recent version of Wasmi, MemoryRef has a safe version of
        // this function, `direct_access`, that allows access through an `impl AsRef<[u8]>`.
        // For now the best we can do is a bit of unsafe code.
        //
        // Note that MemoryRef is already not threadsafe, so we don't have to worry
        // about locking.
        //
        Ok(Bound::new(self.with_direct_access(|slice| {
            let slice = &slice[address..address + length];
            unsafe { mem::transmute::<&'_ [u8], &'static [u8]>(slice) }
        })))
    }

    fn get_slice_mut(
        &mut self,
        address: u32,
        length: u32,
    ) -> FileSystemResult<BoundMut<Self::SliceMut>> {
        let address = usize::try_from(address).unwrap();
        let length = usize::try_from(length).unwrap();
        // NOTE in more recent version of Wasmi, MemoryRef has a safe version of
        // this function, `direct_access`, that allows access through an `impl AsRef<[u8]>`.
        // For now the best we can do is a bit of unsafe code.
        //
        // Note that MemoryRef is already not threadsafe, so we don't have to worry
        // about locking.
        //
        Ok(BoundMut::new(self.with_direct_access_mut(|slice| {
            let slice = &mut slice[address..address + length];
            unsafe { mem::transmute::<&'_ mut [u8], &'static mut [u8]>(slice) }
        })))
    }

    fn get_size(&self) -> FileSystemResult<u32> {
        let bytes = wasmi::memory_units::Bytes::from(self.current_size()).0;
        Ok(u32::try_from(bytes).unwrap())
    }
}

/// The WASMI host provisioning state: the `HostProvisioningState` with the
/// Module and Memory type-variables specialised to WASMI's `ModuleRef` and
/// `MemoryRef` type.
pub(crate) struct WASMIRuntimeState {
    /// The WasiWrapper of the FileSystem.
    vfs: WasiWrapper,
    /// A reference to the WASM program module that will actually execute on
    /// the input data sources.
    program_module: Option<ModuleRef>,
    /// A reference to the WASM program's linear memory (or "heap").
    memory: Option<MemoryRef>,
}
pub(crate) type WasiResult = Result<ErrNo>;

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

/// A type check struct.
struct TypeCheck {}

impl TypeCheck {
    /// The representation type of the WASI `Advice` type.
    const ADVICE: ValueType = ValueType::I32;
    /// The base pointer representation type of the WASI `CIOVecArray` type, which
    /// is passed as a pair of base address and length.
    const CIOVEC_ARRAY_BASE: ValueType = ValueType::I32;
    /// The length representation type of the WASI `CIOVecArray` type, which is
    /// passed as a pair of base address and length.
    const CIOVEC_ARRAY_LENGTH: ValueType = ValueType::I32;
    /// The representation type of the WASI `ClockID` type.
    const CLOCKID: ValueType = ValueType::I32;
    /// The representation type of the WASI `DirCookie` type.
    const DIRCOOKIE: ValueType = ValueType::I64;
    /// The representation type of the WASI `ErrNo` type.
    const ERRNO: ValueType = ValueType::I32;
    /// The representation type of the WASI `ExitCode` type.
    const EXITCODE: ValueType = ValueType::I32;
    /// The representation type of the WASI `FD` type.
    const FD: ValueType = ValueType::I32;
    /// The representation type of the WASI `FDFlags` type.
    const FDFLAGS: ValueType = ValueType::I32;
    /// The representation type of the WASI `FileDelta` type.
    const FILEDELTA: ValueType = ValueType::I64;
    /// The representation type of the WASI `FileSize` type.
    const FILESIZE: ValueType = ValueType::I64;
    /// The representation type of the WASI `FSTFlags` type.
    const FSTFLAGS: ValueType = ValueType::I32;
    /// The base pointer representation type of the WASI `IOVecArray` type, which
    /// is passed as a pair of base address and length.
    const IOVEC_ARRAY_BASE: ValueType = ValueType::I32;
    /// The length representation type of the WASI `IOVecArray` type, which is
    /// passed as a pair of base address and length.
    const IOVEC_ARRAY_LENGTH: ValueType = ValueType::I32;
    /// The representation type of the WASI `LookupFlags` type.
    const LOOKUP_FLAGS: ValueType = ValueType::I32;
    /// The representation type of the WASI `OFlags` type.
    const OFLAGS: ValueType = ValueType::I32;
    /// The representation type of the WASI `Rights` type.
    const RIGHTS: ValueType = ValueType::I64;
    /// The representation type of the WASI `SDFlags` type.
    const SDFLAGS: ValueType = ValueType::I32;
    /// The representation type of the WASI `SIFlags` type.
    const SIFLAGS: ValueType = ValueType::I32;
    /// The representation type of the WASI `RIFlags` type.
    const RIFLAGS: ValueType = ValueType::I32;
    /// The representation type of the WASI `Signal` type.
    const SIGNAL: ValueType = ValueType::I32;
    /// The representation type of the WASI `Size` type.
    const SIZE: ValueType = ValueType::I32;
    /// The representation type of the WASI `Timestamp` type.
    const TIMESTAMP: ValueType = ValueType::I64;
    /// The representation type of the WASI `Whence` type.
    const WHENCE: ValueType = ValueType::I32;
    /// The representation type of WASM `const` pointers (assuming `wasm32`).
    const CONST_POINTER: ValueType = ValueType::I32;
    /// The representation type of WASM pointers (assuming `wasm32`).
    const POINTER: ValueType = ValueType::I32;
    /// The representation type of WASM buffer length (assuming `wasm32`).
    const SIZE_T: ValueType = ValueType::I32;

    ////////////////////////////////////////////////////////////////////////////////
    // Function well-formedness checks.
    ////////////////////////////////////////////////////////////////////////////////

    /// Checks the function signature, `signature`, has the correct type for the
    /// host call coded by `index`.
    pub(self) fn check_signature(index: APIName, signature: &Signature) -> bool {
        // Match the parameters
        let expected_params = Self::get_params(index);
        if signature.params() != expected_params.as_slice() {
            return false;
        }
        // Match the return type. Apart from proc_exit, which has no return,
        // the rest should return ErrNo.
        if index == APIName::WasiAPIName(WasiAPIName::PROC_EXIT) {
            signature.return_type() == None
        } else {
            signature.return_type() == Some(Self::ERRNO)
        }
    }

    /// Return the parameters list of a wasi function call `index`.
    pub(crate) fn get_params(index: APIName) -> Vec<ValueType> {
        match index {
            APIName::WasiAPIName(index) => match index {
                WasiAPIName::ARGS_GET => vec![Self::POINTER, Self::POINTER],
                WasiAPIName::ARGS_SIZES_GET => vec![Self::POINTER, Self::POINTER],
                WasiAPIName::ENVIRON_GET => vec![Self::POINTER, Self::POINTER],
                WasiAPIName::ENVIRON_SIZES_GET => vec![Self::POINTER, Self::POINTER],
                WasiAPIName::CLOCK_RES_GET => vec![Self::CLOCKID, Self::POINTER],
                WasiAPIName::CLOCK_TIME_GET => vec![Self::CLOCKID, Self::TIMESTAMP, Self::POINTER],
                WasiAPIName::FD_ADVISE => {
                    vec![Self::FD, Self::FILESIZE, Self::FILESIZE, Self::ADVICE]
                }
                WasiAPIName::FD_ALLOCATE => vec![Self::FD, Self::FILESIZE, Self::FILESIZE],
                WasiAPIName::FD_CLOSE => vec![Self::FD],
                WasiAPIName::FD_DATASYNC => vec![Self::FD],
                WasiAPIName::FD_FDSTAT_GET => vec![Self::FD, Self::POINTER],
                WasiAPIName::FD_FDSTAT_SET_FLAGS => vec![Self::FD, Self::FDFLAGS],
                WasiAPIName::FD_FDSTAT_SET_RIGHTS => vec![Self::FD, Self::RIGHTS, Self::RIGHTS],
                WasiAPIName::FD_FILESTAT_GET => vec![Self::FD, Self::POINTER],
                WasiAPIName::FD_FILESTAT_SET_SIZE => vec![Self::FD, Self::FILESIZE],
                WasiAPIName::FD_FILESTAT_SET_TIMES => {
                    vec![Self::FD, Self::TIMESTAMP, Self::TIMESTAMP, Self::FSTFLAGS]
                }
                WasiAPIName::FD_PREAD => vec![
                    Self::FD,
                    Self::CIOVEC_ARRAY_BASE,
                    Self::CIOVEC_ARRAY_LENGTH,
                    Self::FILESIZE,
                    Self::POINTER,
                ],
                WasiAPIName::FD_PRESTAT_GET => vec![Self::FD, Self::POINTER],
                WasiAPIName::FD_PRESTAT_DIR_NAME => vec![Self::FD, Self::POINTER, Self::SIZE],
                WasiAPIName::FD_PWRITE => vec![
                    Self::FD,
                    Self::CIOVEC_ARRAY_BASE,
                    Self::CIOVEC_ARRAY_LENGTH,
                    Self::FILESIZE,
                    Self::POINTER,
                ],
                WasiAPIName::FD_READ => vec![
                    Self::FD,
                    Self::IOVEC_ARRAY_BASE,
                    Self::IOVEC_ARRAY_LENGTH,
                    Self::POINTER,
                ],
                WasiAPIName::FD_READDIR => vec![
                    Self::FD,
                    Self::POINTER,
                    Self::SIZE,
                    Self::DIRCOOKIE,
                    Self::POINTER,
                ],
                WasiAPIName::FD_RENUMBER => vec![Self::FD, Self::FD],
                WasiAPIName::FD_SEEK => {
                    vec![Self::FD, Self::FILEDELTA, Self::WHENCE, Self::POINTER]
                }
                WasiAPIName::FD_SYNC => vec![Self::FD],
                WasiAPIName::FD_TELL => vec![Self::FD, Self::POINTER],
                WasiAPIName::FD_WRITE => vec![
                    Self::FD,
                    Self::CIOVEC_ARRAY_BASE,
                    Self::CIOVEC_ARRAY_LENGTH,
                    Self::POINTER,
                ],
                WasiAPIName::PATH_CREATE_DIRECTORY => vec![Self::FD, Self::POINTER, Self::SIZE_T],
                WasiAPIName::PATH_FILESTAT_GET => vec![
                    Self::FD,
                    Self::LOOKUP_FLAGS,
                    Self::POINTER,
                    Self::SIZE_T,
                    Self::POINTER,
                ],
                WasiAPIName::PATH_FILESTAT_SET_TIMES => vec![
                    Self::FD,
                    Self::LOOKUP_FLAGS,
                    Self::POINTER,
                    Self::SIZE_T,
                    Self::TIMESTAMP,
                    Self::TIMESTAMP,
                    Self::FSTFLAGS,
                ],
                WasiAPIName::PATH_LINK => vec![
                    Self::FD,
                    Self::LOOKUP_FLAGS,
                    Self::POINTER,
                    Self::SIZE_T,
                    Self::FD,
                    Self::POINTER,
                    Self::SIZE_T,
                ],
                WasiAPIName::PATH_OPEN => vec![
                    Self::FD,
                    Self::LOOKUP_FLAGS,
                    Self::POINTER,
                    Self::SIZE_T,
                    Self::OFLAGS,
                    Self::RIGHTS,
                    Self::RIGHTS,
                    Self::FDFLAGS,
                    Self::POINTER,
                ],
                WasiAPIName::PATH_READLINK => vec![
                    Self::FD,
                    Self::POINTER,
                    Self::SIZE_T,
                    Self::POINTER,
                    Self::SIZE_T,
                    Self::POINTER,
                ],
                WasiAPIName::PATH_REMOVE_DIRECTORY => vec![Self::FD, Self::POINTER, Self::SIZE_T],
                WasiAPIName::PATH_RENAME => vec![
                    Self::FD,
                    Self::POINTER,
                    Self::SIZE_T,
                    Self::FD,
                    Self::POINTER,
                    Self::SIZE_T,
                ],
                WasiAPIName::PATH_SYMLINK => vec![
                    Self::POINTER,
                    Self::SIZE_T,
                    Self::FD,
                    Self::POINTER,
                    Self::SIZE_T,
                ],
                WasiAPIName::PATH_UNLINK_FILE => vec![Self::FD, Self::POINTER, Self::SIZE_T],
                WasiAPIName::POLL_ONEOFF => vec![
                    Self::CONST_POINTER,
                    Self::POINTER,
                    Self::SIZE,
                    Self::POINTER,
                ],
                WasiAPIName::PROC_EXIT => vec![Self::EXITCODE],
                WasiAPIName::PROC_RAISE => vec![Self::SIGNAL],
                WasiAPIName::SCHED_YIELD => vec![],
                WasiAPIName::RANDOM_GET => vec![Self::POINTER, Self::SIZE],
                WasiAPIName::SOCK_RECV => vec![
                    Self::FD,
                    Self::IOVEC_ARRAY_BASE,
                    Self::IOVEC_ARRAY_LENGTH,
                    Self::RIFLAGS,
                    Self::POINTER,
                    Self::POINTER,
                ],
                WasiAPIName::SOCK_SEND => vec![
                    Self::FD,
                    Self::CIOVEC_ARRAY_BASE,
                    Self::CIOVEC_ARRAY_LENGTH,
                    Self::SIFLAGS,
                    Self::POINTER,
                ],
                WasiAPIName::SOCK_SHUTDOWN => vec![Self::FD, Self::SDFLAGS],
                WasiAPIName::_LAST => unreachable!(),
            },
            APIName::VeracruzAPIName(index) => match index {
                VeracruzAPIName::FD_CREATE => vec![Self::POINTER],
                VeracruzAPIName::NANOSLEEP => vec![ValueType::I64],
            },
        }
    }

    /// Check if the numbers of parameters in `args` is correct against the wasi function call `index`.
    /// Return FatalEngineError::BadArgumentsToHostFunction{ index }, if not.
    // TODO: Make this also work for VeracruzAPIName.
    pub(crate) fn check_args_number(args: &RuntimeArgs, index: WasiAPIName) -> Result<()> {
        if args.len() == Self::get_params(APIName::WasiAPIName(index)).len() {
            Ok(())
        } else {
            Err(anyhow!(FatalEngineError::BadArgumentsToHostFunction {
                function_name: index,
            }))
        }
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
    } else if params == [ValueType::I32, ValueType::I32] && return_type == None {
        EntrySignature::ArgvAndArgc
    } else {
        EntrySignature::NoEntryFound
    }
}

/// Finds the entry point of the WASM module, `module`, and extracts its
/// signature template.  If no entry is found returns
/// `EntrySignature::NoEntryFound`.
fn check_main(module: &ModuleInstance) -> EntrySignature {
    match module.export_by_name(WasiWrapper::ENTRY_POINT_NAME) {
        Some(ExternVal::Func(funcref)) => check_main_signature(&funcref.signature()),
        _otherwise => EntrySignature::NoEntryFound,
    }
}

/// Finds the linear memory of the WASM module, `module`, and returns it,
/// otherwise creating a fatal host error that will kill the Veracruz instance.
fn get_module_memory(module: &ModuleRef) -> Result<MemoryRef> {
    match module.export_by_name(WasiWrapper::LINEAR_MEMORY_NAME) {
        Some(ExternVal::Memory(memoryref)) => Ok(memoryref),
        _otherwise => Err(anyhow!(FatalEngineError::NoMemoryRegistered)),
    }
}

////////////////////////////////////////////////////////////////////////////////
// The H-call interface.
////////////////////////////////////////////////////////////////////////////////

impl ModuleImportResolver for WASMIRuntimeState {
    /// "Resolves" a H-call by translating from a H-call name, `field_name` to
    /// the corresponding H-call code, and dispatching appropriately.
    fn resolve_func(&self, field_name: &str, signature: &Signature) -> Result<FuncRef, Error> {
        let index = if let Ok(x) = WasiAPIName::from_str(field_name) {
            APIName::WasiAPIName(x)
        } else if let Ok(x) = VeracruzAPIName::from_str(field_name) {
            APIName::VeracruzAPIName(x)
        } else {
            return Err(Error::Instantiation(format!(
                "Unknown function {} with signature: {:?}.",
                field_name, signature
            )));
        };

        if !TypeCheck::check_signature(index, signature) {
            Err(Error::Instantiation(format!(
                "Function {} has an unexpected type-signature: {:?}.",
                field_name, signature
            )))
        } else {
            Ok(FuncInstance::alloc_host(
                signature.clone(),
                index.to_usize().unwrap(),
            ))
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
        let call_index = APIName::from_u64(index as u64).ok_or(
            FatalEngineError::UnknownHostFunction(HostFunctionIndexOrName::Index(index)),
        )?;

        let return_code = match call_index {
            APIName::WasiAPIName(wasi_call_index) => match wasi_call_index {
                WasiAPIName::ARGS_GET => self.wasi_args_get(args),
                WasiAPIName::ARGS_SIZES_GET => self.wasi_args_sizes_get(args),
                WasiAPIName::ENVIRON_GET => self.wasi_environ_get(args),
                WasiAPIName::ENVIRON_SIZES_GET => self.wasi_environ_sizes_get(args),
                WasiAPIName::CLOCK_RES_GET => self.wasi_clock_res_get(args),
                WasiAPIName::CLOCK_TIME_GET => self.wasi_clock_time_get(args),
                WasiAPIName::FD_ADVISE => self.wasi_fd_advise(args),
                WasiAPIName::FD_ALLOCATE => self.wasi_fd_allocate(args),
                WasiAPIName::FD_CLOSE => self.wasi_fd_close(args),
                WasiAPIName::FD_DATASYNC => self.wasi_fd_datasync(args),
                WasiAPIName::FD_FDSTAT_GET => self.wasi_fd_fdstat_get(args),
                WasiAPIName::FD_FDSTAT_SET_FLAGS => self.wasi_fd_fdstat_set_flags(args),
                WasiAPIName::FD_FDSTAT_SET_RIGHTS => self.wasi_fd_fdstat_set_rights(args),
                WasiAPIName::FD_FILESTAT_GET => self.wasi_fd_filestat_get(args),
                WasiAPIName::FD_FILESTAT_SET_SIZE => self.wasi_fd_filestat_set_size(args),
                WasiAPIName::FD_FILESTAT_SET_TIMES => self.wasi_fd_filestat_set_times(args),
                WasiAPIName::FD_PREAD => self.wasi_fd_pread(args),
                WasiAPIName::FD_PRESTAT_GET => self.wasi_fd_prestat_get(args),
                WasiAPIName::FD_PRESTAT_DIR_NAME => self.wasi_fd_prestat_dir_name(args),
                WasiAPIName::FD_PWRITE => self.wasi_fd_pwrite(args),
                WasiAPIName::FD_READ => self.wasi_fd_read(args),
                WasiAPIName::FD_READDIR => self.wasi_fd_readdir(args),
                WasiAPIName::FD_RENUMBER => self.wasi_fd_renumber(args),
                WasiAPIName::FD_SEEK => self.wasi_fd_seek(args),
                WasiAPIName::FD_SYNC => self.wasi_fd_sync(args),
                WasiAPIName::FD_TELL => self.wasi_fd_tell(args),
                WasiAPIName::FD_WRITE => self.wasi_fd_write(args),
                WasiAPIName::PATH_CREATE_DIRECTORY => self.wasi_path_create_directory(args),
                WasiAPIName::PATH_FILESTAT_GET => self.wasi_path_filestat_get(args),
                WasiAPIName::PATH_FILESTAT_SET_TIMES => self.wasi_path_filestat_set_times(args),
                WasiAPIName::PATH_LINK => self.wasi_path_link(args),
                WasiAPIName::PATH_OPEN => self.wasi_path_open(args),
                WasiAPIName::PATH_READLINK => self.wasi_path_readlink(args),
                WasiAPIName::PATH_REMOVE_DIRECTORY => self.wasi_path_remove_directory(args),
                WasiAPIName::PATH_RENAME => self.wasi_path_rename(args),
                WasiAPIName::PATH_SYMLINK => self.wasi_path_symlink(args),
                WasiAPIName::PATH_UNLINK_FILE => self.wasi_path_unlink_file(args),
                WasiAPIName::POLL_ONEOFF => self.wasi_poll_oneoff(args),
                WasiAPIName::PROC_EXIT => self.wasi_proc_exit(args),
                WasiAPIName::PROC_RAISE => self.wasi_proc_raise(args),
                WasiAPIName::SCHED_YIELD => self.wasi_sched_yield(args),
                WasiAPIName::RANDOM_GET => self.wasi_random_get(args),
                WasiAPIName::SOCK_RECV => self.wasi_sock_recv(args),
                WasiAPIName::SOCK_SEND => self.wasi_sock_send(args),
                WasiAPIName::SOCK_SHUTDOWN => self.wasi_sock_shutdown(args),
                WasiAPIName::_LAST => unreachable!(),
            },
            APIName::VeracruzAPIName(veracruz_call_index) => match veracruz_call_index {
                VeracruzAPIName::FD_CREATE => self.veracruz_fd_create(args),
                VeracruzAPIName::NANOSLEEP => self.veracruz_nanosleep(args),
            },
        }
        .map_err(|e| {
            error!("{}", e);
            FatalEngineError::Trap(format!("{}", e))
        })?;
        Ok(Some(RuntimeValue::I32((return_code as i16).into())))
    }
}

/// Functionality of the `WASMIRuntimeState` type that relies on it satisfying
/// the `Externals` and `ModuleImportResolver` constraints.
impl WASMIRuntimeState {
    /// Creates a new initial `WASMIRuntimeState`.
    #[inline]
    pub fn new(filesystem: FileSystem, options: Options) -> FileSystemResult<Self> {
        Ok(Self {
            vfs: WasiWrapper::new(filesystem, options)?,
            program_module: None,
            memory: None,
        })
        //NOTE: cannot find a way to immediately call the load_program here,
        // therefore we might eliminate the Option on program_module and memory.
    }

    #[inline]
    /// Returns the ref to the wasm memory or the ErrNo if fails.
    pub(crate) fn memory(&self) -> Result<MemoryRef> {
        match &self.memory {
            //NOTE: The cost is very minimum as it is a reference to memory.
            Some(m) => Ok(m.clone()),
            None => Err(anyhow!(FatalEngineError::NoMemoryRegistered)),
        }
    }

    ////////////////////////////////////////////////////////////////////////////
    // Provisioning and program execution-related material.
    ////////////////////////////////////////////////////////////////////////////

    /// Loads a compiled program into the host state.  Tries to parse `buffer`
    /// to obtain a WASM `Module` struct.  Returns an appropriate error if this
    /// fails.
    fn load_program(&mut self, buffer: &[u8]) -> Result<()> {
        let module = Module::from_buffer(buffer)?;
        let env_resolver = wasmi::ImportsBuilder::new()
            .with_resolver(WasiWrapper::WASI_SNAPSHOT_MODULE_NAME, self)
            .with_resolver(WasiWrapper::VERACRUZ_SI_MODULE_NAME, self);

        let not_started_module_ref = ModuleInstance::new(&module, &env_resolver)?;
        if not_started_module_ref.has_start() {
            return Err(anyhow!(FatalEngineError::InvalidWASMModule));
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
    fn invoke_export(&mut self, export_name: &str) -> Result<Option<RuntimeValue>, Error> {
        // Eliminate this .cloned() call, if possible
        let (not_started, program_arguments) = match self.program_module.as_ref().cloned() {
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

    fn convert_to_errno(input: FileSystemResult<()>) -> WasiResult {
        let errno = match input {
            Ok(_) => ErrNo::Success,
            Err(e) => e,
        };
        Ok(errno)
    }

    /// The implementation of the WASI `args_get` function.
    fn wasi_args_get(&mut self, args: RuntimeArgs) -> WasiResult {
        TypeCheck::check_args_number(&args, WasiAPIName::ARGS_GET)?;
        let string_ptr_address = args.nth_checked::<u32>(0)?;
        let buf_address = args.nth_checked::<u32>(1)?;
        Self::convert_to_errno(self.vfs.args_get(
            &mut self.memory()?,
            string_ptr_address,
            buf_address,
        ))
    }

    /// The implementation of the WASI `args_sizes_get` function.
    fn wasi_args_sizes_get(&mut self, args: RuntimeArgs) -> WasiResult {
        TypeCheck::check_args_number(&args, WasiAPIName::ARGS_SIZES_GET)?;
        let arg_count_address = args.nth_checked::<u32>(0)?;
        let arg_buf_size_address = args.nth_checked::<u32>(1)?;
        Self::convert_to_errno(self.vfs.args_sizes_get(
            &mut self.memory()?,
            arg_count_address,
            arg_buf_size_address,
        ))
    }

    /// The implementation of the WASI `environ_get` function.
    fn wasi_environ_get(&mut self, args: RuntimeArgs) -> WasiResult {
        TypeCheck::check_args_number(&args, WasiAPIName::ENVIRON_GET)?;
        let string_ptr_address = args.nth(0);
        let buf_address = args.nth(1);
        Self::convert_to_errno(self.vfs.environ_get(
            &mut self.memory()?,
            string_ptr_address,
            buf_address,
        ))
    }

    /// The implementation of the WASI `environ_sizes_get` function.
    fn wasi_environ_sizes_get(&mut self, args: RuntimeArgs) -> WasiResult {
        TypeCheck::check_args_number(&args, WasiAPIName::ENVIRON_SIZES_GET)?;
        let environc_address = args.nth_checked::<u32>(0)?;
        let environ_buf_size_address = args.nth_checked::<u32>(1)?;
        Self::convert_to_errno(self.vfs.environ_sizes_get(
            &mut self.memory()?,
            environc_address,
            environ_buf_size_address,
        ))
    }

    /// The implementation of the WASI `clock_res_get` function.
    fn wasi_clock_res_get(&mut self, args: RuntimeArgs) -> WasiResult {
        TypeCheck::check_args_number(&args, WasiAPIName::CLOCK_RES_GET)?;
        let clock_id = args.nth_checked::<u32>(0)?;
        let address = args.nth_checked::<u32>(1)?;
        Self::convert_to_errno(
            self.vfs
                .clock_res_get(&mut self.memory()?, clock_id, address),
        )
    }

    /// The implementation of the WASI `clock_time_get` function.
    fn wasi_clock_time_get(&mut self, args: RuntimeArgs) -> WasiResult {
        TypeCheck::check_args_number(&args, WasiAPIName::CLOCK_TIME_GET)?;
        let clock_id = args.nth_checked::<u32>(0)?;
        let precision = args.nth_checked::<u64>(1)?;
        let address = args.nth_checked::<u32>(2)?;
        Self::convert_to_errno(self.vfs.clock_time_get(
            &mut self.memory()?,
            clock_id,
            precision,
            address,
        ))
    }

    /// The implementation of the WASI `fd_advise` function.
    fn wasi_fd_advise(&mut self, args: RuntimeArgs) -> WasiResult {
        TypeCheck::check_args_number(&args, WasiAPIName::FD_ADVISE)?;
        let fd = args.nth_checked::<u32>(0)?;
        let offset = args.nth_checked::<u64>(1)?;
        let len = args.nth_checked::<u64>(2)?;
        let advice = args.nth::<u8>(3);
        Self::convert_to_errno(
            self.vfs
                .fd_advise(&mut self.memory()?, fd, offset, len, advice),
        )
    }

    /// The implementation of the WASI `fd_allocate` function.
    fn wasi_fd_allocate(&mut self, args: RuntimeArgs) -> WasiResult {
        TypeCheck::check_args_number(&args, WasiAPIName::FD_ALLOCATE)?;
        let fd = args.nth_checked::<u32>(0)?;
        let offset = args.nth_checked::<u64>(1)?;
        let len = args.nth_checked::<u64>(2)?;
        Self::convert_to_errno(self.vfs.fd_allocate(&mut self.memory()?, fd, offset, len))
    }

    /// The implementation of the WASI `fd_close` function.
    fn wasi_fd_close(&mut self, args: RuntimeArgs) -> WasiResult {
        TypeCheck::check_args_number(&args, WasiAPIName::FD_CLOSE)?;
        let fd = args.nth_checked::<u32>(0)?;
        Self::convert_to_errno(self.vfs.fd_close(&self.memory()?, fd))
    }

    /// The implementation of the WASI `fd_datasync` function.
    fn wasi_fd_datasync(&mut self, args: RuntimeArgs) -> WasiResult {
        TypeCheck::check_args_number(&args, WasiAPIName::FD_DATASYNC)?;
        let fd = args.nth_checked::<u32>(0)?;
        Self::convert_to_errno(self.vfs.fd_datasync(&mut self.memory()?, fd))
    }

    /// The implementation of the WASI `fd_fdstat_get` function.
    fn wasi_fd_fdstat_get(&mut self, args: RuntimeArgs) -> WasiResult {
        TypeCheck::check_args_number(&args, WasiAPIName::FD_FDSTAT_GET)?;
        let fd = args.nth_checked::<u32>(0)?;
        let address = args.nth_checked::<u32>(1)?;
        Self::convert_to_errno(self.vfs.fd_fdstat_get(&mut self.memory()?, fd, address))
    }

    /// The implementation of the WASI `fd_fdstat_set_flags` function.
    fn wasi_fd_fdstat_set_flags(&mut self, args: RuntimeArgs) -> WasiResult {
        TypeCheck::check_args_number(&args, WasiAPIName::FD_FDSTAT_SET_FLAGS)?;
        let fd = args.nth_checked::<u32>(0)?;
        let flags = args.nth_checked::<u16>(1)?;
        Self::convert_to_errno(self.vfs.fd_fdstat_set_flags(&mut self.memory()?, fd, flags))
    }

    /// The implementation of the WASI `fd_fdstat_set_rights` function.
    fn wasi_fd_fdstat_set_rights(&mut self, args: RuntimeArgs) -> WasiResult {
        TypeCheck::check_args_number(&args, WasiAPIName::FD_FDSTAT_SET_RIGHTS)?;
        let fd = args.nth_checked::<u32>(0)?;
        let rights_base = args.nth_checked::<u64>(1)?;
        let rights_inheriting = args.nth_checked::<u64>(2)?;
        Self::convert_to_errno(self.vfs.fd_fdstat_set_rights(
            &mut self.memory()?,
            fd,
            rights_base,
            rights_inheriting,
        ))
    }

    /// The implementation of the WASI `fd_filestat_get` function.
    fn wasi_fd_filestat_get(&mut self, args: RuntimeArgs) -> WasiResult {
        TypeCheck::check_args_number(&args, WasiAPIName::FD_FILESTAT_GET)?;
        let fd = args.nth_checked::<u32>(0)?;
        let address = args.nth_checked::<u32>(1)?;
        Self::convert_to_errno(self.vfs.fd_filestat_get(&mut self.memory()?, fd, address))
    }

    /// The implementation of the WASI `fd_filestat_set_size` function.
    fn wasi_fd_filestat_set_size(&mut self, args: RuntimeArgs) -> WasiResult {
        TypeCheck::check_args_number(&args, WasiAPIName::FD_FILESTAT_SET_SIZE)?;
        let fd = args.nth_checked::<u32>(0)?;
        let size = args.nth_checked::<u64>(1)?;
        Self::convert_to_errno(self.vfs.fd_filestat_set_size(&mut self.memory()?, fd, size))
    }

    /// The implementation of the WASI `fd_filestat_set_times` function.  This
    /// is not supported by Veracruz and we simply return `ErrNo::NoSys`.
    fn wasi_fd_filestat_set_times(&mut self, args: RuntimeArgs) -> WasiResult {
        TypeCheck::check_args_number(&args, WasiAPIName::FD_FILESTAT_SET_TIMES)?;
        let fd = args.nth_checked::<u32>(0)?;
        let atime = args.nth_checked::<u64>(1)?;
        let mtime = args.nth_checked::<u64>(2)?;
        let fst_flag = args.nth_checked::<u16>(3)?;
        Self::convert_to_errno(self.vfs.fd_filestat_set_times(
            &mut self.memory()?,
            fd,
            atime,
            mtime,
            fst_flag,
        ))
    }

    /// The implementation of the WASI `fd_pread` function.
    fn wasi_fd_pread(&mut self, args: RuntimeArgs) -> WasiResult {
        TypeCheck::check_args_number(&args, WasiAPIName::FD_PREAD)?;
        let fd = args.nth_checked::<u32>(0)?;
        let iovec_base = args.nth_checked::<u32>(1)?;
        let iovec_length = args.nth_checked::<u32>(2)?;
        let offset = args.nth_checked::<u64>(3)?;
        let address = args.nth_checked::<u32>(4)?;
        Self::convert_to_errno(self.vfs.fd_pread(
            &mut self.memory()?,
            fd,
            iovec_base,
            iovec_length,
            offset,
            address,
        ))
    }

    /// The implementation of the WASI `fd_prestat_get` function.
    fn wasi_fd_prestat_get(&mut self, args: RuntimeArgs) -> WasiResult {
        TypeCheck::check_args_number(&args, WasiAPIName::FD_PRESTAT_GET)?;
        let fd = args.nth_checked::<u32>(0)?;
        let address = args.nth_checked::<u32>(1)?;
        Self::convert_to_errno(self.vfs.fd_prestat_get(&mut self.memory()?, fd, address))
    }

    /// The implementation of the WASI `fd_prestat_dir_name` function.
    fn wasi_fd_prestat_dir_name(&mut self, args: RuntimeArgs) -> WasiResult {
        TypeCheck::check_args_number(&args, WasiAPIName::FD_PRESTAT_DIR_NAME)?;
        let fd = args.nth_checked::<u32>(0)?;
        let address = args.nth_checked::<u32>(1)?;
        let size = args.nth_checked::<u32>(2)?;
        Self::convert_to_errno(
            self.vfs
                .fd_prestat_dir_name(&mut self.memory()?, fd, address, size),
        )
    }

    /// The implementation of the WASI `fd_pwrite` function.
    fn wasi_fd_pwrite(&mut self, args: RuntimeArgs) -> WasiResult {
        TypeCheck::check_args_number(&args, WasiAPIName::FD_PWRITE)?;
        let fd = args.nth_checked::<u32>(0)?;
        let iovec_base = args.nth_checked::<u32>(1)?;
        let iovec_length = args.nth_checked::<u32>(2)?;
        let offset = args.nth_checked::<u64>(3)?;
        let address = args.nth_checked::<u32>(4)?;
        Self::convert_to_errno(self.vfs.fd_pwrite(
            &mut self.memory()?,
            fd,
            iovec_base,
            iovec_length,
            offset,
            address,
        ))
    }

    /// The implementation of the WASI `fd_read` function.
    fn wasi_fd_read(&mut self, args: RuntimeArgs) -> WasiResult {
        TypeCheck::check_args_number(&args, WasiAPIName::FD_READ)?;
        let fd = args.nth_checked::<u32>(0)?;
        let iovec_base: u32 = args.nth_checked::<u32>(1)?;
        let iovec_len: u32 = args.nth_checked::<u32>(2)?;
        let address: u32 = args.nth_checked::<u32>(3)?;
        Self::convert_to_errno(self.vfs.fd_read(
            &mut self.memory()?,
            fd,
            iovec_base,
            iovec_len,
            address,
        ))
    }

    /// The implementation of the WASI `fd_readdir` function.
    fn wasi_fd_readdir(&mut self, args: RuntimeArgs) -> WasiResult {
        TypeCheck::check_args_number(&args, WasiAPIName::FD_READDIR)?;
        let fd = args.nth_checked::<u32>(0)?;
        let dirent_base = args.nth_checked::<u32>(1)?;
        let dirent_length = args.nth_checked::<u32>(2)?;
        let cookie = args.nth_checked::<u64>(3)?;
        let address = args.nth_checked::<u32>(4)?;
        Self::convert_to_errno(self.vfs.fd_readdir(
            &mut self.memory()?,
            fd,
            dirent_base,
            dirent_length,
            cookie,
            address,
        ))
    }

    /// The implementation of the WASI `fd_renumber` function.
    fn wasi_fd_renumber(&mut self, args: RuntimeArgs) -> WasiResult {
        TypeCheck::check_args_number(&args, WasiAPIName::FD_RENUMBER)?;
        let old_fd = args.nth_checked::<u32>(0)?;
        let new_fd = args.nth_checked::<u32>(1)?;
        Self::convert_to_errno(self.vfs.fd_renumber(&mut self.memory()?, old_fd, new_fd))
    }

    /// The implementation of the WASI `fd_seek` function.
    fn wasi_fd_seek(&mut self, args: RuntimeArgs) -> WasiResult {
        TypeCheck::check_args_number(&args, WasiAPIName::FD_SEEK)?;
        let fd = args.nth_checked::<u32>(0)?;
        let offset = args.nth_checked::<i64>(1)?;
        let whence = args.nth::<u8>(2);
        let address = args.nth_checked::<u32>(3)?;
        Self::convert_to_errno(
            self.vfs
                .fd_seek(&mut self.memory()?, fd, offset, whence, address),
        )
    }

    /// The implementation of the WASI `fd_sync` function.  This is not
    /// supported by Veracruz.  We simply return `ErrNo::NoSys`.
    fn wasi_fd_sync(&mut self, args: RuntimeArgs) -> WasiResult {
        TypeCheck::check_args_number(&args, WasiAPIName::FD_SYNC)?;
        let fd = args.nth_checked::<u32>(0)?;
        Self::convert_to_errno(self.vfs.fd_sync(&mut self.memory()?, fd))
    }

    /// The implementation of the WASI `fd_tell` function.
    fn wasi_fd_tell(&mut self, args: RuntimeArgs) -> WasiResult {
        TypeCheck::check_args_number(&args, WasiAPIName::FD_TELL)?;
        let fd = args.nth_checked::<u32>(0)?;
        let address = args.nth_checked::<u32>(1)?;
        Self::convert_to_errno(self.vfs.fd_tell(&mut self.memory()?, fd, address))
    }

    /// The implementation of the WASI `fd_write` function.
    fn wasi_fd_write(&mut self, args: RuntimeArgs) -> WasiResult {
        TypeCheck::check_args_number(&args, WasiAPIName::FD_WRITE)?;
        let fd = args.nth_checked::<u32>(0)?;
        let iovec_base = args.nth_checked::<u32>(1)?;
        let iovec_len = args.nth_checked::<u32>(2)?;
        let address = args.nth_checked::<u32>(3)?;
        Self::convert_to_errno(self.vfs.fd_write(
            &mut self.memory()?,
            fd,
            iovec_base,
            iovec_len,
            address,
        ))
    }

    /// The implementation of the WASI `path_create_directory` function.
    fn wasi_path_create_directory(&mut self, args: RuntimeArgs) -> WasiResult {
        TypeCheck::check_args_number(&args, WasiAPIName::PATH_CREATE_DIRECTORY)?;
        let fd = args.nth_checked::<u32>(0)?;
        let path = args.nth_checked::<u32>(1)?;
        let path_len = args.nth_checked::<u32>(2)?;
        Self::convert_to_errno(self.vfs.path_create_directory(
            &mut self.memory()?,
            fd,
            path,
            path_len,
        ))
    }

    /// The implementation of the WASI `path_filestat_get` function.
    fn wasi_path_filestat_get(&mut self, args: RuntimeArgs) -> WasiResult {
        TypeCheck::check_args_number(&args, WasiAPIName::PATH_FILESTAT_GET)?;
        let fd = args.nth_checked::<u32>(0)?;
        let flag = args.nth_checked::<u32>(1)?;
        let path_address = args.nth_checked::<u32>(2)?;
        let path_length = args.nth_checked::<u32>(3)?;
        let address = args.nth_checked::<u32>(4)?;
        Self::convert_to_errno(self.vfs.path_filestat_get(
            &mut self.memory()?,
            fd,
            flag,
            path_address,
            path_length,
            address,
        ))
    }

    /// The implementation of the WASI `path_filestat_set_times` function.  This
    /// is not supported by Veracruz.  We simply return `ErrNo::NoSys`.
    fn wasi_path_filestat_set_times(&mut self, args: RuntimeArgs) -> WasiResult {
        TypeCheck::check_args_number(&args, WasiAPIName::PATH_FILESTAT_SET_TIMES)?;
        let fd = args.nth_checked::<u32>(0)?;
        let flag = args.nth_checked::<u32>(1)?;
        let path_address = args.nth_checked::<u32>(2)?;
        let path_length = args.nth_checked::<u32>(3)?;
        let atime = args.nth_checked::<u64>(4)?;
        let mtime = args.nth_checked::<u64>(5)?;
        let fst_flags = args.nth_checked::<u16>(6)?;
        Self::convert_to_errno(self.vfs.path_filestat_set_times(
            &mut self.memory()?,
            fd,
            flag,
            path_address,
            path_length,
            atime,
            mtime,
            fst_flags,
        ))
    }

    /// The implementation of the WASI `path_readlink` function.  This
    /// is not supported by Veracruz.  We simply return `ErrNo::NoSys`.
    fn wasi_path_link(&mut self, args: RuntimeArgs) -> WasiResult {
        TypeCheck::check_args_number(&args, WasiAPIName::PATH_LINK)?;
        let old_fd = args.nth_checked::<u32>(0)?;
        let old_flags = args.nth_checked::<u32>(1)?;
        let old_address = args.nth_checked::<u32>(2)?;
        let old_path_len = args.nth_checked::<u32>(3)?;
        let new_fd = args.nth_checked::<u32>(4)?;
        let new_address = args.nth_checked::<u32>(5)?;
        let new_path_len = args.nth_checked::<u32>(6)?;
        Self::convert_to_errno(self.vfs.path_link(
            &mut self.memory()?,
            old_fd,
            old_flags,
            old_address,
            old_path_len,
            new_fd,
            new_address,
            new_path_len,
        ))
    }

    /// The implementation of the WASI `path_open` function.
    fn wasi_path_open(&mut self, args: RuntimeArgs) -> WasiResult {
        TypeCheck::check_args_number(&args, WasiAPIName::PATH_OPEN)?;
        let fd = args.nth_checked::<u32>(0)?;
        let dirflags = args.nth_checked::<u32>(1)?;
        let path_address = args.nth_checked::<u32>(2)?;
        let path_length = args.nth_checked::<u32>(3)?;
        let oflags = args.nth_checked::<u16>(4)?;
        let fs_rights_base = args.nth_checked::<u64>(5)?;
        let fs_rights_inheriting = args.nth_checked::<u64>(6)?;
        let fd_flags = args.nth_checked::<u16>(7)?;
        let address = args.nth_checked::<u32>(8)?;
        Self::convert_to_errno(self.vfs.path_open(
            &mut self.memory()?,
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

    /// The implementation of the WASI `path_readlink` function.
    fn wasi_path_readlink(&mut self, args: RuntimeArgs) -> WasiResult {
        TypeCheck::check_args_number(&args, WasiAPIName::PATH_READLINK)?;
        let fd = args.nth_checked::<u32>(0)?;
        let path_address = args.nth_checked::<u32>(1)?;
        let path_length = args.nth_checked::<u32>(2)?;
        let buf_address = args.nth_checked::<u32>(3)?;
        let buf_length = args.nth_checked::<u32>(4)?;
        let address = args.nth_checked::<u32>(5)?;
        Self::convert_to_errno(self.vfs.path_readlink(
            &mut self.memory()?,
            fd,
            path_address,
            path_length,
            buf_address,
            buf_length,
            address,
        ))
    }

    /// The implementation of the WASI `path_remove_directory` function.
    fn wasi_path_remove_directory(&mut self, args: RuntimeArgs) -> WasiResult {
        TypeCheck::check_args_number(&args, WasiAPIName::PATH_REMOVE_DIRECTORY)?;
        let fd = args.nth_checked::<u32>(0)?;
        let path_address = args.nth_checked::<u32>(1)?;
        let path_length = args.nth_checked::<u32>(2)?;
        Self::convert_to_errno(self.vfs.path_remove_directory(
            &mut self.memory()?,
            fd,
            path_address,
            path_length,
        ))
    }

    /// The implementation of the WASI `path_rename` function.
    fn wasi_path_rename(&mut self, args: RuntimeArgs) -> WasiResult {
        TypeCheck::check_args_number(&args, WasiAPIName::PATH_RENAME)?;
        let old_fd = args.nth_checked::<u32>(0)?;
        let old_path_address = args.nth_checked::<u32>(1)?;
        let old_path_len = args.nth_checked::<u32>(2)?;
        let new_fd = args.nth_checked::<u32>(3)?;
        let new_path_address = args.nth_checked::<u32>(4)?;
        let new_path_len = args.nth_checked::<u32>(5)?;
        Self::convert_to_errno(self.vfs.path_rename(
            &mut self.memory()?,
            old_fd,
            old_path_address,
            old_path_len,
            new_fd,
            new_path_address,
            new_path_len,
        ))
    }

    /// The implementation of the WASI `path_symlink` function.
    fn wasi_path_symlink(&mut self, args: RuntimeArgs) -> WasiResult {
        TypeCheck::check_args_number(&args, WasiAPIName::PATH_SYMLINK)?;
        let old_path_address = args.nth_checked::<u32>(0)?;
        let old_path_len = args.nth_checked::<u32>(1)?;
        let fd = args.nth_checked::<u32>(2)?;
        let new_path_address = args.nth_checked::<u32>(3)?;
        let new_path_len = args.nth_checked::<u32>(4)?;
        Self::convert_to_errno(self.vfs.path_symlink(
            &mut self.memory()?,
            old_path_address,
            old_path_len,
            fd,
            new_path_address,
            new_path_len,
        ))
    }

    /// The implementation of the WASI `path_unlink_file` function.  This is not
    /// supported by Veracruz.  We simply return `ErrNo::NoSys`.
    fn wasi_path_unlink_file(&mut self, args: RuntimeArgs) -> WasiResult {
        TypeCheck::check_args_number(&args, WasiAPIName::PATH_UNLINK_FILE)?;
        let fd = args.nth_checked::<u32>(0)?;
        let path_address = args.nth_checked::<u32>(1)?;
        let path_len = args.nth_checked::<u32>(2)?;
        Self::convert_to_errno(self.vfs.path_unlink_file(
            &mut self.memory()?,
            fd,
            path_address,
            path_len,
        ))
    }

    /// The implementation of the WASI `poll_oneoff` function.  This is not
    /// supported by Veracruz.  We write `0` as the number of subscriptions that
    /// were registered and return `ErrNo::NoSys`.
    fn wasi_poll_oneoff(&mut self, args: RuntimeArgs) -> WasiResult {
        TypeCheck::check_args_number(&args, WasiAPIName::POLL_ONEOFF)?;
        let subscriptions = args.nth_checked::<u32>(0)?;
        let events = args.nth_checked::<u32>(1)?;
        let size = args.nth_checked::<u32>(2)?;
        let address = args.nth_checked::<u32>(3)?;
        Self::convert_to_errno(self.vfs.poll_oneoff(
            &mut self.memory()?,
            subscriptions,
            events,
            size,
            address,
        ))
    }

    /// The implementation of the WASI `proc_raise` function.  This halts
    /// termination of the interpreter, returning an error code.  No return code
    /// is returned to the calling WASM process.
    fn wasi_proc_exit(&mut self, args: RuntimeArgs) -> WasiResult {
        TypeCheck::check_args_number(&args, WasiAPIName::PROC_EXIT)?;
        let exit_code = args.nth_checked::<u32>(0)?;
        self.vfs.proc_exit(&mut self.memory()?, exit_code);
        // NB: this gets routed to the runtime, not the calling WASM program,
        // for handling.
        Ok(ErrNo::Success)
    }

    /// The implementation of the WASI `proc_raise` function.  This is not
    /// supported by Veracruz and implemented as a no-op, simply returning
    /// `ErrNo::NoSys`.
    fn wasi_proc_raise(&mut self, args: RuntimeArgs) -> WasiResult {
        TypeCheck::check_args_number(&args, WasiAPIName::PROC_RAISE)?;
        let signal = args.nth::<u8>(0);
        Self::convert_to_errno(self.vfs.proc_raise(&mut self.memory()?, signal))
    }

    /// The implementation of the WASI `sched_yield` function.  This is
    /// not supported by Veracruz and simply returns `ErrNo::NoSys`.
    fn wasi_sched_yield(&mut self, args: RuntimeArgs) -> WasiResult {
        TypeCheck::check_args_number(&args, WasiAPIName::SCHED_YIELD)?;
        Self::convert_to_errno(self.vfs.sched_yield(&mut self.memory()?))
    }

    /// The implementation of the WASI `random_get` function, which calls
    /// through to the random number generator provided by `platform_services`.
    /// Returns `ErrNo::Success` on successful execution of the random number
    /// generator, or `ErrNo::NoSys` if a random number generator is not
    /// available on this platform, or if the call to the random number
    /// generator fails for some reason.
    fn wasi_random_get(&mut self, args: RuntimeArgs) -> WasiResult {
        TypeCheck::check_args_number(&args, WasiAPIName::RANDOM_GET)?;
        let address = args.nth_checked::<u32>(0)?;
        let size = args.nth_checked::<u32>(1)?;
        Self::convert_to_errno(self.vfs.random_get(&mut self.memory()?, address, size))
    }

    /// The implementation of the WASI `sock_send` function.  This is not
    /// supported by Veracruz and returns `ErrNo::NoSys`, writing back
    /// `0` as the length of the transmission.
    fn wasi_sock_send(&mut self, args: RuntimeArgs) -> WasiResult {
        TypeCheck::check_args_number(&args, WasiAPIName::SOCK_SEND)?;
        let socket = args.nth_checked::<u32>(0)?;
        let buf_address = args.nth_checked::<u32>(1)?;
        let buf_len = args.nth_checked::<u32>(2)?;
        let si_flag = args.nth_checked::<u16>(3)?;
        let ro_data_len = args.nth_checked::<u32>(4)?;
        Self::convert_to_errno(self.vfs.sock_send(
            &mut self.memory()?,
            socket,
            buf_address,
            buf_len,
            si_flag,
            ro_data_len,
        ))
    }

    /// The implementation of the WASI `sock_recv` function.  This is not
    /// supported by Veracruz and returns `ErrNo::NoSys`, writing back
    /// `0` as the length of the transmission.
    fn wasi_sock_recv(&mut self, args: RuntimeArgs) -> WasiResult {
        TypeCheck::check_args_number(&args, WasiAPIName::SOCK_RECV)?;
        let socket = args.nth_checked::<u32>(0)?;
        let buf_address = args.nth_checked::<u32>(1)?;
        let buf_len = args.nth_checked::<u32>(2)?;
        let ri_flag = args.nth_checked::<u16>(3)?;
        let ro_data_len = args.nth_checked::<u32>(4)?;
        let ro_flag = args.nth_checked::<u32>(5)?;
        Self::convert_to_errno(self.vfs.sock_recv(
            &mut self.memory()?,
            socket,
            buf_address,
            buf_len,
            ri_flag,
            ro_data_len,
            ro_flag,
        ))
    }

    /// The implementation of the WASI `sock_shutdown` function.  This is
    /// not supported by Veracruz and simply returns `ErrNo::NoSys`.
    fn wasi_sock_shutdown(&mut self, args: RuntimeArgs) -> WasiResult {
        TypeCheck::check_args_number(&args, WasiAPIName::SOCK_SHUTDOWN)?;
        let socket = args.nth_checked::<u32>(0)?;
        let sd_flag = args.nth::<u8>(1);
        Self::convert_to_errno(self.vfs.sock_shutdown(&mut self.memory()?, socket, sd_flag))
    }

    fn veracruz_fd_create(&mut self, args: RuntimeArgs) -> WasiResult {
        let address = args.nth_checked::<u32>(0)?;
        Self::convert_to_errno(self.vfs.fd_create(&mut self.memory()?, address))
    }

    fn veracruz_nanosleep(&mut self, args: RuntimeArgs) -> WasiResult {
        let x = args.nth_checked::<u64>(0)?;
        println!("xx wasmi nanosleep({}) begin", x);
        std::thread::sleep(std::time::Duration::from_nanos(x));
        println!("xx wasmi nanosleep({}) end", x);
        Ok(ErrNo::Success)
    }

}

////////////////////////////////////////////////////////////////////////////////
// The ExecutionEngine trait implementation.
////////////////////////////////////////////////////////////////////////////////

/// The `WASMIRuntimeState` implements everything needed to create a
/// compliant instance of `ExecutionEngine`.
impl ExecutionEngine for WASMIRuntimeState {
    /// Executes the program, `program`, within the context of the execution
    /// engine options, `options`.
    ///
    /// Returns `Ok(code)` if the pipeline successfully executed and returned a
    /// defined error code, `code`.  Alternatively, returns `Err(fatal)` to
    /// signal that a fatal runtime error, `fatal`, occurred during the
    /// execution of the pipeline.
    fn invoke_entry_point(&mut self, program: Vec<u8>) -> Result<u32> {
        self.load_program(&program)?;

        let execute_result = self.invoke_export(WasiWrapper::ENTRY_POINT_NAME);
        let exit_code = self.vfs.exit_code();

        // Get the return code, ZERO as the default, or the exit_code if exists.
        match execute_result {
            // If the function does not explicitly provide return code,
            // either read the exit_code passed by proc_exit call or use ZERO as the default.
            Ok(None) => Ok(exit_code.unwrap_or(0)),
            // Return the explicit return code
            Ok(Some(RuntimeValue::I32(c))) => Ok(c as u32),
            // NOTE: Surpress the trap, if the `proc_exit` is called.
            //       In this case, the error code is exit_code.
            Ok(Some(_)) => Err(anyhow!(FatalEngineError::ReturnedCodeError)),
            // NOTE: Surpress the trap, if the `proc_exit` is called.
            //       In this case, the error code is exit_code.
            Err(Error::Trap(trap)) => exit_code.ok_or(anyhow!(trap)),
            Err(err) => Err(anyhow!(err)),
        }
    }
}
