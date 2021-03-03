//! Wasmtime host-call interface implementation.
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Copyright
//!
//! See the file `LICENSE.markdown` in the Veracruz root directory for licensing
//! and copyright information.

#[cfg(any(feature = "std", feature = "tz", feature = "nitro"))]
use std::sync::{Mutex, Arc};
#[cfg(feature = "sgx")]
use std::sync::{SgxMutex as Mutex, Arc};

use std::{time::Instant, vec::Vec, collections::HashMap};

use byteorder::{ByteOrder, LittleEndian};
use wasmtime::{Caller, Extern, ExternType, Func, Instance, Module, Store, Trap, ValType};

use platform_services::{getrandom, result};

use crate::{
    error::common::VeracruzError,
    hcall::common::{
        ExecutionEngine, EntrySignature, FatalHostError,
        HostProvisioningError, VFSService, HCALL_GETRANDOM_NAME,
        HCALL_INPUT_COUNT_NAME, HCALL_INPUT_SIZE_NAME, HCALL_READ_INPUT_NAME,
        HCALL_WRITE_OUTPUT_NAME,
    },
};
use veracruz_utils::VeracruzCapabilityIndex;
use crate::hcall::buffer::VFS;

////////////////////////////////////////////////////////////////////////////////
// The Wasmtime host provisioning state.
////////////////////////////////////////////////////////////////////////////////

lazy_static! {
    static ref VFS_INSTANCE: Mutex<VFSService> = Mutex::new(VFSService::new(Arc::new(Mutex::new(VFS::new(&HashMap::new(),&HashMap::new())))));
}

/// The name of the WASM program's entry point.
const ENTRY_POINT_NAME: &'static str = "main";
/// The name of the WASM program's linear memory.
const LINEAR_MEMORY_NAME: &'static str = "memory";

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
///
type WasmtimeResult = Result<i32, Trap>;

/// The WASMI host provisioning state: the `HostProvisioningState` with the
/// Module and Memory type-variables specialised to WASMI's `ModuleRef` and
/// `MemoryRef` type.
pub struct WasmtimeHostProvisioningState{ } 

impl WasmtimeHostProvisioningState {

    /// Creates a new initial `HostProvisioningState`.
    pub fn new(
        vfs : Arc<Mutex<VFS>>,
    ) -> Self {
        *VFS_INSTANCE.lock().unwrap() = VFSService::new(vfs);
        Self{}
    }

    /// ExecutionEngine wrapper of append_file implementation in WasmiHostProvisioningState.
    #[inline]
    fn append_file(client_id: &VeracruzCapabilityIndex, file_name: &str, data: &[u8]) -> Result<(), HostProvisioningError> {
        VFS_INSTANCE.lock()?.append_file_base(client_id,file_name, data)
    }

    /// ExecutionEngine wrapper of write_file implementation in WasmiHostProvisioningState.
    #[inline]
    fn write_file(client_id: &VeracruzCapabilityIndex, file_name: &str, data: &[u8]) -> Result<(), HostProvisioningError> {
        VFS_INSTANCE.lock()?.write_file_base(client_id,file_name, data)
    }

    /// ExecutionEngine wrapper of read_file implementation in WasmiHostProvisioningState.
    #[inline]
    fn read_file(client_id: &VeracruzCapabilityIndex, file_name: &str) -> Result<Option<Vec<u8>>, HostProvisioningError> {
        VFS_INSTANCE.lock()?.read_file_base(client_id,file_name)
    }

    #[inline]
    fn count_file(prefix: &str) -> Result<u64, HostProvisioningError> {
        VFS_INSTANCE.lock()?.count_file_base(prefix)
    }

    /// The Wasmtime implementation of `__veracruz_hcall_write_output()`.
    fn write_output(caller: Caller, address: i32, size: i32) -> WasmtimeResult {
        let start = Instant::now();
        let memory = caller
            .get_export(LINEAR_MEMORY_NAME)
            .and_then(|export| export.into_memory())
            .ok_or(Trap::new("write_output failed: no memory registered".to_string()))?;

        let address = address as usize;
        let size = size as usize;
        let mut bytes: Vec<u8> = vec![0; size];

        unsafe {
            bytes.copy_from_slice(std::slice::from_raw_parts(
                memory.data_ptr().add(address),
                size,
            ))
        };

        Self::write_file(&VeracruzCapabilityIndex::InternalSuperUser,"output",&bytes).map_err(|e| Trap::new(format!("write_output failed: {:?}",e)))?;
        println!(
            ">>> rite_output successfully executed in {:?}.",
            start.elapsed()
        );
        Ok(i32::from(VeracruzError::Success))
    }

    /// The Wasmtime implementation of `__veracruz_hcall_input_count()`.
    fn input_count(caller: Caller, address: i32) -> WasmtimeResult {
        let start = Instant::now();
        let memory = caller
            .get_export(LINEAR_MEMORY_NAME)
            .and_then(|export| export.into_memory())
            .ok_or(Trap::new("input_count failed: no memory registered".to_string()))?;

        let address = address as usize;
        let result : u32 = WasmtimeHostProvisioningState::count_file("input").map_err(|e| Trap::new(format!("input_count failed: {:?}",e)))? as u32;

        let mut buffer = [0u8; std::mem::size_of::<u32>()];
        LittleEndian::write_u32(&mut buffer, result);

        unsafe {
            std::slice::from_raw_parts_mut(
                memory.data_ptr().add(address),
                std::mem::size_of::<u32>(),
            )
            .copy_from_slice(&buffer)
        };

        println!(
            ">>> input_count successfully executed in {:?}.",
            start.elapsed()
        );
        Ok(i32::from(VeracruzError::Success))
    }

    /// The Wasmtime implementation of `__veracruz_hcall_input_size()`.
    fn input_size(caller: Caller, index: i32, address: i32) -> WasmtimeResult {
        let start = Instant::now();
        let memory = caller
            .get_export(LINEAR_MEMORY_NAME)
            .and_then(|export| export.into_memory())
            .ok_or(Trap::new("input_size failed: no memory registered".to_string()))?;

        let index = index as usize;
        let address = address as usize;

        let size : u32 = Self::read_file(&VeracruzCapabilityIndex::InternalSuperUser,&format!("input-{}",index)).map_err(|e| Trap::new(format!("input_size failed: {:?}",e)))?.ok_or(Trap::new(format!("File input-{} cannot be found",index)))?.len() as u32;

        let mut buffer = vec![0u8; std::mem::size_of::<u32>()];
        LittleEndian::write_u32(&mut buffer, size);

        unsafe {
            std::slice::from_raw_parts_mut(
                memory.data_ptr().add(address),
                std::mem::size_of::<u32>(),
            )
            .copy_from_slice(&buffer)
        };

        println!(
            ">>> input_size successfully executed in {:?}.",
            start.elapsed()
        );
        Ok(i32::from(VeracruzError::Success))
    }

    /// The Wasmtime implementation of `__veracruz_hcall_read_input()`.
    fn read_input(caller: Caller, index: i32, address: i32, size: i32) -> WasmtimeResult {
        let start = Instant::now();
        let memory = caller
            .get_export(LINEAR_MEMORY_NAME)
            .and_then(|export| export.into_memory())
            .ok_or(Trap::new("read_input failed: no memory registered".to_string()))?;

        let address = address as usize;
        let index = index as usize;
        let size = size as usize;

        let data = Self::read_file(&VeracruzCapabilityIndex::InternalSuperUser,&format!("input-{}",index)).map_err(|e| Trap::new(format!("read_input failed: {:?}",e)))?.ok_or(Trap::new(format!("File input-{} cannot be found",index)))?;

        let return_code = if data.len() > size {
            VeracruzError::DataSourceSize
        } else {
            unsafe {
                std::slice::from_raw_parts_mut(memory.data_ptr().add(address), size)
                    .copy_from_slice(&data)
            };

            println!(
                ">>> read_input successfully executed in {:?}.",
                start.elapsed()
            );

            VeracruzError::Success
        };
        Ok(i32::from(return_code))
    }

    /// The Wasmtime implementation of `__veracruz_hcall_getrandom()`.
    fn get_random(caller: Caller, address: i32, size: i32) -> WasmtimeResult {
        let start = Instant::now();

        let memory = caller
            .get_export(LINEAR_MEMORY_NAME)
            .and_then(|export| export.into_memory())
            .ok_or(Trap::new("getrandom failed: no memory registered".to_string()))?;

        let address = address as usize;
        let size = size as usize;
        let mut buffer: Vec<u8> = vec![0; size];

        let return_code = match getrandom(&mut buffer) {
            result::Result::Success => {
                unsafe {
                    std::slice::from_raw_parts_mut(memory.data_ptr().add(address), size)
                        .copy_from_slice(&buffer)
                };
                println!(
                    ">>> getrandom successfully executed in {:?}.",
                    start.elapsed()
                );

                VeracruzError::Success
            }
            result::Result::Unavailable => VeracruzError::ServiceUnavailable,
            result::Result::UnknownError => VeracruzError::Generic,
        };
        Ok(i32::from(return_code))
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
    pub(crate) fn invoke_entry_point_base(binary : Vec<u8>) -> WasmtimeResult {
        let start = Instant::now();

        let store = Store::default();

        match Module::new(store.engine(), binary) {
            Err(_err) => return Err(Trap::new("Cannot create WASM module from input binary.")),
            Ok(module) => {
                let mut exports: Vec<Extern> = Vec::new();

                for import in module.imports() {
                    if import.module() != "env" {
                        return Err(Trap::new(format!("Veracruz programs support only the Veracruz host interface.  Unrecognised module import '{}'.", import.name())));
                    }

                    let host_call_body = match import.name() {
                        HCALL_GETRANDOM_NAME => {
                            Func::wrap(&store, |caller: Caller, buffer: i32, size: i32| {
                                WasmtimeHostProvisioningState::get_random(caller, buffer, size)
                            })
                        },
                        HCALL_INPUT_COUNT_NAME => {
                            Func::wrap(&store, |caller: Caller, buffer: i32| {
                                WasmtimeHostProvisioningState::input_count(caller, buffer)
                            })
                        }
                        HCALL_INPUT_SIZE_NAME => {
                            Func::wrap(&store, |caller: Caller, index: i32, buffer: i32| {
                                WasmtimeHostProvisioningState::input_size(caller, index, buffer)
                            })
                        },
                        HCALL_READ_INPUT_NAME => {
                            Func::wrap(&store, |caller: Caller, index: i32, buffer: i32, size: i32| {
                                WasmtimeHostProvisioningState::read_input(caller, index, buffer, size)
                            })
                        },
                        HCALL_WRITE_OUTPUT_NAME => {
                            Func::wrap(&store, |caller: Caller, buffer: i32, size: i32| {
                                WasmtimeHostProvisioningState::write_output(caller, buffer, size)
                            })
                        },
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

                match instance.get_export(ENTRY_POINT_NAME) {
                    Some(export) => match check_main(&export.ty()) {
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
                                    .get0::<i32>()
                                    .expect("Internal invariant failed: entry point type-checking bug.");

                            println!(
                                ">>> invoke_main took {:?} to setup pre-main.",
                                start.elapsed()
                            );
                            main()
                        }
                        EntrySignature::NoEntryFound => {
                            return Err(Trap::new(format!(
                                "Entry point '{}' has a missing or incorrect type signature.",
                                ENTRY_POINT_NAME
                            )))
                        }
                    },
                    None => return Err(Trap::new("No export with name '{}' in WASM program.")),
                }
            }
        }
    }
}

/// The `WasmtimeHostProvisioningState` implements everything needed to create a
/// compliant instance of `ExecutionEngine`.
impl ExecutionEngine for WasmtimeHostProvisioningState {

    /// ExecutionEngine wrapper of invoke_entry_point.
    /// Raises a panic if the global wasmtime host is unavailable.
    #[inline]
    fn invoke_entry_point(&mut self, file_name: &str) -> Result<i32, FatalHostError> {

        //TODO check the permission XXX TODO XXX
        let program = Self::read_file(&VeracruzCapabilityIndex::InternalSuperUser,file_name)?.ok_or(format!("Program file {} cannot be found.",file_name))?;

        Self::invoke_entry_point_base(program.to_vec())
            .map_err(|e| {
                FatalHostError::DirectErrorMessage(format!("WASM program issued trap: {}.", e))
            })
            .map(|r| r.clone())
    }
}

