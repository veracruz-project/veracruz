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
use crate::hcall::common::{ExecutionEngine, FatalEngineError, HostProvisioningError, EngineReturnCode, VFSService, EntrySignature};
use lazy_static::lazy_static;
#[cfg(any(feature = "std", feature = "tz", feature = "nitro"))]
use std::sync::{Mutex, Arc};
#[cfg(feature = "sgx")]
use std::sync::{SgxMutex as Mutex, Arc};
use veracruz_utils::policy::principal::Principal;
use crate::hcall::buffer::VFS;
use byteorder::{ByteOrder, LittleEndian};
use wasmtime::{Caller, Extern, ExternType, Func, Instance, Module, Store, Trap, ValType};

////////////////////////////////////////////////////////////////////////////////
// The Wasmtime runtime state.
////////////////////////////////////////////////////////////////////////////////


lazy_static! {
    // The initial value has NO use.
    static ref VFS_INSTANCE: Mutex<VFSService> = Mutex::new(VFSService::new(Arc::new(Mutex::new(VFS::new(&HashMap::new(),&HashMap::new())))));
    // The initial value has NO use.
    static ref CUR_PROGRAM: Mutex<Principal> = Mutex::new(Principal::NoCap);
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
        *VFS_INSTANCE.lock().unwrap() = VFSService::new(vfs);
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
                    if import.module() != "env" {
                        return Err(Trap::new(format!("Veracruz programs support only the Veracruz host interface.  Unrecognised module import '{}'.", import.name())));
                    }

                    let host_call_body = match import.name() {
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

                let export = instance.get_export(ENTRY_POINT_NAME).ok_or(Trap::new("No export with name '{}' in WASM program."))?; 
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
                }
            }
        }
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

