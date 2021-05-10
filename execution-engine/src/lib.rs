//! The Veracruz WASM execution engine
//!
//! This module executes the WASM binary, and manages its execution, using two
//! *execution strategies*.  These are:
//!
//! 1. Interpretation, using the WASMI interpreter,
//! 2. JIT compilation, using the Wasmtime JIT.
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

#![cfg_attr(feature = "sgx", no_std)]

#[cfg(feature = "sgx")]
#[macro_use]
extern crate sgx_tstd as std;

#[cfg(feature = "std")]
#[macro_use]
extern crate std;

#[macro_use]
extern crate num_derive;

pub mod fs;
mod wasi;
// Expose the error to the external.
pub use wasi::common::FatalEngineError;

#[cfg(any(feature = "std", feature = "tz", feature = "nitro"))]
use std::sync::Mutex;
#[cfg(feature = "sgx")]
use std::sync::SgxMutex as Mutex;
#[cfg(feature = "std")]
use crate::wasi::wasmtime::WasmtimeRuntimeState;
use crate::{
    fs::FileSystem,
    wasi::{
        common::ExecutionEngine,
        wasmi::WASMIRuntimeState,
    }
};
use std::{
    boxed::Box,
    sync::Arc,
};
use veracruz_utils::policy::principal::ExecutionStrategy;

/// The top-level function executes program `program_name` on 
/// the `filesystem` handle, in which inputs, outputs and programs are stored.
/// The function requires execution `strategy`. In the case of
/// `Interpretation` being chosen, an implementation of the `ExecutionEngine` trait
/// is returned which uses an interpretation execution strategy.  Similarly, in
/// the case of `JIT` an implementation using a JITting execution strategy is
/// returned.  Note that the `execute` function is essentially this library's
/// interface to the outside world, and details exactly what external clients
/// such as `freestanding-executuon-engine` and `runtime-manager` can rely on.
pub fn execute(
    strategy: &ExecutionStrategy,
    filesystem: Arc<Mutex<FileSystem>>,
    program_name: &str,
) -> Result<wasi_types::ErrNo, FatalEngineError> {
    let mut engine : Box<dyn ExecutionEngine> = match strategy {
        ExecutionStrategy::Interpretation => Box::new(WASMIRuntimeState::new(filesystem, program_name)),
        ExecutionStrategy::JIT => 
        {
            #[cfg(feature = "std")]
            {
                Box::new(WasmtimeRuntimeState::new(filesystem, program_name))
            }
            #[cfg(any(feature = "tz", feature = "sgx", feature = "nitro"))]
            {
                return Err(FatalEngineError::EngineIsNotReady);
            }
        }
    };
    engine.invoke_entry_point(&program_name)
}
