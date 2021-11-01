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
//! See the `LICENSE_MIT.markdown` file in the Veracruz root directory for
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

#[cfg(feature = "std")]
use crate::wasi::wasmtime::WasmtimeRuntimeState;
use crate::{
    fs::FileSystem,
    wasi::{common::ExecutionEngine, wasmi::WASMIRuntimeState},
};
use policy_utils::principal::ExecutionStrategy;
use std::sync::Mutex;
use std::{boxed::Box, string::String, string::ToString, sync::Arc, vec::Vec};

pub struct Options {
    pub environment_variables: Vec<(String, String)>,
    pub program_arguments: Vec<String>,
    pub enable_clock: bool,
}

impl Default for Options {
    fn default() -> Options {
        Options {
            environment_variables: Vec::new(),
            program_arguments: Vec::new(),
            enable_clock: false,
        }
    }
}

/// The top-level function executes program `program_name` on
/// the `filesystem` handler, in which inputs, outputs and programs are stored.
/// The function requires execution `strategy`.
/// It currently supports `interp` or `JIT`, backed by `WASI` and `wasmtime`, respectively.
/// Note that the `execute` function is essentially this library's
/// interface to the outside world, and details exactly what external clients
/// such as `freestanding-executuon-engine` and `runtime-manager` can rely on.
pub fn execute(
    strategy: &ExecutionStrategy,
    filesystem: Arc<Mutex<FileSystem>>,
    program_name: &str,
    options: Options,
) -> Result<u32, FatalEngineError> {
    let mut engine: Box<dyn ExecutionEngine> = match strategy {
        ExecutionStrategy::Interpretation => {
            Box::new(WASMIRuntimeState::new(filesystem, program_name.to_string()))
        }
        ExecutionStrategy::JIT => {
            cfg_if::cfg_if! {
                if #[cfg(feature = "std")] {
                    Box::new(WasmtimeRuntimeState::new(filesystem, program_name.to_string())?)
                } else {
                    return Err(FatalEngineError::EngineIsNotReady);
                }
            }
        }
    };
    engine.invoke_entry_point(program_name, options)
}
