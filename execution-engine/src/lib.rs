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

#[cfg(feature = "std")]
#[macro_use]
extern crate std;

#[macro_use]
extern crate num_derive;

mod engines;
pub mod fs;
mod native_modules;
// Expose the error to the external.
pub use engines::common::FatalEngineError;

#[cfg(feature = "std")]
use crate::engines::wasmtime::WasmtimeRuntimeState;
use crate::{
    engines::{common::ExecutionEngine, wasmi::WASMIRuntimeState},
    fs::FileSystem,
};
use anyhow::Result;
use policy_utils::principal::ExecutionStrategy;
use std::{boxed::Box, string::String, vec::Vec};

/// Runtime options for a program.
#[derive(Default)]
pub struct Options {
    /// A list of key-value pairs corresponding to the environment variables of the
    /// program, if any.
    pub environment_variables: Vec<(String, String)>,
    /// A list of strings, corresponding to the command-line arguments of the program,
    /// if any.
    pub program_arguments: Vec<String>,
    /// Whether clock-related functionality is enabled for the program.  If not
    /// enabled, clock- and time-related WASI host-calls return an unimplemented
    /// status code.
    pub enable_clock: bool,
    /// Whether strace-like output is enabled.
    pub enable_strace: bool,
}

/// The top-level function executes program `program` on
/// the `filesystem` handler, in which inputs, outputs and programs are stored.
/// The function requires execution `strategy`.
/// It currently supports `interp` or `JIT`, backed by `WASI` and `wasmtime`, respectively.
/// Note that the `execute` function is essentially this library's
/// interface to the outside world, and details exactly what external clients
/// such as `freestanding-execution-engine` and `runtime-manager` can rely on.
pub fn execute(
    strategy: &ExecutionStrategy,
    filesystem: FileSystem,
    program: Vec<u8>,
    options: Options,
) -> Result<u32> {
    let mut engine: Box<dyn ExecutionEngine> = match strategy {
        ExecutionStrategy::Interpretation => Box::new(WASMIRuntimeState::new(filesystem, options)?),
        ExecutionStrategy::JIT => {
            cfg_if::cfg_if! {
                if #[cfg(any(feature = "std", feature = "nitro"))] {
                    Box::new(WasmtimeRuntimeState::new(filesystem, options)?)
                } else {
                    return Err(anyhow!(FatalEngineError::EngineIsNotReady));
                }
            }
        }
    };
    engine.invoke_entry_point(program)
}
