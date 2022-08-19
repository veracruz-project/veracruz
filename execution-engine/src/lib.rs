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
mod pipeline;
// Expose the error to the external.
pub use engines::common::FatalEngineError;

use crate::fs::FileSystem;
use policy_utils::{pipeline::Expr, principal::ExecutionStrategy};
use std::boxed::Box;

/// Runtime options for a program.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Default)]
pub struct Options {
    /// Whether clock-related functionality is enabled for the program.  If not
    /// enabled, clock- and time-related WASI host-calls return an unimplemented
    /// status code.
    pub enable_clock: bool,
    /// Whether strace-like output is enabled.
    pub enable_strace: bool,
}

/// The top-level function executes the pipeline of programs, `pipeline`, on
/// the `filesystem` handler, in which inputs, outputs and programs are stored,
/// and an initial set of environment variables "shared" across the entire
/// pipeline, `initial_environment_variables`.
///
/// The function also requires a specified execution `strategy`, which is either
/// `interp` or `JIT`, backed by `WASMI` and `Wasmtime`, respectively.
///
/// Note that the `execute` function is essentially this library's
/// interface to the outside world, and details exactly what external clients
/// such as `freestanding-execution-engine` and `runtime-manager` can rely on.
pub fn execute(
    strategy: &ExecutionStrategy,
    filesystem: FileSystem,
    pipeline: Box<Expr>,
    options: &Options,
) -> anyhow::Result<u32> {
    //TODO install the environment variables 
    Ok(pipeline::execute_pipeline(strategy, filesystem, pipeline, options)?.0)
}
