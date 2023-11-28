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
//! See the `LICENSE.md` file in the Veracruz root directory for
//! information on licensing and copyright.

#[cfg(feature = "std")]
#[macro_use]
extern crate std;

mod engines;
mod service;
mod pipeline;
mod common;


use policy_utils::{pipeline::Expr, principal::{PrincipalPermission, ExecutionStrategy, Service}};
use std::boxed::Box;

/// Runtime environment for a program.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Default)]
pub struct Environment {
    /// The environment variables currently set, and their bindings.
    pub environment_variables: Vec<(String, String)>,
    /// The program arguments of the executable being executed.
    pub program_arguments: Vec<String>,
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
    caller_permissions: &PrincipalPermission,
    execution_permissions: &PrincipalPermission,
    services: &[Service],
    pipeline: Box<Expr>,
    env: &Environment,
) -> anyhow::Result<()> {
    pipeline::execute_pipeline(strategy, caller_permissions, execution_permissions, services, pipeline, env)
}
