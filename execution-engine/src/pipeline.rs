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
use crate::engines::wasmtime::WasmtimeRuntimeState;
use crate::{
    engines::{common::ExecutionEngine, wasmi::WASMIRuntimeState},
    fs::FileSystem,
};
use policy_utils::{pipeline::Expr, principal::ExecutionStrategy};
use std::boxed::Box;
use crate::Options;
use anyhow::Result;
use log::info;

/// Execute `pipeline`. Program will be read with the `caller_filesystem`, who should have
/// `FD_EXECUTE` and `FD_SEEK` permissions and executed with `pipeline_filesystem`.
/// The function will return the error code.
pub fn execute_pipeline(
    strategy: &ExecutionStrategy,
    caller_filesystem: &mut FileSystem,
    pipeline_filesystem: &FileSystem,
    pipeline: Box<Expr>,
    options: &Options,
) -> Result<u32> {
    use policy_utils::pipeline::Expr::*;
    match *pipeline {
        Literal(path_string) => {
            info!("Literal {:?}", path_string);
            // read and call execute_program
            let binary = caller_filesystem.read_exeutable_by_absolute_path(path_string)?;
            info!("Successful to read binary");
            let return_code = execute_program(strategy, pipeline_filesystem.clone(), binary, options)?;
            Ok(return_code)
        },
        Seq(vec) => {
            info!("Seq {:?}", vec);
            for expr in vec {
                let return_code = execute_pipeline(strategy, caller_filesystem, pipeline_filesystem, expr, options)?;

                // An error occurs
                if return_code != 0 {
                    return Ok(return_code);
                }
            }

            // default return_code is zero.
            Ok(0)
        },
        IfElse(cond, true_branch, false_branch) => {
            info!("IfElse {:?} true -> {:?} false -> {:?}", cond, true_branch, false_branch);
            let return_code = if caller_filesystem.file_exists(cond)? {
                execute_pipeline(strategy, caller_filesystem, pipeline_filesystem, true_branch, options)?
            } else {
                match false_branch {
                    Some(f) => execute_pipeline(strategy, caller_filesystem, pipeline_filesystem, f, options)?,
                    None => 0,
                }
            };
            Ok(return_code)
        },
    }
}

/// Execute the `program`. All I/O operations in the program are through at `filesystem`.
fn execute_program(
    strategy: &ExecutionStrategy,
    filesystem: FileSystem,
    program: Vec<u8>,
    options: &Options,
) -> Result<u32> {
    let mut engine: Box<dyn ExecutionEngine> = match strategy {
        ExecutionStrategy::Interpretation => Box::new(WASMIRuntimeState::new(filesystem, options.clone())?),
        ExecutionStrategy::JIT => {
            cfg_if::cfg_if! {
                if #[cfg(any(feature = "std", feature = "nitro"))] {
                    Box::new(WasmtimeRuntimeState::new(filesystem, options.clone())?)
                } else {
                    return Err(anyhow::anyhow!(crate::engines::common::FatalEngineError::EngineIsNotReady));
                }
            }
        }
    };
    engine.invoke_entry_point(program)
}
