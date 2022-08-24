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

pub fn execute_pipeline(
    strategy: &ExecutionStrategy,
    // TODO: Assume it is the filesystem to execute the entire pipeline
    mut filesystem: FileSystem,
    pipeline: Box<Expr>,
    options: &Options,
) -> Result<(u32, FileSystem)> {
    use policy_utils::pipeline::Expr::*;
    match *pipeline {
        Literal(path_string) => {
            info!("Literal {:?}", path_string);
            // read and call execute_program
            let binary = filesystem.read_file_by_absolute_path(path_string)?;
            info!("Successful to read binary");
            // DO we do somoething on the filesystem, intersection with the 
            let return_code = execute_program(strategy, filesystem.clone(), binary, options)?;
            Ok((return_code, filesystem))
        },
        Seq(vec) => {
            info!("Seq {:?}", vec);
            for expr in vec {
                let (return_code, return_filesystem) = execute_pipeline(strategy, filesystem, expr, options)?;
                // ownership movement here
                filesystem = return_filesystem;
                if return_code != 0 {
                    return Ok((return_code, filesystem));
                }
            }
            //TODO change the return code
            Ok((0, filesystem))
        },
        IfElse(cond, true_branch, false_branch) => {
            info!("IfElse {:?} true -> {:?} false -> {:?}", cond, true_branch, false_branch);
            // TODO impl
            Ok((0, filesystem))
        },
    }
}

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
                    return Err(anyhow::anyhow!(FatalEngineError::EngineIsNotReady));
                }
            }
        }
    };
    engine.invoke_entry_point(program)
}
