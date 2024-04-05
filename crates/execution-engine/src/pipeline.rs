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
use crate::engines::wasmtime::WasmtimeRuntimeState;
use crate::Environment;
use crate::{
    //engines::{common::ExecutionEngine, wasmi::WASMIRuntimeState},
    engines::{common::ExecutionEngine},
    //fs::FileSystem,
    native_module_manager::NativeModuleManager,
};
use anyhow::{anyhow, Result};
use log::info;
use policy_utils::{
    pipeline::Expr,
    principal::{ExecutionStrategy, NativeModule, NativeModuleType},
};
use std::{boxed::Box, path::{Path, PathBuf}, fs, collections::HashSet};

/// Returns whether the given path corresponds to a WASM binary.
fn is_wasm_binary(path_string: &String) -> bool {
    path_string.ends_with(".wasm")
}

/// Execute `pipeline`. Program will be read with the `caller_filesystem`, who should have
/// `FD_EXECUTE` and `FD_SEEK` permissions and executed with `pipeline_filesystem`.
/// The function will return the error code.
pub fn execute_pipeline(
    strategy: &ExecutionStrategy,
    //caller_filesystem: &mut FileSystem,
    pipeline_preopened_dir: &HashSet<PathBuf>,
    pipeline: Box<Expr>,
    env: &Environment,
) -> Result<u32> {
    use policy_utils::pipeline::Expr::*;
    match *pipeline {
        Literal(mut path_string) => {
            // Turn a relative path into an absolute path.
            //if &path_string[0..1] != "/" {
                //path_string.insert(0, '/');
            //}
            info!("Literal {:?}", path_string);
            if is_wasm_binary(&path_string) {
                // Read and call execute_WASM program
                // TODO: open the local file
                //let binary = caller_filesystem.read_executable_by_absolute_path(path_string)?;
                let binary = fs::read(path_string)?;
                info!("Successful to read binary");
                let return_code =
                    execute_program(strategy, pipeline_preopened_dir, binary, env)?;
                Ok(return_code)
            } else {
                // Treat program as a provisioned native module
                let native_module = NativeModule::new(
                    path_string.clone(),
                    NativeModuleType::Provisioned {
                        entry_point: PathBuf::from(&path_string),
                    },
                );

                // Invoke native module in the native module manager with no input.
                // The execution principal (native module) should have read access
                // to the directory containing the execution artifacts (binaries and
                // shared libraries), or the native module manager won't be able to
                // prepare the sandbox
                let mut native_module_manager =
                    NativeModuleManager::new(native_module);
                native_module_manager
                    .execute(vec![])
                    .map(|_| 0)
                    .map_err(|err| anyhow!(err))
            }
        }
        Seq(vec) => {
            info!("Seq {:?}", vec);
            for expr in vec {
                let return_code = execute_pipeline(strategy, pipeline_preopened_dir, expr, env)?;

                // An error occurs
                if return_code != 0 {
                    return Ok(return_code);
                }
            }

            // default return_code is zero.
            Ok(0)
        }
        IfElse(cond, true_branch, false_branch) => {
            info!("IfElse {:?} true -> {:?} false -> {:?}", cond, true_branch, false_branch);
            let return_code = if Path::new(&cond).exists() {
                execute_pipeline(strategy, pipeline_preopened_dir, true_branch, env)?
            } else {
                match false_branch {
                    Some(f) => execute_pipeline(strategy, pipeline_preopened_dir, f, env)?,
                    None => 0,
                }
            };
            Ok(return_code)
        }
    }
}

/// Execute the `program`. All I/O operations in the program are through at `filesystem`.
fn execute_program(
    strategy: &ExecutionStrategy,
    preopened_dir: &HashSet<PathBuf>,
    program: Vec<u8>,
    env: &Environment,
) -> Result<u32> {
    let mut engine: Box<dyn ExecutionEngine> = match strategy {
        ExecutionStrategy::Interpretation => {
            //Box::new(WASMIRuntimeState::new(filesystem, options.clone())?),
            return Err(anyhow::anyhow!(crate::engines::common::FatalEngineError::EngineIsNotReady));
        }
        ExecutionStrategy::JIT => {
            cfg_if::cfg_if! {
                if #[cfg(any(feature = "std", feature = "nitro"))] {
                    Box::new(WasmtimeRuntimeState::new(preopened_dir, env)?)
                } else {
                    return Err(anyhow::anyhow!(crate::engines::common::FatalEngineError::EngineIsNotReady));
                }
            }
        }
    };
    engine.invoke_entry_point(program)
}
