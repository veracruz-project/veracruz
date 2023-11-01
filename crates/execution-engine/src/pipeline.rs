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
use crate::{
    Environment,
    engines::common::ExecutionEngine,
    native_module_manager::NativeModuleManager,
    native_modules::common::initial_service,
};
use anyhow::{anyhow, Result};
use log::info;
use policy_utils::{
    pipeline::Expr,
    principal::{PrincipalPermission, FilePermissions, ExecutionStrategy, NativeModule, NativeModuleType, check_permission},
};
use std::{boxed::Box, path::{Path, PathBuf}};

/// Returns whether the given path corresponds to a WASM binary.
fn is_wasm_binary(path_string: &String) -> bool {
    path_string.ends_with(".wasm")
}

/// Execute `pipeline`. Program will be read with the `caller_filesystem`, who should have
/// `FD_EXECUTE` and `FD_SEEK` permissions and executed with `pipeline_filesystem`.
/// The function will return the error code.
pub fn execute_pipeline(
    strategy: &ExecutionStrategy,
    caller_permissions: &PrincipalPermission,
    execution_permissions: &PrincipalPermission,
    pipeline: Box<Expr>,
    env: &Environment,
) -> Result<()> {
    use policy_utils::pipeline::Expr::*;
    match *pipeline {
        Literal(path) => {
            info!("Literal {:?}", path);
            // checker permission
            if !check_permission(&caller_permissions, path.clone(), &FilePermissions{read: false, write: false, execute: true}) {
                return Err(anyhow!("Permission denies"));
            }
            if is_wasm_binary(&path) {
                info!("Read wasm binary: {}", path);
                // Read and call execute_WASM program
                execute_program(strategy, execution_permissions, &Path::new(&path), env)
            } else {
                info!("Invoke native binary: {}", path);
                // Treat program as a provisioned native module
                let native_module = NativeModule::new(
                    path.clone(),
                    NativeModuleType::Provisioned { entry_point: PathBuf::from(&path) },
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
                    .map(|_| ())
                    .map_err(|err| anyhow!(err))
            }
        }
        Seq(vec) => {
            info!("Seq {:?}", vec);
            for expr in vec {
                execute_pipeline(strategy, caller_permissions, execution_permissions, expr, env)?;
            }

            // default return_code is zero.
            Ok(())
        }
        IfElse(cond, true_branch, false_branch) => {
            info!("IfElse {:?} true -> {:?} false -> {:?}", cond, true_branch, false_branch);
            let return_code = if Path::new(&cond).exists() {
                execute_pipeline(strategy, caller_permissions, execution_permissions, true_branch, env)?
            } else {
                match false_branch {
                    Some(f) => execute_pipeline(strategy, caller_permissions, execution_permissions, f, env)?,
                    None => (),
                }
            };
            Ok(return_code)
        }
    }
}

/// Execute the `program`. All I/O operations in the program are through at `filesystem`.
fn execute_program(
    strategy: &ExecutionStrategy,
    execution_permissions: &PrincipalPermission,
    program_path: &Path,
    env: &Environment,
) -> Result<()> {
    info!("Execute program with permissions {:?}", execution_permissions);
    initial_service();
    let mut engine: Box<dyn ExecutionEngine> = match strategy {
        ExecutionStrategy::Interpretation => {
            return Err(anyhow!("No interpretation engine."));
        }
        ExecutionStrategy::JIT => {
            cfg_if::cfg_if! {
                if #[cfg(any(feature = "std", feature = "nitro"))] {
                    info!("JIT engine initialising");
                    Box::new(WasmtimeRuntimeState::new(execution_permissions.clone(), env.clone())?)
                    
                } else {
                    return Err(anyhow!("No JIT enine."));
                }
            }
        }
    };
    info!("engine call");
    engine.serve(program_path)
}
