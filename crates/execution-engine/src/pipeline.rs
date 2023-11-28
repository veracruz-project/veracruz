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
    Execution,
    service::common::initial_service,
    engines::sandbox::Sandbox,
};
use anyhow::{anyhow, Result};
use log::info;
use policy_utils::{
    pipeline::Expr,
    principal::{PrincipalPermission, FilePermissions, ExecutionStrategy, check_permission, Service},
};
use std::{boxed::Box, path::Path};

/// Returns whether the given path corresponds to a WASM binary.
fn is_wasm_binary(path_string: &String) -> bool {
    path_string.ends_with(".wasm")
}

/// Execute `pipeline`. Program will be read with the `caller_filesystem`, who should have
/// `FD_EXECUTE` and `FD_SEEK` permissions and executed with `pipeline_filesystem`.
/// The function will return the error code.
pub(crate) fn execute_pipeline(
    strategy: &ExecutionStrategy,
    caller_permissions: &PrincipalPermission,
    execution_permissions: &PrincipalPermission,
    services: &[Service],
    pipeline: Box<Expr>,
    env: &Environment,
) -> Result<()> {
    // Iniital internal services
    initial_service(services)?;
    use policy_utils::pipeline::Expr::*;
    match *pipeline {
        Literal(path) => {
            info!("Literal {:?}", path);
            // checker permission
            if !check_permission(&caller_permissions, path.clone(), &FilePermissions{read: false, write: false, execute: true}) {
                return Err(anyhow!("Permission denies"));
            }
            if is_wasm_binary(&path) {
                info!("Invoke wasm binary: {path}");
                // Read and call execute_WASM program
                execute_wasm(strategy, execution_permissions, &Path::new(&path), env)
            } else { // Sandbox
                info!("Invoke native binary: {path}");
                execute_native_binary(&Path::new(&path))
            }
        }
        Seq(vec) => {
            info!("Seq {:?}", vec);
            for expr in vec {
                execute_pipeline(strategy, caller_permissions, execution_permissions, services, expr, env)?;
            }
            Ok(())
        }
        IfElse(cond, true_branch, false_branch) => {
            info!("IfElse {:?} true -> {:?} false -> {:?}", cond, true_branch, false_branch);
            let return_code = if Path::new(&cond).exists() {
                execute_pipeline(strategy, caller_permissions, execution_permissions, services, true_branch, env)?
            } else {
                match false_branch {
                    Some(f) => execute_pipeline(strategy, caller_permissions, execution_permissions, services, f, env)?,
                    None => (),
                }
            };
            Ok(return_code)
        }
    }
}

/// Execute the `program`. All I/O operations in the program are through at `filesystem`.
fn execute_wasm(
    strategy: &ExecutionStrategy,
    execution_permissions: &PrincipalPermission,
    program_path: &Path,
    env: &Environment,
) -> Result<()> {
    info!("Execute program with permissions {:?}", execution_permissions);
    let mut engine: Box<dyn Execution> = match strategy {
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
    engine.execute(program_path)
}

fn execute_native_binary(program_path: &Path) -> Result<()> {
    let program_name = program_path.file_name().and_then(|os_str| os_str.to_str()).ok_or(anyhow!("Failed to extract program name from program path to a native binary."))?;
    Sandbox::new(&program_name).execute(program_path)
}
