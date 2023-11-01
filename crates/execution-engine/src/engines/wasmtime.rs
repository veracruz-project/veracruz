//! An implementation of the ExecutionEngine runtime state for Wasmtime.
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Copyright
//!
//! See the file `LICENSE.md` in the Veracruz root directory for licensing
//! and copyright information.

#![allow(clippy::too_many_arguments)]

use crate::{
    engines::common::ExecutionEngine,
    Environment,
};
use anyhow::Result;
use log::info;
use std::{
    vec::Vec,
    fs::{create_dir_all, File},
};
use wasmtime::{Config, Engine, Linker, Module, Store};
use wasmtime_wasi::sync::{Dir, WasiCtxBuilder};
use policy_utils::principal::PrincipalPermission;

////////////////////////////////////////////////////////////////////////////////
// The Wasmtime host provisioning state.
////////////////////////////////////////////////////////////////////////////////
/// The facade of WASMTIME host provisioning state.
pub struct WasmtimeRuntimeState {
    permissions: PrincipalPermission,
    environment: Environment,
}

////////////////////////////////////////////////////////////////////////////////
// Operations on the WasmtimeRuntimeState.
////////////////////////////////////////////////////////////////////////////////

impl WasmtimeRuntimeState {
    /// Creates a new initial `HostProvisioningState`.
    pub fn new(permissions: PrincipalPermission, environment: Environment
        ) -> Result<Self> {
        info!("Wasmtime is initialised");
        Ok(Self {
            permissions,
            environment,
        })
    }
}

/// The `WasmtimeHostProvisioningState` implements everything needed to create a
/// compliant instance of `ExecutionEngine`.
impl ExecutionEngine for WasmtimeRuntimeState {
    /// Executes the entry point of the WASM program provisioned into the
    /// Veracruz host.
    ///
    /// Raises a panic if the global Wasmtime host is unavailable.
    /// Returns an error if no program is registered, the program is invalid,
    /// the program contains invalid external function calls or if the machine is not
    /// in the `LifecycleState::ReadyToExecute` state prior to being called.
    ///
    /// Also returns an error if the WASM program or the Veracruz instance
    /// create a runtime trap during program execution (e.g. if the program
    /// executes an abort instruction, or passes bad parameters to the Veracruz
    /// host).
    ///
    /// Otherwise, returns the return value of the entry point function of the
    /// program, along with a host state capturing the result of the program's
    /// execution.
    #[inline]
    fn invoke_entry_point(&mut self, program: Vec<u8>) -> Result<u32> {
        info!("Initialize a wasmtime engine.");

        let mut config = Config::default();
        config.wasm_simd(true);
        let engine = Engine::new(&config)?;
        // https://docs.wasmtime.dev/examples-rust-wasi.html
        let mut linker = Linker::new(&engine);
        wasmtime_wasi::add_to_linker(&mut linker, |s| s)?;

        let wasm_build = WasiCtxBuilder::new()
            // https://docs.wasmtime.dev/api/wasmtime_wasi/sync/struct.WasiCtxBuilder.html#method.args
            .inherit_stdio()
            .envs(&self.environment.environment_variables)?
            .args(&self.environment.program_arguments)?
            .inherit_env()?
            .inherit_args()?;

        let wasm_build = self.permissions.keys().fold(Ok(wasm_build), |acc : Result<WasiCtxBuilder>, path| {
            let wasm_build = acc?;
            create_dir_all(path)?;
            let file = File::open(&path)?;
            info!("pre-opened directory {:?} created if necessary and opened", path);
            Ok(wasm_build.preopened_dir(Dir::from_std_file(file), path)?)
        })?;

        let wasi = wasm_build.build();
        let mut store = Store::new(&engine, wasi);
        let module = Module::new(&engine, program)?;
        linker.module(&mut store, "", &module)?;

        info!("Engine readies.");

        linker
            .get_default(&mut store, "")?
            .typed::<(), ()>(&store)?
            .call(&mut store, ())
            .map_err(|e| {
                info!("Engine return error: {:?}", e);
                e
            })?;

        info!("Execution returns.");

        Ok(0)
    }
}
