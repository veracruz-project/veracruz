//! A factory method returning execution strategies
//!
//! ## About
//!
//! The factory functions defined in this file is one of the few functions
//! exported from the ExecutionEngine library, and takes an enumeration value
//! detailing which execution strategy should be used.  In the case of
//! `Interpretation` being chosen, an implementation of the `ExecutionEngine` trait
//! is returned which uses an interpretation execution strategy.  Similarly, in
//! the case of `JIT` an implementation using a JITting execution strategy is
//! returned.  Note that the `ExecutionEngine` trait is essentially this library's
//! interface to the outside world, and details exactly what external clients
//! such as `freestanding-executuon-engine` and `runtime-manager` can rely on.
//!
//! ## Todo
//!
//! Try to merge `single_threaded_execution_engine` and
//! `multi_threaded_execution_engine` into a single function.  Problem: if you
//! return `boxed::Box<..>` then `runtime-manager/src/managers/mod.rs` is seemingly
//! impossible to implement as you run into issues with no compile-time size for
//! the trait object when converting the `Box<..>` into `Arc<Mutex<..>>`.
//!
//! Also: remove the panic and include a proper error report that is propagated.
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Copyright
//!
//! See the file `LICENSE.markdown` in the Veracruz root directory for licensing
//! and copyright information.

#[cfg(any(feature = "std", feature = "tz", feature = "nitro"))]
use std::sync::Mutex;
#[cfg(feature = "sgx")]
use std::sync::SgxMutex as Mutex;

#[cfg(feature = "std")]
use crate::hcall::wasi::wasmtime::runtime_state::WasmtimeRuntimeState;
use crate::{
    fs::FileSystem,
    hcall::{
        common::{EngineReturnCode, ExecutionEngine, FatalEngineError},
        wasi::wasmi::runtime_state::WASMIRuntimeState,
    }
};
use std::{
    boxed::Box,
    sync::Arc,
};
use veracruz_utils::policy::principal::ExecutionStrategy;

pub fn execute(
    strategy: &ExecutionStrategy,
    filesystem: Arc<Mutex<FileSystem>>,
    program_name: &str,
) -> Result<EngineReturnCode, FatalEngineError> {
    // TODO MODIFY when `new` directly fill in a program this can simply the wasmi impl esp. option
    // on memory and program module.
    let mut engine : Box<dyn ExecutionEngine> = match strategy {
        ExecutionStrategy::Interpretation => Box::new(WASMIRuntimeState::new(filesystem, program_name)),
        ExecutionStrategy::JIT => 
        {
            #[cfg(feature = "std")]
            {
                Box::new(WasmtimeRuntimeState::new(filesystem, program_name))
            }
            #[cfg(any(feature = "tz", feature = "sgx", feature = "nitro"))]
            {
                return Err(FatalEngineError::EngineIsNotReady);
            }
        }
    };
    engine.invoke_entry_point(&program_name)
}
