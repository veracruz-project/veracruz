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
use crate::hcall::wasmtime;
use crate::hcall::{
    buffer::VFS,
    common::{EngineReturnCode, ExecutionEngine, FatalEngineError, RuntimeState},
    wasmi::runtime_state::WASMIRuntimeState,
};
use std::{
    boxed::Box,
    fmt::{Display, Error, Formatter},
    sync::Arc,
};

/// The following type captures the execution strategy which is being requested,
/// for the WASM program, from ExecutionEngine.
#[derive(Debug)]
pub enum ExecutionStrategy {
    /// An interpretation execution strategy should be used, running the WASM
    /// program on top of the *WASMI* execution engine.
    Interpretation,
    /// A JITting execution strategy should be used, running the WASM program
    /// on top of the *Wasmtime* execution engine.
    JIT,
}

/// Selects an ExecutionEngine implementation based on a stated preference for
/// execution strategy, passing the lists of client IDs of clients that can
/// provision data and request platform shutdown straight to the relevant
/// execution engine.
///
/// NB: wasmtime is only supported when feature=std is set at the moment,
/// hence the branching around the body of this function.  When we get
/// it compiled for SGX and TZ, then this will disappear.
#[deprecated]
pub fn single_threaded_execution_engine(
    strategy: &ExecutionStrategy,
    vfs: Arc<Mutex<VFS>>,
) -> Result<Option<Box<dyn ExecutionEngine>>, FatalEngineError> {
    let instance: Option<Box<dyn ExecutionEngine>> = match strategy {
        ExecutionStrategy::Interpretation => {
            Some(Box::new(wasmi::WasmiHostProvisioningState::new(vfs)))
        }
        ExecutionStrategy::JIT => {
            #[cfg(feature = "std")]
            {
                Some(Box::new(wasmtime::WasmtimeHostProvisioningState::new(vfs)?))
            }
            #[cfg(any(feature = "tz", feature = "sgx", feature = "nitro"))]
            None
        }
    };
    Ok(instance)
}

/// Selects an ExecutionEngine implementation based on a stated preference for
/// execution strategy, passing the lists of client IDs of clients that can
/// provision data and request platform shutdown straight to the relevant
/// execution engine.
///
/// NB: wasmtime is only supported when feature=std is set at the moment,
/// hence the branching around the body of this function.  When we get
/// it compiled for SGX and TZ, then this will disappear.
#[deprecated]
pub fn multi_threaded_execution_engine(
    strategy: &ExecutionStrategy,
    vfs: Arc<Mutex<VFS>>,
) -> Result<Option<Box<dyn ExecutionEngine>>, FatalEngineError> {
    let instance: Option<Box<dyn ExecutionEngine>> = match strategy {
        ExecutionStrategy::Interpretation => {
            Some(Box::new(wasmi::WasmiHostProvisioningState::new(vfs)))
        }
        ExecutionStrategy::JIT => {
            #[cfg(feature = "std")]
            {
                Some(Box::new(wasmtime::WasmtimeHostProvisioningState::new(vfs)?))
            }
            #[cfg(any(feature = "tz", feature = "sgx", feature = "nitro"))]
            None
        }
    };
    Ok(instance)
}

pub fn execute(
    strategy: &ExecutionStrategy,
    vfs: Arc<Mutex<VFS>>,
    program_file_name: &str,
) -> Result<EngineReturnCode, FatalEngineError> {
    let mut engine: Box<dyn ExecutionEngine> = match strategy {
        ExecutionStrategy::Interpretation => Box::new(wasmi::WasmiHostProvisioningState::new(vfs)),
        ExecutionStrategy::JIT => {
            #[cfg(feature = "std")]
            {
                Box::new(wasmtime::WasmtimeHostProvisioningState::new(vfs)?)
            }
            #[cfg(any(feature = "tz", feature = "sgx", feature = "nitro"))]
            {
                return Err(FatalEngineError::EngineIsNotReady);
            }
        }
    };
    engine.invoke_entry_point(&program_file_name)
}

////////////////////////////////////////////////////////////////////////////////
// Trait implementations
////////////////////////////////////////////////////////////////////////////////

impl Display for ExecutionStrategy {
    fn fmt(&self, f: &mut Formatter) -> Result<(), Error> {
        match self {
            ExecutionStrategy::Interpretation => write!(f, "Interpretation"),
            ExecutionStrategy::JIT => write!(f, "JIT"),
        }
    }
}
