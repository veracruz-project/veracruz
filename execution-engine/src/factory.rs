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
use crate::hcall::{common::ExecutionEngine, wasmi, buffer::VFS};
use std::{
    boxed::Box,
    fmt::{Display, Error, Formatter},
    sync::Arc,
};

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
pub fn single_threaded_execution_engine(
    strategy: &ExecutionStrategy,
    vfs : Arc<Mutex<VFS>>,
) -> Option<Box<dyn ExecutionEngine + 'static>> {
    #[cfg(feature = "std")]
    {
        match strategy {
            ExecutionStrategy::Interpretation => {
                let state = new_wasmi_instance(vfs);

                Some(Box::new(state))
            }
            ExecutionStrategy::JIT => {
                wasmtime::initialize(
                    expected_data_sources,
                    expected_stream_sources,
                    expected_shutdown_sources,
                );

                Some(Box::new(wasmtime::DummyWasmtimeHostProvisioningState::new()))
            }
        }
    }
    #[cfg(any(feature = "tz", feature = "sgx", feature = "nitro"))]
    {
        match strategy {
            ExecutionStrategy::Interpretation => {
                let state = new_wasmi_instance(vfs);

                Some(Box::new(state))
            }
            ExecutionStrategy::JIT => None,
        }
    }
}

/// Selects an ExecutionEngine implementation based on a stated preference for
/// execution strategy, passing the lists of client IDs of clients that can
/// provision data and request platform shutdown straight to the relevant
/// execution engine.
///
/// NB: wasmtime is only supported when feature=std is set at the moment,
/// hence the branching around the body of this function.  When we get
/// it compiled for SGX and TZ, then this will disappear.
pub fn multi_threaded_execution_engine(
    strategy: &ExecutionStrategy,
    vfs : Arc<Mutex<VFS>>,
) -> Option<impl ExecutionEngine> {
    #[cfg(feature = "std")]
    {
        match strategy {
            ExecutionStrategy::Interpretation => {
                Some(new_wasmi_instance(vfs))
            }
            ExecutionStrategy::JIT => {
                //TODO change
                wasmtime::initialize(
                    &vec!([]),
                    &vec!([]),
                    expected_shutdown_sources,
                );

                Some(wasmtime::DummyWasmtimeHostProvisioningState::new())
            }
        }
    }
    #[cfg(any(feature = "tz", feature = "sgx", feature = "nitro"))]
    {
        match strategy {
            ExecutionStrategy::Interpretation => {
                Some(new_wasmi_instance(vfs))
            }
            ExecutionStrategy::JIT => None,
        }
    }
}

//TODO remove old parameters.
fn new_wasmi_instance (
    vfs : Arc<Mutex<VFS>>
) -> impl ExecutionEngine {
    wasmi::WasmiHostProvisioningState::new(vfs)
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
