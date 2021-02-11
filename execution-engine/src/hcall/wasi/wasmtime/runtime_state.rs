//! An implementation of the Chihuahua runtime state for Wasmtime.
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Copyright
//!
//! See the file `LICENSE.markdown` in the Veracruz root directory for licensing
//! and copyright information.

use std::{vec::Vec};

use crate::hcall::common::{RuntimeState, Chihuahua, RuntimePanic, ProvisioningError, LifecycleState};

////////////////////////////////////////////////////////////////////////////////
// The Wasmtime runtime state.
////////////////////////////////////////////////////////////////////////////////

/// The WASMI host provisioning state: the `HostProvisioningState` with the
/// Module and Memory type-variables specialised to WASMI's `ModuleRef` and
/// `MemoryRef` type.
type WasmtimeRuntimeState = RuntimeState<Vec<u8>, ()>;

lazy_static! {
    static ref WASMTIME_RUNTIME_STATE: Mutex<WasmtimeRuntimeState> = Mutex::new(RuntimeState::new());
}

////////////////////////////////////////////////////////////////////////////////
// Operations on the WasmtimeRuntimeState.
////////////////////////////////////////////////////////////////////////////////

impl WasmtimeRuntimeState {
    pub fn load_program(&mut self, buffer: &[u8]) -> Result<(), ProvisioningError> {
        unimplemented!()
    }
}

////////////////////////////////////////////////////////////////////////////////
// An atomic Wasmtime runtime state.
////////////////////////////////////////////////////////////////////////////////

pub(crate) struct AtomicWasmtimeRuntimeState;

impl AtomicWasmtimeRuntimeState {
    pub fn load_program(&mut _self, buffer: &[u8])
}

////////////////////////////////////////////////////////////////////////////////
// Chihuahua trait implementation.
////////////////////////////////////////////////////////////////////////////////

impl Chihuahua for AtomicWasmtimeRuntimeState {
    #[inline]
    fn load_program(&mut self, buffer: &[u8]) -> Result<(), ProvisioningError> {
        self.load_program(buffer)
    }

    fn add_data_source(&mut self, fname: _, buffer: _) -> Result<(), ProvisioningError> {
        unimplemented!()
    }

    fn add_stream_source(&mut self, fname: _, buffer: _) -> Result<(), ProvisioningError> {
        unimplemented!()
    }

    fn invoke_entry_point(&mut self) -> Result<i32, RuntimePanic> {
        unimplemented!()
    }

    fn is_program_module_registered(&self) -> bool {
        unimplemented!()
    }

    fn is_memory_registered(&self) -> bool {
        unimplemented!()
    }

    fn is_able_to_shutdown(&self) -> bool {
        unimplemented!()
    }

    fn lifecycle_state(&self) -> &LifecycleState {
        unimplemented!()
    }

    fn registered_data_source_count(&self) -> usize {
        unimplemented!()
    }

    fn registered_stream_source_count(&self) -> usize {
        unimplemented!()
    }

    fn expected_data_source_count(&self) -> usize {
        unimplemented!()
    }

    fn expected_stream_source_count(&self) -> usize {
        unimplemented!()
    }

    fn expected_shutdown_sources(&self) -> &_ {
        unimplemented!()
    }

    fn result_filename(&self) -> Option<&_> {
        unimplemented!()
    }

    fn program_digest(&self) -> Option<&_> {
        unimplemented!()
    }

    fn set_expected_data_source_count(&mut self, sources: usize) -> &mut dyn Chihuahua {
        unimplemented!()
    }

    fn set_expected_stream_source_count(&mut self, sources: usize) -> &mut dyn Chihuahua {
        unimplemented!()
    }

    fn set_expected_shutdown_sources(&mut self, sources: _) -> &mut dyn Chihuahua {
        unimplemented!()
    }

    fn error(&mut self) -> &mut dyn Chihuahua {
        unimplemented!()
    }

    fn request_shutdown(&mut self, client_id: &u64) -> &mut dyn Chihuahua {
        unimplemented!()
    }
}