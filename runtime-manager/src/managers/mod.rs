//! Management module for the Veracruz execution engine.
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

#[cfg(feature = "tz")]
use optee_utee::trace_println;
#[cfg(feature = "sgx")]
use sgx_types::sgx_status_t;
#[cfg(any(feature = "tz", feature = "nitro"))]
use std::sync::Mutex;
use std::{
    collections::HashMap,
    string::String,
    sync::{
        atomic::{AtomicBool, AtomicU32, Ordering},
        Arc,
    },
    vec::Vec,
};
#[cfg(feature = "sgx")]
use std::{ffi::CString, sync::SgxMutex as Mutex};

use lazy_static::lazy_static;

use execution_engine::{
    factory::multi_threaded_execution_engine,
    hcall::common::{ExecutionEngine, DataSourceMetadata, LifecycleState},
};

use veracruz_utils::{policy::{policy::Policy, principal::ExecutionStrategy}};

pub mod session_manager;
pub mod buffer;
pub mod execution_engine_manager;
pub mod error;
pub use error::RuntimeManagerError;

////////////////////////////////////////////////////////////////////////////////
// Various bits of persistent state.
////////////////////////////////////////////////////////////////////////////////

lazy_static! {
    static ref MY_SESSION_MANAGER: Mutex<Option<::session_manager::SessionContext>> = Mutex::new(None);
    static ref SESSION_COUNTER: AtomicU32 = AtomicU32::new(1);
    static ref SESSIONS: Mutex<HashMap<u32, ::session_manager::Session>> = Mutex::new(HashMap::new());
    static ref PROTOCOL_STATE: Mutex<Option<ProtocolState>> = Mutex::new(None);
    static ref DEBUG_FLAG: AtomicBool = AtomicBool::new(false);
}

////////////////////////////////////////////////////////////////////////////////
// Error and response codes and messages.
////////////////////////////////////////////////////////////////////////////////

/// The possible responses to a provisioning step: either a protocol error (i.e.
/// somebody did something out of turn, they didn't have permission to do
/// something, or similar), we need to wait for more data to complete an action,
/// or success.
pub enum ProvisioningResponse {
    /// Signals a message has arrived too soon, and the enclave's state machine
    /// is in the incorrect state to process this message.
    ProtocolError {
        /// The server response.
        response: Vec<u8>,
    },
    /// The incoming buffer is not full, so we cannot parse a complete protobuf
    /// message.  We need to wait longer for this to arrive.
    WaitForMoreData,
    /// Provisioning succeeded, in which case an optional response was
    /// generated.  In the case of waiting for more data (e.g. when the incoming
    /// buffer does not contain enough data to parse a correct protobuf message)
    /// this response will be empty.
    Success {
        /// The server response.
        response: Vec<u8>,
    },
}

/// Result type of provisioning functions.
pub type ProvisioningResult = Result<ProvisioningResponse, RuntimeManagerError>;

/// The configuration details for the ongoing provisioning of secrets into the
/// Veracruz platform, containing information that must be persisted across the
/// different rounds of the provisioning process and the fixed global policy.
struct ProtocolState {
    /// The Veracruz host provisioning state, which captures "transient" state
    /// of the provisioning process and updates its internal lifecycle state
    /// appropriately as more and more clients provision their secrets.
    host_state: Arc<Mutex<dyn ExecutionEngine>>,
    /// The fixed, global policy parameterising the computation.  This should
    /// not change...
    global_policy: Policy,
    /// A hex-encoding of the raw JSON global policy.
    global_policy_hash: String,
}

impl ProtocolState {
    /// Constructs a new `ProtocolState` from a global policy.  The selected
    /// execution strategy is extrated from the global policy and a suitable
    /// Veracruz execution strategy is selected based on that.
    pub fn new(
        global_policy: Policy,
        global_policy_hash: String,
    ) -> Result<Self, RuntimeManagerError> {
        let expected_data_sources = global_policy.data_provision_order();
        let expected_stream_sources = global_policy.stream_provision_order();
        let expected_shutdown_sources = global_policy.expected_shutdown_list();

        let execution_strategy = match global_policy.execution_strategy() {
            ExecutionStrategy::Interpretation => {
                execution_engine::factory::ExecutionStrategy::Interpretation
            }
            ExecutionStrategy::JIT => execution_engine::factory::ExecutionStrategy::JIT,
        };

        let host_state = multi_threaded_execution_engine(
            &execution_strategy,
            &expected_data_sources,
            &expected_stream_sources,
            expected_shutdown_sources
                .iter()
                .map(|e| *e as u64)
                .collect::<Vec<u64>>()
                .as_slice(),
        )
        .ok_or(RuntimeManagerError::InvalidExecutionStrategyError)?;

        Ok(ProtocolState {
            host_state,
            global_policy,
            global_policy_hash,
        })
    }

    /// Returns the global policy associated with the protocol state.
    #[inline]
    pub(crate) fn get_policy(&self) -> &Policy {
        &self.global_policy
    }

    /// Returns the global policy's hash, a hex-encoded string.
    #[inline]
    pub(crate) fn get_policy_hash(&self) -> &str {
        &self.global_policy_hash
    }

    ////////////////////////////////////////////////////////////////////////////
    // The ExecutionEngine facade.
    ////////////////////////////////////////////////////////////////////////////

    /* The following re-implements a subset of the ExecutionEngine API for
     * `ProtocolState` by just calling through to the underlying
     * `Arc<Mutex<dyn ExecutionEngine>>` object.  All lock-handling code is therefore
     * hidden from the user.
     */

    /// Loads a raw WASM program from a buffer of received or parsed bytes.
    /// Will fail if the lifecycle state is not in `LifecycleState::Initial` or
    /// if the buffer cannot be parsed.  On success bumps the lifecycle state to
    /// `LifecycleState::ReadyToExecute` in cases where no data sources are
    /// expected (i.e. we are a pure delegate) or
    /// `LifecycleState::DataSourcesLoading` in cases where we are expecting
    /// data to be provisioned.
    pub(crate) fn load_program(&self, buffer: &[u8]) -> Result<(), RuntimeManagerError> {
        Ok(self.host_state.lock()?.load_program(buffer)?)
    }

    /// Provisions a new data source, described using a `DataSourceMetadata`
    /// frame into the host state.  Will fail if the lifecycle state is not
    /// `LifecycleState::DataSourcesLoading`.  Will bump the lifecycle state to
    /// `LifecycleState::StreamSourcesLoading` when the call represents the last
    /// data source to be loaded,
    /// `LifecycleState::ReadyToExecute` if no stream data is required,
    /// or maintains the current lifecycle state.
    pub(crate) fn add_new_data_source(
        &self,
        metadata: DataSourceMetadata,
    ) -> Result<(), RuntimeManagerError> {
        Ok(self.host_state.lock()?.add_new_data_source(metadata)?)
    }

    /// Provisions a new stream source, described using a `DataSourceMetadata`
    /// frame into the host state.  Will fail if the lifecycle state is not
    /// `LifecycleState::StreamSourcesLoading`.  Will bump the lifecycle state to
    /// `LifecycleState::ReadyToExecute` when the call represents the last
    /// data source to be loaded, or maintains the current lifecycle state.
    pub(crate) fn add_new_stream_source(
        &self,
        metadata: DataSourceMetadata,
    ) -> Result<(), RuntimeManagerError> {
        Ok(self.host_state.lock()?.add_new_stream_source(metadata)?)
    }

    /// Invokes the entry point of the provisioned WASM program.  Will fail if
    /// the current lifecycle state is not `LifecycleState::ReadyToExecute` or
    /// if the WASM program fails at runtime.  On success, bumps the lifecycle
    /// state to `LifecycleState::FinishedExecuting` and returns the error code
    /// returned by the WASM program entry point as an `i32` value.
    pub(crate) fn invoke_entry_point(&self) -> Result<i32, RuntimeManagerError> {
        Ok(self.host_state.lock()?.invoke_entry_point()?)
    }

    /// Returns the current lifecycle state that the host provisioning state is
    /// in.
    pub(crate) fn get_lifecycle_state(&self) -> Result<LifecycleState, RuntimeManagerError> {
        Ok(self.host_state.lock()?.get_lifecycle_state().clone())
    }

    /// Returns a result of a WASM computation that has executed on the host
    /// provisioning state.  Returns `None` iff no such result has been
    /// registered.
    pub(crate) fn get_result(&self) -> Result<Option<Vec<u8>>, RuntimeManagerError> {
        Ok(self.host_state.lock()?.get_result().map(|o| o.clone()))
    }

    /// Sets the `previous_result` field.
    pub(crate) fn set_previous_result(
        &mut self,
        result: &Option<Vec<u8>>,
    ) -> Result<(), RuntimeManagerError> {
        self.host_state.lock()?.set_previous_result(result);
        Ok(())
    }

    /// Returns an SHA-256 digest of the bytes loaded into the host provisioning
    /// state.  Returns `None` iff no such program has yet been loaded.
    pub(crate) fn get_program_digest(&self) -> Result<Option<Vec<u8>>, RuntimeManagerError> {
        Ok(self
            .host_state
            .lock()?
            .get_program_digest()
            .map(|o| o.clone()))
    }

    /// Moves the host provisioning state's lifecycle state into
    /// `LifecycleState::Error`, a state which it cannot ever escape,
    /// effectively invalidating it.
    pub(crate) fn invalidate(&self) -> Result<(), RuntimeManagerError> {
        Ok(self.host_state.lock()?.invalidate())
    }

    /// Requests shutdown on behalf of a client, as identified by their client
    /// ID, and then checks if this request was sufficient to reach a threshold
    /// of requests wherein the platform can finally shutdown.
    pub(crate) fn request_and_check_shutdown(
        &self,
        client_id: u64,
    ) -> Result<bool, RuntimeManagerError> {
        Ok(self
            .host_state
            .lock()?
            .request_and_check_shutdown(client_id))
    }
}

////////////////////////////////////////////////////////////////////////////////
// Debug printing outside of the enclave.
////////////////////////////////////////////////////////////////////////////////

/// Prints a debug message, `message`, via our debug OCALL print mechanism, if
/// the debug configuration flat is set for the enclave.  Has no effect,
/// otherwise.
pub fn debug_message(message: String) {
    if DEBUG_FLAG.load(Ordering::SeqCst) {
        print_message(message, 0);
    }
}

/// Prints an error message, `message`, with a fixed error code, `error_code`,
/// via our debug OCALL print mechanism, if the debug configuration flat is set
/// for the enclave.  Has no effect, otherwise.
pub fn error_message(message: String, error_code: u32) {
    print_message(message, error_code);
}

/// Base function for printing messages outside of the enclave.  Note that this
/// should only print something to *stdoout* on the host's machine if the debug
/// configuration flag is set in the Veracruz global policy.
fn print_message(message: String, code: u32) {
    #[cfg(feature = "sgx")]
    {
        let mut ocall_ret = sgx_status_t::SGX_SUCCESS;
        let ocall_rst = unsafe {
            crate::runtime_manager_sgx::debug_and_error_output_ocall(
                &mut ocall_ret,
                CString::new(message).unwrap().as_ptr(),
                code,
            )
        };
        if ocall_ret != sgx_status_t::SGX_SUCCESS || ocall_rst != sgx_status_t::SGX_SUCCESS {
            // NOTE: This function is the exit point for Err.
            //       If it has a problem, just panic.
            panic!();
        }
    }
    #[cfg(feature = "tz")]
    if code == 0 {
        trace_println!("Enclave debug message \"{}\"", message);
    } else {
        trace_println!(
            "Enclave returns error code {} and message \"{}\"",
            code,
            message
        );
    }
}
