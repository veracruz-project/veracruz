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
    hcall::common::{ExecutionEngine, LifecycleState},
    hcall::buffer::VFS,
};

use veracruz_utils::{policy::{policy::Policy, principal::ExecutionStrategy}};
use veracruz_utils::{VeracruzCapabilityIndex, VeracruzPolicy};

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

//TODO MOVE THIS TO A SEPARATE FILE?
/// Result type of provisioning functions.
pub type ProvisioningResult = Result<ProvisioningResponse, RuntimeManagerError>;

/// The configuration details for the ongoing provisioning of secrets into the
/// Veracruz platform, containing information that must be persisted across the
/// different rounds of the provisioning process and the fixed global policy.
struct ProtocolState {
    #[deprecated]
    /// The Veracruz host provisioning state, which captures "transient" state
    /// of the provisioning process and updates its internal lifecycle state
    /// appropriately as more and more clients provision their secrets.
    host_state: Arc<Mutex<dyn ExecutionEngine>>,
    /// This flag indicates if new data or program is arrived since last execution.
    /// It decides if it is necessary to run a program when result retriever requests reading
    /// result.
    /// TODO: more defined tracking, e.g. flag per available program in the policy?
    is_modified : bool,
    /// The fixed, global policy parameterising the computation.  This should
    /// not change...
    global_policy: Policy,
    /// A hex-encoding of the raw JSON global policy.
    global_policy_hash: String,
    /// The list of clients (their IDs) that can request shutdown of the
    /// Veracruz platform.
    expected_shutdown_sources: Vec<u64>,
    vfs : Arc<Mutex<VFS>>,
}

impl ProtocolState {
    /// Constructs a new `ProtocolState` from a global policy.  The selected
    /// execution strategy is extrated from the global policy and a suitable
    /// Veracruz execution strategy is selected based on that.
    pub fn new(
        global_policy: Policy,
        global_policy_hash: String,
    ) -> Result<Self, RuntimeManagerError> {
        let expected_shutdown_sources = global_policy.expected_shutdown_list();

        let execution_strategy = match global_policy.execution_strategy() {
            ExecutionStrategy::Interpretation => {
                execution_engine::factory::ExecutionStrategy::Interpretation
            }
            ExecutionStrategy::JIT => execution_engine::factory::ExecutionStrategy::JIT,
        };
        let capability_table = global_policy.get_capability_table();
        let program_digests = global_policy.get_program_digests()?;
        let vfs = Arc::new(Mutex::new(VFS::new(&capability_table,&program_digests)));

        let host_state = multi_threaded_execution_engine(
            &execution_strategy,
            vfs.clone()
        )
        .ok_or(RuntimeManagerError::InvalidExecutionStrategyError)?;

        Ok(ProtocolState {
            host_state,
            global_policy,
            global_policy_hash,
            expected_shutdown_sources,
            vfs,
            is_modified : false
        })
    }

    #[deprecated]
    pub fn reload(&mut self) -> Result<(), MexicoCityError> {
        let execution_strategy = match self.global_policy.execution_strategy() {
            veracruz_utils::ExecutionStrategy::Interpretation => {
                chihuahua::factory::ExecutionStrategy::Interpretation
            }
            veracruz_utils::ExecutionStrategy::JIT => chihuahua::factory::ExecutionStrategy::JIT,
        };
        self.host_state = multi_threaded_chihuahua(
            &execution_strategy,
            self.vfs.clone()
        )
        .ok_or(MexicoCityError::InvalidExecutionStrategyError)?;
        self.is_modified = true;
        Ok(())
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

    //TODO: add description
    pub(crate) fn write_file(&self, client_id: &VeracruzCapabilityIndex, file_name: &str, data: &[u8]) -> Result<(), MexicoCityError> {
        Ok(self.host_state.lock()?.write_file(client_id,file_name,data)?)
    }

    //TODO: add description
    pub(crate) fn append_file(&self, client_id: &VeracruzCapabilityIndex, file_name: &str, data: &[u8]) -> Result<(), MexicoCityError> {
        Ok(self.host_state.lock()?.append_file(client_id,file_name,data)?)
    }

    //TODO: add description
    pub(crate) fn read_file(&self, client_id: &VeracruzCapabilityIndex, file_name: &str) -> Result<Option<Vec<u8>>, MexicoCityError> {
        Ok(self.host_state.lock()?.read_file(client_id,file_name)?)
    }

    /// Invokes the entry point of the provisioned WASM program.  Will fail if
    /// the current lifecycle state is not `LifecycleState::ReadyToExecute` or
    /// if the WASM program fails at runtime.  On success, bumps the lifecycle
    /// state to `LifecycleState::FinishedExecuting` and returns the error code
    /// returned by the WASM program entry point as an `i32` value.
    pub(crate) fn invoke_entry_point(&self,file_name:&str) -> Result<i32, RuntimeManagerError> {
        Ok(self.host_state.lock()?.invoke_entry_point(file_name)?)
    }

    /// Returns the current lifecycle state that the host provisioning state is
    /// in.
    pub(crate) fn get_lifecycle_state(&self) -> Result<LifecycleState, RuntimeManagerError> {
        Ok(self.host_state.lock()?.get_lifecycle_state().clone())
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
        &mut self,
        client_id: u64,
    ) -> Result<bool, RuntimeManagerError> {
        self.expected_shutdown_sources.retain(|v| v != &client_id);
        Ok(self.expected_shutdown_sources.is_empty())
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
