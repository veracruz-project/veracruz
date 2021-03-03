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
    hcall::common::EngineReturnCode,
    hcall::buffer::VFS,
};

use veracruz_utils::{policy::{policy::Policy, principal::ExecutionStrategy}};
use veracruz_utils::{VeracruzCapabilityIndex, VeracruzPolicy, VeracruzCapability};

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
    //TODO REMOVE?
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
pub(crate) struct ProtocolState {
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

        Ok(ProtocolState {
            global_policy,
            global_policy_hash,
            expected_shutdown_sources,
            vfs,
            is_modified : true
        })
    }

    #[deprecated]
    pub fn reload(&mut self) -> Result<(), RuntimeManagerError> {
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

    //TODO: add description
    pub(crate) fn write_file(&mut self, client_id: &VeracruzCapabilityIndex, file_name: &str, data: &[u8]) -> Result<(), RuntimeManagerError> {
        self.is_modified = true;
        self.vfs.lock()?.check_capability(client_id,file_name, &VeracruzCapability::Write)?;
        Ok(self.vfs.lock()?.write(file_name,data)?)
    }

    //TODO: add description
    pub(crate) fn append_file(&mut self, client_id: &VeracruzCapabilityIndex, file_name: &str, data: &[u8]) -> Result<(), RuntimeManagerError> {
        self.is_modified = true;
        self.vfs.lock()?.check_capability(client_id,file_name, &VeracruzCapability::Write)?;
        Ok(self.vfs.lock()?.append(file_name,data)?)
    }

    //TODO: add description
    pub(crate) fn read_file(&self, client_id: &VeracruzCapabilityIndex, file_name: &str) -> Result<Option<Vec<u8>>, RuntimeManagerError> {
        self.vfs.lock()?.check_capability(client_id,file_name, &VeracruzCapability::Read)?;
        Ok(self.vfs.lock()?.read(file_name)?)
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
    
    pub(crate) fn launch(&mut self, file_name: &str, client_id: u64) -> ProvisioningResult {
        let execution_strategy = match self.global_policy.execution_strategy() {
            veracruz_utils::ExecutionStrategy::Interpretation => {
                execution_engine::factory::ExecutionStrategy::Interpretation
            }
            veracruz_utils::ExecutionStrategy::JIT => execution_engine::factory::ExecutionStrategy::JIT,
        };
        let return_code = multi_threaded_execution_engine(
            &execution_strategy,
            self.vfs.clone()
        )
        // TODO: change the error
        .ok_or(RuntimeManagerError::InvalidExecutionStrategyError)?
        .invoke_entry_point(&file_name)?;
        
        let response = if return_code == EngineReturnCode::Success {
            let result = self.read_file(&VeracruzCapabilityIndex::Principal(client_id),"output")?;
            Self::response_success(result)
        } else {
            Self::response_error_code_returned(return_code)
        };

        self.is_modified = false;
        Ok(ProvisioningResponse::Success { response })
    }

    fn response_success(result: Option<Vec<u8>>) -> Vec<u8> {
        colima::serialize_result(colima::ResponseStatus::SUCCESS as i32, result)
            .unwrap_or_else(|err| panic!(err))
    }

    fn response_error_code_returned(error_code: EngineReturnCode) -> std::vec::Vec<u8> {
        colima::serialize_result(
            colima::ResponseStatus::FAILED_ERROR_CODE_RETURNED as i32,
            Some(i32::from(error_code).to_le_bytes().to_vec()),
        )
        .unwrap_or_else(|err| panic!(err))
    }

    fn is_modified(&self) -> bool {
        self.is_modified
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
