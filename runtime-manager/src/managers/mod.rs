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
#[cfg(feature = "sgx")]
use std::{ffi::CString, sync::SgxMutex as Mutex};
use std::{
    collections::HashMap,
    string::String,
    sync::{
        atomic::{AtomicBool, AtomicU32, Ordering},
        Arc,
    },
    vec::Vec,
};
use lazy_static::lazy_static;
use execution_engine::{fs::FileSystem, execute};
use veracruz_utils::policy::{
    policy::Policy,
    principal::Principal,
};
use wasi_types::ErrNo;

pub mod error;
pub mod execution_engine_manager;
pub mod session_manager;
pub use error::RuntimeManagerError;

////////////////////////////////////////////////////////////////////////////////
// Various bits of persistent state.
////////////////////////////////////////////////////////////////////////////////

lazy_static! {
    static ref MY_SESSION_MANAGER: Mutex<Option<::session_manager::SessionContext>> =
        Mutex::new(None);
    static ref SESSION_COUNTER: AtomicU32 = AtomicU32::new(1);
    static ref SESSIONS: Mutex<HashMap<u32, ::session_manager::Session>> =
        Mutex::new(HashMap::new());
    static ref PROTOCOL_STATE: Mutex<Option<ProtocolState>> = Mutex::new(None);
    static ref DEBUG_FLAG: AtomicBool = AtomicBool::new(false);
}

const OUTPUT_FILE: &'static str = "output";

////////////////////////////////////////////////////////////////////////////////
// Error and response codes and messages.
////////////////////////////////////////////////////////////////////////////////

/// `None` means that the incoming buffer is not full,
/// so we cannot parse a complete protobuf message.
/// We need to wait longer for this to arrive.
type ProvisioningResponse = Option<Vec<u8>>;

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
    is_modified: bool,
    /// The fixed, global policy parameterising the computation.  This should
    /// not change...
    global_policy: Policy,
    /// A hex-encoding of the raw JSON global policy.
    global_policy_hash: String,
    /// The list of clients (their IDs) that can request shutdown of the
    /// Veracruz platform.
    expected_shutdown_sources: Vec<u64>,
    /// The ref to the VFS.
    vfs: Arc<Mutex<FileSystem>>,
    /// Digest table. Certain files must match the digest before writting to the filesystem.
    digest_table: HashMap<String, Vec<u8>>,
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

        let rights_table = global_policy.get_rights_table();
        let digest_table = global_policy.get_digest_table()?;
        let vfs = Arc::new(Mutex::new(FileSystem::new(rights_table)));

        Ok(ProtocolState {
            global_policy,
            global_policy_hash,
            expected_shutdown_sources,
            vfs,
            digest_table,
            is_modified: true,
        })
    }

    /// Force re-execute the program even if there is no new data coming from participants.
    #[inline]
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

    /// Check if a client has capability to write to a file, and then overwrite it with new `data`.
    pub(crate) fn write_file(
        &mut self,
        client_id: &Principal,
        file_name: &str,
        data: &[u8],
    ) -> Result<(), RuntimeManagerError> {

        // Check the digest, if necessary
        if let Some(digest) = self.digest_table.get(file_name) {
            let incoming_digest = Self::sha_256_digest(data);
            if incoming_digest.len() != digest.len() {
                return Err(RuntimeManagerError::FileSystemError(ErrNo::Access));
            }
            for (lhs, rhs) in digest.iter().zip(incoming_digest.iter()) {
                if lhs != rhs {
                    return Err(RuntimeManagerError::FileSystemError(ErrNo::Access));
                }
            }
        }
        // Set the modified flag 
        self.is_modified = true;
        self.vfs.lock()?.write_file_by_filename(
            client_id,
            file_name,
            data,
            false,
        )?;
        Ok(())
    }

    /// Compute the digest of a `buffer`
    #[inline]
    fn sha_256_digest(buffer: &[u8]) -> Vec<u8> {
        ring::digest::digest(&ring::digest::SHA256, buffer)
            .as_ref()
            .to_vec()
    }

    /// Check if a client has capability to write to a file, and then overwrite it with new `data`.
    pub(crate) fn append_file(
        &mut self,
        client_id: &Principal,
        file_name: &str,
        data: &[u8],
    ) -> Result<(), RuntimeManagerError> {
        // If a file must match a digest, e.g. a program, 
        // it is not permitted to append the file.
        if self.digest_table.contains_key(file_name) {
            return Err(RuntimeManagerError::FileSystemError(ErrNo::Access));
        }
        self.is_modified = true;
        self.vfs.lock()?.write_file_by_filename(
            client_id,
            file_name,
            data,
            // set the append flag to true
            true,
        )?;
        Ok(())
    }

    /// Check if a client has capability to read from a file, if so, return the content in bytes.
    pub(crate) fn read_file(
        &self,
        client_id: &Principal,
        file_name: &str,
    ) -> Result<Option<Vec<u8>>, RuntimeManagerError> {
        let rst = self.vfs.lock()?.read_file_by_filename(
            client_id,
            file_name,
        )?;
        if rst.len() == 0 {
            return Ok(None);
        }
        Ok(Some(rst))
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

    /// Execute the program `file_name` on behalf of the client (participant) identified by `client_id`.
    pub(crate) fn execute(&mut self, file_name: &str, client_id: u64) -> ProvisioningResult {
        let execution_strategy = self.global_policy.execution_strategy();
        let return_code = execute(&execution_strategy, self.vfs.clone(), file_name)?;

        let response = if return_code == ErrNo::Success {
            let result = self.read_file(&Principal::Participant(client_id), OUTPUT_FILE)?;
            Self::response_success(result)
        } else {
            Self::response_error_code_returned(return_code)
        };

        self.is_modified = false;
        Ok(Some(response))
    }

    #[inline]
    fn response_success(result: Option<Vec<u8>>) -> Vec<u8> {
        transport_protocol::serialize_result(
            transport_protocol::ResponseStatus::SUCCESS as i32,
            result,
        )
        .unwrap_or_else(|err| panic!(err))
    }

    #[inline]
    fn response_error_code_returned(error_code: ErrNo) -> std::vec::Vec<u8> {
        transport_protocol::serialize_result(
            transport_protocol::ResponseStatus::FAILED_ERROR_CODE_RETURNED as i32,
            Some(i32::from(error_code as u16).to_le_bytes().to_vec()),
        )
        .unwrap_or_else(|err| panic!(err))
    }

    #[inline]
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
