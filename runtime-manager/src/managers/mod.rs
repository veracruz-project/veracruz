//! Management module for the Veracruz execution engine.
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE_MIT.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

use policy_utils::{policy::Policy, principal::Principal, CANONICAL_STDIN_FILE_PATH};

use execution_engine::{execute, fs::FileSystem};
use lazy_static::lazy_static;
use std::{
    collections::HashMap,
    path::PathBuf,
    string::{String, ToString},
    sync::{
        atomic::{AtomicBool, AtomicU32, Ordering},
        Mutex,
    },
    vec::Vec,
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
    /// The fixed, global policy parameterising the computation.  This should
    /// not change...
    global_policy: Policy,
    /// A hex-encoding of the raw JSON global policy.
    global_policy_hash: String,
    /// The list of clients (their IDs) that can request shutdown of the
    /// Veracruz platform.
    expected_shutdown_sources: Vec<u64>,
    /// The ref to the VFS, this is a FS handler with super user capability.
    vfs: FileSystem,
    /// Digest table. Certain files must match the digest before writting to the filesystem.
    digest_table: HashMap<PathBuf, Vec<u8>>,
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
        let digest_table = global_policy.get_file_hash_table()?;
        let vfs = FileSystem::new(rights_table)?;

        Ok(ProtocolState {
            global_policy,
            global_policy_hash,
            expected_shutdown_sources,
            vfs,
            digest_table,
        })
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
        data: Vec<u8>,
    ) -> Result<(), RuntimeManagerError> {
        // Check the digest, if necessary
        if let Some(digest) = self.digest_table.get(&PathBuf::from(file_name)) {
            let incoming_digest = Self::sha_256_digest(&data);
            if incoming_digest.len() != digest.len() {
                return Err(RuntimeManagerError::FileSystemError(ErrNo::Access));
            }
            for (lhs, rhs) in digest.iter().zip(incoming_digest.iter()) {
                if lhs != rhs {
                    return Err(RuntimeManagerError::FileSystemError(ErrNo::Access));
                }
            }
        }

        if file_name == CANONICAL_STDIN_FILE_PATH {
            self.vfs.spawn(client_id)?.write_stdin(&data)?;
        } else {
            self.vfs
                .spawn(client_id)?
                .write_file_by_absolute_path(file_name, data, false)?;
        }

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
        data: Vec<u8>,
    ) -> Result<(), RuntimeManagerError> {
        // If a file must match a digest, e.g. a program,
        // it is not permitted to append the file.
        if self.digest_table.contains_key(&PathBuf::from(file_name)) {
            return Err(RuntimeManagerError::FileSystemError(ErrNo::Access));
        }
        self.vfs.spawn(client_id)?.write_file_by_absolute_path(
            file_name, data, // set the append flag to true
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
        let mut vfs = self.vfs.spawn(client_id)?;
        let rst = match file_name {
            "stderr" => vfs.read_stderr()?,
            "stdout" => vfs.read_stdout()?,
            _otherwise => vfs.read_file_by_absolute_path(file_name)?,
        };
        if rst.len() == 0 {
            return Ok(None);
        }
        Ok(Some(rst))
    }

    /// Requests shutdown on behalf of a client, as identified by their client
    /// ID.
    /// TODO: Do something better (https://github.com/veracruz-project/veracruz/issues/393)
    pub(crate) fn request_and_check_shutdown(
        &mut self,
        client_id: u64,
    ) -> Result<bool, RuntimeManagerError> {
        Ok(self.expected_shutdown_sources.contains(&client_id))
    }

    /// Execute the program `file_name` on behalf of the client (participant) identified by `client_id`.
    /// The client must have the right to read the program.
    pub(crate) fn execute(&mut self, client_id: &Principal, file_name: &str) -> ProvisioningResult {
        let execution_strategy = self.global_policy.execution_strategy();
        let options = execution_engine::Options {
            enable_clock: *self.global_policy.enable_clock(),
            ..Default::default()
        };
        let program = self
            .read_file(client_id, file_name)?
            .ok_or(RuntimeManagerError::FileSystemError(ErrNo::NoEnt))?;
        let return_code = execute(
            &execution_strategy,
            self.vfs.spawn(&Principal::Program(file_name.to_string()))?,
            program,
            options,
        )?;

        let response = Self::response_error_code_returned(return_code);
        Ok(Some(response))
    }

    #[inline]
    fn response_error_code_returned(error_code: u32) -> std::vec::Vec<u8> {
        transport_protocol::serialize_result(
            transport_protocol::ResponseStatus::SUCCESS as i32,
            Some(error_code.to_le_bytes().to_vec()),
        )
        .unwrap_or_else(|err| panic!("{:?}", err))
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
fn print_message(#[allow(unused)] message: String, #[allow(unused)] code: u32) {
    #[cfg(feature = "linux")]
    if code == 0 {
        eprintln!("Enclave debug message \"{}\"", message);
    } else {
        eprintln!(
            "Enclave returns error code {} and message \"{}\"",
            code, message
        );
    }
}
