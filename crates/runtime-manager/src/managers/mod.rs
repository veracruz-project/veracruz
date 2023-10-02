//! Management module for the Veracruz execution engine.
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE.md` file in the Veracruz root directory for
//! information on licensing and copyright.

use anyhow::{anyhow, Result};
use execution_engine::{execute};
use lazy_static::lazy_static;
use log::info;
use policy_utils::{
    pipeline::Expr, policy::Policy, principal::{Principal, FilePermissions},
};
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    string::String,
    sync::{
        atomic::AtomicU32,
        Mutex,
    },
    vec::Vec,
    fs::{self, OpenOptions},
    io::Write,
};
use veracruz_utils::sha256::sha256;

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
}

////////////////////////////////////////////////////////////////////////////////
// Error and response codes and messages.
////////////////////////////////////////////////////////////////////////////////

/// `None` means that the incoming buffer is not full,
/// so we cannot parse a complete protobuf message.
/// We need to wait longer for this to arrive.
type ProvisioningResponse = Option<Vec<u8>>;

/// Result type of provisioning functions.
pub type ProvisioningResult = Result<ProvisioningResponse>;

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
    /// Digest table. Certain files must match the digest before writing to
    /// the filesystem.
    digest_table: HashMap<PathBuf, Vec<u8>>,
}

impl ProtocolState {
    /// Constructs a new `ProtocolState` from a global policy.  The selected
    /// execution strategy is extracted from the global policy and a suitable
    /// Veracruz execution strategy is selected based on that.
    pub fn new(global_policy: Policy, global_policy_hash: String) -> Result<Self> {
        let expected_shutdown_sources = global_policy.expected_shutdown_list();

        let mut rights_table = global_policy.get_rights_table();

        // Grant the super user read access to any file under the root. This is
        // used internally to read the program on behalf of the executing party
        let mut su_read_rights = HashMap::new();
        su_read_rights.insert(PathBuf::from("/"), FilePermissions{read: true, write: true, execute: true});
        rights_table.insert(Principal::InternalSuperUser, su_read_rights);

        let digest_table = global_policy.get_file_hash_table()?;
        let native_modules = global_policy.native_modules();

        Ok(ProtocolState {
            global_policy,
            global_policy_hash,
            expected_shutdown_sources,
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
    pub(crate) fn write_file<T: AsRef<Path>>(
        &mut self,
        client_id: &Principal,
        path: T,
        data: Vec<u8>,
    ) -> Result<()> {
        // Check the digest, if necessary
        let path = path.as_ref();
        info!("write_file to path {:?}", path);
        if let Some(digest) = self.digest_table.get(&PathBuf::from(path)) {
            let incoming_digest = sha256(&data);
            if incoming_digest.len() != digest.len() {
                return Err(anyhow!(RuntimeManagerError::FileSystemAccessDenialError));
            }
            for (lhs, rhs) in digest.iter().zip(incoming_digest.iter()) {
                if lhs != rhs {
                    return Err(anyhow!(RuntimeManagerError::FileSystemAccessDenialError));
                }
            }
        }
        
        //TODO permission check
        match path.parent() {
            None => return Err(anyhow!(RuntimeManagerError::FileSystemAccessDenialError)),
            Some(parent_path) => {
                if !parent_path.try_exists()? {
                    fs::create_dir_all(parent_path)?;
                }
            }
        }

        info!("write_file to path {:?} after create dir", path);
        fs::write(path, data)?;

        Ok(())
    }

    /// Check if a client has capability to write to a file, and then overwrite it with new `data`.
    pub(crate) fn append_file(
        &mut self,
        client_id: &Principal,
        file_name: &str,
        data: Vec<u8>,
    ) -> Result<()> {
        // If a file must match a digest, e.g. a program,
        // it is not permitted to append the file.
        if self.digest_table.contains_key(&PathBuf::from(file_name)) {
            return Err(anyhow!(RuntimeManagerError::FileSystemAccessDenialError));
        }

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(file_name)?;

        file.write_all(&data)?;

        Ok(())
    }

    /// Check if a client has capability to read from a file, if so, return the content in bytes.
    pub(crate) fn read_file(
        &self,
        client_id: &Principal,
        file_name: &str,
    ) -> Result<Option<Vec<u8>>> {
        let rst = fs::read(file_name)?;
        if rst.len() == 0 {
            return Ok(None);
        }
        Ok(Some(rst))
    }

    pub(crate) fn read_pipeline_script(&self, pipeline_id: usize) -> Result<Box<Expr>> {
        info!("try tp read pipeline_id {}.", pipeline_id);
        let expr = self
            .global_policy
            .get_pipeline(pipeline_id)?
            .get_parsed_pipeline()
            .map(|e| e.clone())?;
        info!("result {:?}", expr);
        Ok(expr)
    }

    /// Requests shutdown on behalf of a client, as identified by their client
    /// ID.
    /// TODO: Do something better (https://github.com/veracruz-project/veracruz/issues/393)
    pub(crate) fn request_and_check_shutdown(&mut self, client_id: u64) -> Result<bool> {
        Ok(self.expected_shutdown_sources.contains(&client_id))
    }

    /// Execute the program `file_name` on behalf of the client (participant)
    /// identified by `principal`.  The client must have the right to execute the
    /// program.
    pub(crate) fn execute(
        &mut self,
        caller_principal: &Principal,
        execution_principal: &Principal,
        environment_variables: Vec<(String, String)>,
        pipeline: Box<Expr>,
    ) -> ProvisioningResult {
        info!(
            "Execute program, caller: {:?} and execution: {:?}",
            caller_principal, execution_principal
        );
        let execution_strategy = self.global_policy.execution_strategy();
        let env = execution_engine::Environment {
            environment_variables,
            ..Default::default()
        };
        let permission_table = self.global_policy.get_rights_table();
        let permission = permission_table.get(execution_principal).ok_or(anyhow!("principal cannot be found"))?;

        let return_code = execute(
            &execution_strategy,
            &permission,
            pipeline,
            &env,
        )?;

        let response = Self::response_error_code_returned(return_code);
        Ok(Some(response))
    }

    /// Internal function converts error code to response message.
    #[inline]
    fn response_error_code_returned(error_code: u32) -> std::vec::Vec<u8> {
        transport_protocol::serialize_result(
            transport_protocol::ResponseStatus::SUCCESS as i32,
            Some(error_code.to_le_bytes().to_vec()),
        )
        .unwrap_or_else(|err| panic!("{:?}", err))
    }
}
