//! The Veracruz global policy.
//!
//! The global policy captures important information about a Veracruz
//! computation that principals need to audit before they enroll themselves in a
//! computation.  This includes:
//!
//! - The identities and roles of every principals in the computation,
//! - Important URLs, both for the Veracruz bridge server on the untrusted
//!   host's machine and the Veracruz proxy attestation service,
//! - Permissible ciphersuites for TLS connections between clients and the
//!   trusted Veracruz runtime, as well as the hashes of the expected program
//!   and of the trusted Veracruz runtime itself,
//! - The expiry date (moment in time) of the self-signed certificate issued by
//!   the enclave during a pre-computation bootstrapping process,
//! - The execution strategy that will be used by the trusted Veracruz runtime
//!   to execute the WASM binary, as well as a debug configuration flag which
//!   allows the WASM binary to write data to `stdout` on the untrusted host's
//!   machine,
//! - The rights table of the standard streams (`stdin`, `stdout`, `stderr`),
//! - A clock flag which allows the the WASM binary to call clock functions to
//!   e.g. get a clock's time or resolution,
//! - The order in which data inputs provisioned into the enclave will be placed
//!   which is important for the program provider to understand in order to
//!   write software for Veracruz.
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE.md` file in the Veracruz root directory for
//! information on licensing and copyright.

#![allow(clippy::too_many_arguments)]

use super::{
    error::PolicyError,
    expiry::Timepoint,
    principal::{PrincipalPermission, ExecutionStrategy, FileHash, Identity, Service, Pipeline, Principal, Program},
    Platform,
};
use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    path::PathBuf,
    string::{String, ToString},
    vec::Vec,
};
use veracruz_utils::sha256::sha256;
use log::info;

////////////////////////////////////////////////////////////////////////////////
// Veracruz policies, proper.
////////////////////////////////////////////////////////////////////////////////

/// A type representing the data stored in a Veracruz global policy.  This file
/// is public information available to every principal in a Veracruz computation
/// and contains data that every principal needs to audit and understand before
/// they enroll in a computation, so that they are capable of assessing whether
/// a computation is "safe" or not for them to join.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Policy {
    /// The identities of every principal involved in a computation.
    identities: Vec<Identity<String>>,
    /// The candidate programs that can be loaded in the execution engine.
    programs: Vec<Program>,
    /// The candidate native modules that can be loaded.
    native_modules: Vec<Service>,
    /// The list of files, e.g. binaries and configurations, that must match given hashes.
    file_hashes: Vec<FileHash>,
    /// The list of pipelines.
    pipelines: Vec<Pipeline>,
    /// The URL of the Veracruz server.
    veracruz_server_url: String,
    /// The expiry of the enclave's self-signed certificate, which will be
    /// issued during the Veracruz bootstrapping process prior to the
    /// computation.
    enclave_cert_expiry: Timepoint,
    /// The ciphersuite that will be used with the TLS connections between the
    /// principals of the computation and the enclave.
    ciphersuite: String,
    /// The hash of the Veracruz trusted runtime for Linux applications.
    runtime_manager_hash_linux: Option<String>,
    /// The hash of the Veracruz trusted runtime for AWS Nitro Enclaves.
    runtime_manager_hash_nitro: Option<String>,
    /// The hash of the Veracruz trusted runtime for AMD SEV SNP.
    runtime_manager_hash_sevsnp: Option<String>,
    /// The URL of the proxy attestation service.
    proxy_attestation_server_url: String,
    /// The PEM encoded certificate for the proxy service that matches the chosen
    /// platform constraints for the policy
    proxy_service_cert: String,
    /// The execution strategy that will be used to execute the WASM binary.
    execution_strategy: ExecutionStrategy,
    /// The maximum amount of memory in MiB available to the isolate. Only
    /// enforced in Nitro for now.
    max_memory_mib: u32,
    /// Hash of the JSON representation if the policy was parsed from a file.
    /// This field is not present in the text JSON file.
    #[serde(skip)]
    policy_hash: Option<String>,
}

impl Policy {
    /// Constructs a new Veracruz policy type, validating the well-formedness of
    /// the resulting policy in the process.  Returns `Ok(policy)` iff these
    /// well-formedness checks pass.
    pub fn new(
        identities: Vec<Identity<String>>,
        programs: Vec<Program>,
        native_modules: Vec<Service>,
        mut pipelines: Vec<Pipeline>,
        veracruz_server_url: String,
        enclave_cert_expiry: Timepoint,
        ciphersuite: String,
        runtime_manager_hash_linux: Option<String>,
        runtime_manager_hash_nitro: Option<String>,
        runtime_manager_hash_sevsnp: Option<String>,
        proxy_attestation_server_url: String,
        proxy_service_cert: String,
        execution_strategy: ExecutionStrategy,
        file_hashes: Vec<FileHash>,
        max_memory_mib: u32,
    ) -> Result<Self> {
        for p in pipelines.iter_mut() {
            p.parse()?;
        }

        let policy = Self {
            identities,
            proxy_service_cert,
            programs,
            native_modules,
            pipelines,
            veracruz_server_url,
            enclave_cert_expiry,
            ciphersuite,
            runtime_manager_hash_linux,
            runtime_manager_hash_nitro,
            runtime_manager_hash_sevsnp,
            proxy_attestation_server_url,
            execution_strategy,
            max_memory_mib,
            policy_hash: None,
            file_hashes,
        };

        policy.assert_valid()?;

        Ok(policy)
    }

    /// Parses a Veracruz policy type from a JSON-encoded string, `json`,
    /// validating the well-formedness of the resulting policy in the process.
    /// Returns `Ok(policy)` iff these well-formedness checks pass.
    pub fn from_json(json: &str) -> Result<Self> {
        // parse json
        info!("from_json:{:?}", json);
        let mut policy: Self = serde_json::from_str(json)?;

        for p in policy.pipelines.iter_mut() {
            p.parse()?;
        }

        policy.assert_valid()?;

        // include hash?
        let hash = hex::encode(sha256(json.as_bytes()));
        policy.policy_hash = Some(hash);

        Ok(policy)
    }

    /// Returns the identities associated with this policy.
    #[inline]
    pub fn identities(&self) -> &[Identity<String>] {
        &self.identities
    }

    /// Returns the native modules associated with this policy.
    #[inline]
    pub fn services(&self) -> &[Service] {
        &self.native_modules
    }

    /// Returns the URL of the Veracruz server associated with this policy.
    #[inline]
    pub fn veracruz_server_url(&self) -> &str {
        &self.veracruz_server_url
    }

    /// Returns the proxy service certificate associated with this policy
    pub fn proxy_service_cert(&self) -> &str {
        &self.proxy_service_cert
    }
    /// Returns the enclave certificate expiry moment associated with this
    /// policy.
    #[inline]
    pub fn enclave_cert_expiry(&self) -> &Timepoint {
        &self.enclave_cert_expiry
    }

    /// Returns the permissible ciphersuites for TLS links associated with this
    /// policy.
    #[inline]
    pub fn ciphersuite(&self) -> &str {
        &self.ciphersuite
    }

    /// Returns the hash of the trusted Veracruz runtime, associated with this
    /// policy.
    #[inline]
    pub fn runtime_manager_hash(&self, platform: &Platform) -> Result<&str> {
        let hash = match platform {
            Platform::Linux => self
                .runtime_manager_hash_linux
                .as_ref()
                .ok_or(anyhow!(PolicyError::InvalidPlatform))?,
            Platform::Nitro => self
                .runtime_manager_hash_nitro
                .as_ref()
                .ok_or(anyhow!(PolicyError::InvalidPlatform))?,
            Platform::SEVSNP => self
                .runtime_manager_hash_sevsnp
                .as_ref()
                .ok_or(anyhow!(PolicyError::InvalidPlatform))?,
            Platform::Mock => self
                .runtime_manager_hash_nitro
                .as_ref()
                .ok_or(anyhow!(PolicyError::InvalidPlatform))?,
        };
        Ok(&hash)
    }

    /// Returns the URL of the proxy attestation service, associated with this
    /// policy.
    #[inline]
    pub fn proxy_attestation_server_url(&self) -> &str {
        &self.proxy_attestation_server_url
    }

    /// Returns the execution strategy associated with this policy.
    #[inline]
    pub fn execution_strategy(&self) -> &ExecutionStrategy {
        &self.execution_strategy
    }

    /// Returns the maximum amount of memory available to the isolate associated
    /// with this policy.
    #[inline]
    pub fn max_memory_mib(&self) -> &u32 {
        &self.max_memory_mib
    }

    /// Returns the hash of the source JSON representation, if available
    #[inline]
    pub fn policy_hash(&self) -> Option<&str> {
        self.policy_hash.as_deref()
    }

    /// Checks that the policy is valid, returning `Err(reason)` iff the policy
    /// is found to be invalid.  In all other cases, `Ok(())` is returned.
    fn assert_valid(&self) -> Result<()> {
        let mut client_ids = Vec::new();

        for identity in self.identities.iter() {
            identity.assert_valid()?;

            // check IDs of all the participants
            if client_ids.contains(&identity.id()) {
                return Err(anyhow!(PolicyError::FormatError));
            }
            client_ids.push(identity.id());
        }

        // Check the ciphersuite
        veracruz_utils::lookup_ciphersuite(self.ciphersuite()).ok_or(
            PolicyError::TLSInvalidCiphersuiteError(self.ciphersuite().to_string()),
        )?;

        // NB: no check of enclave certificate validity as there is no reliable
        // way of obtaining a time from within an enclave.  This is the
        // responsibility of the clients of Veracruz.

        Ok(())
    }

    /// Returns the identity of any principal in the computation who is capable
    /// of requesting a shutdown of the computation.  At the moment, only the
    /// principals who can request the result can also request shutdown.
    pub fn expected_shutdown_list(&self) -> Vec<u64> {
        self.identities
            .iter()
            .map(|identity| identity.id_u64())
            .collect()
    }

    /// Returns `Ok(identity)` if a principal with a certificate matching the
    /// X509 certificate, `cert`, is present within the list of
    /// identities/principals associated with this policy.  Otherwise, returns
    /// an error.
    pub fn check_client_id(&self, cert: &str) -> Result<u64> {
        for identity in self.identities.iter() {
            if identity.certificate().as_str() == cert {
                return Ok(identity.id_u64());
            }
        }
        Err(anyhow!(PolicyError::InvalidClientCertificateError(
            cert.to_string()
        )))
    }

    pub fn get_permission(&self, principal: &Principal) -> Result<PrincipalPermission> {
        match principal {
            Principal::InternalSuperUser | Principal::NoCap => return Err(anyhow!("SuperUser or NoCap")),
            Principal::Participant(id) => {
                if let Some(principal) = self.identities.iter().find(|x| *id == x.id_u64()) {
                    return Ok(principal.file_rights_map())
                }
            },
            Principal::Program(path) => {
                if let Some(principal) = self.programs.iter().find(|x| path == x.program_file_name()) {
                    return Ok(principal.file_rights_map())
                }
            },
            Principal::Pipeline(name) | Principal::NativeModule(name)  => {
                if let Some(principal) = self.pipelines.iter().find(|x| name == x.name()) {
                    return Ok(principal.file_rights_map())
                }
            },
        }
        Err(anyhow!("Cannot find {:?}", principal))
    }

    /// Return the file hash table, mapping filenames to their expected hashes.
    pub fn get_file_hash_table(&self) -> Result<HashMap<PathBuf, Vec<u8>>> {
        let mut table = HashMap::new();

        for file_hash in self.file_hashes.iter() {
            table.insert(
                PathBuf::from(file_hash.file_path()),
                hex::decode(file_hash.hash())?,
            );
        }
        Ok(table)
    }

    /// Return the pipeline of `pipeline_id`
    pub fn get_pipeline(&self, pipeline_id: usize) -> Result<&Pipeline> {
        self.pipelines
            .get(pipeline_id)
            .ok_or(anyhow!("Failed to find pipeline {}", pipeline_id))
    }
}
