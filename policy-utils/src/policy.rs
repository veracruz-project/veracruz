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
//! See the `LICENSE_MIT.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

#![allow(clippy::too_many_arguments)]

use super::Platform;
use super::{
    error::PolicyError,
    expiry::Timepoint,
    principal::{ExecutionStrategy, FileHash, Identity, Principal, Program, RightsTable},
};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    path::PathBuf,
    string::{String, ToString},
    vec::Vec,
};
use wasi_types::Rights;

////////////////////////////////////////////////////////////////////////////////
// Veracruz policies, proper.
////////////////////////////////////////////////////////////////////////////////

/// A type representing the data stored in a Veracruz global policy.  This file
/// is public information available to every principal in a Veracruz computation
/// and contains data that every principal needs to audit and understand before
/// they enroll in a computation, so that they are capable of assessing whether
/// a computation is "safe" or not for them to join.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Policy {
    /// The identities of every principal involved in a computation.
    identities: Vec<Identity<String>>,
    /// The candidate programs that can be loaded in the execution engine.
    programs: Vec<Program>,
    /// The list of files, e.g. binaries and configurations, that must match given hashes.
    file_hashes: Vec<FileHash>,
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
    /// The hash of the Veracruz trusted runtime for IceCap.
    runtime_manager_hash_icecap: Option<String>,
    /// The URL of the proxy attestation service.
    proxy_attestation_server_url: String,
    /// The PEM encoded certificate for the proxy service that matches the chosen
    /// platform constraints for the policy
    proxy_service_cert: String,
    /// The debug configuration flag.  This dictates whether the WASM program
    /// will be able to print debug configuration messages to `stdout` on the
    /// host's machine.
    debug: bool,
    /// The execution strategy that will be used to execute the WASM binary.
    execution_strategy: ExecutionStrategy,
    /// The clock flag.  This dictates whether the WASM program will be able to
    /// call clock functions to e.g. get a clock's time or resolution.
    enable_clock: bool,

    /// Hash of the JSON representation if the Policy was parsed from a file.
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
        veracruz_server_url: String,
        enclave_cert_expiry: Timepoint,
        ciphersuite: String,
        runtime_manager_hash_linux: Option<String>,
        runtime_manager_hash_nitro: Option<String>,
        runtime_manager_hash_icecap: Option<String>,
        proxy_attestation_server_url: String,
        proxy_service_cert: String,
        debug: bool,
        execution_strategy: ExecutionStrategy,
        file_hashes: Vec<FileHash>,
        enable_clock: bool,
    ) -> Result<Self, PolicyError> {
        let policy = Self {
            identities,
            proxy_service_cert,
            programs,
            veracruz_server_url,
            enclave_cert_expiry,
            ciphersuite,
            runtime_manager_hash_linux,
            runtime_manager_hash_nitro,
            runtime_manager_hash_icecap,
            proxy_attestation_server_url,
            debug,
            execution_strategy,
            enable_clock,
            policy_hash: None,
            file_hashes,
        };

        policy.assert_valid()?;

        Ok(policy)
    }

    /// Parses a Veracruz policy type from a JSON-encoded string, `json`,
    /// validating the well-formedness of the resulting policy in the process.
    /// Returns `Ok(policy)` iff these well-formedness checks pass.
    pub fn from_json(json: &str) -> Result<Self, PolicyError> {
        // parse json
        let mut policy: Self = serde_json::from_str(json)?;
        policy.assert_valid()?;

        // include hash?
        let hash = hex::encode(ring::digest::digest(&ring::digest::SHA256, json.as_bytes()));
        policy.policy_hash = Some(hash);

        Ok(policy)
    }

    /// Returns the identities associated with this policy.
    #[inline]
    pub fn identities(&self) -> &Vec<Identity<String>> {
        &self.identities
    }

    /// Returns the URL of the Veracruz server associated with this policy.
    #[inline]
    pub fn veracruz_server_url(&self) -> &String {
        &self.veracruz_server_url
    }

    /// Returns the proxy service certificate associated with this policy
    pub fn proxy_service_cert(&self) -> &String {
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
    pub fn ciphersuite(&self) -> &String {
        &self.ciphersuite
    }

    /// Returns the hash of the trusted Veracruz runtime, associated with this
    /// policy.
    #[inline]
    pub fn runtime_manager_hash(&self, platform: &Platform) -> Result<&String, PolicyError> {
        let hash = match platform {
            Platform::Linux => match &self.runtime_manager_hash_linux {
                Some(hash) => hash,
                None => {
                    return Err(PolicyError::MissingPolicyFieldError(
                        "runtime_manager_hash_linux".to_string(),
                    ))
                }
            },
            Platform::Nitro => match &self.runtime_manager_hash_nitro {
                Some(hash) => hash,
                None => {
                    return Err(PolicyError::MissingPolicyFieldError(
                        "runtime_manager_hash_nitro".to_string(),
                    ))
                }
            },
            Platform::IceCap => match &self.runtime_manager_hash_icecap {
                Some(hash) => hash,
                None => {
                    return Err(PolicyError::MissingPolicyFieldError(
                        "runtime_manager_hash_icecap".to_string(),
                    ))
                }
            },
            Platform::Mock => match &self.runtime_manager_hash_nitro {
                Some(hash) => hash,
                None => {
                    return Err(PolicyError::MissingPolicyFieldError(
                        "runtime_manager_hash_nitro".to_string(),
                    ))
                }
            },
        };
        Ok(&hash)
    }

    /// Returns the URL of the proxy attestation service, associated with this
    /// policy.
    #[inline]
    pub fn proxy_attestation_server_url(&self) -> &String {
        &self.proxy_attestation_server_url
    }

    /// Returns the debug configuration flag associated with this policy.
    #[inline]
    pub fn debug(&self) -> &bool {
        &self.debug
    }

    /// Returns the execution strategy associated with this policy.
    #[inline]
    pub fn execution_strategy(&self) -> &ExecutionStrategy {
        &self.execution_strategy
    }

    /// Returns the clock flag associated with this policy.
    #[inline]
    pub fn enable_clock(&self) -> &bool {
        &self.enable_clock
    }

    /// Returns the hash of the source JSON representation, if available
    #[inline]
    pub fn policy_hash(&self) -> Option<&str> {
        self.policy_hash.as_deref()
    }

    /// Checks that the policy is valid, returning `Err(reason)` iff the policy
    /// is found to be invalid.  In all other cases, `Ok(())` is returned.
    fn assert_valid(&self) -> Result<(), PolicyError> {
        let mut client_ids = Vec::new();

        for identity in self.identities.iter() {
            identity.assert_valid()?;

            // check IDs of all the participants
            if client_ids.contains(identity.id()) {
                return Err(PolicyError::DuplicatedClientIDError(*identity.id() as u64));
            }
            client_ids.push(*identity.id());
        }

        // Check the ciphersuite
        #[cfg(features = "std")]
        {
            let policy_ciphersuite = rustls::CipherSuite::lookup_value(self.ciphersuite())
                .map_err(|_| {
                    PolicyError::TLSInvalidCyphersuiteError(self.get_ciphersuite().to_string())
                })?;
            if !rustls::ALL_CIPHERSUITES
                .iter()
                .fold(false, |acc, sup| acc || (sup.suite == policy_ciphersuite))
            {
                return Err(PolicyError::TLSUnsupportedCyphersuiteError(
                    policy_ciphersuite,
                ));
            }
        }

        // NB: no check of enclave certificate validity as there is no reliable
        // way of obtaining a time from within an enclave.  This is the
        // responsibility of the clients of Veracruz.

        Ok(())
    }

    /// Returns the identity of any principal in the computation who is capable
    /// of requesting a shutdown of the computation.  At the moment, only the
    /// principals who can request the result can also request shutdown.
    pub fn expected_shutdown_list(&self) -> Vec<u64> {
        self.identities()
            .iter()
            .fold(Vec::new(), |mut acc, identity| {
                acc.push(*identity.id() as u64);
                acc
            })
    }

    /// Returns `Ok(identity)` if a principal with a certificate matching the
    /// X509 certificate, `cert`, is present within the list of
    /// identities/principals associated with this policy.  Otherwise, returns
    /// an error.
    pub fn check_client_id(&self, cert: &str) -> Result<u64, PolicyError> {
        for identity in self.identities().iter() {
            if identity.certificate().as_str() == cert {
                return Ok(*identity.id() as u64);
            }
        }
        Err(PolicyError::InvalidClientCertificateError(cert.to_string()))
    }

    /// Return the CapabilityTable in this policy. It contains capabilities related to all
    /// participants and programs.
    pub fn get_rights_table(&self) -> RightsTable {
        let mut table = HashMap::new();
        for identity in self.identities() {
            let id = Principal::Participant(*identity.id() as u64);
            let right_map = identity.file_rights_map();
            table.insert(id, right_map);
        }
        for program in &self.programs {
            let program_file_name = program.program_file_name();
            let id = Principal::Program(program_file_name.to_string());
            let right_map = program.file_rights_map();
            table.insert(id, right_map);
        }
        table
    }

    /// Return the file hash table, mapping filenames to their expected hashes.
    pub fn get_file_hash_table(&self) -> Result<HashMap<PathBuf, Vec<u8>>, PolicyError> {
        let mut table = HashMap::new();

        for file_hash in self.file_hashes.iter() {
            table.insert(
                PathBuf::from(file_hash.file_path()),
                hex::decode(file_hash.hash())?,
            );
        }
        Ok(table)
    }

    /// Return the program input table, mapping program filenames to their expected input filenames.
    pub fn get_input_table(&self) -> Result<HashMap<String, Vec<PathBuf>>, PolicyError> {
        let mut table = HashMap::new();
        for program in &self.programs {
            let program_file_name = program.program_file_name();
            let file_rights_map = program.file_rights_map();
            table.insert(
                program_file_name.to_string(),
                Self::get_required_inputs(&file_rights_map),
            );
        }
        Ok(table)
    }

    /// Extract the input filenames from a right_map. If a prorgam has rights call
    /// fd_read and path_open, it is considered as an input file.
    fn get_required_inputs(right_map: &HashMap<PathBuf, Rights>) -> Vec<PathBuf> {
        let mut rst = right_map
            .iter()
            .fold(Vec::new(), |mut acc, (file_name, right)| {
                if right.contains(Rights::FD_READ | Rights::PATH_OPEN) {
                    acc.push(file_name.into());
                }
                acc
            });
        rst.sort();
        rst
    }
}
