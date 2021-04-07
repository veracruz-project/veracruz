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
//! See the `LICENSE.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

use crate::{
    platform::Platform,
    policy::{
        error::PolicyError,
        expiry::Timepoint,
        principal::{ExecutionStrategy, Identity, Role}
    }
};
use serde::{Deserialize, Serialize};
use serde_json;
use std::{
    string::{String, ToString},
    vec::Vec,
};

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
    /// The URL of the Veracruz server.
    veracruz_server_url: String,
    /// The expiry of the enclave's self-signed certificate, which will be
    /// issued during the Veracruz bootstrapping process prior to the
    /// computation.
    enclave_cert_expiry: Timepoint,
    /// The ciphersuite that will be used with the TLS connections between the
    /// principals of the computation and the enclave.
    ciphersuite: String,
    /// The hash of the Veracruz trusted runtime for SGX enclaves.
    runtime_manager_hash_sgx: Option<String>,
    /// The hash of the Veracruz trusted runtime for TrustZone TAs.
    runtime_manager_hash_tz: Option<String>,
    /// The hash of the Veracruz trusted runtime for AWS Nitro Enclaves.
    runtime_manager_hash_nitro: Option<String>,
    /// The declared ordering of data inputs, provided by the various data
    /// providers, as specified in the policy.  Note that data providers can
    /// provision their inputs asynchronously, and in an arbitrary order.  Once
    /// all are provisioned, however, we reorder these inputs into this fixed
    /// declared order so that the Veracruz host ABI, which allows access to
    /// inputs via an index, remains well-defined.
    data_provision_order: Vec<u64>,
    /// The URL of the proxy attestation service.
    proxy_attestation_server_url: String,
    /// The hash of the program which will be provisioned into Veracruz by the
    /// program provider.
    pi_hash: String,
    /// The debug configuration flag.  This dictates whether the WASM program
    /// will be able to print debug configuration messages to *stdout* on the
    /// host's machine.
    debug: bool,
    /// The execution strategy that will be used to execute the WASM binary.
    execution_strategy: ExecutionStrategy,
    /// The declared ordering of stream package data inputs, provided by the various data
    /// providers, as specified in the policy.  Note that data providers can
    /// provision their inputs asynchronously, and in an arbitrary order.  Once
    /// all are provisioned, however, we reorder these inputs into this fixed
    /// declared order so that the Veracruz host ABI, which allows access to
    /// inputs via an index, remains well-defined.
    streaming_order: Vec<u64>,
}

impl Policy {
    /// Constructs a new Veracruz policy type, validating the well-formedness of
    /// the resulting policy in the process.  Returns `Ok(policy)` iff these
    /// well-formedness checks pass.
    pub fn new(
        identities: Vec<Identity<String>>,
        veracruz_server_url: String,
        enclave_cert_expiry: Timepoint,
        ciphersuite: String,
        runtime_manager_hash_sgx: Option<String>,
        runtime_manager_hash_tz: Option<String>,
        runtime_manager_hash_nitro: Option<String>,
        data_provision_order: Vec<u64>,
        streaming_order: Vec<u64>,
        proxy_attestation_server_url: String,
        pi_hash: String,
        debug: bool,
        execution_strategy: ExecutionStrategy,
    ) -> Result<Self, PolicyError> {
        let policy = Self {
            identities,
            veracruz_server_url,
            enclave_cert_expiry,
            ciphersuite,
            runtime_manager_hash_sgx,
            runtime_manager_hash_tz,
            runtime_manager_hash_nitro,
            data_provision_order,
            proxy_attestation_server_url,
            pi_hash,
            debug,
            execution_strategy,
            streaming_order,
        };

        policy.assert_valid()?;

        Ok(policy)
    }

    /// Parses a Veracruz policy type from a JSON-encoded string, `json`,
    /// validating the well-formedness of the resulting policy in the process.
    /// Returns `Ok(policy)` iff these well-formedness checks pass.
    pub fn from_json(json: &str) -> Result<Self, PolicyError> {
        let policy: Self = serde_json::from_str(json)?;
        policy.assert_valid()?;
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
            Platform::SGX => match &self.runtime_manager_hash_sgx {
                Some(hash) => hash,
                None => {
                    return Err(PolicyError::MissingPolicyFieldError(
                        "runtime_manager_hash_sgx".to_string(),
                    ))
                }
            },
            Platform::TrustZone => match &self.runtime_manager_hash_tz {
                Some(hash) => hash,
                None => {
                    return Err(PolicyError::MissingPolicyFieldError(
                        "runtime_manager_hash_tz".to_string(),
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
            Platform::Mock => match &self.runtime_manager_hash_sgx {
                Some(hash) => hash,
                None => {
                    return Err(PolicyError::MissingPolicyFieldError(
                        "runtime_manager_hash_sgx".to_string(),
                    ))
                }
            },
        };
        return Ok(&hash);
    }

    /// Returns the fixed data provisioning order, associated with this policy.
    #[inline]
    pub fn data_provision_order(&self) -> &Vec<u64> {
        &self.data_provision_order
    }

    /// Returns the fixed stream provisioning order, associated with this policy.
    #[inline]
    pub fn stream_provision_order(&self) -> &Vec<u64> {
        &self.streaming_order
    }

    /// Returns the URL of the proxy attestation service, associated with this
    /// policy.
    #[inline]
    pub fn proxy_attestation_server_url(&self) -> &String {
        &self.proxy_attestation_server_url
    }

    /// Returns the hash of the WASM binary, associated with this policy.
    #[inline]
    pub fn pi_hash(&self) -> &String {
        &self.pi_hash
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

    /// Checks that the policy is valid, returning `Err(reason)` iff the policy
    /// is found to be invalid.  In all other cases, `Ok(())` is returned.
    fn assert_valid(&self) -> Result<(), PolicyError> {
        let mut client_ids = Vec::new();
        let mut has_pi_provider = false;
        let mut has_result_reader = false;

        for identity in self.identities.iter() {
            identity.assert_valid()?;

            // check IDs of all the participants
            if client_ids.contains(identity.id()) {
                return Err(PolicyError::DuplicatedClientIDError(
                    *identity.id() as u64
                ));
            }
            client_ids.push(*identity.id());

            // check there is at least one role per client, and there is at least one PiProvider
            // and ResultReader
            if identity.roles().is_empty() {
                return Err(PolicyError::EmptyRoleError(*identity.id() as u64));
            }

            has_result_reader =
                has_result_reader || identity.roles().contains(&Role::ResultReader);

            let new_pi_flag = identity.has_role(&Role::ProgramProvider);

            if has_pi_provider && new_pi_flag {
                return Err(PolicyError::NoProgramProviderError);
            } else {
                has_pi_provider = has_pi_provider || new_pi_flag;
            }
        }

        // check if the data_provision_order contains the valid IDs.
        if !self
            .data_provision_order()
            .iter()
            .fold(true, |last_rst, i| {
                last_rst && client_ids.contains(&(*i as u32))
            })
        {
            return Err(PolicyError::DataProviderError);
        }

        if !has_result_reader {
            return Err(PolicyError::NoResultRetrieverError);
        }

        if !has_pi_provider {
            return Err(PolicyError::NoProgramProviderError);
        }

        // Check the ciphersuite
        #[cfg(features = "std")]
        {
            let policy_ciphersuite = rustls::CipherSuite::lookup_value(self.ciphersuite())
                .map_err(|_| {
                    PolicyError::TLSInvalidCyphersuiteError(
                        self.get_ciphersuite().to_string(),
                    )
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
    pub fn expected_shutdown_list(&self) -> Vec<u32> {
        self.identities()
            .iter()
            .fold(Vec::new(), |mut acc, identity| {
                if identity.has_role(&Role::ResultReader) {
                    acc.push(*identity.id());
                }
                acc
            })
    }

    /// Returns the count of data providers expected, as specified in this
    /// policy.
    #[inline]
    pub fn expected_data_source_count(&self) -> usize {
        self.data_provision_order().len()
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
        Err(PolicyError::InvalidClientCertificateError(
            cert.to_string(),
        ))
    }
}
