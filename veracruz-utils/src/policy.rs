//! The Veracruz global policy.
//!
//! The global policy captures important information about a Veracruz
//! computation that principals need to audit before they enroll themselves in a
//! computation.  This includes:
//!
//! - The identities and roles of every principals in the computation,
//! - Important URLs, both for the Sinaloa bridge server on the untrusted host's
//!   machine and the Tabasco proxy attestation service,
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

use err_derive::Error;
use serde::{Deserialize, Serialize};
use serde_json;
use std::{
    slice::Iter,
    string::{String, ToString},
    vec::Vec,
};

////////////////////////////////////////////////////////////////////////////////
// Error type.
////////////////////////////////////////////////////////////////////////////////

/// This error type contains more contructors when compiling for clients or hosts.
#[derive(Debug, Error)]
pub enum VeracruzUtilError {
    #[error(display = "VeracruzUtil: SerdeJsonError: {:?}.", _0)]
    SerdeJsonError(#[error(source)] serde_json::Error),
    // NOTE: PENError and X509Error do not implement Error trait, cannot use error(source).
    #[cfg(feature = "std")]
    #[error(display = "VeracruzUtil: X509Error: {:?}.", _0)]
    X509ParserPEMError(x509_parser::error::PEMError),
    // NOTE: it is strange to work with nom::Err, which disallows unwrap.
    #[error(display = "VeracruzUtil: X509Error: {:?}.", _0)]
    X509ParserError(String),
    #[cfg(feature = "std")]
    #[error(display = "VeracruzUtil: TLSError: {:?}.", _0)]
    TLSError(#[error(source)] rustls::TLSError),
    #[error(display = "VeracruzUtil: TLSError: invalid cyphersuite: {:?}.", _0)]
    TLSInvalidCyphersuiteError(std::string::String),
    #[error(display = "VeracruzUtil: SystemTimeError: {:?}.", _0)]
    SystemTimeError(#[error(source)] std::time::SystemTimeError),
    #[error(display = "VeracruzUtil: unauthorized client certificate: {}.", _0)]
    InvalidClientCertificateError(String),
    #[error(display = "VeracruzUtil: Enclave expired.")]
    EnclaveExpireError,
    #[error(display = "VeracruzUtil: Certificate expired: {:?}.", _0)]
    CertificateExpireError(String),
    #[cfg(feature = "std")]
    #[error(display = "VeracruzUtil: TLSError: Unsupported cyphersuite {:?}.", _0)]
    TLSUnsupportedCyphersuiteError(rustls::CipherSuite),
    #[error(display = "VeracruzUtil: Certificate format error: {:?}.", _0)]
    CertificateFormatError(String),
    #[error(display = "VeracruzUtil: Duplicated client ID {}.", _0)]
    DuplicatedClientIDError(u64),
    #[error(display = "VeracruzUtil: Client {} has no role.", _0)]
    EmptyRoleError(u64),
    #[error(display = "VeracruzUtil: Policy has no program provider.")]
    NoProgramProviderError,
    #[error(display = "VeracruzUtil: Policy has an invalid data provider order field.")]
    DataProviderError,
    #[error(display = "VeracruzUtil: Policy has no result retriever.")]
    NoResultRetrieverError,
    #[error(display = "VeracruzUtil: Policy is missing a field: {:?}", _0)]
    MissingPolicyFieldError(String),
}

#[cfg(feature = "std")]
impl From<x509_parser::error::PEMError> for VeracruzUtilError {
    fn from(error: x509_parser::error::PEMError) -> Self {
        VeracruzUtilError::X509ParserPEMError(error)
    }
}

////////////////////////////////////////////////////////////////////////////////
// Execution strategy.
////////////////////////////////////////////////////////////////////////////////

/// Defines the execution strategy that will be used to execute the WASM
/// program.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum ExecutionStrategy {
    /// Interpretation will be used to execute the WASM binary.
    Interpretation,
    /// JIT compilation will be used to execute the WASM binary.
    JIT,
}

////////////////////////////////////////////////////////////////////////////////
// Roles and identities of principals.
////////////////////////////////////////////////////////////////////////////////

/// Defines the role (or mix of roles) that a principal can take on in any
/// Veracruz computation.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum VeracruzRole {
    /// The principal is responsible for supplying the program to execute.
    PiProvider,
    /// The principal is responsible for providing an input data set to the
    /// computation.
    DataProvider,
    /// The principal is capable of retrieving the result of the computation.
    ResultReader,
    /// The principal is responsible for providing an input stream package set to the
    /// computation.
    StreamProvider,
}

/// A notion of identitity for Veracruz principals.  Note that in different
/// contexts we require different representations from our cryptographic
/// certificates: in some contexts these should be unparsed text representations
/// of the certificates (e.g. in the material below), and in other circumstances
/// a parsed format is more appropriate, e.g. the `Certificate` type from the
/// `RusTLS` library, as used in Baja.  We therefore abstract over the concrete
/// types of certificates to obtain a single type that suits both contexts.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct VeracruzIdentity<U> {
    /// The cryptographic certificate associated with this identity.  Note that
    /// the actual implementation of this is kept abstract.
    certificate: U,
    /// The ID associated with this identity.
    /// TODO: what is this?  Explain it properly.
    id: u32,
    /// The mixture of roles that the principal behind this identity has taken
    /// on for the Veracruz computation.
    roles: Vec<VeracruzRole>,
}

impl<U> VeracruzIdentity<U> {
    /// Creates a new identity from a certificate, and identifier.  Initially,
    /// we keep the set of roles empty.
    #[inline]
    pub fn new(certificate: U, id: u32) -> Self {
        Self {
            certificate,
            id,
            roles: Vec::new(),
        }
    }

    /// Adds a new role to the principal's set of assigned roles.
    #[inline]
    pub fn add_role(&mut self, role: VeracruzRole) -> &mut Self {
        self.roles.push(role);
        self
    }

    /// Adds multiple new roles to the principal's set of assigned roles,
    /// reading them from an iterator.
    pub fn add_roles<T>(&mut self, roles: T) -> &mut Self
    where
        T: IntoIterator<Item = VeracruzRole>,
    {
        for role in roles {
            self.add_role(role);
        }
        self
    }

    /// Returns `true` iff the principal has the role, `role`.
    #[inline]
    pub fn has_role(&self, role: &VeracruzRole) -> bool {
        self.roles.iter().any(|r| r == role)
    }

    /// Returns the certificate associated with this identity.
    #[inline]
    pub fn certificate(&self) -> &U {
        &self.certificate
    }

    /// Returns the ID associated with this identity.
    #[inline]
    pub fn id(&self) -> &u32 {
        &self.id
    }

    /// Returns the mixture of roles associated with this identity.
    #[inline]
    pub fn roles(&self) -> &Vec<VeracruzRole> {
        &self.roles
    }
}

impl VeracruzIdentity<String> {
    /// Checks the validity of the identity, including well-formedness checks on
    /// the structure of the X509 certificate.  Returns `Err(reason)` iff the
    /// identity is malformed.  Returns `Ok(())` in all other cases.
    ///
    /// NOTE: the X509 apparently does not check the end of certificates for a
    /// valid certificate termination line.  As a result, we check that in this
    /// function.
    pub fn assert_valid(&self) -> Result<(), VeracruzUtilError> {
        if !self.certificate().ends_with("-----END CERTIFICATE-----") {
            return Err(VeracruzUtilError::CertificateFormatError(
                self.certificate().clone(),
            ));
        }

        #[cfg(features = "std")]
        {
            let parsed_cert =
                x509_parser::pem::Pem::read(std::io::Cursor::new(self.certificate().as_bytes()))?;

            let parsed_cert = parsed_cert.0.parse_x509()?.tbs_certificate;

            if parsed_cert.validity.time_to_expiration().is_none() {
                return Err(VeracruzUtilError::CertificateExpireError(
                    self.certificate().clone(),
                ));
            }
        }

        Ok(())
    }
}

////////////////////////////////////////////////////////////////////////////////
// Veracruz policies, proper.
////////////////////////////////////////////////////////////////////////////////

/// Defines the moment at which a certificate will expire.
///
/// Semantics of fields follows ISO 8601.
///
//// Note that we do not validate certificate expiry timepoints from within the
/// enclave, as there is no way for us to obtain a reliable time.  Instead, this
/// is left as the responsibility of the clients.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct VeracruzExpiry {
    /// Year of expiry.
    year: u32,
    /// Month of expiry.
    month: u8,
    /// Day of expiry.
    day: u8,
    /// Hour of expiry.
    hour: u8,
    /// Minute of expiry.
    minute: u8,
}

impl VeracruzExpiry {
    /// Constructs a new point of expiry from a year, month, day, hour, and
    /// minute.
    ///
    /// TODO: input data needs to be validated.
    #[inline]
    pub fn new(year: u32, month: u8, day: u8, hour: u8, minute: u8) -> Self {
        Self {
            year,
            month,
            day,
            hour,
            minute,
        }
    }

    /// Returns the year of expiry.
    #[inline]
    pub fn year(&self) -> &u32 {
        &self.year
    }

    /// Returns the month of expiry.
    #[inline]
    pub fn month(&self) -> &u8 {
        &self.month
    }

    /// Returns the day of expiry.
    #[inline]
    pub fn day(&self) -> &u8 {
        &self.day
    }

    /// Returns the hour of expiry.
    #[inline]
    pub fn hour(&self) -> &u8 {
        &self.hour
    }

    /// Returns the minute of expiry.
    #[inline]
    pub fn minute(&self) -> &u8 {
        &self.minute
    }

    /// Returns the expiry moment, decoded into a tuple form of year, month,
    /// day, hour, minute, second.
    ///
    /// NB: note that the second field is always zero.
    #[inline]
    pub fn as_tuple(&self) -> (&u32, &u8, &u8, &u8, &u8, &u8) {
        (
            self.year(),
            self.month(),
            self.day(),
            self.hour(),
            self.minute(),
            &0,
        )
    }
}

/// A type representing the data stored in a Veracruz global policy.  This file
/// is public information available to every principal in a Veracruz computation
/// and contains data that every principal needs to audit and understand before
/// they enroll in a computation, so that they are capable of assessing whether
/// a computation is "safe" or not for them to join.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct VeracruzPolicy {
    /// The identities of every principal involved in a computation.
    identities: Vec<VeracruzIdentity<String>>,
    /// The URL of the Sinaloa server.
    sinaloa_url: String,
    /// The expiry of the enclave's self-signed certificate, which will be
    /// issued during the Veracruz bootstrapping process prior to the
    /// computation.
    enclave_cert_expiry: VeracruzExpiry,
    /// The ciphersuite that will be used with the TLS connections between the
    /// principals of the computation and the enclave.
    ciphersuite: String,
    /// The hash of the Veracruz trusted runtime for SGX enclaves.
    mexico_city_hash_sgx: Option<String>,
    /// The hash of the Veracruz trusted runtime for TrustZone TAs.
    mexico_city_hash_tz: Option<String>,
    /// The hash of the Veracruz trusted runtime for AWS Nitro Enclaves.
    mexico_city_hash_nitro: Option<String>,
    /// The declared ordering of data inputs, provided by the various data
    /// providers, as specified in the policy.  Note that data providers can
    /// provision their inputs asynchronously, and in an arbitrary order.  Once
    /// all are provisioned, however, we reorder these inputs into this fixed
    /// declared order so that the Veracruz host ABI, which allows access to
    /// inputs via an index, remains well-defined.
    data_provision_order: Vec<u64>,
    /// The URL of the Tabasco attestation service.
    tabasco_url: String,
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

/// an enumerated type representing the platform the enclave is running on
pub enum EnclavePlatform {
    SGX,
    TrustZone,
    Nitro,
    /// The Mock platform is for unit testing (durango unit tests, at the moment)
    Mock, 
}

impl VeracruzPolicy {
    /// Constructs a new Veracruz policy type, validating the well-formedness of
    /// the resulting policy in the process.  Returns `Ok(policy)` iff these
    /// well-formedness checks pass.
    pub fn new(
        identities: Vec<VeracruzIdentity<String>>,
        sinaloa_url: String,
        enclave_cert_expiry: VeracruzExpiry,
        ciphersuite: String,
        mexico_city_hash_sgx: Option<String>,
        mexico_city_hash_tz: Option<String>,
        mexico_city_hash_nitro: Option<String>,
        data_provision_order: Vec<u64>,
        streaming_order: Vec<u64>,
        tabasco_url: String,
        pi_hash: String,
        debug: bool,
        execution_strategy: ExecutionStrategy,
    ) -> Result<Self, VeracruzUtilError> {
        let policy = Self {
            identities,
            sinaloa_url,
            enclave_cert_expiry,
            ciphersuite,
            mexico_city_hash_sgx,
            mexico_city_hash_tz,
            mexico_city_hash_nitro,
            data_provision_order,
            tabasco_url,
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
    pub fn from_json(json: &str) -> Result<Self, VeracruzUtilError> {
        let policy: Self = serde_json::from_str(json)?;
        policy.assert_valid()?;
        Ok(policy)
    }

    /// Returns the identities associated with this policy.
    #[inline]
    pub fn identities(&self) -> &Vec<VeracruzIdentity<String>> {
        &self.identities
    }

    /// Returns the URL of the Sinaloa server associated with this policy.
    #[inline]
    pub fn sinaloa_url(&self) -> &String {
        &self.sinaloa_url
    }

    /// Returns the enclave certificate expiry moment associated with this
    /// policy.
    #[inline]
    pub fn enclave_cert_expiry(&self) -> &VeracruzExpiry {
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
    pub fn mexico_city_hash(&self, platform: &EnclavePlatform) -> Result<&String, VeracruzUtilError>  {
        let hash = match platform {
            EnclavePlatform::SGX => match &self.mexico_city_hash_sgx {
                Some(hash) => hash,
                None => return Err(VeracruzUtilError::MissingPolicyFieldError("mexico_city_hash_sgx".to_string())),
            },
            EnclavePlatform::TrustZone => match &self.mexico_city_hash_tz {
                Some(hash) => hash,
                None => return Err(VeracruzUtilError::MissingPolicyFieldError("mexico_city_hash_tz".to_string())),
            },
            EnclavePlatform::Nitro => match &self.mexico_city_hash_nitro {
                Some(hash) => hash,
                None => return Err(VeracruzUtilError::MissingPolicyFieldError("mexico_city_hash_nitro".to_string())),
            },
            EnclavePlatform::Mock => match &self.mexico_city_hash_sgx {
                Some(hash) => hash,
                None => return Err(VeracruzUtilError::MissingPolicyFieldError("mexico_city_hash_sgx".to_string())),
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

    /// Returns the URL of the Tabasco attestation service, associated with this
    /// policy.
    #[inline]
    pub fn tabasco_url(&self) -> &String {
        &self.tabasco_url
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
    fn assert_valid(&self) -> Result<(), VeracruzUtilError> {
        let mut client_ids = Vec::new();
        let mut has_pi_provider = false;
        let mut has_result_reader = false;

        for identity in self.identities.iter() {
            identity.assert_valid()?;

            // check IDs of all the participants
            if client_ids.contains(identity.id()) {
                return Err(VeracruzUtilError::DuplicatedClientIDError(
                    *identity.id() as u64
                ));
            }
            client_ids.push(*identity.id());

            // check there is at least one role per client, and there is at least one PiProvider
            // and ResultReader
            if identity.roles().is_empty() {
                return Err(VeracruzUtilError::EmptyRoleError(*identity.id() as u64));
            }

            has_result_reader =
                has_result_reader || identity.roles.contains(&VeracruzRole::ResultReader);

            let new_pi_flag = identity.roles.contains(&VeracruzRole::PiProvider);

            if has_pi_provider && new_pi_flag {
                return Err(VeracruzUtilError::NoProgramProviderError);
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
            return Err(VeracruzUtilError::DataProviderError);
        }

        if !has_result_reader {
            return Err(VeracruzUtilError::NoResultRetrieverError);
        }

        if !has_pi_provider {
            return Err(VeracruzUtilError::NoProgramProviderError);
        }

        // Check the ciphersuite
        #[cfg(features = "std")]
        {
            let policy_ciphersuite = rustls::CipherSuite::lookup_value(self.ciphersuite())
                .map_err(|_| {
                    VeracruzUtilError::TLSInvalidCyphersuiteError(
                        self.get_ciphersuite().to_string(),
                    )
                })?;
            if !rustls::ALL_CIPHERSUITES
                .iter()
                .fold(false, |acc, sup| acc || (sup.suite == policy_ciphersuite))
            {
                return Err(VeracruzUtilError::TLSUnsupportedCyphersuiteError(
                    policy_ciphersuite,
                ));
            }
        }

        // NB: no check of enclave certificate validity as there is no reliable
        // way of obtaining a time from within an enclave.  This is the
        // responsibility of the clients of Veracruz.

        Ok(())
    }

    /// Returns an iterator to the list of identities associated with this
    /// policy.
    ///
    /// TODO: where is this used, and why is it needed if we have access to
    /// the identities through `self.identities()`?
    #[inline]
    pub fn iter_on_client<'a>(&'a self) -> Iter<'a, VeracruzIdentity<String>> {
        self.identities().iter()
    }

    /// Returns the identity of any principal in the computation who is capable
    /// of requesting a shutdown of the computation.  At the moment, only the
    /// principals who can request the result can also request shutdown.
    pub fn expected_shutdown_list(&self) -> Vec<u32> {
        self.identities()
            .iter()
            .fold(Vec::new(), |mut acc, identity| {
                if identity.roles.contains(&VeracruzRole::ResultReader) {
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
    pub fn check_client_id(&self, cert: &str) -> Result<u64, VeracruzUtilError> {
        for identity in self.identities().iter() {
            if identity.certificate().as_str() == cert {
                return Ok(*identity.id() as u64);
            }
        }
        Err(VeracruzUtilError::InvalidClientCertificateError(
            cert.to_string(),
        ))
    }
}
