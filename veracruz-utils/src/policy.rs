//! The Veracruz global policy.
//!
//! The global policy captures important information about a Veracruz
//! computation that principals need to audit before they enroll themselves in a
//! computation.  This includes:
//!
//! - The identities and roles of every principals in the computation,
//! - Important URLs, both for the Sinaloa bridge server on the untrusted host's
//!   machine and the Veracruz proxy attestation service,
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
use ring;
use hex;
use serde::{Deserialize, Serialize};
use serde_json;
use std::{
    fs,
    path,
    slice::Iter,
    string::{String, ToString},
    vec::Vec,
    collections::{HashMap, HashSet},
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
    #[error(display = "VeracruzUtil: HexDecodeError: {:?}.", _0)]
    HexDecodeError(String),
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
    #[error(display = "VeracruzUtil: Policy has no program file: {:?}.",_0)]
    NoProgramFileError(String),
    #[error(display = "VeracruzUtil: IOError: {:?}.", _0)]
    IOError(#[error(source)] std::io::Error),
}

#[cfg(feature = "std")]
impl From<x509_parser::error::PEMError> for VeracruzUtilError {
    fn from(error: x509_parser::error::PEMError) -> Self {
        VeracruzUtilError::X509ParserPEMError(error)
    }
}

////////////////////////////////////////////////////////////////////////////////
// File operation and capabilities.
////////////////////////////////////////////////////////////////////////////////

/// List of file operations
/// TODO: line up wasi-type, if necessary
#[derive(Clone, Hash, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum VeracruzCapability {
    Read,
    Write,
    Execute,
}

#[derive(Clone,Hash,PartialEq,Eq,Debug, Serialize, Deserialize)]
pub enum VeracruzCapabilityIndex {
    InternalSuperUser,
    // Client ID
    Principal(u64),
    // Program
    Program(String),
    NoCap,
}

pub type VeracruzCapabilityTable = HashMap<VeracruzCapabilityIndex,HashMap<String, HashSet<VeracruzCapability>>>;

/// Defines the permission of a file.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct VeracruzFileCapability {
    /// The file name 
    file_name : String,
    /// Read permission
    read : bool,
    /// Write permission
    write : bool,
    /// Execute permission
    execute : bool,
}

impl VeracruzFileCapability {
    /// Creates a new file permission.
    #[inline]
    pub fn new(file_name: String, read: bool, write: bool, execute: bool) -> Self {
        Self {
            file_name,
            read,
            write,
            execute,
        }
    }

    /// Returns the file_name.
    #[inline]
    pub fn file_name(&self) -> &str {
        self.file_name.as_str()
    }

    /// If it is allowed to read.
    #[inline]
    pub fn read(&self) -> bool {
        self.read
    }

    /// If it is allowed to write.
    #[inline]
    pub fn write(&self) -> bool {
        self.write
    }

    /// If it is allowed to execute.
    #[inline]
    pub fn execute(&self) -> bool {
        self.execute
    }
}

////////////////////////////////////////////////////////////////////////////////
// Program permission
////////////////////////////////////////////////////////////////////////////////
/// Defines a program that can be loaded into execution engine.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct VeracruzProgram {
    /// The file name 
    program_file_name : String,
    /// The program ID
    id: u32,
    /// The hash of the program which will be provisioned into Veracruz by the
    /// program provider.
    pi_hash : String,
    /// The file permission that specifies the program's ability to read, write and execute files.
    file_permissions : Vec<VeracruzFileCapability>,
}

impl VeracruzProgram {
    /// Creates a veracruz program.
    #[inline]
    pub fn new(program_file_name: String, id: u32, pi_hash: String, file_permissions : Vec<VeracruzFileCapability>) -> Self {
        Self {
            program_file_name,
            id,
            pi_hash,
            file_permissions,
        }
    }

    /// Return the program file name.
    #[inline]
    pub fn program_file_name(&self) -> &str {
        self.program_file_name.as_str()
    }

    /// Return the program id.
    #[inline]
    pub fn id(&self) -> u32 {
        self.id
    }

    /// Return the program hash.
    #[inline]
    pub fn pi_hash(&self) -> &str {
        self.pi_hash.as_str()
    }

    /// Return file permissions associated to the program.
    #[inline]
    pub fn file_permissions(&self) -> &[VeracruzFileCapability] {
        self.file_permissions.as_slice()
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

/// A notion of identitity for Veracruz principals.  Note that in different
/// contexts we require different representations from our cryptographic
/// certificates: in some contexts these should be unparsed text representations
/// of the certificates (e.g. in the material below), and in other circumstances
/// a parsed format is more appropriate, e.g. the `Certificate` type from the
/// `RusTLS` library, as used by the session manager.  We therefore abstract
/// over the concrete types of certificates to obtain a single type that suits
/// both contexts.
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
    file_permissions : Vec<VeracruzFileCapability>,
}

impl<U> VeracruzIdentity<U> {
    /// Creates a new identity from a certificate, and identifier.  Initially,
    /// we keep the set of roles empty.
    #[inline]
    pub fn new(certificate: U, id: u32, file_permissions : Vec<VeracruzFileCapability>) -> Self {
        Self {
            certificate,
            id,
            file_permissions,
        }
    }

    /// Returns `true` iff the principal has the role, `role`.
    #[inline]
    pub fn file_permissions(&self) -> &[VeracruzFileCapability] {
        self.file_permissions.as_slice()
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
    // TODO: change to ID -> Identity
    /// The identities of every principal involved in a computation.
    identities: Vec<VeracruzIdentity<String>>,
    // TODO: change to Program_file_name -> VeracruzProgram, i.e hash.
    /// The candidate programs that can be loaded in the execution engine.
    programs : Vec<VeracruzProgram>,
    //TODO: add permission table: VeracruzCapabilityIndex -> file_name -> Vec<permission>.
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
    /// The URL of the proxy attestation service.
    proxy_attestation_server_url: String,
    /// The debug configuration flag.  This dictates whether the WASM program
    /// will be able to print debug configuration messages to *stdout* on the
    /// host's machine.
    debug: bool,
    /// The execution strategy that will be used to execute the WASM binary.
    execution_strategy: ExecutionStrategy,
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
        programs : Vec<VeracruzProgram>,
        sinaloa_url: String,
        enclave_cert_expiry: VeracruzExpiry,
        ciphersuite: String,
        mexico_city_hash_sgx: Option<String>,
        mexico_city_hash_tz: Option<String>,
        mexico_city_hash_nitro: Option<String>,
        proxy_attestation_server_url: String,
        debug: bool,
        execution_strategy: ExecutionStrategy,
    ) -> Result<Self, VeracruzUtilError> {
        let policy = Self {
            identities,
            programs,
            sinaloa_url,
            enclave_cert_expiry,
            ciphersuite,
            mexico_city_hash_sgx,
            mexico_city_hash_tz,
            mexico_city_hash_nitro,
            proxy_attestation_server_url,
            debug,
            execution_strategy,
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

    /// Returns the programs associated with this policy.
    #[inline]
    pub fn programs(&self) -> &[VeracruzProgram] {
        self.programs.as_slice()
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

    /// Returns the URL of the proxy attestation service, associated with this
    /// policy.
    #[inline]
    pub fn proxy_attestation_server_url(&self) -> &String {
        &self.proxy_attestation_server_url
    }

    /// Returns the hash of the WASM binary, associated with this policy.
    #[deprecated]
    #[inline]
    pub fn pi_hash(&self, program_file_name : &str) -> Result<&str, VeracruzUtilError> {
        self.programs.iter().find(|VeracruzProgram{program_file_name : p, ..}| program_file_name == p)
            .map(|VeracruzProgram{pi_hash, ..}|pi_hash.as_str()).ok_or(VeracruzUtilError::NoProgramFileError(program_file_name.to_string()))
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

        for identity in self.identities.iter() {
            identity.assert_valid()?;

            // check IDs of all the participants
            if client_ids.contains(identity.id()) {
                return Err(VeracruzUtilError::DuplicatedClientIDError(
                    *identity.id() as u64
                ));
            }
            client_ids.push(*identity.id());
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

    pub fn get_capability_table(&self) -> VeracruzCapabilityTable {
        let mut table = HashMap::new();
        for identity in self.identities() {
            let VeracruzIdentity {
                id,
                file_permissions,
                ..
            } = identity;
            let capabilities_table = Self::to_capabilities(file_permissions);
            table.insert(VeracruzCapabilityIndex::Principal(*id as u64),capabilities_table);
        }
        for program in self.programs() {
            let VeracruzProgram{
                program_file_name,
                file_permissions,
                ..
            } = program;
            let capabilities_table = Self::to_capabilities(file_permissions);
            table.insert(VeracruzCapabilityIndex::Program(program_file_name.to_string()),capabilities_table);
        }
        table
    }

    fn to_capabilities(file_permissions : &[VeracruzFileCapability]) -> HashMap<String, HashSet<VeracruzCapability>> {
        let mut capabilities_table = HashMap::new();
        for permission in file_permissions {
            let (file_name,capabilities) = Self::to_capability_entry(permission);
            capabilities_table.insert(file_name,capabilities);
        }
        capabilities_table 
    }

    fn to_capability_entry(VeracruzFileCapability {
                    file_name,
                    read,
                    write,
                    execute,
                } : &VeracruzFileCapability) -> (String, HashSet<VeracruzCapability>) {

        let mut capabilities = HashSet::new();
        if *read {
            capabilities.insert(VeracruzCapability::Read);
        }
        if *write {
            capabilities.insert(VeracruzCapability::Write);
        }
        if *execute {
            capabilities.insert(VeracruzCapability::Execute);
        }
        (file_name.to_string(), capabilities)
    }

    pub fn get_program_digests(&self) -> Result<HashMap<String, Vec<u8>>,VeracruzUtilError> {
        let mut table = HashMap::new();
        for program in self.programs() {
            let VeracruzProgram{
                program_file_name,
                pi_hash,
                ..
            } = program;
            table.insert(program_file_name.to_string(),hex::decode(pi_hash).map_err(|_e|VeracruzUtilError::HexDecodeError(program_file_name.to_string()))?);
        }
        Ok(table)
    }

    pub fn get_input_table(&self) -> Result<HashMap<String, Vec<String>>, VeracruzUtilError> {
        let mut table = HashMap::new();
        for program in self.programs() {
            let VeracruzProgram{
                program_file_name,
                file_permissions,
                ..
            } = program;
            table.insert(program_file_name.to_string(),Self::get_required_inputs(file_permissions));
        }
        Ok(table)
    }

    fn get_required_inputs(cap : &[VeracruzFileCapability] )-> Vec<String> {
        let mut rst = cap.iter().fold(Vec::new(), |mut acc, x| {
            if x.read() {
                acc.push(x.file_name.to_string());
            }
            acc
        });
        rst.sort();
        rst
    }
}


/// Parses and hashes a Veracruz policy from the given file, validating
/// the well-formedness of the resulting policy in the process.
/// Returns `Ok((policy, policy_hash))` iff these well-formedness checks pass.
pub fn policy_and_hash_from_file<P>(
    path: P
) -> Result<(VeracruzPolicy, String), VeracruzUtilError>
where
    P: AsRef<path::Path>
{
    let policy_json = fs::read_to_string(path)?;
    policy_and_hash_from_json(&policy_json)
}

/// Parses and hashes a Veracruz policy from a JSON-encoded string, `json`,
/// validating the well-formedness of the resulting policy in the process.
/// Returns `Ok((policy, policy_hash))` iff these well-formedness checks pass.
pub fn policy_and_hash_from_json(
    json: &str
) -> Result<(VeracruzPolicy, String), VeracruzUtilError> {
    // hash
    let hash_bytes = ring::digest::digest(
        &ring::digest::SHA256,
        json.as_bytes()
    );
    let hash = hex::encode(&hash_bytes);

    // decode policy
    let policy = VeracruzPolicy::from_json(json)?;

    Ok((policy, hash))
}
