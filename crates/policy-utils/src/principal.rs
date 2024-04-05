//! Principals
//!
//! Types and definitions in this module are used to describe Veracruz
//! principals, namely their identities and capabilities.
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE.md` file in the Veracruz root directory for
//! information on licensing and copyright.

use super::error::PolicyError;
use crate::{parsers::parse_pipeline, pipeline::Expr};
use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize, Serializer, Deserializer};
use std::{collections::HashMap, fmt::Debug, path::{Path, PathBuf}, string::String, str::FromStr};



////////////////////////////////////////////////////////////////////////////////
// File operation and capabilities.
////////////////////////////////////////////////////////////////////////////////

/// The Principal of Capability in Veracruz.
#[derive(Clone, Hash, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum Principal {
    /// The Maximum Capability. It is used in some internal functions.
    InternalSuperUser,
    /// Participant of Veracruz identified by ID
    Participant(u64),
    /// Program in Veracruz, identified by the program file name.
    Program(String),
    /// Pipeline in Veracruz, identified by the pipeline name.
    Pipeline(String),
    /// Native module in Veracruz, identified by its name.
    NativeModule(String),
    /// No Capability, the bottom Capability. It is used in some Initialization.
    NoCap,
}

/// The Permission Table, i.e. the allowed operations, `rwx`, of a Principal on directories.
pub type PrincipalPermission = HashMap<PathBuf, FilePermissions>;
pub type PermissionTable = HashMap<Principal, PrincipalPermission>;

/// Check if the `target_path` is allowed to perform `target_permission` in the `table`.
pub fn check_permission<T: AsRef<Path>>(
    table: &PrincipalPermission,
    target_path: T,
    target_permission: &FilePermissions,
) -> bool {
    table
       .iter()
       // Find the permission corresponding to the longest prefix.
       .fold((0, false), |(max_length, result), (path, permission)|{
           if !target_path.as_ref().starts_with(path){
               // prefix of target_path does not match path
               // return the previous result
               return (max_length, result);
           }  

           let size = path.as_os_str().len();

           if size <= max_length {
               // The matched path is shorted than previous one
               // return the previous result
               return (max_length, result);
           }

           // If reaching here, find a longer prefix match
           (size, permission.allows(target_permission))

       }).1
}

/// Defines a file entry in the policy, containing the name and `Right`, the allowed op.
#[derive(Clone, Debug, PartialEq)]
pub struct FilePermissions {
    pub read: bool,
    pub write: bool,
    pub execute: bool,
}

impl FilePermissions {
    /// Creates a new file permission.
    #[inline]
    pub fn new(read: bool, write: bool, execute: bool) -> Self {
        Self { read, write, execute }
    }

    /// Check if the current permission allows `request`
    pub fn allows(&self, request: &Self) -> bool {
        // request -> (logic imply) self
        // This means, if `request` needs a true, 
        // then check the permission in `self`. Otherwise, `request` 
        // is false and the entire formulae is true.
        //
        // Noting that A -> B is logically equivalent to
        // ~(A /\ ~B) where ~ means negation and /\ means logical and.
        !(request.read & !self.read)
        & !(request.write & !self.write)
        & !(request.execute & !self.execute)
    }
}

/// Custom serialize and deserialize to "rwx"
impl Serialize for FilePermissions {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut permission = String::new();
        if self.read {
            permission.push('r');
        } 
        if self.write {
            permission.push('w');
        }
        if self.execute {
            permission.push('x');
        }

        serializer.serialize_str(&permission)
    }
}

impl<'de> Deserialize<'de> for FilePermissions {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s: &str = Deserialize::deserialize(deserializer)?;
        Ok(Self {
            read: s.contains('r'),
            write: s.contains('w'),
            execute: s.contains('x'),
        })
    }
}

////////////////////////////////////////////////////////////////////////////////
// Program
////////////////////////////////////////////////////////////////////////////////
/// Defines a program that can be loaded into execution engine.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Program {
    /// The file name
    program_file_name: String,
    /// The program ID
    id: u32,
    /// The file permission that specifies the program's ability to read, write and execute files.
    file_rights: PrincipalPermission,
}

impl Program {
    /// Creates a veracruz program.
    #[inline]
    pub fn new<T: Into<u32>>(
        program_file_name: String,
        id: T,
        file_rights: PrincipalPermission,
    ) -> Self {
        Self {
            program_file_name,
            id: id.into(),
            file_rights,
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

    /// Return file rights map associated to the program.
    #[inline]
    pub fn file_rights_map(&self) -> PrincipalPermission {
        self.file_rights.clone()
    }
}

/// Defines a native module that can be loaded directly (provisioned native
/// module) or indirectly (static and dynamic native modules) in the execution
/// environment.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Service {
    /// The source (executable) of the service
    pub source: ServiceSource,
    /// The root directory used by this service
    pub special_dir: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ServiceSource {
    Internal(String),
    Provision(PathBuf),
}

impl Service {
    /// Creates a Veracruz native module.
    #[inline]
    pub fn new(source: ServiceSource, special_dir: PathBuf) -> Self {
        Self { source, special_dir }
    }

    /// Return the name.
    #[inline]
    pub fn source(&self) -> &ServiceSource {
        &self.source
    }

    /// return the dir where the service should be mounted.
    #[inline]
    pub fn dir(&self) -> &PathBuf {
        &self.special_dir
    }
}

////////////////////////////////////////////////////////////////////////////////
// Pipeline
////////////////////////////////////////////////////////////////////////////////
/// Defines a program that can be loaded into execution engine.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Pipeline {
    /// The pipeline name
    name: String,
    /// The script
    #[serde(rename = "pipeline")]
    preparsed_pipeline: String,
    /// The parsed, AST representation of the conditional pipeline of programs
    /// to execute.  This is not present in the JSON representation of a policy
    /// file.
    #[serde(skip)]
    parsed_pipeline: Option<Box<Expr>>,
    /// The pipeline ID
    id: u32,
    /// The file permission that specifies the program's ability to read, write and execute files.
    file_rights: PrincipalPermission,
}

impl Pipeline {
    /// Creates a veracruz pipeline.
    #[inline]
    pub fn new<T: Into<u32>>(
        name: String,
        id: T,
        preparsed_pipeline: String,
        file_rights: PrincipalPermission,
    ) -> Result<Self> {
        let parsed_pipeline = Some(parse_pipeline(&preparsed_pipeline)?);
        Ok(Self {
            name,
            id: id.into(),
            parsed_pipeline,
            preparsed_pipeline,
            file_rights,
        })
    }

    /// Parse the pipeline.
    #[inline]
    pub fn parse(&mut self) -> Result<()> {
        if let None = self.parsed_pipeline {
            self.parsed_pipeline = Some(parse_pipeline(&self.preparsed_pipeline)?);
        }
        Ok(())
    }

    /// Return the name of the pipeline.
    #[inline]
    pub fn name(&self) -> &str {
        self.name.as_str()
    }

    /// Return file rights map associated to the program.
    #[inline]
    pub fn file_rights_map(&self) -> PrincipalPermission {
        self.file_rights.clone()
    }

    /// Return the pipeline AST.
    #[inline]
    pub fn get_parsed_pipeline(&self) -> Result<&Box<Expr>> {
        self.parsed_pipeline
            .as_ref()
            .ok_or(anyhow!("The pipeline is not parsed"))
    }
}

////////////////////////////////////////////////////////////////////////////////
// Execution strategies.
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


impl FromStr for ExecutionStrategy {
    type Err = anyhow::Error;

    // Required method
    fn from_str(s: &str) -> Result<Self> {
        match s {
            "Interpretation" => Ok(ExecutionStrategy::Interpretation),
            "JIT" => Ok(ExecutionStrategy::JIT),
            _otherwise => Err(anyhow!("Could not parse execution strategy argument.")),
        }
    }
}

////////////////////////////////////////////////////////////////////////////////
// Identities.
////////////////////////////////////////////////////////////////////////////////

/// A notion of identity for Veracruz principals.  Note that in different
/// contexts we require different representations from our cryptographic
/// certificates: in some contexts these should be unparsed text representations
/// of the certificates (e.g. in the material below), and in other circumstances
/// a parsed format is more appropriate, e.g. the `Certificate` type from the
/// `Mbed TLS` library, as used by the session manager.  We therefore abstract
/// over the concrete types of certificates to obtain a single type that suits
/// both contexts.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Identity<U> {
    /// The cryptographic certificate associated with this identity.  Note that
    /// the actual implementation of this is kept abstract.
    certificate: U,
    /// The ID associated with this identity.
    /// TODO: what is this?  Explain it properly.
    id: u32,
    /// The file capabilities that specifies this principal's ability to read,
    /// write and execute files.
    file_rights: PrincipalPermission,
}

impl<U> Identity<U> {
    /// Creates a new identity from a certificate, and identifier.  Initially,
    /// we keep the set of roles empty.
    #[inline]
    pub fn new<T>(certificate: U, id: T, file_rights: PrincipalPermission) -> Self
    where
        T: Into<u32>,
    {
        Self {
            certificate,
            id: id.into(),
            file_rights,
        }
    }

    /// Return file rights map associated to the program.
    #[inline]
    pub fn file_rights_map(&self) -> PrincipalPermission {
        self.file_rights.clone()
    }

    /// Returns the certificate associated with this identity.
    #[inline]
    pub fn certificate(&self) -> &U {
        &self.certificate
    }

    /// Returns the ID associated with this identity.
    #[inline]
    pub fn id(&self) -> u32 {
        self.id
    }

    /// Returns the ID associated with this identity.
    #[inline]
    pub fn id_u64(&self) -> u64 {
        self.id as u64
    }
}

impl Identity<String> {
    /// Checks the validity of the identity, including well-formedness checks on
    /// the structure of the X509 certificate.  Returns `Err(reason)` iff the
    /// identity is malformed.  Returns `Ok(())` in all other cases.
    ///
    /// NOTE: the X509 apparently does not check the end of certificates for a
    /// valid certificate termination line.  As a result, we check that in this
    /// function.
    pub fn assert_valid(&self) -> Result<()> {
        if !self.certificate().ends_with("-----END CERTIFICATE-----") {
            return Err(anyhow!(PolicyError::FormatError));
        }

        #[cfg(features = "std")]
        {
            use mbedtls::x509::Certificate;
            use veracruz_utils::csr::generate_x509_time_now;

            let mut buffer: Vec<u8> = self.certificate().as_bytes().to_vec();
            buffer.push(b'\0');
            let cert = Certificate::from_pem(&buffer)?;
            let not_before = cert.not_before()?.to_x509_time();
            let not_after = cert.not_after()?.to_x509_time();
            let now = generate_x509_time_now();
            if now < not_before || now > not_after {
                return Err(anyhow!(PolicyError::FormatError));
            }
        }

        Ok(())
    }
}

/// Defines a file and its expected hash.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct FileHash {
    file_path: String,
    hash: String,
}

impl FileHash {
    /// Creates a new file permission.
    #[inline]
    pub fn new(file_path: String, hash: String) -> Self {
        Self { file_path, hash }
    }

    /// Returns the file_name.
    #[inline]
    pub fn file_path(&self) -> &str {
        self.file_path.as_str()
    }

    /// Returns the rights.
    #[inline]
    pub fn hash(&self) -> &str {
        &self.hash.as_str()
    }
}
