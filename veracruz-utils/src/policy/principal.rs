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
//! See the `LICENSE.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

use serde::{Deserialize, Serialize};
use super::error::PolicyError;
use std::{string::String, vec::Vec, collections::{HashMap, HashSet}};

////////////////////////////////////////////////////////////////////////////////
// File operation and capabilities.
////////////////////////////////////////////////////////////////////////////////

/// List of file operations
/// TODO: line up  wasi operations eps. the `Right` defined in wasi.
#[derive(Clone, Hash, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum FileOperation {
    Read,
    Write,
    Execute,
}

#[derive(Clone,Hash,PartialEq,Eq,Debug, Serialize, Deserialize)]
pub enum Principal {
    InternalSuperUser,
    // Participant ID
    Participant(u64),
    // Program
    Program(String),
    NoCap,
}

// Principal -> file name -> Set(FileOperation)
pub type CapabilityTable = HashMap<Principal,HashMap<String, HashSet<FileOperation>>>;

/// Defines the capabilities on a file.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct FileCapability {
    /// The file name 
    pub(crate) file_name : String,
    /// Read permission
    pub(crate) read : bool,
    /// Write permission
    pub(crate) write : bool,
    /// Execute permission
    pub(crate) execute : bool,
}

impl FileCapability {
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
pub struct Program {
    /// The file name 
    pub(crate) program_file_name : String,
    /// The program ID
    pub(crate) id: u32,
    /// The hash of the program which will be provisioned into Veracruz by the
    /// program provider.
    pub(crate) pi_hash : String,
    /// The file permission that specifies the program's ability to read, write and execute files.
    pub(crate) file_permissions : Vec<FileCapability>,
}

impl Program {
    /// Creates a veracruz program.
    #[inline]
    pub fn new(program_file_name: String, id: u32, pi_hash: String, file_permissions : Vec<FileCapability>) -> Self {
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
    pub fn file_permissions(&self) -> &[FileCapability] {
        self.file_permissions.as_slice()
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

////////////////////////////////////////////////////////////////////////////////
// Identities.
////////////////////////////////////////////////////////////////////////////////

/// A notion of identity for Veracruz principals.  Note that in different
/// contexts we require different representations from our cryptographic
/// certificates: in some contexts these should be unparsed text representations
/// of the certificates (e.g. in the material below), and in other circumstances
/// a parsed format is more appropriate, e.g. the `Certificate` type from the
/// `RusTLS` library, as used by the session manager.  We therefore abstract
/// over the concrete types of certificates to obtain a single type that suits
/// both contexts.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Identity<U> {
    /// The cryptographic certificate associated with this identity.  Note that
    /// the actual implementation of this is kept abstract.
    pub(crate) certificate: U,
    /// The ID associated with this identity.
    /// TODO: what is this?  Explain it properly.
    pub(crate) id: u32,
    /// The file capabilities that specifies this principal's ability to read,
    /// write and execute files.
    pub(crate) file_permissions : Vec<FileCapability>,
}

impl<U> Identity<U> {
    /// Creates a new identity from a certificate, and identifier.  Initially,
    /// we keep the set of roles empty.
    #[inline]
    pub fn new(certificate: U, id: u32, file_permissions : Vec<FileCapability>) -> Self 
    {
        Self {
            certificate,
            id,
            file_permissions,
        }
    }

    pub fn file_permissions(&self) -> &[FileCapability] {
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

impl Identity<String> {
    /// Checks the validity of the identity, including well-formedness checks on
    /// the structure of the X509 certificate.  Returns `Err(reason)` iff the
    /// identity is malformed.  Returns `Ok(())` in all other cases.
    ///
    /// NOTE: the X509 apparently does not check the end of certificates for a
    /// valid certificate termination line.  As a result, we check that in this
    /// function.
    pub fn assert_valid(&self) -> Result<(), PolicyError> {
        if !self.certificate().ends_with("-----END CERTIFICATE-----") {
            return Err(PolicyError::CertificateFormatError(
                self.certificate().clone(),
            ));
        }

        #[cfg(features = "std")]
        {
            let parsed_cert =
                x509_parser::pem::Pem::read(std::io::Cursor::new(self.certificate().as_bytes()))?;

            let parsed_cert = parsed_cert.0.parse_x509()?.tbs_certificate;

            if parsed_cert.validity.time_to_expiration().is_none() {
                return Err(PolicyError::CertificateExpireError(
                    self.certificate().clone(),
                ));
            }
        }

        Ok(())
    }
}
