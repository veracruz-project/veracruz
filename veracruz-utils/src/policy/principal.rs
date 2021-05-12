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

use super::error::PolicyError;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    string::{String, ToString},
    vec::Vec,
};
use wasi_types::Rights;

////////////////////////////////////////////////////////////////////////////////
// File operation and capabilities.
////////////////////////////////////////////////////////////////////////////////

/// The Principal of Capability in Veracruz.
#[derive(Clone, Hash, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum Principal {
    /// The Maximum Capability. It is used in some internal functions.
    InternalSuperUser,
    /// Participant of Veracruz indentified by ID
    Participant(u64),
    /// Program in Veracruz, indentified by the program file name.
    Program(String),
    /// No Capability, the bottom Capability. It is used in some Initialization.
    NoCap,
}

/// The Right Table, contains the `Right`, i.e.
/// the allowed operations of a Principal on a file
pub type RightsTable = HashMap<Principal, HashMap<String, Rights>>;

/// Defines a file entry in the policy, containing the name and `Right`, the allowed op.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct FileRights {
    /// The file name
    file_name: String,
    /// The associated right, when someone open the file
    rights : u32,
}

impl FileRights {
    /// Creates a new file permission.
    #[inline]
    pub fn new(file_name: String, rights: u32) -> Self {
        Self {
            file_name,
            rights,
        }
    }

    /// Returns the file_name.
    #[inline]
    pub fn file_name(&self) -> &str {
        self.file_name.as_str()
    }

    /// Returns the rights.
    #[inline]
    pub fn rights(&self) -> &u32 {
        &self.rights
    }

    /// Convert a vec of FileRights to a Hashmap from filenames to Rights.
    #[inline]
    pub fn to_right_map(file_right_vec: &[FileRights]) -> HashMap<String, Rights> {
        file_right_vec.iter().fold(HashMap::new(), |mut acc, FileRights{file_name, rights}| {
            acc.insert(file_name.to_string(), Rights::from_bits_truncate(*rights as u64));
            acc
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
    /// The hash of the program which will be provisioned into Veracruz by the
    /// program provider.
    pi_hash: String,
    /// The file permission that specifies the program's ability to read, write and execute files.
    file_rights: Vec<FileRights>,
}

impl Program {
    /// Creates a veracruz program.
    #[inline]
    pub fn new<T>(
        program_file_name: String,
        id: T,
        pi_hash: String,
        file_rights: Vec<FileRights>,
    ) -> Self
    where
        T: Into<u32>,
    {
        Self {
            program_file_name,
            id: id.into(),
            pi_hash,
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

    /// Return the program hash.
    #[inline]
    pub fn pi_hash(&self) -> &str {
        self.pi_hash.as_str()
    }

    /// Return file rights map associated to the program.
    #[inline]
    pub fn file_rights_map(&self) -> HashMap<String, Rights> {
        FileRights::to_right_map(&self.file_rights)
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
    certificate: U,
    /// The ID associated with this identity.
    /// TODO: what is this?  Explain it properly.
    id: u32,
    /// The file capabilities that specifies this principal's ability to read,
    /// write and execute files.
    file_rights: Vec<FileRights>,
}

impl<U> Identity<U> {
    /// Creates a new identity from a certificate, and identifier.  Initially,
    /// we keep the set of roles empty.
    #[inline]
    pub fn new<T>(certificate: U, id: T, file_rights: Vec<FileRights>) -> Self
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
    pub fn file_rights(&self) -> &Vec<FileRights> {
        &self.file_rights
    }

    /// Return file rights map associated to the program.
    #[inline]
    pub fn file_rights_map(&self) -> HashMap<String, Rights> {
        FileRights::to_right_map(&self.file_rights)
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
