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
use std::{string::String, vec::Vec};

////////////////////////////////////////////////////////////////////////////////
// Roles.
////////////////////////////////////////////////////////////////////////////////

/// Defines the role (or mix of roles) that a principal can take on in any
/// Veracruz computation.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum Role {
    /// The principal is responsible for supplying the program to execute.
    ProgramProvider,
    /// The principal is responsible for providing an input data set to the
    /// computation.
    DataProvider,
    /// The principal is capable of retrieving the result of the computation.
    ResultReader,
    /// The principal is responsible for providing an input stream package set to the
    /// computation.
    StreamProvider,
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
    /// The mixture of roles that the principal behind this identity has taken
    /// on for the Veracruz computation.
    roles: Vec<Role>,
}

impl<U> Identity<U> {
    /// Creates a new identity from a certificate, and identifier.  Initially,
    /// we keep the set of roles empty.
    #[inline]
    pub fn new<T>(certificate: U, id: T) -> Self
    where
        T: Into<u32>,
    {
        Self {
            certificate,
            id: id.into(),
            roles: Vec::new(),
        }
    }

    /// Adds a new role to the principal's set of assigned roles.
    #[inline]
    pub fn add_role(&mut self, role: Role) -> &mut Self {
        self.roles.push(role);
        self
    }

    /// Adds multiple new roles to the principal's set of assigned roles,
    /// reading them from an iterator.
    pub fn add_roles<T>(&mut self, roles: T) -> &mut Self
    where
        T: IntoIterator<Item = Role>,
    {
        for role in roles {
            self.add_role(role);
        }
        self
    }

    /// Returns `true` iff the principal has the role, `role`.
    #[inline]
    pub fn has_role(&self, role: &Role) -> bool {
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
    pub fn roles(&self) -> &Vec<Role> {
        &self.roles
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
