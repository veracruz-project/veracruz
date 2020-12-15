//! Baja sessions
//!
//! Management and abstraction of TLS server sessions.
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

use crate::error::BajaError;
use veracruz_utils::VeracruzRole;

use std::{
    io::{Read, Write},
    vec::Vec,
};

use rustls::{Certificate, ServerSession, Session};

////////////////////////////////////////////////////////////////////////////////
// Principals.
////////////////////////////////////////////////////////////////////////////////

/// A principal is an individual identified with a cryptographic certificate,
/// and assigned a set of roles that dictate what that principal can and cannot
/// do in a Veracruz computation.
pub struct Principal {
    /// The unique client ID of the principal.
    client_id: u32,
    /// The identifying cryptographic certificate associated with the principal.
    certificate: Certificate,
    /// The set of roles that the principal possesses.
    roles: Vec<VeracruzRole>,
}

impl Principal {
    /// Creates a new principal from a client ID and a certificate.  Assigns the
    /// principal an empty set of roles.
    #[inline]
    pub fn new(client_id: u32, certificate: rustls::Certificate) -> Self {
        Self {
            client_id,
            certificate,
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

    /// Returns the unique client ID associated with this principal.
    #[inline]
    pub fn client_id(&self) -> u32 {
        self.client_id
    }

    /// Returns the cryptographic certificate associated with this principal.
    #[inline]
    pub fn certificate(&self) -> &Certificate {
        &self.certificate
    }

    /// Returns the set of roles associated with this principal.
    #[inline]
    pub fn roles(&self) -> &Vec<VeracruzRole> {
        &self.roles
    }
}

////////////////////////////////////////////////////////////////////////////////
// Baja sessions.
////////////////////////////////////////////////////////////////////////////////

/// A Baja session consists of a TLS server session with a list of principals
/// and their identifying information.
pub struct BajaSession {
    /// The TLS server session.
    tls_session: ServerSession,
    /// The list of principals, their identities, and roles in the Veracruz
    /// computation.
    principals: Vec<Principal>,
}

impl BajaSession {
    /// Creates a new Baja session from a server configuration and a list of
    /// principals.
    pub fn new(
        config: rustls::ServerConfig,
        principals: Vec<Principal>,
    ) -> Self {
        let tls_session = ServerSession::new(&std::sync::Arc::new(config));

        BajaSession {
            tls_session,
            principals,
        }
    }

    /// Writes the contents of `input` over the Baja session's TLS server session.
    pub fn send_tls_data(&mut self, input: &mut Vec<u8>) -> Result<(), BajaError> {
        let mut slice = input.as_slice();
        self.tls_session.read_tls(&mut slice)?;
        self.tls_session.process_new_packets()?;
        Ok(())
    }

    /// Writes the entirety of the `input` buffer over the TLS connection.
    #[inline]
    pub fn return_data(&mut self, input: &[u8]) -> Result<(), BajaError> {
        self.tls_session.write_all(input)?;
        Ok(())
    }

    /// Reads TLS data from the Baja session's TLS server session.  If the TLS
    /// session has no data to read, returns `Ok(None)`.  If data is available
    /// for reading, returns `Ok(Some(buffer))` for some byte buffer, `buffer`.
    /// If reading fails, then an error is returned.
    pub fn read_tls_data(&mut self) -> Result<Option<Vec<u8>>, BajaError> {
        if self.tls_session.wants_write() {
            let mut output = Vec::new();
            self.tls_session.write_tls(&mut output)?;
            Ok(Some(output))
        } else {
            Ok(None)
        }
    }

    /// Reads data via the established TLS session, returning the unique client
    /// ID and the set of roles associated with the principal that sent the
    /// data.
    pub fn read_plaintext_data(
        &mut self,
    ) -> Result<Option<(u32, Vec<VeracruzRole>, Vec<u8>)>, BajaError> {
        let mut received_buffer: Vec<u8> = Vec::new();
        let num_bytes = self.tls_session.read_to_end(&mut received_buffer)?;

        if num_bytes > 0 {
            let peer_certs = self
                .tls_session
                .get_peer_certificates()
                .ok_or(BajaError::PeerCertificateError)?;

            if peer_certs.len() != 1 {
                return Err(BajaError::InvalidLengthError("peer_certs", 1));
            }

            let mut roles = Vec::new();
            let mut client_id = 0;

            for principal in self.principals.iter() {
                if principal.certificate() == peer_certs[0] {
                    roles = principal.roles().clone();
                    client_id = principal.client_id();
                }
            }

            if roles.is_empty() {
                return Err(BajaError::EmptyRoleError(client_id.into()));
            }

            Ok(Some((client_id, roles, received_buffer)))
        } else {
            Ok(None)
        }
    }

    /// Returns `true` iff the Baja session's TLS server session has data to be
    /// read.
    #[inline]
    pub fn read_tls_needed(&self) -> bool {
        self.tls_session.wants_write()
    }

    /// Returns `true` iff the Baja session's TLS server session has finished
    /// handshaking and therefore authentication has been completed.
    #[inline]
    pub fn is_authenticated(&self) -> bool {
        !self.tls_session.is_handshaking()
    }
}
