//! Sessions
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

use crate::error::SessionManagerError;
use veracruz_utils::policy::principal::{Identity, Role};

use std::{
    io::{Read, Write},
    vec::Vec,
};

use rustls::{Certificate, ServerSession, Session as TLSSession};

////////////////////////////////////////////////////////////////////////////////
// Sessions.
////////////////////////////////////////////////////////////////////////////////

/// A principal is an individual identified with a cryptographic certificate,
/// and assigned a set of roles that dictate what that principal can and cannot
/// do in a Veracruz computation.
pub type Principal = Identity<Certificate>;

/// A session consists of a TLS server session with a list of principals and
/// their identifying information.
pub struct Session {
    /// The TLS server session.
    tls_session: ServerSession,
    /// The list of principals, their identities, and roles in the Veracruz
    /// computation.
    principals: Vec<Principal>,
}

impl Session {
    /// Creates a new session from a server configuration and a list of
    /// principals.
    pub fn new(config: rustls::ServerConfig, principals: Vec<Principal>) -> Self {
        let tls_session = ServerSession::new(&std::sync::Arc::new(config));

        Session {
            tls_session,
            principals,
        }
    }

    /// Writes the contents of `input` over the session's TLS server session.
    pub fn send_tls_data(&mut self, input: &mut Vec<u8>) -> Result<(), SessionManagerError> {
        let mut slice = input.as_slice();
        self.tls_session.read_tls(&mut slice)?;
        self.tls_session.process_new_packets()?;
        Ok(())
    }

    /// Writes the entirety of the `input` buffer over the TLS connection.
    #[inline]
    pub fn return_data(&mut self, input: &[u8]) -> Result<(), SessionManagerError> {
        self.tls_session.write_all(input)?;
        Ok(())
    }

    /// Reads TLS data from the session's TLS server session.  If the TLS
    /// session has no data to read, returns `Ok(None)`.  If data is available
    /// for reading, returns `Ok(Some(buffer))` for some byte buffer, `buffer`.
    /// If reading fails, then an error is returned.
    pub fn read_tls_data(&mut self) -> Result<Option<Vec<u8>>, SessionManagerError> {
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
    ) -> Result<Option<(u32, Vec<Role>, Vec<u8>)>, SessionManagerError> {
        let mut received_buffer: Vec<u8> = Vec::new();
        let num_bytes = self.tls_session.read_to_end(&mut received_buffer)?;

        if num_bytes > 0 {
            let peer_certs = self
                .tls_session
                .get_peer_certificates()
                .ok_or(SessionManagerError::PeerCertificateError)?;

            if peer_certs.len() != 1 {
                return Err(SessionManagerError::InvalidLengthError("peer_certs", 1));
            }

            let mut roles = Vec::new();
            let mut client_id = 0;

            for principal in self.principals.iter() {
                if principal.certificate() == &peer_certs[0] {
                    roles = principal.roles().clone();
                    client_id = principal.id().clone();
                }
            }

            if roles.is_empty() {
                return Err(SessionManagerError::EmptyRoleError(client_id.into()));
            }

            Ok(Some((client_id, roles, received_buffer)))
        } else {
            Ok(None)
        }
    }

    /// Returns `true` iff the session's TLS server session has data to be read.
    #[inline]
    pub fn read_tls_needed(&self) -> bool {
        self.tls_session.wants_write()
    }

    /// Returns `true` iff the session's TLS server session has finished
    /// handshaking and therefore authentication has been completed.
    #[inline]
    pub fn is_authenticated(&self) -> bool {
        !self.tls_session.is_handshaking()
    }
}
