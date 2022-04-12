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
//! See the `LICENSE_MIT.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

use crate::error::SessionManagerError;
use policy_utils::principal::Identity;

use std::{
    io::{Read, Write},
    vec::Vec,
};

use rustls::{Certificate, ServerConnection};

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
    tls_connection: ServerConnection,
    /// The list of principals, their identities, and roles in the Veracruz
    /// computation.
    principals: Vec<Principal>,
}

impl Session {
    /// Creates a new session from a server configuration and a list of
    /// principals.
    pub fn new(config: rustls::ServerConfig, principals: &Vec<Principal>) -> Result<Self, SessionManagerError> {
        let mut tls_connection = ServerConnection::new(std::sync::Arc::new(config))?;
        tls_connection.set_buffer_limit(Some(512 * 1024));

        Ok(Session {
            tls_connection: tls_connection,
            principals: principals.to_vec(),
        })
    }

    /// Writes the contents of `input` over the session's TLS server session.
    pub fn send_tls_data(&mut self, input: &mut Vec<u8>) -> Result<(), SessionManagerError> {
        let mut slice = input.as_slice();
        while slice.len() > 0 {
            self.tls_connection.read_tls(&mut slice)?;
            self.tls_connection.process_new_packets()?;
        }
        Ok(())
    }

    /// Writes the entirety of the `input` buffer over the TLS connection.
    #[inline]
    pub fn return_data(&mut self, input: &[u8]) -> Result<(), SessionManagerError> {
        self.tls_connection.writer().write_all(input)?;
        Ok(())
    }

    /// Reads TLS data from the session's TLS server session.  If the TLS
    /// session has no data to read, returns `Ok(None)`.  If data is available
    /// for reading, returns `Ok(Some(buffer))` for some byte buffer, `buffer`.
    /// If reading fails, then an error is returned.
    pub fn read_tls_data(&mut self) -> Result<Option<Vec<u8>>, SessionManagerError> {
        if self.tls_connection.wants_write() {
            let mut output = Vec::new();
            self.tls_connection.write_tls(&mut output)?;
            Ok(Some(output))
        } else {
            Ok(None)
        }
    }

    /// Reads data via the established TLS session, returning the unique client
    /// ID and the set of roles associated with the principal that sent the
    /// data.
    pub fn read_plaintext_data(&mut self) -> Result<Option<(u32, Vec<u8>)>, SessionManagerError> {
        let mut received_buffer: Vec<u8> = Vec::new();
        match self.tls_connection.reader().read_to_end(&mut received_buffer) {
            Ok(_num) => (),
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                ()
            },
            Err(err) => return Err(SessionManagerError::IOError(err)),
        }
        self.tls_connection.process_new_packets()?;

        if received_buffer.len() > 0 {
            let peer_certs = self
                .tls_connection
                .peer_certificates()
                .ok_or(SessionManagerError::PeerCertificateError)?;

            if peer_certs.len() != 1 {
                return Err(SessionManagerError::InvalidLengthError("peer_certs", 1));
            }

            let mut client_id = 0;

            for principal in self.principals.iter() {
                if principal.certificate() == &peer_certs[0] {
                    client_id = principal.id().clone();
                }
            }

            Ok(Some((client_id, received_buffer)))
        } else {
            Ok(None)
        }
    }

    /// Returns `true` iff the session's TLS server session has data to be read.
    #[inline]
    pub fn read_tls_needed(&self) -> bool {
        self.tls_connection.wants_write()
    }

    /// Returns `true` iff the session's TLS server session has finished
    /// handshaking and therefore authentication has been completed.
    #[inline]
    pub fn is_authenticated(&self) -> bool {
        !self.tls_connection.is_handshaking()
    }
}
