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
use anyhow::{anyhow, Result};
use mbedtls::{alloc::List, ssl::Config, x509::Certificate};
use policy_utils::principal::Identity;
use std::{
    io::{Read, Write},
    sync::{Arc, Mutex},
    vec::Vec,
};

////////////////////////////////////////////////////////////////////////////////
// Sessions.
////////////////////////////////////////////////////////////////////////////////

/// A principal is an individual identified with a cryptographic certificate,
/// and assigned a set of roles that dictate what that principal can and cannot
/// do in a Veracruz computation.
pub type Principal = Identity<List<Certificate>>;

/// A session consists of a TLS server session with a list of principals and
/// their identifying information.
pub struct Session {
    /// The TLS server session.
    tls_context: mbedtls::ssl::Context<InsecureConnection>,
    /// Whether the connection is established.
    established: bool,
    /// Read and write buffers shared with InsecureConnection.
    shared_buffers: Arc<Mutex<Buffers>>,
    /// The list of principals, their identities, and roles in the Veracruz
    /// computation.
    principals: Vec<Principal>,
}

struct Buffers {
    /// Read buffer used by mbedtls for cyphertext.
    read_buffer: Vec<u8>,
    /// Write buffer used by mbedtls for cyphertext.
    write_buffer: Option<Vec<u8>>,
}

/// This is the structure given to mbedtls and used for reading and
/// writing cyphertext, using the standard Read and Write traits.
struct InsecureConnection {
    /// Read and write buffers shared with Session.
    shared_buffers: Arc<Mutex<Buffers>>,
}

// To convert any error to a std::io error:
fn std_err(error_text: &str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, error_text)
}

impl Read for InsecureConnection {
    fn read(&mut self, data: &mut [u8]) -> Result<usize, std::io::Error> {
        // Return as much data from the read_buffer as fits.
        let mut shared_buffers = self
            .shared_buffers
            .lock()
            .map_err(|_| std_err("lock failed"))?;
        let n = std::cmp::min(data.len(), shared_buffers.read_buffer.len());
        if n == 0 {
            Err(std::io::Error::new(
                std::io::ErrorKind::WouldBlock,
                "InsecureConnection Read",
            ))
        } else {
            data[0..n].clone_from_slice(&shared_buffers.read_buffer[0..n]);
            shared_buffers.read_buffer = shared_buffers.read_buffer[n..].to_vec();
            Ok(n)
        }
    }
}

impl Write for InsecureConnection {
    fn write(&mut self, data: &[u8]) -> Result<usize, std::io::Error> {
        // Append to write buffer.
        let mut shared_buffers = self
            .shared_buffers
            .lock()
            .map_err(|_| std_err("lock failed"))?;
        match &mut shared_buffers.write_buffer {
            None => shared_buffers.write_buffer = Some(data.to_vec()),
            Some(x) => x.extend_from_slice(data),
        }
        // Return value to indicate that we handled all the data.
        Ok(data.len())
    }
    fn flush(&mut self) -> Result<(), std::io::Error> {
        Ok(())
    }
}

impl Session {
    /// Creates a new session from a server configuration and a list of
    /// principals.
    pub fn new(config: Config, principals: &Vec<Principal>) -> Result<Self> {
        let tls_context = mbedtls::ssl::Context::new(Arc::new(config));
        let shared_buffers = Arc::new(Mutex::new(Buffers {
            read_buffer: vec![],
            write_buffer: None,
        }));

        Ok(Session {
            tls_context,
            established: false,
            shared_buffers,
            principals: principals.to_vec(),
        })
    }

    /// Writes the contents of `input` over the session's TLS server session.
    pub fn send_tls_data(&mut self, input: &mut Vec<u8>) -> Result<()> {
        self.shared_buffers
            .lock()
            .map_err(|_| SessionManagerError::SharedBufferLock)?
            .read_buffer
            .append(input);
        Ok(())
    }

    /// Writes the entirety of the `input` buffer over the TLS connection.
    #[inline]
    pub fn write_plaintext_data(&mut self, input: &[u8]) -> Result<()> {
        self.tls_context.write_all(&input)?;
        Ok(())
    }

    /// Reads TLS data from the session's TLS server session.  If the TLS
    /// session has no data to read, returns `Ok(None)`.  If data is available
    /// for reading, returns `Ok(Some(buffer))` for some byte buffer, `buffer`.
    /// If reading fails, then an error is returned.
    pub fn read_tls_data(&mut self) -> Result<Option<Vec<u8>>> {
        let mut shared_buffers = self
            .shared_buffers
            .lock()
            .map_err(|_| SessionManagerError::SharedBufferLock)?;
        Ok(shared_buffers.write_buffer.take())
    }

    /// Reads data via the established TLS session, returning the unique client
    /// ID and the set of roles associated with the principal that sent the
    /// data.
    pub fn read_plaintext_data(&mut self) -> Result<Option<(u32, Vec<u8>)>> {
        let mut received_buffer = vec![];
        self.established()?;
        let t = self.tls_context.read_to_end(&mut received_buffer);
        match t {
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => 0,
            x => x?,
        };

        if received_buffer.len() > 0 {
            let mut client_id = 0;
            let peer_certs = self.tls_context.peer_cert()?;
            if peer_certs.iter().count() == 1 {
                let peer_cert = peer_certs
                    .ok_or(anyhow!(SessionManagerError::PeerCertificateError))?
                    .iter()
                    .nth(0)
                    .ok_or(anyhow!(SessionManagerError::PeerCertificateError))?
                    .as_der();

                for principal in self.principals.iter() {
                    let x = principal
                        .certificate()
                        .iter()
                        .nth(0)
                        .ok_or(SessionManagerError::PeerCertificateError)?;
                    if x.as_der() == peer_cert {
                        client_id = principal.id().clone();
                    }
                }
            }
            Ok(Some((client_id, received_buffer)))
        } else {
            Ok(None)
        }
    }

    fn established(&mut self) -> Result<()> {
        if !self.established {
            let conn = InsecureConnection {
                shared_buffers: Arc::clone(&self.shared_buffers),
            };
            match self.tls_context.establish(conn, None) {
                Err(mbedtls::Error::SslWantRead) => (),
                x => x?,
            };
            self.established = true;
        }
        Ok(())
    }
}
