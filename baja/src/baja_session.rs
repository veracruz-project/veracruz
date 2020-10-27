//! Baja sessions
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

use super::BajaError;
use rustls::Session;
use std::io::{Read, Write};
use std::vec::Vec;
use veracruz_utils;

pub struct BajaSession {
    tls_session: rustls::ServerSession,
    pub client_identities: Vec<(u32, rustls::Certificate, Vec<veracruz_utils::VeracruzRole>)>,
}

impl BajaSession {
    pub fn new(
        config: &rustls::ServerConfig,
        client_identities: &Vec<(u32, rustls::Certificate, Vec<veracruz_utils::VeracruzRole>)>,
    ) -> Result<BajaSession, BajaError> {
        let tls_session = rustls::ServerSession::new(&std::sync::Arc::new(config.clone()));

        let session = BajaSession {
            tls_session: tls_session,
            client_identities: client_identities.clone(),
        };
        Ok(session)
    }

    pub fn send_tls_data(&mut self, input: &mut Vec<u8>) -> Result<(), BajaError> {
        let mut slice = &input[..];
        self.tls_session.read_tls(&mut slice)?;
        self.tls_session.process_new_packets()?;
        Ok(())
    }

    pub fn read_tls_data(&mut self) -> Result<Option<Vec<u8>>, BajaError> {
        if self.tls_session.wants_write() {
            let mut output = Vec::new();
            self.tls_session.write_tls(&mut output)?;
            Ok(Some(output))
        } else {
            Ok(None)
        }
    }

    pub fn read_plaintext_data(
        &mut self,
    ) -> Result<Option<(u32, Vec<veracruz_utils::VeracruzRole>, Vec<u8>)>, BajaError> {
        let mut received_buffer: std::vec::Vec<u8> = std::vec::Vec::new();

        let num_bytes = self.tls_session.read_to_end(&mut received_buffer)?;
        if num_bytes > 0 {
            let peer_certs = self
                .tls_session
                .get_peer_certificates()
                .ok_or(BajaError::PeerCertificateError)?;
            if peer_certs.len() != 1 {
                return Err(BajaError::InvalidLengthError("peer_certs", 1));
            }
            let mut roles: Vec<veracruz_utils::VeracruzRole> = Vec::new();
            let mut client_id = 0;
            for this_identity in self.client_identities.iter() {
                if this_identity.1 == peer_certs[0] {
                    roles = this_identity.2.clone();
                    client_id = this_identity.0;
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

    pub fn read_tls_needed(&self) -> bool {
        self.tls_session.wants_write()
    }

    pub fn return_data(&mut self, input: Vec<u8>) -> Result<(), BajaError> {
        self.tls_session.write_all(&input[..])?;
        Ok(())
    }

    pub fn is_authenticated(&self) -> bool {
        !self.tls_session.is_handshaking()
    }
}
