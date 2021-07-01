//! Session contexts
//!
//! Contexts contain meta-data, such as certificates and principals and their
//! roles, necessary to establish and manage a session.
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

use std::{
    io::Cursor,
    string::{String, ToString},
    vec::Vec,
};

use crate::{
    session::{Session, Principal},
    error::SessionManagerError,
};
use veracruz_utils::policy::policy::Policy;

use ring::{rand::SystemRandom, signature::EcdsaKeyPair};
use rustls::{AllowAnyAuthenticatedClient, Certificate, CipherSuite, PrivateKey, RootCertStore, ServerConfig};

////////////////////////////////////////////////////////////////////////////////
// Constants.
////////////////////////////////////////////////////////////////////////////////

////////////////////////////////////////////////////////////////////////////////
// Miscellaneous certificate-related material.
////////////////////////////////////////////////////////////////////////////////

/// Converts a string into a parsed X509 cryptographic certificate.
fn convert_cert_buffer<'a, U>(cert_string: U) -> Result<Certificate, SessionManagerError>
where
    U: Into<&'a String>,
{
    let mut cursor = Cursor::new(cert_string.into());
    rustls::internal::pemfile::certs(&mut cursor)
        .map_err(|_| SessionManagerError::TLSUnspecifiedError)
        .and_then(|certs| {
            if certs.is_empty() {
                Err(SessionManagerError::NoCertificateError)
            } else {
                Ok(certs[0].clone())
            }
        })
}

////////////////////////////////////////////////////////////////////////////////
// The session context.
////////////////////////////////////////////////////////////////////////////////

/// A session context contains various bits of meta-data, such as certificates
/// and server configuration options, for managing a server session.
pub struct SessionContext {
    /// The configuration options for the server.
    server_config: ServerConfig,
    /// The global policy associated with the Veracruz computation, detailing
    /// identities and roles for all principals, amongst other things.
    policy: Policy,
    /// The set of principals, as specified in the Veracruz global policy, with
    /// their identifying certificates and roles.
    principals: Vec<Principal>,
    /// The private key used by the server
    server_private_key: PrivateKey,
    /// The public key used by the server (as a Vec<u8> for convenience)
    server_public_key: Vec<u8>,
}

impl SessionContext {
    /// Creates a new context using the global Veracruz policy, `policy`.
    pub fn new(policy: Policy) -> Result<Self, SessionManagerError> {
        // create the root_cert_store that contains all of the certs of the clients that can connect
        // Note: We are not using a CA here, so each client that needs to connect must have it's
        // cert directly in the RootCertStore
        let mut root_cert_store = RootCertStore::empty();
        let mut principals = Vec::new();

        for identity in policy.identities().iter() {
            let cert = convert_cert_buffer(identity.certificate())?;
            let principal = Principal::new(cert.clone(), *identity.id(), identity.file_rights().to_vec());

            root_cert_store.add(&cert)?;

            principals.push(principal);
        }

        let (server_private_key, server_public_key) = {
            let rng = SystemRandom::new();
            // ECDSA prime256r1 generation.
            let pkcs8_bytes = EcdsaKeyPair::generate_pkcs8(
                &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
                &rng,
            )?;
            (
                rustls::PrivateKey(pkcs8_bytes.as_ref().to_vec()),
                pkcs8_bytes.as_ref()[70..138].to_vec(),
            )
        };

        // create the configuration
        let mut server_config =
            ServerConfig::new(AllowAnyAuthenticatedClient::new(root_cert_store));

        // Set the supported ciphersuites in the server to the one specified in
        // the policy.  This is a dumb way to do this, but I leave it up to the
        // student to find a better way (the ALL_CIPHERSUITES array is not very
        // long, anyway).

        let policy_ciphersuite = CipherSuite::lookup_value(policy.ciphersuite())
            .map_err(|_| SessionManagerError::TLSInvalidCyphersuiteError(policy.ciphersuite().to_string()))?;
        let mut supported_ciphersuite = None;

        for this_supported_cs in rustls::ALL_CIPHERSUITES.iter() {
            if this_supported_cs.suite == policy_ciphersuite {
                supported_ciphersuite = Some(this_supported_cs);
            }
        }

        let supported_ciphersuite = supported_ciphersuite.ok_or(
            SessionManagerError::TLSUnsupportedCyphersuiteError(policy_ciphersuite),
        )?;

        server_config.ciphersuites = vec![supported_ciphersuite];
        server_config.versions = vec![rustls::ProtocolVersion::TLSv1_2];

        Ok(Self {
            server_config,
            principals,
            policy,
            server_public_key,
            server_private_key,
        })
    }

    pub fn set_cert_chain(&mut self, chain_data: &Vec<Vec<u8>>) -> Result<(), SessionManagerError> {
        let mut cert_chain: Vec<rustls::Certificate> = Vec::new();
        for this_chain_data in chain_data {
            let cert: rustls::Certificate = rustls::Certificate(this_chain_data.clone());
            cert_chain.push(cert);
        }
        self.server_config.set_single_cert(cert_chain, self.server_private_key.clone())?;
        return Ok(());
    }

    /// Returns the configuration associated with the server.
    #[inline]
    pub fn server_config(&self) -> &ServerConfig {
        &self.server_config
    }

    /// Returns the principals associated with the server.
    #[inline]
    pub fn principals(&self) -> &Vec<Principal> {
        &self.principals
    }

    /// Returns the public key (as a Vec<u8>) of the server
    #[inline]
    pub fn public_key(&self) -> Vec<u8> {
        return self.server_public_key.clone();
    }

    /// Returns the private key of the server
    /// TODO: Should we do any operations with this key inside this struct instead?
    /// Returning the private key seems a little irresponsible (not that the
    /// software requesting it couldn't just inspect the memory, but still...)
    #[inline]
    pub fn private_key(&self) -> PrivateKey {
        return self.server_private_key.clone();
    }

    /// Creates a new session, using server configuration and information about
    /// the principals that are stored in this context.  Fails iff the creation
    /// of the new session fails.
    #[inline]
    pub fn create_session(&self) -> Session {
        Session::new(self.server_config().clone(), self.principals().clone())
    }
}
