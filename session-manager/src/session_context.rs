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
//! See the `LICENSE_MIT.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

use std::{
    io::Cursor,
    string::String,
    vec::Vec,
};

use crate::{
    error::SessionManagerError,
    session::{Principal, Session},
};
use policy_utils::policy::Policy;

use ring::{rand::SystemRandom, signature::EcdsaKeyPair};
use rustls::{
    Certificate, PrivateKey, RootCertStore, ServerConfig,
};
use rustls_pemfile;

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
    rustls_pemfile::certs(&mut cursor)
        .map_err(|_| SessionManagerError::TLSUnspecifiedError)
        .and_then(|certs| {
            if certs.is_empty() {
                Err(SessionManagerError::NoCertificateError)
            } else {
                Ok(Certificate(certs[0].clone()))
            }
        })
}

////////////////////////////////////////////////////////////////////////////////
// The session context.
////////////////////////////////////////////////////////////////////////////////

/// A session context contains various bits of meta-data, such as certificates
/// and server configuration options, for managing a server session.
pub struct SessionContext {
    /// An intermediate ConfigBuilder that will be present after the policy is 
    /// provided but before the certificate chain is provided
    server_config_builder: Option<rustls::ConfigBuilder<rustls::ServerConfig, rustls::server::WantsServerCert>>,
    /// The configuration options for the server.
    server_config: Option<ServerConfig>,
    /// The global policy associated with the Veracruz computation, detailing
    /// identities and roles for all principals, amongst other things.
    policy: Option<Policy>,
    /// The set of principals, as specified in the Veracruz global policy, with
    /// their identifying certificates and roles.
    principals: Option<Vec<Principal>>,
    /// The private key used by the server
    server_private_key: PrivateKey,
    /// The public key used by the server (as a Vec<u8> for convenience)
    server_public_key: Vec<u8>,
}

impl SessionContext {
    /// Creates a new context
    pub fn new() -> Result<Self, SessionManagerError> {
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

        Ok(Self {
            server_config_builder: None,
            server_config: None,
            principals: None,
            policy: None,
            server_public_key: server_public_key,
            server_private_key: server_private_key,
        })
    }

    pub fn set_policy(&mut self, policy: Policy) -> Result<(), SessionManagerError> {
        // create the root_cert_store that contains all of the certs of the clients that can connect
        // Note: We are not using a CA here, so each client that needs to connect must have it's
        // cert directly in the RootCertStore
        let mut root_cert_store = RootCertStore::empty();
        let mut principals = Vec::new();

        for identity in policy.identities().iter() {
            let cert = convert_cert_buffer(identity.certificate())?;
            let principal = Principal::new(
                cert.clone(),
                *identity.id(),
                identity.file_rights().to_vec(),
            );

            root_cert_store.add(&cert)?;

            principals.push(principal);
        }
        // create the configuration
        let policy_ciphersuite = veracruz_utils::lookup_ciphersuite(&policy.ciphersuite())
              .ok_or_else(|| SessionManagerError::TLSInvalidCiphersuiteError(policy.ciphersuite().clone()))?;

        let server_config_builder = rustls::ServerConfig::builder()
            .with_cipher_suites(&[policy_ciphersuite])
            .with_safe_default_kx_groups()
            .with_protocol_versions(&[&rustls::version::TLS12])?
            .with_client_cert_verifier(rustls::server::AllowAnyAuthenticatedClient::new(root_cert_store));

        self.server_config_builder = Some(server_config_builder);
        self.principals = Some(principals);
        self.policy = Some(policy);

        return Ok(());
    }

    pub fn set_cert_chain(&mut self, chain_data: &Vec<Vec<u8>>) -> Result<(), SessionManagerError> {
        let mut cert_chain: Vec<rustls::Certificate> = Vec::new();
        for this_chain_data in chain_data {
            let cert: rustls::Certificate = rustls::Certificate(this_chain_data.clone());
            cert_chain.push(cert);
        }
        let config_builder_option = self.server_config_builder.take(); // After this, server_config_builder will be None
        match config_builder_option {
            Some(config_builder) => {
                let config = config_builder.with_single_cert(cert_chain, self.server_private_key.clone())?;
                self.server_config = Some(config);
            }
            None => return Err(SessionManagerError::InvalidStateError),
            
        }
        return Ok(());
    }

    /// Returns the configuration associated with the server.
    #[inline]
    pub fn server_config(&self) -> Result<ServerConfig, SessionManagerError> {
        match &self.server_config {
            Some(config) => return Ok(config.clone()),
            None => return Err(SessionManagerError::InvalidStateError),
        }
    }

    /// Returns the principals associated with the server.
    #[inline]
    pub fn principals(&self) -> Result<&Vec<Principal>, SessionManagerError> {
        match &self.principals {
            Some(principals) => return Ok(&principals),
            None => return Err(SessionManagerError::InvalidStateError),
        }
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
    pub fn create_session(&self) -> Result<Session, SessionManagerError> {
        Ok(Session::new(self.server_config()?, self.principals()?)?)
    }
}
