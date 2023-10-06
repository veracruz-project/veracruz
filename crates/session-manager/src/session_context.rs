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
//! See the `LICENSE.md` file in the Veracruz root directory for
//! information on licensing and copyright.

use crate::{
    error::SessionManagerError,
    session::{Principal, Session},
};
use anyhow::{anyhow, Result};
use mbedtls::{
    self,
    alloc::List,
    ssl::{config, Config},
    x509::Certificate,
};
use platform_services::getrandom;
use policy_utils::policy::Policy;
use std::{string::String, sync::Arc, vec::Vec};

////////////////////////////////////////////////////////////////////////////////
// Constants.
////////////////////////////////////////////////////////////////////////////////

////////////////////////////////////////////////////////////////////////////////
// Miscellaneous certificate-related material.
////////////////////////////////////////////////////////////////////////////////

/// Converts a string into a parsed X509 cryptographic certificate.
fn convert_cert_buffer<'a, U: Into<&'a String>>(cert_string: U) -> Result<List<Certificate>> {
    let cert_string_string: &String = cert_string.into();
    let mut buffer = std::vec::Vec::new();
    buffer.extend_from_slice(cert_string_string.as_bytes());
    buffer.push(b'\0');
    let cert_vec = Certificate::from_pem_multiple(&buffer)?;
    if cert_vec.iter().count() < 1 {
        Err(anyhow!(SessionManagerError::NoCertificateError))
    } else {
        Ok(cert_vec)
    }
}

////////////////////////////////////////////////////////////////////////////////
// The session context.
////////////////////////////////////////////////////////////////////////////////

/// A session context contains various bits of meta-data, such as certificates
/// and server configuration options, for managing a server session.
pub struct SessionContext {
    /// Vector of permitted cypher suites as used by mbedtls.
    cipher_suites: Vec<i32>,
    /// Root certificates.
    root_certs: List<Certificate>,
    /// Certificate chain.
    cert_chain: List<Certificate>,
    /// The global policy associated with the Veracruz computation, detailing
    /// identities and roles for all principals, amongst other things.
    policy: Option<Policy>,
    /// The set of principals, as specified in the Veracruz global policy, with
    /// their identifying certificates and roles.
    principals: Option<Vec<Principal>>,
    /// The private key used by the server (as a Vec<u8> for convenience)
    server_private_key: Vec<u8>,
    /// The public key used by the server (as a Vec<u8> for convenience)
    server_public_key: Vec<u8>,
}

impl SessionContext {
    /// Creates a new context
    pub fn new() -> Result<Self> {
        let (server_public_key, server_private_key) = {
            let mut rng = |buffer: *mut u8, size: usize| {
                let mut slice = unsafe { std::slice::from_raw_parts_mut(buffer, size) };
                getrandom(&mut slice);
                0
            };
            let mut key =
                mbedtls::pk::Pk::generate_ec(&mut rng, mbedtls::pk::EcGroupId::SecP256R1)?;
            (
                key.write_public_der_vec()?[23..].to_vec(),
                key.write_private_der_vec()?,
            )
        };

        Ok(Self {
            cipher_suites: vec![0],
            root_certs: List::new(),
            cert_chain: List::new(),
            principals: None,
            policy: None,
            server_public_key,
            server_private_key,
        })
    }

    pub fn set_policy(&mut self, policy: Policy) -> Result<()> {
        // create the root_cert_store that contains all of the certs of the clients that can connect
        // Note: We are not using a CA here, so each client that needs to connect must have it's
        // cert directly in the RootCertStore
        let mut root_certs = List::new();
        let mut principals = Vec::new();

        for identity in policy.identities().iter() {
            let cert = convert_cert_buffer(identity.certificate())?;
            let principal = Principal::new(
                cert.clone(),
                identity.id(),
                identity.file_rights_map(),
            );

            root_certs.append(cert);

            principals.push(principal);
        }
        // create the configuration
        let policy_ciphersuite =
            veracruz_utils::lookup_ciphersuite(&policy.ciphersuite()).ok_or(anyhow!(
                SessionManagerError::TLSInvalidCiphersuiteError(policy.ciphersuite().clone())
            ))?;

        self.cipher_suites = vec![policy_ciphersuite, 0];
        self.root_certs = root_certs;
        self.principals = Some(principals);
        self.policy = Some(policy);

        return Ok(());
    }

    pub fn set_cert_chain(&mut self, chain_data: &Vec<u8>) -> Result<()> {
        let mut cert_chain = List::new();
        let cert_list = Certificate::from_pem_multiple(chain_data)?;
        cert_chain.append(cert_list);
        self.cert_chain = cert_chain;
        Ok(())
    }

    /// Returns the configuration associated with the server.
    #[inline]
    pub fn server_config(&self) -> Result<Config> {
        let mut config = Config::new(
            config::Endpoint::Server,
            config::Transport::Stream,
            config::Preset::Default,
        );
        config.set_ciphersuites(Arc::new(self.cipher_suites.clone()));
        let entropy = Arc::new(mbedtls::rng::OsEntropy::new());
        let rng = Arc::new(mbedtls::rng::CtrDrbg::new(entropy, None)?);
        config.set_rng(rng);
        config.set_min_version(config::Version::Tls13)?;
        config.set_max_version(config::Version::Tls13)?;
        config.set_ca_list(Arc::new(self.root_certs.clone()), None);
        config.push_cert(
            Arc::new(self.cert_chain.clone()),
            Arc::new(mbedtls::pk::Pk::from_private_key(
                &mut mbedtls::rng::CtrDrbg::new(Arc::new(mbedtls::rng::OsEntropy::new()), None)?,
                &self.server_private_key,
                None,
            )?),
        )?;
        config.set_authmode(config::AuthMode::Required);
        Ok(config)
    }

    /// Returns the principals associated with the server.
    #[inline]
    pub fn principals(&self) -> Result<&Vec<Principal>> {
        match &self.principals {
            Some(principals) => Ok(&principals),
            None => Err(anyhow!(SessionManagerError::InvalidStateError)),
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
    pub fn private_key(&self) -> &[u8] {
        &self.server_private_key
    }

    /// Creates a new session, using server configuration and information about
    /// the principals that are stored in this context.  Fails iff the creation
    /// of the new session fails.
    #[inline]
    pub fn create_session(&self) -> Result<Session> {
        Ok(Session::new(self.server_config()?, self.principals()?)?)
    }
}
