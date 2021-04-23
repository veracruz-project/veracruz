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
use rustls::{AllowAnyAuthenticatedClient, Certificate, CipherSuite, RootCertStore, ServerConfig};

////////////////////////////////////////////////////////////////////////////////
// Constants.
////////////////////////////////////////////////////////////////////////////////

/// The template of bytes for the cryptographic certificate.
const CERTIFICATE_TEMPLATE: [u8; 536] = [
    0x30, 0x82, 0x02, 0x14, 0x30, 0x82, 0x01, 0xb9, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x14, 0x44,
    0x82, 0x4b, 0x6c, 0x8d, 0xb7, 0x8c, 0x7d, 0x94, 0xd9, 0x56, 0x8f, 0x1e, 0xd2, 0x42, 0xc1, 0xd2,
    0x3a, 0x5e, 0xc9, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x30,
    0x77, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x0e,
    0x30, 0x0c, 0x06, 0x03, 0x55, 0x04, 0x08, 0x0c, 0x05, 0x54, 0x65, 0x78, 0x61, 0x73, 0x31, 0x0f,
    0x30, 0x0d, 0x06, 0x03, 0x55, 0x04, 0x07, 0x0c, 0x06, 0x41, 0x75, 0x73, 0x74, 0x69, 0x6e, 0x31,
    0x10, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x07, 0x41, 0x72, 0x6d, 0x20, 0x4c, 0x74,
    0x64, 0x31, 0x23, 0x30, 0x21, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x01,
    0x16, 0x14, 0x64, 0x65, 0x72, 0x65, 0x6b, 0x2e, 0x6d, 0x69, 0x6c, 0x6c, 0x65, 0x72, 0x40, 0x61,
    0x72, 0x6d, 0x2e, 0x63, 0x6f, 0x6d, 0x31, 0x10, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c,
    0x07, 0x61, 0x62, 0x63, 0x66, 0x64, 0x34, 0x62, 0x30, 0x1e, 0x17, 0x0d, 0x31, 0x39, 0x30, 0x37,
    0x30, 0x38, 0x32, 0x31, 0x35, 0x33, 0x35, 0x31, 0x5a, 0x17, 0x0d, 0x31, 0x39, 0x30, 0x37, 0x30,
    0x39, 0x32, 0x31, 0x35, 0x33, 0x35, 0x31, 0x5a, 0x30, 0x77, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03,
    0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x0e, 0x30, 0x0c, 0x06, 0x03, 0x55, 0x04, 0x08,
    0x0c, 0x05, 0x54, 0x65, 0x78, 0x61, 0x73, 0x31, 0x0f, 0x30, 0x0d, 0x06, 0x03, 0x55, 0x04, 0x07,
    0x0c, 0x06, 0x41, 0x75, 0x73, 0x74, 0x69, 0x6e, 0x31, 0x10, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x04,
    0x0a, 0x0c, 0x07, 0x41, 0x72, 0x6d, 0x20, 0x4c, 0x74, 0x64, 0x31, 0x23, 0x30, 0x21, 0x06, 0x09,
    0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x01, 0x16, 0x14, 0x64, 0x65, 0x72, 0x65, 0x6b,
    0x2e, 0x6d, 0x69, 0x6c, 0x6c, 0x65, 0x72, 0x40, 0x61, 0x72, 0x6d, 0x2e, 0x63, 0x6f, 0x6d, 0x31,
    0x10, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x07, 0x61, 0x72, 0x6d, 0x2e, 0x63, 0x6f,
    0x6d, 0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08,
    0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0x10, 0x68, 0x37, 0xed,
    0x72, 0x4e, 0x16, 0x1d, 0xd1, 0x3e, 0x0a, 0x55, 0x4b, 0xf9, 0xfd, 0x7b, 0x6c, 0x78, 0x2c, 0x19,
    0xbc, 0xec, 0xd5, 0x58, 0x16, 0x4e, 0x9a, 0xb2, 0xae, 0x1b, 0x26, 0x43, 0x54, 0xf3, 0x6d, 0x68,
    0xaf, 0x1d, 0x9f, 0xde, 0xb9, 0x06, 0xbd, 0xb7, 0xc4, 0x16, 0xac, 0xf7, 0x62, 0x49, 0x40, 0x2f,
    0xc1, 0xad, 0x39, 0xc0, 0xb5, 0x94, 0xc8, 0xd8, 0x4f, 0x89, 0xe1, 0x37, 0xa3, 0x23, 0x30, 0x21,
    0x30, 0x1f, 0x06, 0x03, 0x55, 0x1d, 0x11, 0x04, 0x18, 0x30, 0x16, 0x82, 0x07, 0x61, 0x62, 0x63,
    0x66, 0x64, 0x34, 0x62, 0x82, 0x0b, 0x77, 0x77, 0x77, 0x2e, 0x61, 0x62, 0x63, 0x66, 0x64, 0x34,
    0x62, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x03, 0x49, 0x00,
    0x30, 0x46, 0x02, 0x21, 0x00, 0x30, 0x45, 0x02, 0x21, 0x00, 0xca, 0x59, 0xa4, 0x52, 0x46, 0x6c,
    0x7d, 0xe7, 0x7a, 0x1f, 0xe0, 0xa3, 0x9b, 0xb4, 0x79, 0x64, 0x44, 0x97, 0x53, 0x29, 0x79, 0x36,
    0xac, 0x65, 0xa2, 0x66, 0x33, 0x02, 0x21, 0x00, 0x12, 0xc2, 0xd2, 0x08, 0x65, 0x02, 0x20, 0x18,
    0x7d, 0x2d, 0x36, 0xe1, 0x68, 0x6a, 0x39, 0x65, 0xc8, 0x86, 0x94, 0xf3, 0xd1, 0x14, 0x16, 0xf7,
    0xa1, 0xdb, 0x6e, 0x10, 0x33, 0x91, 0x91, 0x8f,
];

/// The fixed server name.  Note that, strictly speaking, this should be
/// randomly generated, however there is currently a problem on the TrustZone
/// platform where this is impossible.  As a result, we use a fixed arbitrary
/// value for our server name.  Note that this **does not** have any security
/// implications.
const FIXED_SERVER_NAME: &str = "ac40a0c";

/// The byte range in the certificate template where the issuer common name is
/// found.  Lower limit is inclusive, upper limit exclusive.
const ISSUER_COMMON_NAME_LOCATION: (usize, usize) = (161, 168);
/// The byte range in the certificate template where the valid from date is
/// found.  Lower limit is inclusive, upper limit exclusive.
const VALIDITY_VALID_FROM_LOCATION: (usize, usize) = (172, 185);
/// The byte range in the certificate template where the valid to date is
/// found.  Lower limit is inclusive, upper limit exclusive.
const VALIDITY_VALID_TO_LOCATION: (usize, usize) = (187, 200);
/// The byte range in the certificate template where the subject common name is
/// found.  Lower limit is inclusive, upper limit exclusive.
const SUBJECT_COMMON_NAME_LOCATION: (usize, usize) = (314, 321);
/// The byte range in the certificate template where the public key is
/// found.  Lower limit is inclusive, upper limit exclusive.
const PUBLIC_KEY_LOCATION: (usize, usize) = (344, 412);
/// The byte range in the certificate template where the subject alternative
/// first name is found.  Lower limit is inclusive, upper limit exclusive.
const SUBJECT_ALT_NAME_FIRST_LOCATION: (usize, usize) = (429, 436);
/// The byte range in the certificate template where the subject alternative
/// second name is found.  Lower limit is inclusive, upper limit exclusive.
const SUBJECT_ALT_NAME_SECOND_LOCATION: (usize, usize) = (442, 449);
/// The byte range in the certificate template where the first part of the
/// signature is found.  Lower limit is inclusive, upper limit exclusive.
const SIGNATURE_PART_1_LOCATION: (usize, usize) = (469, 501);
/// The byte range in the certificate template where the second part of the
/// signature is found.  Lower limit is inclusive, upper limit exclusive.
const SIGNATURE_PART_2_LOCATION: (usize, usize) = (504, 536);

////////////////////////////////////////////////////////////////////////////////
// Miscellaneous certificate-related material.
////////////////////////////////////////////////////////////////////////////////

/// Generates a cryptographic certificate using the template at the top of the
/// file, filling in names, validity dates, and similar metadata by explicit
/// splicing.
fn generate_certificate(
    common_name_bytes: Vec<u8>,
    private_key: rustls::PrivateKey,
    public_key: Vec<u8>,
    policy: &Policy,
) -> Result<Vec<u8>, SessionManagerError> {
    let ring_private_key = EcdsaKeyPair::from_pkcs8(
        &ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING,
        &private_key.0[..],
    )?;

    let mut constructed_cert = CERTIFICATE_TEMPLATE.to_vec();

    if common_name_bytes.len() != (ISSUER_COMMON_NAME_LOCATION.1 - ISSUER_COMMON_NAME_LOCATION.0) {
        return Err(SessionManagerError::InvalidLengthError(
            "common_name",
            ISSUER_COMMON_NAME_LOCATION.1 - ISSUER_COMMON_NAME_LOCATION.0,
        ));
    }
    constructed_cert.splice(
        ISSUER_COMMON_NAME_LOCATION.0..ISSUER_COMMON_NAME_LOCATION.1,
        common_name_bytes.iter().cloned(),
    );

    // Add the valid from field
    {
        let year = 2019 % 100;
        let month = 11;
        let day = 6;
        let hour = 6;
        let minute = 43;
        let second = 0;
        let valid_from = format!(
            "{:02}{:02}{:02}{:02}{:02}{:02}Z",
            year, month, day, hour, minute, second
        );
        let valid_from_bytes = valid_from.as_bytes().to_vec();
        if valid_from_bytes.len()
            != (VALIDITY_VALID_FROM_LOCATION.1 - VALIDITY_VALID_FROM_LOCATION.0)
        {
            return Err(SessionManagerError::InvalidLengthError(
                "valid_from_bytes",
                VALIDITY_VALID_FROM_LOCATION.1 - VALIDITY_VALID_FROM_LOCATION.0,
            ));
        }

        constructed_cert.splice(
            VALIDITY_VALID_FROM_LOCATION.0..VALIDITY_VALID_FROM_LOCATION.1,
            valid_from_bytes.iter().cloned(),
        );
    }

    // Add the valid to field
    {
        let (year, month, day, hour, minute, second) = policy.enclave_cert_expiry().as_tuple();
        let year = year % 100;
        let valid_to = format!(
            "{:02}{:02}{:02}{:02}{:02}{:02}Z",
            year, month, day, hour, minute, second
        );
        let valid_to_bytes = valid_to.as_bytes().to_vec();
        if valid_to_bytes.len() != (VALIDITY_VALID_TO_LOCATION.1 - VALIDITY_VALID_TO_LOCATION.0) {
            return Err(SessionManagerError::InvalidLengthError(
                "valid_to_bytes",
                VALIDITY_VALID_TO_LOCATION.1 - VALIDITY_VALID_TO_LOCATION.0,
            ));
        }
        constructed_cert.splice(
            VALIDITY_VALID_TO_LOCATION.0..VALIDITY_VALID_TO_LOCATION.1,
            valid_to_bytes.iter().cloned(),
        );
    };

    if common_name_bytes.len() != (SUBJECT_COMMON_NAME_LOCATION.1 - SUBJECT_COMMON_NAME_LOCATION.0)
    {
        return Err(SessionManagerError::InvalidLengthError(
            "common_name_bytes",
            SUBJECT_COMMON_NAME_LOCATION.1 - SUBJECT_COMMON_NAME_LOCATION.0,
        ));
    }
    constructed_cert.splice(
        SUBJECT_COMMON_NAME_LOCATION.0..SUBJECT_COMMON_NAME_LOCATION.1,
        common_name_bytes.iter().cloned(),
    );

    if public_key.len() != (PUBLIC_KEY_LOCATION.1 - PUBLIC_KEY_LOCATION.0) {
        return Err(SessionManagerError::InvalidLengthError(
            "public_key",
            PUBLIC_KEY_LOCATION.1 - PUBLIC_KEY_LOCATION.0,
        ));
    }
    constructed_cert.splice(
        PUBLIC_KEY_LOCATION.0..PUBLIC_KEY_LOCATION.1,
        public_key.iter().cloned(),
    );

    if common_name_bytes.len()
        != (SUBJECT_ALT_NAME_FIRST_LOCATION.1 - SUBJECT_ALT_NAME_FIRST_LOCATION.0)
    {
        return Err(SessionManagerError::InvalidLengthError(
            "common_name_bytes",
            SUBJECT_ALT_NAME_FIRST_LOCATION.1 - SUBJECT_ALT_NAME_FIRST_LOCATION.0,
        ));
    }
    constructed_cert.splice(
        SUBJECT_ALT_NAME_FIRST_LOCATION.0..SUBJECT_ALT_NAME_FIRST_LOCATION.1,
        common_name_bytes.iter().cloned(),
    );
    if common_name_bytes.len()
        != (SUBJECT_ALT_NAME_SECOND_LOCATION.1 - SUBJECT_ALT_NAME_SECOND_LOCATION.0)
    {
        return Err(SessionManagerError::InvalidLengthError(
            "common_name_bytes",
            SUBJECT_ALT_NAME_SECOND_LOCATION.1 - SUBJECT_ALT_NAME_SECOND_LOCATION.0,
        ));
    }
    constructed_cert.splice(
        SUBJECT_ALT_NAME_SECOND_LOCATION.0..SUBJECT_ALT_NAME_SECOND_LOCATION.1,
        common_name_bytes.iter().cloned(),
    );

    let rng = SystemRandom::new();
    let signature = ring_private_key.sign(&rng, &constructed_cert[..])?;

    let signature_vec = signature.as_ref();

    let mut signature_first_vec = vec![0; 32];
    signature_first_vec[..].clone_from_slice(&signature_vec[0..32]);
    if signature_first_vec.len() != (SIGNATURE_PART_1_LOCATION.1 - SIGNATURE_PART_1_LOCATION.0) {
        return Err(SessionManagerError::InvalidLengthError(
            "signature_first_vec",
            SIGNATURE_PART_1_LOCATION.1 - SIGNATURE_PART_1_LOCATION.0,
        ));
    }
    constructed_cert.splice(
        SIGNATURE_PART_1_LOCATION.0..SIGNATURE_PART_1_LOCATION.1,
        signature_first_vec.iter().cloned(),
    );

    let mut signature_second_vec = vec![0; 32];
    signature_second_vec[..].clone_from_slice(&signature_vec[32..64]);
    if signature_second_vec.len() != (SIGNATURE_PART_2_LOCATION.1 - SIGNATURE_PART_2_LOCATION.0) {
        return Err(SessionManagerError::InvalidLengthError(
            "signature_second_vec",
            SIGNATURE_PART_2_LOCATION.1 - SIGNATURE_PART_2_LOCATION.0,
        ));
    }
    constructed_cert.splice(
        SIGNATURE_PART_2_LOCATION.0..SIGNATURE_PART_2_LOCATION.1,
        signature_second_vec.iter().cloned(),
    );

    if constructed_cert.len() != CERTIFICATE_TEMPLATE.len() {
        return Err(SessionManagerError::InvalidLengthError(
            "constructed_cert",
            CERTIFICATE_TEMPLATE.len(),
        ));
    } else {
        Ok(constructed_cert.clone())
    }
}

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
    /// A buffer for storing an unparsed PEM certificate for the server.
    server_certificate_buffer: Vec<u8>,
    /// The parsed PEM certificate for the server.
    server_certificate: Certificate,
    /// The configuration options for the server.
    server_config: ServerConfig,
    /// The global policy associated with the Veracruz computation, detailing
    /// identities and roles for all principals, amongst other things.
    policy: Policy,
    /// A randomly generated name for the server.
    name: String,
    /// The set of principals, as specified in the Veracruz global policy, with
    /// their identifying certificates and roles.
    principals: Vec<Principal>,
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
            let principal = Principal::new(cert.clone(), *identity.id(), identity.file_permissions().to_vec());

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

        let name = {
            // This should be randomly generated as below. But this is causing
            // temporary problems on Trustzone, so instead of randomly generating
            // it, we're using a static value for now.
            // This does not compromise the security of the system
            // TODO
            //let mut temp = vec![0; 3];

            //let rng = ring::rand::SystemRandom::new();
            //rng.fill(&mut temp)
            //.map_err(|_| "Error generating random bytes")?;
            // It must be a valid DNS name, which must not be all numeric
            // so we add an a at the beginning to be sure
            //let full_string = format!("a{:02x}{:02x}{:02x}", temp[0], temp[1], temp[2]);
            //full_string[..7].to_string()
            FIXED_SERVER_NAME.to_string()
        };
        let server_certificate_buffer = generate_certificate(
            name.as_bytes().to_vec(),
            server_private_key.clone(),
            server_public_key,
            &policy,
        )?;

        let server_certificate = Certificate(server_certificate_buffer.clone());
        // create the configuration
        let mut server_config =
            ServerConfig::new(AllowAnyAuthenticatedClient::new(root_cert_store));

        // specialize the configuration
        server_config
            .set_single_cert(vec![server_certificate.clone()], server_private_key.clone())?;

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
            server_certificate_buffer,
            server_certificate,
            server_config,
            policy,
            name,
            principals,
        })
    }

    /// Returns the randomly-generated name associated with the context.
    #[inline]
    pub fn name(&self) -> &String {
        &self.name
    }

    /// Returns the buffer associated with the unparsed PEM certificate of the
    /// server.
    #[inline]
    pub fn server_certificate_buffer(&self) -> &Vec<u8> {
        &self.server_certificate_buffer
    }

    /// Returns the parsed PEM certificate associated with the server.
    #[inline]
    pub fn server_certificate(&self) -> &Certificate {
        &self.server_certificate
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

    /// Creates a new session, using server configuration and information about
    /// the principals that are stored in this context.  Fails iff the creation
    /// of the new session fails.
    #[inline]
    pub fn create_session(&self) -> Session {
        Session::new(self.server_config().clone(), self.principals().clone())
    }
}
