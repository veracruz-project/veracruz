//! Baja
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

use super::BajaError;
use crate::baja_session::BajaSession;
use ring;
use rustls;
use std::string::{String, ToString};
use std::vec::Vec;
use veracruz_utils;

pub struct Baja {
    pub server_cert_buffer: Vec<u8>,
    pub server_cert: rustls::Certificate,
    pub server_config: rustls::ServerConfig,
    pub policy: veracruz_utils::VeracruzPolicy,
    pub name: String,
    client_identities: Vec<(u32, rustls::Certificate, Vec<veracruz_utils::VeracruzRole>)>,
}

fn generate_certificate(
    common_name: &String,
    private_key: &rustls::PrivateKey,
    public_key: &Vec<u8>,
    policy: &veracruz_utils::VeracruzPolicy,
) -> Result<Vec<u8>, BajaError> {
    let common_name_bytes = common_name.as_bytes();

    let ring_private_key = ring::signature::EcdsaKeyPair::from_pkcs8(
        &ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING,
        &private_key.0[..],
    )?;

    let cert_template = vec![
        0x30, 0x82, 0x02, 0x14, 0x30, 0x82, 0x01, 0xb9, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x14,
        0x44, 0x82, 0x4b, 0x6c, 0x8d, 0xb7, 0x8c, 0x7d, 0x94, 0xd9, 0x56, 0x8f, 0x1e, 0xd2, 0x42,
        0xc1, 0xd2, 0x3a, 0x5e, 0xc9, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04,
        0x03, 0x02, 0x30, 0x77, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02,
        0x55, 0x53, 0x31, 0x0e, 0x30, 0x0c, 0x06, 0x03, 0x55, 0x04, 0x08, 0x0c, 0x05, 0x54, 0x65,
        0x78, 0x61, 0x73, 0x31, 0x0f, 0x30, 0x0d, 0x06, 0x03, 0x55, 0x04, 0x07, 0x0c, 0x06, 0x41,
        0x75, 0x73, 0x74, 0x69, 0x6e, 0x31, 0x10, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c,
        0x07, 0x41, 0x72, 0x6d, 0x20, 0x4c, 0x74, 0x64, 0x31, 0x23, 0x30, 0x21, 0x06, 0x09, 0x2a,
        0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x01, 0x16, 0x14, 0x64, 0x65, 0x72, 0x65, 0x6b,
        0x2e, 0x6d, 0x69, 0x6c, 0x6c, 0x65, 0x72, 0x40, 0x61, 0x72, 0x6d, 0x2e, 0x63, 0x6f, 0x6d,
        0x31, 0x10, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x07, 0x61, 0x62, 0x63, 0x66,
        0x64, 0x34, 0x62, 0x30, 0x1e, 0x17, 0x0d, 0x31, 0x39, 0x30, 0x37, 0x30, 0x38, 0x32, 0x31,
        0x35, 0x33, 0x35, 0x31, 0x5a, 0x17, 0x0d, 0x31, 0x39, 0x30, 0x37, 0x30, 0x39, 0x32, 0x31,
        0x35, 0x33, 0x35, 0x31, 0x5a, 0x30, 0x77, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04,
        0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x0e, 0x30, 0x0c, 0x06, 0x03, 0x55, 0x04, 0x08, 0x0c,
        0x05, 0x54, 0x65, 0x78, 0x61, 0x73, 0x31, 0x0f, 0x30, 0x0d, 0x06, 0x03, 0x55, 0x04, 0x07,
        0x0c, 0x06, 0x41, 0x75, 0x73, 0x74, 0x69, 0x6e, 0x31, 0x10, 0x30, 0x0e, 0x06, 0x03, 0x55,
        0x04, 0x0a, 0x0c, 0x07, 0x41, 0x72, 0x6d, 0x20, 0x4c, 0x74, 0x64, 0x31, 0x23, 0x30, 0x21,
        0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x01, 0x16, 0x14, 0x64, 0x65,
        0x72, 0x65, 0x6b, 0x2e, 0x6d, 0x69, 0x6c, 0x6c, 0x65, 0x72, 0x40, 0x61, 0x72, 0x6d, 0x2e,
        0x63, 0x6f, 0x6d, 0x31, 0x10, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x07, 0x61,
        0x72, 0x6d, 0x2e, 0x63, 0x6f, 0x6d, 0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48,
        0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03,
        0x42, 0x00, 0x04, 0x10, 0x68, 0x37, 0xed, 0x72, 0x4e, 0x16, 0x1d, 0xd1, 0x3e, 0x0a, 0x55,
        0x4b, 0xf9, 0xfd, 0x7b, 0x6c, 0x78, 0x2c, 0x19, 0xbc, 0xec, 0xd5, 0x58, 0x16, 0x4e, 0x9a,
        0xb2, 0xae, 0x1b, 0x26, 0x43, 0x54, 0xf3, 0x6d, 0x68, 0xaf, 0x1d, 0x9f, 0xde, 0xb9, 0x06,
        0xbd, 0xb7, 0xc4, 0x16, 0xac, 0xf7, 0x62, 0x49, 0x40, 0x2f, 0xc1, 0xad, 0x39, 0xc0, 0xb5,
        0x94, 0xc8, 0xd8, 0x4f, 0x89, 0xe1, 0x37, 0xa3, 0x23, 0x30, 0x21, 0x30, 0x1f, 0x06, 0x03,
        0x55, 0x1d, 0x11, 0x04, 0x18, 0x30, 0x16, 0x82, 0x07, 0x61, 0x62, 0x63, 0x66, 0x64, 0x34,
        0x62, 0x82, 0x0b, 0x77, 0x77, 0x77, 0x2e, 0x61, 0x62, 0x63, 0x66, 0x64, 0x34, 0x62, 0x30,
        0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x03, 0x49, 0x00, 0x30,
        0x46, 0x02, 0x21, 0x00, 0x30, 0x45, 0x02, 0x21, 0x00, 0xca, 0x59, 0xa4, 0x52, 0x46, 0x6c,
        0x7d, 0xe7, 0x7a, 0x1f, 0xe0, 0xa3, 0x9b, 0xb4, 0x79, 0x64, 0x44, 0x97, 0x53, 0x29, 0x79,
        0x36, 0xac, 0x65, 0xa2, 0x66, 0x33, 0x02, 0x21, 0x00, 0x12, 0xc2, 0xd2, 0x08, 0x65, 0x02,
        0x20, 0x18, 0x7d, 0x2d, 0x36, 0xe1, 0x68, 0x6a, 0x39, 0x65, 0xc8, 0x86, 0x94, 0xf3, 0xd1,
        0x14, 0x16, 0xf7, 0xa1, 0xdb, 0x6e, 0x10, 0x33, 0x91, 0x91, 0x8f,
    ];

    // The following locations follow Rust's Range symantics. Lower bound is inclusive, upper bound is exclusive
    let issuer_common_name_location = (161, 168);
    let validity_valid_from_location = (172, 185);
    let validity_valid_to_location = (187, 200);
    let subject_common_name_location = (314, 321);
    let public_key_location = (344, 412);
    let subject_alt_name_first_location = (429, 436);
    let subject_alt_name_second_location = (442, 449);
    let signature_part_1_location = (469, 501);
    let signature_part_2_location = (504, 536);

    let mut constructed_cert = cert_template.clone();

    if common_name_bytes.len() != (issuer_common_name_location.1 - issuer_common_name_location.0) {
        return Err(BajaError::InvalidLengthError(
            "common_name",
            issuer_common_name_location.1 - issuer_common_name_location.0,
        ));
    }
    constructed_cert.splice(
        issuer_common_name_location.0..issuer_common_name_location.1,
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
        let valid_from_bytes = valid_from.as_bytes();
        if valid_from_bytes.len()
            != (validity_valid_from_location.1 - validity_valid_from_location.0)
        {
            return Err(BajaError::InvalidLengthError(
                "valid_from_bytes",
                validity_valid_from_location.1 - validity_valid_from_location.0,
            ));
        }
        constructed_cert.splice(
            validity_valid_from_location.0..validity_valid_from_location.1,
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
        let valid_to_bytes = valid_to.as_bytes();
        if valid_to_bytes.len() != (validity_valid_to_location.1 - validity_valid_to_location.0) {
            return Err(BajaError::InvalidLengthError(
                "valid_to_bytes",
                validity_valid_to_location.1 - validity_valid_to_location.0,
            ));
        }
        constructed_cert.splice(
            validity_valid_to_location.0..validity_valid_to_location.1,
            valid_to_bytes.iter().cloned(),
        );
    };

    if common_name_bytes.len() != (subject_common_name_location.1 - subject_common_name_location.0)
    {
        return Err(BajaError::InvalidLengthError(
            "common_name_bytes",
            subject_common_name_location.1 - subject_common_name_location.0,
        ));
    }
    constructed_cert.splice(
        subject_common_name_location.0..subject_common_name_location.1,
        common_name_bytes.iter().cloned(),
    );

    if public_key.len() != (public_key_location.1 - public_key_location.0) {
        return Err(BajaError::InvalidLengthError(
            "public_key",
            public_key_location.1 - public_key_location.0,
        ));
    }
    constructed_cert.splice(
        public_key_location.0..public_key_location.1,
        public_key.iter().cloned(),
    );

    if common_name_bytes.len()
        != (subject_alt_name_first_location.1 - subject_alt_name_first_location.0)
    {
        return Err(BajaError::InvalidLengthError(
            "common_name_bytes",
            subject_alt_name_first_location.1 - subject_alt_name_first_location.0,
        ));
    }
    constructed_cert.splice(
        subject_alt_name_first_location.0..subject_alt_name_first_location.1,
        common_name_bytes.iter().cloned(),
    );
    if common_name_bytes.len()
        != (subject_alt_name_second_location.1 - subject_alt_name_second_location.0)
    {
        return Err(BajaError::InvalidLengthError(
            "common_name_bytes",
            subject_alt_name_second_location.1 - subject_alt_name_second_location.0,
        ));
    }
    constructed_cert.splice(
        subject_alt_name_second_location.0..subject_alt_name_second_location.1,
        common_name_bytes.iter().cloned(),
    );

    let rng = ring::rand::SystemRandom::new();
    let signature = ring_private_key.sign(&rng, &constructed_cert[..])?;

    let signature_vec = signature.as_ref();

    let mut signature_first_vec = vec![0; 32];
    signature_first_vec[..].clone_from_slice(&signature_vec[0..32]);
    if signature_first_vec.len() != (signature_part_1_location.1 - signature_part_1_location.0) {
        return Err(BajaError::InvalidLengthError(
            "signature_first_vec",
            signature_part_1_location.1 - signature_part_1_location.0,
        ));
    }
    constructed_cert.splice(
        signature_part_1_location.0..signature_part_1_location.1,
        signature_first_vec.iter().cloned(),
    );

    let mut signature_second_vec = vec![0; 32];
    signature_second_vec[..].clone_from_slice(&signature_vec[32..64]);
    if signature_second_vec.len() != (signature_part_2_location.1 - signature_part_2_location.0) {
        return Err(BajaError::InvalidLengthError(
            "signature_second_vec",
            signature_part_2_location.1 - signature_part_2_location.0,
        ));
    }
    constructed_cert.splice(
        signature_part_2_location.0..signature_part_2_location.1,
        signature_second_vec.iter().cloned(),
    );

    if constructed_cert.len() != cert_template.len() {
        return Err(BajaError::InvalidLengthError(
            "constructed_cert",
            cert_template.len(),
        ));
    } else {
        Ok(constructed_cert.clone())
    }
}

fn convert_cert_buffer(cert_string: &String) -> Result<rustls::Certificate, BajaError> {
    let mut cursor = std::io::Cursor::new(cert_string);
    rustls::internal::pemfile::certs(&mut cursor)
        .map_err(|_| BajaError::TLSUnspecifiedError)
        .and_then(|certs| {
            if certs.len() > 0 {
                Ok(certs[0].clone())
            } else {
                Err(BajaError::NoCertificateError)
            }
        })
}

//fn search_client_id()

impl Baja {
    pub fn new(policy: veracruz_utils::VeracruzPolicy) -> Result<Self, BajaError> {
        // create the root_cert_store that contains all of the certs of the clients that can connect
        // Note: We are not using a CA here, so each client that needs to connect must have it's
        // cert directly in the RootCertStore
        let mut root_cert_store = rustls::RootCertStore::empty();
        let mut client_identities = Vec::new();
        for this_identity in policy.identities().iter() {
            let cert = convert_cert_buffer(&this_identity.certificate())?;
            let _ = root_cert_store.add(&cert)?;
            client_identities.push((
                this_identity.id().clone(),
                cert,
                this_identity.roles().clone(),
            ));
        }
        let (server_private_key, server_public_key) = {
            let rng = ring::rand::SystemRandom::new();
            // ECDSA prime256r1 generation.
            let pkcs8_bytes = ring::signature::EcdsaKeyPair::generate_pkcs8(
                &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
                &rng,
            )?;
            (
                rustls::PrivateKey(pkcs8_bytes.as_ref().to_vec()),
                pkcs8_bytes.as_ref()[70..138].to_vec(),
            )
        };

        let common_name = {
            // This should be randomly generated as below. But this is causing
            // temporary problems on Trustzone, so instead of randomly generating
            // it, we're using a static value for now.
            // This does not compromise the security of the system
            //let mut temp = vec![0; 3];

            //let rng = ring::rand::SystemRandom::new();
            //rng.fill(&mut temp)
            //.map_err(|_| "Error generating random bytes")?;
            // It must be a valid DNS name, which must not be all numeric
            // so we add an a at the beginning to be sure
            //let full_string = format!("a{:02x}{:02x}{:02x}", temp[0], temp[1], temp[2]);
            //full_string[..7].to_string()
            "ac40a0c".to_string()
        };
        let server_cert_buffer = generate_certificate(
            &common_name,
            &server_private_key,
            &server_public_key,
            &policy,
        )?;

        let server_cert = rustls::Certificate(server_cert_buffer.clone());
        // create the configuration
        let mut server_config =
            rustls::ServerConfig::new(rustls::AllowAnyAuthenticatedClient::new(root_cert_store));

        // specialize the configuration
        server_config.set_single_cert(vec![server_cert.clone()], server_private_key.clone())?;

        // set the supported ciphersuites in the server to the one specified in the policy
        // This is a dumb way to do this, but I leave it up to the student to find a better way
        // (The ALL_CIPHERSUITES array is not very long, anyway)
        let policy_ciphersuite = rustls::CipherSuite::lookup_value(policy.ciphersuite())
            .map_err(|_| BajaError::TLSInvalidCyphersuiteError(policy.ciphersuite().to_string()))?;
        let mut supported_ciphersuite = None;
        for this_supported_cs in rustls::ALL_CIPHERSUITES.iter() {
            if this_supported_cs.suite == policy_ciphersuite {
                supported_ciphersuite = Some(this_supported_cs);
            }
        }
        let supported_ciphersuite = supported_ciphersuite.ok_or(
            BajaError::TLSUnsupportedCyphersuiteError(policy_ciphersuite),
        )?;

        server_config.ciphersuites = vec![supported_ciphersuite];
        server_config.versions = vec![rustls::ProtocolVersion::TLSv1_2];

        let baja = Baja {
            server_cert_buffer: server_cert_buffer,
            server_cert: server_cert.clone(),
            server_config: server_config,
            policy: policy,
            name: common_name,
            client_identities: client_identities,
        };
        Ok(baja)
    }

    pub fn get_name(&self) -> String {
        self.name.clone()
    }

    pub fn get_server_cert_pem(&self) -> Vec<u8> {
        self.server_cert_buffer.clone()
    }

    pub fn get_server_cert(&self) -> rustls::Certificate {
        self.server_cert.clone()
    }

    pub fn new_session(&self) -> Result<BajaSession, BajaError> {
        let session = BajaSession::new(&self.server_config.clone(), &self.client_identities)?;
        Ok(session)
    }
}
