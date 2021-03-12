//! Remote attestation functionality
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

use veracruz_utils::EnclavePlatform;

#[cfg(feature = "mock")]
use mockall::{automock, predicate::*};

#[cfg_attr(feature = "mock", automock)]
pub trait Attestation {
    fn attestation(
        policy: &veracruz_utils::VeracruzPolicy,
        target_platform: &EnclavePlatform,
    ) -> Result<(Vec<u8>, String), VeracruzClientError>;
}

use crate::error::VeracruzClientError;
use base64;
use transport_protocol;
use hex;
use rand::Rng;
use reqwest;

// define a dummy structure for implementing the trait
pub struct AttestationPSA();

impl Attestation for AttestationPSA {
    /// Attestation against the global policy
    fn attestation(
        policy: &veracruz_utils::VeracruzPolicy,
        target_platform: &EnclavePlatform,
    ) -> Result<(Vec<u8>, String), VeracruzClientError> {
        let runtime_manager_hash = policy.runtime_manager_hash(target_platform)
            .map_err(|err| {
                println!("Did not find Runtime Manager hash for platform in policy:{:?}", err);
                err
            })?;
        let expected_enclave_hash = hex::decode(runtime_manager_hash.as_str())?;
        Self::attestation_flow(
            &policy.proxy_attestation_server_url().as_str(),
            &policy.veracruz_server_url().as_str(),
            &expected_enclave_hash,
        )
    }
}

impl AttestationPSA {
    fn attestation_flow(
        proxy_attestation_server_url: &str,
        remote_url: &str,
        expected_enclave_hash: &Vec<u8>,
    ) -> Result<(Vec<u8>, String), VeracruzClientError> {
        let challenge = rand::thread_rng().gen::<[u8; 32]>();
        let serialized_rpat = transport_protocol::serialize_request_proxy_psa_attestation_token(&challenge)?;
        let received_string = AttestationPSA::post_veracruz_server(remote_url, &serialized_rpat)?;

        let complete_proxy_attestation_server_url = format!("http://{:}/VerifyPAT", proxy_attestation_server_url);
        let received_buffer = AttestationPSA::post_string(&complete_proxy_attestation_server_url, received_string)?;

        let received_payload = base64::decode(&received_buffer)?;

        if challenge != received_payload[8..40] {
            return Err(VeracruzClientError::MismatchError {
                variable: "challenge",
                expected: challenge.to_vec(),
                received: received_payload[8..40].to_vec(),
            });
        }

        if *expected_enclave_hash != received_payload[47..79].to_vec() {
            return Err(VeracruzClientError::MismatchError {
                variable: "expected_enclave_hash",
                expected: expected_enclave_hash.to_vec(),
                received: received_payload[47..79].to_vec(),
            });
        }
        let enclave_cert_hash = received_payload[86..118].to_vec();

        let enclave_name = std::str::from_utf8(&received_payload[124..131])?;
        Ok((enclave_cert_hash, enclave_name.to_string()))
    }

    fn post_veracruz_server(remote_url: &str, data: &Vec<u8>) -> Result<String, VeracruzClientError> {
        let string_data = base64::encode(data);
        let dest_url = format!("http://{:}/veracruz_server", remote_url);
        let post_result_string = AttestationPSA::post_string(&dest_url, string_data);
        post_result_string
    }

    fn post_string(url: &str, data: String) -> Result<String, VeracruzClientError> {
        let mut response = reqwest::Client::new().post(url).body(data).send()?;
        if response.status() != reqwest::StatusCode::OK {
            return Err(VeracruzClientError::InvalidReqwestError(response.status()));
        }
        response.text().map_err(|e| e.into())
    }
}
