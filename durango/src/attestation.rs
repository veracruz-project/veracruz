//! Remote attestation functionality
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

#[cfg(feature = "mock")]
use mockall::{automock, predicate::*};

#[cfg_attr(feature = "mock", automock)]
pub trait Attestation {
    fn attestation(
        policy: &veracruz_utils::VeracruzPolicy,
    ) -> Result<(Vec<u8>, String), DurangoError>;
}

use crate::error::DurangoError;
use base64;
use colima;
use hex;
use rand::Rng;
use reqwest;

// define a dummy structure for implementing the trait
pub struct AttestationPSA();

impl Attestation for AttestationPSA {
    /// Attestation against the global policy
    fn attestation(
        policy: &veracruz_utils::VeracruzPolicy,
    ) -> Result<(Vec<u8>, String), DurangoError> {
        let expected_enclave_hash = hex::decode(policy.mexico_city_hash().as_str())?;
        Self::attestation_flow(
            &policy.tabasco_url().as_str(),
            &policy.sinaloa_url().as_str(),
            &expected_enclave_hash,
        )
    }
}

impl AttestationPSA {
    fn attestation_flow(
        tabasco_url: &str,
        remote_url: &str,
        expected_enclave_hash: &Vec<u8>,
    ) -> Result<(Vec<u8>, String), DurangoError> {
        let challenge = rand::thread_rng().gen::<[u8; 32]>();
        let serialized_rpat = colima::serialize_request_proxy_psa_attestation_token(&challenge)?;
        let received_string = AttestationPSA::post_sinaloa(remote_url, &serialized_rpat)?;

        let complete_tabasco_url = format!("http://{:}/VerifyPAT", tabasco_url);
        let received_buffer = AttestationPSA::post_string(&complete_tabasco_url, received_string)?;

        let received_payload = base64::decode(&received_buffer)?;

        if challenge != received_payload[8..40] {
            return Err(DurangoError::MismatchError {
                variable: "challenge",
                expected: challenge.to_vec(),
                received: received_payload[8..40].to_vec(),
            });
        }

        if *expected_enclave_hash != received_payload[47..79].to_vec() {
            return Err(DurangoError::MismatchError {
                variable: "expected_enclave_hash",
                expected: expected_enclave_hash.to_vec(),
                received: received_payload[47..79].to_vec(),
            });
        }
        let enclave_cert_hash = received_payload[86..118].to_vec();

        let enclave_name = std::str::from_utf8(&received_payload[124..131])?;
        Ok((enclave_cert_hash, enclave_name.to_string()))
    }

    fn post_sinaloa(remote_url: &str, data: &Vec<u8>) -> Result<String, DurangoError> {
        let string_data = base64::encode(data);
        let dest_url = format!("http://{:}/sinaloa", remote_url);
        let post_result_string = AttestationPSA::post_string(&dest_url, string_data);
        post_result_string
    }

    fn post_string(url: &str, data: String) -> Result<String, DurangoError> {
        let mut response = reqwest::Client::new().post(url).body(data).send()?;
        if response.status() != reqwest::StatusCode::OK {
            return Err(DurangoError::InvalidReqwestError(response.status()));
        }
        response.text().map_err(|e| e.into())
    }
}
