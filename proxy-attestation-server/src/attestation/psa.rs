//! PSA Attestation-specific material for the Veracruz proxy attestation server
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE_MIT.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

use crate::error::*;
use io_utils::http::{HttpResponse, post_bytes};
use lazy_static::lazy_static;
use log::error;
use rand::Rng;
use std::{collections::HashMap, sync::Mutex};
use veracruz_utils::sha256::sha256;

#[derive(Clone)]
struct PsaAttestationContext {
    challenge: [u8; 32],
}

lazy_static! {
    static ref ATTESTATION_CONTEXT: Mutex<HashMap<i32, PsaAttestationContext>> =
        Mutex::new(HashMap::new());
}

pub fn start(device_id: i32) -> ProxyAttestationServerResponder {
    let mut challenge: [u8; 32] = [0; 32];
    let mut rng = rand::thread_rng();

    rng.fill(&mut challenge);

    let attestation_context = PsaAttestationContext {
        challenge,
    };
    {
        let mut ac_hash = ATTESTATION_CONTEXT.lock()?;
        ac_hash.insert(device_id, attestation_context);
    }
    let serialized_attestation_init =
        transport_protocol::serialize_psa_attestation_init(&challenge, device_id)?;
    Ok(base64::encode(&serialized_attestation_init))
}

pub fn attestation_token(body_string: String) -> ProxyAttestationServerResponder {
    let received_bytes = base64::decode(&body_string)?;

    let parsed = transport_protocol::parse_proxy_attestation_server_request(None, &received_bytes)?;
    if !parsed.has_native_psa_attestation_token() {
        println!("proxy-attestation-server::attestation::psa::attestation_token received data is incorrect.");
        return Err(ProxyAttestationServerError::MissingFieldError(
            "native_psa_attestation_token",
        ));
    }
    let (token, csr, device_id) = transport_protocol::parse_native_psa_attestation_token(
        parsed.get_native_psa_attestation_token(),
    );

    let (received_enclave_hash, received_csr_hash) = verify_attestation_token(&token, device_id)
        .map_err(|err| {
            println!("proxy-attestation-server/attestation/psa/attestation_token Verification of token failed: {:?}", err);
            ProxyAttestationServerError::FailedToVerifyError("attestation_token Failed to verify attestation token")
        }
    )?;

    //let received_csr_hash = &token_payload[86..118];
    let calculated_csr_hash = sha256(&csr);
    if received_csr_hash != calculated_csr_hash {
        println!("proxy_attestation_server::attestation::psa::attestation_token csr hash failed to verify");
        return Err(ProxyAttestationServerError::MismatchError {
            variable: "received_csr_hash",
            expected: calculated_csr_hash,
            received: received_csr_hash.to_vec(),
        });
    }

    let cert = crate::attestation::convert_csr_to_certificate(&csr, &received_enclave_hash)
        .map_err(|err| {
            println!("proxy-attestation-server::attestation::psa::attestation_token convert_csr_to_certificate failed:{:?}", err);
            err
        })?;

    let root_cert_der = crate::attestation::get_ca_certificate()?;

    let response_bytes = transport_protocol::serialize_cert_chain(&cert.to_der()?, &root_cert_der)?;

    let response_b64 = base64::encode(&response_bytes);

    // clean up the Attestation Context by removing this context
    // {
    //     let mut ac_hash = ATTESTATION_CONTEXT.lock()?;
    //     ac_hash.remove(&device_id);
    // }

    Ok(response_b64)
}

fn verify_attestation_token(token: &[u8], device_id: i32) -> Result<(Vec<u8>, Vec<u8>), ProxyAttestationServerError> {
    let challenge = {
        let mut ac_hash = ATTESTATION_CONTEXT.lock()?;
        ac_hash
            .remove(&device_id)
            .ok_or(ProxyAttestationServerError::NoDeviceError(device_id))?.challenge
    };
    let mut veraison_challenge: [u8; 32] = [0; 32];
    let mut rng = rand::thread_rng();
    rng.fill(&mut veraison_challenge);
    // convert to non-mutable for safety
    let veraison_challenge = veraison_challenge;

    let encoded_veraison_challenge = base64::encode_config(&veraison_challenge, base64::URL_SAFE);

    let url = format!("{:}/challenge-response/v1/newSession?nonce={:}", super::VERAISON_VERIFIER_IP_ADDRESS, encoded_veraison_challenge);
    let session_info = post_bytes(&url, "nothing here", Some("application/x-www-form-urlencoded"))
        .map_err(|err| {
            ProxyAttestationServerError::HttpError(err)
        })?;

    let verify_path = match session_info {
        HttpResponse::Created(location, _body) => {
            location
        },
        not_created => {
            error!("proxy-attestation-server::verify_attestation_token failed to post_bytes:{:?}", not_created);
            return Err(ProxyAttestationServerError::FailedToVerifyError("Unknown verify error"));
        }
    };

    // post to /challenge-response/v1/session/sessionId token
    let url = format!("{:}/challenge-response/v1/{:}", super::VERAISON_VERIFIER_IP_ADDRESS, verify_path);
    let result = post_bytes(&url, &token, Some("application/psa-attestation-token"))
        .map_err(|err| {
            ProxyAttestationServerError::HttpError(err)
        })?;
    let json_data = match result {
        HttpResponse::Ok(data) => data,
        _ => return Err(ProxyAttestationServerError::UnimplementedRequestError),
    };
    let serde_data: serde_json::Value  = serde_json::from_str(&json_data)
        .map_err(|err| {
            println!("serde_json::from_str failed:{:?}", err);
            ProxyAttestationServerError::SerdeJsonError(err)
        })?;

    println!("serde_data:{:?}", serde_data);
    if serde_data["status"].as_str().unwrap() == "failed" {
        println!("We've failed. We don't know why we've failed. You need to find out why we've failed");
        return Err(ProxyAttestationServerError::Anyhow(anyhow::anyhow!("Unspecified remote server error")));
    }
    let result_field = serde_data["result"].as_str().unwrap();
    let decoded_result = base64::decode(&result_field).unwrap();
    let decoded_result_field_str = std::str::from_utf8(&decoded_result).unwrap();
    let decoded_json: serde_json::Value = serde_json::from_str(&decoded_result_field_str).unwrap();
    let received_nonce = base64::decode(&decoded_json["veraison-processed-evidence"]["psa-nonce"].as_str().unwrap())
        .map_err(|err| ProxyAttestationServerError::Base64Error(err))?;
    if received_nonce != challenge {
        println!("proxy-attestation-server::attestation::psa::verify_attestation_token received_hash:{:?} did not match challenge:{:?}", received_nonce, challenge);
        return Err(ProxyAttestationServerError::MismatchError {
            variable: "challenge",
            expected:challenge.to_vec(),
            received:received_nonce
        });
    }
    let received_veraison_nonce = {
        let temp = serde_data["nonce"].as_str().unwrap();
        base64::decode(&temp)
            .map_err(|err| {
                println!("psa::attestation base64 decode failed:{:?}", err);
                ProxyAttestationServerError::Base64Error(err)
            })?
    };
    if received_veraison_nonce != veraison_challenge {
        println!("proxy-attestation-server::attestation::psa::attestation_token received nonce:{:?} did not match challenge:{:?}", received_nonce, challenge);
        return Err(ProxyAttestationServerError::MismatchError {
            variable: "veraison_challenge",
            expected: veraison_challenge.to_vec(),
            received: received_veraison_nonce,
        });
    }

    let enclave_hash = base64::decode(&decoded_json["veraison-processed-evidence"]["psa-software-components"][0]["measurement-value"].as_str().unwrap())
        .map_err(|err| ProxyAttestationServerError::Base64Error(err))?;

    let csr_hash = base64::decode(decoded_json["veraison-processed-evidence"]["psa-software-components"][0]["signer-id"].as_str().unwrap())
        .map_err(|err| ProxyAttestationServerError::Base64Error(err))?;

    return Ok((enclave_hash.to_vec(), csr_hash.to_vec()));
}
