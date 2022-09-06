//! AWS Nitro specific material for the Veracruz proxy attestation server
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
use std::io::Write;
use std::{collections::HashMap, str, string::String, sync::Mutex};

/// A struct containing information needed for attestation of a specific
/// Nitro Root enclave
#[derive(Clone)]
struct NitroAttestationContext {
    /// The challenge that we sent to the Nitro Root Enclave (used
    /// when authenticating it's token)
    challenge: [u8; 32],
}

lazy_static! {
    /// A hash map containing a `NitroAttestationContext` for each of the
    /// Nitro enclaves that we have started native attestation for
    static ref ATTESTATION_CONTEXT: Mutex<HashMap<i32, NitroAttestationContext>> =
        Mutex::new(HashMap::new());
}

/// Start the Nitro enclave attestation process for an enclave with the
/// provided firmware version and the provided `device_id`.
/// Note that this is the `device_id` we sent with the challenge.
pub fn start(device_id: i32) -> ProxyAttestationServerResponder {
    let mut challenge: [u8; 32] = [0; 32];
    let mut rng = rand::thread_rng();

    rng.fill(&mut challenge);

    let attestation_context = NitroAttestationContext {
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

/// Handle an attestation token passed to us in the `body_string` parameter
pub fn attestation_token(body_string: String) -> ProxyAttestationServerResponder {

    let received_bytes = base64::decode(&body_string)
        .map_err(|err| {
            println!("proxy-attestation-server::attestation::nitro::attestation_token failed to decode base64:{:?}", err);
            let _ignore = std::io::stdout().flush();
            err
        })?;

    let parsed = transport_protocol::parse_proxy_attestation_server_request(None, &received_bytes)
        .map_err(|err| {
            println!("proxy-attestation-server::attestation::nitro::attestation_token failed to parse proxy attestation server request:{:?}", err);
            let _ignore = std::io::stdout().flush();
            err
        })?;
    if !parsed.has_nitro_attestation_doc() {
        println!("proxy-attestation-server::attestation::nitro::attestation_token received data is incorrect.");
        let _ignore = std::io::stdout().flush();
        return Err(ProxyAttestationServerError::MissingFieldError(
            "nitro_attestation_doc",
        ));
    }
    let (att_doc_data, device_id) =
        transport_protocol::parse_nitro_attestation_doc(parsed.get_nitro_attestation_doc());
    let challenge = {
        let mut ac_hash = ATTESTATION_CONTEXT.lock()
            .map_err(|err| {
                println!("proxy-attestation-server::nitro::attestation_token failed to obtain lock on ATTESTATION_CONTEXT:{:?}", err);
                let _ignore = std::io::stdout().flush();
                err
            })?;
        // remove because we are not going to need this context again
        match ac_hash.remove(&device_id) {
            Some(entry) => entry.challenge,
            None => {
                println!("proxy-attestation-server::nitro::attestation_token device not found. device_id:{:?}", device_id);
                let _ignore = std::io::stdout().flush();
                return Err(ProxyAttestationServerError::NoDeviceError(device_id));
            }
        }
    };
    let mut veraison_challenge: [u8; 32] = [0; 32];
    let mut rng = rand::thread_rng();
    rng.fill(&mut veraison_challenge);
    // convert to non-mutable for safetly
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
    //let encoded_att_doc = base64::encode(att_doc_data);
    let url = format!("{:}/challenge-response/v1/{:}", super::VERAISON_VERIFIER_IP_ADDRESS, verify_path);
    //let result = post_bytes(&url, &encoded_att_doc, Some("application/aws-nitro-document"))
    let result = post_bytes(&url, &att_doc_data, Some("application/aws-nitro-document"))
        .map_err(|err| {
            ProxyAttestationServerError::HttpError(err)
        })?;
    let json_data = match result {
        HttpResponse::Ok(data) => data,
        _ => return Err(ProxyAttestationServerError::UnimplementedRequestError),
    };
    let serde_data: serde_json::Value = serde_json::from_str(&json_data)
        .map_err(|err| {
            println!("serde_json::from_str failed:{:?}", err);
            ProxyAttestationServerError::SerdeJsonError(err)
        })?;

    let status_field = serde_data["status"].as_str().unwrap();
    if status_field != "complete" {
        return Err(
            ProxyAttestationServerError::FailedToVerifyError(
                "AWS nitro enclave documentation failed to authenticate"
            )
        );
    }
    let result_field = serde_data["result"].as_str().unwrap();
    let decoded_result = base64::decode(&result_field).unwrap();
    let decoded_result_field_str = str::from_utf8(&decoded_result).unwrap();
    let decoded_json: serde_json::Value = serde_json::from_str(&decoded_result_field_str).unwrap();
    let received_nonce = base64::decode(&decoded_json["veraison-processed-evidence"]["nonce"].as_str().unwrap())
        .map_err(|err| ProxyAttestationServerError::Base64Error(err))?;

    if received_nonce != challenge {
        println!("proxy-attestation-server::attestation::nitro::attestation_token received nonce:{:?}, expected challenge:{:?}", received_nonce, challenge);
        return Err(ProxyAttestationServerError::MismatchError {
            variable: "challenge",
            expected: challenge.to_vec(),
            received: received_nonce
        });
    }
    let received_veraison_nonce = {
        let temp = serde_data["nonce"].as_str().unwrap();
        base64::decode(&temp)
            .map_err(|err| {
                println!("nitro::attestation_token base64 decode failed:{:?}", err);
                ProxyAttestationServerError::Base64Error(err)
            })?
    };

    if received_veraison_nonce != veraison_challenge {
        println!("proxy-attestation-server::attestation::nitro::attestation_token received nonce:{:?} did not match challenge:{:?}", received_nonce, challenge);
        return Err(ProxyAttestationServerError::MismatchError {
            variable: "veraison_challenge",
            expected: veraison_challenge.to_vec(),
            received: received_veraison_nonce
        });
    };

    let pcr0 = decoded_json["veraison-processed-evidence"]["PCR0"].as_str().unwrap();
    let user_data = &decoded_json["veraison-processed-evidence"]["user_data"].as_str().unwrap();

    let received_enclave_hash = base64::decode(pcr0).unwrap();

    let csr = base64::decode(user_data).unwrap();

    // // convert the CSR into a certificate
    let re_cert = crate::attestation::convert_csr_to_certificate(&csr, &received_enclave_hash[0..32])
        .map_err(|err| {
            println!("proxy-attestation-server::attestation::nitro::attestation_token convert_csr_to_certificate failed:{:?}", err);
            err
        })?;

    let root_cert_der = crate::attestation::get_ca_certificate()?;

    let response_bytes = transport_protocol::serialize_cert_chain(&re_cert.to_der()?, &root_cert_der)
        .map_err(|err| {
            println!("proxy-attestation-server::attestation::nitro::attestation_token serialize_cert_chain failed:{:?}", err);
            err
        })?;

    let response_b64 = base64::encode(&response_bytes);

    Ok(response_b64)
}
