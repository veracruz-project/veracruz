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
use coset::{CoseSign1, TaggedCborSerializable};
use io_utils::http::{HttpResponse, post_bytes};
use lazy_static::lazy_static;
use log::error;
use rand::Rng;
use std::{collections::HashMap, convert::TryInto, sync::Mutex};
use veracruz_utils::sha256::sha256;

// Yes, I'm doing what you think I'm doing here. Each instance of the SGX root enclave
// will have the same public key. Yes, I'm embedding that key in the source
// code. I could come up with a complicated system for auto generating a key
// for each instance, and then use that key.
// That's what needs to be done if you want to productize this.
// That's not what I'm going to do for this research project
static PUBLIC_KEY: [u8; 65] = [
    0x4, 0x5f, 0x5, 0x5d, 0x39, 0xd9, 0xad, 0x60, 0x89, 0xf1, 0x33, 0x7e, 0x6c, 0xf9, 0x57, 0xe,
    0x6f, 0x84, 0x25, 0x5f, 0x16, 0xf8, 0xcd, 0x9c, 0xe4, 0xa0, 0xa2, 0x8d, 0x7a, 0x4f, 0xb7, 0xe4,
    0xd3, 0x60, 0x37, 0x2a, 0x81, 0x4f, 0x7, 0xc2, 0x5a, 0x24, 0x85, 0xbf, 0x47, 0xbc, 0x84, 0x47,
    0x40, 0xc5, 0x9b, 0xff, 0xff, 0xd2, 0x76, 0x32, 0x82, 0x4d, 0x76, 0x4d, 0xb4, 0x50, 0xee, 0x9f,
    0x22,
];

#[derive(Clone)]
struct PsaAttestationContext {
    firmware_version: String,
    challenge: [u8; 32],
}

lazy_static! {
    static ref ATTESTATION_CONTEXT: Mutex<HashMap<i32, PsaAttestationContext>> =
        Mutex::new(HashMap::new());
}

pub fn start(firmware_version: &str, device_id: i32) -> ProxyAttestationServerResponder {
    let mut challenge: [u8; 32] = [0; 32];
    let mut rng = rand::thread_rng();

    rng.fill(&mut challenge);

    let attestation_context = PsaAttestationContext {
        firmware_version: firmware_version.to_string(),
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

use psa_crypto::types::key::{Attributes, Type, Lifetime, Policy, UsageFlags};
use psa_crypto::types::algorithm::{Algorithm, AsymmetricSignature, Hash};

#[derive(Clone)]
struct Verifier {
    key_id: Option<psa_crypto::types::key::Id>,
}

impl Verifier {
    pub fn verify(&self, sig: &[u8], data: &[u8]) -> Result<(), ProxyAttestationServerError> {
        let mut hash: [u8; 32] = [0; 32];
        psa_crypto::operations::hash::hash_compute(Hash::Sha256.into(), data, &mut hash)
            .map_err(|err| ProxyAttestationServerError::PSACryptoError(format!("hash_compute failed:{:?}", err)))?;
        let alg = AsymmetricSignature::Ecdsa {
            hash_alg: Hash::Sha256.into(),
        };
        if let Some(key_id) = self.key_id {
            match psa_crypto::operations::asym_signature::verify_hash(key_id, alg, &hash, &sig) {
                Ok(_) => return Ok(()),
                Err(_) => return Err(ProxyAttestationServerError::FailedToVerifyError("signature verification of psa attestation token failed")),
            }
        } else {
            return Err(ProxyAttestationServerError::MissingFieldError("key_idcl"));
        }
    }

    pub fn set_key(&mut self, key_data: &[u8]) -> Result<(), ProxyAttestationServerError> {
        
        let mut usage_flags: UsageFlags = Default::default();
        usage_flags.set_verify_hash();
        let attributes = Attributes {
            key_type: Type::EccPublicKey {
                curve_family:psa_crypto::types::key::EccFamily::SecpR1,
            },
            bits: 256,
            lifetime: Lifetime::Volatile,
            policy: Policy {
                usage_flags: usage_flags,
                permitted_algorithms: Algorithm::AsymmetricSignature(AsymmetricSignature::Ecdsa {
                    hash_alg: Hash::Sha256.into(),
                }),
            },
        };

        self.key_id = Some(psa_crypto::operations::key_management::import(
            attributes, // attributes
            None, // Id
            key_data, // data
        ).map_err(|err| ProxyAttestationServerError::PSACryptoError(format!("key import failed:{:?}", err)))?);
        return Ok(());
    }
}

impl Drop for Verifier {
    fn drop(&mut self) {
        if let Some(key_id) = self.key_id {
            let _ = unsafe { psa_crypto::operations::key_management::destroy(key_id) };
        }
    }
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

static VERAISON_VERIFIER_IP_ADDRESS: &str = "192.168.32.3:8080";

fn verify_attestation_token(token: &[u8], device_id: i32) -> Result<(Vec<u8>, Vec<u8>), ProxyAttestationServerError> {
    println!("proxy-attestation-server::verify_attestation_token started");
    let challenge = {
        let mut ac_hash = ATTESTATION_CONTEXT.lock()?;
        ac_hash
            .remove(&device_id)
            .ok_or(ProxyAttestationServerError::NoDeviceError(device_id))?.challenge
    };

    let encoded_challenge = base64::encode(&challenge);
    let buffer = format!("nonce={:}", &encoded_challenge);
    let url = format!("{:}/challenge-response/v1/newSession", VERAISON_VERIFIER_IP_ADDRESS);
    let session_info = post_bytes(&url, &challenge, None)
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
    let url = format!("{:}{:}", VERAISON_VERIFIER_IP_ADDRESS, verify_path);
    println!("proxy-attestation-server::verify_attestation_token calling post buffer for verify to url:{:?}", url);
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

    let received_nonce = base64::decode(&serde_data["result"]["processed_evidence"]["nonce"].as_str().unwrap())
        .map_err(|err| ProxyAttestationServerError::Base64Error(err))?;
    if received_nonce != challenge {
        println!("proxy-attestation-server::attestation::psa::verify_attestation_token received_hash:{:?} did not match challenge:{:?}", received_nonce, challenge);
        return Err(ProxyAttestationServerError::MismatchError {
            variable: "challenge",
            expected:challenge.to_vec(),
            received:received_nonce
        });
    }

    let enclave_hash = base64::decode(&serde_data["result"]["processed_evidence"]["software-components"][0]["measurement-value"].as_str().unwrap())
        .map_err(|err| ProxyAttestationServerError::Base64Error(err))?;

    let csr_hash = base64::decode(serde_data["result"]["processed_evidence"]["software-components"][0]["signer-id"].as_str().unwrap())
        .map_err(|err| ProxyAttestationServerError::Base64Error(err))?;

    return Ok((enclave_hash.to_vec(), csr_hash.to_vec()));
}
