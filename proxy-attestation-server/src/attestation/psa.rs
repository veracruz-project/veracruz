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
use lazy_static::lazy_static;
use io_utils::http::{HttpResponse, post_bytes};
use lazy_static::lazy_static;
use log::error;
use psa_attestation::{
    q_useful_buf_c, t_cose_crypto_lib_t_T_COSE_CRYPTO_LIB_PSA, t_cose_key,
    t_cose_key__bindgen_ty_1, t_cose_parameters, t_cose_sign1_set_verification_key,
    t_cose_sign1_verify, t_cose_sign1_verify_ctx, t_cose_sign1_verify_delete_public_key,
    t_cose_sign1_verify_init, t_cose_sign1_verify_load_public_key,
};
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

fn _verify_attestation_token(token: &[u8], device_id: i32) -> Result<&[u8], ProxyAttestationServerError> {

    let mut verifier = Verifier {
        key_id: None,
    };

    let sign1 = CoseSign1::from_tagged_slice(&token)
        .map_err(|err| ProxyAttestationServerError::CoseError(err))?;

    let aad: [u8; 0] = [];
    verifier.set_key(&PUBLIC_KEY)?;
    sign1.verify_signature(&aad, |sig, data| verifier.verify(sig, data))
        .map_err(|_| ProxyAttestationServerError::FailedToVerifyError("signature verification failed"))?;
    let body_bytes = sign1.payload.ok_or(ProxyAttestationServerError::MissingFieldError("sign1.payload"))?;
    let body_parsed: ciborium::value::Value = ciborium::de::from_reader(&body_bytes[..])
        .map_err(|err| ProxyAttestationServerError::CiboriumError(err))?;
    let body_map = body_parsed.as_map().ok_or(ProxyAttestationServerError::MissingFieldError("body_parsed.as_map"))?;
    let mut csr_hash_matched: bool = false;
    let mut received_enclave_hash: Option<Vec<u8>> = None;
    let mut received_challenge: Option<Vec<u8>> = None;
    for map_pair in body_map {
        let index = &map_pair.0;
        let value = &map_pair.1;

        let index_value: i32 = index.as_integer()
            .ok_or(ProxyAttestationServerError::MissingFieldError("index.as_integer"))?
            .try_into()
            .map_err(|_| ProxyAttestationServerError::IntConversionError)?;
        if index_value == -75006 {
            let sw_components = value.as_array()
                .ok_or(ProxyAttestationServerError::MissingFieldError("value.as_array"))?;
            for this_sw_component in sw_components {
                let sw_component_map = this_sw_component.as_map()
                    .ok_or(ProxyAttestationServerError::MissingFieldError("this_sw_component.as_map"))?;
                for this_sw_component_item in sw_component_map {
                    let index = &this_sw_component_item.0;
                    let value = &this_sw_component_item.1;
                    let index_int: i32 = index.as_integer()
                        .ok_or(ProxyAttestationServerError::MissingFieldError("index.as_integer"))?
                        .try_into()
                        .map_err(|_| ProxyAttestationServerError::IntConversionError)?;
                    match index_int {
                        5 => {
                            let received_csr_hash = value.as_bytes()
                                .ok_or(ProxyAttestationServerError::MissingFieldError("value.as_bytes()"))?;
                            let calculated_csr_hash = sha256(&csr);
                            if *received_csr_hash != calculated_csr_hash {
                                println!("proxy_attestation_server::attestation::psa::attestation_token csr hash failed to verify");
                                return Err(ProxyAttestationServerError::MismatchError {
                                    variable: "received_csr_hash",
                                    expected: calculated_csr_hash,
                                    received: received_csr_hash.clone(),
                                });
                            } else {
                                csr_hash_matched = true;
                            }
                        },
                        2 => {
                            let enclave_hash = value.as_bytes()
                                .ok_or(ProxyAttestationServerError::MissingFieldError("value.as_bytes()"))?;
                            received_enclave_hash = Some(enclave_hash.clone());
                        },
                        _ => (), // do nothing for other tags
                    }
                }
            }
        } else if index_value == 10 {
            received_challenge = Some(value.as_bytes()
                .ok_or(ProxyAttestationServerError::MissingFieldError("value.as_bytes()"))?
                .to_vec());
        }
    }
    if !csr_hash_matched {
        println!("proxy_attestation_server::attestation::psa::attestation_token csr hash failed to verify");
        return Err(ProxyAttestationServerError::MissingFieldError("csr_hash"));
    }

    if let Some(received_challenge_value) = received_challenge {
        if attestation_context.challenge[..] != received_challenge_value[..] {
            return Err(ProxyAttestationServerError::MismatchError {
                variable: "received_challenge_value",
                expected: attestation_context.challenge.to_vec(),
                received: received_challenge_value,
            });
        } else {
            println!("Challenges matched, biatch!");
        }
    } else {
        return Err(ProxyAttestationServerError::MissingFieldError("challenge"));
    }
    return Ok(payload_slice);
}

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
    let url = format!("192.168.32.3:8080/challenge-response/v1/newSession");
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
    let url = format!("192.168.32.3:8080{:}", verify_path);
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
