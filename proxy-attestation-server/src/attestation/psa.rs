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
use lazy_static::lazy_static;
use psa_attestation::{
    q_useful_buf_c, t_cose_crypto_lib_t_T_COSE_CRYPTO_LIB_PSA, t_cose_key,
    t_cose_key__bindgen_ty_1, t_cose_parameters, t_cose_sign1_set_verification_key,
    t_cose_sign1_verify, t_cose_sign1_verify_ctx, t_cose_sign1_verify_delete_public_key,
    t_cose_sign1_verify_init, t_cose_sign1_verify_load_public_key,
};
use rand::Rng;
use std::{collections::HashMap, io::Read, ffi::c_void, sync::Mutex};

// Yes, I'm doing what you think I'm doing here. Each instance of the SGX root enclave
// will have the same public key. Yes, I'm embedding that key in the source
// code. I could come up with a complicated system for auto generating a key
// for each instance, and then populate the device database with they key.
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
        challenge: challenge.clone(),
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

    let parsed = transport_protocol::parse_proxy_attestation_server_request(&received_bytes)?;
    if !parsed.has_native_psa_attestation_token() {
        println!("proxy-attestation-server::attestation::psa::attestation_token received data is incorrect.");
        return Err(ProxyAttestationServerError::MissingFieldError(
            "native_psa_attestation_token",
        ));
    }
    let (token, csr, device_id) =
        transport_protocol::parse_native_psa_attestation_token(&parsed.get_native_psa_attestation_token());

    let attestation_context = {
        let ac_hash = ATTESTATION_CONTEXT.lock()?;
        let context = ac_hash
            .get(&device_id)
            .ok_or(ProxyAttestationServerError::NoDeviceError(device_id))?;
        (*context).clone()
    };

    let mut t_cose_ctx: t_cose_sign1_verify_ctx = unsafe { ::std::mem::zeroed() };
    unsafe { t_cose_sign1_verify_init(&mut t_cose_ctx, 0) };

    let mut key_handle: u16 = 0;
    let lpk_ret = unsafe {
        t_cose_sign1_verify_load_public_key(
            &PUBLIC_KEY as *const u8,
            PUBLIC_KEY.len() as u64,
            &mut key_handle,
        )
    };
    if lpk_ret != 0 {
        return Err(ProxyAttestationServerError::UnsafeCallError(
            "attestation_token t_cose_sign1_verify_load_public_key",
            lpk_ret,
        ));
    }

    let cose_key = t_cose_key {
        crypto_lib: t_cose_crypto_lib_t_T_COSE_CRYPTO_LIB_PSA,
        k: t_cose_key__bindgen_ty_1 {
            key_handle: key_handle as u64,
        },
    };
    unsafe { t_cose_sign1_set_verification_key(&mut t_cose_ctx, cose_key) };
    let sign1 = q_useful_buf_c {
        ptr: token.as_ptr() as *mut c_void,
        len: token.len() as u64,
    };
    let mut payload_vec = Vec::with_capacity(token.len());
    let mut payload = q_useful_buf_c {
        ptr: payload_vec.as_mut_ptr() as *mut c_void,
        len: payload_vec.capacity() as u64,
    };

    let mut decoded_parameters: t_cose_parameters = unsafe { ::std::mem::zeroed() };

    let sv_ret = unsafe {
        t_cose_sign1_verify(
            &mut t_cose_ctx,
            sign1,
            &mut payload,
            &mut decoded_parameters,
        )
    };
    // remove the key from storage
    let dpk_ret = unsafe { t_cose_sign1_verify_delete_public_key(&mut key_handle) };
    if dpk_ret != 0 {
        println!("proxy-attestation-server::attestation::psa_attestation_token Was unable to delete public key, and received the error code:{:?}.
                  I can't do anything about it, and it may not cause a problem right now, but this will probably end badly for you.", dpk_ret);
    }

    if sv_ret != 0 {
        println!("sv_ret:{:}", sv_ret);
        return Err(ProxyAttestationServerError::UnsafeCallError(
            "attestation_token t_cose_sign1_verify",
            sv_ret,
        ));
    }
    let payload_vec =
        unsafe { std::slice::from_raw_parts(payload.ptr as *const u8, payload.len as usize) };
    if attestation_context.challenge != payload_vec[8..40] {
        return Err(ProxyAttestationServerError::MismatchError {
            variable: "payload_vec[8..40]",
            expected: attestation_context.challenge.to_vec(),
            received: payload_vec[8..40].to_vec(),
        });
    }

    let received_csr_hash = &payload_vec[86..118];
    let calculated_csr_hash = ring::digest::digest(&ring::digest::SHA256, &csr);
    if received_csr_hash != calculated_csr_hash.as_ref() {
        println!("proxy_attestation_server::attestation::psa::attestation_token csr hash failed to verify");
        return Err(ProxyAttestationServerError::MismatchError {
            variable: "received_csr_hash",
            expected: calculated_csr_hash.as_ref().to_vec(),
            received: received_csr_hash.to_vec(),
        });
    }

    let received_enclave_hash: Vec<u8> = payload_vec[47..79].to_vec();

    let expected_enclave_hash: Vec<u8> = {
        let connection = crate::orm::establish_connection()?;
        crate::orm::get_firmware_version_hash(
            &connection,
            &"psa".to_string(),
            &attestation_context.firmware_version,
        )?
        .ok_or(ProxyAttestationServerError::MissingFieldError("firmware version"))?
    };
    if expected_enclave_hash != received_enclave_hash {
        return Err(ProxyAttestationServerError::MismatchError {
            variable: "received_enclave_hash",
            expected: expected_enclave_hash,
            received: received_enclave_hash.to_vec(),
        });
    }
    let cert = crate::attestation::convert_csr_to_certificate(&csr, false, &received_enclave_hash)
        .map_err(|err| {
            println!("proxy-attestation-server::attestation::psa::attestation_token convert_csr_to_certificate failed:{:?}", err);
            err
        })?;

    let root_cert_der = crate::attestation::get_ca_certificate()?;

    let response_bytes = transport_protocol::serialize_cert_chain(&cert.to_der()?, &root_cert_der)?;
        
    let response_b64 = base64::encode(&response_bytes);

    // clean up the Attestation Context by removing this context
    {
        let mut ac_hash = ATTESTATION_CONTEXT.lock()?;
        ac_hash.remove(&device_id);
    }

    return Ok(response_b64);
}
