//! The SGX root enclave
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

#![no_std]
#[macro_use]
extern crate sgx_tstd as std;

use lazy_static::lazy_static;
use psa_attestation;
use psa_attestation::{
    psa_initial_attest_get_token, psa_initial_attest_load_key, t_cose_sign1_get_verification_pubkey,
};
use sgx_tdh::{SgxDhInitiator, SgxDhMsg3};
use sgx_types;
use sgx_types::{
    sgx_create_report, sgx_dh_msg1_t, sgx_dh_msg2_t, sgx_dh_msg3_t,
    sgx_dh_session_enclave_identity_t, sgx_ec256_public_t, sgx_key_128bit_t, sgx_ra_context_t,
    sgx_ra_init, sgx_status_t, sgx_target_info_t,
};
use std::{collections::HashMap, mem, string::ToString};

lazy_static! {
    static ref SESSION_ID: std::sync::SgxMutex<u64> = std::sync::SgxMutex::new(0);
    static ref DEVICE_ID: std::sync::SgxMutex<Option<i32>> = std::sync::SgxMutex::new(None);
    static ref INITIATOR_HASH: std::sync::SgxMutex<HashMap<u64, SgxDhInitiator>> =
        std::sync::SgxMutex::new(HashMap::new());
    static ref KEYHANDLE: std::sync::SgxMutex<Option<u16>> = std::sync::SgxMutex::new(None);
}

#[no_mangle]
pub extern "C" fn get_firmware_version_len(p_fwv_len: &mut usize) -> sgx_status_t {
    let version = env!("CARGO_PKG_VERSION");
    *p_fwv_len = version.len();
    sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub extern "C" fn get_firmware_version(
    p_firmware_version_buf: *mut u8,
    fv_buf_size: usize,
) -> sgx_status_t {
    let version = env!("CARGO_PKG_VERSION");
    assert!(version.len() <= fv_buf_size);
    let version_buf_slice =
        unsafe { std::slice::from_raw_parts_mut(p_firmware_version_buf, fv_buf_size) };
    version_buf_slice.clone_from_slice(&version.as_bytes());
    sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub extern "C" fn init_remote_attestation_enc(
    pub_key_buf: *const u8,
    pub_key_size: usize,
    device_id: i32,
    p_context: *mut sgx_ra_context_t,
) -> sgx_status_t {
    assert!(pub_key_size != 0);
    assert!(!pub_key_buf.is_null());
    let pub_key_vec = unsafe { std::slice::from_raw_parts(pub_key_buf, pub_key_size) };

    let pub_key = sgx_ec256_public_t {
        gx: from_slice(&pub_key_vec[0..32]),
        gy: from_slice(&pub_key_vec[32..64]),
    };
    {
        let mut device_id_wrapper = DEVICE_ID.lock().expect("Failed to get lock on DEVICE_ID");
        *device_id_wrapper = Some(device_id); // intentionall obliterate any previous value
    }

    let mut context: sgx_ra_context_t = 0;
    assert!(pub_key_vec.len() > 0);
    let ret = unsafe {
        sgx_ra_init(
            &pub_key as *const sgx_ec256_public_t,
            0,
            &mut context as *mut sgx_ra_context_t,
        )
    };

    unsafe {
        *p_context = context;
    }

    ret
}

#[no_mangle]
pub extern "C" fn sgx_get_pubkey_report(
    p_pubkey_challenge: *const u8,
    pubkey_challenge_size: usize,
    p_target_info: *const sgx_target_info_t,
    report: *mut sgx_types::sgx_report_t,
) -> sgx_status_t {
    let pubkey_challenge_vec =
        unsafe { std::slice::from_raw_parts(p_pubkey_challenge, pubkey_challenge_size) };
    let mut report_data = sgx_types::sgx_report_data_t::default();

    let enclave_name = "TODOCRP".to_string();

    // place the challenge in the report
    report_data.d[0..pubkey_challenge_size].copy_from_slice(&pubkey_challenge_vec);

    let private_key = {
        let rng = ring::rand::SystemRandom::new();
        // ECDSA prime256r1 generation.
        let pkcs8_bytes = ring::signature::EcdsaKeyPair::generate_pkcs8(
            &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
            &rng,
        )
        .expect("Error generating PKCS-8");
        pkcs8_bytes.as_ref()[38..70].to_vec()
    };
    let mut key_handle: u16 = 0;
    let status = unsafe {
        psa_initial_attest_load_key(
            private_key.as_ptr(),
            private_key.len() as u64,
            &mut key_handle,
        )
    };
    assert!(status == 0);
    let mut public_key = std::vec::Vec::with_capacity(128); // TODO: Don't do this
    let mut public_key_size: u64 = 0;
    let ret = unsafe {
        t_cose_sign1_get_verification_pubkey(
            key_handle,
            public_key.as_mut_ptr() as *mut u8,
            public_key.capacity() as u64,
            &mut public_key_size as *mut u64,
        )
    };
    assert!(ret == 0);
    unsafe { public_key.set_len(public_key_size as usize) };

    // save the key handle
    {
        let mut key_handle_option = KEYHANDLE.lock().unwrap();
        match &*key_handle_option {
            Some(_) => {
                panic!("Unhandled case. Need to implement");
            }
            None => {
                *key_handle_option = Some(key_handle);
            }
        }
    }
    // // place the hash of the public key in the report
    let pubkey_hash = ring::digest::digest(&ring::digest::SHA256, public_key.as_ref());
    report_data.d[pubkey_challenge_size..48].copy_from_slice(pubkey_hash.as_ref());

    // place the enclave name in the report
    report_data.d[48..55].copy_from_slice(enclave_name.as_bytes());
    let ret = unsafe { sgx_create_report(p_target_info, &report_data, report) };
    assert!(ret == sgx_types::sgx_status_t::SGX_SUCCESS);

    sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub extern "C" fn start_local_attest_enc(
    msg1: &sgx_dh_msg1_t,
    msg2: &mut sgx_dh_msg2_t,
    sgx_root_enclave_session_id: &mut u64,
) -> sgx_status_t {
    let mut initiator = SgxDhInitiator::init_session();

    let status = initiator.proc_msg1(msg1, msg2);
    assert!(!status.is_err());
    let session_id = {
        let mut sess_id_wrap = SESSION_ID
            .lock()
            .expect("Failed to obtain lock on SESSION_ID");
        *sess_id_wrap = *sess_id_wrap + 1;
        *sess_id_wrap
    };

    {
        let mut initiator_hash = INITIATOR_HASH
            .lock()
            .expect("Failed to obtain lock on INITIATOR_HASH");
        initiator_hash.insert(session_id, initiator);
    }
    *sgx_root_enclave_session_id = session_id;

    sgx_status_t::SGX_SUCCESS
}

pub enum SgxRootEnclave {
    Success = 0x00,
    Msg3RawError = 0x01,
    ProcMsg3Error = 0x02,
}

#[no_mangle]
pub extern "C" fn finish_local_attest_enc(
    dh_msg3_raw: &mut sgx_dh_msg3_t,
    challenge: *const u8,
    challenge_size: usize,
    enclave_cert_hash: *const u8,
    enclave_cert_hash_size: usize,
    enclave_name: *const i8,
    enclave_name_size: usize,
    sgx_root_enclave_session_id: u64,
    token: *mut u8,
    token_buf_size: usize,
    token_size: *mut usize,
    p_pubkey: *mut u8,
    pubkey_buf_size: usize,
    p_pubkey_size: *mut usize,
    p_device_id: &mut i32,
) -> SgxRootEnclave {
    let dh_msg3_raw_len =
        mem::size_of::<sgx_dh_msg3_t>() as u32 + dh_msg3_raw.msg3_body.additional_prop_length;
    let dh_msg3 = unsafe { SgxDhMsg3::from_raw_dh_msg3_t(dh_msg3_raw, dh_msg3_raw_len) };
    assert!(!dh_msg3.is_none());
    if dh_msg3.is_none() {
        return SgxRootEnclave::Msg3RawError;
    }
    let dh_msg3 = dh_msg3.unwrap();
    {
        let mut initiator_hash = INITIATOR_HASH.lock().unwrap();
        let mut initiator = initiator_hash.remove(&sgx_root_enclave_session_id).unwrap();
        //.unwrap("Failed to get entry. Something is wrong");
        let mut dh_aek: sgx_key_128bit_t = sgx_key_128bit_t::default(); // Session Key, we won't use this

        let mut responder_identity = sgx_dh_session_enclave_identity_t::default();
        let status = initiator.proc_msg3(&dh_msg3, &mut dh_aek, &mut responder_identity);
        if status.is_err() {
            return SgxRootEnclave::ProcMsg3Error;
        }
        // TODO: Decide what/how we are going to put in the PSA Attestation token
        // cpu_svn? attributes?
        // mr_enclave definitely
        // mr_signer? isv_prod_id? isv_svn?
        let received_veracruz_hash = responder_identity.mr_enclave;

        let status = unsafe {
            psa_initial_attest_get_token(
                received_veracruz_hash.m.as_ptr() as *const u8,
                received_veracruz_hash.m.len() as u64,
                enclave_cert_hash,
                enclave_cert_hash_size as u64,
                enclave_name,
                enclave_name_size as u64,
                challenge,
                challenge_size as u64,
                token,
                token_buf_size as u64,
                token_size as *mut u64,
            )
        };
        assert!(status == 0);

        {
            let key_handle_option = KEYHANDLE.lock().unwrap();
            match &*key_handle_option {
                Some(key_handle) => {
                    let ret = unsafe {
                        t_cose_sign1_get_verification_pubkey(
                            *key_handle,
                            p_pubkey,
                            pubkey_buf_size as u64,
                            p_pubkey_size as *mut u64,
                        )
                    };
                    assert!(ret == 0);
                }
                None => {
                    panic!("Unhandled case. Need to implement");
                }
            }
        }
        *p_device_id = {
            let device_id_wrapper = DEVICE_ID.lock().expect("Failed to get lock on DEVICE_ID");
            device_id_wrapper.unwrap()
        };
    }

    SgxRootEnclave::Success
}

fn from_slice(bytes: &[u8]) -> [u8; 32] {
    let mut array = [0; 32];
    let bytes = &bytes[..array.len()]; // panics if not enough data
    for index in 0..32 {
        array[index] = bytes[index];
    }
    array
}
