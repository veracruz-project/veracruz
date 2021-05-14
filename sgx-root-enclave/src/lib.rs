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
use sgx_tdh::{SgxDhInitiator, SgxDhMsg3};
use sgx_types;
use sgx_types::{
    sgx_create_report, sgx_dh_msg1_t, sgx_dh_msg2_t, sgx_dh_msg3_t,
    sgx_dh_session_enclave_identity_t, sgx_ec256_public_t, sgx_key_128bit_t, sgx_ra_context_t,
    sgx_ra_init, sgx_status_t, sgx_target_info_t,
};
use std::{collections::HashMap, mem, sync::atomic::{AtomicU64, Ordering}};
use ring::{rand::SystemRandom, signature::EcdsaKeyPair};

use veracruz_utils::csr;

lazy_static! {
    static ref SESSION_ID: AtomicU64 = AtomicU64::new(1);
    static ref INITIATOR_HASH: std::sync::SgxMutex<HashMap<u64, SgxDhInitiator>> =
        std::sync::SgxMutex::new(HashMap::new());
    static ref PRIVATE_KEY: std::sync::SgxMutex<Option<std::vec::Vec<u8>>> = std::sync::SgxMutex::new(None);
    static ref CERT_CHAIN: std::sync::SgxMutex<Option<(std::vec::Vec<u8>, std::vec::Vec<u8>)>> = std::sync::SgxMutex::new(None);
}

pub enum SgxRootEnclave {
    Success = 0x00,
    Msg3RawError = 0x01,
    ProcMsg3Error = 0x02,
    CsrVerifyFail = 0x03,
    CsrToCertFail = 0x04,
    LockFail      = 0x05,
    HashError     = 0x06,
    PKCS8Error    = 0x07,
    StateError    = 0x08,
    PrivateKeyNotPopulated = 0x09,
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
    p_context: *mut sgx_ra_context_t,
) -> sgx_status_t {
    assert!(pub_key_size != 0);
    assert!(!pub_key_buf.is_null());
    let pub_key_vec = unsafe { std::slice::from_raw_parts(pub_key_buf, pub_key_size) };

    let pub_key = sgx_ec256_public_t {
        gx: from_slice(&pub_key_vec[0..32]),
        gy: from_slice(&pub_key_vec[32..64]),
    };

    let mut context: sgx_ra_context_t = 0;
    assert!(pub_key_vec.len() > 0);
    let ret = unsafe {
        sgx_ra_init(
            &pub_key as *const sgx_ec256_public_t,
            0,
            &mut context as *mut sgx_ra_context_t,
        )
    };
    if ret != sgx_status_t::SGX_SUCCESS {
        return ret;
    }

    unsafe {
        *p_context = context;
    }

    return ret;
}

/// Retrieve or generate the private key as a Vec<u8>
fn get_private_key() -> Result<std::vec::Vec<u8>, SgxRootEnclave> {
    let mut private_key_guard = match PRIVATE_KEY.lock() {
        Err(_) => return Err(SgxRootEnclave::LockFail),
        Ok(guard) => guard,
    };
    let pkcs8_bytes = match &*private_key_guard {
        Some(bytes) => {
            bytes.clone()
        }
        None => {
            // ECDSA prime256r1 generation.
            let pkcs8_bytes = EcdsaKeyPair::generate_pkcs8(
                &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
                &SystemRandom::new(),)
                    .map_err(|_| SgxRootEnclave::PKCS8Error)?;
            *private_key_guard = Some(pkcs8_bytes.as_ref().to_vec());
            pkcs8_bytes.as_ref().to_vec()
        }
    };
    return Ok(pkcs8_bytes);
}

#[no_mangle]
pub extern "C" fn sgx_get_collateral_report(
    p_pubkey_challenge: *const u8,
    pubkey_challenge_size: usize,
    p_target_info: *const sgx_target_info_t,
    report: *mut sgx_types::sgx_report_t,
    csr_buffer: *mut u8,
    csr_buf_size: usize,
    p_csr_size: *mut usize,
) -> sgx_status_t {
    let pubkey_challenge_vec =
        unsafe { std::slice::from_raw_parts(p_pubkey_challenge, pubkey_challenge_size) };
    let mut report_data = sgx_types::sgx_report_data_t::default();

    // place the challenge in the report
    report_data.d[0..pubkey_challenge_size].copy_from_slice(&pubkey_challenge_vec);

    let private_key_ring = {
        let private_key_vec = match get_private_key() {
            Ok(vec) => vec,
            Err(_) => return sgx_status_t::SGX_ERROR_UNEXPECTED,
        };
        match EcdsaKeyPair::from_pkcs8(&ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING, &private_key_vec) {
            Ok(pkr) => pkr,
            Err(_) => return sgx_status_t::SGX_ERROR_UNEXPECTED,
        }
    };

    // generate the certificate signing request
    let csr_vec = match csr::generate_csr(&csr::ROOT_ENCLAVE_CSR_TEMPLATE, &private_key_ring) {
        Ok(csr) => csr,
        Err(_) => return sgx_status_t::SGX_ERROR_UNEXPECTED,
    };

    // // place the hash of the csr in the report
    let collateral_hash = ring::digest::digest(&ring::digest::SHA256, &csr_vec);
    report_data.d[pubkey_challenge_size..48].copy_from_slice(collateral_hash.as_ref());

    let ret = unsafe { sgx_create_report(p_target_info, &report_data, report) };
    assert!(ret == sgx_types::sgx_status_t::SGX_SUCCESS);

    // place the csr where it needs to be
    if csr_vec.len() > csr_buf_size {
        assert!(false);
    } else {
        let csr_buf_slice = unsafe { std::slice::from_raw_parts_mut(csr_buffer, csr_vec.len()) };
        csr_buf_slice.clone_from_slice(&csr_vec);
        unsafe { *p_csr_size = csr_vec.len() };
    }

    sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub extern "C" fn sgx_send_cert_chain(
    root_cert: *const u8,
    root_cert_size: usize,
    enclave_cert: *const u8,
    enclave_cert_size: usize,
) -> sgx_status_t {
    let root_cert_slice = unsafe { std::slice::from_raw_parts(root_cert, root_cert_size) };
    let enclave_cert_slice = unsafe { std::slice::from_raw_parts(enclave_cert, enclave_cert_size) };

    let mut cert_chain_guard = match CERT_CHAIN.lock() {
        Err(_) => return sgx_status_t::SGX_ERROR_UNEXPECTED,
        Ok(guard) => guard,
    };
    match &*cert_chain_guard {
        Some(_) => {
            panic!("Unhandled. CERT_CHAIN is not None.");
        }
        None => {
            *cert_chain_guard = Some((enclave_cert_slice.to_vec(), root_cert_slice.to_vec()));
        }
    }
    return sgx_status_t::SGX_SUCCESS;
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
    let session_id = SESSION_ID.fetch_add(1, Ordering::SeqCst);

    {
        let mut initiator_hash = match INITIATOR_HASH.lock() {
            Err(_) => return sgx_status_t::SGX_ERROR_UNEXPECTED,
            Ok(guard) => guard,
        };
        initiator_hash.insert(session_id, initiator);
    }
    *sgx_root_enclave_session_id = session_id;

    sgx_status_t::SGX_SUCCESS
}

const CSR_BODY_LOCATION: (usize, usize) = (4, 4 + 218);
const CSR_PUBKEY_LOCATION: (usize, usize) = (129 + 26, 220);

fn verify_csr(csr: &[u8]) -> Result<bool, std::string::String> {
    let pubkey_bytes = &csr[CSR_PUBKEY_LOCATION.0..CSR_PUBKEY_LOCATION.1];
    let public_key = ring::signature::UnparsedPublicKey::new(&ring::signature::ECDSA_P256_SHA256_ASN1, pubkey_bytes);
    let csr_body = &csr[CSR_BODY_LOCATION.0..CSR_BODY_LOCATION.1];
    let csr_signature = &csr[237..];
    let verify_result = public_key.verify(&csr_body, &csr_signature);
    if verify_result.is_err() {
        return Err(format!("verify_csr failed:{:?}", verify_result));
    } else {
        return Ok(true);
    }
}

#[no_mangle]
pub extern "C" fn finish_local_attest_enc(
    dh_msg3_raw: &mut sgx_dh_msg3_t,
    csr: *const u8,
    csr_size: usize,
    sgx_root_enclave_session_id: u64,
    p_cert_buf: *mut u8,
    cert_buf_size: usize,
    p_cert_size: *mut usize,
    cert_lengths: *mut u32,
    cert_lengths_size: usize,
) -> SgxRootEnclave {
    let dh_msg3_raw_len =
        mem::size_of::<sgx_dh_msg3_t>() as u32 + dh_msg3_raw.msg3_body.additional_prop_length;
    let dh_msg3 = unsafe { SgxDhMsg3::from_raw_dh_msg3_t(dh_msg3_raw, dh_msg3_raw_len) };
    assert!(!dh_msg3.is_none());

    let dh_msg3 = match dh_msg3 {
        Some(msg) => msg,
        None => {
            return SgxRootEnclave::Msg3RawError;
        }
    };

    let mut initiator = {
        let mut initiator_hash = match INITIATOR_HASH.lock() {
            Err(_) => return SgxRootEnclave::LockFail,
            Ok(guard) => guard,
        };
        initiator_hash.remove(&sgx_root_enclave_session_id).unwrap()
    };

    let mut dh_aek: sgx_key_128bit_t = sgx_key_128bit_t::default(); // Session Key, we won't use this

    let mut responder_identity = sgx_dh_session_enclave_identity_t::default();
    let status = initiator.proc_msg3(&dh_msg3, &mut dh_aek, &mut responder_identity);
    if status.is_err() {
        return SgxRootEnclave::ProcMsg3Error;
    }

    // now that the msg3 is authenticated, we can generate the cert from the csr
    let csr_slice = unsafe { std::slice::from_raw_parts(csr, csr_size) };

    match verify_csr(&csr_slice) {
        Ok(status) => match status {
            true => (), // Do nothing
            false => {
                println!("CSR Did not verify successfully");
                return SgxRootEnclave::CsrVerifyFail;
            },
        },
        Err(err) => {
            println!("CSR did not verify:{:?}. Returning error", err);
            return SgxRootEnclave::CsrVerifyFail;
        },
    }

    //generate cert from csr, signed by PRIVATE_KEY
    let private_key = {
        let private_key_vec = match get_private_key() {
            Ok(key) => key,
            Err(_)  => return SgxRootEnclave::PrivateKeyNotPopulated,
        };
        match EcdsaKeyPair::from_pkcs8(&ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING, &private_key_vec) {
            Ok(key) => key,
            Err(_)  => return SgxRootEnclave::PKCS8Error,
        }
    };
    let mut compute_enclave_cert = match csr::convert_csr_to_cert(&csr_slice, &csr::COMPUTE_ENCLAVE_CERT_TEMPLATE, &responder_identity.mr_enclave.m, &private_key) {
        Ok(bytes) => bytes,
        Err(err) => {
            println!("Failed to convert csr to cert:{:?}", err);
            return SgxRootEnclave::CsrToCertFail;
        },
    };
    let (mut root_enclave_cert, mut root_cert) = {
        let cert_chain_guard = match CERT_CHAIN.lock() {
            Err(_) => return SgxRootEnclave::LockFail,
            Ok(guard) => guard,
        };
        match &*cert_chain_guard {
            Some((re_cert, r_cert)) => {
                (re_cert.clone(), r_cert.clone())
            }
            None => {
                panic!("CERT_CHAIN is not populated");
            },
        }
    };

    if cert_buf_size < (compute_enclave_cert.len() + root_enclave_cert.len() + root_cert.len()) {
        assert!(false);
    }
    let cert_buf_slice = unsafe { std::slice::from_raw_parts_mut(p_cert_buf, compute_enclave_cert.len() + root_enclave_cert.len() + root_cert.len()) };
    unsafe { *p_cert_size = compute_enclave_cert.len() + root_enclave_cert.len() + root_cert.len() };
    let cert_lengths_slice = unsafe { std::slice::from_raw_parts_mut(cert_lengths, cert_lengths_size/std::mem::size_of::<u32>()) };

    // create a buffer to aggregate the certificates
    let mut temp_cert_buf: std::vec::Vec<u8> = std::vec::Vec::new();
    let mut temp_cert_lengths: std::vec::Vec<u32> = std::vec::Vec::new();
    // add the compute_enclave_cert to the return buffer
    temp_cert_lengths.push(compute_enclave_cert.len() as u32);
    temp_cert_buf.append(&mut compute_enclave_cert);

    // add the root_enclave cert to the temp buffer
    temp_cert_lengths.push(root_enclave_cert.len() as u32);
    temp_cert_buf.append(&mut root_enclave_cert);

    // add the root cert to the temp buffer
    temp_cert_lengths.push(root_cert.len() as u32);
    temp_cert_buf.append(&mut root_cert);

    // Copy the temporary certificate buffer contents to the destination buffer
    cert_buf_slice.clone_from_slice(&temp_cert_buf);
    cert_lengths_slice.clone_from_slice(&temp_cert_lengths);

    return SgxRootEnclave::Success;
}

fn from_slice(bytes: &[u8]) -> [u8; 32] {
    let mut array = [0; 32];
    let bytes = &bytes[..array.len()]; // panics if not enough data
    for index in 0..32 {
        array[index] = bytes[index];
    }
    array
}
