//! Intel SGX-specific material for the Mexico City enclave
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

pub use crate::managers;
pub use crate::managers::MexicoCityError;

use sgx_tdh::{SgxDhMsg1, SgxDhMsg2, SgxDhMsg3, SgxDhResponder};
use sgx_types::{
    c_char, sgx_dh_msg1_t, sgx_dh_msg2_t, sgx_dh_msg3_t, sgx_dh_session_enclave_identity_t,
    sgx_key_128bit_t, sgx_status_t,
};
use std::mem;

extern "C" {
    pub fn start_local_attest_ocall(
        ret: &mut sgx_status_t,
        dh_msg1: &sgx_dh_msg1_t,
        dh_msg2: &mut sgx_dh_msg2_t,
        trustzone_root_enclave_session_id: &mut u64,
    ) -> sgx_status_t;

    pub fn finish_local_attest_ocall(
        ret: &mut sgx_status_t,
        dh_msg3: &sgx_dh_msg3_t,
        challenge: *const u8,
        challenge_size: usize,
        enclave_cert_hash: *const u8,
        enclave_cert_hash_size: usize,
        enclave_name: *const i8,
        enclave_name_size: usize,
        trustzone_root_enclave_session_id: u64,
        token: *mut u8,
        token_buf_size: usize,
        token_size: &mut usize,
        p_pubkey: *mut u8,
        pubkey_buf_size: usize,
        p_pubkey_size: *mut usize,
        p_device_id: *mut i32,
    ) -> sgx_status_t;

    pub fn debug_and_error_output_ocall(
        ret: &mut sgx_status_t,
        message: *const c_char,
        errro_code: u32,
    ) -> sgx_status_t;
}

#[no_mangle]
#[cfg(feature = "sgx")]
pub extern "C" fn init_session_manager_enc(policy_buf: *const u8, policy_buf_size: usize) -> sgx_status_t {
    if policy_buf_size == 0 && policy_buf.is_null() {
        return sgx_status_t::SGX_ERROR_UNEXPECTED;
    }
    let policy_vec = unsafe { std::slice::from_raw_parts(policy_buf, policy_buf_size) };
    if policy_vec.len() == 0 {
        return sgx_status_t::SGX_ERROR_UNEXPECTED;
    }
    let policy_str = match std::str::from_utf8(policy_vec) {
        Ok(policy_str) => policy_str,
        Err(_) => return sgx_status_t::SGX_ERROR_UNEXPECTED,
    };

    let ret = crate::managers::session_manager::init_session_manager(&policy_str);
    if ret.is_ok() {
        sgx_status_t::SGX_SUCCESS
    } else {
        println!("mc_sgx::init_session_manager_enc failed session_manager:{:?}", ret);
        sgx_status_t::SGX_ERROR_UNEXPECTED
    }
}

#[no_mangle]
#[cfg(feature = "sgx")]
pub extern "C" fn new_session_enc(session_id: *mut u32) -> sgx_status_t {
    match managers::session_manager::new_session() {
        Ok(local_session_id) => {
            unsafe {
                *session_id = local_session_id;
            }
            sgx_status_t::SGX_SUCCESS
        }
        Err(_) => sgx_status_t::SGX_ERROR_UNEXPECTED,
    }
}

#[no_mangle]
#[cfg(feature = "sgx")]
pub extern "C" fn close_session_enc(session_id: u32) -> sgx_status_t {
    match managers::session_manager::close_session(session_id) {
        Ok(_) => sgx_status_t::SGX_SUCCESS,
        Err(_) => sgx_status_t::SGX_ERROR_UNEXPECTED,
    }
}

#[no_mangle]
#[cfg(feature = "sgx")]
pub extern "C" fn psa_attestation_get_token_enc(
    challenge: *const u8,
    challenge_size: usize,
    token: *mut u8,
    token_buf_size: usize,
    token_size: &mut usize,
    p_pubkey: *mut u8,
    pubkey_buf_size: usize,
    p_pubkey_size: *mut usize,
    p_device_id: *mut i32,
) -> sgx_status_t {
    // The below construct is intended to mimic the behavior of
    // ffi_utils::catch_unwind_result (which we can't use because our stdlib
    // doesn't support it)
    // What we are doing:
    // 1. create a closure that returns Result<(), String>. Errors inside the
    //    closure can use the ? operator or call return Err...
    // 2. call the closure and match the Result. Return 0 for no error,
    //    non-zero for Err
    let mut body_closure = || -> Result<(), MexicoCityError> {
        *token_size = 0;
        let mut dh_msg1: SgxDhMsg1 = SgxDhMsg1::default();

        let mut responder = SgxDhResponder::init_session();
        responder.gen_msg1(&mut dh_msg1)?;

        let mut dh_msg2: SgxDhMsg2 = SgxDhMsg2::default();
        let mut ocall_ret = sgx_status_t::SGX_SUCCESS;
        let mut trustzone_root_enclave_session_id: u64 = 0;
        let ocall_status = unsafe {
            start_local_attest_ocall(
                &mut ocall_ret,
                &dh_msg1,
                &mut dh_msg2,
                &mut trustzone_root_enclave_session_id,
            )
        };
        if ocall_status != sgx_status_t::SGX_SUCCESS {
            return Err(MexicoCityError::SGXError(ocall_status));
        }
        if ocall_ret != sgx_status_t::SGX_SUCCESS {
            return Err(MexicoCityError::SGXError(ocall_ret));
        }

        let mut dh_msg3 = SgxDhMsg3::default();
        let mut dh_aek = sgx_key_128bit_t::default(); // session key. Will not use
        let mut initiator_identity = sgx_dh_session_enclave_identity_t::default();
        responder.proc_msg2(&dh_msg2, &mut dh_msg3, &mut dh_aek, &mut initiator_identity)?;

        let mut dh_msg3_raw = sgx_dh_msg3_t::default();

        unsafe {
            dh_msg3.to_raw_dh_msg3_t(
                &mut dh_msg3_raw,
                (dh_msg3_raw.msg3_body.additional_prop_length as usize
                    + mem::size_of::<sgx_dh_msg3_t>()) as u32,
            )
        };

        let enclave_cert = managers::session_manager::get_enclave_cert()?;

        let enclave_cert_hash = ring::digest::digest(&ring::digest::SHA256, enclave_cert.as_ref());

        let mut ocall_ret = sgx_status_t::SGX_SUCCESS;

        let enclave_name: std::string::String = managers::session_manager::get_enclave_name()?;

        let ocall_status = unsafe {
            finish_local_attest_ocall(
                &mut ocall_ret,
                &dh_msg3_raw,
                challenge,
                challenge_size,
                enclave_cert_hash.as_ref().as_ptr() as *const u8,
                enclave_cert_hash.as_ref().len(),
                enclave_name.as_ptr() as *const i8,
                enclave_name.len(),
                trustzone_root_enclave_session_id,
                token,
                token_buf_size,
                token_size,
                p_pubkey,
                pubkey_buf_size,
                p_pubkey_size,
                p_device_id,
            )
        };
        if ocall_status != sgx_status_t::SGX_SUCCESS {
            return Err(MexicoCityError::SGXError(ocall_status));
        }
        if ocall_ret != sgx_status_t::SGX_SUCCESS {
            return Err(MexicoCityError::SGXError(ocall_ret));
        }
        return Ok(());
    };
    match body_closure() {
        Ok(_) => return sgx_status_t::SGX_SUCCESS,
        Err(err) => {
            println!(
                "mc::psa_attestation_get_token_enc returning an error:{:?}",
                err
            );
            return sgx_status_t::SGX_ERROR_INVALID_STATE;
        }
    }
}

#[no_mangle]
#[cfg(feature = "sgx")]
pub extern "C" fn tls_send_data_enc(
    session_id: u32,
    input_buf: *const u8,
    input_size: usize,
) -> sgx_status_t {
    let input_vec = unsafe { std::slice::from_raw_parts(input_buf, input_size) };

    match managers::session_manager::send_data(session_id, &input_vec) {
        Ok(_) => sgx_status_t::SGX_SUCCESS,
        Err(err) => {
            println!(
                "mc::tls_send_data_enc session_manager::send_data failed with err:{:?}",
                err
            );
            sgx_status_t::SGX_ERROR_UNEXPECTED
        }
    }
}

#[no_mangle]
#[cfg(feature = "sgx")]
pub extern "C" fn tls_get_data_enc(
    session_id: u32,
    output_buf: *mut u8,
    output_buf_size: usize,
    output_data_size: &mut usize,
    active_flag: &mut u8,
) -> sgx_status_t {
    match managers::session_manager::get_data(session_id) {
        Ok((active_bool, output_data)) => {
            let output_buf_slice =
                unsafe { std::slice::from_raw_parts_mut(output_buf, output_buf_size) };
            output_buf_slice[..output_data.len()].copy_from_slice(&output_data[..]);
            if output_data.len() < output_buf_size {
                *output_data_size = output_data.len();
                *active_flag = if active_bool { 1 } else { 0 };
                sgx_status_t::SGX_SUCCESS
            } else {
                sgx_status_t::SGX_ERROR_UNEXPECTED
            }
        }
        Err(_) => sgx_status_t::SGX_ERROR_UNEXPECTED,
    }
}

#[no_mangle]
#[cfg(feature = "sgx")]
pub extern "C" fn tls_get_data_needed_enc(session_id: u32, needed: *mut u8) -> sgx_status_t {
    match managers::session_manager::get_data_needed(session_id) {
        Ok(local_needed) => {
            if local_needed {
                unsafe { *needed = 1 };
            } else {
                unsafe { *needed = 0 };
            }
            sgx_status_t::SGX_SUCCESS
        }
        Err(_) => sgx_status_t::SGX_ERROR_UNEXPECTED,
    }
}

#[no_mangle]
#[cfg(feature = "sgx")]
pub extern "C" fn get_enclave_cert_len_enc(cert_buf_len: &mut usize) -> sgx_status_t {
    match managers::session_manager::get_enclave_cert_pem() {
        Ok(cert) => {
            *cert_buf_len = cert.len();
            sgx_status_t::SGX_SUCCESS
        }
        Err(_) => sgx_status_t::SGX_ERROR_UNEXPECTED,
    }
}

#[no_mangle]
#[cfg(feature = "sgx")]
pub extern "C" fn get_enclave_cert_enc(
    cert_buf: *mut u8,
    cert_buf_size: usize,
    cert_buf_len: &mut usize,
) -> sgx_status_t {
    match managers::session_manager::get_enclave_cert_pem() {
        Ok(cert) => {
            if cert.len() <= cert_buf_size {
                let cert_buf_slice =
                    unsafe { std::slice::from_raw_parts_mut(cert_buf, cert_buf_size) };
                cert_buf_slice.clone_from_slice(&cert[..]);
                *cert_buf_len = cert.len();
                sgx_status_t::SGX_SUCCESS
            } else {
                sgx_status_t::SGX_ERROR_UNEXPECTED
            }
        }
        Err(_) => sgx_status_t::SGX_ERROR_UNEXPECTED,
    }
}

#[no_mangle]
#[cfg(feature = "sgx")]
pub extern "C" fn get_enclave_name_len_enc(name_len: &mut usize) -> sgx_status_t {
    match managers::session_manager::get_enclave_name() {
        Ok(name) => {
            *name_len = name.len();
            sgx_status_t::SGX_SUCCESS
        }
        Err(_) => sgx_status_t::SGX_ERROR_UNEXPECTED,
    }
}

#[no_mangle]
#[cfg(feature = "sgx")]
pub extern "C" fn get_enclave_name_enc(name_buf: *mut u8, name_buf_size: usize) -> sgx_status_t {
    match managers::session_manager::get_enclave_name() {
        Ok(name) => {
            if name.len() <= name_buf_size {
                let name_buf_slice =
                    unsafe { std::slice::from_raw_parts_mut(name_buf, name_buf_size) };
                name_buf_slice.clone_from_slice(&name.as_bytes());
                sgx_status_t::SGX_SUCCESS
            } else {
                sgx_status_t::SGX_ERROR_UNEXPECTED
            }
        }
        Err(_) => sgx_status_t::SGX_ERROR_UNEXPECTED,
    }
}
