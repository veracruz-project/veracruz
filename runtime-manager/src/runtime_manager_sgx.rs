//! Intel SGX-specific material for the Runtime Manager enclave
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
pub use crate::managers::RuntimeManagerError;

use sgx_tdh::{SgxDhMsg1, SgxDhMsg2, SgxDhMsg3, SgxDhResponder};
use sgx_types::{
    c_char, sgx_dh_msg1_t, sgx_dh_msg2_t, sgx_dh_msg3_t, sgx_dh_session_enclave_identity_t,
    sgx_key_128bit_t, sgx_status_t,
};
use std::mem;
use crate::managers::debug_message;

extern "C" {
    pub fn start_local_attest_ocall(
        ret: &mut sgx_status_t,
        dh_msg1: &sgx_dh_msg1_t,
        dh_msg2: &mut sgx_dh_msg2_t,
        sgx_root_enclave_session_id: &mut u64,
    ) -> sgx_status_t;

    pub fn finish_local_attest_ocall(
        ret: &mut sgx_status_t,
        dh_msg3: &sgx_dh_msg3_t,
        csr: *const u8,
        csr_size: usize,
        sgx_root_enclave_session_id: u64,
        cert: *mut u8,
        cert_buf_size: usize,
        cert_size: &mut usize,
        cert_lengths: *mut u32,
        cert_lengths_size: usize,
    ) -> sgx_status_t;

    pub fn debug_and_error_output_ocall(
        ret: &mut sgx_status_t,
        message: *const c_char,
        errro_code: u32,
    ) -> sgx_status_t;
}

#[no_mangle]
#[cfg(feature = "sgx")]
pub extern "C" fn init_session_manager_enc(
    policy_buf: *const u8,
    policy_buf_size: usize,
) -> sgx_status_t {
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
    if ret.is_err() {
        println!("runtime_manager_sgx::init_session_manager_enc failed session_manager:{:?}", ret);
        return sgx_status_t::SGX_ERROR_UNEXPECTED
    }

    debug_message(format!("init_session_manager_enc getting csr"));
    // TODO: Make this conditional on a field in the policy
    let csr_result = managers::session_manager::generate_csr();
    let csr = match csr_result {
        Ok(val) => val,
        Err(err) => {
            println!("runtime_manager_sgx::init_session_manager_enc call to get_csr failed:{:?}", err);
            return sgx_status_t::SGX_ERROR_UNEXPECTED; 
        }
    };

    let certs = match local_attestation_get_cert_enc(&csr) {
        Ok(data) => data,
        Err(e)  => {
            println!("runtime_manager_sgx::init_session_manager_enc call to local_attestation_get_cert_enc failed:{:?}", e);
            return sgx_status_t::SGX_ERROR_UNEXPECTED;
        }
    };

    match managers::session_manager::load_cert_chain(certs) {
        Ok(_) => (),
        Err(e) => {
            println!("runtime_manager_sgx::init_session_manager_enc call to load_cert_chain failed:{:?}", e);
            return sgx_status_t::SGX_ERROR_UNEXPECTED;
        }
    }

    return sgx_status_t::SGX_SUCCESS;
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

#[cfg(feature = "sgx")]
fn local_attestation_get_cert_enc(
    csr: &std::vec::Vec<u8>,
) -> Result<std::vec::Vec<std::vec::Vec<u8>>, RuntimeManagerError> {
    let mut dh_msg1: SgxDhMsg1 = SgxDhMsg1::default();

    let mut responder = SgxDhResponder::init_session();
    responder.gen_msg1(&mut dh_msg1)?;

    let mut dh_msg2: SgxDhMsg2 = SgxDhMsg2::default();
    let mut ocall_ret = sgx_status_t::SGX_SUCCESS;
    let mut sgx_root_enclave_session_id: u64 = 0;
    let ocall_status = unsafe {
        start_local_attest_ocall(
            &mut ocall_ret,
            &dh_msg1,
            &mut dh_msg2,
            &mut sgx_root_enclave_session_id,
        )
    };
    if ocall_status != sgx_status_t::SGX_SUCCESS {
        return Err(RuntimeManagerError::SGXError(ocall_status));
    }
    if ocall_ret != sgx_status_t::SGX_SUCCESS {
        return Err(RuntimeManagerError::SGXError(ocall_ret));
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

    let mut ocall_ret = sgx_status_t::SGX_SUCCESS;

    // It's diffucult/annoying to pass 2d rust Vecs to C. Instead, we will create
    // a 1D array to contain all of the certifcates, one after the other
    let mut cert_array: std::vec::Vec<u8> = std::vec::Vec::with_capacity(3 * 2048);
    // Upon return, will contain the complete size of the `cert_array`
    let mut cert_array_size: usize = 0;
    // The certificate_lengths vec, which on return will contain the lengths of
    // each of the certificates. This will allow us to break `cert_array` on
    // the certificate boundaries.
    let mut certificate_lengths: std::vec::Vec<u32> = vec!(0, 0, 0);

    let ocall_status = unsafe {
        finish_local_attest_ocall(
            &mut ocall_ret,
            &dh_msg3_raw,
            csr.as_ptr() as *const u8,
            csr.len(),
            sgx_root_enclave_session_id,
            cert_array.as_mut_ptr() as *mut u8,
            cert_array.capacity(),
            &mut cert_array_size,
            certificate_lengths.as_mut_ptr() as *mut u32,
            certificate_lengths.len() * std::mem::size_of::<u32>(),
        )
    };
    // need to check both return values. the status and the ret
    if ocall_status != sgx_status_t::SGX_SUCCESS {
        return Err(RuntimeManagerError::SGXError(ocall_status));
    }
    if ocall_ret != sgx_status_t::SGX_SUCCESS {
        return Err(RuntimeManagerError::SGXError(ocall_ret));
    }

    // Set the length of cert_array according to what the ocall told us
    unsafe { cert_array.set_len(cert_array_size) };

    let certs: std::vec::Vec< std::vec::Vec<u8> > = 
        crate::runtime_manager::break_up_cert_array(&cert_array, &certificate_lengths)?;

    return Ok(certs);
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
                "runtime_manager::tls_send_data_enc session_manager::send_data failed with err:{:?}",
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

