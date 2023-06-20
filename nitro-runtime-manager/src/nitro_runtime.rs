//! The AWS Nitro-specific runtime struct
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE_MIT.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

use anyhow::{anyhow, Result};
use nsm_api;
use nsm_lib;
use runtime_manager::{
    managers::{
        RuntimeManagerError,
        session_manager::{
            init_session_manager,
            generate_csr,
        }
    },
    platform_runtime::PlatformRuntime,
};
use veracruz_utils::{
    runtime_manager_message::RuntimeManagerResponse,
    sha256::sha256,
};

const NSM_MAX_ATTESTATION_DOC_SIZE: usize = 16 * 1024;

pub struct NitroRuntime {

}

impl PlatformRuntime for NitroRuntime {
    fn attestation(&self, challenge: &Vec<u8>) -> Result<RuntimeManagerResponse> {
        println!("runtime_manager_nitro::attestation started");
        init_session_manager()?;
        // generate the csr
        let csr: Vec<u8> = generate_csr()?;
        // generate the attestation document
        let mut att_doc: Vec<u8> = {
            let mut buffer: Vec<u8> = vec![0; NSM_MAX_ATTESTATION_DOC_SIZE];
            let mut buffer_len: u32 = buffer.len() as u32;
            let nsm_fd = nsm_lib::nsm_lib_init();
            if nsm_fd < 0 {
                return Err(anyhow!(RuntimeManagerError::NsmLibError(nsm_fd)));
            }
            let csr_hash = sha256(&csr);
            let status = unsafe {
                nsm_lib::nsm_get_attestation_doc(
                    nsm_fd,                         // fd
                    csr_hash.as_ptr() as *const u8, // user_data
                    csr_hash.len() as u32,          // user_data_len
                    challenge.as_ptr(),             // nonce_data
                    challenge.len() as u32,         // nonce_len
                    std::ptr::null() as *const u8,  // pub_key_data
                    0 as u32,                       // pub_key_len
                    buffer.as_mut_ptr(),            // att_doc_data
                    &mut buffer_len,                // att_doc_len
                )
            };
            match status {
                nsm_api::api::ErrorCode::Success => (),
                _ => return Err(anyhow!(RuntimeManagerError::NsmErrorCode(status))),
            }
            unsafe {
                buffer.set_len(buffer_len as usize);
            }
            buffer.clone()
        };
        att_doc.insert(0, 0xd2); // the golang implementation of cose needs this. Still need to investigate why

        return Ok(RuntimeManagerResponse::AttestationData(att_doc, csr));
    }
}
