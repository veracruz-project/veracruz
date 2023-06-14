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
use serde_bytes;
use veracruz_utils::{
    runtime_manager_message::RuntimeManagerResponse,
    sha256::sha256,
};

pub struct NitroRuntime {

}

impl PlatformRuntime for NitroRuntime {
    fn attestation(&self, challenge: &Vec<u8>) -> Result<RuntimeManagerResponse> {
        println!("runtime_manager_nitro::attestation started");
        init_session_manager()?;
        // generate the csr
        let csr: Vec<u8> = generate_csr()?;

        let csr_hash = sha256(&csr);
        let nsm_fd = nsm_api::driver::nsm_init();
        if nsm_fd < 0 {
            let e = nsm_api::api::ErrorCode::InternalError;
            return Err(anyhow!(RuntimeManagerError::NsmErrorCode(e)));
        }

        let request = nsm_api::api::Request::Attestation{
            user_data: Some(serde_bytes::ByteBuf::from(csr_hash)),
            nonce: Some(serde_bytes::ByteBuf::from(challenge.clone())),
            public_key: None
        };
        // generate the attestation document
        let response = nsm_api::driver::nsm_process_request(nsm_fd, request);
        nsm_api::driver::nsm_exit(nsm_fd);

        match response {
            nsm_api::api::Response::Attestation { document } => {
                let mut att_doc = document.clone();
                att_doc.insert(0, 0xd2); // the golang implementation of cose needs this. Still need to investigate why
                Ok(RuntimeManagerResponse::AttestationData(att_doc, csr))
            },
            nsm_api::api::Response::Error(e) => {
                Err(anyhow!(RuntimeManagerError::NsmErrorCode(e)))
            },
            _ => {
                let e = nsm_api::api::ErrorCode::InvalidResponse;
                Err(anyhow!(RuntimeManagerError::NsmErrorCode(e)))
            },
        }
    }
}
