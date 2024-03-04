//! The SEV-specific runtime struct
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

use runtime_manager::{
    managers::{
        RuntimeManagerError,
        session_manager::{
            init_session_manager,
            generate_csr,
        },
    },
    platform_runtime::PlatformRuntime
};
use sev_snp_utils::{AttestationReport, Requester};
use std::io::Write;
use veracruz_utils::{
    runtime_manager_message::RuntimeManagerResponse,
    sha256::sha256,
};

// Got this by doing the math on the `struct attestation_report`
// in https://github.com/AMDESE/sev-guest/blob/main/include/attestation.h
// (actually it was 1184, but I rounded up)
// 0x2a0 + 72 +72 + (512-144)
const ATTESTATION_REPORT_SIZE: usize = 1184;

extern "C" {
    fn get_report(data: *const u8, data_size: usize, report: *mut u8)-> i32;
    fn get_extended_report(data: *const u8, data_size: usize, report: *mut u8, certs: *mut *mut u8, cert_size: *mut usize) -> i32;
}

pub struct SevRuntime {

}

impl PlatformRuntime for SevRuntime {
    fn attestation(&self, challenge: &Vec<u8>) -> Result<RuntimeManagerResponse> {
        println!("sev-runtime-manager::SevRuntime::attestation started");
        init_session_manager()
            .map_err(|err| {
                println!("sev-runtime-manager::SevRuntime::attestation init_session_manager failed:{:?}", err);
                err
            })?;
        let csr: Vec<u8> = generate_csr()
            .map_err(|err| {
                println!("sev-runtime-manager::SevRuntime::attestation generate_csr failed:{:?}", err);
                err
            })?;
        let csr_hash = sha256(&csr);
        let mut user_data: [u8; 64] = [0; 64];
        user_data[0..32].copy_from_slice(&csr_hash[0..32]);
        let attestation_report = AttestationReport::request_raw(&user_data).unwrap();
        let response = RuntimeManagerResponse::AttestationData(attestation_report, csr);
        return Ok(response);
    }
}