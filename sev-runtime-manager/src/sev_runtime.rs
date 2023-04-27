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

use runtime_manager_enclave::{
    managers::{
        RuntimeManagerError,
        session_manager::{
            init_session_manager,
            generate_csr,
        },
    },
    platform_runtime::PlatformRuntime};
use veracruz_utils::runtime_manager_message::RuntimeManagerResponse;

// Got this by doing the math on the `struct attestation_report`
// in https://github.com/AMDESE/sev-guest/blob/main/include/attestation.h
// (actually it was 1184, but I rounded up)
// 0x2a0 + 72 +72 + (512-144)
const ATTESTATION_REPORT_SIZE: usize = 1184;

extern "C" {
    fn get_report(data: *const u8, data_size: usize, report: *mut u8)-> i32;
}

pub struct SevRuntime {

}

impl PlatformRuntime for SevRuntime {
    fn attestation(&self, challenge: &Vec<u8>) -> Result<RuntimeManagerResponse> {
        println!("sev-runtime-manager::SevRuntime::attestation started");
        init_session_manager()?;
        let csr: Vec<u8> = generate_csr()?;
        let mut attestation_report: Vec<u8> = vec![0; ATTESTATION_REPORT_SIZE];

        let retval = unsafe { get_report(csr.as_ptr(), csr.len(), attestation_report.as_mut_ptr()) };
        if retval != 0 {
            return Err(anyhow!(RuntimeManagerError::FirmwareError));
        }

        let response = RuntimeManagerResponse::AttestationData(attestation_report, csr);
        return Ok(response);
    }
}
