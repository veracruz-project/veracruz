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
    platform_runtime::PlatformRuntime
};
use std::io::Write;
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
        let mut attestation_report = Vec::with_capacity(ATTESTATION_REPORT_SIZE);

        {
            println!("sev-runtime-manager::SevRuntime::attestation writing csr file");
            let mut file = std::fs::File::create("/root/csr.dat")?;
            // Write a slice of bytes to the file
            file.write_all(&csr)?;
            println!("sev-runtime-manager::SevRuntime::attestation csr file completed write");
        }
        println!("sev-runtime-manager::SevRuntime::attestation calling get_report with 32");
        let retval = unsafe { get_report(csr.as_ptr() as *const u8, 32 /*csr.len()*/, attestation_report.as_mut_ptr() as *mut u8) };
        println!("sev-runtime-manager::SevRuntime::attestation get_report returned");
        if retval != 0 {
            println!("sev-runtime-manager::SevRuntime::attestation get_report returned:{:?}", retval);
            return Err(anyhow!(RuntimeManagerError::FirmwareError));
        }
        unsafe { attestation_report.set_len(ATTESTATION_REPORT_SIZE as usize)};
        println!("sev-runtime-manager::SevRuntime::attestation get_report suceeded");

        let response = RuntimeManagerResponse::AttestationData(attestation_report, csr);
        return Ok(response);
    }
}
