//! Certificate Singing Request generation
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
use std::vec::Vec;
use err_derive::Error;
use mbedtls;
use platform_services::getrandom;

////////////////////////////////////////////////////////////////////////////////
// Error type.
////////////////////////////////////////////////////////////////////////////////

/// A generic catch-all error type for functionality related to policies.  This
/// error type contains more constructors when compiling for clients or hosts.
#[derive(Debug, Error)]
pub enum CertError {
    #[error(
        display = "CertError: Invalid UTC Inputs: M:{}, D:{}, H:{}, min:{}, s:{}",
        month,
        day,
        hour,
        minute,
        second
    )]
    InvalidUtcInputs {
        month: u32,
        day: u32,
        hour: u32,
        minute: u32,
        second: u32,
    },
}

pub fn generate_csr(private_key_der: &[u8]) -> Result<Vec<u8>> {
    let mut pk_private = mbedtls::pk::Pk::from_private_key(private_key_der, None).unwrap();
    let mut rng = |buffer: *mut u8, size: usize| {
        let mut slice = unsafe { std::slice::from_raw_parts_mut(buffer, size) };
        getrandom(&mut slice);
        0
    };
    let csr = mbedtls::x509::csr::Builder::new()
        .key(&mut pk_private)
        .subject("C=US")
        .unwrap()
        .subject("ST=Texas")
        .unwrap()
        .subject("L=Austin")
        .unwrap()
        .subject("O=Veracruz")
        .unwrap()
        .subject("OU=Compute Enclave")
        .unwrap()
        .subject("CN=VeracruzCompute")
        .unwrap()
        .signature_hash(mbedtls::hash::Type::Sha256)
        .write_der_vec(&mut rng)
        .unwrap();
    Ok(csr)
}

pub fn generate_utc_time(
    year: u32,
    month: u32,
    day: u32,
    hour: u32,
    minute: u32,
    second: u32,
) -> Result<Vec<u8>> {
    if month > 11 || day > 30 || hour > 23 || minute > 59 || second > 59 {
        return Err(anyhow!(CertError::InvalidUtcInputs {
            month,
            day,
            hour,
            minute,
            second,
        }));
    }
    let year = year % 2000;
    let generated_time = format!(
        "{:02}{:02}{:02}{:02}{:02}{:02}Z",
        year, month, day, hour, minute, second
    );
    return Ok(generated_time.as_bytes().to_vec());
}
