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

use std::vec::Vec;

use crate::der;
use err_derive::Error;
use mbedtls;

//xx:
fn rng(buffer: *mut u8, size: usize) -> i32 {
    for i in 0..size {
        unsafe { *buffer.add(i) = 1 }
    }
    0
}

////////////////////////////////////////////////////////////////////////////////
// Error type.
////////////////////////////////////////////////////////////////////////////////

/// A generic catch-all error type for functionality related to policies.  This
/// error type contains more constructors when compiling for clients or hosts.
#[derive(Debug, Error)]
pub enum CertError {
    #[error(
        display = "CertError: Invalid: length for `{}`, expected {:?} but received {:?}.",
        variable,
        expected,
        received
    )]
    InvalidLength {
        variable: &'static str,
        expected: usize,
        received: usize,
    },
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

pub fn generate_csr(public_key: &[u8], private_key: &[u8]) -> Result<Vec<u8>, CertError> {
    let (_der_public, der_private) = der::keypair_to_der(public_key, private_key);
    let mut pk_private = mbedtls::pk::Pk::from_private_key(&der_private, None).unwrap();
    let csr = mbedtls::x509::csr::Builder::new()
        .key(&mut pk_private)
        .subject_with_nul("CN=mbedtls.example\0") //xx
        .unwrap()
        .signature_hash(mbedtls::hash::Type::Sha256)
        .write_der_vec(&mut rng)
        .unwrap();
    return Ok(csr);
}

pub fn generate_utc_time(
    year: u32,
    month: u32,
    day: u32,
    hour: u32,
    minute: u32,
    second: u32,
) -> Result<Vec<u8>, CertError> {
    if month > 11 || day > 30 || hour > 23 || minute > 59 || second > 59 {
        return Err(CertError::InvalidUtcInputs {
            month,
            day,
            hour,
            minute,
            second,
        });
    }
    let year = year % 2000;
    let generated_time = format!(
        "{:02}{:02}{:02}{:02}{:02}{:02}Z",
        year, month, day, hour, minute, second
    );
    return Ok(generated_time.as_bytes().to_vec());
}
