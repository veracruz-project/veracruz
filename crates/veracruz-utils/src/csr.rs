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

use anyhow::Result;
use err_derive::Error;
use mbedtls;
use platform_services::getrandom;
use std::vec::Vec;

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
    let mut rng = |buffer: *mut u8, size: usize| {
        let mut slice = unsafe { std::slice::from_raw_parts_mut(buffer, size) };
        getrandom(&mut slice);
        0
    };
    let mut pk_private = mbedtls::pk::Pk::from_private_key(&mut rng, private_key_der, None)?;
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

#[cfg(features = "std")]
pub fn generate_x509_time_now() -> [u8; 15] {
    use chrono::{Datelike, Timelike, Utc};
    use std::io::Write;

    let mut buf = [0u8; 15];
    let mut cursor = std::io::Cursor::new(&mut buf[..]);
    let now = Utc::now();
    let r = write!(
        cursor,
        "{:04}{:02}{:02}{:02}{:02}{:02}",
        now.year(),
        now.month(),
        now.day(),
        now.hour(),
        now.minute(),
        now.second()
    );
    if r.is_err() || cursor.position() != 14 {
        panic!("bad time")
    }
    buf
}
