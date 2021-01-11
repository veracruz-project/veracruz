//! Attestation
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

#[cfg(feature = "psa")]
pub mod psa;
#[cfg(feature = "sgx")]
pub mod sgx;
#[cfg(feature = "nitro")]
pub mod nitro;

use crate::error::*;
use lazy_static::lazy_static;
use std::sync::Mutex;

lazy_static! {
    static ref DEVICE_ID: Mutex<i32> = Mutex::new(0);
}

pub async fn start(body_string: String) -> TabascoResponder {
    let received_bytes = base64::decode(&body_string)?;

    let parsed = colima::parse_tabasco_request(&received_bytes)?;

    if !parsed.has_start_msg() {
        println!("Tabasco::attestation::start it don't have start_msg");
        return Err(TabascoError::MissingFieldError("start msg"));
    }
    let (protocol, firmware_version) = colima::parse_start_msg(&parsed);

    let device_id = {
        let mut device_id_wrapper = DEVICE_ID.lock()?;
        *device_id_wrapper = *device_id_wrapper + 1;
        *device_id_wrapper
    };

    match protocol.as_str() {
        #[cfg(feature = "sgx")]
        "sgx" => sgx::start(&firmware_version, device_id),
        #[cfg(feature = "psa")]
        "psa" => psa::start(&firmware_version, device_id),
        #[cfg(feature = "nitro")]
        "nitro" => nitro::start(&firmware_version, device_id),
        _ => Err(TabascoError::UnknownAttestationTokenError),
    }
}
