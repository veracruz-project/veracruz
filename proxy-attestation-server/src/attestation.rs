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

pub async fn start(body_string: String) -> ProxyAttestationServerResponder {
    let received_bytes = base64::decode(&body_string)
        .map_err(|err| {
            println!("proxy-attestation-server::attestation::start failed to decode body_string as base64:{:?}", err);
            err
        })?;

    let parsed = transport_protocol::parse_proxy_attestation_server_request(&received_bytes)
        .map_err(|err| {
            println!("proxy-attestation-server::attestation::start failed to parse_proxy_attestation_server_request:{:?}", err);
            err
        })?;

    if !parsed.has_start_msg() {
        println!("proxy-attestation-server::attestation::start doesn't have start_msg");
        return Err(ProxyAttestationServerError::MissingFieldError("start msg"));
    }
    let (protocol, firmware_version) = transport_protocol::parse_start_msg(&parsed);

    let device_id = {
        let mut device_id_wrapper = DEVICE_ID.lock()
            .map_err(|err| {
                println!("proxy-attestation-server::attestation::start failed to obtain lock on DEVICE_ID:{:?}", err);
                err
            })?;
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
        _ => Err(ProxyAttestationServerError::UnknownAttestationTokenError),
    }
}
