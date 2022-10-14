//! Common HTTP and proxy-attestation service-related functionality
//!
//! Provides material for posting buffers over HTTP, and for sending messages
//! to the proxy attestation service over a HTTP interface.
//!
//! # Authors
//!
//! The Veracruz Development Team.
//!
//! # Copyright and licensing
//!
//! See the `LICENSE_MIT.markdown` file in the Veracruz root directory for copyright
//! and licensing information.

use anyhow::{anyhow, Result};
use err_derive::Error;
use log::{error, info};
use std::{string::String, vec::Vec};
use transport_protocol::{
    parse_proxy_attestation_server_response, parse_psa_attestation_init, serialize_start_msg,
    ProxyAttestationServerResponse,
};

///////////////////////////////////////////////////////////////////////////////
// Errors.
///////////////////////////////////////////////////////////////////////////////

/// HTTP-related errors.
#[derive(Debug, Error)]
pub enum HttpError {
    /// An unexpected HTTP status code was returned.
    #[error(display = "An unexpected HTTP return code was returned.")]
    HttpSuccess,
    #[error(display = "The proxy attestation service issued an unexpected reply.")]
    ProtocolError(ProxyAttestationServerResponse),
}

///////////////////////////////////////////////////////////////////////////////
// HTTP-related functionality.
///////////////////////////////////////////////////////////////////////////////

/// Sends an encoded `buffer` via HTTP to a server at `url`.  Fails if the
/// Curl session fails for any reason, or if a non-success HTTP code is
/// returned.
pub fn post_buffer(url: &String, buffer: &String) -> Result<String> {
    let url: String = format!("http://{}", &url);
    let buffer: String = buffer.to_string();
    // To convert any error to a std::io error:
    let err = |t| std::io::Error::new(std::io::ErrorKind::Other, t);
    // Spawn a separate thread so that we can use reqwest::blocking.
    let body = std::thread::spawn(move || {
        let ret = reqwest::blocking::Client::new()
            .post(url)
            .body(buffer)
            .send()
            .map_err(|_| err("HTTP error"))?;
        if ret.status() != reqwest::StatusCode::OK {
            return Err(err("HTTP error"));
        }
        Ok(ret.text().map_err(|_| err("HTTP error"))?)
    })
    .join()
    .map_err(|_| err("HTTP error"))??;
    Ok(body)
}

///////////////////////////////////////////////////////////////////////////////
// Proxy-attestation server-related functionality.
///////////////////////////////////////////////////////////////////////////////

/// Sends the "Start" message to the Proxy Attestation Server via HTTP.
/// Returns a device ID and a generated challenge from the Proxy Attestation
/// Service, which is generated in response to the "Start" message, if the
/// message is successfully sent.
pub fn send_proxy_attestation_server_start<U: AsRef<str>, P: AsRef<str>, F: AsRef<str>>(
    proxy_attestation_server_url_base: U,
    protocol_name: P,
    firmware_version: F,
) -> Result<(i32, Vec<u8>)> {
    let proxy_attestation_server_url_base = proxy_attestation_server_url_base.as_ref();
    let protocol_name = protocol_name.as_ref();
    let firmware_version = firmware_version.as_ref();

    info!("Sending Start message to Proxy Attestation Service.");

    let start_msg = serialize_start_msg(protocol_name, firmware_version).map_err(|e| {
        error!(
            "Failed to serialize Start message.  Error produced: {:?}.",
            e
        );

        e
    })?;

    let encoded_start_msg = base64::encode(&start_msg);

    let url = format!("{}/Start", proxy_attestation_server_url_base);

    let response = post_buffer(&url, &encoded_start_msg).map_err(|e| {
        error!(
            "Failed to send proxy attestation service start message.  Error produced: {}.",
            e
        );

        e
    })?;

    info!("Response received from Proxy Attestation Service.");

    let response_body = base64::decode(&response).map_err(|e| {
        error!(
            "Failed to deserialize response from Proxy Attestation Service.  Error produced: {:?}.",
            e
        );

        e
    })?;

    let response = parse_proxy_attestation_server_response(None, &response_body).map_err(|e| {
        error!("Failed to parse response to Start message from Proxy Attestation Service.  Error produced: {:?}.", e);

        e
    })?;

    info!("Response successfully parsed.");

    if response.has_psa_attestation_init() {
        let (challenge, device_id) =
            parse_psa_attestation_init(response.get_psa_attestation_init()).map_err(|e| {
                error!(
                "Failed to parse PSA attestation initialization message.  Error produced: {:?}.",
                e
            );

                e
            })?;

        info!("Device ID and challenge successfully obtained from Proxy Attestation Service.");

        Ok((device_id, challenge))
    } else {
        error!("Unexpected response from Proxy Attestation Service.  Expecting PSA attestation initialization message.");

        Err(anyhow!(HttpError::ProtocolError(response)))
    }
}
