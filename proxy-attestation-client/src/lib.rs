//! Client code for the Proxy attestation server
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE_MIT.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

use anyhow::{anyhow, Result as AnyhowResult};
use base64;
use err_derive::Error;
use io_utils::http::{HttpResponse, post_form, post_buffer};
use log::{error, info};
use std::collections::HashMap;
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum ProxyAttestationClientError {
    #[error(display = "ProxyAttestationClient: HttpError: {:?}", _0)]
    HttpError(io_utils::http::HttpError),
    #[error(display = "ProxyAttestationClient: Bad Response")]
    BadResponse,
}
/// Sends the "Start" message to the Proxy Attestation Server via HTTP.
/// Returns a device ID and a generated challenge from the Proxy Attestation
/// Service, which is generated in response to the "Start" message, if the
/// message is successfully sent.
pub fn start_proxy_attestation<U: AsRef<str>>(
    proxy_attestation_server_url_base: U
) -> AnyhowResult<(Uuid, Vec<u8>)> {
    let proxy_attestation_server_url_base = proxy_attestation_server_url_base.as_ref();

    info!("Sending Start message to Proxy Attestation Service.");


    let url = format!("http://{}/proxy/v1/Start", proxy_attestation_server_url_base);
    let empty_buffer: String = "".to_string();

    let (id, nonce) = match post_buffer(&url, &empty_buffer, None).map_err(|e| {
            error!(
                "Failed to send proxy attestation service start message.  Error produced: {}.",
                e
            );
            e
        })? {
        HttpResponse::Created(location, body) => {
            (location, body)
        }
        non_created => {
            println!("Received incorrect response:{:?} from post_buffer", non_created);
            return Err(anyhow!(ProxyAttestationClientError::BadResponse));
        }
    };
    println!("calling parse_str on id:{:?}", id);
    let id = Uuid::parse_str(&id)
        .map_err(|e| {
            println!("Uuid::parse_str failed:{:?}", e);
            e
        })?;

    return Ok((id, nonce));
}

/// Send the native (AWS Nitro) attestation token to the proxy attestation server
pub fn complete_proxy_attestation_nitro(
    proxy_attestation_server_url: &str,
    att_doc: &[u8],
    csr: &[u8],
    challenge_id: Uuid,
) -> AnyhowResult<Vec<u8>> {
    let url = format!("http://{:}/proxy/v1/Nitro/{:}", proxy_attestation_server_url, challenge_id);
    let mut form_fields: HashMap<String, String> = HashMap::new();
    form_fields.insert("token".to_string(), base64::encode(att_doc));
    form_fields.insert("csr".to_string(), base64::encode(csr));

    let response = post_form(url, &form_fields)
        .map_err(|err| ProxyAttestationClientError::HttpError(err))?;
    match response {
        HttpResponse::Ok(data) => return Ok(data),
        _ => return Err(anyhow!(ProxyAttestationClientError::BadResponse)),
    }
}

pub fn complete_proxy_attestation_linux(
    proxy_attestation_server_url: &str,
    token: &[u8],
    csr: &[u8],
    challenge_id: Uuid,
) -> AnyhowResult<Vec<u8>> {
    let url = format!("http://{:}/proxy/v1/PSA/{:}", proxy_attestation_server_url, challenge_id);
    let mut form_fields: HashMap<String, String> = HashMap::new();
    form_fields.insert("token".to_string(), base64::encode(token));
    form_fields.insert("csr".to_string(), base64::encode(csr));

    let response = post_form(url, &form_fields)
        .map_err(|err| ProxyAttestationClientError::HttpError(err))?;
    match response {
        HttpResponse::Ok(data) => return Ok(data),
        _ => return Err(anyhow!(ProxyAttestationClientError::BadResponse)),
    }
}
