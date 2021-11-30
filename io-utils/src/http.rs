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
//! See the `LICENSE.markdown` file in the Veracruz root directory for copyright
//! and licensing information.

use curl::{
    easy::{Easy, List},
    Error as CurlError,
};
use err_derive::Error;
use log::{error, info};
use std::{io::Read, str::from_utf8, string::String, vec::Vec};
use stringreader::StringReader;
use transport_protocol::{
    parse_proxy_attestation_server_response, parse_psa_attestation_init,
    serialize_start_msg, ProxyAttestationServerResponse,
    TransportProtocolError,
};

///////////////////////////////////////////////////////////////////////////////
// Errors.
///////////////////////////////////////////////////////////////////////////////

/// HTTP-related errors.
#[derive(Debug, Error)]
pub enum HttpError {
    /// An error originating from Curl was raised.
    #[error(display = "An error originating from Curl was raised: {}.", _0)]
    CurlError(CurlError),
    /// An unexpected HTTP status code was returned.
    #[error(display = "An unexpected HTTP return code was returned.")]
    HttpSuccess,
    #[error(
        display = "A transport protocol message could not be (de)serialized: {}.",
        _0
    )]
    SerializationError(TransportProtocolError),
    #[error(
        display = "A base64-encoded message could not be (de)serialized: {}.",
        _0
    )]
    Base64Error(base64::DecodeError),
    #[error(display = "A transport protocol error occurred: {}.", _0)]
    TransportProtocolError(TransportProtocolError),
    #[error(display = "An attestation-related error occurred: {}.", _0)]
    AttestationError(TransportProtocolError),
    #[error(display = "The proxy attestation service issued an unexpected reply.")]
    ProtocolError(ProxyAttestationServerResponse),
}

///////////////////////////////////////////////////////////////////////////////
// HTTP-related functionality.
///////////////////////////////////////////////////////////////////////////////

/// Sends an encoded `buffer` via HTTP to a server at `url`.  Fails if the
/// Curl session fails for any reason, or if a non-success HTTP code is
/// returned.
pub fn post_buffer<U, B>(url: U, buffer: B) -> Result<String, HttpError>
where
    U: AsRef<str>,
    B: AsRef<str>,
{
    let url = url.as_ref();
    let buffer = buffer.as_ref();

    info!(
        "Posting buffer {} ({} bytes) to {}.",
        buffer,
        buffer.len(),
        url
    );

    let mut curl_request = Easy::new();

    curl_request.url(url).map_err(|err| {
        error!("Failed to set URL with Curl.  Error produced: {:?}.", err);

        HttpError::CurlError(err)
    })?;

    let mut headers = List::new();
    headers
        .append("Content-Type: application/octet-stream")
        .map_err(|err| {
            error!(
                "Failed to append `Content-Type` header.  Error produced: {:?}.",
                err
            );

            HttpError::CurlError(err)
        })?;

    curl_request.http_headers(headers).map_err(|err| {
        error!(
            "Failed to set HTTP headers with Curl.  Error produced: {:?}.",
            err
        );

        HttpError::CurlError(err)
    })?;
    curl_request.post(true).map_err(|err| {
        error!(
            "Failed to set post field to `true` with Curl.  Error produced: {:?}.",
            err
        );

        HttpError::CurlError(err)
    })?;
    curl_request
        .post_field_size(buffer.len() as u64)
        .map_err(|err| {
            error!(
                "Failed to set post field size with Curl.  Error produced: {:?}.",
                err
            );

            HttpError::CurlError(err)
        })?;

    let mut buffer_reader = StringReader::new(buffer);
    let mut received_body = String::new();
    let mut received_header = String::new();

    {
        let mut transfer = curl_request.transfer();

        transfer
            .read_function(|buf| Ok(buffer_reader.read(buf).unwrap_or(0)))
            .map_err(|err| {
                error!(
                    "Failed to register read function with Curl.  Error produced: {:?}.",
                    err
                );

                HttpError::CurlError(err)
            })?;

        transfer
            .write_function(|buf| {
                received_body.push_str(from_utf8(buf).expect({
                    info!(
                        "Error converting data {:?} from UTF-8.  Continuing with default value.",
                        buf
                    );

                    &format!("Error converting data {:?} from UTF-8.", buf)
                }));

                Ok(buf.len())
            })
            .map_err(|err| {
                error!(
                    "Failed to register write function with Curl.  Error produced: {:?}.",
                    err
                );

                HttpError::CurlError(err)
            })?;

        info!("Received response body.");

        transfer
            .header_function(|buf| {
                received_header.push_str(from_utf8(buf).expect({
                    info!(
                        "Error converting data {:?} from UTF-8.  Continuing with default value.",
                        buf
                    );

                    &format!("Error converting data {:?} from UTF-8", buf)
                }));

                true
            })
            .map_err(|err| {
                error!(
                    "Failed to register header function with Curl.  Error produced: {:?}.",
                    err
                );

                HttpError::CurlError(err)
            })?;

        transfer.perform().map_err(|err| {
            error!(
                "Failed to perform data transfer with Curl.  Error produced: {:?}.",
                err
            );

            HttpError::CurlError(err)
        })?;
    }

    info!("Received response header: {}.", received_header);

    if !received_header.contains("HTTP/1.1 200 OK\r") {
        return Err(HttpError::HttpSuccess);
    }

    info!("Buffer successfully posted.");

    Ok(received_body)
}

///////////////////////////////////////////////////////////////////////////////
// Proxy-attestation server-related functionality.
///////////////////////////////////////////////////////////////////////////////

/// Sends the "Start" message to the Proxy Attestation Server via HTTP.
/// Returns a device ID and a generated challenge from the Proxy Attestation
/// Service, which is generated in response to the "Start" message, if the
/// message is successfully sent.
pub fn send_proxy_attestation_server_start<U, P, F>(
    proxy_attestation_server_url_base: U,
    protocol_name: P,
    firmware_version: F,
) -> Result<(i32, Vec<u8>), HttpError>
where
    U: AsRef<str>,
    P: AsRef<str>,
    F: AsRef<str>,
{
    let proxy_attestation_server_url_base = proxy_attestation_server_url_base.as_ref();
    let protocol_name = protocol_name.as_ref();
    let firmware_version = firmware_version.as_ref();

    info!("Sending Start message to Proxy Attestation Service.");

    let start_msg = serialize_start_msg(protocol_name, firmware_version).map_err(|e| {
        error!(
            "Failed to serialize Start message.  Error produced: {:?}.",
            e
        );

        HttpError::SerializationError(e)
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

        HttpError::Base64Error(e)
    })?;

    let response = parse_proxy_attestation_server_response(&response_body).map_err(|e| {
        error!("Failed to parse response to Start message from Proxy Attestation Service.  Error produced: {:?}.", e);

        HttpError::TransportProtocolError(e)
    })?;

    info!("Response successfully parsed.");

    #[cfg(any(
        feature = "linux",
        feature = "nitro",
        feature = "icecap"
    ))]
    if response.has_psa_attestation_init() {
        let (challenge, device_id) =
            parse_psa_attestation_init(response.get_psa_attestation_init()).map_err(|e| {
                error!(
                "Failed to parse PSA attestation initialization message.  Error produced: {:?}.",
                e
            );

                HttpError::AttestationError(e)
            })?;

        info!("Device ID and challenge successfully obtained from Proxy Attestation Service.");

        Ok((device_id, challenge))
    } else {
        error!("Unexpected response from Proxy Attestation Service.  Expecting PSA attestation initialization message.");

        Err(HttpError::ProtocolError(response))
    }
}
