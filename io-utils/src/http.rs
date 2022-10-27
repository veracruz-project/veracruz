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

use anyhow::{anyhow, Result as AnyhowResult};
use err_derive::Error;
use log::{error, info};
use reqwest;
use std::{string::String, vec::Vec};
use transport_protocol::{
    ProxyAttestationServerResponse, TransportProtocolError,
};
use uuid::Uuid;

///////////////////////////////////////////////////////////////////////////////
// Errors.
///////////////////////////////////////////////////////////////////////////////

/// HTTP-related errors.
#[derive(Debug, Error)]
pub enum HttpError {
    /// Reqwest generated an error
    #[error(display = "Reqwest generated an error:{}", _0)]
    ReqwestError(reqwest::Error),
    /// Invalid Header value
    #[error(display = "Invalid header value:{}", _0)]
    InvalidHeaderValue(reqwest::header::InvalidHeaderValue),
    /// An unexpected HTTP status code was returned.
    #[error(display = "An unexpected HTTP return code was returned.")]
    UnexpectedHttpCode,
    /// Response did not contain a field that we expected
    #[error(display = "Response did not contain an expected field.")]
    PoorlyFormedResponse,
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
    #[error(display = "Unable to convert bytes to UTF8: {}.", _0)]
    Utf8Error(std::str::Utf8Error),
}

///////////////////////////////////////////////////////////////////////////////
// HTTP-related functionality.
///////////////////////////////////////////////////////////////////////////////

#[derive(Debug)]
pub enum HttpResponse {
    Ok(Vec<u8>), // 200: Body
    Created(String, Vec<u8>), //201: Location, Body
    Accepted(Vec<u8>), // 202: Body
    NonAuthoritativeInformation(Vec<u8>), // 203: Body
    NoContent, // 204
    ResetContent(Vec<u8>), // 205: Body
    PartialContent(Vec<u8>), // 206: Body
}

fn convert_reqwest_response_to_http_response(res: reqwest::blocking::Response) -> Result<HttpResponse, HttpError> {
    let response = match res.status() {
        reqwest::StatusCode::OK => {
            let body = res.bytes().map_err(|_| HttpError::PoorlyFormedResponse)?;
            HttpResponse::Ok(body.to_vec())
        },
        reqwest::StatusCode::CREATED => {
            let location = match res.headers().get(reqwest::header::LOCATION) {
                None => return Err(HttpError::PoorlyFormedResponse),
                Some(loc) => loc.to_str().map_err(|_| HttpError::PoorlyFormedResponse)?.to_string(),
            };
            let body = res.bytes().map_err(|_| HttpError::PoorlyFormedResponse)?;

            HttpResponse::Created(location, body.to_vec())
        }
        reqwest::StatusCode::ACCEPTED => {
            let body = res.bytes().map_err(|_| HttpError::PoorlyFormedResponse)?;
            HttpResponse::Accepted(body.to_vec())
        }
        reqwest::StatusCode::NON_AUTHORITATIVE_INFORMATION => {
            let body = res.bytes().map_err(|_| HttpError::PoorlyFormedResponse)?;
            HttpResponse::NonAuthoritativeInformation(body.to_vec())
        }
        reqwest::StatusCode::NO_CONTENT => HttpResponse::NoContent,
        reqwest::StatusCode::RESET_CONTENT => {
            let body = res.bytes().map_err(|_| HttpError::PoorlyFormedResponse)?;
            HttpResponse::ResetContent(body.to_vec())
        }
        reqwest::StatusCode::PARTIAL_CONTENT => {
            let body = res.bytes().map_err(|_| HttpError::PoorlyFormedResponse)?;
            HttpResponse::PartialContent(body.to_vec())
        }
        _ => return Err(HttpError::UnexpectedHttpCode),
    };
    return Ok(response);
}

/// Sends an encoded `buffer` via HTTP to a server at `url`.  Fails if the
/// Curl session fails for any reason, or if a non-success HTTP code is
/// returned.
pub fn post_string<U>(url: U, buffer: &String, content_type_option: Option<&str>) -> Result<HttpResponse, HttpError>
where
    U: AsRef<str>,
{
    let url = url.as_ref();
    let buffer: String = buffer.to_string();

    info!(
        "Posting buffer {} ({} bytes) to {}.",
        buffer,
        buffer.len(),
        url
    );

    let request_builder = reqwest::blocking::Client::new()
        .post(url)
        .body(buffer);
    
    let request_builder = match content_type_option {
        Some(content_type) => {
            request_builder.header(reqwest::header::CONTENT_TYPE, reqwest::header::HeaderValue::from_str(content_type).map_err(|err| HttpError::InvalidHeaderValue(err))?)
        }
        None => request_builder, // do nothing
    };
    let ret = request_builder.send()
        .map_err(|err| HttpError::ReqwestError(err))?;
    let response = convert_reqwest_response_to_http_response(ret)?;

    return Ok(response);
}

/// Sends an raw byte `buffer` via HTTP to a server at `url`.  Fails if the
/// Curl session fails for any reason, or if a non-success HTTP code is
/// returned.
pub fn post_bytes<U>(url: U, buffer: &[u8], content_type_option: Option<&str>) -> Result<HttpResponse, HttpError>
where
    U: AsRef<str>,
{
    let url = url.as_ref();
    let buffer = buffer.to_vec();

    info!(
        "Posting byte buffer {:?} ({} bytes) to {}.",
        buffer,
        buffer.len(),
        url
    );

    let request_builder = reqwest::blocking::Client::new()
        .post(url)
        .body(buffer);
    let request_builder = match content_type_option {
        Some(content_type) => {
            request_builder.header(reqwest::header::CONTENT_TYPE, reqwest::header::HeaderValue::from_str(content_type).map_err(|err| HttpError::InvalidHeaderValue(err))?)
        }
        None => request_builder, // do nothing
    };
    let ret = request_builder.send()
        .map_err(|err| HttpError::ReqwestError(err))?;
    let response = convert_reqwest_response_to_http_response(ret)?;

    return Ok(response);
}

///////////////////////////////////////////////////////////////////////////////
// Proxy-attestation server-related functionality.
///////////////////////////////////////////////////////////////////////////////

/// Sends the "Start" message to the Proxy Attestation Server via HTTP.
/// Returns a device ID and a generated challenge from the Proxy Attestation
/// Service, which is generated in response to the "Start" message, if the
/// message is successfully sent.
pub fn send_proxy_attestation_server_start<U: AsRef<str>>(
    proxy_attestation_server_url_base: U
) -> AnyhowResult<(Uuid, Vec<u8>)> {
    let proxy_attestation_server_url_base = proxy_attestation_server_url_base.as_ref();

    info!("Sending Start message to Proxy Attestation Service.");


    let url = format!("http://{}/proxy/v1/Start", proxy_attestation_server_url_base);
    let empty_buffer: Vec<u8> = Vec::new();

    let (id, nonce) = match post_bytes(&url, &empty_buffer, None).map_err(|e| {
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
            println!("Received incorrect response:{:?} from post_string", non_created);
            return Err(anyhow!(HttpError::UnexpectedHttpCode));
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
