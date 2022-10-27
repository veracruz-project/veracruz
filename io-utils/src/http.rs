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
use reqwest::{blocking, Error as ReqwestError, header, StatusCode};
use std::{collections::HashMap, string::String, vec::Vec};
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
    ReqwestError(ReqwestError),
    /// Invalid Header value
    #[error(display = "Invalid header value:{}", _0)]
    InvalidHeaderValue(header::InvalidHeaderValue),
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

fn convert_reqwest_response_to_http_response(res: blocking::Response) -> Result<HttpResponse, HttpError> {
    let response = match res.status() {
        StatusCode::OK => {
            let body = res.bytes().map_err(|_| HttpError::PoorlyFormedResponse)?;
            HttpResponse::Ok(body.to_vec())
        },
        StatusCode::CREATED => {
            let location = match res.headers().get(header::LOCATION) {
                None => return Err(HttpError::PoorlyFormedResponse),
                Some(loc) => loc.to_str().map_err(|_| HttpError::PoorlyFormedResponse)?.to_string(),
            };
            let body = res.bytes().map_err(|_| HttpError::PoorlyFormedResponse)?;

            HttpResponse::Created(location, body.to_vec())
        }
        StatusCode::ACCEPTED => {
            let body = res.bytes().map_err(|_| HttpError::PoorlyFormedResponse)?;
            HttpResponse::Accepted(body.to_vec())
        }
        StatusCode::NON_AUTHORITATIVE_INFORMATION => {
            let body = res.bytes().map_err(|_| HttpError::PoorlyFormedResponse)?;
            HttpResponse::NonAuthoritativeInformation(body.to_vec())
        }
        StatusCode::NO_CONTENT => HttpResponse::NoContent,
        StatusCode::RESET_CONTENT => {
            let body = res.bytes().map_err(|_| HttpError::PoorlyFormedResponse)?;
            HttpResponse::ResetContent(body.to_vec())
        }
        StatusCode::PARTIAL_CONTENT => {
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
pub fn post_string<U,>(url: U, buffer: &String, content_type_option: Option<&str>) -> Result<HttpResponse, HttpError>
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

    let request_builder = blocking::Client::new()
        .post(url)
        .body(buffer);
    
    let request_builder = match content_type_option {
        Some(content_type) => {
            request_builder.header(header::CONTENT_TYPE, header::HeaderValue::from_str(content_type).map_err(|err| HttpError::InvalidHeaderValue(err))?)
        }
        None => request_builder, // do nothing
    };
    let ret = request_builder.send()
        .map_err(|err| HttpError::ReqwestError(err))?;
    let response = convert_reqwest_response_to_http_response(ret)?;

    return Ok(response);
}

pub fn post_form<U: AsRef<str>>(url: U, form_data: &HashMap<String, String>) -> Result<HttpResponse, HttpError> {
    let url = url.as_ref();
    let client_builder = blocking::ClientBuilder::new();

    let client = client_builder.build()
        .map_err(|err| {
            HttpError::ReqwestError(err)
        })?;
    let mut form = blocking::multipart::Form::new();
    for (key, value) in &*form_data {
        form = form.text(key.clone(), value.clone());
    }

    let response = client.post(url)
        .multipart(form)
        .send()
        .map_err(|err| {
            HttpError::ReqwestError(err)
        })?;
    let response = convert_reqwest_response_to_http_response(response)?;
    return Ok(response);
}

