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
use curl::{
    easy::{Easy, List},
    Error as CurlError,
};
use err_derive::Error;
use log::{error, info, trace};
use regex::Regex;
use serde::Deserialize;
use serde_json;
use std::{io::Read, str::from_utf8, string::String, vec::Vec};
use stringreader::StringReader;
use transport_protocol::{
    parse_proxy_attestation_server_response, parse_psa_attestation_init, serialize_start_msg,
    ProxyAttestationServerResponse, TransportProtocolError,
};
use uuid::Uuid;

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

/// Sends an encoded `buffer` via HTTP to a server at `url`.  Fails if the
/// Curl session fails for any reason, or if a non-success HTTP code is
/// returned.
pub fn post_string<U, B>(url: U, buffer: B, content_type_option: Option<&str>) -> AnyhowResult<HttpResponse, HttpError>
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

        return HttpError::CurlError(err);
    })?;

    let mut headers = List::new();
    if let Some(content_type) = content_type_option {
        headers
            .append(format!("Content-Type: {:}", content_type).as_str())
            .map_err(|err| {
                error!(
                    "Failed to append `Content-Type` {:}. Error produced: {:?}",
                    content_type,
                    err
                );

                HttpError::CurlError(err)
            })?;
    } else {
        headers
            .append("Content-Type: application/octet-stream")
            .map_err(|err| {
                error!(
                    "Failed to append `Content-Type` header.  Error produced: {:?}.",
                    err
                );

                HttpError::CurlError(err)
            })?;
    }

    curl_request.http_headers(headers).map_err(|err| {
        error!(
            "Failed to set HTTP headers with Curl.  Error produced: {:?}.",
            err
        );

        return HttpError::CurlError(err);
    })?;
    curl_request.post(true).map_err(|err| {
        error!(
            "Failed to set post field to `true` with Curl.  Error produced: {:?}.",
            err
        );

        return HttpError::CurlError(err);
    })?;
    curl_request
        .post_field_size(buffer.len() as u64)
        .map_err(|err| {
            error!(
                "Failed to set post field size with Curl.  Error produced: {:?}.",
                err
            );

            return HttpError::CurlError(err);
        })?;

    let mut buffer_reader = StringReader::new(buffer);
    let mut received_body: Vec<u8> = Vec::new();
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

                return HttpError::CurlError(err);
            })?;

        transfer
            .write_function(|buf| {
                received_body.extend_from_slice(buf);

                Ok(buf.len())
            })
            .map_err(|err| {
                error!(
                    "Failed to register write function with Curl.  Error produced: {:?}.",
                    err
                );

                return HttpError::CurlError(err);
            })?;

        info!("Received response body.");

        transfer
            .header_function(|buf| {
                received_header.push_str(from_utf8(buf).unwrap_or_else(|_| {
                    panic!("{}", {
                        trace!(
                            "Error converting data {:?} from UTF-8.  Continuing with default value.",
                            buf
                        );

                        &format!("Error converting data {:?} from UTF-8", buf)
                    })
                }));

                true
            })
            .map_err(|err| {
                error!(
                    "Failed to register header function with Curl.  Error produced: {:?}.",
                    err
                );

                return HttpError::CurlError(err);
            })?;

        transfer.perform().map_err(|err| {
            error!(
                "Failed to perform data transfer with Curl.  Error produced: {:?}.",
                err
            );

            return HttpError::CurlError(err);
        })?;
    }

    info!("Received response header: {}.", received_header);
    let response = if received_header.contains("HTTP/1.1 200 OK\r") {
        HttpResponse::Ok(received_body)
    } else if received_header.contains("HTTP/1.1 201 Created\r") {
        // Get the "Location" field from the header
        let location_regex = Regex::new(r"Location:\s(.*)\r").unwrap();
        let location = location_regex.captures(&received_header).unwrap().get(1).unwrap().as_str();
        HttpResponse::Created(location.to_string(), received_body)
    } else if received_header.contains("HTTP/1.1 202 Accepted\r") {
        HttpResponse::Accepted(received_body)
    } else if received_header.contains("HTTP/1.1 203 Non-Authoritative Information\r") {
        HttpResponse::NonAuthoritativeInformation(received_body)
    } else if received_header.contains("HTTP/1.1 204 No Content\r") {
        HttpResponse::NoContent
    } else if received_header.contains("HTTP/1.1 205 Reset Content\r") {
        HttpResponse::ResetContent(received_body)
    } else if received_header.contains("HTTP/1.1 206 Partial Content\r") {
        HttpResponse::PartialContent(received_body)
    } else {
        println!("post_string: received_header:{:?}", received_header);
        return Err(HttpError::HttpSuccess);
    };
    Ok(response)
}

/// Sends an encoded `buffer` via HTTP to a server at `url`.  Fails if the
/// Curl session fails for any reason, or if a non-success HTTP code is
/// returned.
pub fn post_bytes<U, B>(url: U, buffer: B, content_type_option: Option<&str>) -> AnyhowResult<HttpResponse, HttpError>
where
    U: AsRef<str>,
    B: AsRef<[u8]>,
{
    let url = url.as_ref();
    let buffer = buffer.as_ref();

    // info!(
    //     "Posting buffer {} ({} bytes) to {}.",
    //     buffer,
    //     buffer.len(),
    //     url
    // );

    let mut curl_request = Easy::new();

    curl_request.url(url).map_err(|err| {
        error!("Failed to set URL with Curl.  Error produced: {:?}.", err);
        HttpError::CurlError(err)
    })?;

    let mut headers = List::new();
    if let Some(content_type) = content_type_option {
        headers
            .append(format!("Content-Type: {:}", content_type).as_str())
            .map_err(|err| {
                error!(
                    "Failed to append `Content-Type` {:}. Error produced: {:?}",
                    content_type,
                    err
                );
                HttpError::CurlError(err)
            })?;
    } else {
        headers
            .append("Content-Type: application/octet-stream")
            .map_err(|err| {
                error!(
                    "Failed to append `Content-Type` header.  Error produced: {:?}.",
                    err
                );

                HttpError::CurlError(err)
            })?;
    }

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

    let mut buffer_reader = std::io::Cursor::new(buffer);
    let mut received_body: Vec<u8> = Vec::new();
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
                received_body.extend_from_slice(buf);

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
                received_header.push_str(from_utf8(buf).unwrap_or_else(|_| {
                    panic!("{}", {
                        trace!(
                            "Error converting data {:?} from UTF-8.  Continuing with default value.",
                            buf
                        );

                        &format!("Error converting data {:?} from UTF-8", buf)
                    })
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

    let response = if received_header.contains("HTTP/1.1 200 OK\r") {
        HttpResponse::Ok(received_body)
    } else if received_header.contains("HTTP/1.1 201 Created\r") {
        // Get the "Location" field from the header
        let location_regex = Regex::new(r"Location:\s(.*)\r").unwrap();
        let location = location_regex.captures(&received_header).unwrap().get(1).unwrap().as_str();
        HttpResponse::Created(location.to_string(), received_body)
    } else if received_header.contains("HTTP/1.1 202 Accepted\r") {
        HttpResponse::Accepted(received_body)
    } else if received_header.contains("HTTP/1.1 203 Non-Authoritative Information\r") {
        HttpResponse::NonAuthoritativeInformation(received_body)
    } else if received_header.contains("HTTP/1.1 204 No Content\r") {
        HttpResponse::NoContent
    } else if received_header.contains("HTTP/1.1 205 Reset Content\r") {
        HttpResponse::ResetContent(received_body)
    } else if received_header.contains("HTTP/1.1 206 Partial Content\r") {
        HttpResponse::PartialContent(received_body)
    } else {
        println!("post_bytes: received_header:{:?}", received_header);
        return Err(HttpError::HttpSuccess);
    };
    Ok(response)
}

///////////////////////////////////////////////////////////////////////////////
// Proxy-attestation server-related functionality.
///////////////////////////////////////////////////////////////////////////////

/// Sends the "Start" message to the Proxy Attestation Server via HTTP.
/// Returns a device ID and a generated challenge from the Proxy Attestation
/// Service, which is generated in response to the "Start" message, if the
/// message is successfully sent.
pub fn send_proxy_attestation_server_start<U: AsRef<str>, P: AsRef<str>>(
    proxy_attestation_server_url_base: U,
    protocol_name: P,
) -> AnyhowResult<(Uuid, Vec<u8>)> {
    let proxy_attestation_server_url_base = proxy_attestation_server_url_base.as_ref();
    let protocol_name = protocol_name.as_ref();

    info!("Sending Start message to Proxy Attestation Service.");


    let url = format!("{}/proxy/v1/Start", proxy_attestation_server_url_base);
    let empty_buffer: Vec<u8> = Vec::new();

    let (id, nonce) = match post_bytes(&url, empty_buffer, None).map_err(|e| {
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
            return Err(anyhow!(HttpError::HttpSuccess));
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
