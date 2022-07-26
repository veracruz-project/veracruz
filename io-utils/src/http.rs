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
use log::{error, info, trace};
use regex::Regex;
use std::{io::Read, str::from_utf8, string::String, vec::Vec};
use stringreader::StringReader;
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

#[derive(Debug)]
pub enum HttpResponse {
    Ok(String), // 200: Body
    Created(String, String), //201: Location, Body
    Accepted(String), // 202: Body
    NonAuthoritativeInformation(String), // 203: Body
    NoContent, // 204
    ResetContent(String), // 205: Body
    PartialContent(String), // 206: Body
}

/// Sends an encoded `buffer` via HTTP to a server at `url`.  Fails if the
/// Curl session fails for any reason, or if a non-success HTTP code is
/// returned.
pub fn post_string<U, B>(url: U, buffer: B, content_type_option: Option<&str>) -> Result<HttpResponse, HttpError>
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

        err
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

        err
    })?;
    curl_request.post(true).map_err(|err| {
        error!(
            "Failed to set post field to `true` with Curl.  Error produced: {:?}.",
            err
        );

        err
    })?;
    curl_request
        .post_field_size(buffer.len() as u64)
        .map_err(|err| {
            error!(
                "Failed to set post field size with Curl.  Error produced: {:?}.",
                err
            );

            err
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

                err
            })?;

        transfer
            .write_function(|buf| {
                received_body.push_str(from_utf8(buf).unwrap_or_else(|_| {
                    panic!("{}", {
                        trace!(
                            "Error converting data {:?} from UTF-8.  Continuing with default value.",
                            buf
                        );

                        &format!("Error converting data {:?} from UTF-8.", buf)
                    })
                }));

                Ok(buf.len())
            })
            .map_err(|err| {
                error!(
                    "Failed to register write function with Curl.  Error produced: {:?}.",
                    err
                );

                err
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

                err
            })?;

        transfer.perform().map_err(|err| {
            error!(
                "Failed to perform data transfer with Curl.  Error produced: {:?}.",
                err
            );

            err
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
        return Err(HttpError::HttpSuccess);
    };
    Ok(response)
}

/// Sends an encoded `buffer` via HTTP to a server at `url`.  Fails if the
/// Curl session fails for any reason, or if a non-success HTTP code is
/// returned.
pub fn post_bytes<U, B>(url: U, buffer: B, content_type_option: Option<&str>) -> Result<HttpResponse, HttpError>
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
                received_body.push_str(from_utf8(buf).unwrap_or_else(|_| {
                    panic!("{}", {
                        trace!(
                            "Error converting data {:?} from UTF-8.  Continuing with default value.",
                            buf
                        );

                        &format!("Error converting data {:?} from UTF-8.", buf)
                    })
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

    println!("Received response header: {}.", received_header);
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

    let response = match post_string(&url, &encoded_start_msg, None).map_err(|e| {
            error!(
                "Failed to send proxy attestation service start message.  Error produced: {}.",
                e
            );
            e
        })? {
        HttpResponse::Ok(body) => body,
        non_ok => {
            error!("Received incorrect response:{:?} from post_string", non_ok);
            return Err(HttpError::HttpSuccess);
        }
    };

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
