//! Veracruz server
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

#[cfg(feature = "nitro")]
use crate::ec2_instance::EC2Error;
use actix_http::ResponseBuilder;
use actix_web::{error, http::StatusCode, HttpResponse};
use curl::easy::{Easy, List};
use err_derive::Error;
use log::debug;
use std::io::Read;
#[cfg(feature = "nitro")]
use veracruz_utils::nitro_enclave::NitroError;
#[cfg(feature = "icecap")]
use crate::veracruz_server_icecap::IceCapError;

pub type VeracruzServerResponder = Result<String, VeracruzServerError>;

#[derive(Debug, Error)]
pub enum VeracruzServerError {
    #[error(display = "VeracruzServer: TLSError: {:?}.", _0)]
    TLSError(#[error(source)] rustls::TLSError),
    #[error(display = "VeracruzServer: HexError: {:?}.", _0)]
    HexError(#[error(source)] hex::FromHexError),
    #[error(display = "VeracruzServer: Utf8Error: {:?}.", _0)]
    Utf8Error(#[error(source)] std::str::Utf8Error),
    #[error(display = "VeracruzServer: FromUtf8Error: {:?}.", _0)]
    FromUtf8Error(#[error(source)] std::string::FromUtf8Error),
    #[error(display = "VeracruzServer: SerdeJsonError: {:?}.", _0)]
    SerdeJsonError(#[error(source)] serde_json::Error),
    #[error(
        display = "VeracruzServer: Function {} received non-success status: {:?}",
        _0,
        _1
    )]
    ResponseError(&'static str, transport_protocol::ResponseStatus),
    #[error(display = "VeracruzServer: IOError: {:?}.", _0)]
    IOError(#[error(source)] std::io::Error),
    #[error(display = "VeracruzServer: Base64Error: {:?}.", _0)]
    Base64Error(#[error(source)] base64::DecodeError),
    #[error(display = "VeracruzServer: TLSError: unspecified.")]
    TLSUnspecifiedError,
    #[error(display = "VeracruzServer: webpki: {:?}.", _0)]
    WebpkiError(#[error(source)] webpki::Error),
    #[error(display = "VeracruzServer: webpki: {:?}.", _0)]
    WebpkiDNSNameError(#[error(source)] webpki::InvalidDNSNameError),
    #[error(display = "VeracruzServer: Failed to obtain lock {:?}.", _0)]
    LockError(String),
    #[error(display = "VeracruzServer: TryIntoError: {}.", _0)]
    TryIntoError(#[error(source)] std::num::TryFromIntError),
    #[error(display = "VeracruzServer: ParseIntError: {}.", _0)]
    ParseIntError(#[error(source)] std::num::ParseIntError),
    #[error(display = "VeracruzServer: MpscSendError (of type ()) Error: {}.", _0)]
    MpscSendEmptyError(#[error(source)] std::sync::mpsc::SendError<()>),
    #[error(
        display = "VeracruzServer: MpscSendError (of type std::sync::mpsc::SendError<(u32, std::vec::Vec<u8>)>) Error: {}.",
        _0
    )]
    MpscSendU32VecU8Error(#[error(source)] std::sync::mpsc::SendError<(u32, std::vec::Vec<u8>)>),
    #[error(
        display = "VeracruzServer: MpscSendError (of type std::vec::Vec<u8>) Error: {}.",
        _0
    )]
    MpscSendVecU8Error(#[error(source)] std::sync::mpsc::SendError<std::vec::Vec<u8>>),
    #[error(display = "VeracruzServer: Mpsc TryRecvError: {}.", _0)]
    MpscTryRecvError(#[error(source)] std::sync::mpsc::TryRecvError),
    #[error(display = "VeracruzServer: CurlError: {:?}.", _0)]
    CurlError(#[error(source)] curl::Error),
    #[cfg(feature = "sgx")]
    #[error(display = "VeracruzServer: SGXError: {:?}.", _0)]
    SGXError(sgx_types::sgx_status_t),
    #[cfg(feature = "nitro")]
    #[error(display = "VeracruzServer: BincodeError: {:?}", _0)]
    BincodeError(bincode::ErrorKind),
    #[cfg(feature = "nitro")]
    #[error(display = "VeracruzServer: RuntimeManagerMessage::Status: {:?}", _0)]
    RuntimeManagerMessageStatus(veracruz_utils::RuntimeManagerMessage),
    #[cfg(feature = "nitro")]
    #[error(display = "VeracruzServer: NitroStatus: {:?}", _0)]
    NitroStatus(veracruz_utils::NitroStatus),
    #[cfg(feature = "nitro")]
    #[error(display = "VeracruzServer: Received Invalid Runtime Manager Message: {:?}", _0)]
    InvalidRuntimeManagerMessage(veracruz_utils::RuntimeManagerMessage),
    #[cfg(feature = "nitro")]
    #[error(
        display = "VeracruzServer: Received Invalid Nitro Root Enclave Message: {:?}",
        _0
    )]
    InvalidNitroRootEnclaveMessage(veracruz_utils::NitroRootEnclaveMessage),
    #[cfg(feature = "nitro")]
    #[error(display = "VeracruzServer: Received Invalid Protocol Buffer Message")]
    InvalidProtoBufMessage,
    #[cfg(feature = "nitro")]
    #[error(display = "VeracruzServer: Nix Error: {:?}", _0)]
    NixError(#[error(source)] nix::Error),
    #[cfg(feature = "nitro")]
    #[error(display = "VeracruzServer: Serde Error")]
    SerdeError,
    #[cfg(feature = "nitro")]
    #[error(display = "VeracruzServer: Veracruz Socket Error:{:?}", _0)]
    VeracruzSocketError(#[error(source)] veracruz_utils::VeracruzSocketError),
    #[cfg(feature = "nitro")]
    #[error(display = "VeracruzServer: Nitro Error:{:?}", _0)]
    NitroError(#[error(source)] NitroError),
    #[cfg(feature = "nitro")]
    #[error(display = "VeracruzServer: EC2 Error:{:?}", _0)]
    EC2Error(#[error(source)] EC2Error),
    #[cfg(feature = "tz")]
    #[error(display = "VeracruzServer: UUIDError: {:?}.", _0)]
    UUIDError(#[error(source)] uuid::parser::ParseError),
    #[cfg(feature = "tz")]
    #[error(display = "VeracruzServer: OpteeError: {:?}.", _0)]
    OpteeError(#[error(source)] optee_teec::Error),
    #[cfg(feature = "icecap")]
    #[error(display = "VeracruzServer: IceCap error: {:?}", _0)]
    IceCapError(IceCapError),
    #[error(display = "VeracruzServer: Enclave function {} failed.", _0)]
    EnclaveCallError(&'static str),
    #[error(
        display = "VeracruzServer: Missing {}, which is caused by non-existence, empty field, null, zero, etc.",
        _0
    )]
    MissingFieldError(&'static str),
    #[error(
        display = "VeracruzServer: MismatchError: variable `{}` mismatch, expected {:?} but received {:?}.",
        variable,
        expected,
        received
    )]
    MismatchError {
        variable: &'static str,
        expected: std::vec::Vec<u8>,
        received: std::vec::Vec<u8>,
    },
    #[error(display = "VeracruzServer: TransportProtocolError: {:?}.", _0)]
    TransportProtocolError(#[error(source)] transport_protocol::TransportProtocolError),
    #[error(display = "VeracruzServer: PolicyError: {:?}.", _0)]
    VeracruzUtilError(#[error(source)] veracruz_utils::policy::error::PolicyError),
    #[error(display = "VeracruzServer: Pinecone Error: {:?}.", _0)]
    PineconeError(#[error(source)] pinecone::Error),
    #[error(display = "VeracruzServer: Join Error: {:?}.", _0)]
    JoinError(std::boxed::Box<dyn std::any::Any + Send + 'static>),
    #[error(
        display = "VeracruzServer: Invalid length of variable `{}`, expected {}",
        _0,
        _1
    )]
    InvalidLengthError(&'static str, usize),
    #[error(display = "VeracruzServer: Uninitialized enclave.")]
    UninitializedEnclaveError,
    #[error(display = "VeracruzServer: Unknown attestation protocol.")]
    UnknownAttestationTokenError,
    #[error(display = "VeracruzServer: Unsupported request (not implemented in this platform).")]
    UnimplementedRequestError,
    #[error(display = "VeracruzServer: Unsupported request (not found).")]
    UnsupportedRequestError,
    #[error(display = "VeracruzServer: Invalid request format")]
    InvalidRequestFormatError,
    #[error(display = "VeracruzServer: Received non-success post status.")]
    ReceivedNonSuccessPostStatusError,
    #[error(display = "VeracruzServer: Debug is disable.")]
    DebugIsDisableError,
    #[error(display = "VeracruzServer: Direct response message {}.", _0)]
    DirectMessageError(String, StatusCode),
    #[error(display = "VeracruzServer: Error message {}.", _0)]
    DirectStringError(String),
    #[error(display = "VeracruzServer: Unimplemented")]
    UnimplementedError,
}

impl<T> From<std::sync::PoisonError<T>> for VeracruzServerError {
    fn from(error: std::sync::PoisonError<T>) -> Self {
        VeracruzServerError::LockError(format!("{:?}", error))
    }
}

#[cfg(feature = "sgx")]
impl From<sgx_types::sgx_status_t> for VeracruzServerError {
    fn from(error: sgx_types::sgx_status_t) -> Self {
        match error {
            sgx_types::sgx_status_t::SGX_SUCCESS => {
                panic!("Expected an error code but received an success status")
            }
            e => VeracruzServerError::SGXError(e),
        }
    }
}

impl error::ResponseError for VeracruzServerError {
    fn error_response(&self) -> HttpResponse {
        ResponseBuilder::new(self.status_code()).body(format!("{:?}", self))
    }
    fn status_code(&self) -> StatusCode {
        match self {
            VeracruzServerError::DirectMessageError(_, e) => e.clone(),
            VeracruzServerError::UnimplementedRequestError
            | VeracruzServerError::UnknownAttestationTokenError => StatusCode::NOT_IMPLEMENTED,
            VeracruzServerError::UnsupportedRequestError => StatusCode::NOT_FOUND,
            _otherwise => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

#[cfg(feature = "nitro")]
impl From<std::boxed::Box<bincode::ErrorKind>> for VeracruzServerError {
    fn from(error: std::boxed::Box<bincode::ErrorKind>) -> Self {
        VeracruzServerError::BincodeError(*error)
    }
}

pub trait VeracruzServer {
    fn new(policy: &str) -> Result<Self, VeracruzServerError>
    where
        Self: Sized;

    fn proxy_psa_attestation_get_token(
        &mut self,
        challenge: Vec<u8>,
    ) -> Result<(Vec<u8>, Vec<u8>, i32), VeracruzServerError>;

    fn plaintext_data(&mut self, data: Vec<u8>) -> Result<Option<Vec<u8>>, VeracruzServerError>;

    // Note: this function will go away
    fn get_enclave_cert(&mut self) -> Result<Vec<u8>, VeracruzServerError>;

    // Note: This function will go away
    fn get_enclave_name(&mut self) -> Result<String, VeracruzServerError>;

    fn new_tls_session(&mut self) -> Result<u32, VeracruzServerError>;

    fn close_tls_session(&mut self, session_id: u32) -> Result<(), VeracruzServerError>;

    // The first bool indicates if the enclave is active, and the second vec contains the response
    fn tls_data(
        &mut self,
        session_id: u32,
        input: Vec<u8>,
    ) -> Result<(bool, Option<Vec<Vec<u8>>>), VeracruzServerError>;

    fn close(&mut self) -> Result<bool, VeracruzServerError>;
}

pub fn send_proxy_attestation_server_start(
    url_base: &str,
    protocol: &str,
    firmware_version: &str,
) -> Result<transport_protocol::ProxyAttestationServerResponse, VeracruzServerError> {
    let serialized_start_msg = transport_protocol::serialize_start_msg(protocol, firmware_version)?;
    let encoded_start_msg: String = base64::encode(&serialized_start_msg);
    let url = format!("{:}/Start", url_base);

    let received_body: String = post_buffer(&url, &encoded_start_msg)?;

    let body_vec = base64::decode(&received_body)?;
    let response = transport_protocol::parse_proxy_attestation_server_response(&body_vec)?;
    return Ok(response);
}

pub fn post_buffer(url: &str, buffer: &String) -> Result<String, VeracruzServerError> {
    let mut buffer_reader = stringreader::StringReader::new(buffer);

    let mut curl_request = Easy::new();
    curl_request.url(&url)?;
    let mut headers = List::new();
    headers.append("Content-Type: application/octet-stream")?;
    curl_request.http_headers(headers)?;
    curl_request.post(true)?;
    curl_request.post_field_size(buffer.len() as u64)?;

    let mut received_body = std::string::String::new();
    let mut received_header = std::string::String::new();
    {
        let mut transfer = curl_request.transfer();

        transfer.read_function(|buf| Ok(buffer_reader.read(buf).unwrap_or(0)))?;
        transfer.write_function(|buf| {
            received_body.push_str(
                std::str::from_utf8(buf)
                    .expect(&format!("Error converting data {:?} from UTF-8", buf)),
            );
            Ok(buf.len())
        })?;

        transfer.header_function(|buf| {
            received_header.push_str(
                std::str::from_utf8(buf)
                    .expect(&format!("Error converting data {:?} from UTF-8", buf)),
            );
            true
        })?;

        transfer.perform()?;
    }
    let header_lines: Vec<&str> = {
        let lines = received_header.split("\n");
        lines.collect()
    };
    println!(
        "veracruz_server::send_proxy_attestation_server_start received header:{:?}",
        received_header
    );
    if !received_header.contains("HTTP/1.1 200 OK\r") {
        return Err(VeracruzServerError::ReceivedNonSuccessPostStatusError);
    }

    debug!("veracruz_server::post_buffer header_lines:{:?}", header_lines);

    return Ok(received_body);
}
