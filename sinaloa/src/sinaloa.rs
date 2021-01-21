//! Sinaloa
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

pub type SinaloaResponder = Result<String, SinaloaError>;

#[derive(Debug, Error)]
pub enum SinaloaError {
    #[error(display = "Sinaloa: TLSError: {:?}.", _0)]
    TLSError(#[error(source)] rustls::TLSError),
    #[error(display = "Sinaloa: HexError: {:?}.", _0)]
    HexError(#[error(source)] hex::FromHexError),
    #[error(display = "Sinaloa: Utf8Error: {:?}.", _0)]
    Utf8Error(#[error(source)] std::str::Utf8Error),
    #[error(display = "Sinaloa: FromUtf8Error: {:?}.", _0)]
    FromUtf8Error(#[error(source)] std::string::FromUtf8Error),
    #[error(display = "Sinaloa: SerdeJsonError: {:?}.", _0)]
    SerdeJsonError(#[error(source)] serde_json::Error),
    #[error(
        display = "Sinaloa: Function {} received non-success status: {:?}",
        _0,
        _1
    )]
    ResponseError(&'static str, colima::ResponseStatus),
    #[error(display = "Sinaloa: IOError: {:?}.", _0)]
    IOError(#[error(source)] std::io::Error),
    #[error(display = "Sinaloa: Base64Error: {:?}.", _0)]
    Base64Error(#[error(source)] base64::DecodeError),
    #[error(display = "Sinaloa: TLSError: unspecified.")]
    TLSUnspecifiedError,
    #[error(display = "Sinaloa: webpki: {:?}.", _0)]
    WebpkiError(#[error(source)] webpki::Error),
    #[error(display = "Sinaloa: webpki: {:?}.", _0)]
    WebpkiDNSNameError(#[error(source)] webpki::InvalidDNSNameError),
    #[error(display = "Sinaloa: Failed to obtain lock {:?}.", _0)]
    LockError(String),
    #[error(display = "Sinaloa: TryIntoError: {}.", _0)]
    TryIntoError(#[error(source)] std::num::TryFromIntError),
    #[error(display = "Sinaloa: ParseIntError: {}.", _0)]
    ParseIntError(#[error(source)] std::num::ParseIntError),
    #[error(display = "Sinaloa: MpscSendError (of type ()) Error: {}.", _0)]
    MpscSendEmptyError(#[error(source)] std::sync::mpsc::SendError<()>),
    #[error(
        display = "Sinaloa: MpscSendError (of type std::sync::mpsc::SendError<(u32, std::vec::Vec<u8>)>) Error: {}.",
        _0
    )]
    MpscSendU32VecU8Error(#[error(source)] std::sync::mpsc::SendError<(u32, std::vec::Vec<u8>)>),
    #[error(
        display = "Sinaloa: MpscSendError (of type std::vec::Vec<u8>) Error: {}.",
        _0
    )]
    MpscSendVecU8Error(#[error(source)] std::sync::mpsc::SendError<std::vec::Vec<u8>>),
    #[error(display = "Sinaloa: Mpsc TryRecvError: {}.", _0)]
    MpscTryRecvError(#[error(source)] std::sync::mpsc::TryRecvError),
    #[error(display = "Sinaloa: CurlError: {:?}.", _0)]
    CurlError(#[error(source)] curl::Error),
    #[cfg(feature = "sgx")]
    #[error(display = "Sinaloa: SGXError: {:?}.", _0)]
    SGXError(sgx_types::sgx_status_t),
    #[cfg(feature = "nitro")]
    #[error(display = "Sinaloa: BincodeError: {:?}", _0)]
    BincodeError(bincode::ErrorKind),
    #[cfg(feature = "nitro")]
    #[error(display = "Sinaloa: MCMessage::Status: {:?}", _0)]
    MCMessageStatus(veracruz_utils::MCMessage),
    #[cfg(feature = "nitro")]
    #[error(display = "Sinaloa: NitroStatus: {:?}", _0)]
    NitroStatus(veracruz_utils::NitroStatus),
    #[cfg(feature = "nitro")]
    #[error(display = "Sinaloa: Received Invalid MC Message: {:?}", _0)]
    InvalidMCMessage(veracruz_utils::MCMessage),
    #[cfg(feature = "nitro")]
    #[error(
        display = "Sinaloa: Received Invalid Nitro Root Enclave Message: {:?}",
        _0
    )]
    InvalidNitroRootEnclaveMessage(veracruz_utils::NitroRootEnclaveMessage),
    #[cfg(feature = "nitro")]
    #[error(display = "Sinaloa: Received Invalid Protocol Buffer Message")]
    InvalidProtoBufMessage,
    #[cfg(feature = "nitro")]
    #[error(display = "Sinaloa: Nix Error: {:?}", _0)]
    NixError(#[error(source)] nix::Error),
    #[cfg(feature = "nitro")]
    #[error(display = "Sinaloa: Serde Error")]
    SerdeError,
    #[cfg(feature = "nitro")]
    #[error(display = "Sinaloa: Veracruz Socket Error:{:?}", _0)]
    VeracruzSocketError(#[error(source)] veracruz_utils::VeracruzSocketError),
    #[cfg(feature = "nitro")]
    #[error(display = "Sinaloa: Nitro Error:{:?}", _0)]
    NitroError(#[error(source)] NitroError),
    #[cfg(feature = "nitro")]
    #[error(display = "Sinaloa: EC2 Error:{:?}", _0)]
    EC2Error(#[error(source)] EC2Error),
    #[cfg(feature = "tz")]
    #[error(display = "Sinaloa: UUIDError: {:?}.", _0)]
    UUIDError(#[error(source)] uuid::parser::ParseError),
    #[cfg(feature = "tz")]
    #[error(display = "Sinaloa: OpteeError: {:?}.", _0)]
    OpteeError(#[error(source)] optee_teec::Error),
    #[error(display = "Sinaloa: Enclave function {} failed.", _0)]
    EnclaveCallError(&'static str),
    #[error(
        display = "Sinaloa: Missing {}, which is caused by non-existence, empty field, null, zero, etc.",
        _0
    )]
    MissingFieldError(&'static str),
    #[error(
        display = "Sinaloa: MismatchError: variable `{}` mismatch, expected {:?} but received {:?}.",
        variable,
        expected,
        received
    )]
    MismatchError {
        variable: &'static str,
        expected: std::vec::Vec<u8>,
        received: std::vec::Vec<u8>,
    },
    #[error(display = "Sinaloa: ColimaError: {:?}.", _0)]
    ColimaError(#[error(source)] colima::ColimaError),
    #[error(display = "Sinaloa: VeracruzUtilError: {:?}.", _0)]
    VeracruzUtilError(#[error(source)] veracruz_utils::policy::VeracruzUtilError),
    #[error(display = "Sinaloa: Pinecone Error: {:?}.", _0)]
    PineconeError(#[error(source)] pinecone::Error),
    #[error(display = "Sinaloa: Join Error: {:?}.", _0)]
    JoinError(std::boxed::Box<dyn std::any::Any + Send + 'static>),
    #[error(
        display = "Sinaloa: Invalid length of variable `{}`, expected {}",
        _0,
        _1
    )]
    InvalidLengthError(&'static str, usize),
    #[error(display = "Sinaloa: Uninitialized enclave.")]
    UninitializedEnclaveError,
    #[error(display = "Sinaloa: Unknown attestation protocol.")]
    UnknownAttestationTokenError,
    #[error(display = "Sinaloa: Unsupported request (not implemented in this platform).")]
    UnimplementedRequestError,
    #[error(display = "Sinaloa: Unsupported request (not found).")]
    UnsupportedRequestError,
    #[error(display = "Sinaloa: Invalid request format")]
    InvalidRequestFormatError,
    #[error(display = "Sinaloa: Received non-success post status.")]
    ReceivedNonSuccessPostStatusError,
    #[error(display = "Sinaloa: Debug is disable.")]
    DebugIsDisableError,
    #[error(display = "Sinaloa: Direct response message {}.", _0)]
    DirectMessageError(String, StatusCode),
    #[error(display = "Sinaloa: Error message {}.", _0)]
    DirectStrError(&'static str),
    #[error(display = "Sinaloa: Unimplemented")]
    UnimplementedError,
}

impl<T> From<std::sync::PoisonError<T>> for SinaloaError {
    fn from(error: std::sync::PoisonError<T>) -> Self {
        SinaloaError::LockError(format!("{:?}", error))
    }
}

#[cfg(feature = "sgx")]
impl From<sgx_types::sgx_status_t> for SinaloaError {
    fn from(error: sgx_types::sgx_status_t) -> Self {
        match error {
            sgx_types::sgx_status_t::SGX_SUCCESS => {
                panic!("Expected an error code but received an success status")
            }
            e => SinaloaError::SGXError(e),
        }
    }
}

impl error::ResponseError for SinaloaError {
    fn error_response(&self) -> HttpResponse {
        ResponseBuilder::new(self.status_code()).body(format!("{:?}", self))
    }
    fn status_code(&self) -> StatusCode {
        match self {
            SinaloaError::DirectMessageError(_, e) => e.clone(),
            SinaloaError::UnimplementedRequestError
            | SinaloaError::UnknownAttestationTokenError => StatusCode::NOT_IMPLEMENTED,
            SinaloaError::UnsupportedRequestError => StatusCode::NOT_FOUND,
            _otherwise => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

#[cfg(feature = "nitro")]
impl From<std::boxed::Box<bincode::ErrorKind>> for SinaloaError {
    fn from(error: std::boxed::Box<bincode::ErrorKind>) -> Self {
        SinaloaError::BincodeError(*error)
    }
}

pub trait Sinaloa {
    fn new(policy: &str) -> Result<Self, SinaloaError>
    where
        Self: Sized;

    fn proxy_psa_attestation_get_token(
        &self,
        challenge: Vec<u8>,
    ) -> Result<(Vec<u8>, Vec<u8>, i32), SinaloaError>;

    fn plaintext_data(&self, data: Vec<u8>) -> Result<Option<Vec<u8>>, SinaloaError>;

    // Note: this function will go away
    fn get_enclave_cert(&self) -> Result<Vec<u8>, SinaloaError>;

    // Note: This function will go away
    fn get_enclave_name(&self) -> Result<String, SinaloaError>;

    fn new_tls_session(&self) -> Result<u32, SinaloaError>;

    fn close_tls_session(&self, session_id: u32) -> Result<(), SinaloaError>;

    // The first bool indicates if the enclave is active, and the second vec contains the response
    fn tls_data(
        &self,
        session_id: u32,
        input: Vec<u8>,
    ) -> Result<(bool, Option<Vec<Vec<u8>>>), SinaloaError>;

    fn close(&mut self) -> Result<bool, SinaloaError>;
}

pub fn send_tabasco_start(
    url_base: &str,
    protocol: &str,
    firmware_version: &str,
) -> Result<colima::TabascoResponse, SinaloaError> {
    let serialized_start_msg = colima::serialize_start_msg(protocol, firmware_version)?;
    let encoded_start_msg: String = base64::encode(&serialized_start_msg);
    let url = format!("{:}/Start", url_base);

    let received_body: String = post_buffer(&url, &encoded_start_msg)?;

    let body_vec = base64::decode(&received_body)?;
    let response = colima::parse_tabasco_response(&body_vec)?;
    return Ok(response);
}

pub fn post_buffer(url: &str, buffer: &String) -> Result<String, SinaloaError> {
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
        "sinaloa::send_tabasco_start received header:{:?}",
        received_header
    );
    if !received_header.contains("HTTP/1.1 200 OK\r") {
        return Err(SinaloaError::ReceivedNonSuccessPostStatusError);
    }

    debug!("sinaloa::post_buffer header_lines:{:?}", header_lines);

    return Ok(received_body);
}
