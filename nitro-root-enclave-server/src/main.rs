//! Server for the Nitro Root Enclave
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

use base64;
use bincode;
use clap::{App, Arg};
use transport_protocol;
use curl::easy::{Easy, List};
use err_derive::Error;
use hex;
use nix::sys::socket::{
    accept, bind, listen, socket, AddressFamily, InetAddr, IpAddr, SockAddr, SockFlag, SockType,
};
use std::io::Read;
use stringreader;
use veracruz_utils::nitro_enclave::NitroError;
use veracruz_utils::{io::raw_fd::{receive_buffer, send_buffer} , platform::nitro::{nitro_enclave::NitroEnclave, nitro::NitroRootEnclaveMessage}};

/// Maximum number of outstanding connections in the socket's
/// listen queue
const BACKLOG: usize = 128;

/// The path to the enclave file that will be started
const NITRO_ROOT_ENCLAVE_EIF_PATH: &str = "/home/ec2-user/nitro_root_enclave.eif";

/// The inbound port number
const INBOUND_PORT: u16 = 9090;

/// Nitro root enclave-specific errors
#[derive(Debug, Error)]
pub enum NitroServerError {
    /// The root enclave returned an invalid message
    #[error(display = "NitroServer: InvalidRootEnclaveMessage")]
    InvalidRootEnclaveMessage,
    /// A Bincode error was received
    #[error(display = "NitroServer: Bincode Error:{:?}", _0)]
    Bincode(#[error(source)] bincode::ErrorKind),
    /// The enclave framework returned an error (this did not necessarily come
        /// from the enclave itself
    #[error(display = "NitroServer: Enclave error:{:?}", _0)]
    EnclaveError(#[error(source)] NitroError),
    /// An error was received from hex encoding or decoding
    #[error(display = "NitroServer: Hex error:{:?}", _0)]
    HexError(#[error(source)] hex::FromHexError),
    /// A base64 decode error occurred
    #[error(display = "NitroServer: Base64 Decode error:{:?}", _0)]
    Base64Decode(#[error(source)] base64::DecodeError),
    /// An invalid protocol buffer message was received
    #[error(display = "NitroServer: Invalid Protocol Buffer Message")]
    InvalidProtoBufMessage,
    /// A remote http server returned a non-success (200) status
    #[error(display = "NitroServer: Non-Success HTTP Response received")]
    NonSuccessHttp,
    /// Transport protocol buffer handling returned an error
    #[error(display = "NitroServer: TransportProtocol error:{:?}", _0)]
    TransportProtocol(transport_protocol::custom::TransportProtocolError),
    /// Curl returned an error
    #[error(display = "NitroServer: Curl error:{:?}", _0)]
    Curl(curl::Error),
}

/// The main routine for the Nitro Root Enclave server
fn main() {
    println!("Hello, world!");
    let matches = App::new("nitro-root-enclave-server")
        .arg(
            Arg::with_name("proxy-attestation-server")
                .takes_value(true)
                .required(true)
                .help("URL for proxy attestation server"),
        )
        .arg(
            Arg::with_name("debug")
                .long("debug")
                .takes_value(false)
                .help("Enables debug mode in the enclave"),
        )
        .get_matches();
    let proxy_attestation_server_url = matches.value_of("proxy-attestation-server").unwrap(); // Since the proxy attestation server argument is required, this should never actually panic
    let enclave_debug = matches.is_present("debug");

    // first, start the nitro-root-enclave
    let enclave = loop {
        match native_attestation(proxy_attestation_server_url, enclave_debug) {
            Err(err) => {
                println!("nitro-root-enclave-server::main native_attestation failed({:?}). Sleeping and trying again.", err);
                std::thread::sleep(std::time::Duration::from_secs(2));
                continue;
            }
            Ok(enc) => break enc,
        }
    };

    let socket_fd = socket(
        AddressFamily::Inet,
        SockType::Stream,
        SockFlag::empty(),
        None,
    )
    .expect("Failed to create socket_td");

    let ip_string = local_ipaddress::get().expect("Failed to get local ip address");
    let ip_addr: Vec<u8> = ip_string
        .split(".")
        .map(|s| s.parse().expect("Parse error"))
        .collect();
    let my_ip_address = InetAddr::new(
        IpAddr::new_v4(ip_addr[0], ip_addr[1], ip_addr[2], ip_addr[3]),
        INBOUND_PORT,
    );
    let sockaddr = SockAddr::new_inet(my_ip_address);

    bind(socket_fd, &sockaddr).expect("Failed to bind socket");

    listen(socket_fd, BACKLOG).expect("Failed to listen to socket");

    println!("nitro-root-enclave-server::main waiting for someone to connect on the socket");
    let mut fd = accept(socket_fd).expect("Failed to accept socket");
    loop {
        println!("nitro-root-enclave-server::main reading buffer from other instance");
        let received_buffer = receive_buffer(fd).expect("Failed to receive buffer");
        println!("nitro-root-enclave-server::main forwarding buffer to enclave");
        enclave
            .send_buffer(&received_buffer)
            .expect("Failed to send buffer to enclave");
        println!("nitro-root-enclave-server::main reading buffer from enclave");
        match enclave.receive_buffer() {
            Ok(buffer_to_return) => {
                println!("nitro-root-enclave-server::main forwarding return buffer to other instance");
                send_buffer(fd, &buffer_to_return).expect("Failed to return buffer to caller");
            },
            Err(err) => {
                println!("Failed to receive buffer from enclave:{:?}", err);
                fd = accept(socket_fd).expect("Failed to accept socket on recovery");
                println!("recovery accept succeeded");
            }
        }
    }
}

/// Start the nitro-root-enclave Nitro Enclave and handle it's native attestation
fn native_attestation(
    proxy_attestation_server_url: &str,
    enclave_debug: bool,
) -> Result<NitroEnclave, NitroServerError> {
    println!("nitro-root-enclave-server::native_attestation started");
    let nre_enclave = NitroEnclave::new(true, NITRO_ROOT_ENCLAVE_EIF_PATH, enclave_debug, None)
        .map_err(|err| NitroServerError::EnclaveError(err))?;

    println!(
        "nitro-root-enclave-server::native_attstation new completed. fetching firmware version"
    );
    let firmware_version = fetch_firmware_version(&nre_enclave)?;
    println!("nitro-root-enclave-server::native_attestation fetch_firmware_version complete. Now setting Runtime Manager hash");

    println!("VeracruzServerNitro::native_attestation completed setting Runtime Manager hash. Now sending start to proxy attestation server.");
    let (challenge, device_id) = send_start(proxy_attestation_server_url, "nitro", &firmware_version)?;

    println!("VeracruzServerNitro::native_attestation completed send to the proxy attestation server. Now sending NativeAttestation message to Nitro Root Enclave");
    let message = NitroRootEnclaveMessage::NativeAttestation(challenge, device_id);
    let message_buffer =
        bincode::serialize(&message).map_err(|err| NitroServerError::Bincode(*err))?;
    nre_enclave.send_buffer(&message_buffer)?;

    // data returned is token, public key
    let return_buffer = nre_enclave.receive_buffer()?;
    let received_message =
        bincode::deserialize(&return_buffer).map_err(|err| NitroServerError::Bincode(*err))?;
    let (att_doc, _public_key) = match received_message {
        NitroRootEnclaveMessage::TokenData(tok, pubkey) => (tok, pubkey),
        _ => return Err(NitroServerError::InvalidRootEnclaveMessage),
    };

    println!(
        "nitro-root-enclave-server::native_attestation posting native_attestation_token to the proxy attestation server."
    );
    let (re_cert, ca_cert) = post_native_attestation_token(proxy_attestation_server_url, &att_doc, device_id)?;

    let message = NitroRootEnclaveMessage::SetCertChain(re_cert, ca_cert);
    let message_buffer =
        bincode::serialize(&message).map_err(|err| NitroServerError::Bincode(*err))?;
    nre_enclave.send_buffer(&message_buffer)?;

    // check the return
    let return_buffer = nre_enclave.receive_buffer()?;
    let received_message: NitroRootEnclaveMessage =
        bincode::deserialize(&return_buffer).map_err(|err| NitroServerError::Bincode(*err))?;
    match received_message {
        NitroRootEnclaveMessage::Success => (),
        _ => return Err(NitroServerError::InvalidRootEnclaveMessage),
    }

    println!("nitro-root-enclave-server::native_attestation returning Ok");
    return Ok(nre_enclave);
}

/// Send the native (AWS Nitro) attestation token to the proxy attestation server
fn post_native_attestation_token(
    proxy_attestation_server_url: &str,
    att_doc: &[u8],
    device_id: i32,
) -> Result<(Vec<u8>, Vec<u8>), NitroServerError> {
    let serialized_nitro_attestation_doc_request =
        transport_protocol::serialize_nitro_attestation_doc(att_doc, device_id)
            .map_err(|err| NitroServerError::TransportProtocol(err))?;
    let encoded_str = base64::encode(&serialized_nitro_attestation_doc_request);
    let url = format!("{:}/Nitro/AttestationToken", proxy_attestation_server_url);
    println!(
        "nitro-root-enclave-server::post_native_attestation_token posting to URL{:?}",
        url
    );
    let received_body: String = post_buffer(&url, &encoded_str)?;

    println!(
        "nitro-root-enclave-server::post_psa_attestation_token received buffer:{:?}",
        received_body
    );

    let body_vec =
        base64::decode(&received_body).map_err(|err| NitroServerError::Base64Decode(err))?;
    let response =
        transport_protocol::parse_proxy_attestation_server_response(&body_vec).map_err(|err| NitroServerError::TransportProtocol(err))?;

    let (re_cert, ca_cert) = if response.has_cert_chain() {
        let cert_chain = response.get_cert_chain();
        (cert_chain.get_enclave_cert(), cert_chain.get_root_cert())
    } else {
        return Err(NitroServerError::InvalidProtoBufMessage);
    };
    return Ok((re_cert.to_vec(), ca_cert.to_vec()));
}

/// Fetch the firmware version from the nitro-root-enclave
fn fetch_firmware_version(nre_enclave: &NitroEnclave) -> Result<String, NitroServerError> {
    println!("nitro-root-enclave-server::fetch_firmware_version started");

    let firmware_version: String = {
        let message = NitroRootEnclaveMessage::FetchFirmwareVersion;
        let message_buffer =
            bincode::serialize(&message).map_err(|err| NitroServerError::Bincode(*err))?;
        println!(
            "VeracruzServerNitro::Fetch_firmware_version sending message_buffer:{:?}",
            message_buffer
        );
        nre_enclave.send_buffer(&message_buffer)?;

        let returned_buffer = nre_enclave.receive_buffer()?;
        let response: NitroRootEnclaveMessage = bincode::deserialize(&returned_buffer)
            .map_err(|err| NitroServerError::Bincode(*err))?;
        match response {
            NitroRootEnclaveMessage::FirmwareVersion(version) => version,
            _ => return Err(NitroServerError::InvalidRootEnclaveMessage),
        }
    };
    println!("nitro-root-enclave-server::fetch_firmware_version finished");
    return Ok(firmware_version);
}

/// Send the start message to the proxy attestation server (this triggers the server to
/// send the challenge) and then handle the response
fn send_start(
    url_base: &str,
    protocol: &str,
    firmware_version: &str,
) -> Result<(Vec<u8>, i32), NitroServerError> {
    let proxy_attestation_server_response = send_proxy_attestation_server_start(url_base, protocol, firmware_version)?;
    if proxy_attestation_server_response.has_psa_attestation_init() {
        let (challenge, device_id) =
            transport_protocol::parse_psa_attestation_init(proxy_attestation_server_response.get_psa_attestation_init())
                .map_err(|err| NitroServerError::TransportProtocol(err))?;
        return Ok((challenge, device_id));
    } else {
        return Err(NitroServerError::InvalidProtoBufMessage);
    }
}

/// Post a buffer to a remote HTTP server
pub fn post_buffer(url: &str, buffer: &String) -> Result<String, NitroServerError> {
    let mut buffer_reader = stringreader::StringReader::new(buffer);

    let mut curl_request = Easy::new();
    curl_request
        .url(&url)
        .map_err(|err| NitroServerError::Curl(err))?;
    let mut headers = List::new();
    headers
        .append("Content-Type: application/octet-stream")
        .map_err(|err| NitroServerError::Curl(err))?;
    curl_request
        .http_headers(headers)
        .map_err(|err| NitroServerError::Curl(err))?;
    curl_request
        .post(true)
        .map_err(|err| NitroServerError::Curl(err))?;
    curl_request
        .post_field_size(buffer.len() as u64)
        .map_err(|err| NitroServerError::Curl(err))?;

    let mut received_body = String::new();
    let mut received_header = String::new();
    {
        let mut transfer = curl_request.transfer();

        transfer
            .read_function(|buf| Ok(buffer_reader.read(buf).unwrap_or(0)))
            .map_err(|err| NitroServerError::Curl(err))?;
        transfer
            .write_function(|buf| {
                received_body.push_str(
                    std::str::from_utf8(buf)
                        .expect(&format!("Error converting data {:?} from UTF-8", buf)),
                );
                Ok(buf.len())
            })
            .map_err(|err| NitroServerError::Curl(err))?;

        transfer
            .header_function(|buf| {
                received_header.push_str(
                    std::str::from_utf8(buf)
                        .expect(&format!("Error converting data {:?} from UTF-8", buf)),
                );
                true
            })
            .map_err(|err| NitroServerError::Curl(err))?;

        transfer
            .perform()
            .map_err(|err| NitroServerError::Curl(err))?;
    }
    let header_lines: Vec<&str> = received_header.split("\n").collect();

    println!(
        "nitro-root-enclave-server::post_buffer received header:{:?}",
        received_header
    );
    if !received_header.contains("HTTP/1.1 200 OK\r") {
        return Err(NitroServerError::NonSuccessHttp);
    }

    println!(
        "nitro-root-enclave-server::post_buffer header_lines:{:?}",
        header_lines
    );

    return Ok(received_body);
}

/// Send start to the proxy attestation server.
pub fn send_proxy_attestation_server_start(
    url_base: &str,
    protocol: &str,
    firmware_version: &str,
) -> Result<transport_protocol::ProxyAttestationServerResponse, NitroServerError> {
    let serialized_start_msg = transport_protocol::serialize_start_msg(protocol, firmware_version)
        .map_err(|err| NitroServerError::TransportProtocol(err))?;
    let encoded_start_msg: String = base64::encode(&serialized_start_msg);
    let url = format!("{:}/Start", url_base);

    println!(
        "nitro-root-enclave-server::send_proxy_attestation_server_start sending to url:{:?}",
        url
    );
    let received_body: String = post_buffer(&url, &encoded_start_msg)?;
    println!("nitro-root-enclave-server::send_proxy_attestation_server_start completed post command");

    let body_vec =
        base64::decode(&received_body).map_err(|err| NitroServerError::Base64Decode(err))?;
    let response =
        transport_protocol::parse_proxy_attestation_server_response(&body_vec).map_err(|err| NitroServerError::TransportProtocol(err))?;
    println!("nitro-root-enclave-server::send_proxy_attestation_server_start completed. Returning.");
    return Ok(response);
}
