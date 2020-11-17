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
use colima;
use curl::easy::{Easy, List};
use clap::{Arg, App};
use err_derive::Error;
use hex;
use nix::sys::socket::{
    accept, bind, listen, socket, AddressFamily, InetAddr, IpAddr, SockAddr, SockFlag, SockType,
};
use std::io::Read;
use stringreader;
use veracruz_utils::nitro_enclave::NitroError;
use veracruz_utils::{
    receive_buffer, send_buffer, NitroEnclave, NitroRootEnclaveMessage, NitroStatus,
};

// Maximum number of outstanding connections in the socket's
// listen queue
const BACKLOG: usize = 128;

const TABASCO_URL: &str = "127.0.0.1:80";
const NITRO_ROOT_ENCLAVE_EIF_PATH: &str = "./nitro_root_enclave.eif";

#[derive(Debug, Error)]
pub enum NitroServerError {
    #[error(display = "NitroServer: Non Success Status")]
    NonSuccessStatus,
    #[error(display = "NitroServer: InvalidRootEnclaveMessage")]
    InvalidRootEnclaveMessage,
    #[error(display = "NitroServer: Bincode Error:{:?}", _0)]
    Bincode(#[error(source)] bincode::ErrorKind),
    #[error(display = "NitroServer: Enclave error:{:?}", _0)]
    EnclaveError(#[error(source)] NitroError),
    #[error(display = "NitroServer: Hex error:{:?}", _0)]
    HexError(#[error(source)] hex::FromHexError),
    #[error(display = "NitroServer: Base64 Decode error:{:?}", _0)]
    Base64Decode(#[error(source)] base64::DecodeError),
    #[error(display = "NitroServer: Invalid Protocol Buffer Message")]
    InvalidProtoBufMessage,
    #[error(display = "NitroServer: Non-Success HTTP Response received")]
    NonSuccessHttp,
    #[error(display = "NitroServer: Colima error:{:?}", _0)]
    Colima(colima::custom::ColimaError),
    #[error(display = "NitroServer: Curl error:{:?}", _0)]
    Curl(curl::Error),
    #[error(display = "NitroServer: Unimplemented")]
    UnimplementedError,
}

fn main() {
    println!("Hello, world!");
    let matches = App::new("nitro-root-enclave-server")
        .arg(Arg::with_name("tabasco")
            .takes_value(true)
            .help("URL for Tabasco server"))
        .get_matches();
    let tabasco_url = matches.value_of("tabasco").unwrap();

    // first, start the nitro-root-enclave
    let enclave = native_attestation(tabasco_url, NITRO_ROOT_ENCLAVE_EIF_PATH)
        .expect("Failed to perform native attestion");

    let socket_fd = socket(
        AddressFamily::Inet,
        SockType::Stream,
        SockFlag::empty(),
        None,
    )
    .expect("Failed to create socket_td");

    let my_ip_address = InetAddr::new(IpAddr::new_v4(127, 0, 0, 1), 9090);
    let sockaddr = SockAddr::new_inet(my_ip_address);

    bind(socket_fd, &sockaddr).expect("Failed to bind socket");

    listen(socket_fd, BACKLOG).expect("Failed to listen to socket");

    let fd = accept(socket_fd).expect("Failed to accept socket");
    loop {
        let received_buffer = receive_buffer(fd).expect("Failed to receive buffer");
        enclave
            .send_buffer(&received_buffer)
            .expect("Failed to send buffer to enclave");
        let buffer_to_return = enclave
            .receive_buffer()
            .expect("Failed to receive buffer from enclave");
        send_buffer(fd, &buffer_to_return).expect("Failed to return buffer to caller");
    }
}

fn native_attestation(
    tabasco_url: &str,
    mexico_city_hash: &str,
) -> Result<NitroEnclave, NitroServerError> {
    println!("nitro-root-enclave-server::native_attestation started");
    let nre_enclave = NitroEnclave::new(NITRO_ROOT_ENCLAVE_EIF_PATH)
        .map_err(|err| NitroServerError::EnclaveError(err))?;

    println!(
        "nitro-root-enclave-server::native_attstation new completed. fetching firmware version"
    );
    let firmware_version = fetch_firmware_version(&nre_enclave)?;
    println!("nitro-root-enclave-server::native_attestation fetch_firmware_version complete. Now setting mexico city hash");

    {
        let mexico_city_hash_vec =
            hex::decode(mexico_city_hash).map_err(|err| NitroServerError::HexError(err))?;

        let message = NitroRootEnclaveMessage::SetMexicoCityHashHack(mexico_city_hash_vec);
        let message_buffer =
            bincode::serialize(&message).map_err(|err| NitroServerError::Bincode(*err))?;
        println!(
            "nitro-root-enclave-server::native_attestation sending buffer:{:?}",
            message_buffer
        );
        nre_enclave.send_buffer(&message_buffer)?;

        let return_buffer = nre_enclave.receive_buffer()?;
        let received_message =
            bincode::deserialize(&return_buffer).map_err(|err| NitroServerError::Bincode(*err))?;
        let status = match received_message {
            NitroRootEnclaveMessage::Status(status) => status,
            _ => return Err(NitroServerError::InvalidRootEnclaveMessage)?,
        };
        match status {
            NitroStatus::Success => (),
            _ => return Err(NitroServerError::NonSuccessStatus),
        }
    }
    println!("SinaloaNitro::native_attestation completed setting Mexico City Hash. Now sending start to tabasco");
    let (challenge, device_id) = send_start(tabasco_url, "nitro", &firmware_version)?;

    println!("SinaloaNitro::native_attestation completed send to tabasco. Now sending NativeAttestation message to Nitro Root Enclave");
    let message = NitroRootEnclaveMessage::NativeAttestation(challenge, device_id);
    let message_buffer =
        bincode::serialize(&message).map_err(|err| NitroServerError::Bincode(*err))?;
    nre_enclave.send_buffer(&message_buffer)?;

    // data returned is token, public key
    let return_buffer = nre_enclave.receive_buffer()?;
    let received_message =
        bincode::deserialize(&return_buffer).map_err(|err| NitroServerError::Bincode(*err))?;
    let (token, _public_key) = match received_message {
        NitroRootEnclaveMessage::TokenData(tok, pubkey) => (tok, pubkey),
        _ => return Err(NitroServerError::InvalidRootEnclaveMessage),
    };

    println!(
        "nitro-root-enclave-server::native_attestation posting native_attestation_token to tabasco"
    );
    post_native_attestation_token(tabasco_url, &token, device_id)?;
    println!("sinaloa_tz::native_attestation returning Ok");
    return Ok(nre_enclave);
}

fn post_native_attestation_token(
    tabasco_url: &str,
    token: &Vec<u8>,
    device_id: i32,
) -> Result<(), NitroServerError> {
    println!("nitro-root-enclave-server::post_native_attestation_token started");
    let serialized_tabasco_request =
        colima::serialize_native_psa_attestation_token(token, device_id)
            .map_err(|err| NitroServerError::Colima(err))?;
    let encoded_str = base64::encode(&serialized_tabasco_request);
    let url = format!("{:}/Nitro/AttestationToken", tabasco_url);
    println!(
        "nitro-root-enclave-server::post_native_attestation_token posting to URL{:?}",
        url
    );
    let response = post_buffer(&url, &encoded_str)?;

    println!(
        "sinaloa_tz::post_psa_attestation_token received buffer:{:?}",
        response
    );
    return Ok(());
}

fn fetch_firmware_version(nre_enclave: &NitroEnclave) -> Result<String, NitroServerError> {
    println!("nitro-root-enclave-server::fetch_firmware_version started");

    let firmware_version: String = {
        let message = NitroRootEnclaveMessage::FetchFirmwareVersion;
        let message_buffer =
            bincode::serialize(&message).map_err(|err| NitroServerError::Bincode(*err))?;
        println!(
            "SinaloaNitro::Fetch_firmware_version sending message_buffer:{:?}",
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

fn send_start(
    url_base: &str,
    protocol: &str,
    firmware_version: &str,
) -> Result<(Vec<u8>, i32), NitroServerError> {
    let tabasco_response = send_tabasco_start(url_base, protocol, firmware_version)?;
    match tabasco_response.has_psa_attestation_init() {
        false => {
            return Err(NitroServerError::InvalidProtoBufMessage);
        }
        true => {
            let (challenge, device_id) =
                colima::parse_psa_attestation_init(tabasco_response.get_psa_attestation_init())
                    .map_err(|err| NitroServerError::Colima(err))?;
            return Ok((challenge, device_id));
        }
    }
}

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

    let mut received_body = std::string::String::new();
    let mut received_header = std::string::String::new();
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
    let header_lines: Vec<&str> = {
        let lines = received_header.split("\n");
        lines.collect()
    };
    println!(
        "nitro-root-enclave-server::send_tabasco_start reeceived header:{:?}",
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

pub fn send_tabasco_start(
    url_base: &str,
    protocol: &str,
    firmware_version: &str,
) -> Result<colima::TabascoResponse, NitroServerError> {
    let serialized_start_msg = colima::serialize_start_msg(protocol, firmware_version)
        .map_err(|err| NitroServerError::Colima(err))?;
    let encoded_start_msg: String = base64::encode(&serialized_start_msg);
    let url = format!("{:}/Start", url_base);

    let received_body: String = post_buffer(&url, &encoded_start_msg)?;

    let body_vec =
        base64::decode(&received_body).map_err(|err| NitroServerError::Base64Decode(err))?;
    let response =
        colima::parse_tabasco_response(&body_vec).map_err(|err| NitroServerError::Colima(err))?;
    return Ok(response);
}
