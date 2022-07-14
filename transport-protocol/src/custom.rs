//! Custom and derived functionality relating to the transport protocol.
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE_MIT.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

use anyhow::{anyhow, Result};
use crate::transport_protocol;
use err_derive::Error;
use lazy_static::lazy_static;
use protobuf::{error::ProtobufError, Message, ProtobufEnum};
use std::{collections::HashMap, string::ToString, sync::Mutex, vec::Vec};

pub const LENGTH_PREFIX_SIZE: usize = 8;

////////////////////////////////////////////////////////////////////////////////
// The buffer of incoming data, indexed by a session id.
////////////////////////////////////////////////////////////////////////////////

lazy_static! {
    // TODO: wrap into a runtime manager management object.
    static ref INCOMING_BUFFER_HASH: Mutex<HashMap<u32, (u64, Vec<u8>)>> = Mutex::new(HashMap::new());
}

#[derive(Debug, Error)]
pub enum TransportProtocolError {
    // NOTE: Protobuf does not implement clone, hence derive(clone) is impossible.
    #[error(display = "TransportProtocol: ProtobufError: {:?}.", _0)]
    ProtobufError(#[error(source)] ProtobufError),
    #[error(display = "TransportProtocol: Invalid response status: {:?}.", _0)]
    ResponseStatusError(i32),
    #[error(display = "TransportProtocol: TryIntoError: {}.", _0)]
    TryIntoError(#[error(source)] std::num::TryFromIntError),
    #[error(
        display = "TransportProtocol: Session {:?}: Buffer is partial, still waiting for chunks",
        _0
    )]
    PartialBuffer(u32),
    #[error(display = "TransportProtocol: Session {:?}: Length prefix missing", _0)]
    MissingLengthPrefix(u32),
    #[error(
        display = "TransportProtocol: Session {:?}: Incoming buffer not found",
        _0
    )]
    BufferNotFound(u32),
    #[error(
        display = "TransportProtocol: Session {:?}: Can't get mutex for incoming buffer",
        _0
    )]
    MutexError(u32),
}
pub type TransportProtocolResult = Result<std::vec::Vec<u8>>;

/// Strip the length prefix from the input buffer.
/// Return the length and the stripped buffer.
/// This function must be called before deserializing a `protobuf` message
fn get_length_prefix(
    session_id: u32,
    buffer: &[u8],
) -> Result<(u64, &[u8])> {
    if buffer.len() < LENGTH_PREFIX_SIZE {
        return Err(anyhow!(TransportProtocolError::MissingLengthPrefix(session_id)));
    }

    let mut length_bytes: [u8; LENGTH_PREFIX_SIZE] = [0; LENGTH_PREFIX_SIZE];
    length_bytes.copy_from_slice(&buffer[..LENGTH_PREFIX_SIZE]);
    let remaining_buffer = &buffer[LENGTH_PREFIX_SIZE..];
    Ok((u64::from_be_bytes(length_bytes), remaining_buffer))
}

/// Return the input buffer prefixed with its length.
/// This function must be called after serializing a `protobuf` message
fn set_length_prefix(buffer: &mut Vec<u8>) -> TransportProtocolResult {
    let length = u64::to_be_bytes(buffer.len() as u64);
    let mut length_bytes = length.to_vec();
    length_bytes.append(buffer);
    Ok(length_bytes)
}

/// Strip the length prefix from the first chunk received and append subsequent
/// chunks to the session's incoming buffer until the protocol buffer is
/// complete and can be deserialized into a message.
/// This function must be called everytime a new chunk is received.
/// Take a session id and chunk as input.
/// Return the complete buffer, or an error indicating that the buffer is
/// partial, or any other error
///
/// TODO: harden this against potential malfeasance.  See the note, below.
fn handle_protocol_buffer(session_id: Option<u32>, mut input: &[u8]) -> TransportProtocolResult {
    // Default session id to 0
    let session_id = session_id.unwrap_or(0);

    let mut incoming_buffer_hash = INCOMING_BUFFER_HASH
        .lock()
        .map_err(|_| TransportProtocolError::MutexError(session_id))?;

    // First, check if there is an entry in the hash for the specified session.
    // If not, we assume this is the first chunk of the protocol buffer.
    if incoming_buffer_hash.get(&session_id).is_none() {
        // Extract the protocol buffer's total length
        let (expected_length, input_unprefixed) = get_length_prefix(session_id, input)?;

        // Insert the expected length in the hash table
        incoming_buffer_hash.insert(session_id, (expected_length, Vec::new()));

        input = input_unprefixed;
    }

    let (expected_length, incoming_buffer) = match incoming_buffer_hash.get_mut(&session_id) {
        Some(v) => v,
        None => return Err(anyhow!(TransportProtocolError::BufferNotFound(session_id))),
    };

    // Append chunk to incoming buffer
    incoming_buffer.append(&mut input.to_vec());

    // We return `Ok(None)` as long as the full protocol buffer has not yet been
    // received. Once received, we return `Ok(buffer)`.
    // In a well-behaving system, this is reasonable.  In a poorly-behaved
    // system (under attack, clients just getting confused) it is not
    // reasonable, and can eventually result in "Out of Memory" or Garbage out.
    //
    // TODO: It would be nice to check the error, and then determine if this
    // might be the case or if it is hopeless and we could just error out.

    if incoming_buffer.len() < *expected_length as usize {
        Err(anyhow!(TransportProtocolError::PartialBuffer(session_id)))
    } else {
        let incoming_buffer = incoming_buffer.to_vec();
        incoming_buffer_hash.remove(&session_id);
        Ok(incoming_buffer)
    }
}

/// Parse a request to the Runtime Manager.
pub fn parse_runtime_manager_request(
    session_id: Option<u32>,
    buffer: &[u8],
) -> Result<transport_protocol::RuntimeManagerRequest> {
    let full_unprefixed_buffer = handle_protocol_buffer(session_id, buffer)?;
    Ok(protobuf::parse_from_bytes::<
        transport_protocol::RuntimeManagerRequest,
    >(&full_unprefixed_buffer)?)
}

/// Parse a response from the Runtime Manager.
pub fn parse_runtime_manager_response(
    session_id: Option<u32>,
    buffer: &[u8],
) -> Result<transport_protocol::RuntimeManagerResponse> {
    let full_unprefixed_buffer = handle_protocol_buffer(session_id, buffer)?;
    Ok(protobuf::parse_from_bytes::<
        transport_protocol::RuntimeManagerResponse,
    >(&full_unprefixed_buffer)?)
}

pub fn parse_proxy_attestation_server_request(
    session_id: Option<u32>,
    buffer: &[u8],
) -> Result<transport_protocol::ProxyAttestationServerRequest> {
    let full_unprefixed_buffer = handle_protocol_buffer(session_id, buffer)?;
    Ok(protobuf::parse_from_bytes::<
        transport_protocol::ProxyAttestationServerRequest,
    >(&full_unprefixed_buffer)?)
}

pub fn parse_proxy_attestation_server_response(
    session_id: Option<u32>,
    buffer: &[u8],
) -> Result<transport_protocol::ProxyAttestationServerResponse> {
    let full_unprefixed_buffer = handle_protocol_buffer(session_id, buffer)?;
    Ok(protobuf::parse_from_bytes::<
        transport_protocol::ProxyAttestationServerResponse,
    >(&full_unprefixed_buffer)?)
}

/// Serialize a (static) data package and its package ID.
pub fn serialize_write_file(data_buffer: &[u8], file_name: &str) -> TransportProtocolResult {
    let mut data = transport_protocol::Data::new();
    data.set_data(data_buffer.to_vec());
    data.set_file_name(file_name.to_string());
    let mut transport_protocol = transport_protocol::RuntimeManagerRequest::new();
    transport_protocol.set_write_file(data);

    // Prefix buffer with its length
    let mut buffer = transport_protocol.write_to_bytes()?;
    set_length_prefix(&mut buffer)
}

/// Serialize a (static) data package and its package ID.
pub fn serialize_read_file(file_name: &str) -> TransportProtocolResult {
    let mut data = transport_protocol::Read::new();
    data.set_file_name(file_name.to_string());
    let mut transport_protocol = transport_protocol::RuntimeManagerRequest::new();
    transport_protocol.set_read_file(data);

    // Prefix buffer with its length
    let mut buffer = transport_protocol.write_to_bytes()?;
    set_length_prefix(&mut buffer)
}

pub fn serialize_append_file(data_buffer: &[u8], file_name: &str) -> TransportProtocolResult {
    let mut data = transport_protocol::Data::new();
    data.set_data(data_buffer.to_vec());
    data.set_file_name(file_name.to_string());
    let mut transport_protocol = transport_protocol::RuntimeManagerRequest::new();
    transport_protocol.set_append_file(data);

    // Prefix buffer with its length
    let mut buffer = transport_protocol.write_to_bytes()?;
    set_length_prefix(&mut buffer)
}

/// Serialize the request for querying the result.
pub fn serialize_request_result(file_name: &str) -> TransportProtocolResult {
    let mut command = transport_protocol::RequestResult::new();
    command.set_file_name(file_name.to_string());
    let mut request = transport_protocol::RuntimeManagerRequest::new();
    request.set_request_result(command);

    // Prefix buffer with its length
    let mut buffer = request.write_to_bytes()?;
    set_length_prefix(&mut buffer)
}

/// Serialize the request for shutting down the enclave.
pub fn serialize_request_shutdown() -> TransportProtocolResult {
    let command = transport_protocol::RequestShutdown::new();
    let mut request = transport_protocol::RuntimeManagerRequest::new();
    request.set_request_shutdown(command);

    // Prefix buffer with its length
    let mut buffer = request.write_to_bytes()?;
    set_length_prefix(&mut buffer)
}

pub fn serialize_request_proxy_psa_attestation_token(challenge: &[u8]) -> TransportProtocolResult {
    let mut rpat = transport_protocol::RequestProxyPsaAttestationToken::new();
    rpat.set_challenge(challenge.to_vec());
    let mut request = transport_protocol::RuntimeManagerRequest::new();
    request.set_request_proxy_psa_attestation_token(rpat);

    // Prefix buffer with its length
    let mut buffer = request.write_to_bytes()?;
    set_length_prefix(&mut buffer)
}

pub fn parse_request_proxy_psa_attestation_token(
    proto: &transport_protocol::RequestProxyPsaAttestationToken,
) -> std::vec::Vec<u8> {
    proto.get_challenge().to_vec()
}

pub fn parse_cert_chain(
    chain: &transport_protocol::CertChain,
) -> (std::vec::Vec<u8>, std::vec::Vec<u8>) {
    return (
        chain.get_root_cert().to_vec(),
        chain.get_enclave_cert().to_vec(),
    );
}

pub fn serialize_proxy_psa_attestation_token(
    token: &[u8],
    pubkey: &[u8],
    device_id: i32,
) -> TransportProtocolResult {
    let mut pat_proto = transport_protocol::ProxyPsaAttestationToken::new();
    pat_proto.set_token(token.to_vec());
    pat_proto.set_pubkey(pubkey.to_vec());
    pat_proto.set_device_id(device_id);
    let mut proxy_attestation_server_request =
        transport_protocol::ProxyAttestationServerRequest::new();
    proxy_attestation_server_request.set_proxy_psa_attestation_token(pat_proto);

    // Prefix buffer with its length
    let mut buffer = proxy_attestation_server_request.write_to_bytes()?;
    set_length_prefix(&mut buffer)
}

pub fn serialize_nitro_attestation_doc(doc: &[u8], device_id: i32) -> TransportProtocolResult {
    let mut nad_proto = transport_protocol::NitroAttestationDoc::new();
    nad_proto.set_doc(doc.to_vec());
    nad_proto.set_device_id(device_id);
    let mut proxy_attestation_server_request =
        transport_protocol::ProxyAttestationServerRequest::new();
    proxy_attestation_server_request.set_nitro_attestation_doc(nad_proto);

    // Prefix buffer with its length
    let mut buffer = proxy_attestation_server_request.write_to_bytes()?;
    set_length_prefix(&mut buffer)
}

pub fn serialize_certificate(cert: &[u8]) -> TransportProtocolResult {
    let mut proto_cert = transport_protocol::Cert::new();
    proto_cert.set_data(cert.to_vec());
    let mut rmr = transport_protocol::RuntimeManagerResponse::new();
    rmr.set_cert(proto_cert);

    // Prefix buffer with its length
    let mut buffer = rmr.write_to_bytes()?;
    set_length_prefix(&mut buffer)
}

pub fn parse_proxy_psa_attestation_token(
    proto: &transport_protocol::ProxyPsaAttestationToken,
) -> (std::vec::Vec<u8>, std::vec::Vec<u8>, i32) {
    (
        proto.get_token().to_vec(),
        proto.get_pubkey().to_vec(),
        proto.get_device_id(),
    )
}

pub fn serialize_native_psa_attestation_token(
    token: &[u8],
    csr: &[u8],
    device_id: i32,
) -> TransportProtocolResult {
    let mut pat_proto = transport_protocol::NativePsaAttestationToken::new();
    pat_proto.set_token(token.to_vec());
    pat_proto.set_csr(csr.to_vec());
    pat_proto.set_device_id(device_id);
    let mut proxy_attestation_server_request =
        transport_protocol::ProxyAttestationServerRequest::new();
    proxy_attestation_server_request.set_native_psa_attestation_token(pat_proto);

    // Prefix buffer with its length
    let mut buffer = proxy_attestation_server_request.write_to_bytes()?;
    set_length_prefix(&mut buffer)
}

pub fn parse_native_psa_attestation_token(
    proto: &transport_protocol::NativePsaAttestationToken,
) -> (std::vec::Vec<u8>, std::vec::Vec<u8>, i32) {
    (
        proto.get_token().to_vec(),
        proto.get_csr().to_vec(),
        proto.get_device_id(),
    )
}

pub fn parse_nitro_attestation_doc(
    proto: &transport_protocol::NitroAttestationDoc,
) -> (std::vec::Vec<u8>, i32) {
    (proto.get_doc().to_vec(), proto.get_device_id())
}

pub fn serialize_cert_chain(enclave_cert: &[u8], root_cert: &[u8]) -> TransportProtocolResult {
    let mut cert_chain = transport_protocol::CertChain::new();
    cert_chain.set_root_cert(root_cert.to_vec());
    cert_chain.set_enclave_cert(enclave_cert.to_vec());
    let mut response = transport_protocol::ProxyAttestationServerResponse::new();
    response.set_cert_chain(cert_chain);

    // Prefix buffer with its length
    let mut buffer = response.write_to_bytes()?;
    set_length_prefix(&mut buffer)
}

pub fn serialize_psa_attestation_init(challenge: &[u8], device_id: i32) -> TransportProtocolResult {
    let mut request = transport_protocol::ProxyAttestationServerResponse::new();
    let mut pai = transport_protocol::PsaAttestationInit::new();
    pai.set_challenge(challenge.to_vec());
    pai.set_device_id(device_id);
    request.set_psa_attestation_init(pai);

    // Prefix buffer with its length
    let mut buffer = request.write_to_bytes()?;
    set_length_prefix(&mut buffer)
}

pub fn parse_psa_attestation_init(
    pai: &transport_protocol::PsaAttestationInit,
) -> Result<(std::vec::Vec<u8>, i32)> {
    Ok((pai.get_challenge().to_vec(), pai.get_device_id()))
}

/// Serialize the request for querying the hash of the provisioned program.
#[deprecated]
pub fn serialize_request_pi_hash(file_name: &str) -> TransportProtocolResult {
    let mut request = transport_protocol::RuntimeManagerRequest::new();
    let mut rph = transport_protocol::RequestPiHash::new();
    rph.set_file_name(file_name.to_string());
    request.set_request_pi_hash(rph);

    // Prefix buffer with its length
    let mut buffer = request.write_to_bytes()?;
    set_length_prefix(&mut buffer)
}

/// Serialize the request for querying the enclave policy.
pub fn serialize_request_policy_hash() -> TransportProtocolResult {
    let mut request = transport_protocol::RuntimeManagerRequest::new();
    let rph = transport_protocol::RequestPolicyHash::new();
    request.set_request_policy_hash(rph);

    // Prefix buffer with its length
    let mut buffer = request.write_to_bytes()?;
    set_length_prefix(&mut buffer)
}

/// Serialize a response containing the program hash.
pub fn serialize_pi_hash(hash: &[u8]) -> TransportProtocolResult {
    let mut response = transport_protocol::RuntimeManagerResponse::new();

    response.set_status(transport_protocol::ResponseStatus::SUCCESS);
    let mut pi_hash = transport_protocol::PiHash::new();
    pi_hash.data.resize(hash.len(), 0);
    pi_hash.data.copy_from_slice(hash);
    response.set_pi_hash(pi_hash);

    // Prefix buffer with its length
    let mut buffer = response.write_to_bytes()?;
    set_length_prefix(&mut buffer)
}

/// Serialize a response containing the policy hash.
pub fn serialize_policy_hash(hash: &[u8]) -> TransportProtocolResult {
    let mut response = transport_protocol::RuntimeManagerResponse::new();

    response.set_status(transport_protocol::ResponseStatus::SUCCESS);
    let mut policy_hash = transport_protocol::PolicyHash::new();
    policy_hash.data.resize(hash.len(), 0);
    policy_hash.data.copy_from_slice(hash);
    response.set_policy_hash(policy_hash);

    // Prefix buffer with its length
    let mut buffer = response.write_to_bytes()?;
    set_length_prefix(&mut buffer)
}

/// Serialize an empty response.
pub fn serialize_empty_response(status: i32) -> TransportProtocolResult {
    let mut response = transport_protocol::RuntimeManagerResponse::new();
    let encoded_status = transport_protocol::ResponseStatus::from_i32(status)
        .ok_or(TransportProtocolError::ResponseStatusError(status))?;
    response.set_status(encoded_status);

    // Prefix buffer with its length
    let mut buffer = response.write_to_bytes()?;
    set_length_prefix(&mut buffer)
}

/// Serialize a response containing the computation result.
pub fn serialize_result(
    status: i32,
    data_opt: Option<std::vec::Vec<u8>>,
) -> TransportProtocolResult {
    let mut response = transport_protocol::RuntimeManagerResponse::new();

    let encoded_status = transport_protocol::ResponseStatus::from_i32(status)
        .ok_or(TransportProtocolError::ResponseStatusError(status))?;

    response.set_status(encoded_status);

    if let Some(ref data) = data_opt {
        let mut result = transport_protocol::Result::new();
        result.data.resize(data.len(), 0);
        result.data.copy_from_slice(data);
        response.set_result(result);
    }

    // Prefix buffer with its length
    let mut buffer = response.write_to_bytes()?;
    set_length_prefix(&mut buffer)
}

pub fn parse_result(
    response: &transport_protocol::RuntimeManagerResponse,
) -> Result<Option<std::vec::Vec<u8>>> {
    let status = response.get_status();
    let decoded_status = match status {
        transport_protocol::ResponseStatus::UNSET => -1,
        transport_protocol::ResponseStatus::SUCCESS => 0,
        transport_protocol::ResponseStatus::FAILED_INVALID_ROLE => 1,
        transport_protocol::ResponseStatus::FAILED_NOT_READY => 2,
        transport_protocol::ResponseStatus::FAILED_GENERIC => 3,
        transport_protocol::ResponseStatus::FAILED_VM_ERROR => 4,
        transport_protocol::ResponseStatus::FAILED_ERROR_CODE_RETURNED => 5,
        transport_protocol::ResponseStatus::FAILED_INVALID_REQUEST => 6,
    };
    if status != transport_protocol::ResponseStatus::SUCCESS {
        return Err(anyhow!(TransportProtocolError::ResponseStatusError(decoded_status)));
    }

    let data_opt = {
        if response.has_result() {
            let result = response.get_result();
            let mut data = std::vec::Vec::new();
            data.resize(result.get_data().len(), 0);
            data.copy_from_slice(&response.get_result().data);
            Some(data)
        } else {
            None
        }
    };

    Ok(data_opt)
}

pub fn parse_start_msg(
    parsed: &transport_protocol::ProxyAttestationServerRequest,
) -> (std::string::String, std::string::String) {
    let start_msg = parsed.get_start_msg();
    (
        start_msg.protocol.clone(),
        start_msg.firmware_version.clone(),
    )
}

pub fn serialize_start_msg(protocol: &str, firmware_version: &str) -> TransportProtocolResult {
    let mut transport_protocol = transport_protocol::ProxyAttestationServerRequest::new();
    let mut start_msg = transport_protocol::StartMsg::new();
    start_msg.set_protocol(protocol.to_string());
    start_msg.set_firmware_version(firmware_version.to_string());
    transport_protocol.set_start_msg(start_msg);

    // Prefix buffer with its length
    let mut buffer = transport_protocol.write_to_bytes()?;
    set_length_prefix(&mut buffer)
}
