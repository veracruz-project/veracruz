//! Execution engine management code, decoding protocol messages and turning them into
//! actions on the Veracruz host provisioning state.
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE_MIT.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

use super::{ProtocolState, ProvisioningResult, RuntimeManagerError};
use lazy_static::lazy_static;
use policy_utils::principal::Principal;
use std::sync::Mutex;
use std::{collections::HashMap, result::Result, vec::Vec};
use transport_protocol::transport_protocol::{
    RuntimeManagerRequest as REQUEST, RuntimeManagerRequest_oneof_message_oneof as MESSAGE,
};

////////////////////////////////////////////////////////////////////////////////
// The buffer of incoming data.
////////////////////////////////////////////////////////////////////////////////

lazy_static! {
    // TODO: wrap into a runtime manager management object.
    static ref INCOMING_BUFFER_HASH: Mutex<HashMap<u32, Vec<u8>>> = Mutex::new(HashMap::new());
}

////////////////////////////////////////////////////////////////////////////////
// Protocol response messages.
////////////////////////////////////////////////////////////////////////////////

/// Encodes a successful computation result, ready for transmission back to whoever requested a
/// result.
#[inline]
fn response_success(result: Option<Vec<u8>>) -> Vec<u8> {
    transport_protocol::serialize_result(transport_protocol::ResponseStatus::SUCCESS as i32, result)
        .unwrap_or_else(|err| panic!("{}", err))
}

/// Encodes an error code indicating that somebody sent an invalid or malformed
/// protocol request.
fn response_invalid_request() -> super::ProvisioningResult {
    let rst = transport_protocol::serialize_result(
        transport_protocol::ResponseStatus::FAILED_INVALID_REQUEST as i32,
        None,
    )?;
    Ok(Some(rst))
}

////////////////////////////////////////////////////////////////////////////////
// Protocol message dispatch.
////////////////////////////////////////////////////////////////////////////////

/// Returns the SHA-256 digest of the policy.
fn dispatch_on_policy_hash(protocol_state: &ProtocolState) -> ProvisioningResult {
    let hash = protocol_state.get_policy_hash();
    let response = transport_protocol::serialize_policy_hash(hash.as_bytes())?;
    Ok(Some(response))
}

/// Returns the result of a computation, computing the result first.
fn dispatch_on_result(
    transport_protocol::RequestResult { file_name, .. }: transport_protocol::RequestResult,
    protocol_state: &mut ProtocolState,
    client_id: u64,
) -> ProvisioningResult {
    protocol_state.execute(&Principal::Participant(client_id), &file_name)
}

/// Write a file into the VFS. It will overwrite previous content. Fails if the client has no permission.
fn dispatch_on_write(
    protocol_state: &mut ProtocolState,
    transport_protocol::Data {
        data, file_name, ..
    }: transport_protocol::Data,
    client_id: u64,
) -> ProvisioningResult {
    protocol_state.write_file(&Principal::Participant(client_id), file_name.as_str(), data)?;
    let response = transport_protocol::serialize_result(
        transport_protocol::ResponseStatus::SUCCESS as i32,
        None,
    )?;
    Ok(Some(response))
}

/// Append a file in the VFS. Fails if the client has no permission.
fn dispatch_on_append(
    protocol_state: &mut ProtocolState,
    transport_protocol::Data {
        data, file_name, ..
    }: transport_protocol::Data,
    client_id: u64,
) -> ProvisioningResult {
    protocol_state.append_file(&Principal::Participant(client_id), file_name.as_str(), data)?;
    let response = transport_protocol::serialize_result(
        transport_protocol::ResponseStatus::SUCCESS as i32,
        None,
    )?;
    Ok(Some(response))
}

/// Read a file from the VFS. Fails if the client has no permission.
fn dispatch_on_read(
    protocol_state: &mut ProtocolState,
    transport_protocol::Read { file_name, .. }: transport_protocol::Read,
    client_id: u64,
) -> ProvisioningResult {
    let result =
        protocol_state.read_file(&Principal::Participant(client_id), file_name.as_str())?;
    let response = response_success(result);
    Ok(Some(response))
}

/// Branches on a decoded protobuf message, `request`, and invokes appropriate
/// behaviour from more specialised functions.
///
/// TODO: Do we want any one of the client roles to be able to terminate the
/// operation? There's no guarantee of a timely shutdown, so it doesn't really
/// guarantee better security, but if a client detects something's wrong, they
/// may want the ability.
fn dispatch_on_request(client_id: u64, request: MESSAGE) -> ProvisioningResult {
    let mut protocol_state_guard = super::PROTOCOL_STATE.lock()?;
    let protocol_state = protocol_state_guard
        .as_mut()
        .ok_or_else(|| RuntimeManagerError::UninitializedProtocolState)?;

    match request {
        MESSAGE::write_file(data) => dispatch_on_write(protocol_state, data, client_id),
        MESSAGE::append_file(data) => dispatch_on_append(protocol_state, data, client_id),
        MESSAGE::request_pi_hash(_) => {
            Ok(Some(transport_protocol::serialize_pi_hash(b"deprecated")?))
        }
        MESSAGE::request_policy_hash(_) => dispatch_on_policy_hash(protocol_state),
        MESSAGE::request_result(result_request) => {
            dispatch_on_result(result_request, protocol_state, client_id)
        }
        MESSAGE::request_shutdown(_) => {
            let is_dead = protocol_state.request_and_check_shutdown(client_id)?;
            if is_dead {
                *protocol_state_guard = None;
            }
            Ok(Some(response_success(None)))
        }
        MESSAGE::read_file(read) => dispatch_on_read(protocol_state, read, client_id),
        _otherwise => response_invalid_request(),
    }
}

/// Tries to parse the incoming data into a `RuntimeManagerRequest`.  If this is not
/// possible, returns `Err(reason)`.  If we still need to receive more data in
/// order to parse a full request, returns `Ok(None)`.  Otherwise, returns
/// `Ok(request)` for the parsed request.
///
/// TODO: harden this against potential malfeasance.  See the note, below.
fn parse_incoming_buffer(
    tls_session_id: u32,
    mut input: Vec<u8>,
) -> Result<Option<transport_protocol::RuntimeManagerRequest>, RuntimeManagerError> {
    let mut incoming_buffer_hash = INCOMING_BUFFER_HASH.lock()?;

    // First, make sure there is an entry in the hash for the TLS session.
    if incoming_buffer_hash.get(&tls_session_id).is_none() {
        incoming_buffer_hash.insert(tls_session_id, Vec::new());
    }

    // This should not panic, given the above.  If it does, something is wrong.
    let incoming_buffer = incoming_buffer_hash.get_mut(&tls_session_id).ok_or(
        RuntimeManagerError::UnavailableIncomeBufferError(tls_session_id as u64),
    )?;

    incoming_buffer.append(&mut input);

    // NB: `parse_from_bytes()` returning failure is interpreted as meaning the
    // full protocol buffer has not yet been received. So we return `Ok(None)`
    // with the hope that eventually we will receive all of it, and then
    // `parse_from_bytes()` will return `Ok(parsed)`. In a well-behaving system,
    // this is reasonable.  In a poorly-behaved system (under attack, clients
    // just getting confused) it is not reasonable, and can eventually result in
    // "Out of Memory" or Garbage out.
    //
    // TODO: It would be nice to check the error, and then determine if this might
    // be the case or if it is hopeless and we could just error out.
    match protobuf::parse_from_bytes::<transport_protocol::RuntimeManagerRequest>(&incoming_buffer)
    {
        Err(_) => Ok(None),
        Ok(parsed) => {
            incoming_buffer_hash.remove(&tls_session_id);
            Ok(Some(parsed))
        }
    }
}

/// Top-level function which tries to parse an incoming buffer of bytes, `input`,
/// into a protobuf protocol message.  If we cannot yet parse the buffer, then
/// we return a protocol message indicating that we are waiting for more data,
/// otherwise we branch on the message contained inside the parsed protobuf
/// request frame: if it is valid then dispatch on that decoded message,
/// otherwise fail with an invalid request message.
pub fn dispatch_on_incoming_data(
    tls_session_id: u32,
    client_id: u64,
    input: &Vec<u8>,
) -> ProvisioningResult {
    match parse_incoming_buffer(tls_session_id, input.clone())? {
        None => Ok(None),
        Some(REQUEST {
            message_oneof: None,
            ..
        }) => response_invalid_request(),
        Some(REQUEST {
            message_oneof: Some(request),
            ..
        }) => dispatch_on_request(client_id, request),
    }
}
