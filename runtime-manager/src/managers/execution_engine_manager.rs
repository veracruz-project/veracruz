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
use anyhow::{anyhow, Result};
use policy_utils::{pipeline::Expr, principal::Principal};
use std::vec::Vec;
use transport_protocol::{
    transport_protocol::{
        RuntimeManagerRequest as REQUEST, RuntimeManagerRequest_oneof_message_oneof as MESSAGE,
    },
    TransportProtocolError,
};
use log::info;

////////////////////////////////////////////////////////////////////////////////
// Protocol response messages.
////////////////////////////////////////////////////////////////////////////////

/// Encodes a successful computation result, ready for transmission back to whoever requested a
/// result.
#[inline]
fn response_success(result: Option<Vec<u8>>) -> Vec<u8> {
    transport_protocol::serialize_result(transport_protocol::ResponseStatus::SUCCESS as i32, result)
        .unwrap_or_else(|err| panic!("{:?}", err))
}

/// Encodes an error code indicating that somebody sent an invalid or malformed
/// protocol request.
fn response_invalid_request() -> ProvisioningResult {
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
    //TODO fill in the correct virtural filesystem handler
    info!("call {}", client_id);
    protocol_state.execute(&Principal::Participant(client_id), &Principal::Program(file_name.clone()), Vec::new(), Box::new(Expr::Literal(file_name)))
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
    let mut protocol_state_guard = super::PROTOCOL_STATE
        .lock()
        .map_err(|_| anyhow!(RuntimeManagerError::LockProtocolState))?;
    let protocol_state = protocol_state_guard
        .as_mut()
        .ok_or(anyhow!(RuntimeManagerError::UninitializedProtocolState))?;

    match request {
        MESSAGE::write_file(data) => dispatch_on_write(protocol_state, data, client_id),
        MESSAGE::append_file(data) => dispatch_on_append(protocol_state, data, client_id),
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

/// Try to parse the incoming buffer into a `RuntimeManagerRequest` message.
/// Return `Ok(request)` if it's a success or `Ok(None)` if the message is
/// partial. Propagate the error otherwise
fn parse_incoming_buffer(
    tls_session_id: u32,
    input: Vec<u8>,
) -> Result<Option<transport_protocol::RuntimeManagerRequest>> {
    match transport_protocol::parse_runtime_manager_request(Some(tls_session_id), &input) {
        Ok(v) => Ok(Some(v)),
        Err(e) => {
            match e.downcast_ref::<TransportProtocolError>() {
                Some(TransportProtocolError::PartialBuffer(_)) => Ok(None),
                _otherwise => Err(e),
            }
        },
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
