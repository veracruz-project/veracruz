//! Execution engine management code, decoding protocol messages and turning them into
//! actions on the Veracruz host provisioning state.
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

use super::{
    buffer::RuntimeManagerBuffer, RuntimeManagerError, ProtocolState, ProvisioningResponse,
    ProvisioningResult,
};
use execution_engine::hcall::common::{DataSourceMetadata, LifecycleState};
use transport_protocol::transport_protocol::{
    RuntimeManagerRequest as REQUEST, RuntimeManagerRequest_oneof_message_oneof as MESSAGE,
};
use lazy_static::lazy_static;
#[cfg(any(feature = "tz", feature = "nitro"))]

use std::sync::Mutex;
#[cfg(feature = "sgx")]
use std::sync::SgxMutex as Mutex;
use std::{collections::HashMap, result::Result, vec::Vec};
use veracruz_utils::policy::principal::Role;

////////////////////////////////////////////////////////////////////////////////
// The buffer of incoming data.
////////////////////////////////////////////////////////////////////////////////

lazy_static! {
    static ref INCOMING_BUFFER_HASH: Mutex<HashMap<u32, Vec<u8>>> = Mutex::new(HashMap::new());
    //TODO: replace by dedicated FS with meta-data, e.g. permission.
    static ref PROG_AND_DATA_BUFFER: Mutex<RuntimeManagerBuffer> = Mutex::new(RuntimeManagerBuffer::new());
}

////////////////////////////////////////////////////////////////////////////////
// Utility functions.
////////////////////////////////////////////////////////////////////////////////

/// Checks that the host provisioning state is in one of a number of expected
/// states, otherwise raises an error with an error message detailing the
/// mismatch.
#[inline]
fn check_state(current: &LifecycleState, expected: &[LifecycleState]) -> bool {
    expected.contains(&current)
}

/// Checks that the expected set of roles is satisfied by the roles possessed
/// by the current principal.  Returns `false` iff this is not the case.
#[inline]
fn check_roles(current: &Vec<Role>, expected: &[Role]) -> bool {
    current.iter().any(|rho| expected.contains(rho))
}

////////////////////////////////////////////////////////////////////////////////
// Protocol response messages.
////////////////////////////////////////////////////////////////////////////////

/// Encodes a successful computation result, ready for transmission back to whoever requested a
/// result.
#[inline]
fn response_success(result: Option<Vec<u8>>) -> Vec<u8> {
    transport_protocol::serialize_result(transport_protocol::ResponseStatus::SUCCESS as i32, result)
        .unwrap_or_else(|err| panic!(err))
}

/// Encodes an error code that the virtual machine program produced, ready for
/// transmission back to swhoever requested a result.
fn response_error_code_returned(error_code: &i32) -> std::vec::Vec<u8> {
    transport_protocol::serialize_result(
        transport_protocol::ResponseStatus::FAILED_ERROR_CODE_RETURNED as i32,
        Some(error_code.to_le_bytes().to_vec()),
    )
    .unwrap_or_else(|err| panic!(err))
}

/// Encodes an error code indicating that the enclace is not ready to receive a
/// particular type of message.
fn response_not_ready() -> super::ProvisioningResult {
    let rst = transport_protocol::serialize_result(transport_protocol::ResponseStatus::FAILED_NOT_READY as i32, None)?;
    Ok(super::ProvisioningResponse::ProtocolError { response: rst })
}

/// Encodes an error code indicating that a principal with an invalid role tried
/// to perform an action.
fn response_invalid_role() -> super::ProvisioningResult {
    let rst = transport_protocol::serialize_result(transport_protocol::ResponseStatus::FAILED_INVALID_ROLE as i32, None)?;
    Ok(super::ProvisioningResponse::ProtocolError { response: rst })
}

/// Encodes an error code indicating that somebody sent an invalid or malformed
/// protocol request.
fn response_invalid_request() -> super::ProvisioningResult {
    let rst =
        transport_protocol::serialize_result(transport_protocol::ResponseStatus::FAILED_INVALID_REQUEST as i32, None)?;
    Ok(super::ProvisioningResponse::ProtocolError { response: rst })
}

////////////////////////////////////////////////////////////////////////////////
// Protocol message dispatch.
////////////////////////////////////////////////////////////////////////////////

/// Returns the SHA-256 digest of the provisioned program.  Fails if no hash has
/// yet been computed.
fn dispatch_on_pi_hash(colima::RequestPiHash {file_name, .. } : colima::RequestPiHash, protocol_state: &ProtocolState) -> ProvisioningResult {
    // The digest is computed by Veracruz when the program is provisioned.  If
    // there's no digest, then we must not have been given a program yet.
    match protocol_state.get_program_digest()? {
        None => response_not_ready(),
        Some(digest) => {
            let response = transport_protocol::serialize_pi_hash(&digest)?;
            Ok(ProvisioningResponse::Success { response })
        }
    }
}

/// Returns the SHA-256 digest of the policy.
fn dispatch_on_policy_hash(protocol_state: &ProtocolState) -> ProvisioningResult {
    let hash = protocol_state.get_policy_hash();
    let response = transport_protocol::serialize_policy_hash(hash.as_bytes())?;
    Ok(ProvisioningResponse::Success { response })
}

/// Returns the current lifecycle state of the host provisioning state.  This
/// state can be queried unconditionally (though it may change between the query
/// being serviced and being received back/being acted upon...)
fn dispatch_on_request_state(protocol_state: &ProtocolState) -> ProvisioningResult {
    let response =
        transport_protocol::serialize_machine_state(u8::from(protocol_state.get_lifecycle_state()?))?;
    Ok(ProvisioningResponse::Success { response })
}

/// Returns the result of a computation, computing the result first.  Fails if
/// we are not in the `LifecycleState::ReadyToExecute` state.
fn dispatch_on_result(colima::RequestResult{ file_name, .. } : colima::RequestResult, protocol_state: &ProtocolState) -> ProvisioningResult {
    //TODO: USE THE FILE_NAME 
    if check_state(
        &protocol_state.get_lifecycle_state()?,
        &[LifecycleState::ReadyToExecute],
    ) {
        match protocol_state.invoke_entry_point() {
            Ok(return_code) => {
                assert!(check_state(
                    &protocol_state.get_lifecycle_state()?,
                    &[LifecycleState::FinishedExecuting]
                ));

                if return_code == 0 {
                    let result = protocol_state.get_result()?;
                    let response = response_success(result);
                    Ok(ProvisioningResponse::Success { response })
                } else {
                    let response = response_error_code_returned(&return_code);
                    Ok(ProvisioningResponse::Success { response })
                }
            }
            Err(error) => {
                assert!(check_state(
                    &protocol_state.get_lifecycle_state()?,
                    &[LifecycleState::Error]
                ));
                Err(error)
            }
        }
    } else if check_state(
        &protocol_state.get_lifecycle_state()?,
        &[LifecycleState::FinishedExecuting],
    ) {
        let result = protocol_state.get_result()?;
        let response = response_success(result);
        Ok(ProvisioningResponse::Success { response })
    } else {
        response_not_ready()
    }
}

/// Processes a request from a client to perform a platform shutdown.  Returns
/// `true` iff we have reached a threshold wherein everybody who needs to
/// request a shutdown can go ahead and do so.
#[inline]
fn dispatch_on_shutdown(
    protocol_state: &ProtocolState,
    client_id: u64,
) -> Result<(bool, ProvisioningResult), RuntimeManagerError> {
    Ok((
        protocol_state.request_and_check_shutdown(client_id)?,
        Ok(ProvisioningResponse::Success {
            response: response_success(None),
        }),
    ))
}

/// Provisions a program into the host provisioning state.  Fails if we are not
/// in `LifecycleState::Initial` or if the provisioned program is malformed in
/// some way.
///
/// Note: this doesn't invalidate the host state if something is wrong with the
/// program, as the program provider can try again by uploading another program,
/// which seems benign.  Should this change?
fn dispatch_on_program(
    protocol_state: &ProtocolState,
    transport_protocol::Program { file_name, code, .. }: transport_protocol::Program,
) -> ProvisioningResult {
    // Buffer the program, it will be used in batch process
    PROG_AND_DATA_BUFFER.lock()?.buffer_program(code.as_slice())?;
    PROG_AND_DATA_BUFFER.lock()?.fs.insert(file_name.clone(),code.clone());

    if check_state(
        &protocol_state.get_lifecycle_state()?,
        &[LifecycleState::Initial],
    ) {
        if let Err(reason) = protocol_state.load_program(&code) {
            // If program loading fails we stay in the initial state as the
            // program provisioner can just try again.
            assert!(check_state(
                &protocol_state.get_lifecycle_state()?,
                &[LifecycleState::Error, LifecycleState::Initial]
            ));

            Err(reason)
        } else {
            // After program load we're either waiting for data sources or not
            // expecting any data sources and therefore ready to execute.
            assert!(check_state(
                &protocol_state.get_lifecycle_state()?,
                &[
                    LifecycleState::DataSourcesLoading,
                    LifecycleState::ReadyToExecute
                ]
            ));

            let response = transport_protocol::serialize_result(transport_protocol::ResponseStatus::SUCCESS as i32, None)?;
            Ok(ProvisioningResponse::Success { response })
        }
    } else {
        response_not_ready()
    }
}

/// Provisions a data source into the host provisioning state.  Fails if we are
/// not in `LifecycleState::DataSourcesLoading`.  If we are still expecting more
/// data then we stay in state `LifecycleState::DataSourcesLoading`, otherwise
/// if this represents the last data provisioning step then the host
/// provisioning state automatically switches to
/// `LifecycleState::ReadyToExecute` or `LifecycleState::StreamSourcesLoading`
/// if stream data is required.
fn dispatch_on_data(
    protocol_state: &ProtocolState,
    transport_protocol::Data {
        data, file_name, ..
    }: transport_protocol::Data,
    client_id: u64,
) -> ProvisioningResult {
    //TODO: REPLACE BY FS API
    let package_id = file_name.parse::<u64>()?;
    let frame = DataSourceMetadata::new(&data, client_id, package_id as u64);
    PROG_AND_DATA_BUFFER.lock()?.buffer_data(&frame)?;

    if check_state(
        &protocol_state.get_lifecycle_state()?,
        &[LifecycleState::DataSourcesLoading],
    ) {
        let frame = DataSourceMetadata::new(&data, client_id, package_id as u64);

        if let Err(error) = protocol_state.append_file(client_id,file_name.as_str(),data.as_slice()) {
            // If something critical went wrong (e.g. all data was provisioned,
            // but the platform couldn't sort the incoming data for some reason
            // then we should be in an error state, otherwise we remain in the
            // same state.

            assert!(check_state(
                &protocol_state.get_lifecycle_state()?,
                &[LifecycleState::Error, LifecycleState::DataSourcesLoading]
            ));

            Err(error)
        } else {
            // We either stay in the same state, or progress to ready to execute
            // if all data is now available.
            assert!(check_state(
                &protocol_state.get_lifecycle_state()?,
                &[
                    LifecycleState::DataSourcesLoading,
                    LifecycleState::StreamSourcesLoading,
                    LifecycleState::ReadyToExecute,
                ]
            ));

            let response = transport_protocol::serialize_result(transport_protocol::ResponseStatus::SUCCESS as i32, None)?;
            Ok(ProvisioningResponse::Success { response })
        }
    } else {
        response_not_ready()
    }
}

/// Provisions a stream source into the host provisioning state.  Fails if we are
/// not in `LifecycleState::StreamSourcesLoading`.  If we are still expecting more
/// data then we stay in state `LifecycleState::StreamSourcesLoading`, otherwise
/// if this represents the last data provisioning step then the host
/// provisioning state automatically switches to
/// `LifecycleState::ReadyToExecute`.
fn dispatch_on_stream(
    protocol_state: &ProtocolState,
    transport_protocol::Data {
        data, file_name, ..
    }: transport_protocol::Data,
    client_id: u64,
) -> ProvisioningResult {
    if check_state(
        &protocol_state.get_lifecycle_state()?,
        &[LifecycleState::StreamSourcesLoading],
    ) {
        //TODO: REPLACE BY FS API
        let package_id = file_name.parse::<u64>()?;
        let frame = DataSourceMetadata::new(&data, client_id, package_id as u64);

        if let Err(error) = protocol_state.add_new_stream_source(frame) {
            // If something critical went wrong (e.g. all data was provisioned,
            // but the platform couldn't sort the incoming data for some reason
            // then we should be in an error state, otherwise we remain in the
            // same state.

            assert!(check_state(
                &protocol_state.get_lifecycle_state()?,
                &[LifecycleState::Error, LifecycleState::StreamSourcesLoading]
            ));

            Err(error)
        } else {
            // We either stay in the same state, or progress to ready to execute
            // if all data is now available.
            assert!(check_state(
                &protocol_state.get_lifecycle_state()?,
                &[
                    LifecycleState::StreamSourcesLoading,
                    LifecycleState::ReadyToExecute
                ]
            ));

            let response = transport_protocol::serialize_result(transport_protocol::ResponseStatus::SUCCESS as i32, None)?;
            Ok(ProvisioningResponse::Success { response })
        }
    } else {
        response_not_ready()
    }
}

/// Signals the next round of computation. It will reload the program and all (static) data,
/// and load the current result as the `previous_result` for the next round.
/// Fails if the enclave is not in `LifecycleState::FinishedExecuting`.
fn dispatch_on_next_round(
    protocol_state: &mut ProtocolState,
) -> (Option<ProtocolState>, ProvisioningResult) {
    let lifecycle_state = match protocol_state.get_lifecycle_state() {
        Ok(o) => o,
        Err(e) => return (None, Err(e)),
    };
    if check_state(&lifecycle_state, &[LifecycleState::FinishedExecuting]) {
        match reload(protocol_state) {
            Ok(o) => (
                Some(o),
                Ok(ProvisioningResponse::Success {
                    response: response_success(None),
                }),
            ),
            Err(e) => (None, Err(e)),
        }
    } else {
        (None, response_not_ready())
    }
}

/// Allocates a new protocol state, reloads the program and all (static) data,
/// and loads the current result as the `previous_result` for the new instance.
fn reload(old_protocol_state: &ProtocolState) -> Result<ProtocolState, RuntimeManagerError> {
    let mut new_protocol_state = ProtocolState::new(
        old_protocol_state.get_policy().clone(),
        format!("{}", old_protocol_state.get_policy_hash()),
    )?;
    new_protocol_state.set_previous_result(&old_protocol_state.get_result()?)?;
    let buffer = PROG_AND_DATA_BUFFER.lock()?;
    new_protocol_state.load_program(buffer.get_program()?)?;
    let all_data = buffer.all_data()?;
    for data in all_data {
        new_protocol_state.add_new_data_source(data)?;
    }
    Ok(new_protocol_state)
}

/// Branches on a decoded protobuf message, `request`, and invokes appropriate
/// behaviour from more specialised functions.
///
/// TODO: Do we want any one of the client roles to be able to terminate the
/// operation? There's no guarantee of a timely shutdown, so it doesn't really
/// guarantee better security, but if a client detects something's wrong, they
/// may want the ability.
fn dispatch_on_request(
    client_id: u64,
    roles: &Vec<Role>,
    request: MESSAGE,
) -> ProvisioningResult {
    let mut protocol_state_guard = super::PROTOCOL_STATE.lock()?;
    let protocol_state = protocol_state_guard
        .as_mut()
        .ok_or_else(|| RuntimeManagerError::UninitializedProtocolState)?;

    match request {
        MESSAGE::data(data) => {
            if check_roles(roles, &[Role::DataProvider]) {
                dispatch_on_data(protocol_state, data, client_id)
            } else {
                response_invalid_role()
            }
        }
        MESSAGE::program(prog) => {
            if check_roles(roles, &[Role::ProgramProvider]) {
                dispatch_on_program(protocol_state, prog)
            } else {
                response_invalid_role()
            }
        }
        MESSAGE::request_pi_hash(pi_hash_request) => dispatch_on_pi_hash(pi_hash_request, protocol_state),
        MESSAGE::request_policy_hash(_) => dispatch_on_policy_hash(protocol_state),
        MESSAGE::request_result(result_request) => {
            if check_roles(roles, &[Role::ResultReader]) {
                dispatch_on_result(result_request,protocol_state)
            } else {
                response_invalid_role()
            }
        }
        MESSAGE::request_state(_) => dispatch_on_request_state(protocol_state),
        MESSAGE::request_shutdown(_) => {
            if check_roles(roles, &[Role::ResultReader]) {
                let (is_dead, response) = dispatch_on_shutdown(protocol_state, client_id.into())?;

                // If we're not alive, clobber the global lock guarding the
                // protocol state and make it unusable.
                if is_dead {
                    *protocol_state_guard = None;
                }

                response
            } else {
                response_invalid_role()
            }
        }
        MESSAGE::stream(stream) => {
            if check_roles(roles, &vec![Role::DataProvider]) {
                dispatch_on_stream(protocol_state, stream, client_id)
            } else {
                response_invalid_role()
            }
        }
        MESSAGE::request_next_round(_) => {
            if check_roles(roles, &vec![Role::ResultReader]) {
                let (new_protocol_state, response) = dispatch_on_next_round(protocol_state);
                *protocol_state_guard = new_protocol_state;
                response
            } else {
                response_invalid_role()
            }
        }
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
    match protobuf::parse_from_bytes::<transport_protocol::RuntimeManagerRequest>(&incoming_buffer) {
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
    roles: &Vec<Role>,
    input: &Vec<u8>,
) -> ProvisioningResult {
    match parse_incoming_buffer(tls_session_id, input.clone())? {
        None => Ok(ProvisioningResponse::WaitForMoreData),
        Some(REQUEST {
            message_oneof: None,
            ..
        }) => response_invalid_request(),
        Some(REQUEST {
            message_oneof: Some(request),
            ..
        }) => dispatch_on_request(client_id, roles, request),
    }
}
