//! Interfaces with the session manager.
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE.md` file in the Veracruz root directory for
//! information on licensing and copyright.

use crate::managers::{ProtocolState, RuntimeManagerError, MY_SESSION_MANAGER};
use anyhow::{anyhow, Result};
use policy_utils::policy::Policy;
use session_manager::SessionContext;
use std::{sync::atomic::Ordering, vec::Vec};
use veracruz_utils::csr;
use veracruz_utils::sha256::sha256;
use log::info;

pub fn init_session_manager() -> Result<()> {
    let new_session_manager = SessionContext::new()?;

    *super::MY_SESSION_MANAGER
        .lock()
        .map_err(|_| anyhow!(RuntimeManagerError::LockSessionManager))? = Some(new_session_manager);

    Ok(())
}

pub fn load_policy(policy_json: &str) -> Result<()> {
    info!("load_policy:{:?}", policy_json);
    let policy_hash = sha256(&policy_json.as_bytes());
    let policy = Policy::from_json(policy_json)?;

    if *policy.debug() {
        super::DEBUG_FLAG.store(true, Ordering::SeqCst);
    }

    let state = ProtocolState::new(policy.clone(), hex::encode(policy_hash))?;
    *super::PROTOCOL_STATE
        .lock()
        .map_err(|_| anyhow!(RuntimeManagerError::LockProtocolState))? = Some(state);

    super::MY_SESSION_MANAGER
        .lock()
        .map_err(|_| anyhow!(RuntimeManagerError::LockSessionManager))?
        .as_mut()
        .ok_or(anyhow!(RuntimeManagerError::UninitializedSessionError(
            "session_manager_state",
        )))?
        .set_policy(policy)?;
    Ok(())
}

pub fn load_cert_chain(chain: &Vec<u8>) -> Result<()> {
    MY_SESSION_MANAGER
        .lock()
        .map_err(|_| anyhow!(RuntimeManagerError::LockSessionManager))?
        .as_mut()
        .ok_or(anyhow!(RuntimeManagerError::UninitializedSessionError(
            "load_cert_chain",
        )))?
        .set_cert_chain(chain)?;
    Ok(())
}

pub fn new_session() -> Result<u32> {
    let local_session_id = super::SESSION_COUNTER.fetch_add(1, Ordering::SeqCst);

    let session = super::MY_SESSION_MANAGER
        .lock()
        .map_err(|_| anyhow!(RuntimeManagerError::LockSessionManager))?
        .as_mut()
        .ok_or(anyhow!(RuntimeManagerError::UninitializedSessionError(
            "new_session",
        )))?
        .create_session()?;

    super::SESSIONS
        .lock()
        .map_err(|_| anyhow!(RuntimeManagerError::LockSessionTable))?
        .insert(local_session_id, session);
    Ok(local_session_id)
}

pub fn close_session(session_id: u32) -> Result<()> {
    super::SESSIONS
        .lock()
        .map_err(|_| anyhow!(RuntimeManagerError::LockSessionTable))?
        .remove(&session_id);
    Ok(())
}

pub fn send_data(session_id: u32, input_data: &[u8]) -> Result<()> {
    let mut sessions = super::SESSIONS
        .lock()
        .map_err(|_| anyhow!(RuntimeManagerError::LockSessionTable))?;
    let this_session = sessions.get_mut(&session_id).ok_or(anyhow!(
        RuntimeManagerError::UnavailableSessionError(session_id as u64,)
    ))?;
    this_session.send_tls_data(&mut input_data.to_vec())?;

    let plaintext_option = this_session.read_plaintext_data()?;

    let proc_ret: super::ProvisioningResponse = match plaintext_option {
        Some((client_id, plaintext_data)) => {
            super::execution_engine_manager::dispatch_on_incoming_data(
                session_id,
                client_id as u64,
                &plaintext_data,
            )?
        }
        // We need to wait longer for this to arrive.
        None => return Ok(()),
    };

    match proc_ret {
        // The incoming buffer is not full, so we cannot parse a complete protobuf
        // message.  We need to wait longer for this to arrive.
        None => Ok(()),
        Some(response) => Ok(this_session.write_plaintext_data(&response)?),
    }
}

pub fn get_data(session_id: u32) -> Result<(bool, Vec<u8>)> {
    let result = match super::SESSIONS
        .lock()
        .map_err(|_| anyhow!(RuntimeManagerError::LockSessionTable))?
        .get_mut(&session_id)
    {
        Some(this_session) => Ok(this_session.read_tls_data()),
        None => Err(anyhow!(RuntimeManagerError::UnavailableSessionError(
            session_id as u64,
        ))),
    }??;

    let active_flag = super::PROTOCOL_STATE
        .lock()
        .map_err(|_| anyhow!(RuntimeManagerError::LockProtocolState))?
        .is_some();

    Ok((active_flag, result.unwrap_or(vec![])))
}

fn get_enclave_private_key_der() -> Result<Vec<u8>> {
    Ok(super::MY_SESSION_MANAGER
        .lock()
        .map_err(|_| anyhow!(RuntimeManagerError::LockSessionManager))?
        .as_mut()
        .ok_or(anyhow!(RuntimeManagerError::UninitializedSessionError(
            "get_enclave_private_key",
        )))?
        .private_key()
        .to_vec())
}

pub fn generate_csr() -> Result<Vec<u8>> {
    let private_key_der = get_enclave_private_key_der()?;
    let csr = csr::generate_csr(&private_key_der).map_err(|err| anyhow!(err))?;
    return Ok(csr);
}
