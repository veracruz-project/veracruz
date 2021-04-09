//! Interfaces with the session manager.
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

use crate::managers::*;
use ::session_manager::SessionContext;
use std::{sync::atomic::Ordering, vec::Vec};
use veracruz_utils::policy::policy::Policy;
use ring::{rand::SystemRandom};
use rustls::PrivateKey;

pub fn init_session_manager(policy_json: &str) -> Result<(), RuntimeManagerError> {
    let policy_hash = ring::digest::digest(&ring::digest::SHA256, &policy_json.as_bytes());
    let policy = Policy::from_json(policy_json)?;

    if *policy.debug() {
        super::DEBUG_FLAG.store(true, Ordering::SeqCst);
    }

    {
        let state = ProtocolState::new(policy.clone(), hex::encode(policy_hash.as_ref()))?;
        let mut protocol_state = super::PROTOCOL_STATE.lock()?;
        *protocol_state = Some(state);
    }

    //TODO: change the error type
    let new_session_manager = SessionContext::new(policy)?;

    {
        let mut session_manager_state = super::MY_SESSION_MANAGER.lock()?;
        *session_manager_state = Some(new_session_manager);
    }

    Ok(())
}

pub fn new_session() -> Result<u32, RuntimeManagerError> {
    let local_session_id = super::SESSION_COUNTER.fetch_add(1, Ordering::SeqCst);

    let session = match &*super::MY_SESSION_MANAGER.lock()? {
        Some(my_session_manager) => my_session_manager.create_session(),
        None => {
            return Err(RuntimeManagerError::UninitializedSessionError(
                "new_session",
            ))
        }
    };

    super::SESSIONS.lock()?.insert(local_session_id, session);
    Ok(local_session_id)
}

pub fn close_session(session_id: u32) -> Result<(), RuntimeManagerError> {
    super::SESSIONS.lock()?.remove(&session_id);
    Ok(())
}

pub fn send_data(session_id: u32, input_data: &[u8]) -> Result<(), RuntimeManagerError> {
    let mut sessions = super::SESSIONS.lock()?;
    let this_session =
        sessions
            .get_mut(&session_id)
            .ok_or(RuntimeManagerError::UnavailableSessionError(
                session_id as u64,
            ))?;
    let _result = this_session.send_tls_data(&mut input_data.to_vec())?;

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
        Some(response) => Ok(this_session.return_data(&response)?),
    }
}

// TODO: The 'match' inside the and_then closure is difficult to parse
pub fn get_data(session_id: u32) -> Result<(bool, Vec<u8>), RuntimeManagerError> {
    let (result, _) = match super::SESSIONS.lock()?.get_mut(&session_id) {
        Some(this_session) => {
            let result = this_session.read_tls_data();
            let needed = this_session.read_tls_needed();
            //TODO: change the error type
            Ok((result, needed))
        }
        None => Err(RuntimeManagerError::UnavailableSessionError(
            session_id as u64,
        )),
    }?;

    let active_flag = super::PROTOCOL_STATE.lock()?.is_some();

    match result? {
        Some(output_data) => Ok((active_flag, output_data)),
        None => Err(RuntimeManagerError::NoDataError),
    }
}

pub fn get_data_needed(session_id: u32) -> Result<bool, RuntimeManagerError> {
    match super::SESSIONS.lock()?.get_mut(&session_id) {
        Some(this_session) => Ok(this_session.read_tls_needed()),
        None => Err(RuntimeManagerError::UnavailableSessionError(
            session_id as u64,
        )),
    }
}

pub fn get_enclave_cert_pem() -> Result<Vec<u8>, RuntimeManagerError> {
    match &*super::MY_SESSION_MANAGER.lock()? {
        Some(my_session_manager) => Ok(my_session_manager.server_certificate_buffer().clone()),
        None => Err(RuntimeManagerError::UninitializedSessionError(
            "get_enclave_cert_pem",
        )),
    }
}

pub fn get_enclave_cert() -> Result<rustls::Certificate, RuntimeManagerError> {
    match &*super::MY_SESSION_MANAGER.lock()? {
        Some(my_session_manager) => Ok(my_session_manager.server_certificate().clone()),
        None => Err(RuntimeManagerError::UninitializedSessionError(
            "get_enclave_cert",
        )),
    }
}

fn get_enclave_public_key() -> Result<Vec<u8>, RuntimeManagerError> {
    match &*super::MY_SESSION_MANAGER.lock()? {
        Some(session_manager) => {
            return Ok(session_manager.public_key());
        },
        None => {
            return Err(RuntimeManagerError::UninitializedSessionError("get_enclave_public_key"));
        },
    }
}

fn get_enclave_private_key() -> Result<PrivateKey, RuntimeManagerError> {
    match &*super::MY_SESSION_MANAGER.lock()? {
        Some(session_manager) => {
            return Ok(session_manager.private_key());
        },
        None => {
            return Err(RuntimeManagerError::UninitializedSessionError("get_enclave_private_key"));
        },
    }
}

const CSR_TEMPLATE: [u8; 308] = [
    0x30, 0x82, 0x01, 0x30, 0x30, 0x81, 0xd7, 0x02, 0x01, 0x00, 0x30, 0x75, 0x31, 0x0b, 0x30, 0x09,
    0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x0e, 0x30, 0x0c, 0x06, 0x03, 0x55,
    0x04, 0x08, 0x0c, 0x05, 0x54, 0x65, 0x78, 0x61, 0x73, 0x31, 0x0f, 0x30, 0x0d, 0x06, 0x03, 0x55,
    0x04, 0x07, 0x0c, 0x06, 0x41, 0x75, 0x73, 0x74, 0x69, 0x6e, 0x31, 0x11, 0x30, 0x0f, 0x06, 0x03,
    0x55, 0x04, 0x0a, 0x0c, 0x08, 0x56, 0x65, 0x72, 0x61, 0x63, 0x72, 0x75, 0x7a, 0x31, 0x18, 0x30,
    0x16, 0x06, 0x03, 0x55, 0x04, 0x0b, 0x0c, 0x0f, 0x43, 0x6f, 0x6d, 0x70, 0x75, 0x74, 0x65, 0x20,
    0x45, 0x6e, 0x63, 0x6c, 0x61, 0x76, 0x65, 0x31, 0x18, 0x30, 0x16, 0x06, 0x03, 0x55, 0x04, 0x03,
    0x0c, 0x0f, 0x56, 0x65, 0x72, 0x61, 0x63, 0x72, 0x75, 0x7a, 0x43, 0x6f, 0x6d, 0x70, 0x75, 0x74,
    0x65, 0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08,
    0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0x50, 0x29, 0x2c, 0x67,
    0xbe, 0x19, 0x99, 0xed, 0xcc, 0xb0, 0x95, 0x06, 0x93, 0xea, 0xb8, 0xf1, 0xe9, 0xc5, 0x0c, 0x10,
    0xdd, 0x8c, 0x61, 0xa9, 0xa8, 0x3a, 0xe4, 0xb8, 0x17, 0xa7, 0xbe, 0xf6, 0xcb, 0x9f, 0x64, 0x76,
    0x57, 0x19, 0x3e, 0x84, 0x97, 0x66, 0x63, 0x8c, 0x26, 0x51, 0x71, 0x5c, 0x7d, 0x7f, 0xee, 0xe6,
    0x8a, 0xeb, 0xd4, 0xd1, 0x1d, 0x73, 0x5b, 0x94, 0xec, 0x9d, 0xf6, 0x98, 0xa0, 0x00, 0x30, 0x0a,
    0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x03, 0x48, 0x00, 0x30, 0x45, 0x02,
    0x20, 0x42, 0x24, 0x0e, 0x7d, 0x03, 0x71, 0x27, 0xbc, 0x5c, 0x6c, 0x81, 0xc3, 0xec, 0x2a, 0x75,
    0xb4, 0xaa, 0x46, 0xcd, 0x5c, 0x81, 0x2d, 0xdf, 0x05, 0x7c, 0xd5, 0x76, 0x8e, 0x03, 0xe2, 0xf5,
    0x54, 0x02, 0x21, 0x00, 0xf6, 0xfc, 0x0b, 0xb6, 0xd8, 0xbb, 0xc1, 0x11, 0x93, 0x47, 0x73, 0xbd,
    0xd9, 0xcf, 0x86, 0x14, 0x71, 0x15, 0x94, 0x6c, 0x5f, 0x35, 0xf1, 0x68, 0xfc, 0x24, 0xac, 0xbd,
    0xba, 0x07, 0xc2, 0x62
];

const PUBLIC_KEY_LOCATION: (usize, usize) = (152, 152 + 68);
const SIGNATURE_PART_1_LOCATION: (usize, usize) = (241, 241 + 32);
const SIGNATURE_PART_2_LOCATION: (usize, usize) = (276, 276 + 32);

pub fn get_csr() -> Result<Vec<u8>, RuntimeManagerError> {
    let mut constructed_csr = CSR_TEMPLATE.to_vec();

    let public_key = get_enclave_public_key()?;
    let message = format!("public_key.len:{:?}, expected:{:?}", public_key.len(), PUBLIC_KEY_LOCATION.1 - PUBLIC_KEY_LOCATION.0);
    println!("{:?}", message);
    assert!(public_key.len() == (PUBLIC_KEY_LOCATION.1 - PUBLIC_KEY_LOCATION.0), message);
    constructed_csr.splice(
        PUBLIC_KEY_LOCATION.0..PUBLIC_KEY_LOCATION.1,
        public_key.iter().cloned(),
    );

    let private_key_vec = get_enclave_private_key()?.0;
    let private_key = ring::signature::EcdsaKeyPair::from_pkcs8(&ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING, &private_key_vec)
        .map_err(|err| RuntimeManagerError::RingKeyRejected(err))?;
    let rng = SystemRandom::new();
    let signature: Vec<u8> = private_key.sign(&rng, &constructed_csr[..]).unwrap().as_ref().to_vec();

    let mut signature_first = vec![0; 32];
    signature_first[..].clone_from_slice(&signature[0..32]);
    if signature_first.len() != (SIGNATURE_PART_1_LOCATION.1 - SIGNATURE_PART_1_LOCATION.0) {
        return Err(RuntimeManagerError::DataWrongSizeForField( format!("signature_first"), SIGNATURE_PART_1_LOCATION.1 - SIGNATURE_PART_1_LOCATION.0, signature_first.len()));
    }
    constructed_csr.splice(
        SIGNATURE_PART_1_LOCATION.0..SIGNATURE_PART_1_LOCATION.1,
        signature_first.iter().cloned(),
    );

    let mut signature_second = vec![0; 32];
    signature_second[..].clone_from_slice(&signature[32..64]);
    if signature_second.len() != (SIGNATURE_PART_2_LOCATION.1 - SIGNATURE_PART_2_LOCATION.0) {
        return Err(RuntimeManagerError::DataWrongSizeForField(format!("signature_second"), SIGNATURE_PART_2_LOCATION.1 - SIGNATURE_PART_2_LOCATION.0, signature_second.len()));
    }
    println!("Attempting final. constructed_csr.len:{:?}", constructed_csr.len());
    constructed_csr.splice(
        SIGNATURE_PART_2_LOCATION.0..SIGNATURE_PART_2_LOCATION.1,
        signature_second.iter().cloned(),
    );
    println!("Final complete. The problem ain't here.");

    if constructed_csr.len() != CSR_TEMPLATE.len() {
        return Err(RuntimeManagerError::DataWrongSizeForField(
            format!("constructed_csr"),
            CSR_TEMPLATE.len(),
            constructed_csr.len()
        ));
    };
    return Ok(constructed_csr);
}

pub fn get_enclave_name() -> Result<std::string::String, RuntimeManagerError> {
    match &*super::MY_SESSION_MANAGER.lock()? {
        Some(my_session_manager) => Ok(my_session_manager.name().clone()),
        None => Err(RuntimeManagerError::UninitializedSessionError(
            "get_enclave_name",
        )),
    }
}
