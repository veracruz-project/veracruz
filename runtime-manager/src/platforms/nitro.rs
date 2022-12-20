//! AWS Nitro-Enclaves-specific material for the Runtime Manager enclave
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE_MIT.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

use crate::managers::{self, RuntimeManagerError};
use anyhow::{anyhow, Result};
use io_utils::raw_fd::{receive_buffer, send_buffer};
use nix::sys::socket::{
    accept, bind, listen as listen_vsock, socket, AddressFamily, SockAddr, SockFlag, SockType,
};
use nsm_api;
use nsm_lib;
use veracruz_utils::{
    runtime_manager_message::{RuntimeManagerRequest, RuntimeManagerResponse, Status},
    sha256::sha256,
};

/// The CID for the VSOCK to listen on
/// Currently set to all 1's so it will listen on all of them
const CID: u32 = 0xFFFFFFFF; // VMADDR_CID_ANY
/// The incoming port to listen on
const PORT: u32 = 5005;
/// max number of outstanding connections in the socket listen queue
const BACKLOG: usize = 128;

/// The maximum attestation document size
/// the value was copied from https://github.com/aws/aws-nitro-enclaves-sdk-c/blob/main/source/attestation.c
/// I've no idea where it came from (I've seen no documentation on this), but
/// I guess I have to trust Amazon on this one
const NSM_MAX_ATTESTATION_DOC_SIZE: usize = 16 * 1024;

/// The main function for the Nitro Runtime Manager enclave
pub fn nitro_main() -> Result<()> {
    let socket_fd = socket(
        AddressFamily::Vsock,
        SockType::Stream,
        SockFlag::empty(),
        None,
    )?;
    println!(
        "runtime_manager_nitro::nitro_main creating SockAddr, CID:{:?}, PORT:{:?}",
        CID, PORT
    );

    let sockaddr = SockAddr::new_vsock(CID, PORT);

    bind(socket_fd, &sockaddr)?;
    println!("runtime_manager_nitro::nitro_main calling accept");

    listen_vsock(socket_fd, BACKLOG)?;

    let fd = accept(socket_fd)?;
    println!("runtime_manager_nitro::nitro_main accept succeeded. looping");

    loop {
        let received_buffer = receive_buffer(fd)?;
        let received_message: RuntimeManagerRequest = bincode::deserialize(&received_buffer)?;
        let return_message = match received_message {
            RuntimeManagerRequest::Attestation(challenge, _challenge_id) => {
                attestation(&challenge)?
            }
            RuntimeManagerRequest::Initialize(policy_json, certificate_chain) => {
                initialize(&policy_json, &certificate_chain)?
            }
            RuntimeManagerRequest::NewTlsSession => {
                println!("runtime_manager_nitro::main NewTlsSession");
                let ns_result = managers::session_manager::new_session();
                let return_message: RuntimeManagerResponse = match ns_result {
                    Ok(session_id) => RuntimeManagerResponse::TlsSession(session_id),
                    Err(_) => RuntimeManagerResponse::Status(Status::Fail),
                };
                return_message
            }
            RuntimeManagerRequest::CloseTlsSession(session_id) => {
                println!("runtime_manager_nitro::main CloseTlsSession");
                let cs_result = managers::session_manager::close_session(session_id);
                let return_message: RuntimeManagerResponse = match cs_result {
                    Ok(_) => RuntimeManagerResponse::Status(Status::Success),
                    Err(_) => RuntimeManagerResponse::Status(Status::Fail),
                };
                return_message
            }
            RuntimeManagerRequest::GetTlsDataNeeded(session_id) => {
                println!("runtime_manager_nitro::main GetTlsDataNeeded");
                let return_message = match managers::session_manager::get_data_needed(session_id) {
                    Ok(needed) => RuntimeManagerResponse::TlsDataNeeded(needed),
                    Err(_) => RuntimeManagerResponse::Status(Status::Fail),
                };
                return_message
            }
            RuntimeManagerRequest::SendTlsData(session_id, tls_data) => {
                println!("runtime_manager_nitro::main SendTlsData");
                let return_message =
                    match managers::session_manager::send_data(session_id, &tls_data) {
                        Ok(_) => RuntimeManagerResponse::Status(Status::Success),
                        Err(_) => RuntimeManagerResponse::Status(Status::Fail),
                    };
                return_message
            }
            RuntimeManagerRequest::GetTlsData(session_id) => {
                println!("runtime_manager_nitro::main GetTlsData");
                let return_message = match managers::session_manager::get_data(session_id) {
                    Ok((active, output_data)) => {
                        RuntimeManagerResponse::TlsData(output_data, active)
                    }
                    Err(_) => RuntimeManagerResponse::Status(Status::Fail),
                };
                return_message
            }
        };
        let return_buffer = bincode::serialize(&return_message)?;
        println!(
            "runtime_manager_nitro::main calling send buffer with buffer_len:{:?}",
            return_buffer.len()
        );
        send_buffer(fd, &return_buffer)?;
    }
}

fn attestation(challenge: &[u8]) -> Result<RuntimeManagerResponse> {
    println!("runtime_manager_nitro::attestation started");
    managers::session_manager::init_session_manager()?;
    // generate the csr
    let csr: Vec<u8> = managers::session_manager::generate_csr()?;
    // generate the attestation document
    let att_doc: Vec<u8> = {
        let mut buffer: Vec<u8> = vec![0; NSM_MAX_ATTESTATION_DOC_SIZE];
        let mut buffer_len: u32 = buffer.len() as u32;
        let nsm_fd = nsm_lib::nsm_lib_init();
        if nsm_fd < 0 {
            return Err(anyhow!(RuntimeManagerError::NsmLibError(nsm_fd)));
        }
        let csr_hash = sha256(&csr);
        let status = unsafe {
            nsm_lib::nsm_get_attestation_doc(
                nsm_fd,                         // fd
                csr_hash.as_ptr() as *const u8, // user_data
                csr_hash.len() as u32,          // user_data_len
                challenge.as_ptr(),             // nonce_data
                challenge.len() as u32,         // nonce_len
                std::ptr::null() as *const u8,  // pub_key_data
                0 as u32,                       // pub_key_len
                buffer.as_mut_ptr(),            // att_doc_data
                &mut buffer_len,                // att_doc_len
            )
        };
        match status {
            nsm_api::api::ErrorCode::Success => (),
            _ => return Err(anyhow!(RuntimeManagerError::NsmErrorCode(status))),
        }
        unsafe {
            buffer.set_len(buffer_len as usize);
        }
        buffer.clone()
    };

    return Ok(RuntimeManagerResponse::AttestationData(att_doc, csr));
}

/// Handler for the RuntimeManagerRequest::Initialize message
fn initialize(policy_json: &str, cert_chain: &Vec<u8>) -> Result<RuntimeManagerResponse> {
    managers::session_manager::load_policy(policy_json)?;
    managers::session_manager::load_cert_chain(cert_chain)?;

    return Ok(RuntimeManagerResponse::Status(Status::Success));
}
