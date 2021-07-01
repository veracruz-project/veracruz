//! AWS Nitro-Enclaves-specific material for the Runtime Manager enclave
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

use nix::sys::socket::listen as listen_vsock;
use nix::sys::socket::{accept, bind, SockAddr};
use nix::sys::socket::{socket, AddressFamily, SockFlag, SockType};
use nsm_io;
use nsm_lib;
use std::os::unix::io::AsRawFd;
use veracruz_utils::{
    io::raw_fd::{receive_buffer, send_buffer}, io::vsocket, platform::nitro::nitro::{NitroRootEnclaveMessage, NitroStatus, RuntimeManagerMessage},
};

use crate::managers;
use crate::managers::RuntimeManagerError;

/// The CID for the VSOCK to listen on
/// Currently set to all 1's so it will listen on all of them
const CID: u32 = 0xFFFFFFFF; // VMADDR_CID_ANY
/// The CID to send ocalls to that the non-secure host is listening on
const HOST_CID: u32 = 3;
/// The incoming port to listen on
const PORT: u32 = 5005;
/// max number of outstanding connectiosn in the socket listen queue
const BACKLOG: usize = 128;
/// The port to use when performing ocalls to the non-secure host
const OCALL_PORT: u32 = 5006;

/// The maximum attestation document size
/// the value was copied from https://github.com/aws/aws-nitro-enclaves-sdk-c/blob/main/source/attestation.c
/// I've no idea where it came from (I've seen no documentation on this), but
/// I guess I have to trust Amazon on this one
const NSM_MAX_ATTESTATION_DOC_SIZE: usize = 16 * 1024;

/// The main function for the Nitro Runtime Manager enclave
pub fn nitro_main() -> Result<(), RuntimeManagerError> {
    let socket_fd = socket(
        AddressFamily::Vsock,
        SockType::Stream,
        SockFlag::empty(),
        None,
    )
    .map_err(|err| RuntimeManagerError::SocketError(err))?;
    println!(
        "runtime_manager_nitro::nitro_main creating SockAddr, CID:{:?}, PORT:{:?}",
        CID, PORT
    );

    let sockaddr = SockAddr::new_vsock(CID, PORT);

    bind(socket_fd, &sockaddr).map_err(|err| RuntimeManagerError::SocketError(err))?;
    println!("runtime_manager_nitro::nitro_main calling accept");

    listen_vsock(socket_fd, BACKLOG).map_err(|err| RuntimeManagerError::SocketError(err))?;

    let fd = accept(socket_fd).map_err(|err| RuntimeManagerError::SocketError(err))?;
    println!("runtime_manager_nitro::nitro_main accept succeeded. looping");
    loop {
        let received_buffer =
            receive_buffer(fd).map_err(|err| RuntimeManagerError::VeracruzSocketError(err))?;
        let received_message: RuntimeManagerMessage = bincode::deserialize(&received_buffer)
            .map_err(|err| RuntimeManagerError::BincodeError(err))?;
        let return_message = match received_message {
            RuntimeManagerMessage::Initialize(policy_json, challenge, challenge_id) => initialize(&policy_json, &challenge, challenge_id)?,
            RuntimeManagerMessage::NewTLSSession => {
                println!("runtime_manager_nitro::main NewTLSSession");
                let ns_result = managers::session_manager::new_session();
                let return_message: RuntimeManagerMessage = match ns_result {
                    Ok(session_id) => RuntimeManagerMessage::TLSSession(session_id),
                    Err(_) => RuntimeManagerMessage::Status(NitroStatus::Fail),
                };
                return_message
            }
            RuntimeManagerMessage::CloseTLSSession(session_id) => {
                println!("runtime_manager_nitro::main CloseTLSSession");
                let cs_result = managers::session_manager::close_session(session_id);
                let return_message: RuntimeManagerMessage = match cs_result {
                    Ok(_) => RuntimeManagerMessage::Status(NitroStatus::Success),
                    Err(_) => RuntimeManagerMessage::Status(NitroStatus::Fail),
                };
                return_message
            }
            RuntimeManagerMessage::GetTLSDataNeeded(session_id) => {
                println!("runtime_manager_nitro::main GetTLSDataNeeded");
                let return_message = match managers::session_manager::get_data_needed(session_id) {
                    Ok(needed) => RuntimeManagerMessage::TLSDataNeeded(needed),
                    Err(_) => RuntimeManagerMessage::Status(NitroStatus::Fail),
                };
                return_message
            }
            RuntimeManagerMessage::SendTLSData(session_id, tls_data) => {
                println!("runtime_manager_nitro::main SendTLSData");
                let return_message =
                    match managers::session_manager::send_data(session_id, &tls_data) {
                        Ok(_) => RuntimeManagerMessage::Status(NitroStatus::Success),
                        Err(_) => RuntimeManagerMessage::Status(NitroStatus::Fail),
                    };
                return_message
            }
            RuntimeManagerMessage::GetTLSData(session_id) => {
                println!("runtime_manager_nitro::main GetTLSData");
                let return_message = match managers::session_manager::get_data(session_id) {
                    Ok((active, output_data)) => {
                        RuntimeManagerMessage::TLSData(output_data, active)
                    }
                    Err(_) => RuntimeManagerMessage::Status(NitroStatus::Fail),
                };
                return_message
            }
            RuntimeManagerMessage::ResetEnclave => {
                // Do nothing here for now
                println!("runtime_manager_nitro::main ResetEnclave");
                RuntimeManagerMessage::Status(NitroStatus::Success)
            }
            _ => {
                println!("runtime_manager_nitro::main Unknown Opcode");
                RuntimeManagerMessage::Status(NitroStatus::Unimplemented)
            }
        };
        let return_buffer = bincode::serialize(&return_message)
            .map_err(|err| RuntimeManagerError::BincodeError(err))?;
        println!(
            "runtime_manager_nitro::main calling send buffer with buffer_len:{:?}",
            return_buffer.len()
        );
        send_buffer(fd, &return_buffer)
            .map_err(|err| RuntimeManagerError::VeracruzSocketError(err))?;
    }
}

/// Handler for the RuntimeManagerMessage::Initialize message
fn initialize(policy_json: &str, challenge: &[u8], challenge_id: i32) -> Result<RuntimeManagerMessage, RuntimeManagerError> {
    println!("runtime_manager_nitro::initialize started");
    managers::session_manager::init_session_manager(policy_json)?;
    
    // generate the csr
    let csr: Vec<u8> = managers::session_manager::generate_csr()?;
    // generate the attestation document
    let att_doc: Vec<u8> = {
        let mut buffer: Vec<u8> = vec![0; NSM_MAX_ATTESTATION_DOC_SIZE];
        let mut buffer_len: u32 = buffer.len() as u32;
        let nsm_fd = nsm_lib::nsm_lib_init();
        if nsm_fd < 0 {
            return Err(RuntimeManagerError::NsmLibError(nsm_fd));
        }
        let status = unsafe {
            nsm_lib::nsm_get_attestation_doc(
                nsm_fd,                             //fd
                csr.as_ptr() as *const u8,          // user_data
                csr.len() as u32,                   // user_data_len
                challenge.as_ptr(),                 // nonce_data
                challenge.len() as u32,             // nonce_len
                std::ptr::null() as *const u8,      // pub_key_data
                0 as u32,                           // pub_key_len
                buffer.as_mut_ptr(),                // att_doc_data
                &mut buffer_len,                    // att_doc_len
            )
        };
        match status {
            nsm_io::ErrorCode::Success => (),
            _ => return Err(RuntimeManagerError::NsmErrorCode(status)),
        }
        unsafe {
            buffer.set_len(buffer_len as usize);
        }
        buffer.clone()
    };

    let proxy_attestation_message = NitroRootEnclaveMessage::ProxyAttestation(att_doc, challenge_id);
    let pam_message_buffer =
        bincode::serialize(&proxy_attestation_message).map_err(|err| RuntimeManagerError::BincodeError(err))?;

    // send the attestation message to the root enclave via an ocall
    let vsocksocket = vsocket::VsockSocket::connect(HOST_CID, OCALL_PORT)
        .map_err(|err| RuntimeManagerError::SocketError(err))?;
    send_buffer(vsocksocket.as_raw_fd(), &pam_message_buffer)
        .map_err(|err| RuntimeManagerError::VeracruzSocketError(err))?;
    let received_buffer = receive_buffer(vsocksocket.as_raw_fd())
        .map_err(|err| RuntimeManagerError::VeracruzSocketError(err))?;
    let received_message: NitroRootEnclaveMessage = bincode::deserialize(&received_buffer)
        .map_err(|err| RuntimeManagerError::BincodeError(err))?;

    let cert_chain = match received_message {
        NitroRootEnclaveMessage::CertChain(chain) => chain,
        _ => return Err(RuntimeManagerError::WrongMessageTypeError(received_message)),
    };

    managers::session_manager::load_cert_chain(cert_chain)?;

    return Ok(RuntimeManagerMessage::Status(NitroStatus::Success));
}
