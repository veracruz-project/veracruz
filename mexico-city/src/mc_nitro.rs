//! AWS Nitro-Enclaves-specific material for the Mexico City enclave
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

use byteorder::{ByteOrder, LittleEndian};
use nix::sys::socket::listen as listen_vsock;
use nix::sys::socket::{accept, bind, recv, send, MsgFlags, SockAddr};
use nix::sys::socket::{socket, AddressFamily, SockFlag, SockType};
use nsm_io;
use nsm_lib;
use std::convert::TryInto;
use std::os::unix::io::AsRawFd;
use std::os::unix::io::RawFd;
use veracruz_utils::{
    receive_buffer, send_buffer, vsocket, MCMessage, NitroRootEnclaveMessage, NitroStatus,
};

use crate::managers;
use crate::managers::MexicoCityError;

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

/// The main function for the Nitro mexico city enclave
pub fn nitro_main() -> Result<(), MexicoCityError> {
    let socket_fd = socket(
        AddressFamily::Vsock,
        SockType::Stream,
        SockFlag::empty(),
        None,
    )
    .map_err(|err| MexicoCityError::SocketError(err))?;
    println!(
        "mc_nitro::nitro_main creating SockAddr, CID:{:?}, PORT:{:?}",
        CID, PORT
    );
    let sockaddr = SockAddr::new_vsock(CID, PORT);

    bind(socket_fd, &sockaddr).map_err(|err| MexicoCityError::SocketError(err))?;
    println!("mc_nitro::nitro_main calling accept");

    listen_vsock(socket_fd, BACKLOG)
        .map_err(|err| MexicoCityError::SocketError(err))?;

    let fd = accept(socket_fd).map_err(|err| MexicoCityError::SocketError(err))?;
    println!("mc_nitro::nitro_main accept succeeded. looping");
    loop {
        let received_buffer = receive_buffer(fd)
            .map_err(|err| MexicoCityError::VeracruzSocketError(err))?;
        let received_message: MCMessage = bincode::deserialize(&received_buffer)
            .map_err(|err| MexicoCityError::BincodeError(err))?;
        let return_message = match received_message {
            MCMessage::Initialize(policy_json) => initialize(&policy_json)?,
            MCMessage::GetEnclaveCert => {
                println!("mc_nitro::main GetEnclaveCert");
                let return_message = match managers::baja_manager::get_enclave_cert_pem() {
                    Ok(cert) => MCMessage::EnclaveCert(cert),
                    Err(_) => MCMessage::Status(NitroStatus::Fail),
                };
                return_message
            }
            MCMessage::GetEnclaveName => {
                println!("mc_nitro::main GetEnclaveName");
                let return_message = match managers::baja_manager::get_enclave_name() {
                    Ok(name) => MCMessage::EnclaveName(name),
                    Err(_) => MCMessage::Status(NitroStatus::Fail),
                };
                return_message
            }
            MCMessage::NewTLSSession => {
                println!("mc_nitro::main NewTLSSession");
                let ns_result = managers::baja_manager::new_session();
                let return_message: MCMessage = match ns_result {
                    Ok(session_id) => MCMessage::TLSSession(session_id),
                    Err(_) => MCMessage::Status(NitroStatus::Fail),
                };
                return_message
            }
            MCMessage::CloseTLSSession(session_id) => {
                println!("mc_nitro::main CloseTLSSession");
                let cs_result = managers::baja_manager::close_session(session_id);
                let return_message: MCMessage = match cs_result {
                    Ok(_) => MCMessage::Status(NitroStatus::Success),
                    Err(_) => MCMessage::Status(NitroStatus::Fail),
                };
                return_message
            }
            MCMessage::GetTLSDataNeeded(session_id) => {
                println!("mc_nitro::main GetTLSDataNeeded");
                let return_message = match managers::baja_manager::get_data_needed(session_id) {
                    Ok(needed) => MCMessage::TLSDataNeeded(needed),
                    Err(_) => MCMessage::Status(NitroStatus::Fail),
                };
                return_message
            }
            MCMessage::SendTLSData(session_id, tls_data) => {
                println!("mc_nitro::main SendTLSData");
                let return_message = match managers::baja_manager::send_data(session_id, &tls_data)
                {
                    Ok(_) => MCMessage::Status(NitroStatus::Success),
                    Err(_) => MCMessage::Status(NitroStatus::Fail),
                };
                return_message
            }
            MCMessage::GetTLSData(session_id) => {
                println!("mc_nitro::main GetTLSData");
                let return_message = match managers::baja_manager::get_data(session_id) {
                    Ok((active, output_data)) => MCMessage::TLSData(output_data, active),
                    Err(_) => MCMessage::Status(NitroStatus::Fail),
                };
                return_message
            }
            MCMessage::GetPSAAttestationToken(challenge) => {
                println!("mc_nitro::main GetPSAAttestationToken");
                get_psa_attestation_token(&challenge)?
            }
            MCMessage::ResetEnclave => {
                // Do nothing here for now
                println!("mc_nitro::main ResetEnclave");
                MCMessage::Status(NitroStatus::Success)
            }
            _ => {
                println!("mc_nitro::main Unknown Opcode");
                MCMessage::Status(NitroStatus::Unimplemented)
            }
        };
        let return_buffer = bincode::serialize(&return_message)
            .map_err(|err| MexicoCityError::BincodeError(err))?;
        println!(
            "mc_nitro::main calling send buffer with buffer_len:{:?}",
            return_buffer.len()
        );
        send_buffer(fd, &return_buffer)
            .map_err(|err| MexicoCityError::VeracruzSocketError(err))?;
    }
}

/// Handler for the MCMessage::Initialize message
fn initialize(policy_json: &str) -> Result<MCMessage, MexicoCityError> {
    println!("mc_nitro::initialize started");
    managers::baja_manager::init_baja(policy_json)?;
    println!("mc_nitro::main init_baja completed");
    return Ok(MCMessage::Status(NitroStatus::Success));
}

/// Handler for the MCMessage::GetPSAAttestationToken message
fn get_psa_attestation_token(challenge: &[u8]) -> Result<MCMessage, MexicoCityError> {
    println!("mc_nitro::get_psa_attestation_token started");
    println!(
        "nc_nitro::get_psa_attestation_token received challenge:{:?}",
        challenge
    );

    let enclave_cert = managers::baja_manager::get_enclave_cert_pem()?;

    let enclave_cert_hash = ring::digest::digest(&ring::digest::SHA256, &enclave_cert);
    let nitro_token: Vec<u8> = {
        let mut att_doc: Vec<u8> = vec![0; NSM_MAX_ATTESTATION_DOC_SIZE];
        let mut att_doc_len: u32 = att_doc.len() as u32;

        let nsm_fd = nsm_lib::nsm_lib_init();
        if nsm_fd < 0 {
            return Err(MexicoCityError::NsmLibError(nsm_fd));
        }
        let status = unsafe {
            nsm_lib::nsm_get_attestation_doc(
                nsm_fd,                                           //fd
                enclave_cert_hash.as_ref().as_ptr() as *const u8, // user_data
                enclave_cert_hash.as_ref().len() as u32,          // user_data_len
                challenge.as_ptr(),                               // nonce_data
                challenge.len() as u32,                           // nonce_len
                std::ptr::null() as *const u8,                    // pub_key_data
                0 as u32,                                         // pub_key_len
                att_doc.as_mut_ptr(),                             // att_doc_data
                &mut att_doc_len,                                 // att_doc_len
            )
        };
        match status {
            nsm_io::ErrorCode::Success => (),
            _ => return Err(MexicoCityError::NsmErrorCode(status)),
        }
        unsafe {
            att_doc.set_len(att_doc_len as usize);
        }
        att_doc.clone()
    };
    let enclave_name: String = managers::baja_manager::get_enclave_name()?;
    let nre_message =
        NitroRootEnclaveMessage::ProxyAttestation(challenge.to_vec(), nitro_token, enclave_name);
    let nre_message_buffer = bincode::serialize(&nre_message).map_err(|err|MexicoCityError::BincodeError(err))?;

    // send the buffer back to Sinaloa via an ocall
    let vsocksocket = vsocket::vsock_connect(HOST_CID, OCALL_PORT)
        .map_err(|err| MexicoCityError::SocketError(err))?;
    send_buffer(vsocksocket.as_raw_fd(), &nre_message_buffer)
        .map_err(|err| MexicoCityError::VeracruzSocketError(err))?;
    let received_buffer = receive_buffer(vsocksocket.as_raw_fd())
        .map_err(|err| MexicoCityError::VeracruzSocketError(err))?;
    let received_message: NitroRootEnclaveMessage = bincode::deserialize(&received_buffer)
        .map_err(|err| MexicoCityError::BincodeError(err))?;

    let (psa_token, pubkey, device_id) = match received_message {
        NitroRootEnclaveMessage::PSAToken(token, pubkey, d_id) => (token, pubkey, d_id),
        _ => {
            return Err(MexicoCityError::WrongMessageTypeError(received_message))
        }
    };
    let psa_token_message: MCMessage =
        MCMessage::PSAAttestationToken(psa_token, pubkey, device_id.try_into().unwrap());

    return Ok(psa_token_message);
}
