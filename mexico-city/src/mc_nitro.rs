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
use std::os::unix::io::RawFd;
use veracruz_utils::{MCMessage, NitroStatus, receive_buffer, send_buffer};

const CID: u32 = 0xFFFFFFFF; // VMADDR_CID_ANY
const PORT: u32 = 5005;
// max number of outstanding connectiosn in the socket listen queue
const BACKLOG: usize = 128;

pub fn nitro_main() -> Result<(), String> {

    let socket_fd =  socket (AddressFamily::Vsock, SockType::Stream, SockFlag::empty(), None)
        .map_err(|err| format!("mc_nitro::main socket failed:{:?}", err))?;
    println!("mc_nitro::nitro_main creating SockAddr, CID:{:?}, PORT:{:?}", CID, PORT);
    let sockaddr = SockAddr::new_vsock(CID, PORT);

    bind (socket_fd, &sockaddr)
        .map_err(|err| format!("mc_nitro::main bind failed:{:?}", err))?;
    println!("mc_nitro::nitro_main calling accept");

    listen_vsock(socket_fd, BACKLOG)
        .map_err(|err| format!("mc_nistro::main listen_vsock failed:{:?}", err))?;

    std::thread::sleep(std::time::Duration::from_millis(20000));
    let fd = accept(socket_fd)
        .map_err(|err| format!("mc_nitro::main accept failed:{:?}", err))?;
    println!("mc_nitro::nitro_main accept succeeded. looping");
    loop {
        let received_buffer = receive_buffer(fd)
            .map_err(|err| format!("mc_nitro::main receive_buffer failed:{:?}", err))?;
        let received_message: MCMessage = bincode::deserialize(&received_buffer)
            .map_err(|err| format!("mc_nitro::main deserialize failed:{:?}", err))?;
        let return_message = match received_message {
            MCMessage::Initialize(policy_json) => {
                println!("mc_nitro::main Initialize");
                crate::managers::baja_manager::init_baja(&policy_json)
                    .map_err(|err| format!("mc_nitro::main init_baja failed:{:?}", err))?;
                println!("mc_nitro::main init_baja completed");
                MCMessage::Status(NitroStatus::Success)
            },
            MCMessage::GetEnclaveCert => {
                println!("mc_nitro::main GetEnclaveCert");
                MCMessage::Status(NitroStatus::Unimplemented)
            },
            MCMessage::GetEnclaveName => {
                println!("mc_nitro::main GetEnclaveName");
                MCMessage::Status(NitroStatus::Unimplemented)
            },
            MCMessage::NewTLSSession => {
                println!("mc_nitro::main NewTLSSession");
                MCMessage::Status(NitroStatus::Unimplemented)
            },
            MCMessage::CloseTLSSession(_session_id) => {
                println!("mc_nitro::main CloseTLSSession");
                MCMessage::Status(NitroStatus::Unimplemented)
            },
            MCMessage::GetTLSDataNeeded(_session_id) => {
                println!("mc_nitro::main GetTLSDataNeeded");
                MCMessage::Status(NitroStatus::Unimplemented)
            },
            MCMessage::SendTLSData(_session_id, _tls_data) => {
                println!("mc_nitro::main SendTLSData");
                MCMessage::Status(NitroStatus::Unimplemented)
            },
            MCMessage::GetTLSData(_session_id) => {
                println!("mc_nitro::main GetTLSData");
                MCMessage::Status(NitroStatus::Unimplemented)
            },
            MCMessage::GetPSAAttestationToken(_challenge) => {
                println!("mc_nitro::main GetPSAAttestationToken");
                MCMessage::Status(NitroStatus::Unimplemented)
            },
            MCMessage::ResetEnclave => {
                println!("mc_nitro::main ResetEnclave");
                MCMessage::Status(NitroStatus::Unimplemented)
            },
            _ => {
                println!("mc_nitro::main Unknown Opcode");
                MCMessage::Status(NitroStatus::Unimplemented)
            },
        };
        let return_buffer = bincode::serialize(&return_message)
            .map_err(|err| format!("mc_nitro::main serialize failed:{:?}", err))?;
        println!("mc_nitro::main calling send buffer with buffer_len:{:?}", return_buffer.len());
        send_buffer(fd, &return_buffer)
            .map_err(|err| format!("mc_nitro::main send_buffer failed:{:?}", err))?;
    }
}
