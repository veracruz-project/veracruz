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
use veracruz_utils::{MCMessage, NitroStatus};

const CID: u32 = 0xFFFFFFFF; // VMADDR_CID_ANY
const PORT: u32 = 5006;

pub fn nitro_main() -> Result<(), String> {

    let socket_fd =  socket (AddressFamily::Vsock, SockType::Stream, SockFlag::empty(), None)
        .map_err(|err| format!("mc_nitro::main socket failed:{:?}", err))?;
    let sockaddr = SockAddr::new_vsock(CID, PORT);

    bind (socket_fd, &sockaddr)
        .map_err(|err| format!("mc_nitro::main bind failed:{:?}", err))?;
    let fd = accept(socket_fd)
        .map_err(|err| format!("mc_nitro::main accept failed:{:?}", err))?;
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
                MCMessage::Status(NitroStatus::Success)
            },
            MCMessage::GetEnclaveCert => {
                MCMessage::Status(NitroStatus::Unimplemented)
            },
            MCMessage::GetEnclaveName => {
                MCMessage::Status(NitroStatus::Unimplemented)
            },
            MCMessage::NewTLSSession => {
                MCMessage::Status(NitroStatus::Unimplemented)
            },
            MCMessage::CloseTLSSession(_session_id) => {
                MCMessage::Status(NitroStatus::Unimplemented)
            },
            MCMessage::GetTLSDataNeeded(_session_id) => {
                MCMessage::Status(NitroStatus::Unimplemented)
            },
            MCMessage::SendTLSData(_session_id, _tls_data) => {
                MCMessage::Status(NitroStatus::Unimplemented)
            },
            MCMessage::GetTLSData(_session_id) => {
                MCMessage::Status(NitroStatus::Unimplemented)
            },
            MCMessage::GetPSAAttestationToken(_challenge) => {
                MCMessage::Status(NitroStatus::Unimplemented)
            },
            MCMessage::ResetEnclave => {
                MCMessage::Status(NitroStatus::Unimplemented)
            },
            _ => {
                MCMessage::Status(NitroStatus::Unimplemented)
            },
        };
        let return_buffer = bincode::serialize(&return_message)
            .map_err(|err| format!("mc_nitro::main serialize failed:{:?}", err))?;
        send_buffer(fd, &return_buffer)
            .map_err(|err| format!("mc_nitro::main send_buffer failed:{:?}", err))?;
    }
}

fn receive_buffer(fd: RawFd) -> Result<Vec<u8>, String> {
    // first, read the length
    println!("Chiapas::receive_buffer started with fd:{:?}", fd);
    let length = {
        let mut buf = [0u8; 9];
        let len = buf.len();
        let mut received_bytes = 0;
        println!("iterating until we receive len:{:?}", len);
        while received_bytes < len {
            received_bytes += match recv(fd, &mut buf[received_bytes..len], MsgFlags::empty()) {
                Ok(size) => {
                    size
                },
                Err(nix::Error::Sys(EINTR)) => 0,
                Err(err) => {
                    println!("I have experienced an error");
                    return Err(format!(
                        "SinaloaNitro::receive_buffer failed to read bytes of length:{:?}",
                        err
                    ))
                }
            }
        }
        println!("Received num bytes:{:?}", received_bytes);
        println!("Received buffer:{:?}", buf);
        println!("Attempting little endian conversion");
        LittleEndian::read_u64(&buf) as usize
    };
    println!("CHiapas::receive_buffer has read length:{:?}", length);
    let mut buffer: Vec<u8> = vec![0; length];
    // next, read the buffer
    {
        let mut received_bytes: usize = 0;
        while received_bytes < length {
            received_bytes += match recv(fd, &mut buffer[received_bytes..length], MsgFlags::empty())
            {
                Ok(size) => size,
                Err(nix::Error::Sys(EINTR)) => 0,
                Err(err) => {
                    return Err(format!(
                        "SinaloaNitro::receive_buffer failed to read bytes to buffer:{:?}",
                        err
                    ))
                }
            }
        }
    }
    println!("Chiapas::receive_buffer has finished:{:?}", buffer);
    return Ok(buffer);
}

pub fn send_buffer(fd: RawFd, buffer: &Vec<u8>) -> Result<(), String> {
    println!("Chiapas::send_buffer started with fd:{:?}", fd);
    let len = buffer.len();
    // first, send the length of the buffer
    {
        let mut buf = [0u8; 9];
        LittleEndian::write_u64(&mut buf, buffer.len() as u64);
        let mut sent_bytes = 0;
        println!("Chiapas::send_buffer sending this number of bytes:{:?}", buf.len());
        while sent_bytes < buf.len() {
            sent_bytes += match send(fd, &buf[sent_bytes..buf.len()], MsgFlags::empty()) {
                Ok(size) => size,
                //Err(nix::Error::Sys(EINTR)) =>{
                    //println!("Chiapas::send_buffer as encountered EINTR error");
                    //0
                //},
                Err(err) => {
                    return Err(format!(
                        "SinaloaNitro::send_buffer failed to send bytes of length:{:?}",
                        err
                    ))
                }
            };
            println!("Chiapas::send_buffer has send this number of bytes so far:{:?}",sent_bytes);
        }
    }
    println!("Chiapas::send_buffer has sent the length:{:?}", len);
    // next, send the buffer
    {
        let mut sent_bytes = 0;
        while sent_bytes < len {
            let size = match send(fd, &buffer[sent_bytes..len], MsgFlags::empty()) {
                Ok(size) => size,
                Err(nix::Error::Sys(_)) => 0,
                Err(err) => {
                    return Err(format!(
                        "SinaloaNitro: send_buffer failed to send bytes:{:?}",
                        err
                    ))
                }
            };
            sent_bytes += size;
        }
    }
    println!("Chiapas::send_buffer has completed.");
    return Ok(());
}