use serde::{Deserialize, Serialize};

use nix::sys::socket::{recv, send, MsgFlags};
use nix::errno::Errno::EINTR;
use byteorder::{ByteOrder, LittleEndian};
use std::os::unix::io::RawFd;
use err_derive::Error;

#[derive(Serialize, Deserialize, Debug)]
pub enum NitroStatus {
    Success,
    Fail,
    Unimplemented,
}

#[derive(Serialize, Deserialize, Debug)]
pub enum NitroRootEnclaveMessage {
    Status(NitroStatus),
    FetchFirmwareVersion,
    FirmwareVersion(String),
    SetMexicoCityHashHack(Vec<u8>), // hash
    NativeAttestation(Vec<u8>, i32), // challenge, device_id
    TokenData(Vec<u8>, Vec<u8>), // token, public_key
    ProxyAttestation(Vec<u8>, Vec<u8>, String), // challenge, native_token, enclave_name
    PSAToken(Vec<u8>, Vec<u8>, u32), // token, public_key, device_id
}

#[derive(Serialize, Deserialize, Debug)]
pub enum MCMessage {
    Status(NitroStatus), // status
    Initialize(String), // policy_json
    GetEnclaveCert,
    EnclaveCert(Vec<u8>), // cert
    GetEnclaveName,
    EnclaveName(String), // enclave_name
    GetPSAAttestationToken(Vec<u8>), //challenge
    PSAAttestationToken(Vec<u8>, Vec<u8>, i32), // token, public_key, device_id
    NewTLSSession,
    TLSSession(u32), // session_id
    CloseTLSSession(u32), // session_id
    GetTLSDataNeeded(u32), // session_id
    TLSDataNeeded(bool), // data_neeeded
    SendTLSData(u32, Vec<u8>), // session_id, tls_data,
    GetTLSData(u32), // session_id
    TLSData(Vec<u8>, bool), // TLS Data, alive_flag
    ResetEnclave,
}

#[derive(Debug, Error)]
pub enum VeracruzSocketError {
    #[error(display = "VeracruzSocketError: Nix Error: {:?}", _0)]
    NixError(#[error(source)] nix::Error),
}

pub fn send_buffer(fd: RawFd, buffer: &Vec<u8>) -> Result<(), VeracruzSocketError> {
    let len = buffer.len();
    // first, send the length of the buffer
    {
        let mut buf = [0u8; 9];
        LittleEndian::write_u64(&mut buf, buffer.len() as u64);
        let mut sent_bytes = 0;
        while sent_bytes < buf.len() {
            sent_bytes += match send(fd, &buf[sent_bytes..buf.len()], MsgFlags::empty()) {
                Ok(size) => size,
                //Err(nix::Error::Sys(EINTR)) =>{
                    //println!("veracruz-utils::nitro::send_buffer as encountered EINTR error");
                    //0
                //},
                Err(err) => {
                    return Err(VeracruzSocketError::NixError(err));
                }
            };
        }
    }
    // next, send the buffer
    {
        let mut sent_bytes = 0;
        while sent_bytes < len {
            let size = match send(fd, &buffer[sent_bytes..len], MsgFlags::empty()) {
                Ok(size) => size,
                Err(nix::Error::Sys(_)) => 0,
                Err(err) => {
                    return Err(VeracruzSocketError::NixError(err));
                }
            };
            sent_bytes += size;
        }
    }
    return Ok(());
}

pub fn receive_buffer(fd: RawFd) -> Result<Vec<u8>, VeracruzSocketError> {
    // first, read the length
    let length = {
        let mut buf = [0u8; 9];
        let len = buf.len();
        let mut received_bytes = 0;
        while received_bytes < len {
            received_bytes += match recv(fd, &mut buf[received_bytes..len], MsgFlags::empty()) {
                Ok(size) => {
                    size
                },
                Err(nix::Error::Sys(EINTR)) => 0,
                Err(err) => {
                    println!("I have experienced an error:{:?}", err);
                    return Err(VeracruzSocketError::NixError(err));
                }
            }
        }
        LittleEndian::read_u64(&buf) as usize
    };
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
                    return Err(VeracruzSocketError::NixError(err));
                }
            }
        }
    }
    return Ok(buffer);
}