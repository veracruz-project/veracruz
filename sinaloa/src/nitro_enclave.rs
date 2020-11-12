use nix::errno::Errno::EINTR;
use nix::sys::socket::{ MsgFlags, recv, send};
use std::os::unix::io::{AsRawFd, RawFd};
use serde::{Deserialize, Serialize};
use std::process::Command;
use std::sync::Mutex;
use byteorder::{ByteOrder, LittleEndian};
use crate::sinaloa::SinaloaError;
use serde_json::Value;
use veracruz_utils::vsocket;

pub struct NitroEnclave {
    enclave_id: String,
    enclave_cid: u32,
    vsocksocket: vsocket::VsockSocket,
}

const VERACRUZ_PORT: u32 = 5005;

impl NitroEnclave {

    pub fn new(eif_path: &str) -> Result<Self, SinaloaError> {
        let enclave_result = Command::new("nitro-cli")
            .args(&["run-enclave", "--eif-path", eif_path, "--cpu-count", "2", "--memory", "256",]) // "--debug-mode=true"])
            .output()?;
        let enclave_result_stderr = std::str::from_utf8(&enclave_result.stderr)?;
        println!("enclave_result_stderr:{:?}", enclave_result_stderr);
        let enclave_result_stdout = enclave_result.stdout;

        let enclave_result_text = std::str::from_utf8(&enclave_result_stdout)?;
        println!("enclave_result_text:{:?}", enclave_result_text);
        std::thread::sleep(std::time::Duration::from_millis(10000));

        let enclave_data: Value =
            serde_json::from_str(enclave_result_text)?;
        let cid:u32 = if !enclave_data["EnclaveCID"].is_number() {
            return Err(SinaloaError::SerdeError);
        } else {
            serde_json::from_value(enclave_data["EnclaveCID"].clone()).unwrap()
        };

        let enclave: Self = NitroEnclave {
            enclave_id: enclave_data["EnclaveId"].to_string(),
            enclave_cid: cid,
            vsocksocket: veracruz_utils::vsocket::vsock_connect(cid, VERACRUZ_PORT)?,
        };
        return Ok(enclave);
    }

    fn read_length(&self) -> Result<usize, SinaloaError> {
        println!("sinaloa::read_length started");
        let mut buf = [0u8; 9];
        let len = buf.len();
        let mut received_bytes = 0;
        while received_bytes < len {
            println!("iter");
            received_bytes += match recv(self.vsocksocket.as_raw_fd(), &mut buf[received_bytes..len], MsgFlags::empty()) {
                Ok(size) => {
                    println!("read some bytes:{:?}", size);
                    size
                },
                Err(nix::Error::Sys(EINTR)) => {
                    println!("EINTER");
                    0
                },
                Err(err) => return Err(SinaloaError::NixError(err)),
            }
        }
        println!("read_length returning");
        Ok(LittleEndian::read_u64(&buf) as usize)
    }

    pub fn send_buffer(&self, buffer: &Vec<u8>) -> Result<(), SinaloaError> {
        println!("send_buffer started");

        let len = buffer.len();
        // first, send the length of the buffer
        {
            let mut buf = [0u8; 9];
            LittleEndian::write_u64(&mut buf, buffer.len() as u64);
            let mut sent_bytes = 0;
            while sent_bytes < buf.len() {
                sent_bytes += match send(self.vsocksocket.as_raw_fd(), &buf[sent_bytes..buf.len()], MsgFlags::empty()) {
                    Ok(size) => size,
                    Err(nix::Error::Sys(EINTR)) => 0,
                    Err(err) => {
                        println!("send_buffer: Failed to send size.");
                        return Err(SinaloaError::NixError(err))
                    },
                };
            }

        }
        // next, send the buffer
        {
            let mut sent_bytes = 0;
            while sent_bytes < len {
                let size = match send(self.vsocksocket.as_raw_fd(), &buffer[sent_bytes..len], MsgFlags::empty()) {
                    Ok(size) => size,
                    Err(nix::Error::Sys(EINTR)) => 0,
                    Err(err) => {
                        return Err(SinaloaError::NixError(err))
                    },
                };
                sent_bytes += size;
            }
        }
        println!("send_buffer complete. Let's see if it's trying to close the socket (which I don't think I want it to do)");
        return Ok(());
    }

    pub fn receive_buffer(&self) -> Result<Vec<u8>, SinaloaError> {
        println!("nitro_enclave::receive_buffer started");

        // first, read the length
        let length = self.read_length()?;
        println!("nitro_enclave::receive_buffer has received length:{:?}", length);
        let mut buffer: Vec<u8> = vec![0; length];
        // next, read the buffer
        {
            let mut received_bytes: usize = 0;
            while received_bytes < length {
                received_bytes += match recv(self.vsocksocket.as_raw_fd(), &mut buffer[received_bytes..length], MsgFlags::empty()) {
                    Ok(size) => size,
                    Err(nix::Error::Sys(EINTR)) => 0,
                    Err(err) => return Err(SinaloaError::NixError(err)),
                }
            }
        }
        println!("nitro_enclave::receive_buffer has received buffer:{:?}", buffer);
        return Ok(buffer);
    }

    pub fn close(&self) -> Result<(), SinaloaError> {
        let _enclave_result_stdout = Command::new("nitro-cli")
            .args(&["terminate-enclave", "--enclave-id", &self.enclave_id])
            .output()?
            .stdout;
        // There's not much we can do with the result of this command. If it fails to close, what's done?
        // Also, parsing strings is annoying
        return Ok(());
    }
}

impl Drop for NitroEnclave {
    fn drop(&mut self) {
        match self.close() {
            Err(err) => println!("SinaloaNitro::drop failed in call to self.close:{:?}", err),
            _ => (),
        }
    }
}
