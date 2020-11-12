use nix::errno::Errno::EINTR;
use nix::sys::socket::{ MsgFlags, recv, send};
use std::os::unix::io::{AsRawFd, RawFd};
use serde::{Deserialize, Serialize};
use std::process::Command;
use std::sync::Mutex;
use byteorder::{ByteOrder, LittleEndian};
use crate::sinaloa::SinaloaError;
use serde_json::Value;
use veracruz_utils::{ receive_buffer, send_buffer, vsocket};

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

    pub fn send_buffer(&self, buffer: &Vec<u8>) -> Result<(), SinaloaError> {
        println!("send_buffer started");
        send_buffer(self.vsocksocket.as_raw_fd(), buffer)
            .map_err(|err| SinaloaError::VeracruzSocketError(err))
    }

    pub fn receive_buffer(&self) -> Result<Vec<u8>, SinaloaError> {
        println!("nitro_enclave::receive_buffer started");
        receive_buffer(self.vsocksocket.as_raw_fd())
            .map_err(|err| SinaloaError::VeracruzSocketError(err))
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
