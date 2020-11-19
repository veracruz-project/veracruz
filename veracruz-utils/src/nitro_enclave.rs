//! Nitro-Enclave-specific material for Veracruz
//!
//! ## Authors
//!
//! The Veracruz Development Team.
//!
//! ## Licensing and copyright notice
//!
//! See the `LICENSE.markdown` file in the Veracruz root directory for
//! information on licensing and copyright.

use std::os::unix::io::AsRawFd;
use std::process::Command;
use serde_json::Value;
use err_derive::Error;
//use veracruz_utils::{ receive_buffer, send_buffer, vsocket};

#[derive(Debug, Error)]
pub enum NitroError {
    #[error(display = "Nitro: Serde Error")]
    SerdeError,
    #[error(display = "nitro: Serde JSON Error:{:?}", _0)]
    SerdeJsonError(#[error(source)] serde_json::error::Error),
    #[error(display = "Nitrno: Nix Error:{:?}", _0)]
    NixError(#[error(source)] nix::Error),
    #[error(display = "Nitro: IO Error:{:?}", _0)]
    IOError(#[error(source)] std::io::Error),
    #[error(display = "Nitro: Veracruz Socket Error:{:?}", _0)]
    VeracruzSocketError(#[error(source)] crate::VeracruzSocketError),
    #[error(display = "Nitro: Utf8Error:{:?}", _0)]
    Utf8Error(#[error(source)] std::str::Utf8Error),
    #[error(display = "Nitro: Unimplemented")]
    UnimplementedError,
}

pub struct NitroEnclave {
    enclave_id: String,
    //enclave_cid: u32,
    vsocksocket: crate::vsocket::VsockSocket,
}

const VERACRUZ_PORT: u32 = 5005;

impl NitroEnclave {

    pub fn new(eif_path: &str, debug: bool) -> Result<Self, NitroError> {
        let mut args = vec!["run-enclave",
                        "--eif-path", eif_path,
                        "--cpu-count", "2", 
                        "--memory", "256",];
        if debug {
            args.push("--debug-mode=true");
        }
        let enclave_result = Command::new("nitro-cli")
            .args(&args)
            .output()?;
        let enclave_result_stderr = std::str::from_utf8(&enclave_result.stderr)?;
        let enclave_result_stdout = enclave_result.stdout;

        let enclave_result_text = std::str::from_utf8(&enclave_result_stdout)?;
        println!("enclave_result_text:{:?}", enclave_result_text);
        std::thread::sleep(std::time::Duration::from_millis(5000));

        let enclave_data: Value =
            serde_json::from_str(enclave_result_text)?;
        let cid:u32 = if !enclave_data["EnclaveCID"].is_number() {
            return Err(NitroError::SerdeError);
        } else {
            serde_json::from_value(enclave_data["EnclaveCID"].clone()).unwrap()
        };

        println!("NitroEnclave::new calling vsock_connect, among other things, cid:{:?}, port:{:?}", cid, VERACRUZ_PORT);
        let enclave: Self = NitroEnclave {
            enclave_id: enclave_data["EnclaveId"].to_string(),
            //enclave_cid: cid,
            vsocksocket: crate::vsocket::vsock_connect(cid, VERACRUZ_PORT)?,
        };
        println!("NitroEnclave::new succeeded");
        return Ok(enclave);
    }

    pub fn send_buffer(&self, buffer: &Vec<u8>) -> Result<(), NitroError> {
        println!("send_buffer started");
        crate::nitro::send_buffer(self.vsocksocket.as_raw_fd(), buffer)
            .map_err(|err| NitroError::VeracruzSocketError(err))
    }

    pub fn receive_buffer(&self) -> Result<Vec<u8>, NitroError> {
        println!("nitro_enclave::receive_buffer started");
        crate::nitro::receive_buffer(self.vsocksocket.as_raw_fd())
            .map_err(|err| NitroError::VeracruzSocketError(err))
    }

    pub fn close(&self) -> Result<(), NitroError> {
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
