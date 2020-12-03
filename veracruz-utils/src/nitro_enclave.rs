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
use nix::sys::socket::{
    AddressFamily, SockType, SockFlag, SockAddr, socket, bind, listen, accept,
};
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
    #[error(display = "Nitro: EC2 Error")]
    EC2Error,
    #[error(display = "nitro: Mutex Error")]
    MutexError,
    #[error(display = "Nitro: Unimplemented")]
    UnimplementedError,
}

pub struct NitroEnclave {
    enclave_id: String,
    //enclave_cid: u32,
    vsocksocket: crate::vsocket::VsockSocket,
}

const VERACRUZ_PORT: u32 = 5005;
const VMADDR_CID_ANY: u32 = 0xFFFFFFFF;
const OCALL_PORT: u32 = 5006;
const BACKLOG: usize = 128;

pub type OCallHandler = fn(Vec<u8>) -> Result<Vec<u8>, NitroError>;

impl NitroEnclave {
    pub fn new(eif_path: &str, debug: bool, ocall_handler: Option<OCallHandler>) -> Result<Self, NitroError> {
        let mut args = vec!["run-enclave",
                        "--eif-path", eif_path,
                        "--cpu-count", "2", 
                        "--memory", "256",];
        if debug {
            args.push("--debug-mode=true");
        }
        let enclave_result = Command::new("/usr/sbin/nitro-cli")
            .args(&args)
            .output()?;
        let enclave_result_stderr = std::str::from_utf8(&enclave_result.stderr);
        println!("enclave_result_stderr:{:?}", enclave_result_stderr);

        let enclave_result_stdout = std::str::from_utf8(&enclave_result.stdout)?;
        println!("enclave_result_stdout:{:?}", enclave_result_stdout);
        std::thread::sleep(std::time::Duration::from_millis(5000));

        let enclave_data: Value =
            serde_json::from_str(enclave_result_stdout)?;
        let cid:u32 = if !enclave_data["EnclaveCID"].is_number() {
            return Err(NitroError::SerdeError);
        } else {
            serde_json::from_value(enclave_data["EnclaveCID"].clone()).unwrap()
        };

        let enclave: Self = NitroEnclave {
            enclave_id: enclave_data["EnclaveId"].to_string(),
            //enclave_cid: cid,
            vsocksocket: crate::vsocket::vsock_connect(cid, VERACRUZ_PORT)?,
        };

        match ocall_handler {
            None => (), // Do nothing, we don't need to support ocalls
            Some(handler) => {
                let _ocall_thread = std::thread::spawn(move || { NitroEnclave::ocall_loop(handler)});
            },
        }
        return Ok(enclave);
    }

    fn ocall_loop(handler: OCallHandler) {
        println!("NitroEnclave::ocall_loop started");
        let socket_fd = socket(AddressFamily::Vsock, SockType::Stream, SockFlag::empty(), None)
            .expect("NitroEnclave::ocall_loop failed to create a socket");
        let sockaddr = SockAddr::new_vsock(VMADDR_CID_ANY, OCALL_PORT);

        bind(socket_fd, &sockaddr)
            .map_err(|err| NitroError::NixError(err)).expect("NitroEnclave::ocall_loop bind failed");
        listen(socket_fd, BACKLOG)
            .map_err(|err| NitroError::NixError(err)).expect("NitroEnclave::ocall_loop listen failed");

        loop {
            println!("NitroEnclave::ocall_loop looping");
            let fd = accept(socket_fd)
                .map_err(|err| NitroError::NixError(err)).expect("NitroEnclave::ocall_loop accept failed");
            //TODO: How do we gracefully terminate the thread?
            println!("NitroEnclave::ocall_loop calling receive_buffer");
            let received_buffer = crate::nitro::receive_buffer(fd)
                .expect("NitroEnclave::ocall_loop failed to receive buffer");
            // call the handler
            let return_buffer = handler(received_buffer).expect("NitroEnclave::ocall_loop handler failed");
            println!("NitroEnclave::ocall_loop calling send_buffer");
            crate::nitro::send_buffer(fd, &return_buffer)
                .expect("NitroEnclave::ocall_loop failed to send buffer");
        }
    }

    pub fn send_buffer(&self, buffer: &Vec<u8>) -> Result<(), NitroError> {
        println!("nitro_enclave::send_buffer started");
        crate::nitro::send_buffer(self.vsocksocket.as_raw_fd(), buffer)
            .map_err(|err| NitroError::VeracruzSocketError(err))
    }

    pub fn receive_buffer(&self) -> Result<Vec<u8>, NitroError> {
        println!("nitro_enclave::receive_buffer started");
        crate::nitro::receive_buffer(self.vsocksocket.as_raw_fd())
            .map_err(|err| NitroError::VeracruzSocketError(err))
    }

    pub fn close(&self) -> Result<(), NitroError> {
        println!("nitro_enclave::NitroEnclave::close called");
        let _enclave_result_stdout = Command::new("/usr/sbin/nitro-cli")
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
        println!("nitro_enclave::NitroEnclave::drop called");
        match self.close() {
            Err(err) => println!("NitroEnclave::drop failed in call to self.close:{:?}", err),
            _ => (),
        }
    }
}
