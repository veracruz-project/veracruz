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

use err_derive::Error;
use nix::sys::socket::sockopt::{ReuseAddr, ReusePort};
use nix::sys::socket::{
    accept, bind, listen, setsockopt, shutdown, socket, AddressFamily, Shutdown, SockAddr,
    SockFlag, SockType,
};
use nix::unistd::close;
use serde_json::Value;
use std::os::unix::io::AsRawFd;
use std::process::Command;
use std::thread::JoinHandle;

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
    #[error(display = "Nitro: CLI error")]
    CLIError,
    #[error(display = "Nitro: Veracruz Socket Error:{:?}", _0)]
    VeracruzSocketError(#[error(source)] crate::VeracruzSocketError),
    #[error(display = "Nitro: Utf8Error:{:?}", _0)]
    Utf8Error(#[error(source)] std::str::Utf8Error),
    #[error(display = "Nitro: EC2 Error")]
    EC2Error,
    #[error(display = "nitro: Mutex Error")]
    MutexError,
    #[error(display = "nitro: Thread Error")]
    ThreadError,
    #[error(display = "Nitro: Unimplemented")]
    UnimplementedError,
}

pub struct NitroEnclave {
    enclave_id: String,
    vsocksocket: crate::vsocket::VsockSocket,
    ocall_thread: Option<JoinHandle<()>>,
    ocall_terminate_sender: Option<std::sync::Mutex<std::sync::mpsc::Sender<bool>>>,
    nitro_cli_path: String,
}

const VERACRUZ_PORT: u32 = 5005;
const VMADDR_CID_ANY: u32 = 0xFFFFFFFF;
const OCALL_PORT: u32 = 5006;
const BACKLOG: usize = 128;

pub type OCallHandler = fn(Vec<u8>) -> Result<Vec<u8>, NitroError>;

impl NitroEnclave {
    pub fn new(
        nitro_sbin: bool,
        eif_path: &str,
        debug: bool,
        ocall_handler: Option<OCallHandler>,
    ) -> Result<Self, NitroError> {
        let mut args = vec![
            "run-enclave",
            "--eif-path",
            eif_path,
            "--cpu-count",
            "2",
            "--memory",
            "256",
        ];
        if debug {
            args.push("--debug-mode=true");
        }
        let nitro_cli_path = {
            match nitro_sbin {
                true => "/usr/sbin/nitro-cli",
                false => "/usr/bin/nitro-cli",
            }
        };
        let stdout = loop {
            let enclave_result = Command::new(nitro_cli_path)
                .args(&args)
                .output()
                .map_err(|err| err);
            match enclave_result {
                Err(err) => {
                    println!("NitroEnclave::new failed to start enclave:{:?}", err);
                    println!("sleeping before trying again");
                    std::thread::sleep(std::time::Duration::from_millis(1000));
                    continue;
                }
                Ok(result) => {
                    if !result.status.success() {
                        let enclave_result_stderr = std::str::from_utf8(&result.stderr)?;
                        println!("NitroEnclave::new CLI error:{:?}", enclave_result_stderr);
                        println!("sleeping before trying again");
                        std::thread::sleep(std::time::Duration::from_millis(1000));
                        continue;
                    } else {
                        break result.stdout;
                    }
                }
            }
        };

        let enclave_result_stdout = std::str::from_utf8(&stdout)?;
        println!("enclave_result_stdout:{:?}", enclave_result_stdout);

        let enclave_data: Value = serde_json::from_str(enclave_result_stdout)?;
        let cid: u32 = if !enclave_data["EnclaveCID"].is_number() {
            return Err(NitroError::SerdeError);
        } else {
            serde_json::from_value(enclave_data["EnclaveCID"].clone()).unwrap()
        };

        let (ocall_thread_opt, sender) = match ocall_handler {
            None => (None, None), // Do nothing, we don't need to support ocalls
            Some(handler) => {
                let (tx, rx): (
                    std::sync::mpsc::Sender<bool>,
                    std::sync::mpsc::Receiver<bool>,
                ) = std::sync::mpsc::channel();
                let ocall_thread =
                    std::thread::spawn(move || NitroEnclave::ocall_loop(handler, rx));
                (Some(ocall_thread), Some(std::sync::Mutex::new(tx)))
            }
        };

        let enclave: Self = NitroEnclave {
            enclave_id: enclave_data["EnclaveID"]
                .to_string()
                .trim_matches('"')
                .to_string(),
            vsocksocket: crate::vsocket::vsock_connect(cid, VERACRUZ_PORT)?,
            ocall_thread: ocall_thread_opt,
            ocall_terminate_sender: sender,
            nitro_cli_path: nitro_cli_path.to_string(),
        };
        return Ok(enclave);
    }

    fn ocall_loop(handler: OCallHandler, terminate_rx: std::sync::mpsc::Receiver<bool>) {
        let socket_fd = socket(
            AddressFamily::Vsock,
            SockType::Stream,
            SockFlag::SOCK_NONBLOCK,
            None,
        )
        .expect("NitroEnclave::ocall_loop failed to create a socket");

        if let Err(err) = setsockopt(socket_fd, ReuseAddr, &true) {
            println!(
                "NitroEnclave::ocall_loop setsockopt failed for ReuseAddr({:?}). Terminating loop.",
                err
            );
            return;
        }
        if let Err(err) = setsockopt(socket_fd, ReusePort, &true) {
            println!(
                "NitroEnclave::ocall_loop setsockopt failed for ReusePort({:?}). Terminating loop.",
                err
            );
            return;
        }

        let sockaddr = SockAddr::new_vsock(VMADDR_CID_ANY, OCALL_PORT);

        let mut im_done: bool = false;

        while let Err(err) = bind(socket_fd, &sockaddr) {
            println!(
                "NitroEnclave::ocall_loop failed to bind to socket:{:?}",
                err
            );
            if err == nix::Error::Sys(nix::errno::Errno::EADDRINUSE) {
                // before we continue, check to see if we should terminate
                if let Ok(terminate) = terminate_rx.try_recv() {
                    if terminate {
                        im_done = true;
                        break;
                    }
                }
                println!("sleeping before trying again");
                std::thread::sleep(std::time::Duration::from_millis(1000));
            } else {
                panic!(
                    "NitroEnclave::ocall_loop received an unhandled error from bind:{:?}",
                    err
                );
            }
        }

        if !im_done {
            listen(socket_fd, BACKLOG)
                .map_err(|err| NitroError::NixError(err))
                .expect("NitroEnclave::ocall_loop listen failed");
            loop {
                match accept(socket_fd) {
                    Ok(fd) => {
                        let received_buffer = crate::nitro::receive_buffer(fd)
                            .expect("NitroEnclave::ocall_loop failed to receive buffer");
                        // call the handler
                        let return_buffer = handler(received_buffer)
                            .expect("NitroEnclave::ocall_loop handler failed");
                        crate::nitro::send_buffer(fd, &return_buffer)
                            .expect("NitroEnclave::ocall_loop failed to send buffer");
                    }
                    Err(err) => match err {
                        nix::Error::Sys(_) => {
                            if let Ok(terminate) = terminate_rx.try_recv() {
                                if terminate {
                                    break;
                                }
                            }
                        }
                        _ => println!("NitroEnclave::ocall_loop received error:{:?}", err),
                    },
                }
            }
        }

        // TODO: Use veracruz-utils::VsockSocket, which should handle shutdown, close itself in it's Drop function
        if let Err(err) = shutdown(socket_fd, Shutdown::Both) {
            match err {
                nix::Error::Sys(err) => {
                    match err {
                        nix::errno::Errno::ENOTCONN => (), // this is normal
                        _ =>  println!("NitroEnclave::ocall_loop failed to shutdown socket({:?}. This might cause you problems in the future.", err),
                    }
                },
                _ => println!("NitroEnclave::ocall_loop failed to shutdown socket({:?}. This might cause you problems in the future.", err),
            }
        }
        if let Err(err) = close(socket_fd) {
            println!("NitroEnclave::ocall_loop failed to close socket file handle({:?}). This might cause you problems in the future", err);
        }
    }

    pub fn send_buffer(&self, buffer: &Vec<u8>) -> Result<(), NitroError> {
        crate::nitro::send_buffer(self.vsocksocket.as_raw_fd(), buffer)
            .map_err(|err| NitroError::VeracruzSocketError(err))
    }

    pub fn receive_buffer(&self) -> Result<Vec<u8>, NitroError> {
        crate::nitro::receive_buffer(self.vsocksocket.as_raw_fd())
            .map_err(|err| NitroError::VeracruzSocketError(err))
    }
}

impl Drop for NitroEnclave {
    fn drop(&mut self) {
        // first, tell the ocall loop to terminate
        if let Some(tx_mutex) = &self.ocall_terminate_sender {
            let sender_guard = tx_mutex.lock().unwrap();
            if let Err(err) = sender_guard.send(true) {
                println!("NitroEnclave::drop failed to send terminate message to ocall_thread. You can't do anything about this, since we are in the drop method, but I thought you would want to know:{:?}", err);
            }
        }

        // second, wait for the ocall loop to terminate
        // This is referred to as the "Option dance" - https://users.rust-lang.org/t/spawn-threads-and-join-in-destructor/1613
        // we can only do the "take" because we are effectively a destructor
        if let Some(thread_handle) = self.ocall_thread.take() {
            if let Err(err) = thread_handle.join() {
                println!("NitroEnclave::drop failed to join to the ocall_thread. You can't do anything about this, since we are in the drop method, but I thought you would want to know:{:?}", err);
            }
        }

        // now, shutdown the enclave
        loop {
            let enclave_result = Command::new(&self.nitro_cli_path)
                .args(&["terminate-enclave", "--enclave-id", &self.enclave_id])
                .output();
            match enclave_result {
                Err(err) => {
                    println!("NitroEnclave::drop Command::new returned err:{:?}, sleeping and trying again", err);
                    std::thread::sleep(std::time::Duration::from_millis(1000));
                    continue;
                }
                Ok(result) => {
                    if !result.status.success() {
                        println!("NitroEnclave::drop failed to terminate the enclave (exit_status:{:?}. You will need to terminate it yourself.", result.status);
                        let result_stderr = std::str::from_utf8(&result.stderr).unwrap();
                        println!("NitroEnclave::drop CLI error:{:?}", result_stderr);
                    }
                    break;
                }
            }
        }
    }
}
